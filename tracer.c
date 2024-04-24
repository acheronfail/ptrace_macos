#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/ptrace.h>
#include <unistd.h>

// To properly integrate with mach exceptions, we need to use code that's generated
// with `mig`. It's compiled into the resuling binary and we also declare the
// `mac_exc_server` function that's defined in `mach_excServer.c` since we use it.
boolean_t mach_exc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);

// This needs to be global, since it's defined in `main` after the fork, but we
// want to use it in our `catch_mach_exception_raise` handler.
pid_t child_pid;

// Some macros to make error handling less verbose when calling various apis
#define EXIT_WITH_MESSAGE(message, description, code)                                              \
  printf("failed at: %s with %s (%d) [%s:%d]\n", message, description, code, __FILE__, __LINE__);  \
  exit(EXIT_FAILURE);
#define CHECK_ERRNO(expression)                                                                    \
  ({                                                                                               \
    errno = 0;                                                                                     \
    int value = (expression);                                                                      \
    if (value != 0) {                                                                              \
      EXIT_WITH_MESSAGE(#expression, strerror(errno), errno);                                      \
    }                                                                                              \
    value;                                                                                         \
  })
#define CHECK_KERN(expression)                                                                     \
  ({                                                                                               \
    kern_return_t value = (expression);                                                            \
    if (value != KERN_SUCCESS) {                                                                   \
      EXIT_WITH_MESSAGE(#expression, mach_error_string(value), value);                             \
    }                                                                                              \
    value;                                                                                         \
  })

int main(int argc, char *argv[]) {
  // first, we fork - the parent will be the tracer, the child the tracee
  child_pid = fork();
  if (child_pid == -1) {
    EXIT_WITH_MESSAGE("fork", strerror(errno), errno);
  }

  // CHILD PROCESS: the tracee
  if (child_pid == 0) {
    // immediately SIGSTOP ourselves - we will wait for the parent to set itself
    // up as the tracer before it continues our execution
    printf("[child] raise: SIGSTOP\n");
    CHECK_ERRNO(raise(SIGSTOP));

    // now spawn a child process with the arguments passed on the command line
    printf("[child] execvp\n");
    CHECK_ERRNO(execvp(argv[1], &argv[1]));
  }

  // PARENT PROCESS: the tracer
  printf("[parent] child pid: %d\n", child_pid);

  // Full sanity check here to ensure the child was in the state we expected
  printf("[parent] calling waitpid on child\n");
  int wait_status = 0;
  pid_t wait_pid = waitpid(child_pid, &wait_status, WUNTRACED);
  if (wait_pid != child_pid) {
    printf("[parent] unexpected pid from waitpid: %d\n", wait_pid);
    exit(EXIT_FAILURE);
  }
  if (!WIFSTOPPED(wait_status)) {
    printf("[parent] expected child to be stopped, but it wasn't\n");
    exit(EXIT_FAILURE);
  }
  int stop_sig = WSTOPSIG(wait_status);
  if (stop_sig != SIGSTOP) {
    printf("[parent] expected signal to be SIGSTOP, but it was: %s (%d)\n",
           strsignal(stop_sig),
           stop_sig);
    exit(EXIT_FAILURE);
  }

  // Okay, the child was waiting correctly. Let's now attach to it as a tracer.
  // There are a few steps to this:

  // First, we get the mach port for the tracee - in order to call `task_for_pid`
  // on macos, we need to:
  // - embed an Info.plist into our binary with `SecTaskAccess:allowed`
  // - run as root
  //
  // I believe it is possible to do this without running as root, but it seems like
  // it requires codesigning the binary with entitlements and a valid Apple Developer
  // identity or something. Either way, I couldn't figure it out, and have just set
  // this up to use root for the time being.
  printf("[parent] getting child_task for pid: %d\n", child_pid);
  mach_port_name_t child_task = 0;
  CHECK_KERN(task_for_pid(mach_task_self(), child_pid, &child_task));
  printf("[parent] child_task: %d\n", child_task);

  // Next, we want to replace the target task's exception ports with one we own,
  // so we allocate a new one:
  mach_port_name_t child_exc_port = 0;
  CHECK_KERN(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &child_exc_port));
  printf("[parent] child_exc_port: %d\n", child_exc_port);
  CHECK_KERN(mach_port_insert_right(
      mach_task_self(), child_exc_port, child_exc_port, MACH_MSG_TYPE_MAKE_SEND));

  // Now we register our created exception port with the traced process.
  CHECK_KERN(task_set_exception_ports(child_task,
                                      EXC_MASK_ALL,
                                      child_exc_port,
                                      EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                                      THREAD_STATE_NONE));

  // Finally, after all this, we're ready to use ptrace to attach as a tracer.
  // There are a few extra restrictions on this that are relaxed since we're
  // running as root.
  CHECK_ERRNO(ptrace(PT_ATTACHEXC, child_pid, 0, 0));
  printf("[parent] attached as tracer\n");

  // Now we're the tracer for the child, we can start a loop to handle mach
  // exceptions for the child
  while (1) {
    char req[128], rpl[128];

    // this will block until an exception is received
    printf("[parent] waiting for mach exception...\n");
    CHECK_KERN(mach_msg((mach_msg_header_t *)req, /* receive buffer */
                        MACH_RCV_MSG,             /* receive message */
                        0,                        /* size of send buffer */
                        sizeof(req),              /* size of receive buffer */
                        child_exc_port,           /* port to receive on */
                        MACH_MSG_TIMEOUT_NONE,    /* wait indefinitely */
                        MACH_PORT_NULL));         /* notify port, unused */

    // we received an exception, so suspend all threads of the target process
    // FIXME: this sometimes returns `MACH_SEND_INVALID_DEST`? ignored for now
    task_suspend(child_task);

    if (!mach_exc_server((mach_msg_header_t *)req, (mach_msg_header_t *)rpl)) {
      CHECK_KERN(((mig_reply_error_t *)rpl)->RetCode);
      exit(EXIT_FAILURE);
    }

    // we've parsed the exception and are ready to reply, resume the target process
    // FIXME: this sometimes returns `MACH_SEND_INVALID_DEST`? ignored for now
    task_resume(child_task);

    // reply to the exception
    mach_msg_size_t send_sz = ((mach_msg_header_t *)rpl)->msgh_size;
    CHECK_KERN(mach_msg((mach_msg_header_t *)rpl, /* send buffer */
                        MACH_SEND_MSG,            /* send message */
                        send_sz,                  /* size of send buffer */
                        0,                        /* size of receive buffer */
                        MACH_PORT_NULL,           /* port to receive on */
                        MACH_MSG_TIMEOUT_NONE,    /* wait indefinitely */
                        MACH_PORT_NULL));
  }

  // clean up
  CHECK_KERN(mach_port_deallocate(mach_task_self(), child_task));

  return EXIT_SUCCESS;
}

// These functions are required by the mach exception code generated by `mig`.

kern_return_t catch_mach_exception_raise(mach_port_t exception_port,
                                         mach_port_t thread_port,
                                         mach_port_t task_port,
                                         exception_type_t exception_type,
                                         mach_exception_data_t codes,
                                         mach_msg_type_number_t num_codes) {
  printf("[parent] catch_mach_exception_raise:\n");
  printf("[parent] - exception_type: %x\n", exception_type);
  for (int i = 0; i < num_codes; i++)
    printf("[parent] - codes[%d]: 0x%llx\n", i, codes[i]);

  if (exception_type == EXC_SOFTWARE && codes[0] == EXC_SOFT_SIGNAL) {
    // clear SIGTRAP signals before sending through to traced process
    if (codes[1] == SIGTRAP) {
      codes[1] = 0;
    }

    printf("[parent] - child_pid: %d\n", child_pid);
    printf("[parent] - task_port: %d\n", task_port);
    printf("[parent] - thread_port: %d\n", thread_port);
    printf("[parent] - exception_port: %d\n", exception_port);

    printf("[parent] ptrace(PT_THUPDATE, %d, %d, 0x%llx)\n", child_pid, thread_port, codes[1]);
    CHECK_ERRNO(ptrace(PT_THUPDATE, child_pid, (caddr_t)(uintptr_t)thread_port, codes[1]));
  }

  return KERN_SUCCESS;
}

kern_return_t catch_mach_exception_raise_state(mach_port_t exception_port,
                                               exception_type_t exception,
                                               const mach_exception_data_t code,
                                               mach_msg_type_number_t codeCnt,
                                               int *flavor,
                                               const thread_state_t old_state,
                                               mach_msg_type_number_t old_stateCnt,
                                               thread_state_t new_state,
                                               mach_msg_type_number_t *new_stateCnt) {
  printf("catch_mach_exception_raise_state\n");
  // not used because EXCEPTION_STATE is not specified in the call to
  // task_set_exception_ports, but referenced by mach_exc_server
  return MACH_RCV_INVALID_TYPE;
}

kern_return_t catch_mach_exception_raise_state_identity(mach_port_t exception_port,
                                                        mach_port_t thread,
                                                        mach_port_t task,
                                                        exception_type_t exception,
                                                        mach_exception_data_t code,
                                                        mach_msg_type_number_t codeCnt,
                                                        int *flavor,
                                                        thread_state_t old_state,
                                                        mach_msg_type_number_t old_stateCnt,
                                                        thread_state_t new_state,
                                                        mach_msg_type_number_t *new_stateCnt) {
  printf("catch_mach_exception_raise_state_identity\n");
  // not used because EXCEPTION_STATE_IDENTITY is not specified in the call to
  // task_set_exception_ports, but referenced by mach_exc_server
  return MACH_RCV_INVALID_TYPE;
}
