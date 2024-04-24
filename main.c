#include <assert.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <sys/errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "mig/mach_exc.h"
boolean_t mach_exc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);

pid_t child_pid;

kern_return_t catch_mach_exception_raise(mach_port_t exception_port,
                                         mach_port_t thread_port,
                                         mach_port_t task_port,
                                         exception_type_t exception_type,
                                         mach_exception_data_t codes,
                                         mach_msg_type_number_t num_codes) {

  printf("[parent] -- exception_type: %x\n", exception_type);
  for (int i = 0; i < num_codes; i++)
    printf("[parent] -- codes[%d]: %llx\n", i, codes[i]);

  if (exception_type == EXC_SOFTWARE && codes[0] == EXC_SOFT_SIGNAL) {
    // clear SIGTRAP signals before sending through to traced process
    if (codes[1] == SIGTRAP) {
      codes[1] = 0;
    }

    printf("[parent] -- child_pid: %d\n", child_pid);
    printf("[parent] -- task_port: %d\n", task_port);
    printf("[parent] -- thread_port: %d\n", thread_port);
    printf("[parent] -- exception_port: %d\n", exception_port);

    printf("[parent] ptrace(PT_THUPDATE, %d, %d, %lld)\n", child_pid, thread_port, codes[1]);
    int result = ptrace(PT_THUPDATE, child_pid, (caddr_t)(uintptr_t)thread_port, codes[1]);
    if (result != KERN_SUCCESS) {
      printf("[parent] failed to ptrace(PT_THUPDATE): %s (%d)\n", strerror(errno), errno);
      return KERN_FAILURE;
    }
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
  // not used because EXCEPTION_STATE_IDENTITY is not specified in the call to
  // task_set_exception_ports, but referenced by mach_exc_server
  return MACH_RCV_INVALID_TYPE;
}

int main(int argc, char *argv[]) {
  child_pid = fork();
  if (child_pid == -1) {
    printf("failed to fork, errno: %d\n", errno);
    return 1;
  }

  // CHILD PROCESS: the tracee
  if (child_pid == 0) {
    printf("[child] raise: SIGSTOP\n");
    int result = raise(SIGSTOP);
    if (result != 0) {
      printf("[child] failed to raise(SIGSTOP): %s (%d)\n", strerror(errno), errno);
      return 1;
    }

    printf("[child] execvp\n");
    execvp(argv[1], &argv[1]);

    // execvp should never return
    printf("[child] failed to execvp, errno: %s (%d)\n", strerror(errno), errno);
    return 1;
  }

  // PARENT PROCESS: the tracer
  printf("[parent] child pid: %d\n", child_pid);

  // Full sanity check here to ensure the child was in the state we expected
  printf("[parent] calling waitpid on child\n");
  int wait_status = 0;
  pid_t wait_pid = waitpid(child_pid, &wait_status, WUNTRACED);
  if (wait_pid != child_pid) {
    printf("[parent] unexpected pid from waitpid: %d\n", wait_pid);
    return 1;
  }
  if (!WIFSTOPPED(wait_status)) {
    printf("[parent] expected child to be stopped, but it wasn't\n");
    return 1;
  }

  int stop_sig = WSTOPSIG(wait_status);
  if (stop_sig != SIGSTOP) {
    printf("[parent] expected signal to be SIGSTOP, but it was: %s (%d)\n",
           strsignal(stop_sig),
           stop_sig);
    return 1;
  }

  // Okay, the child was waiting correctly. Let's now attach to it as a tracer.
  printf("[parent] getting target_task_port for pid: %d\n", child_pid);
  mach_port_name_t target_task_port = 0;
  kern_return_t kern_r = task_for_pid(mach_task_self(), child_pid, &target_task_port);
  assert(kern_r == KERN_SUCCESS && "task_for_pid failed");
  printf("[parent] target_task_port: %d\n", target_task_port);

  // save the set of exception ports registered in the process
  exception_mask_t saved_masks[EXC_TYPES_COUNT];
  mach_port_t saved_ports[EXC_TYPES_COUNT];
  exception_behavior_t saved_behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t saved_flavors[EXC_TYPES_COUNT];
  mach_msg_type_number_t saved_exception_types_count;

  kern_r = task_get_exception_ports(target_task_port,
                                    EXC_MASK_ALL,
                                    saved_masks,
                                    &saved_exception_types_count,
                                    saved_ports,
                                    saved_behaviors,
                                    saved_flavors);
  assert(kern_r == KERN_SUCCESS && "task_get_exception_ports failed");

  // allocate and authorize a new port
  mach_port_name_t target_exception_port = 0;
  kern_r = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &target_exception_port);
  assert(kern_r == KERN_SUCCESS && "mach_port_allocate failed");
  printf("[parent] target_exception_port: %d\n", target_exception_port);

  kern_r = mach_port_insert_right(
      mach_task_self(), target_exception_port, target_exception_port, MACH_MSG_TYPE_MAKE_SEND);
  assert(kern_r == KERN_SUCCESS && "mach_port_insert_right failed");

  // register the exception port with the target process
  exception_behavior_t b = EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES;
  kern_r = task_set_exception_ports(
      target_task_port, EXC_MASK_ALL, target_exception_port, b, THREAD_STATE_NONE);
  assert(kern_r == KERN_SUCCESS && "task_set_exception_ports failed");

  // finally attach as tracer
  kern_r = ptrace(PT_ATTACHEXC, child_pid, 0, 0);
  if (kern_r == 0) {
    printf("[parent] attached as tracer\n");
  } else {
    printf("[parent] failed to ptrace(PT_ATTACHEXC): %s (%d)\n", strerror(errno), errno);
    return 1;
  }

  // loop while we handle exceptions
  while (1) {
    char req[128], rpl[128];

    // int wait_status = 0;
    // pid_t wait_pid = waitpid(child_pid, &wait_status, WNOHANG);
    // if (WIFEXITED(wait_status)) {
    //   printf("exited: %d\n", WEXITSTATUS(wait_status));
    // }

    // this will block until an exception is received
    printf("[parent] waiting for mach exception...\n");
    kern_r = mach_msg((mach_msg_header_t *)req, /* receive buffer */
                      MACH_RCV_MSG,             /* receive message */
                      0,                        /* size of send buffer */
                      sizeof(req),              /* size of receive buffer */
                      target_exception_port,    /* port to receive on */
                      MACH_MSG_TIMEOUT_NONE,    /* wait indefinitely */
                      MACH_PORT_NULL);          /* notify port, unused */
    assert(kern_r == KERN_SUCCESS && "mach_msg failed");

    mach_msg_header_t *tmp = (mach_msg_header_t *)req;
    printf("[parent] req->msgh_bits: 0x%x\n", tmp->msgh_bits);
    printf("[parent] req->msgh_id: 0x%x\n", tmp->msgh_id);
    printf("[parent] req->msgh_local_port: %d\n", tmp->msgh_local_port);
    printf("[parent] req->msgh_remote_port: %d\n", tmp->msgh_remote_port);
    printf("[parent] req->msgh_size: 0x%x\n", tmp->msgh_size);
    printf("[parent] req->msgh_voucher_port: 0x%x\n", tmp->msgh_voucher_port);

    // we received an exception, so suspend all threads of the target process
    kern_r = task_suspend(target_task_port);
    // if (kern_r != KERN_SUCCESS) {
    //   printf("[parent] task_suspend failed: %s (%x)\n", mach_error_string(kern_r), kern_r);
    //   return 1;
    // }

    if (!mach_exc_server((mach_msg_header_t *)req, (mach_msg_header_t *)rpl)) {
      mig_reply_error_t *err = (mig_reply_error_t *)rpl;
      printf("mach_exc_server failed: %s (%d)\n", mach_error_string(err->RetCode), err->RetCode);
      return 1;
    }

    tmp = (mach_msg_header_t *)rpl;
    printf("[parent] rpl->msgh_bits: 0x%x\n", tmp->msgh_bits);
    printf("[parent] rpl->msgh_id: 0x%x\n", tmp->msgh_id);
    printf("[parent] rpl->msgh_local_port: %d\n", tmp->msgh_local_port);
    printf("[parent] rpl->msgh_remote_port: %d\n", tmp->msgh_remote_port);
    printf("[parent] rpl->msgh_size: 0x%x\n", tmp->msgh_size);
    printf("[parent] rpl->msgh_voucher_port: 0x%x\n", tmp->msgh_voucher_port);

    // we've parsed the exception and are ready to reply, resume the target
    // process
    kern_r = task_resume(target_task_port);
    // if (kern_r != KERN_SUCCESS) {
    //   printf("[parent] task_resume failed: %s (%d)\n", mach_error_string(kern_r), kern_r);
    //   return 1;
    // }

    // reply to the exception
    mach_msg_size_t send_sz = ((mach_msg_header_t *)rpl)->msgh_size;
    kern_r = mach_msg((mach_msg_header_t *)rpl, /* send buffer */
                      MACH_SEND_MSG,            /* send message */
                      send_sz,                  /* size of send buffer */
                      0,                        /* size of receive buffer */
                      MACH_PORT_NULL,           /* port to receive on */
                      MACH_MSG_TIMEOUT_NONE,    /* wait indefinitely */
                      MACH_PORT_NULL);
    assert(kern_r == KERN_SUCCESS && "mach_msg failed");
  }

  // clean up
  kern_r = mach_port_deallocate(mach_task_self(), target_task_port);
  assert(kern_r == KERN_SUCCESS && "mach_port_deallocate failed");

  return 0;
}
