macos_sdk := "/Library/Developer/CommandLineTools/SDKs/MacOSX14.4.sdk/"

_default:
  @just -l

_mig:
  rm -rf mig
  mkdir -p mig
  cd mig && mig -arch arm64 {{macos_sdk}}/usr/include/mach/mach_exc.defs
  cd mig && gcc -c *.c

# build everything
build: _mig
  gcc -o tracee tracee.c
  gcc -sectcreate __TEXT __info_plist Info.plist -o tracer tracer.c mig/*.o

# run the tracer with the tracee program
run: build
  sudo ./tracer ./tracee 1

# run the tracer with the provided command
trace +cmd: build
  sudo ./tracer {{cmd}}
