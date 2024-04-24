macos_sdk := "/Library/Developer/CommandLineTools/SDKs/MacOSX14.4.sdk/"

_default:
  just -l

mig:
  rm -rf mig
  mkdir -p mig
  cd mig && mig -arch arm64 {{macos_sdk}}/usr/include/mach/mach_exc.defs
  cd mig && gcc -c *.c

run: mig
  gcc -o tracee tracee.c
  gcc -sectcreate __TEXT __info_plist Info.plist -o tracer tracer.c mig/*.o
  sudo ./tracer ./tracee 1
