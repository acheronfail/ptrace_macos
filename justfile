macos_sdk := "/Library/Developer/CommandLineTools/SDKs/MacOSX14.4.sdk/"

_default:
  just -l

mig:
  #!/usr/bin/env bash
  rm -rf mig
  mkdir -p mig
  cd mig

  mig -arch arm64 {{macos_sdk}}/usr/include/mach/mach_exc.defs
  gcc -c *.c

run:
  just mig
  gcc -o child child.c
  gcc -sectcreate __TEXT __info_plist Info.plist -o main main.c mig/*.o
  sudo ./main ./child
