#include <unistd.h>
#include <stdio.h>

int main() {
  printf("[child] Sleeping for 2 seconds...\n");
  sleep(2);
  printf("[child] Now exiting...\n");
  return 0;
}
