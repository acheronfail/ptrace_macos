#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  int seconds = argc > 1 ? atoi(argv[1]) : 2;
  printf("[child] Sleeping for %d seconds...\n", seconds);
  sleep(seconds);
  printf("[child] Now exiting...\n");
  return 0;
}
