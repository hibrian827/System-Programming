#include <stdio.h>
#include <string.h>

#define NAME_LEN 32

void copy_name(char *src) {
  char name[NAME_LEN];
  strcpy(name ,src);
  printf("My name is %s\n", name);
  return;
}

int main(int argc, char *argv[]) {
  if(argc < 2) return -1;
  copy_name(argv[1]);
  return 0;
}
