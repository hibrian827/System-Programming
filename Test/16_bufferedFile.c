#include <stdio.h>

int main(int argc, char *argv[]) {
  char buf[1024];
  FILE *infile = stdin;
  if (argc == 2) {
    infile = fopen(argv[1], "r");
  }
  while(fgets(buf, 1024, infile) != NULL) {
    fprintf(stdout, buf);
  }
}