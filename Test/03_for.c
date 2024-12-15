#include <stddef.h>

#define WSIZE 8*sizeof(int)

long pcount_for(unsigned long x) {
  long result = 0;
  size_t i;
  for(i = 0; i < WSIZE; i++) {
    unsigned long bit = (x >> i) & 0x1;
    result += bit;
  }
  return result;
}

int main() {}