long pcount_while(unsigned long x) {
  long result = 0;
  while(x) {
    result += x & 0x1;
    x >>= 1;
  }
  return result;
}

int main() {}