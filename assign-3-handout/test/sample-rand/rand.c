#include <time.h>
#include <stdio.h>
#include <stdlib.h>

unsigned int rand_value = 0x1234;

void pass(void) {
    printf("Congrats! You got this right!\n");
}

void fail(void) {
    printf("Wrong answer. Your rand_value was %x\n", rand_value);
}

int check(void) {
    if (rand_value == 0xaabbccdd)
        pass();
    else
        fail();
}

int main(int argc, char* argv[]) {
    srand(time(0));
    rand_value = rand();

    check();
    return 0;
}
