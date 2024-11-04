#include <time.h>
#include <stdio.h>
#include <stdlib.h>


#define NUM_ITEMS 64
unsigned char xs[NUM_ITEMS];
int ys[NUM_ITEMS];
int zs[NUM_ITEMS];

int main(int argc, char* argv[]) {

    for (int i=0; i<NUM_ITEMS; i++) {
        xs[i] = i%256;
        ys[i] = i;
        zs[i] = i*i;
    }
    return 0;
}
