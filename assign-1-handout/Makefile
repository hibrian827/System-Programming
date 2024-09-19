CFLAGS += -fno-asynchronous-unwind-tables
CFLAGS += -fcf-protection=none

all: main

main: main.o sort_tree.o
	gcc $^ -o $@

main.o: main.c
	gcc $(CFLAGS) -c $< -o $@

sort_tree.o: sort_tree.s
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm -f main *.o
