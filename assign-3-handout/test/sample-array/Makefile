

all: array array.disas

array: array.c
	gcc -Og -o $@ $^

array.disas: array
	objdump -d ./array > array.disas

clean:
	rm -f array array.disas
