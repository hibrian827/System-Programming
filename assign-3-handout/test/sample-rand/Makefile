

all: rand rand.disas

rand: rand.c
	gcc -Og -o $@ $^

rand.disas: rand
	objdump -d ./rand > rand.disas

clean:
	rm -f rand rand.disas
