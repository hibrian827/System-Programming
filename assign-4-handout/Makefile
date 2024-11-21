# Makefile for the CS:APP Shell Lab

TSHARGS = "-p"
CC = gcc
CFLAGS = -Wall -O2 -g
TESTS := $(patsubst traces/%.trace, %, $(wildcard traces/*.trace))
APPS := $(patsubst %.c, %, $(wildcard apps/*.c))

FILES = tsh $(APPS)

all: $(FILES)

test: tsh tsh_ref
	tools/run-test.py $(TESTS)

# clean up
clean:
	rm -f $(FILES) *.o *~
	rm -f $(APPS)
	rm -rf output-tests


