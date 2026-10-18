# Makefile for TRACEWISE-Lite Vulnerable Samples

CC = gcc
CFLAGS = -g -O0 -fno-stack-protector -z execstack -no-pie
LDFLAGS =
TARGETS = buffer_overflow use_after_free format_string integer_overflow

.PHONY: all clean

all: $(TARGETS)

buffer_overflow: buffer_overflow.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

use_after_free: use_after_free.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

format_string: format_string.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

integer_overflow: integer_overflow.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

# Create test inputs
seeds:
	mkdir -p seeds
	echo "INIT" > seeds/seed_1.txt
	echo "TEST" > seeds/seed_2.txt
	python3 -c "print('A'*200)" > seeds/large_input.txt