CC=gcc
CFLAGS=-I ./includes -Wall -Werror

dropper: dropper.c
	mkdir -p bin
	$(CC) -o ./bin/dropper dropper.c $(CFLAGS)

clean:
	rm -f ./bin/dropper dropper.o
