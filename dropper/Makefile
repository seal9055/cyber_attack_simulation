CC=gcc
CFLAGS=-I ./includes -Wall -Werror

dropper: dropper.c
	mkdir -p bin
	as dropper.S -o bin/dropper.o
	objcopy -O binary -j .text bin/dropper.o bin/dropper.bin

	$(CC) -o ./bin/dropper dropper.c $(CFLAGS)

clean:
	rm -f ./bin/dropper dropper.o