CC = gcc
CFLAGS = -Wall -Werror

all: clean generate_stub build

generate_stub:
	as stub.S -o bin/stub.o
	objcopy -O binary -j .text bin/stub.o bin/stub.bin

build:
	$(CC) *.c -o bin/crypter $(CFLAGS)

clean:
	rm -f bin/crypter bin/stub.o bin/stub.bin