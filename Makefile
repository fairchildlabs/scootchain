CC = gcc
CFLAGS = -O2 -Wall -Ithird_party/liboqs/build/include
LDFLAGS = third_party/liboqs/build/lib/liboqs.a

all: scootchain

scootchain: scootchain.c
	$(CC) $(CFLAGS) scootchain.c -o scootchain $(LDFLAGS)

clean:
	rm -f scootchain

