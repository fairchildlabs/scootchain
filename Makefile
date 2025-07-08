# Makefile for scootchain

CC = gcc
CFLAGS = -O2 -Wall -Ithird_party/liboqs/build/include
LDFLAGS = third_party/liboqs/build/lib/liboqs.a
TARGET = scootchain
SRC = scootchain.c

.PHONY: all clean oqs

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

oqs:
	@mkdir -p third_party/liboqs/build
	cd third_party/liboqs && \
	cmake -B build -DCMAKE_INSTALL_PREFIX=build -DBUILD_SHARED_LIBS=OFF -DOQS_USE_OPENSSL=OFF && \
	cmake --build build


clean:
	rm -f $(TARGET)
	rm -rf third_party/liboqs/build

