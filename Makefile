# Makefile for scootchain

CC = gcc
CFLAGS = -O2 -Wall -Ithird_party/liboqs/include
LDFLAGS = third_party/liboqs/build/lib/liboqs.a
TARGET = scootchain
SRC = scootchain.c

.PHONY: all clean oqs

all: oqs $(TARGET)

oqs:
    @mkdir -p third_party/liboqs/build
    cd third_party/liboqs && \
        cmake -B build -DCMAKE_INSTALL_PREFIX=build -DBUILD_SHARED_LIBS=OFF && \
        cmake --build build

$(TARGET): $(SRC)
    $(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
    rm -f $(TARGET)
    rm -rf third_party/liboqs/build

