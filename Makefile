CC = gcc
CFLAGS = -O2 -Wall \
    -Iinc \
    -Ithird_party/liboqs/build/include \
    -Ithird_party/rocksdb/include
LDFLAGS = \
    third_party/liboqs/build/lib/liboqs.a \
#    third_party/rocksdb/build/librocksdb.a \
    -lpthread -ldl -lrt -lgcc_s -lc

#SRC = scootchain.c db_wrapper.c
SRC = scootchain.c 
OBJ = $(SRC:.c=.o)
TARGET = scootchain

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

# Build liboqs
liboqs:
	cd third_party/liboqs && mkdir -p build && cd build && cmake -DBUILD_SHARED_LIBS=OFF -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON .. && make -j1

# Build RocksDB without gflags/snappy/zlib
rocksdb:
	cd third_party/rocksdb && rm -rf build && mkdir -p build && cd build && \
	cmake -DCMAKE_BUILD_TYPE=Release \
	      -DROCKSDB_BUILD_SHARED=OFF \
	      -DROCKSDB_BUILD_STATIC=ON \
	      -DROCKSDB_BUILD_TESTS=OFF \
	      -DROCKSDB_BUILD_BENCHMARKS=OFF \
	      -DWITH_SNAPPY=OFF \
	      -DWITH_ZLIB=OFF \
	      -DWITH_LZ4=OFF \
	      -DWITH_ZSTD=OFF \
	      -DWITH_BZ2=OFF \
	      -DWITH_GFLAGS=OFF \
	      -DPORTABLE=ON \
	      .. && \
	make -j1

# Build everything
deps: liboqs rocksdb

.PHONY: all clean liboqs rocksdb deps

