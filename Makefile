CC = gcc

# Compile flags: add -MMD -MP to auto-generate .d files for header deps
CFLAGS = -O2 -Wall -MMD -MP \
    -Ithird_party/liboqs/build/include \
    -Ithird_party/rocksdb/include

# Linker flags (search paths, etc.) keep here; libraries go in LDLIBS
LDFLAGS =

# Libraries to link against
LDLIBS = third_party/liboqs/build/lib/liboqs.a \
         -lpthread -ldl -lrt -lgcc_s -lc
# If/when you want RocksDB, just uncomment the next line:
# LDLIBS += third_party/rocksdb/build/librocksdb.a

# Sources / objects / target
# SRC = scootchain.c db_wrapper.c
SRC = scootchain.c
OBJ = $(SRC:.c=.o)
DEPS = $(OBJ:.o=.d)
TARGET = scootchain

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Pattern rule to build .o (and .d via -MMD)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Include auto-generated dependency files so header changes trigger rebuilds
-include $(DEPS)

clean:
	rm -f $(OBJ) $(DEPS) $(TARGET)

# Build liboqs
liboqs:
	cd third_party/liboqs && mkdir -p build && cd build && \
	cmake -DBUILD_SHARED_LIBS=OFF -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON .. && \
	make -j1

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

