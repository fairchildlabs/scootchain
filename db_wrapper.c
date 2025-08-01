#include "db_wrapper.h"
#include <rocksdb/c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static rocksdb_t *db = NULL;
static rocksdb_options_t *options = NULL;
static char *err = NULL;

bool db_init(const char *path) {
    options = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(options, 1);

    db = rocksdb_open(options, path, &err);
    if (err) {
        fprintf(stderr, "RocksDB open error: %s\n", err);
        free(err);
        err = NULL;
        return false;
    }
    return true;
}

bool db_put(const char *key, const char *value) {
    rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
    rocksdb_put(db, woptions, key, strlen(key), value, strlen(value), &err);
    rocksdb_writeoptions_destroy(woptions);

    if (err) {
        fprintf(stderr, "RocksDB put error: %s\n", err);
        free(err);
        err = NULL;
        return false;
    }
    return true;
}

char *db_get(const char *key) {
    size_t val_len;
    rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
    char *val = rocksdb_get(db, roptions, key, strlen(key), &val_len, &err);
    rocksdb_readoptions_destroy(roptions);

    if (err) {
        fprintf(stderr, "RocksDB get error: %s\n", err);
        free(err);
        err = NULL;
        return NULL;
    }
    if (!val) return NULL;

    char *result = malloc(val_len + 1);
    memcpy(result, val, val_len);
    result[val_len] = '\0';
    free(val);
    return result;
}

void db_close() {
    if (db) rocksdb_close(db);
    if (options) rocksdb_options_destroy(options);
}

