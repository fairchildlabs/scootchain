#ifndef DB_WRAPPER_H
#define DB_WRAPPER_H

#include <stdbool.h>

bool db_init(const char *path);
bool db_put(const char *key, const char *value);
char *db_get(const char *key); // Caller must free()
void db_close();

#endif

