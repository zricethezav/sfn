#ifndef UTIL_H
#define UTIL_H

#include "uthash.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

#define KB 1024

typedef struct
{
    char *id;          // key
    UT_hash_handle hh; // makes this structure hashable
} str_hash;

void to_lower_case(char *str);
float shannon_entropy(char *s);
void add_to_hash(str_hash **hash_table, const char *id);
int is_in_hash(str_hash *hash_table, const char *id);
void delete_hash(str_hash **hash_table);
int is_binary(const void *buf, const size_t buf_len);

#endif // UTIL_H