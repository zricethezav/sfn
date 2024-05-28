#ifndef DETECT_H
#define DETECT_H

#include "config.h"
#include "util.h"
#include "toml.h"
#include "oniguruma.h"
#include "uthash.h"

#include <dirent.h>
#include <ctype.h>
#include <math.h>
#include <sys/stat.h>

typedef struct
{
    // start idx in buf
    int start;
    // end idx in buf
    int end;
    // rule id
    char *rule_id;
    // line number
    int line_no;
    // captured group, aka the secret
    char *capture;
    // full match of secret regex
    char *match;
    // entropy if needed, defaults to 0
    float entropy;
    // file path
    char *file_path;
    // use hash table to store matches from files
    char *hash_key;
    UT_hash_handle hh;
} match_t;

/* Prototypes */
int detect_secrets(char *buffer, char *file_path, int line_number, size_t bytes_read, match_t **matches, int more_to_read);
void free_match(match_t *match);
void print_match(match_t *m);

#endif // DETECT_H