#ifndef AHOCORASICK_H
#define AHOCORASICK_H

#include "string.h"
#include "stdlib.h"
#include "unistd.h"
#include "stdio.h"
#include "ctype.h"

#define MAX_CHARS 256

/* ahocorasick node */
typedef struct ac_node
{
    // 1 if true
    u_int8_t root;
    u_int8_t end_of_word;

    unsigned char *b;
    int index;
    struct ac_node *child[MAX_CHARS];
    struct ac_node *failure;
} ac_node;

/* Prototypes */
ac_node *ahocorasick_create_node();
void ahocorasick_insert(ac_node *root, const unsigned char *word, const int index, int case_insensitive);
void ahocorasick_build_failure_links(ac_node *root);
int ahocorasick_find_matches(ac_node *root, const unsigned char *text, int **matchIndices, int case_insensitive);
int ahocorasick_find_matches2(ac_node *root, const unsigned char *text, int **matchIndices, int case_insensitive);
void ahocorasick_free_trei(ac_node *current);
ac_node *ahocorasick_create_trie(const unsigned char **dictionary, int numWords, int case_insensitive);

#endif // AHOCORASICK_H