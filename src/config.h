#ifndef CONFIG_H
#define CONFIG_H

#include "ahocorasick.h"
#include "log.h"
#include "toml.h"
#include "uthash.h"
#include "util.h"
#include <oniguruma.h>

#define CASE_INSENSITIVE 1

/* Rule structure */
typedef struct
{
  char *id;
  char *description;
  char *regex;
  OnigRegex compiled_regex;
  char **keywords;
  char **stopwords;
  float entropy;
  int num_keywords;
  int num_stopwords;
  int ref_count; // Reference count
} Rule;

/* A structure to hold a list of rules associated with a keyword */
typedef struct rule_list
{
  Rule *rule;
  struct rule_list *next;
} rule_list;

typedef struct keyword_hash
{
  char *keyword;     // Key: the keyword
  rule_list *rules;  // List of rules associated with this keyword
  UT_hash_handle hh; // makes this structure hashable
} keyword_hash;

/* Config_t structure */
typedef struct
{
  /* Hashmap of rules for quick lookup */
  keyword_hash *rule_table;

  /* Dictionary of keywords for Aho-Corasick */
  unsigned char **dictionary;
  int num_words_in_dictionary;

  /* Aho-Corasick root node */
  ac_node *root;

} Config_t;

// Global config
extern Config_t *config;

/* Prototypes */
void load_config(const char *path);
void free_config(Config_t *config);
int contains_stopword(char *capture, Rule *rule);
void add_rule_to_keyword(keyword_hash **hash_table, const char *keyword, Rule *rule);
rule_list *find_rules_for_keyword(keyword_hash *hash_table, const char *keyword);
void free_keyword_hash(keyword_hash **hash_table);

#endif // CONFIG_H