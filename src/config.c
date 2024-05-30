#include "config.h"

Config_t *config;

void add_rule_to_keyword(keyword_hash **hash_table, const char *keyword, Rule *rule)
{
    keyword_hash *s;
    HASH_FIND_STR(*hash_table, keyword, s);
    if (s == NULL)
    {
        s = (keyword_hash *)malloc(sizeof(keyword_hash));
        s->keyword = strdup(keyword);
        s->rules = NULL;
        HASH_ADD_KEYPTR(hh, *hash_table, s->keyword, strlen(s->keyword), s);
    }
    rule_list *rule_node = (rule_list *)malloc(sizeof(rule_list));
    rule_node->rule = rule;
    rule->ref_count++; // Increment the reference count
    rule_node->next = s->rules;
    s->rules = rule_node;
}

rule_list *find_rules_for_keyword(keyword_hash *hash_table, const char *keyword)
{
    keyword_hash *s;
    HASH_FIND_STR(hash_table, keyword, s);
    return s ? s->rules : NULL;
}

void free_rule(Rule *rule)
{
    if (rule && --rule->ref_count == 0)
    { // Decrement ref_count and check if it's zero
        free(rule->id);
        free(rule->description);
        free(rule->regex);
        onig_free(rule->compiled_regex); // Assuming onig_free safely

        for (int j = 0; j < rule->num_keywords; j++)
        {
            free(rule->keywords[j]);
        }
        free(rule->keywords);

        for (int j = 0; j < rule->num_stopwords; j++)
        {
            free(rule->stopwords[j]);
        }
        free(rule->stopwords);
        free(rule);
    }
}

void free_keyword_hash(keyword_hash **hash_table)
{
    keyword_hash *current, *tmp;
    HASH_ITER(hh, *hash_table, current, tmp)
    {
        rule_list *list = current->rules;
        while (list)
        {
            rule_list *tmp = list;
            Rule *rule = tmp->rule;
            free_rule(rule);
            list = list->next;
            free(tmp);
        }
        HASH_DEL(*hash_table, current);
        free(current->keyword);
        free(current);
    }
}

void free_config(Config_t *config)
{
    if (config == NULL)
    {
        return;
    }
    ahocorasick_free_trei(config->root);
    free(config->dictionary);
    free_keyword_hash(&(config->rule_table));
    printf("done freeing\n");
    free(config);
}

void load_config(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL)
    {
        LOG_ERROR("Error opening file");
        exit(1);
    }

    Rule **rules = NULL;

    char errbuf[200];
    toml_table_t *conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
    if (conf == NULL)
    {
        LOG_ERROR("Error parsing config: %s", errbuf);
        exit(1);
    }

    toml_array_t *rules_toml = toml_array_in(conf, "rules");
    if (!rules_toml)
    {
        LOG_ERROR("No [rules] supplied in config");
        toml_free(conf);
        exit(1);
    }

    config = (Config_t *)malloc(sizeof(Config_t));
    if (config == NULL)
    {
        LOG_ERROR("Failed to allocate memory for config");
        toml_free(conf);
        exit(1);
    }

    // Get the number of rules
    int rule_count = toml_array_nelem(rules_toml);

    // Allocate memory for the rules array
    rules = (Rule **)malloc(rule_count * sizeof(Rule *));
    config->rule_table = NULL;
    config->num_words_in_dictionary = 0;

    if (rules == NULL)
    {
        LOG_ERROR("Failed to allocate memory for rules array");
        free(config);
        toml_free(conf);
        exit(1);
    }

    int num_rules = 0;

    // Iterate over the rules and load them into the config
    for (int i = 0; i < rule_count; i++)
    {
        toml_table_t *rule_d = toml_table_at(rules_toml, i);

        toml_datum_t _id = toml_string_in(rule_d, "id");
        const char *id = strdup(_id.u.s);
        free(_id.u.s);

        toml_datum_t _desc = toml_string_in(rule_d, "description");
        const char *description = strdup(_desc.u.s);
        free(_desc.u.s);

        toml_datum_t _regex = toml_string_in(rule_d, "regex");
        const char *regex = strdup(_regex.u.s);
        free(_regex.u.s);

        const char *raw_entropy = toml_raw_in(rule_d, "entropy");
        const float entropy = raw_entropy ? atof(raw_entropy) : 0.0;

        toml_array_t *kw = toml_array_in(rule_d, "keywords");
        int num_keywords = toml_array_nelem(kw);
        char **keywords = malloc(num_keywords * sizeof(char *));
        if (keywords == NULL)
        {
            printf("NO KEYWORDS");
            LOG_ERROR("Failed to allocate memory for keyword pointers");
            continue;
        }

        for (int j = 0; j < num_keywords; j++)
        {
            toml_datum_t keyword = toml_string_at(kw, j);
            keywords[j] = strdup(keyword.u.s);
            free(keyword.u.s);
        }

        // traverse the allowlist table if it exists
        toml_table_t *allowlist_d = toml_table_in(rule_d, "allowlist");
        char **stopwords = NULL;
        int num_stopwords = 0;
        toml_array_t *sw = NULL;

        char **paths = NULL;
        int num_paths = 0;

        char **regexes = NULL;
        OnigRegex **compiled_regexes = NULL;
        int num_regexes = 0;

        toml_array_t *p = NULL;
        toml_array_t *res = NULL;

        if (allowlist_d)
        {
            printf("Found allowlist!\n");
            sw = toml_array_in(allowlist_d, "stopwords");
            if (sw)
            {
                num_stopwords = toml_array_nelem(sw);
                if (num_stopwords > 0)
                {
                    stopwords = malloc(num_stopwords * sizeof(char *));
                    if (stopwords == NULL)
                    {
                        LOG_ERROR("Failed to allocate memory for stopword pointers");
                        continue;
                    }

                    for (int j = 0; j < num_stopwords; j++)
                    {
                        toml_datum_t stopword = toml_string_at(sw, j);
                        stopwords[j] = strdup(stopword.u.s);
                        free(stopword.u.s);
                    }
                }
            }
            p = toml_array_in(allowlist_d, "paths");
            if (p)
            {
                num_paths = toml_array_nelem(p);
                if (num_paths > 0)
                {
                    paths = malloc(num_paths * sizeof(char *));
                    if (paths == NULL)
                    {
                        LOG_ERROR("Failed to allocate memory for paths pointers");
                        continue;
                    }

                    for (int j = 0; j < num_paths; j++)
                    {
                        toml_datum_t path = toml_string_at(p, j);
                        paths[j] = strdup(path.u.s);
                        free(path.u.s);
                    }
                }
            }

            res = toml_array_in(allowlist_d, "regexes");
            if (res)
            {
                // printf("Found stopwords!\n");
                num_regexes = toml_array_nelem(res);
                if (num_regexes > 0)
                {
                    regexes = malloc(num_regexes * sizeof(char *));
                    if (regexes == NULL)
                    {
                        LOG_ERROR("Failed to allocate memory for allowlist regexes");
                        continue;
                    }

                    for (int j = 0; j < num_regexes; j++)
                    {
                        toml_datum_t regex = toml_string_at(res, j);
                        regexes[j] = strdup(regex.u.s);
                        free(regex.u.s);
                    }
                }

                compiled_regexes = malloc(num_regexes * sizeof(OnigRegex *));
                for (int j = 0; j < num_regexes; j++)
                {
                    printf("allowlist regexes: %s\n", regexes[j]);
                    OnigErrorInfo einfo;
                    int r = onig_new(&compiled_regexes[j], (OnigUChar *)regexes[j], (OnigUChar *)(regexes[j] + strlen(regexes[j])),
                                     ONIG_OPTION_DEFAULT, ONIG_ENCODING_UTF8, ONIG_SYNTAX_DEFAULT, &einfo);
                    if (r != ONIG_NORMAL)
                    {
                        char s[ONIG_MAX_ERROR_MESSAGE_LEN];
                        onig_error_code_to_str((OnigUChar *)s, r, &einfo);
                        LOG_WARNING("Regex compilation failed: %s for rule %s", s, id);
                        return;
                    }
                }
            }
        }

        // create rule
        Rule *rule = (Rule *)malloc(sizeof(Rule));

        if (rule == NULL)
        {
            LOG_WARNING("Failed to allocate memory for rule");
            return;
        }

        rule->id = id;
        rule->description = description;
        rule->regex = regex;
        rule->entropy = entropy;
        rule->num_stopwords = 0;
        rule->num_keywords = 0;

        OnigErrorInfo einfo;
        int r = onig_new(&rule->compiled_regex, (OnigUChar *)regex, (OnigUChar *)(regex + strlen(regex)),
                         ONIG_OPTION_DEFAULT, ONIG_ENCODING_UTF8, ONIG_SYNTAX_DEFAULT, &einfo);
        if (r != ONIG_NORMAL)
        {
            char s[ONIG_MAX_ERROR_MESSAGE_LEN];
            onig_error_code_to_str((OnigUChar *)s, r, &einfo);
            LOG_WARNING("Regex compilation failed: %s for rule %s", s, id);
            return;
        }

        // Set up keywords
        if (num_keywords > 0)
        {
            rule->keywords = (char **)malloc(num_keywords * sizeof(char *));
            if (rule->keywords == NULL)
            {
                LOG_WARNING("Failed to allocate memory for keywords");
                return;
            }
            for (int i = 0; i < num_keywords; i++)
            {
                rule->keywords[i] = strdup(keywords[i]);
                to_lower_case(rule->keywords[i]);
            }
            rule->num_keywords = num_keywords;
        }

        // Set up allowlist
        allowlist_t *allowlist = (allowlist_t *)malloc(sizeof(allowlist_t));

        // Set up stop words
        if (num_stopwords > 0)
        {
            allowlist->stopwords = (char **)malloc(num_stopwords * sizeof(char *));
            if (allowlist->stopwords == NULL)
            {
                LOG_WARNING("Failed to allocate memory for stopwords");
                return;
            }
            for (int i = 0; i < num_stopwords; i++)
            {
                allowlist->stopwords[i] = strdup(stopwords[i]);
                to_lower_case(allowlist->stopwords[i]);
            }
            allowlist->num_stopwords = num_stopwords;
        }
        // Set up regex allows
        if (num_regexes > 0)
        {
            allowlist->compiled_regexes = compiled_regexes;
            allowlist->num_regexes = num_regexes;
        }

        // Set up paths
        if (num_paths > 0)
        {
            allowlist->paths = (char **)malloc(num_paths * sizeof(char *));
            if (allowlist->paths == NULL)
            {
                LOG_WARNING("Failed to allocate memory for paths");
                return;
            }
            for (int i = 0; i < num_paths; i++)
            {
                allowlist->paths[i] = strdup(paths[i]);
                to_lower_case(allowlist->paths[i]);
            }
            allowlist->num_paths = num_paths;
        }

        rule->allowlist = allowlist;

        // Free copies of keywords and stopwords
        for (int j = 0; j < num_keywords; j++)
        {
            free(keywords[j]);
        }
        free(keywords);

        if (sw)
        {
            for (int j = 0; j < num_stopwords; j++)
            {
                free(stopwords[j]);
            }
            free(stopwords);
        }

        rules[num_rules++] = rule;
        for (int j = 0; j < rule->num_keywords; j++)
        {
            add_rule_to_keyword(&config->rule_table, rule->keywords[j], rule);
            config->num_words_in_dictionary++;
        }
    }

    config->dictionary = (unsigned char **)malloc(config->num_words_in_dictionary * sizeof(unsigned char *));
    if (config->dictionary == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for dictionary\n");
        return;
    }

    int dict_index = 0;
    for (int i = 0; i < num_rules; i++)
    {
        Rule *rule = rules[i];
        for (int j = 0; j < rule->num_keywords; j++)
        {
            config->dictionary[dict_index] = (unsigned char *)rule->keywords[j];
            dict_index++;
        }
    }
    printf("total keywords: %d\n", config->num_words_in_dictionary);

    config->root = ahocorasick_create_trie(config->dictionary, config->num_words_in_dictionary, CASE_INSENSITIVE);
    free(rules);
    toml_free(conf);
    return;
}

// discord_client_secret = '8dyfuiRyq=vVc3RRr_edRk-fK__'

int contains_stopword(char *capture, Rule *rule)
{
    if (rule->allowlist == NULL)
    {
        return 0;
    }
    if (rule->allowlist->num_stopwords == 0)
    {
        return 0;
    }

    for (int i = 0; i < rule->allowlist->num_stopwords; i++)
    {
        if (strstr(capture, rule->allowlist->stopwords[i]) != NULL)
        {
            return 1;
        }
    }

    return 0;
}