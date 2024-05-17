
#include "detect.h"

void print_match(match_t *m)
{
    printf("\n");
    printf("line number: %d\n", m->line_no);
    printf("capture: %s\n", m->capture);
    printf("match: %s\n", m->match);
    printf("rule-id: %s\n", m->rule_id);
    printf("file path: %s\n", m->file_path);
    if (m->entropy > 0)
    {
        printf("entropy: %f\n", m->entropy);
    }
}

void free_match(match_t *match)
{
    free(match->rule_id);
    free(match->capture);
    free(match->match);
    free(match->hash_key);
    free(match->file_path);
    free(match);
}

int detect_secrets(char *buffer, char *file_path, int start_line_number, size_t bytes_read, match_t **matches, int more_to_read)
{
    int total_matches = 0;

    // Find matches using Aho-Corasick
    int *match_indices = NULL;
    int num_ahocorasick_matches = ahocorasick_find_matches(
        config->root, (unsigned char *)buffer, &match_indices, CASE_INSENSITIVE);

    str_hash *seen_keywords_table = NULL;
    str_hash *seen_rules_table = NULL;

    char *lower_capture = malloc(bytes_read + 1);
    char *capture = malloc(bytes_read + 1);

    for (int i = 0; i < num_ahocorasick_matches; i++)
    {
        // Grab the keyword from the dictionary of ahocorasick matches
        char *keyword = (char *)config->dictionary[match_indices[i]];
        if (is_in_hash(seen_keywords_table, keyword))
        {
            continue;
        }
        add_to_hash(&seen_keywords_table, keyword);

        int rule_count = 0;
        // Lookup the rules for the keyword. Remember that a keyword can be shared
        // by multiple rules
        rule_list *rules = find_rules_for_keyword(config->rule_table, keyword);

        // Set up the Oniguruma region to store the match information
        OnigRegion *region = onig_region_new();
        while (rules)
        {
            Rule *rule = rules->rule;
            rules = rules->next;
            if (is_in_hash(seen_rules_table, rule->id))
            {
                LOG_DEBUG("skipping rule %s since rule has been tried for this region "
                          "already",
                          rule->id);
                continue;
            }
            add_to_hash(&seen_rules_table, rule->id);

            UChar *start = (UChar *)buffer;
            UChar *end = (UChar *)(buffer + bytes_read);
            UChar *search_start = start;
            UChar *line_start = start; // Keep track of the start of each line
            int r;
            int line_number = 1; // Start from line 1

            // This search is done in a loop to find all matches in the buffer
            while ((r = onig_search(rule->compiled_regex, start, end,
                                    search_start, end, region, ONIG_OPTION_NONE)) >=
                   0)
            {
                int match_start = region->beg[0];
                int match_end = region->end[0];
                int match_length = match_end - match_start;

                // skip the last match if we are at the end of the buffer
                // since we'll catch it on the next iteration
                if ((match_end == bytes_read) && more_to_read)
                {
                    goto end_of_matches;
                }

                LOG_DEBUG("%.*s\n", match_length, (char *)start + match_start);

                // Iterate over the capture groups to extract the matched strings
                for (int i = 1; i < region->num_regs; i++)
                {
                    int capture_start = region->beg[i];
                    int capture_end = region->end[i];

                    // Update the line number
                    for (UChar *p = line_start; p < start + match_start; p++)
                    {
                        if (*p == '\n')
                        {
                            line_number++;
                            line_start = p + 1; // Update line start to position after newline
                        }
                    }

                    int capture_length = capture_end - capture_start;
                    memcpy(capture, (char *)start + capture_start, capture_length);
                    capture[capture_length] = '\0';

                    // Check if the capture group contains a stopword
                    int stopword_present = 0;
                    if (rule->num_stopwords > 0)
                    {
                        // Convert the capture to lowercase for comparing with stopwords
                        memcpy(lower_capture, (char *)start + capture_start,
                               capture_length);
                        lower_capture[capture_length] = '\0';
                        to_lower_case(lower_capture);

                        // check if a stopword is in the capture group
                        if (contains_stopword(lower_capture, rule))
                        {
                            stopword_present = 1;
                        }
                    }

                    if (!stopword_present && capture_start >= 0 && capture_end >= 0)
                    {
                        char *full_match = malloc(match_length + 1);
                        memcpy(full_match, (char *)start + match_start, match_length);
                        full_match[match_length] = '\0';

                        if (start + match_end > line_start && *(start + match_end - 1) == '\n')
                        {
                            line_number++;
                            line_start = start + match_end;
                        }

                        int secret_found = 0;
                        if (rule->entropy == 0.0)
                        {
                            secret_found = 1;
                        }
                        else if (rule->entropy > 0.0 && shannon_entropy(capture) > rule->entropy)
                        {
                            secret_found = 1;
                        }

                        // sanity check for generic secrets...
                        // this is borred from gitleas but basically if we encounter a generic secret
                        // we want to ensure that it has both alpha _and_ numeric characters
                        if (secret_found == 1 && strstr(rule->id, "generic") != NULL)
                        {
                            int has_alpha = 0;
                            int has_digit = 0;
                            for (int i = 0; i < capture_length; i++)
                            {
                                if (isalpha(capture[i]))
                                {
                                    has_alpha = 1;
                                }
                                if (isdigit(capture[i]))
                                {
                                    has_digit = 1;
                                }
                            }
                            if (has_alpha == 0 || has_digit == 0)
                            {
                                secret_found = 0;
                            }
                        }

                        // Create a match if the secret is found
                        if (secret_found == 1)
                        {
                            // add match to match table
                            match_t *match = malloc(sizeof(match_t));
                            match->capture = strdup(capture);
                            match->line_no = start_line_number + line_number;
                            match->rule_id = strdup(rule->id);
                            match->match = strdup(full_match);
                            match->entropy = shannon_entropy(capture);
                            match->file_path = strdup(file_path);

                            // Generate the hash key
                            char *hash_key = malloc(snprintf(NULL, 0, "%d%s", match->line_no, match->capture) + 1);
                            sprintf(hash_key, "%d%s", match->line_no, match->capture);
                            match->hash_key = strdup(hash_key);

                            // Look up the existing match with the same hash key to prevent duplicates
                            // or replace generic matches with specific matches
                            match_t *existing_match;
                            HASH_FIND_STR(*matches, match->hash_key, existing_match);
                            if (existing_match != NULL)
                            {
                                if (strstr(existing_match->rule_id, "generic") != NULL && strstr(match->rule_id, "generic") == NULL)
                                {
                                    // Replace the existing generic match with the current specific match
                                    HASH_DELETE(hh, *matches, existing_match);
                                    free_match(existing_match);
                                    HASH_ADD_KEYPTR(hh, *matches, match->hash_key, strlen(match->hash_key), match);
                                    total_matches--;
                                }
                                else
                                {
                                    // Discard the current match if it's generic and the existing match is specific
                                    free_match(match);
                                    // total_matches--;
                                }
                            }
                            else
                            {
                                HASH_ADD_KEYPTR(hh, *matches, match->hash_key, strlen(match->hash_key), match);
                                total_matches++;
                            }
                            free(hash_key);
                        }
                        free(full_match);
                    }
                }

            end_of_matches:
                // If the start position reaches the end of the buffer, break the loop
                if (search_start >= end)
                {
                    break;
                }

                // Move the start position to the end of the current match
                search_start = start + match_end;
            }
            onig_region_clear(region);

            if (r < 0 && r != ONIG_MISMATCH)
            {
                // Error occurred during regex matching
                UChar err_buf[ONIG_MAX_ERROR_MESSAGE_LEN];
                onig_error_code_to_str(err_buf, r);
                fprintf(stderr, "Regex matching error: %s for rule: %s\n", rule->id,
                        err_buf);
            }
        }
        onig_region_free(region, 1);
        free(rules);
    }

    delete_hash(&seen_keywords_table);
    delete_hash(&seen_rules_table);
    free(match_indices);
    free(capture);
    free(lower_capture);

    return total_matches;
}