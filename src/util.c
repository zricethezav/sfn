#include "util.h"

void to_lower_case(char *str)
{
    if (str == NULL)
        return; // Handle NULL pointer if passed inadvertently

    while (*str)
    {
        *str = tolower((unsigned char)*str); // Convert each character to lowercase
        str++;
    }
}

float shannon_entropy(char *s)
{
    int len = strlen(s);
    int freq[256] = {0};
    for (int i = 0; i < len; i++)
    {
        freq[(unsigned char)s[i]]++;
    }

    float entropy = 0.0;
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] == 0)
        {
            continue;
        }
        float p = (float)freq[i] / len;
        entropy -= p * log2(p);
    }

    return entropy;
}

void add_to_hash(str_hash **hash_table, const char *id)
{
    str_hash *s;
    HASH_FIND_STR(*hash_table, id, s); // id already in the hash?
    if (s == NULL)
    {
        s = (str_hash *)malloc(sizeof(str_hash));
        s->id = strdup(id); // copy the key
        HASH_ADD_KEYPTR(hh, *hash_table, s->id, strlen(s->id), s);
    }
}

int is_in_hash(str_hash *hash_table, const char *id)
{
    str_hash *s;
    HASH_FIND_STR(hash_table, id, s);
    return s != NULL;
}

void delete_hash(str_hash **hash_table)
{
    str_hash *current_item, *tmp;
    HASH_ITER(hh, *hash_table, current_item, tmp)
    {
        HASH_DEL(*hash_table, current_item); // delete; users: remember to free any malloc'ed memory
        free(current_item->id);
        free(current_item);
    }
}

/* This function is very hot. It's called on every file. Borrowed from AG, the silver searcher*/
int is_binary(const void *buf, const size_t buf_len)
{
    size_t suspicious_bytes = 0;
    size_t total_bytes = buf_len > 512 ? 512 : buf_len;
    const unsigned char *buf_c = buf;
    size_t i;

    if (buf_len == 0)
    {
        /* Is an empty file binary? Is it text? */
        return 0;
    }

    if (buf_len >= 3 && buf_c[0] == 0xEF && buf_c[1] == 0xBB && buf_c[2] == 0xBF)
    {
        /* UTF-8 BOM. This isn't binary. */
        return 0;
    }

    if (buf_len >= 5 && strncmp(buf, "%PDF-", 5) == 0)
    {
        /* PDF. This is binary. */
        return 1;
    }

    for (i = 0; i < total_bytes; i++)
    {
        if (buf_c[i] == '\0')
        {
            /* NULL char. It's binary */
            return 1;
        }
        else if ((buf_c[i] < 7 || buf_c[i] > 14) && (buf_c[i] < 32 || buf_c[i] > 127))
        {
            /* UTF-8 detection */
            if (buf_c[i] > 193 && buf_c[i] < 224 && i + 1 < total_bytes)
            {
                i++;
                if (buf_c[i] > 127 && buf_c[i] < 192)
                {
                    continue;
                }
            }
            else if (buf_c[i] > 223 && buf_c[i] < 240 && i + 2 < total_bytes)
            {
                i++;
                if (buf_c[i] > 127 && buf_c[i] < 192 && buf_c[i + 1] > 127 && buf_c[i + 1] < 192)
                {
                    i++;
                    continue;
                }
            }
            suspicious_bytes++;
            /* Disk IO is so slow that it's worthwhile to do this calculation after every suspicious byte. */
            /* This is true even on a 1.6Ghz Atom with an Intel 320 SSD. */
            /* Read at least 32 bytes before making a decision */
            if (i >= 32 && (suspicious_bytes * 100) / total_bytes > 10)
            {
                return 1;
            }
        }
    }
    if ((suspicious_bytes * 100) / total_bytes > 10)
    {
        return 1;
    }

    return 0;
}
