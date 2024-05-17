#include "ahocorasick.h"

/**
 * Create a new node and return a pointer to it.
 * The node is initialized with default values.
 */
ac_node *ahocorasick_create_node()
{
    ac_node *new_node = (ac_node *)malloc(sizeof(ac_node));
    if (new_node == NULL)
    {
        return NULL;
    }
    new_node->root = 0;
    new_node->end_of_word = 0;
    new_node->index = -1;
    new_node->failure = NULL;
    for (int i = 0; i < MAX_CHARS; i++)
    {
        new_node->child[i] = NULL;
    }
    return new_node;
}

void ahocorasick_insert(ac_node *root, const unsigned char *word, const int index, int case_insensitive)
{
    ac_node *current = root;
    for (int i = 0; word[i] != '\0'; i++)
    {
        unsigned char char_code = case_insensitive ? tolower(word[i]) : word[i];
        if (current->child[char_code] == NULL)
        {
            current->child[char_code] = ahocorasick_create_node();
        }
        current = current->child[char_code];
    }
    current->end_of_word = 1;
    current->index = index;
}

void ahocorasick_build_failure_links(ac_node *root)
{
    int queue_capacity = 10; // Initial queue capacity
    int queue_size = 0;
    ac_node **queue = (ac_node **)malloc(queue_capacity * sizeof(ac_node *));
    int front = 0, rear = 0;

    queue[rear++] = root;
    queue_size++;

    while (front < rear)
    {
        ac_node *current = queue[front++];
        for (int i = 0; i < MAX_CHARS; i++)
        {
            ac_node *child = current->child[i];
            if (child && current == root)
            {
                child->failure = root;
            }
            else if (child)
            {
                ac_node *failure = current->failure;
                while (failure && !failure->child[i])
                {
                    failure = failure->failure;
                }
                child->failure = failure ? failure->child[i] : root;
            }

            if (child)
            {
                if (queue_size == queue_capacity)
                {
                    queue_capacity *= 2;
                    queue = (ac_node **)realloc(queue, queue_capacity * sizeof(ac_node *));
                }
                queue[rear++] = child;
                queue_size++;
            }
        }
    }
    free(queue);
}

int ahocorasick_find_matches(ac_node *root, const unsigned char *text, int **matchIndices, int case_insensitive)
{
    ac_node *current = root;
    int len = strlen((char *)text);
    int matchIndicesCapacity = 10; // Initial capacity
    int numMatches = 0;
    *matchIndices = (int *)malloc(matchIndicesCapacity * sizeof(int));

    for (int i = 0; i < len; i++)
    {
        unsigned char char_code = case_insensitive ? tolower(text[i]) : text[i];
        while (current && !current->child[char_code])
        {
            current = current->failure;
        }
        current = current ? current->child[char_code] : root;
        ac_node *temp = current;
        while (temp && temp->end_of_word)
        {
            if (numMatches == matchIndicesCapacity)
            {
                matchIndicesCapacity *= 2;
                *matchIndices = (int *)realloc(*matchIndices, matchIndicesCapacity * sizeof(int));
            }
            (*matchIndices)[numMatches++] = temp->index;
            temp = temp->failure;
        }
    }

    return numMatches;
}

void ahocorasick_free_trei(ac_node *current)
{
    if (current == NULL)
    {
        return;
    }
    for (int i = 0; i < MAX_CHARS; i++)
    {
        if (current->child[i] != NULL)
        {
            ahocorasick_free_trei(current->child[i]);
        }
    }

    free(current);
}

ac_node *ahocorasick_create_trie(const unsigned char **dictionary, int numWords, int case_insensitive)
{
    ac_node *root_node = ahocorasick_create_node();
    if (root_node == NULL)
    {
        return NULL;
    }
    int max_word_length = 0;

    for (int i = 0; i < numWords; i++)
    {
        int word_length = strlen((const char *)dictionary[i]);
        if (word_length > max_word_length)
        {
            max_word_length = word_length;
        }
        ahocorasick_insert(root_node, dictionary[i], i, case_insensitive);
    }

    ahocorasick_build_failure_links(root_node);

    return root_node;
}