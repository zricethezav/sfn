#include "config.h"
#include "toml.h"
#include "detect.h"
#include "oniguruma.h"
#include "uthash.h"
#include "util.h"

#include <ctype.h>
#include <math.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <pthread.h>
#include <stdbool.h>

#define CHUNK_SIZE 10 * KB
#define OVERLAP_SIZE 3 * KB
#define MAX_CHARS 256
#define PATH_MAX 4096
#define MAX_THREADS 40

#define BUFFER_SIZE (CHUNK_SIZE) + (OVERLAP_SIZE)

typedef struct work_item
{
    char file_path[PATH_MAX];
    struct work_item *next;
} work_item;

// Work queue
pthread_mutex_t work_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t work_cond = PTHREAD_COND_INITIALIZER;
work_item *work_head = NULL;
work_item *work_tail = NULL;
int stop = 0;

// Protects global_match_count
pthread_mutex_t match_count_mutex = PTHREAD_MUTEX_INITIALIZER;
int global_match_count = 0;

// prototypes
int scan_file(FILE *file, const char *file_path);
void scan_directory(const char *path);

void *worker(void *arg)
{
    while (1)
    {
        pthread_mutex_lock(&work_mutex);
        while (!work_head && !stop)
        {
            pthread_cond_wait(&work_cond, &work_mutex);
        }

        if (stop && !work_head)
        {
            pthread_mutex_unlock(&work_mutex);
            break;
        }

        work_item *work = work_head;
        if (work)
        {
            work_head = work->next;
            if (!work_head)
            {
                work_tail = NULL;
            }
        }
        pthread_mutex_unlock(&work_mutex);

        if (work)
        {
            FILE *file = fopen(work->file_path, "r");
            if (file)
            {
                int local_matches = scan_file(file, work->file_path);
                if (local_matches > 0)
                {
                    pthread_mutex_lock(&match_count_mutex);
                    global_match_count += local_matches;
                    pthread_mutex_unlock(&match_count_mutex);
                }
                fclose(file);
            }
            else
            {
                fprintf(stderr, "Failed to open file: %s\n", work->file_path);
            }
            free(work);
        }
    }
    return NULL;
}

void add_work(const char *file_path)
{
    work_item *work = (work_item *)malloc(sizeof(work_item));
    strcpy(work->file_path, file_path);
    work->next = NULL;

    pthread_mutex_lock(&work_mutex);
    if (work_tail)
    {
        work_tail->next = work;
    }
    else
    {
        work_head = work;
    }
    work_tail = work;
    pthread_cond_signal(&work_cond);
    pthread_mutex_unlock(&work_mutex);
}

int scan_git(const char *path)
{
    // TODO implement
    return 0;
}

int scan_file(FILE *file, const char *file_path)
{
    if (file_path == NULL)
    {
        LOG_WARNING("File path is NULL, continuing");
        return 0;
    }

    // Check if the file is binary
    char buffer[BUFFER_SIZE];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
    if (is_binary(buffer, bytes_read))
    {
        return 0;
    }
    rewind(file);

    // set up buffers
    char chunk_buffer[CHUNK_SIZE + 1] = {0};
    char overlap_buffer[OVERLAP_SIZE + 1] = {0};
    char combined_buffer[BUFFER_SIZE + 1] = {0};
    size_t curr_buf_start_line_number = 0;
    size_t effective_overlap_length = 0;

    match_t *matches = NULL;
    int num_matches = 0;

    while ((bytes_read = fread(chunk_buffer, 1, CHUNK_SIZE, file)) > 0)
    {
        if (effective_overlap_length + bytes_read > BUFFER_SIZE)
        {
            fprintf(stderr, "Combined buffer size exceeded\n");
            break;
        }

        // Combine overlap buffer with the current chunk. Ensure null-termination.
        // This is the buffer that will be scanned for secrets.
        memcpy(combined_buffer, overlap_buffer, effective_overlap_length);
        memcpy(combined_buffer + effective_overlap_length, chunk_buffer, bytes_read);
        size_t combined_length = effective_overlap_length + bytes_read;
        combined_buffer[effective_overlap_length + bytes_read] = '\0';

        // Find the last newline in the combined buffer
        char *last_newline = strrchr(combined_buffer, '\n');
        size_t process_length = combined_length;
        if (last_newline != NULL)
        {
            // Set up the overlap buffer for the next iteration
            process_length = last_newline - combined_buffer + 1;
            effective_overlap_length = combined_length - process_length;
            effective_overlap_length = (effective_overlap_length > OVERLAP_SIZE) ? OVERLAP_SIZE : effective_overlap_length;
            memcpy(overlap_buffer, combined_buffer + process_length, effective_overlap_length);
            overlap_buffer[effective_overlap_length] = '\0';
        }
        else
        {
            // No newline found, so no overlap is needed. Might be the case if the file is a single line
            // OR if the file contains lots of areas with no newlines... like minified js, for example.
            // In this case, we will not use the overlap buffer and will process _only_ the "chunk_buffer".
            effective_overlap_length = 0;
            overlap_buffer[0] = '\0';
        }

        // Detect secrets in the "processed" part of the combined buffer
        num_matches += detect_secrets(combined_buffer, file_path, curr_buf_start_line_number, process_length, &matches, (bytes_read == CHUNK_SIZE));
        match_t *current_match, *tmp;
        HASH_ITER(hh, matches, current_match, tmp)
        {
            // printf("hash_key: %s\n", current_match->hash_key);
            print_match(current_match);
            HASH_DEL(matches, current_match);
            free_match(current_match);
        }

        // Count lines in the processed part of the combined buffer for the next iteration
        for (size_t i = 0; i < process_length; ++i)
        {
            if (combined_buffer[i] == '\n')
            {
                curr_buf_start_line_number++;
            }
        }
    }

    if (effective_overlap_length > 0)
    {
        num_matches += detect_secrets(overlap_buffer, file_path, curr_buf_start_line_number, effective_overlap_length, &matches, 0);
    }

    return num_matches;
}

void scan_directory(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir)
    {
        fprintf(stderr, "Failed to open directory: %s\n", path);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_type == DT_REG)
        {
            char file_path[PATH_MAX];
            snprintf(file_path, sizeof(file_path), "%s/%s", path, entry->d_name);
            add_work(file_path);
        }
        else if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            char dir_path[PATH_MAX];
            snprintf(dir_path, sizeof(dir_path), "%s/%s", path, entry->d_name);
            scan_directory(dir_path);
        }
    }
    closedir(dir);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <command> <path>\n", argv[0]);
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, "  directory <path>  Scan a directory or file\n");
        fprintf(stderr, "  stdin             Scan input piped in from stdin\n");
        return 1;
    }

    const char *command = argv[1];
    const char *path = argv[2];

    load_config("gitleaks.toml");
    if (!config)
    {
        fprintf(stderr, "Failed to load configuration\n");
        return 1;
    }

    if (strcmp(command, "directory") == 0)
    {
        struct stat path_stat;
        if (stat(path, &path_stat) == 0)
        {
            if (S_ISREG(path_stat.st_mode))
            {
                FILE *file = fopen(path, "r");
                if (!file)
                {
                    fprintf(stderr, "Failed to open file: %s\n", path);
                    return -1;
                }
                global_match_count += scan_file(file, path);
                fclose(file);
            }
            else if (S_ISDIR(path_stat.st_mode))
            {
                pthread_t threads[MAX_THREADS];
                for (int i = 0; i < MAX_THREADS; i++)
                {
                    pthread_create(&threads[i], NULL, worker, NULL);
                }

                scan_directory(path);

                pthread_mutex_lock(&work_mutex);
                stop = 1;
                pthread_cond_broadcast(&work_cond);
                pthread_mutex_unlock(&work_mutex);

                for (int i = 0; i < MAX_THREADS; i++)
                {
                    pthread_join(threads[i], NULL);
                }
            }
            else
            {
                fprintf(stderr, "Invalid file type: %s\n", path);
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "Failed to access path: %s\n", path);
            return 1;
        }
    }
    else if (strcmp(command, "stdin") == 0)
    {
        // TODO, maybe try parallelizing this as well
        global_match_count += scan_file(stdin, "stdin");
    }
    else if (strcmp(command, "git") == 0)
    {
        scan_git(path);
    }

    printf("Total matches: %d\n", global_match_count);
    free_config(config);

    return 0;
}
