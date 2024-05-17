#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>

/* Log levels */
#define LOG_LEVEL_ERROR 0
#define LOG_LEVEL_WARNING 1
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_DEBUG 3

/* Log level threshold */
#define LOG_LEVEL_THRESHOLD LOG_LEVEL_INFO

/* Log macros */
#define LOG_ERROR(format, ...) \
  log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) \
  log_message(LOG_LEVEL_WARNING, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) \
  log_message(LOG_LEVEL_INFO, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_DEBUG(format, ...) \
  log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, format, ##__VA_ARGS__)

/* prototypes */
void log_message(int level, const char *file, int line, const char *format, ...);
void jsonl_log(const char *filename, int level, ...);
void json_log(const char *filename, int level, ...);

#endif // LOG_H
