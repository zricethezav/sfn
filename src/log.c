#include "log.h"
#include <stdlib.h>
#include <string.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void log_message(int level, const char *file, int line, const char *format,
                 ...)
{
  if (level <= LOG_LEVEL_THRESHOLD)
  {
    const char *level_str;
    switch (level)
    {
    case LOG_LEVEL_ERROR:
      level_str = "ERROR";
      break;
    case LOG_LEVEL_WARNING:
      level_str = "WARNING";
      break;
    case LOG_LEVEL_INFO:
      level_str = "INFO";
      break;
    case LOG_LEVEL_DEBUG:
      level_str = "DEBUG";
      break;
    default:
      level_str = "UNKNOWN";
      break;
    }

    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_now);

    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    printf("{\"timestamp\": \"%s\", \"level\": \"%s\", \"file\": \"%s\", "
           "\"line\": %d, \"message\": \"%s\"}\n",
           timestamp, level_str, file, line, buffer);
  }
}
