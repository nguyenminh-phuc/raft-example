#ifndef MD_UTILS_H
#define MD_UTILS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "minidns/config.h"

#ifdef MD_ENABLE_LOGGING
#define MD_PRINT(file, format, ...) \
    fprintf(file, "[%s] %s:%d:%s(): " format "\n", md_utils_get_thread_name(), __FILE__, __LINE__, __func__ __VA_OPT__(,) __VA_ARGS__)
#define MD_LOG(format, ...) MD_PRINT(stdout, format __VA_OPT__(,) __VA_ARGS__)
#ifdef __linux__

#include <execinfo.h>
#include <unistd.h>

#define MD_TRACE(format, ...) do { \
    void* buffer[128]; \
    const int size = backtrace(buffer, sizeof(buffer) / sizeof(void*)); \
    backtrace_symbols_fd(buffer, size, STDERR_FILENO); \
    MD_PRINT(stderr, format __VA_OPT__(,) __VA_ARGS__); \
} while (0)
#else
#define MD_TRACE(format, ...) MD_PRINT(stderr, format __VA_OPT__(,) __VA_ARGS__)
#endif
#define MD_ABORT(format, ...) do { \
    MD_TRACE(format __VA_OPT__(,) __VA_ARGS__); \
    abort(); \
} while (0)
#else
#define MD_PRINT(file, format, ...)
#define MD_LOG(format, ...)
#define MD_TRACE(format, ...)
#define MD_ABORT(format, ...) abort()
#endif

#define md_free(ptr) free((ptr))
#define md_rand() rand()
#ifdef _MSC_VER
#define md_strtok_r(str, delim, saveptr) strtok_s((str), (delim), (saveptr))
#else
#define md_strtok_r(str, delim, saveptr) strtok_r((str), (delim), (saveptr))
#endif

#ifdef __cplusplus
extern "C" {
#endif

MD_API const char *md_utils_get_thread_name(void);

MD_API void md_utils_set_thread_name(const char *name);

MD_API bool md_utils_string_ends_with(const char *string, const char *suffix);

MD_API bool md_utils_timespec_to_string(const struct timespec *ts, char buffer[30]);

MD_API void md_utils_sleep(size_t ms);

static inline void *md_calloc(size_t num, size_t size) {
    void *data = calloc(num, size);
    if (!data) MD_ABORT("calloc returned NULL");
    return data;
}

static inline void *md_malloc(size_t size) {
    void *data = malloc(size);
    if (!data) MD_ABORT("malloc returned NULL");
    return data;
}

static inline void *md_realloc(void *ptr, size_t new_size) {
    void *data = realloc(ptr, new_size);
    if (!data) MD_ABORT("realloc returned NULL");
    return data;
}

static inline int md_sprintf(char *MD_RESTRICT buffer, const char *MD_RESTRICT format, ...) {
#ifdef __cplusplus
    va_list args = {};
#else
    va_list args = {0};
#endif
    va_start(args, format);
    const int result = vsprintf(buffer, format, args);
    va_end(args);

    if (result < 0) MD_ABORT("vsprintf returned %d", result);
    return result;
}

static inline int md_snprintf(char *MD_RESTRICT buffer, size_t bufsz, const char *MD_RESTRICT format, ...) {
#ifdef __cplusplus
    va_list args = {};
#else
    va_list args = {0};
#endif
    va_start(args, format);
    const int result = vsnprintf(buffer, bufsz, format, args);
    va_end(args);

    if (result < 0) MD_ABORT("vsnprintf returned %d", result);
    return result;
}

#ifdef __cplusplus
}
#endif

#endif
