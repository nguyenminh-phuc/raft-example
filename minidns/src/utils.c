#include "minidns/utils.h"
#include <assert.h>
#include "minidns/threads_wrapper.h"

#ifdef _WIN32

#include <windows.h>

#else

#include <time.h>

#endif

static _Thread_local const char *thread_name = "?";

const char *md_utils_get_thread_name(void) {
    return thread_name;
}

void md_utils_set_thread_name(const char *name) {
    assert(name);
    if (name) thread_name = name;
}

bool md_utils_string_ends_with(const char *string, const char *suffix) {
    assert(string && suffix);

    const size_t string_length = strlen(string);
    const size_t suffix_length = strlen(suffix);
    if (suffix_length > string_length) return false;

    return strncmp(string + string_length - suffix_length, suffix, suffix_length) == 0;
}

// https://stackoverflow.com/a/14746954/12247864
bool md_utils_timespec_to_string(const struct timespec *ts, char buffer[30]) {
    struct tm tm;

#ifdef _WIN32
    _tzset();
    if (localtime_s(&tm, &ts->tv_sec)) return false;
#else
    tzset();
    if (!localtime_r(&ts->tv_sec, &tm)) return false;
#endif

    size_t length = 30;
    size_t rc = strftime(buffer, length, "%F %T", &tm);
    if (!rc) return false;

    length -= rc - 1;

    if (snprintf(&buffer[strlen(buffer)], length, ".%09ld", ts->tv_nsec) >= (int) length)
        return false;

    return true;
}

void md_utils_sleep(size_t ms) {
#ifdef _WIN32
    Sleep((DWORD) ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;
    nanosleep(&ts, NULL);
#endif
}
