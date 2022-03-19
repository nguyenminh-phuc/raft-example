#ifndef MD_THREADS_WRAPPER_H
#define MD_THREADS_WRAPPER_H

// Windows: Both MSVC and Clang do not support C11 threads.h
#if defined(_WIN32) && (defined(_MSC_VER) || defined(__clang__))

#include <tinycthread.h>

#else

#include <threads.h>

#endif

#include <assert.h>
#include "minidns/utils.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void md_thread_create(thrd_t *thread, thrd_start_t func, void *arg) {
    assert(thread && func);

    const int rc = thrd_create(thread, func, arg);
    if (rc != thrd_success) MD_ABORT("thrd_create returned %d", rc);
}

static inline int md_thread_join(thrd_t thread) {
    int result = 0;
    const int rc = thrd_join(thread, &result);
    if (rc != thrd_success) MD_ABORT("thrd_join returned %d", rc);

    return rc;
}

static inline void md_thread_detach(thrd_t thread) {
    const int rc = thrd_detach(thread);
    if (rc != thrd_success) MD_ABORT("thrd_detach returned %d", rc);
}

static inline void md_thread_mutex_init(mtx_t *mutex, int type) {
    assert(mutex);

    const int rc = mtx_init(mutex, type);
    if (rc != thrd_success) MD_ABORT("mtx_init returned %d", rc);
}

static inline void md_thread_lock(mtx_t *mutex) {
    assert(mutex);

    const int rc = mtx_lock(mutex);
    if (rc != thrd_success) MD_ABORT("mtx_lock returned %d", rc);
}

static inline void md_thread_unlock(mtx_t *mutex) {
    assert(mutex);

    const int rc = mtx_unlock(mutex);
    if (rc != thrd_success) MD_ABORT("mtx_unlock returned %d", rc);
}

static inline void md_thread_cond_init(cnd_t *cond) {
    assert(cond);

    const int rc = cnd_init(cond);
    if (rc != thrd_success) MD_ABORT("cnd_init returned %d", rc);
}

static inline void md_thread_wait(cnd_t *cond, mtx_t *mutex) {
    assert(cond && mutex);

    const int rc = cnd_wait(cond, mutex);
    if (rc != thrd_success) MD_ABORT("cnd_wait returned %d", rc);
}

static inline int md_thread_timedwait(cnd_t *cond, mtx_t *mutex, const struct timespec *time_point) {
    assert(cond && mutex && time_point);

    const int rc = cnd_timedwait(cond, mutex, time_point);
    if (rc != thrd_success && rc != thrd_timedout) MD_ABORT("cnd_timedwait returned %d", rc);
    return rc;
}

static inline void md_thread_signal(cnd_t *cond) {
    assert(cond);

    const int rc = cnd_signal(cond);
    if (rc != thrd_success) MD_ABORT("cnd_signal returned %d", rc);
}

static inline void md_thread_broadcast(cnd_t *cond) {
    assert(cond);

    const int rc = cnd_broadcast(cond);
    if (rc != thrd_success) MD_ABORT("cnd_broadcast returned %d", rc);
}

#ifdef __cplusplus
}
#endif

#endif
