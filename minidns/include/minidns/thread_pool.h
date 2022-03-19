#ifndef MD_THREAD_POOL_H
#define MD_THREAD_POOL_H

#include <stdbool.h>
#include <stdlib.h>
#include "minidns/config.h"
#include "minidns/threads_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

struct md_task {
    void (*func)(void *);

    void *arg;
    struct md_task *next;
};

struct md_thread_pool {
    struct md_task *tasks;
    size_t total_working_threads;
    size_t total_threads;
    bool terminable;
    mtx_t mutex;
    cnd_t task_cond;
    cnd_t thread_removed_cond;
};

MD_API struct md_thread_pool *md_thread_pool_create(size_t size);

MD_API void md_thread_pool_destroy(struct md_thread_pool *pool);

MD_API void md_thread_pool_add_task(struct md_thread_pool *pool, void (*func)(void *), void *arg);

#ifdef __cplusplus
}
#endif

#endif
