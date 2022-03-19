#include "minidns/thread_pool.h"
#include <assert.h>
#include "minidns/utils.h"

struct arg {
    struct md_thread_pool *pool;
    size_t index;
};

static int thread_main_loop(struct arg *arg) {
    struct md_thread_pool *pool = arg->pool;

    const int n = md_snprintf(NULL, 0, "ThreadPool(%p:%zu)", (void *) pool, arg->index);
    char *thread_name = md_malloc(n + 1);
    md_sprintf(thread_name, "ThreadPool(%p:%zu)", (void *) pool, arg->index);

    md_utils_set_thread_name(thread_name);

    while (true) {
        md_thread_lock(&pool->mutex);

        while (!pool->terminable && !pool->tasks)
            md_thread_wait(&pool->task_cond, &pool->mutex);

        if (pool->terminable) break;

        struct md_task *task = pool->tasks;
        pool->tasks = pool->tasks->next;
        pool->total_working_threads++;

        md_thread_unlock(&pool->mutex);

        task->func(task->arg);
        md_free(task);

        md_thread_lock(&pool->mutex);

        pool->total_working_threads--;

        md_thread_unlock(&pool->mutex);
    }

    pool->total_threads--;
    md_thread_signal(&pool->thread_removed_cond);

    md_thread_unlock(&pool->mutex);

    md_free(thread_name);
    md_free(arg);

    return EXIT_SUCCESS;
}

struct md_thread_pool *md_thread_pool_create(size_t size) {
    assert(size);

    struct md_thread_pool *pool = md_malloc(sizeof(struct md_thread_pool));
    pool->tasks = NULL;
    pool->total_working_threads = 0;
    pool->total_threads = size;
    pool->terminable = false;

    md_thread_mutex_init(&pool->mutex, mtx_plain);
    md_thread_cond_init(&pool->task_cond);
    md_thread_cond_init(&pool->thread_removed_cond);

    for (size_t i = 0; i < size; ++i) {
        struct arg *arg = md_malloc(sizeof(struct arg));
        arg->pool = pool;
        arg->index = i;
        thrd_t thread = {0};

        md_thread_create(&thread, (thrd_start_t) thread_main_loop, arg);
        md_thread_detach(thread);
    }

    return pool;
}

void md_thread_pool_destroy(struct md_thread_pool *pool) {
    if (!pool) return;

    md_thread_lock(&pool->mutex);

    struct md_task *task = pool->tasks;
    while (task) {
        struct md_task *next = task->next;
        md_free(task);
        task = next;
    }

    pool->terminable = true;
    md_thread_broadcast(&pool->task_cond);

    while (true) {
        if (!pool->total_threads) break;
        md_thread_wait(&pool->thread_removed_cond, &pool->mutex);
    }

    md_thread_unlock(&pool->mutex);

    cnd_destroy(&pool->task_cond);
    cnd_destroy(&pool->thread_removed_cond);
    mtx_destroy(&pool->mutex);
    md_free(pool);
}

void md_thread_pool_add_task(struct md_thread_pool *pool, void (*func)(void *), void *arg) {
    assert(pool && func);

    struct md_task *new_task = md_malloc(sizeof(struct md_task));
    new_task->func = func;
    new_task->arg = arg;
    new_task->next = NULL;

    md_thread_lock(&pool->mutex);

    if (pool->tasks == NULL) pool->tasks = new_task;
    else {
        struct md_task *task = pool->tasks;
        while (task->next) task = task->next;
        task->next = new_task;
    }

    md_thread_signal(&pool->task_cond);

    md_thread_unlock(&pool->mutex);
}
