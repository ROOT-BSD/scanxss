/*
 * Copyright (c) 2026 root_bsd <root_bsd@itprof.net.ua>
 * SPDX-License-Identifier: GPL-2.0
 *
 * worker.c — pthread worker pool для паралельного виконання задач.
 *
 * Архітектура:
 *   - N потоків (за замовчуванням 4, максимум 16)
 *   - Спільна черга задач (WorkItem) захищена mutex
 *   - Кожна задача: вказівник на функцію + аргумент
 *   - Головний потік додає задачі, чекає на завершення через barrier
 *
 * Використання:
 *   WorkerPool *pool = worker_pool_create(4);
 *   worker_pool_submit(pool, my_fn, arg);
 *   worker_pool_wait(pool);    // чекаємо всі задачі
 *   worker_pool_destroy(pool);
 *
 * Безпека даних:
 *   - visited[] у crawler.c захищено окремим mutex
 *   - ctx->vulns[] і ctx->vuln_count захищено mutex у attack_add_vuln()
 *   - ctx->requests_made захищено atomic-подібним atomic_fetch_add
 *     (на практиці — той самий mutex що і vuln_count)
 */

#include "scanxss.h"
#include <pthread.h>
#include <stdint.h>

#define WORKER_QUEUE_SIZE  1024

typedef struct {
    WorkerFn  fn;
    void     *arg;
} WorkItem;

struct WorkerPool {
    pthread_t        threads[WORKER_MAX_THREADS];
    int              nthreads;

    WorkItem         queue[WORKER_QUEUE_SIZE];
    int              q_head;
    int              q_tail;
    int              q_size;

    pthread_mutex_t  mu;
    pthread_cond_t   cv_work;    /* є нова задача */
    pthread_cond_t   cv_done;    /* задача завершена */

    int              active;     /* задач у виконанні */
    bool             shutdown;
};

static void *worker_thread(void *arg) {
    WorkerPool *pool = (WorkerPool *)arg;

    while (1) {
        pthread_mutex_lock(&pool->mu);

        /* Чекаємо задачу або shutdown */
        while (pool->q_size == 0 && !pool->shutdown)
            pthread_cond_wait(&pool->cv_work, &pool->mu);

        if (pool->shutdown && pool->q_size == 0) {
            pthread_mutex_unlock(&pool->mu);
            return NULL;
        }

        /* Беремо задачу */
        WorkItem item = pool->queue[pool->q_head];
        pool->q_head  = (pool->q_head + 1) % WORKER_QUEUE_SIZE;
        pool->q_size--;
        pool->active++;
        pthread_mutex_unlock(&pool->mu);

        /* Виконуємо */
        item.fn(item.arg);

        pthread_mutex_lock(&pool->mu);
        pool->active--;
        pthread_cond_broadcast(&pool->cv_done);
        pthread_mutex_unlock(&pool->mu);
    }
    return NULL;
}

WorkerPool *worker_pool_create(int nthreads) {
    if (nthreads < 1) nthreads = 1;
    if (nthreads > WORKER_MAX_THREADS) nthreads = WORKER_MAX_THREADS;

    WorkerPool *pool = calloc(1, sizeof(WorkerPool));
    if (!pool) return NULL;

    pool->nthreads = nthreads;
    pool->shutdown = false;
    pthread_mutex_init(&pool->mu, NULL);
    pthread_cond_init (&pool->cv_work, NULL);
    pthread_cond_init (&pool->cv_done, NULL);

    for (int i = 0; i < nthreads; i++) {
        if (pthread_create(&pool->threads[i], NULL, worker_thread, pool) != 0) {
            /* Не вдалось створити потік — завершуємо вже запущені */
            pool->nthreads = i;
            pool->shutdown = true;
            pthread_cond_broadcast(&pool->cv_work);
            for (int j = 0; j < i; j++)
                pthread_join(pool->threads[j], NULL);
            pthread_mutex_destroy(&pool->mu);
            pthread_cond_destroy(&pool->cv_work);
            pthread_cond_destroy(&pool->cv_done);
            free(pool);
            return NULL;
        }
    }
    return pool;
}

int worker_pool_submit(WorkerPool *pool, WorkerFn fn, void *arg) {
    if (!pool || !fn) return -1;

    pthread_mutex_lock(&pool->mu);

    /* Якщо черга повна — чекаємо місця */
    while (pool->q_size >= WORKER_QUEUE_SIZE && !pool->shutdown)
        pthread_cond_wait(&pool->cv_done, &pool->mu);

    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->mu);
        return -1;
    }

    pool->queue[pool->q_tail].fn  = fn;
    pool->queue[pool->q_tail].arg = arg;
    pool->q_tail = (pool->q_tail + 1) % WORKER_QUEUE_SIZE;
    pool->q_size++;

    pthread_cond_signal(&pool->cv_work);
    pthread_mutex_unlock(&pool->mu);
    return 0;
}

void worker_pool_wait(WorkerPool *pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->mu);
    while (pool->q_size > 0 || pool->active > 0)
        pthread_cond_wait(&pool->cv_done, &pool->mu);
    pthread_mutex_unlock(&pool->mu);
}

void worker_pool_destroy(WorkerPool *pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->mu);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->cv_work);
    pthread_mutex_unlock(&pool->mu);

    for (int i = 0; i < pool->nthreads; i++)
        pthread_join(pool->threads[i], NULL);

    pthread_mutex_destroy(&pool->mu);
    pthread_cond_destroy(&pool->cv_work);
    pthread_cond_destroy(&pool->cv_done);
    free(pool);
}
