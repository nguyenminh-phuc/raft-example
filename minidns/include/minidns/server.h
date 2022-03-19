#ifndef MD_SERVER_H
#define MD_SERVER_H

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include "minidns/config.h"
#include "minidns/threads_wrapper.h"

#include "minidns/raft_service.h"

#ifdef __cplusplus
extern "C" {
#endif

struct sqlite3;
struct md_dns_service;
struct md_raft_service;
struct md_thread_pool;

struct md_server {
    struct sqlite3 *database;
    struct md_thread_pool *thread_pool;
    thrd_t dns_thread;
    thrd_t raft_thread;
    struct md_dns_service *dns_service;
    struct md_raft_service *raft_service;
    volatile const sig_atomic_t *terminable;
};

MD_API struct md_server *md_server_create(
        uint64_t id, const struct md_raft_peer_arg *peers, size_t total_peers,
        uint16_t local_dns_port, size_t local_dns_poll_timeout,
        const char *public_dns_ip, uint16_t public_dns_port, size_t public_dns_poll_timeout,
        uint16_t rpc_port, size_t rpc_timeout,
        size_t election_timeout,
        size_t thread_pool_size,
        const char *db_filename,
        volatile const sig_atomic_t *terminable);

MD_API void md_server_run_main_loop(struct md_server *server);

#ifdef __cplusplus
}
#endif

#endif
