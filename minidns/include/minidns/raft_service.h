#ifndef MD_RAFT_SERVICE_H
#define MD_RAFT_SERVICE_H

#include <stdbool.h>
#include <stdint.h>
#include "minidns/config.h"
#include "minidns/network.h"
#include "minidns/raft.h"
#include "minidns/threads_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

struct sqlite3;
struct md_net_fd;
struct md_thread_pool;

struct md_raft_timer {
    thrd_t thread;
    cnd_t cond;
    size_t timeout;
    bool suspended;
};

struct md_raft_peer_arg {
    uint64_t id;
    char ip[MD_NET_IP_LENGTH];
    uint16_t port;
};

struct md_raft_peer {
    uint64_t id;
    char ip[MD_NET_IP_LENGTH];
    uint16_t port;
    struct md_raft_volatile_leader_state *leader_state;
};

struct md_waiting_client {
    struct md_net_fd *fd;
    size_t log_index;
    struct md_waiting_client *next;
};

struct md_raft_service {
    // Raft
    uint64_t id;
    uint64_t *leader_id;
    enum {
        MD_RAFT_FOLLOWER,
        MD_RAFT_CANDIDATE,
        MD_RAFT_LEADER
    } type;
    struct md_raft_peer *peers;
    size_t total_peers;
    struct md_raft_persistent_state persistent_state;
    struct md_raft_volatile_state volatile_state;
    struct md_raft_timer election_timer;
    struct md_raft_timer heartbeat_timer;

    // RPC
    struct md_net_fd *fd;
    uint16_t port;
    size_t poll_timeout;
    struct md_waiting_client *waiting_clients;

    // Misc
    size_t total_connections;
    struct md_thread_pool *thread_pool;
    struct md_dns_service *dns_service;
    struct sqlite3 *database;
    cnd_t connections_cond;
    mtx_t mutex;
    bool running;
    bool terminable;
};

MD_API struct md_raft_service *md_raft_service_create(
        uint64_t id,
        const struct md_raft_peer_arg *peers, size_t total_peers,
        uint16_t port, size_t poll_timeout,
        size_t election_timeout,
        struct md_thread_pool *thread_pool,
        struct sqlite3 *database);

MD_API void md_raft_service_request_to_terminate(struct md_raft_service *service);

MD_API int md_raft_service_main_loop(struct md_raft_service *service);

#ifdef __cplusplus
}
#endif

#endif
