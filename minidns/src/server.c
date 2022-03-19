#include "minidns/server.h"
#include <assert.h>
#include "minidns/dns_service.h"
#include "minidns/raft_service.h"
#include "minidns/thread_pool.h"
#include "minidns/utils.h"
#include "database.h"

//static size_t get_quorum_count(const struct md_server *server) {
//    return (size_t) ceil((server->total_peers + 1) / 2.);
//}
//
//static uint64_t get_last_log_term(const struct md_server *server) {
//    if (!server->persistent_state->total_entries) return 0;
//    else return server->persistent_state->entries[server->persistent_state->total_entries - 1].term;
//}
//
//// Receiver implementation:
//// 1. Reply false if term < currentTerm
//// 2. If votedFor is null or candidateId, and candidate's log is at least as up-to-date as receiver's log, grant vote
//static void receive_request_vote_request(
//        struct md_server *server,
//        const struct md_rpc_request_vote_request *request,
//        struct md_rpc_request_vote_response *response) {
//    md_thread_lock(&server->mutex);
//
//    // If RPC request or response contains term T > currentTerm: set currentTerm = T, convert to follower
//    if (request->term > server->persistent_state->current_term) {
//        server->persistent_state->current_term = request->term;
//        become_follower(server);
//    }
//
//    response->vote_granted = false;
//    if (request->term < server->persistent_state->current_term) response->vote_granted = false;
//    else {
//        // Raft determines which of two logs is more up-to-date by comparing the index and term of the last entries in the logs.
//        // If the logs have last entries with different terms, then the log with the later term is more up-to-date.
//        // If the logs end with the same term, then whichever log is longer is more up-to-date.
//        if ((!server->persistent_state->voted_for || *server->persistent_state->voted_for == request->candidate_id)
//            && (request->last_log_term > get_last_log_term(server)
//                || (request->last_log_term == get_last_log_term(server)
//                    && request->last_log_index >= server->persistent_state->total_entries))) {
//            response->vote_granted = true;
//            if (!server->persistent_state->voted_for) server->persistent_state->voted_for = md_malloc(sizeof(uint64_t));
//            *server->persistent_state->voted_for = request->candidate_id;
//            reset_election_timer(server);
//        }
//    }
//
//    response->term = server->persistent_state->current_term;
//
//    md_thread_unlock(&server->mutex);
//}
//
//static void receive_request_vote_response(
//        struct md_server *server,
//        const struct md_rpc_request_vote_response *response) {
//    md_thread_lock(&server->mutex);
//
//    // If RPC request or response contains term T > currentTerm: set currentTerm = T, convert to follower
//    if (response->term > server->persistent_state->current_term) {
//        server->persistent_state->current_term = response->term;
//        become_follower(server);
//    }
//
//    if (server->type == MD_RAFT_CANDIDATE && server->persistent_state->current_term == response->term) {
//        (*server->total_votes)++;
//        if (*server->total_votes >= get_quorum_count(server)) {
//            // TODO
//        }
//    }
//
//    md_thread_unlock(&server->mutex);
//}
//
//// On conversion to candidate, start election:
//// - Increment currentTerm
//// - Vote for self
//// - Reset election timer
//// - Send RequestVote RPCs to all other servers
//static void become_candidate(struct md_server *server) {
//    assert(server->type == MD_RAFT_FOLLOWER);
//
//    server->persistent_state->current_term++;
//
//    MD_LOG("Server %"
//                   PRIu64
//                   " is transiting from follower to candidate (term %"
//                   PRIu64
//                   ")", server->id, server->persistent_state->current_term);
//
//    // TODO: free old value
//    server->persistent_state->voted_for = md_malloc(sizeof(uint64_t));
//    *server->persistent_state->voted_for = server->id;
//
//    server->total_votes = md_malloc(sizeof(size_t));
//    *server->total_votes = 1;
//
//    if (server->type == MD_RAFT_LEADER) {
//        server->heartbeat_thread_state = MD_THREAD_STATE_STOP;
//        md_thread_signal(&server->heartbeat_thread_cond);
//    }
//    server->type = MD_RAFT_CANDIDATE;
//    server->election_thread_state = MD_THREAD_STATE_RESET;
//
//    // TODO: Should update storage here
//
//    struct md_rpc_request_vote_request request;
//    request.term = server->persistent_state->current_term;
//    request.candidate_id = server->id;
////              .last_log_index = server->persistent_state->total_entries - 1,
////              .last_log_term = server->persistent_state->total_entries > 0 ? server->persistent_state->entries[]
//
//    if (server->total_peers == 0) {
//        // TODO
//    } else {
//        for (size_t i = 0; i < server->total_peers; ++i) {
//            struct arg *arg = md_malloc(sizeof(struct arg));
//            arg->peer = &server->peers[i];
//            arg->type = MD_RPC_REQUEST_VOTE_REQUEST;
//            arg->request = &request;
//
//            md_thread_pool_add_task(server->thread_pool, (void (*)(void *)) send_request, arg);
//        }
//    }
//}
//
//static void receive_rpcs(struct md_server *server, void *message, enum md_rpc_type type) {
//    switch (type) {
//        case MD_RPC_REQUEST_VOTE_REQUEST:
//            receive_request_vote_request(server, message, NULL);
//            break;
//        case MD_RPC_REQUEST_VOTE_RESPONSE:
//            receive_request_vote_response(server, message);
//            break;
//        default:
//            MD_ABORT("Unknown md_rpc_type case: %d", type);
//    }
//}
//
//// If election timeout elapses without receiving AppendEntries RPC from current leader or granting vote to candidate:
//// convert to candidate
//static int election_timer_func(void *arg) {
//    md_utils_set_thread_name("ElectionTimer");
//
//    struct md_server *server = arg;
//
//    md_thread_lock(&server->mutex);
//
//    while (true) {
//        while (!server->terminable_tmp && server->election_thread_state == MD_THREAD_STATE_STOP)
//            md_thread_wait(&server->election_thread_cond, &server->mutex);
//
//        if (server->terminable_tmp) break;
//
//        if (server->election_thread_state == MD_THREAD_STATE_RESET) {
//            server->election_thread_state = MD_THREAD_STATE_SLEEP;
//
//            const uint32_t timeout = server->election_timeout + md_rand()
//                    % (server->election_timeout * 2 + 1 - server->election_timeout);
//
//            const struct timespec due = get_due_time(timeout);
//            while (true) {
//                if (md_thread_timedwait(&server->election_thread_cond, &server->mutex, &due) == thrd_timedout) {
//                    become_candidate(server);
//                    break;
//                } else {
//                    if (!server->terminable_tmp && server->election_thread_state == MD_THREAD_STATE_SLEEP) continue;
//                    else break;
//                }
//            }
//        }
//    }
//
//    md_thread_unlock(&server->mutex);
//
//    return 0;
//}
//
//static void stop_election_timer(struct md_server *server) {
//    md_thread_lock(&server->mutex);
//
//    server->election_thread_state = MD_THREAD_STATE_STOP;
//    md_thread_signal(&server->election_thread_cond);
//
//    md_thread_unlock(&server->mutex);
//}
//
//static int heartbeat_timer_func(void *arg) {
//    md_utils_set_thread_name("HeartbeatTimer");
//
//    struct md_server *server = arg;
//
//    md_thread_lock(&server->mutex);
//
//    while (true) {
//        while (!server->terminable_tmp && server->heartbeat_thread_state == MD_THREAD_STATE_STOP)
//            md_thread_wait(&server->heartbeat_thread_cond, &server->mutex);
//
//        if (server->terminable_tmp) break;
//
//        if (server->heartbeat_thread_state == MD_THREAD_STATE_RESET) {
////            send_heartbeats(server);
//            server->heartbeat_thread_state = MD_THREAD_STATE_SLEEP;
//
//            const struct timespec due = get_due_time(server->heartbeat_timeout);
//            while (true) {
//                if (md_thread_timedwait(&server->heartbeat_thread_cond, &server->mutex, &due) == thrd_timedout) {
//                    server->heartbeat_thread_state = MD_THREAD_STATE_RESET;
//                    break;
//                } else {
//                    if (!server->terminable_tmp && server->heartbeat_thread_state == MD_THREAD_STATE_SLEEP) continue;
//                    else break;
//                }
//            }
//        }
//    }
//
//    md_thread_unlock(&server->mutex);
//
//    return 0;
//}
//
//static void stop_heartbeat_timer(struct md_server *server) {
//    md_thread_lock(&server->mutex);
//
//    server->heartbeat_thread_state = MD_THREAD_STATE_STOP;
//    md_thread_signal(&server->heartbeat_thread_cond);
//
//    md_thread_unlock(&server->mutex);
//}
//
//static void reset_heartbeat_timer(struct md_server *server) {
//    server->heartbeat_thread_state = MD_THREAD_STATE_RESET;
//    md_thread_signal(&server->heartbeat_thread_cond);
//}

struct md_server *md_server_create(
        uint64_t id, const struct md_raft_peer_arg *peers, size_t total_peers,
        uint16_t local_dns_port, size_t local_dns_poll_timeout,
        const char *public_dns_ip, uint16_t public_dns_port, size_t public_dns_poll_timeout,
        uint16_t rpc_port, size_t rpc_timeout,
        size_t election_timeout,
        size_t thread_pool_size,
        const char *db_filename,
        volatile const sig_atomic_t *terminable) {
    assert(peers && total_peers && public_dns_ip && election_timeout && thread_pool_size && db_filename && terminable);

    struct md_server *server = md_malloc(sizeof(struct md_server));
    server->terminable = terminable;

    server->thread_pool = md_thread_pool_create(thread_pool_size);
    assert(server->thread_pool);

    server->database = db_open(db_filename);
    assert(server->database);

    server->dns_service = md_dns_service_create(
            local_dns_port, local_dns_poll_timeout,
            public_dns_ip, public_dns_port, public_dns_poll_timeout,
            server->thread_pool,
            server->database);
    assert(server->dns_service);

    server->raft_service = md_raft_service_create(
            id,
            peers, total_peers,
            rpc_port, rpc_timeout,
            election_timeout,
            server->thread_pool,
            server->database);
    assert(server->raft_service);

    return server;
}

void md_server_run_main_loop(struct md_server *server) {
    assert(server);

    MD_LOG("Server is running...");
    md_thread_create(&server->dns_thread, (thrd_start_t) md_dns_service_main_loop, server->dns_service);
    md_thread_create(&server->raft_thread, (thrd_start_t) md_raft_service_main_loop, server->raft_service);

    while (!*server->terminable) md_utils_sleep(500);
    MD_LOG("Terminating server...");

    md_raft_service_request_to_terminate(server->raft_service);
    md_dns_service_request_to_terminate(server->dns_service);
    int rc = md_thread_join(server->raft_thread);
    assert(rc == EXIT_SUCCESS);
    rc = md_thread_join(server->dns_thread);
    assert(rc == EXIT_SUCCESS);

    db_close(server->database);
    md_thread_pool_destroy(server->thread_pool);
    md_free(server);
}
