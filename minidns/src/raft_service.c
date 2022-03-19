#include "minidns/raft_service.h"
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "database.h"
#include "minidns/protobuf_wrapper.h"
#include "minidns/rpc2.h"
#include "minidns/thread_pool.h"
#include "minidns/utils.h"

#ifndef _WIN32

#include <sys/socket.h>

#endif

struct main_arg {
    struct md_raft_service *service;
    struct md_net_fd *fd;
};

struct rpc_arg {
    char ip[MD_NET_IP_LENGTH];
    uint16_t port;
    enum md_rpc_type type;
    void *message;
};

struct command_response_rpc_arg {
    struct md_net_fd *fd;
    struct md_rpc_command_response *response;
};

static const size_t total_retries = 3;
static const size_t batch_size = 10;
static const size_t default_capacity = 100;

static const char *const type_str[] = {
        "follower",
        "candidate",
        "leader"
};

// https://stackoverflow.com/a/59554020/12247864
static struct timespec get_due_time(long ms) {
    assert(ms >= 0);

    struct timespec now, due;
    timespec_get(&now, TIME_UTC);

    due.tv_sec = now.tv_sec + ms / 1000;
    due.tv_nsec = now.tv_nsec + (ms % 1000) * 1000000;
    if (due.tv_nsec >= 1000000000) {
        due.tv_nsec -= 1000000000;
        due.tv_sec++;
    }

    return due;
}

static const struct md_raft_entry *get_log_entry(const struct md_raft_log *log, size_t index) {
    if (index > log->total_entries) return NULL;
    else return &log->entries[index - 1];
}

static size_t get_last_log_term(const struct md_raft_log *log) {
    if (!log->total_entries) return 0;
    else return log->entries[log->total_entries - 1].term;
}

static struct md_raft_peer *get_peer(const struct md_raft_service *service, uint64_t id) {
    for (size_t i = 0; i < service->total_peers; ++i)
        if (service->peers[i].id == id) return &service->peers[i];

    MD_ABORT("Peer %" PRIu64 "not found", id);
}

static void append_log(struct md_raft_service *service, const struct md_raft_entry *entry) {
    struct md_raft_log *log = &service->persistent_state.log;

    if (log->total_entries == log->capacity) {
        log->capacity += default_capacity;
        md_realloc(log->entries, sizeof(struct md_raft_entry) * log->capacity);
    }

    memcpy(&log->entries[log->total_entries], entry, sizeof(struct md_raft_entry));
    log->total_entries++;

    service->persistent_state.log_stale = true;
}

// Updated on stable storage before responding to RPCs
static void update_on_stable_storage(struct md_raft_service *service) {
    if (service->persistent_state.state_stale) {
        db_update_term_and_voted_for(service->database,
                                     service->persistent_state.current_term,
                                     service->persistent_state.voted_for);

        service->persistent_state.state_stale = false;
    }

    if (service->persistent_state.log_stale) {
        // TODO

        service->persistent_state.log_stale = false;
    }
}

// Invoked by leader to replicate log entries; also used as heartbeat.
static void replicate_log_entries(struct md_raft_service *service) {
    for (size_t i = 0; i < service->total_peers; ++i) {

    }

    const struct md_raft_volatile_leader_state *state = NULL;
//    for (size_t i = 0; i < service->total_peers; ++i) {
//        if (service->leader_state[i].peer_id == peer->id) {
//            state = &service->leader_state[i];
//            break;
//        }
//    }
    assert(state);

    struct md_rpc_append_entries_request request;
    request.term = service->persistent_state.current_term;
    request.leader_id = service->id;
}

static void send_rpc(struct rpc_arg *arg) {
    struct md_net_fd *fd = NULL;

    size_t size = 0;
    uint8_t *buffer = md_proto_serialize(arg->type, arg->message, &size);
    if (!buffer) {
        MD_LOG("md_proto_serialize returned NULL");
        goto end;
    }

    fd = md_net_create_fd(SOCK_STREAM);
    assert(fd);

    if (!md_net_connect(fd, arg->ip, arg->port)) {
        MD_LOG("md_net_connect returned false");
        goto end;
    }

    if (!md_net_tcp_send_with_u32_size(fd, buffer, size, total_retries))
    MD_LOG("md_net_tcp_send_with_u32_size returned false");

    end:
    md_net_destroy_fd(fd);
    md_free(buffer);
    md_free(arg->message);
    md_free(arg);
}

static void send_append_entries_rpc(struct md_raft_service *service, const struct md_raft_peer *peer) {
    struct md_rpc_append_entries_request *request = md_malloc(sizeof(struct md_rpc_append_entries_request));
    request->term = service->persistent_state.current_term;
    request->leader_id = service->id;
    request->previous_log_index = peer->leader_state->next_index - 1;
    request->previous_log_term = 0;
    request->leader_commit = service->volatile_state.commit_index;

//    request->total_entries =

//    request->previous_log_index = peer->leader_state->next_index;

    struct rpc_arg *arg = md_malloc(sizeof(struct rpc_arg));
    memcpy(arg->ip, peer->ip, MD_NET_IP_LENGTH);
    arg->port = peer->port;
    arg->type = MD_RPC_APPEND_ENTRIES_REQUEST;
    arg->message = request;

    md_thread_pool_add_task(service->thread_pool, (void (*)(void *)) send_rpc, arg);
}

static void send_command_response_rpc(struct command_response_rpc_arg *arg) {
    size_t size = 0;
    uint8_t *buffer = md_proto_serialize(MD_RPC_COMMAND_RESPONSE, arg->response, &size);
    if (!buffer) {
        MD_LOG("md_proto_serialize returned NULL");
        goto end;
    }

    if (!md_net_tcp_send_with_u32_size(arg->fd, buffer, size, total_retries))
    MD_LOG("md_net_tcp_send_with_u32_size returned false");

    end:
    md_free(buffer);
    md_net_destroy_fd(arg->fd);
    md_free(arg->response->leader);
    md_free(arg->response);
    md_free(arg);
}

// Followers
// - If commitIndex > lastApplied: increment lastApplied, apply log[lastApplied] to state machine
// - If RPC request or response contains term T > currentTerm: set currentTerm = T, convert to follower
// - Respond to RPCs from candidates and leaders
// - If election timeout elapses without receiving AppendEntries RPC from current leader or granting vote to candidate: convert to candidate
static void convert_to_follower(struct md_raft_service *service, uint64_t term) {
    MD_LOG("Server %" PRIu64 " is transiting from %s to follower (term %" PRIu64 ")",
           service->id, type_str[service->type], term);

    service->type = MD_RAFT_FOLLOWER;
    service->persistent_state.current_term = term;
    md_free(service->persistent_state.voted_for);
    service->persistent_state.voted_for = NULL;
    service->persistent_state.state_stale = true;

    service->election_timer.suspended = false;

//    if (service->leader_state) {
//        md_free(service->leader_state->next_indexes);
//        md_free(service->leader_state->match_indexes);
//        md_free(service->leader_state);
//        service->leader_state = NULL;
//    }
//    reset_election_timer(service);

}

// Candidates
// - If commitIndex > lastApplied: increment lastApplied, apply log[lastApplied] to state machine
// - If RPC request or response contains term T > currentTerm: set currentTerm = T, convert to follower
// - On conversion to candidate, start election:
//   + Increment currentTerm
//   + Vote for self
//   + Reset election timer
//   + Send RequestVote RPCs to all other servers
//   + If votes received from majority of servers: become leader
// - If AppendEntries RPC received from new leader: convert to follower
// - If election timeout elapses: start new election
static void convert_to_candidate(struct md_raft_service *service) {
    service->persistent_state.current_term++;
    MD_LOG("Server %" PRIu64 " is transiting from %s to follower (term %" PRIu64 ")",
           service->id, type_str[service->type], service->persistent_state.current_term);

    service->type = MD_RAFT_CANDIDATE;

    if (!service->persistent_state.voted_for)
        service->persistent_state.voted_for = md_malloc(sizeof(uint64_t));
    *service->persistent_state.voted_for = service->id;

    service->persistent_state.state_stale = true;

    struct md_rpc_request_vote_request request;
    request.term = service->persistent_state.current_term;
    request.candidate_id = service->id;
    request.last_log_index = service->persistent_state.log.total_entries;

    // TODO
//    request.last_log_term = get_last_log_term(service);

    for (size_t i = 0; i < service->total_peers; ++i) {
        struct rpc_arg *arg = md_malloc(sizeof(struct rpc_arg));
        memcpy(arg->ip, service->peers[i].ip, MD_NET_IP_LENGTH);
        arg->port = service->peers[i].port;
        arg->message = md_malloc(sizeof(struct md_rpc_request_vote_request));
        memcpy(&arg->message, &request, sizeof(struct md_rpc_request_vote_request));

        md_thread_pool_add_task(service->thread_pool, (void (*)(void *)) send_rpc, arg);
    }
}

// Leaders
// - If commitIndex > lastApplied: increment lastApplied, apply log[lastApplied] to state machine
// - If RPC request or response contains term T > currentTerm: set currentTerm = T, convert to follower
// Upon election: send initial empty AppendEntries RPCs (heartbeat) to each server; repeat during idle periods to prevent election timeouts
// - If command received from client: append entry to local log, respond after entry applied to state machine
// - If last log index >= nextIndex for a follower: send AppendEntries RPC with log entries starting at nextIndex
//   + If successful: update nextIndex and matchIndex for follower
//   + If AppendEntries fails because of log inconsistency: decrement nextIndex and retry
//   + If there exists an N such that N > commitIndex, a majority of matchIndex[i] >= N, and log[N].term == currentTerm: set commitIndex = N.
static void convert_to_leader(struct md_raft_service *service) {
    MD_LOG("Server %" PRIu64 " is transiting from candidate to leader (term %" PRIu64 ")",
           service->id, service->persistent_state.current_term);

    service->type = MD_RAFT_LEADER;

    for (size_t i = 0; i < service->total_peers; ++i) {
        service->peers[i].leader_state = md_malloc(sizeof(struct md_raft_volatile_leader_state));
        service->peers[i].leader_state->next_index = 1; // service->persistent_state.log.total_entries + 1
        service->peers[i].leader_state->match_index = 0;

        struct md_rpc_append_entries_request request;
        request.term = service->persistent_state.current_term;
        request.leader_id = service->id;
        request.leader_commit = service->volatile_state.commit_index;
        request.previous_log_index = service->peers[i].leader_state->next_index - 1;

        // 5 + 1 -> next_index = 6
        // log:
        // 1 2 3 4 5
        // a b c d e
        //
        // log:
        // 1 2 3 4
        // a b c d
        // next_index = 6
        size_t x = service->peers[i].leader_state->next_index - 1;

        request.entries = service->persistent_state.log.entries + 1;
        //     ae.entries = raft_get_entries_from_idx(me_, next_idx, &ae.n_entries);
    }
}

// If RPC request or response contains term T > currentTerm: set currentTerm = T, convert to follower
// 1. Reply false if term < currentTerm
// 2. Reply false if log doesn't contain an entry at prevLogIndex whose term matches prevLogTerm
// 3. If an existing entry conflicts with a new one (same index but different terms), delete the existing entry and all that follow it
// 4. Append any new entries not already in the log
static void receive_append_entries_request(struct md_raft_service *service,
                                           const struct md_rpc_append_entries_request *request) {
    if (request->total_entries) {
        MD_LOG("Server %" PRIu64 " received non-heartbeat AppendEntries RPC request from %" PRIu64 ": term %" PRIu64
                       ", prevLogIndex %" PRIu64 ", prevLogIndex %" PRIu64 ", %zu entries, leaderCommit %" PRIu64,
               service->id, request->leader_id,
               request->term,
               request->previous_log_index, request->previous_log_term,
               request->total_entries,
               request->leader_commit);
    }

    struct md_rpc_append_entries_response *response = md_malloc(sizeof(struct md_rpc_append_entries_response));
    response->success = false;

    if (request->term > service->persistent_state.current_term) convert_to_follower(service, request->term);

    if (request->term < service->persistent_state.current_term) goto end;

    const struct md_raft_entry *entry = get_log_entry(&service->persistent_state.log, request->previous_log_index);
    if (!entry) {
        MD_LOG("No log entry found at index %" PRIu64, request->previous_log_index);
        goto end;
    } else if (entry->term != request->previous_log_term) {
        MD_LOG("Log doesn't contain an entry at prevLogIndex whose term matches prevLogTerm %" PRIu64,
               request->previous_log_term);
        goto end;
    }


    end:
    response->term = service->persistent_state.current_term;
}

// If RPC request or response contains term T > currentTerm: set currentTerm = T, convert to follower
static void receive_append_entries_response(struct md_raft_service *service,
                                            const struct md_rpc_append_entries_response *response) {
    MD_LOG("Server %" PRIu64 " received AppendEntries RPC response: term %" PRIu64 ", success %d",
           service->id, response->term, response->success);

    if (response->term > service->persistent_state.current_term) convert_to_follower(service, response->term);
    else if (service->type == MD_RAFT_LEADER && service->persistent_state.current_term == response->term) {
        // TODO
        struct md_raft_peer *peer = get_peer(service, *service->leader_id);

//        service->volatile_state.commit_index
        if (service->volatile_state.commit_index < peer->leader_state->match_index) {
            for (size_t i = 0; i < service->total_peers; ++i) {
                if (service->peers[i].leader_state->match_index >= peer->leader_state->next_index - 1) {

                }
            }
        }
    }
}

// If RPC request or response contains term T > currentTerm: set currentTerm = T, convert to follower
// 1. Reply false if term < currentTerm
// 2. If votedFor is null or candidateId, and candidate's log is at least as up-to-date as receiver's log, grant vote
static void receive_request_vote_request(struct md_raft_service *service,
                                         const struct md_rpc_request_vote_request *request) {
    struct md_rpc_request_vote_response *response = md_malloc(sizeof(struct md_rpc_request_vote_response));

    if (request->term > service->persistent_state.current_term) convert_to_follower(service, request->term);

    if (request->term < service->persistent_state.current_term) response->vote_granted = false;

    else {
        // Raft determines which of two logs is more up-to-date by comparing the index and term of the last entries in the logs.
        // If the logs have last entries with different terms, then the log with the later term is more up-to-date.
        // If the logs end with the same term, then whichever log is longer is more up-to-date.
        if ((!service->persistent_state.voted_for || *service->persistent_state.voted_for == request->candidate_id)
            && (request->last_log_term > get_last_log_term(&service->persistent_state.log))) {
//        response->term = service->persistent_state.current_term;
            response->vote_granted = true;

            if (!service->persistent_state.voted_for) service->persistent_state.voted_for = md_malloc(sizeof(uint64_t));
            *service->persistent_state.voted_for = request->candidate_id;
        }
    }

    response->term = service->persistent_state.current_term;

    update_on_stable_storage(service);

    const struct md_raft_peer *candidate = get_peer(service, request->candidate_id);
    struct rpc_arg *arg = md_malloc(sizeof(struct rpc_arg));
    memcpy(arg->ip, candidate->ip, MD_NET_IP_LENGTH);
    arg->port = candidate->port;
    arg->type = MD_RPC_REQUEST_VOTE_RESPONSE;
    arg->message = response;
    md_thread_pool_add_task(service->thread_pool, (void (*)(void *)) send_rpc, arg);
}

// If RPC request or response contains term T > currentTerm: set currentTerm = T, convert to follower
static void receive_request_vote_response(struct md_raft_service *service,
                                          const struct md_rpc_request_vote_response *response) {
    if (response->term > service->persistent_state.current_term) convert_to_follower(service, response->term);

//    if (service->type == MD_RAFT_CANDIDATE && service->persistent_state.current_term == response->term) {
//        (*service->total_votes)++;
//        if (*service->total_votes >= get_quorum_count(service)) {
//            // TODO
//        }
//    }
}

static void receive_command_request(struct md_net_fd *fd,
                                    struct md_raft_service *service,
                                    const struct md_rpc_command_request *request) {
    // If command received from client: append entry to local log, respond after entry applied to state machine
    if (service->type == MD_RAFT_LEADER) {
        struct md_raft_entry entry;
        memcpy(&entry.command, &request->command, sizeof(struct md_raft_command));
        entry.term = service->persistent_state.current_term;

        struct md_waiting_client *current = NULL;
        if (!service->waiting_clients) current = service->waiting_clients = md_malloc(sizeof(struct md_waiting_client));
        else {
            while (true) {
                if (current->next) current = current->next;
                else {
                    current = current->next = md_malloc(sizeof(struct md_waiting_client));
                    break;
                }
            }
        }
        current->fd = fd;
        current->log_index = service->persistent_state.log.total_entries;
        current->next = NULL;

        append_log(service, &entry);

        md_thread_unlock(&service->mutex);
        return;
    }

    update_on_stable_storage(service);

    struct md_rpc_command_response *response = md_malloc(sizeof(struct md_rpc_command_response));
    if (service->leader_id) {
        response->type = MD_RPC_REDIRECT_TO_LEADER;
        response->leader = md_malloc(sizeof(*response->leader));

        const struct md_raft_peer *leader = get_peer(service, *service->leader_id);
        memcpy(response->leader->ip, leader->ip, MD_NET_IP_LENGTH);
        response->leader->port = leader->port;
    } else {
        response->type = MD_RPC_NO_LEADER;
        response->leader = NULL;
    }

    struct command_response_rpc_arg *arg = md_malloc(sizeof(struct command_response_rpc_arg));
    arg->fd = fd;
    arg->response = response;
    md_thread_pool_add_task(service->thread_pool, (void (*)(void *)) send_command_response_rpc, arg);
}

static void receive_message(struct md_raft_service *service) {
    char ip[MD_NET_IP_LENGTH];
    uint16_t port = 0;
    struct md_net_fd *new_fd = md_net_accept(service->fd, ip, &port);
    assert(new_fd);

    bool should_destroy_fd = true;
    bool should_lock = false;
    void *message = NULL;

    size_t size = 0;
    uint8_t *buffer = md_net_tcp_receive_with_u32_size(new_fd, &size);
    if (!buffer) {
        MD_LOG("md_net_tcp_receive_with_u32_size returned NULL");
        should_lock = true;
        goto end;
    }

    enum md_rpc_type type = 0;
    if (!(message = md_proto_deserialize(&type, buffer, size))) {
        MD_LOG("md_proto_deserialize returned NULL");
        should_lock = true;
        goto end;
    }

    md_thread_lock(&service->mutex);

    if (service->terminable) goto end;

    switch (type) {
        case MD_RPC_APPEND_ENTRIES_REQUEST:
            receive_append_entries_request(service, message);
            break;
        case MD_RPC_APPEND_ENTRIES_RESPONSE:
            receive_append_entries_response(service, message);
            break;
        case MD_RPC_REQUEST_VOTE_REQUEST:
            receive_request_vote_request(service, message);
            break;
        case MD_RPC_REQUEST_VOTE_RESPONSE:
            receive_request_vote_response(service, message);
            break;
        case MD_RPC_COMMAND_REQUEST:
            receive_command_request(new_fd, service, message);
            should_destroy_fd = false;
            break;
        case MD_RPC_COMMAND_RESPONSE:
            MD_ABORT("This should never happen");
        default:
            MD_ABORT("Unknown md_rpc_type case: %d", type);
    }

    end:
    if (should_lock) md_thread_lock(&service->mutex);
    service->total_connections--;
    md_thread_signal(&service->connections_cond);
    md_thread_unlock(&service->mutex);

    md_free(message);
    md_free(buffer);
    if (should_destroy_fd) md_net_destroy_fd(new_fd);
}

static int election_timer_main_loop(struct md_raft_service *service) {
    md_utils_set_thread_name("ElectionTimer");

    md_thread_lock(&service->mutex);

    while (true) {
        while (!service->terminable && service->election_timer.suspended)
            md_thread_wait(&service->election_timer.cond, &service->mutex);

        if (service->terminable) break;

        // [timeout, 2 * timeout]
        const size_t timeout = md_rand() % (service->election_timer.timeout + 1) + service->election_timer.timeout;
        const struct timespec due = get_due_time((long) timeout);

        while (true) {
            if (md_thread_timedwait(&service->election_timer.cond, &service->mutex, &due) == thrd_timedout) {
                convert_to_candidate(service);
                break;
            }

            if (!service->terminable && !service->election_timer.suspended) continue;
        }
    }

    md_thread_unlock(&service->mutex);

    return EXIT_SUCCESS;
}

static int heartbeat_timer_main_loop(struct md_raft_service *service) {
    md_utils_set_thread_name("HeartbeatTimer");

    md_thread_lock(&service->mutex);

    while (true) {
        while (!service->terminable && service->heartbeat_timer.suspended)
            md_thread_wait(&service->heartbeat_timer.cond, &service->mutex);

        if (service->terminable) break;

        const struct timespec due = get_due_time((long) service->heartbeat_timer.timeout);

        while (true) {
            if (md_thread_timedwait(&service->heartbeat_timer.cond, &service->mutex, &due) == thrd_timedout) {
                for (size_t i = 0; service->total_peers; ++i) send_append_entries_rpc(service, &service->peers[i]);
                break;
            }

            if (!service->terminable && !service->heartbeat_timer.suspended) continue;
        }
    }

    md_thread_unlock(&service->mutex);

    return EXIT_SUCCESS;
}

struct md_raft_service *md_raft_service_create(
        uint64_t id,
        const struct md_raft_peer_arg *peers, size_t total_peers,
        uint16_t port, size_t poll_timeout,
        size_t election_timeout,
        struct md_thread_pool *thread_pool,
        struct sqlite3 *database) {
    assert(peers && total_peers && election_timeout && thread_pool && database);
    for (size_t i = 0; i < total_peers; ++i) {
        assert(peers[i].id != id);
        for (size_t j = i + 1; j < total_peers; ++j) {
            assert(peers[i].id != peers[j].id != 0);
            if (strcmp(peers[i].ip, peers[j].ip) == 0) assert(peers[i].port != peers[j].port);
        }
    }

    struct md_raft_service *service = md_malloc(sizeof(struct md_raft_service));
    service->id = id;
    service->leader_id = NULL;
    service->type = MD_RAFT_FOLLOWER;
    service->persistent_state.current_term = 0;
    service->persistent_state.voted_for = NULL;
    service->persistent_state.log.capacity = default_capacity;
    service->persistent_state.log.total_entries = 0;
    service->persistent_state.log.entries = md_malloc(sizeof(struct md_raft_entry) * default_capacity);

    size_t total_entries = 0;
    struct md_raft_entry *entries = NULL;
    if (db_get_persistent_state(
            database,
            &service->persistent_state.current_term, &service->persistent_state.voted_for,
            &entries, &total_entries)) {
        if (total_entries) {
            if (total_entries >= service->persistent_state.log.capacity) {
                service->persistent_state.log.capacity += default_capacity;
                md_realloc(service->persistent_state.log.entries,
                           sizeof(struct md_raft_entry) * service->persistent_state.log.capacity);
            }

            service->persistent_state.log.total_entries = total_entries;
            memcpy(service->persistent_state.log.entries, entries, sizeof(struct md_raft_entry) * total_entries);

            md_free(entries);
        }
    }

    service->persistent_state.state_stale = false;
    service->persistent_state.log_stale = false;

    service->total_peers = total_peers;
    service->peers = md_malloc(sizeof(struct md_raft_peer) * total_peers);
    for (size_t i = 0; i < total_peers; ++i) {
        service->peers[i].id = peers[i].id;
        memcpy(service->peers[i].ip, peers[i].ip, MD_NET_IP_LENGTH);
        service->peers[i].port = peers[i].port;
        service->peers[i].leader_state = NULL;
    }

    service->fd = md_net_create_fd(SOCK_STREAM);
    assert(service->fd);
    service->port = port;
    service->poll_timeout = poll_timeout;
    service->waiting_clients = NULL;

    service->total_connections = 0;
    md_thread_cond_init(&service->connections_cond);
    service->thread_pool = thread_pool;
    service->database = database;
    md_thread_mutex_init(&service->mutex, mtx_plain);
    service->terminable = false;
    service->running = false;

    md_thread_cond_init(&service->election_timer.cond);
    service->election_timer.timeout = election_timeout;
    service->election_timer.suspended = true;
    md_thread_create(service->election_timer.thread, (thrd_start_t) election_timer_main_loop, service);

    return service;
}

void md_raft_service_request_to_terminate(struct md_raft_service *service) {
    assert(service);

    md_thread_lock(&service->mutex);
    assert(service->running);
    service->terminable = true;
    md_thread_unlock(&service->mutex);
}

int md_raft_service_main_loop(struct md_raft_service *service) {
    assert(service);

    md_thread_lock(&service->mutex);

    if (service->terminable || service->running) {
        md_thread_unlock(&service->mutex);
        return EXIT_FAILURE;
    }

    service->running = true;
    service->election_timer.suspended = false;
    md_thread_signal(&service->election_timer.cond);

    md_thread_unlock(&service->mutex);

    MD_LOG("Raft service is running...");

    const bool rc = md_net_bind(service->fd, service->port);
    assert(rc);

    md_net_listen(service->fd);

    while (true) {
        const bool readable = md_net_pollin(service->fd, service->poll_timeout);

        md_thread_lock(&service->mutex);

        if (service->terminable) {
            MD_LOG("Terminating Raft service...");

            while (service->total_connections) md_thread_wait(&service->connections_cond, &service->mutex);
            service->running = false;
            md_thread_unlock(&service->mutex);
            break;
        }

        if (readable) service->total_connections++;

        md_thread_unlock(&service->mutex);

        if (readable) md_thread_pool_add_task(service->thread_pool, (void (*)(void *)) receive_message, service);
    }

    md_thread_join(service->election_timer.thread);

    while (service->waiting_clients) {
        struct md_waiting_client *current = service->waiting_clients;
        service->waiting_clients = service->waiting_clients->next;
        md_net_destroy_fd(current->fd);
        md_free(current);
    }

    md_free(service->leader_id);
    md_free(service->persistent_state.voted_for);
    md_free(service->persistent_state.log.entries);
    md_net_destroy_fd(service->fd);
    cnd_destroy(&service->election_timer.cond);
    cnd_destroy(&service->connections_cond);
    mtx_destroy(&service->mutex);
    md_free(service);

    return EXIT_SUCCESS;
}
