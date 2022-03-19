#ifndef MD_RPC2_H
#define MD_RPC2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "minidns/network.h"
#include "minidns/raft.h"

#ifdef __cplusplus
extern "C" {
#endif

enum md_rpc_type {
    MD_RPC_APPEND_ENTRIES_REQUEST,
    MD_RPC_APPEND_ENTRIES_RESPONSE,
    MD_RPC_REQUEST_VOTE_REQUEST,
    MD_RPC_REQUEST_VOTE_RESPONSE,

    MD_RPC_COMMAND_REQUEST,
    MD_RPC_COMMAND_RESPONSE
};

// Invoked by leader to replicate log entries; also used as heartbeat
struct md_rpc_append_entries_request {
    uint64_t term;                 // leader's term
    uint64_t leader_id;            // so follower can redirect clients
    uint64_t previous_log_index;   // index of log entry immediately preceding new ones
    uint64_t previous_log_term;    // term of prevLogIndex entry
    struct md_raft_entry *entries; // log entries to store (empty for heartbeat; may send more than one for efficiency)
    size_t total_entries;
    uint64_t leader_commit;        // leader's commitIndex
};

struct md_rpc_append_entries_response {
    uint64_t term; // currentTerm, for leader to update itself
    uint64_t id;
    bool success;  // true if follower contained entry matching prevLogIndex and prevLogTerm
};

// Invoked by candidates to gather votes
struct md_rpc_request_vote_request {
    uint64_t term;           // candidate's term
    uint64_t candidate_id;   // candidate requesting vote
    uint64_t last_log_index; // index of candidate's last log entry
    uint64_t last_log_term;  // term of candidate's last log entry
};

struct md_rpc_request_vote_response {
    uint64_t term;     // currentTerm, for candidate to update itself
    bool vote_granted; // true means candidate received vote
};

struct md_rpc_command_request {
    struct md_raft_command command;
};

struct md_rpc_command_response {
    enum {
        MD_RPC_ENTRY_APPLIED,
        MD_RPC_NO_LEADER,
        MD_RPC_REDIRECT_TO_LEADER,
    } type;

    struct {
        char ip[MD_NET_IP_LENGTH];
        uint16_t port;
    } *leader;
};

#ifdef __cplusplus
}
#endif

#endif
