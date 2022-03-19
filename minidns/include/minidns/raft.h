#ifndef MD_RAFT_H
#define MD_RAFT_H

#include <stddef.h>
#include <stdint.h>
#include "minidns/dns.h"

#ifdef __cplusplus
extern "C" {
#endif

struct md_raft_command {
    enum {
        MD_STATE_COMMAND_ADD,
        MD_STATE_COMMAND_REMOVE,
    } type;

    struct md_dns_record record;
};

// Contains command for state machine, and term when entry was received by leader (first index is 1)
struct md_raft_entry {
    struct md_raft_command command;
    uint64_t term;
};

struct md_raft_log {
    size_t capacity;
    size_t total_entries; // last log index
    struct md_raft_entry *entries;
};

// Persistent state on all servers: (Updated on stable storage before responding to RPCs)
struct md_raft_persistent_state {
    uint64_t current_term;  // latest term server has seen (initialized to 0 on first boot, increases monotonically)
    uint64_t *voted_for;    // candidateId that received vote in current term (or null if none)
    struct md_raft_log log; // log entries
    uint64_t *synced_log_index; // TODO
    bool state_stale;
    bool log_stale;
};

// Volatile state on all servers:
struct md_raft_volatile_state {
    uint64_t commit_index; // index of highest log entry known to be committed (initialized to 0, increases monotonically)
    uint64_t last_applied; // index of highest log entry applied to state machine (initialized to 0, increases monotonically)
};

// Volatile state on leaders: (Reinitialized after election)
struct md_raft_volatile_leader_state {
    uint64_t next_index;  // for each server, index of the next log entry to send to that server (initialized to leader last log index + 1)
    uint64_t match_index; // for each server, index of highest log entry known to be replicated on server (initialized to 0, increases monotonically)
};

#ifdef __cplusplus
}
#endif

#endif
