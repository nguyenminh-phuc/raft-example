#ifndef DATABASE_H
#define DATABASE_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

struct sqlite3;
struct md_dns_record;
struct md_raft_entry;

struct sqlite3 *db_open(const char *filename);

void db_close(struct sqlite3 *db);

bool db_get_persistent_state(
        struct sqlite3 *db,
        uint64_t *current_term, uint64_t **voted_for,
        struct md_raft_entry **entries, size_t *total_entries);

bool db_update_term_and_voted_for(struct sqlite3 *db, uint64_t current_term, const uint64_t *voted_for);

struct md_dns_record *db_get_records(struct sqlite3 *db, size_t *size);

bool db_add_record(struct sqlite3 *db, const struct md_dns_record *record);

bool db_remove_record(struct sqlite3 *db, const struct md_dns_record *record);

#endif
