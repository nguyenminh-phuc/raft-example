#include "database.h"
#include <assert.h>
#include <string.h>
#include <sqlite3.h>
#include "minidns/dns.h"
#include "minidns/raft.h"
#include "minidns/utils.h"

enum {
    STATE_ID,
    STATE_CURRENT_TERM,
    STATE_VOTED_FOR
};

enum {
    LOG_ID,
    LOG_TERM,
    LOG_COMMAND_TYPE,
    LOG_NAME,
    LOG_DNS_TYPE,
    LOG_TTL,
    LOG_ADDRESS,
    LOG_DATA,
    LOG_PRIORITY
};

enum {
    RECORD_NAME,
    RECORD_TYPE,
    RECORD_TTL,
    RECORD_ADDRESS,
    RECORD_DATA,
    RECORD_PRIORITY
};

static const int state_id = 1;

static void prepare(struct sqlite3 *db, const char *sql, sqlite3_stmt **stmt) {
    if (sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK)
        MD_ABORT("sqlite3_prepare_v2 returned error: %s", sqlite3_errmsg(db));
}

sqlite3 *db_open(const char *filename) {
    assert(filename);

    sqlite3 *db = NULL;
    char *error = NULL;

    if (sqlite3_open(filename, &db) != SQLITE_OK) {
        MD_TRACE("sqlite3_open returned error: %s", sqlite3_errmsg(db));
        goto error;
    }

    static const char sql[] = "CREATE TABLE IF NOT EXISTS state ("
                              "   id INTEGER PRIMARY KEY,"
                              "   currentTerm INTEGER NOT NULL,"
                              "   votedFor INTEGER);"
                              "CREATE TABLE IF NOT EXISTS log ("
                              "   id INTEGER PRIMARY KEY AUTOINCREMENT,"
                              "   term INTEGER NOT NULL,"
                              "   commandType INTEGER NOT NULL,"
                              "   name TEXT NOT NULL,"
                              "   dnsType INTEGER NOT NULL,"
                              "   ttl INTEGER NOT NULL,"
                              "   address TEXT,"
                              "   data TEXT,"
                              "   priority INTEGER);"
                              "CREATE TABLE IF NOT EXISTS record ("
                              "   name TEXT NOT NULL,"
                              "   type INTEGER NOT NULL,"
                              "   ttl INTEGER NOT NULL,"
                              "   address TEXT,"
                              "   data TEXT,"
                              "   priority INTEGER);";
    if (sqlite3_exec(db, sql, NULL, NULL, &error) != SQLITE_OK) {
        MD_TRACE("sqlite3_exec returned error: %s", error);
        goto error;
    }

    return db;

    error:
    sqlite3_free(error);
    db_close(db);
    return NULL;
}

void db_close(sqlite3 *db) {
    if (sqlite3_close(db) != SQLITE_OK) MD_ABORT("sqlite3_close returned error: %s", sqlite3_errmsg(db));
}

bool db_get_persistent_state(
        struct sqlite3 *db,
        uint64_t *current_term, uint64_t **voted_for,
        struct md_raft_entry **entries, size_t *total_entries) {
    assert(db && current_term && voted_for && entries && total_entries);

    sqlite3_stmt *stmt = NULL;
    prepare(db, "SELECT * FROM state LIMIT 1", &stmt);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return false;
    }

    *current_term = sqlite3_column_int64(stmt, STATE_CURRENT_TERM);
    if (sqlite3_column_type(stmt, STATE_VOTED_FOR) == SQLITE_NULL) *voted_for = NULL;
    else {
        *voted_for = md_malloc(sizeof(uint64_t));
        **voted_for = sqlite3_column_int64(stmt, STATE_VOTED_FOR);
    }

    sqlite3_finalize(stmt);

    stmt = NULL;
    prepare(db, "SELECT COUNT(*) FROM log", &stmt);

    const int rc = sqlite3_step(stmt);
    assert(rc == SQLITE_ROW);

    *total_entries = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (!*total_entries) {
        *entries = NULL;
        return true;
    } else *entries = md_malloc(sizeof(struct md_raft_entry) * *total_entries);

    stmt = NULL;
    prepare(db, "SELECT * FROM log ORDER BY id ASC", &stmt);

    size_t i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        (*entries)[i].term = sqlite3_column_int(stmt, LOG_TERM);
        (*entries)[i].command.type = sqlite3_column_int(stmt, LOG_COMMAND_TYPE);

        struct md_dns_record *record = &(*entries)[i].command.record;
        record->type = sqlite3_column_int(stmt, LOG_DNS_TYPE);
        record->ttl = sqlite3_column_int(stmt, LOG_TTL);

        const char *name = (const char *) sqlite3_column_text(stmt, LOG_NAME);
        assert(name);
        memcpy(record->name, name, strlen(name) + 1);

        if (record->type == MD_DNS_A || record->type == MD_DNS_AAAA) {
            const char *address = (const char *) sqlite3_column_text(stmt, LOG_ADDRESS);
            assert(address);

            if (record->type == MD_DNS_A) memcpy(record->data.a.address, address, strlen(address) + 1);
            else memcpy(record->data.aaaa.address, address, strlen(address) + 1);
        } else if (record->type == MD_DNS_NS || record->type == MD_DNS_CNAME || record->type == MD_DNS_MX) {
            const char *data = (const char *) sqlite3_column_text(stmt, LOG_DATA);
            assert(data);

            if (record->type == MD_DNS_NS) memcpy(record->data.ns.name, data, strlen(data) + 1);
            else if (record->type == MD_DNS_CNAME) memcpy(record->data.cname.name, data, strlen(data) + 1);
            else {
                memcpy(record->data.mx.name, data, strlen(data) + 1);
                record->data.mx.priority = sqlite3_column_int(stmt, LOG_PRIORITY);
            }
        };

        ++i;
    }
    assert(*total_entries == i);

    sqlite3_finalize(stmt);

    return true;
}

bool db_update_term_and_voted_for(struct sqlite3 *db, uint64_t current_term, const uint64_t *voted_for) {
    assert(db);

    sqlite3_stmt *stmt = NULL;
    prepare(db, "INSERT OR REPLACE INTO state VALUES(?, ?, ?)", &stmt);

    sqlite3_bind_int(stmt, STATE_ID + 1, state_id);
    sqlite3_bind_int64(stmt, STATE_CURRENT_TERM + 1, (int) current_term);
    if (!voted_for) sqlite3_bind_null(stmt, STATE_VOTED_FOR + 1);
    else sqlite3_bind_int64(stmt, STATE_VOTED_FOR + 1, *voted_for);

    bool result = true;
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        MD_TRACE("sqlite3_step returned error: %s", sqlite3_errmsg(db));
        result = false;
    }

    sqlite3_finalize(stmt);

    return result;
}

struct md_dns_record *db_get_records(struct sqlite3 *db, size_t *size) {
    assert(db && size);

    sqlite3_stmt *stmt = NULL;
    prepare(db, "SELECT COUNT(*) FROM record", &stmt);

    const int rc = sqlite3_step(stmt);
    assert(rc == SQLITE_ROW);

    *size = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (!*size) return NULL;
    struct md_dns_record *records = md_malloc(sizeof(struct md_dns_record) * *size);

    stmt = NULL;
    prepare(db, "SELECT * FROM record", &stmt);

    size_t i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *name = (const char *) sqlite3_column_text(stmt, RECORD_NAME);
        assert(name);
        memcpy(records[i].name, name, strlen(name) + 1);

        records[i].type = sqlite3_column_int(stmt, RECORD_TYPE);
        records[i].ttl = sqlite3_column_int(stmt, RECORD_TTL);

        if (records[i].type == MD_DNS_A || records[i].type == MD_DNS_AAAA) {
            const char *address = (const char *) sqlite3_column_text(stmt, RECORD_ADDRESS);
            assert(address);

            if (records[i].type == MD_DNS_A) memcpy(records[i].data.a.address, address, strlen(address) + 1);
            else memcpy(records[i].data.aaaa.address, address, strlen(address) + 1);
        } else if (records[i].type == MD_DNS_NS || records[i].type == MD_DNS_CNAME || records[i].type == MD_DNS_MX) {
            const char *data = (const char *) sqlite3_column_text(stmt, RECORD_DATA);
            assert(data);

            if (records[i].type == MD_DNS_NS) memcpy(records[i].data.ns.name, data, strlen(data) + 1);
            else if (records[i].type == MD_DNS_CNAME) memcpy(records[i].data.cname.name, data, strlen(data) + 1);
            else {
                memcpy(records[i].data.mx.name, data, strlen(data) + 1);
                records[i].data.mx.priority = sqlite3_column_int(stmt, RECORD_PRIORITY);
            }
        };

        ++i;
    }
    assert(*size == i);

    sqlite3_finalize(stmt);

    return records;
}

bool db_add_record(struct sqlite3 *db, const struct md_dns_record *record) {
    assert(db && record);

    sqlite3_stmt *stmt = NULL;
    prepare(db, "INSERT INTO record VALUES(?, ?, ?, ?, ?, ?)", &stmt);

    sqlite3_bind_text(stmt, RECORD_NAME + 1, record->name, -1, NULL);
    sqlite3_bind_int(stmt, RECORD_TYPE + 1, record->type);
    sqlite3_bind_int(stmt, RECORD_TTL + 1, record->ttl);

    if (record->type == MD_DNS_A || record->type == MD_DNS_AAAA) {
        if (record->type == MD_DNS_A) sqlite3_bind_text(stmt, RECORD_ADDRESS + 1, record->data.a.address, -1, NULL);
        else sqlite3_bind_text(stmt, RECORD_ADDRESS + 1, record->data.aaaa.address, -1, NULL);
        sqlite3_bind_null(stmt, RECORD_DATA + 1);
        sqlite3_bind_null(stmt, RECORD_PRIORITY + 1);
    } else if (record->type == MD_DNS_NS || record->type == MD_DNS_CNAME || record->type == MD_DNS_MX) {
        sqlite3_bind_null(stmt, RECORD_ADDRESS + 1);
        if (record->type == MD_DNS_NS) {
            sqlite3_bind_text(stmt, RECORD_DATA + 1, record->data.ns.name, -1, NULL);
            sqlite3_bind_null(stmt, RECORD_PRIORITY + 1);
        } else if (record->type == MD_DNS_CNAME) {
            sqlite3_bind_text(stmt, RECORD_DATA + 1, record->data.cname.name, -1, NULL);
            sqlite3_bind_null(stmt, RECORD_PRIORITY + 1);
        } else {
            sqlite3_bind_text(stmt, RECORD_DATA + 1, record->data.cname.name, -1, NULL);
            sqlite3_bind_int(stmt, RECORD_PRIORITY + 1, record->data.mx.priority);
        }
    }

    bool result = true;
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        MD_TRACE("sqlite3_step returned error: %s", sqlite3_errmsg(db));
        result = false;
    }

    sqlite3_finalize(stmt);

    return result;
}

bool db_remove_record(struct sqlite3 *db, const struct md_dns_record *record) {
    assert(db && record);

    static const char a_aaaa_sql[] =
            "DELETE FROM record "
            "WHERE name=? AND type=? AND ttl=? AND address=? AND data IS NULL AND priority IS NULL";
    static const char ns_cname_sql[] =
            "DELETE FROM record "
            "WHERE name=? AND type=? AND ttl=? AND address IS NULL AND data=? AND priority IS NULL";
    static const char mx_sql[] =
            "DELETE FROM record "
            "WHERE name=? AND type=? AND ttl=? AND address IS NULL AND data=? AND priority=?";

    const char *sql = NULL;
    switch (record->type) {
        case MD_DNS_A:
        case MD_DNS_AAAA:
            sql = a_aaaa_sql;
            break;
        case MD_DNS_NS:
        case MD_DNS_CNAME:
            sql = ns_cname_sql;
            break;
        case MD_DNS_MX:
            sql = mx_sql;
            break;
        case MD_DNS_UNKNOWN:
            MD_ABORT("This should never happen");
    }

    sqlite3_stmt *stmt = NULL;
    prepare(db, sql, &stmt);

    sqlite3_bind_text(stmt, 1, record->name, -1, NULL);
    sqlite3_bind_int(stmt, 2, record->type);
    sqlite3_bind_int(stmt, 3, record->ttl);

    switch (record->type) {
        case MD_DNS_A:
            sqlite3_bind_text(stmt, 4, record->data.a.address, -1, NULL);
            break;
        case MD_DNS_NS:
            sqlite3_bind_text(stmt, 4, record->data.ns.name, -1, NULL);
            break;
        case MD_DNS_CNAME:
            sqlite3_bind_text(stmt, 4, record->data.cname.name, -1, NULL);
            break;
        case MD_DNS_MX:
            sqlite3_bind_text(stmt, 4, record->data.cname.name, -1, NULL);
            sqlite3_bind_int(stmt, 5, record->data.mx.priority);
            break;
        case MD_DNS_AAAA:
            sqlite3_bind_text(stmt, 4, record->data.aaaa.address, -1, NULL);
            break;
        case MD_DNS_UNKNOWN:
            MD_ABORT("This should never happen");
    }

    bool result = true;
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        MD_TRACE("sqlite3_step returned error: %s", sqlite3_errmsg(db));
        result = false;
    }

    sqlite3_finalize(stmt);

    return result;
}
