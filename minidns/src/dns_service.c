#include "minidns/dns_service.h"
#include <assert.h>
#include "database.h"
#include "minidns/thread_pool.h"
#include "minidns/utils.h"

#ifndef _WIN32

#include <sys/socket.h>

#endif

// https://www.internic.net/domain/named.root
static const char *const root_ips[] = {
#ifdef MD_ENABLE_IPV6_STACK
        "2001:503:ba3e::2:30",
        "2001:500:200::b",
        "2001:500:2::c",
        "2001:500:2d::d",
        "2001:500:a8::e",
        "2001:500:2f::f",
        "2001:500:12::d0d",
        "2001:500:1::53",
        "2001:7fe::53",
        "2001:503:c27::2:30",
        "2001:7fd::1",
        "2001:500:9f::42",
        "2001:dc3::35"
#else
        "198.41.0.4",
        "199.9.14.201",
        "192.33.4.12",
        "199.7.91.13",
        "192.203.230.10",
        "192.5.5.241",
        "192.112.36.4",
        "198.97.190.53",
        "192.36.148.17",
        "192.58.128.30",
        "193.0.14.129",
        "199.7.83.42",
        "202.12.27.33"
#endif
};

static const char *const root_names[] = {
        "a.root-servers.net",
        "b.root-servers.net",
        "c.root-servers.net",
        "d.root-servers.net",
        "e.root-servers.net",
        "f.root-servers.net",
        "g.root-servers.net",
        "h.root-servers.net",
        "i.root-servers.net",
        "j.root-servers.net",
        "k.root-servers.net",
        "l.root-servers.net",
        "m.root-servers.net",
};

#ifdef MD_ENABLE_IPV6_STACK
static const enum md_dns_type nameserver_type = MD_DNS_AAAA;
#else
static const enum md_dns_type nameserver_type = MD_DNS_A;
#endif

static const size_t default_capacity = 50;

static size_t get_cache_index(enum md_dns_type type) {
    switch (type) {
        case MD_DNS_A:
            return 0;
        case MD_DNS_NS:
            return 1;
        case MD_DNS_CNAME:
            return 2;
        case MD_DNS_MX:
            return 3;
        case MD_DNS_AAAA:
            return 4;
        default:
            MD_ABORT("Unknown md_dns_type case: %d", type);
    }
}

static bool find_existed_record(const struct md_dns_table *table, const struct md_dns_record *record, size_t *index) {
    for (size_t i = 0; i < table->total_records; ++i) {
        bool existed = false;

        if (strcmp(table->records[i].name, record[i].name) != 0 || table->records[i].ttl != record->ttl) continue;
        switch (record->type) {
            case MD_DNS_A:
                if (strcmp(table->records[i].data.a.address, record->data.a.address) == 0) existed = true;
                break;
            case MD_DNS_NS:
                if (strcmp(table->records[i].data.ns.name, record->data.ns.name) == 0) existed = true;
                break;
            case MD_DNS_CNAME:
                if (strcmp(table->records[i].data.cname.name, record->data.cname.name) == 0) existed = true;
                break;
            case MD_DNS_MX:
                if (strcmp(table->records[i].data.mx.name, record->data.mx.name) == 0 &&
                    table->records[i].data.mx.priority == record->data.mx.priority)
                    existed = true;
                break;
            case MD_DNS_AAAA:
                if (strcmp(table->records[i].data.aaaa.address, record->data.aaaa.address) == 0) existed = true;
                break;
            case MD_DNS_UNKNOWN:
                MD_ABORT("This should never happen");
        }

        if (existed) {
            *index = i;
            return true;
        }
    }

    return false;
}

static struct md_dns_packet *create_response_template(const struct md_dns_packet *request) {
    struct md_dns_packet *response = md_calloc(1, sizeof(struct md_dns_packet));
    response->transaction_id = request->transaction_id;
    response->response = MD_DNS_RESPONSE;
    response->recursion_desired = request->recursion_desired;
    response->recursion_available = true;
    response->total_questions = request->total_questions;
    response->questions = md_malloc(sizeof(struct md_dns_question) * response->total_questions);
    memcpy(response->questions, request->questions, sizeof(struct md_dns_question) * response->total_questions);

    return response;
}

static bool lookup_local(
        struct md_dns_table const cache[5],
        const struct md_dns_question *question,
        struct md_dns_packet *response) {
    const struct md_dns_table *table = &cache[get_cache_index(question->type)];

    for (size_t i = 0; i < table->total_records; ++i) {
        if (strcmp(question->name, table->records[i].name) == 0) {
            if (!response->answer_rrs) response->answer_rrs = md_malloc(sizeof(struct md_dns_record));
            else md_realloc(response->answer_rrs, sizeof(struct md_dns_record) * (response->total_answer_rrs + 1));

            memcpy(&response->answer_rrs[response->total_answer_rrs], &table->records[i], sizeof(struct md_dns_record));
            response->total_answer_rrs++;
        }
    }

    return response->total_answer_rrs;
}

static void find_authoritative_nameserver(
        const struct md_dns_packet *packet,
        const char **first_server_name,
        const char **server_name, const char **server_ip,
        const char name[MD_DNS_NAME_LENGTH]) {
    for (size_t i = 0; i < packet->total_authority_rrs; ++i)
        if (packet->authority_rrs[i].type == MD_DNS_NS &&
            md_utils_string_ends_with(name, packet->authority_rrs[i].name)) {
            if (!*first_server_name) *first_server_name = packet->authority_rrs[i].data.cname.name;

            for (size_t j = 0; j < packet->total_additional_rrs; ++j)
                if (packet->additional_rrs[j].type == nameserver_type &&
                    strcmp(packet->authority_rrs[i].data.cname.name, packet->additional_rrs[j].name) == 0) {
                    *server_name = packet->additional_rrs[j].name;
#ifdef MD_ENABLE_IPV6_STACK
                    ns_ip = response->additional_rrs[i].aaaa.address;
#else
                    *server_ip = packet->additional_rrs[j].data.a.address;
#endif
                    return;
                }
        }
}

static bool lookup_nameserver_ip(
        size_t server_timeout,
        const char name[MD_DNS_NAME_LENGTH], char ip[MD_NET_IP_LENGTH]) {
    struct md_dns_packet *response = md_dns_service_lookup_recursive(server_timeout, name, nameserver_type);
    if (!response) return false;

    bool result = false;
    for (size_t i = 0; i < response->total_answer_rrs; ++i) {
        if (strcmp(response->answer_rrs[i].name, name) == 0 &&
            response->answer_rrs[i].type == nameserver_type) {
#ifdef MD_ENABLE_IPV6_STACK
            memcpy(ip, response->answer_rrs[i].aaaa.address, MD_NET_IP_LENGTH);
#else
            memcpy(ip, response->answer_rrs[i].data.a.address, MD_NET_IP_LENGTH);
#endif
            result = true;
            break;
        }
    }

    md_dns_destroy(response);

    return result;
}

static void lookup(
        const struct md_dns_service *service,
        const struct md_dns_question *question,
        struct md_dns_packet *response) {
    if (lookup_local(service->cache, question, response)) return;

    const struct md_dns_packet *remote_response = md_dns_service_lookup(
            service->public_dns_ip, service->public_dns_port, service->public_dns_poll_timeout,
            true,
            question->name, question->type);

    if (!remote_response) {
        response->reply_code = MD_DNS_REPLY_SERVER_FAILURE;
        return;
    } else response->reply_code = response->reply_code;

    if ((response->total_answer_rrs = remote_response->total_answer_rrs)) {
        response->answer_rrs = md_malloc(sizeof(struct md_dns_record) * response->total_answer_rrs);
        memcpy(response->answer_rrs,
               remote_response->answer_rrs,
               sizeof(struct md_dns_record) * response->total_answer_rrs);
    }

    if ((response->total_authority_rrs = remote_response->total_authority_rrs)) {
        response->authority_rrs = md_malloc(sizeof(struct md_dns_record) * response->total_authority_rrs);
        memcpy(response->authority_rrs,
               remote_response->authority_rrs,
               sizeof(struct md_dns_record) * response->total_authority_rrs);
    }

    if ((response->total_additional_rrs = remote_response->total_additional_rrs)) {
        response->additional_rrs = md_malloc(sizeof(struct md_dns_record) * response->total_additional_rrs);
        memcpy(response->additional_rrs,
               remote_response->additional_rrs,
               sizeof(struct md_dns_record) * response->total_additional_rrs);
    }
}

static void receive_request(struct md_dns_service *service) {
    struct md_dns_packet *request = NULL, *response = NULL;

    uint8_t request_buffer[MD_DNS_MAX_SIZE];
    size_t request_buffer_size = sizeof request_buffer;
    char ip[MD_NET_IP_LENGTH];
    uint16_t port = 0;
    if (!md_net_udp_receive(service->fd, request_buffer, &request_buffer_size, ip, &port)) goto end;

    request = md_dns_parse(request_buffer, request_buffer_size);
    if (!request || request->response != MD_DNS_QUERY || request->truncated) goto end;

    response = create_response_template(request);
    if (request->opcode != MD_DNS_OP_QUERY) response->reply_code = MD_DNS_REPLY_NOT_IMPLEMENTED;
    else if (request->total_questions != 1) response->reply_code = MD_DNS_REPLY_FORMAT_ERROR;
    else lookup(service, &request->questions[0], response);

    uint8_t response_buffer[MD_DNS_MAX_SIZE];
    size_t response_buffer_size = sizeof response_buffer;

    md_dns_serialize(response, response_buffer, &response_buffer_size);

    md_net_udp_send(service->fd, response_buffer, response_buffer_size, true, ip, port);

    end:
    md_thread_lock(&service->mutex);
    service->total_connections--;
    md_thread_signal(&service->connections_cond);
    md_thread_unlock(&service->mutex);

    md_dns_destroy(response);
    md_dns_destroy(request);
}

struct md_dns_packet *md_dns_service_lookup(
        const char server_ip[MD_NET_IP_LENGTH], uint16_t server_port, size_t server_timeout,
        bool recursion_desired,
        const char name[MD_DNS_NAME_LENGTH], enum md_dns_type type) {
    assert(server_ip && name && type != MD_DNS_UNKNOWN);

    struct md_dns_packet *result = NULL;

    struct md_dns_packet *request = md_dns_create_request(recursion_desired, name, type);
    assert(request);

    uint8_t request_buffer[MD_DNS_MAX_SIZE];
    size_t request_size = sizeof request_buffer;
    md_dns_serialize(request, request_buffer, &request_size);

    struct md_net_fd *fd = md_net_create_fd(SOCK_DGRAM);

    md_net_udp_send(fd, request_buffer, request_size, false, server_ip, server_port);

    if (!md_net_pollin(fd, server_timeout)) goto end;

    uint8_t response_buffer[MD_DNS_MAX_SIZE];
    size_t response_size = sizeof response_buffer;
    char remote_ip[MD_NET_IP_LENGTH];
    uint16_t remote_port = 0;
    if (!md_net_udp_receive(fd, response_buffer, &response_size, remote_ip, &remote_port)) goto end;
    if (strcmp(server_ip, remote_ip) != 0 || server_port != remote_port) goto end;

    struct md_dns_packet *response = md_dns_parse(response_buffer, response_size);
    if (!response) goto end;

    if (response->transaction_id != request->transaction_id)
        md_dns_destroy(response);
    else result = response;

    end:
    md_net_destroy_fd(fd);
    md_dns_destroy(request);

    return result;
}

struct md_dns_packet *md_dns_service_lookup_recursive(
        size_t server_timeout,
        const char name[MD_DNS_NAME_LENGTH], enum md_dns_type type) {
    assert(name && type != MD_DNS_UNKNOWN);

    char server_name[MD_DNS_NAME_LENGTH];
    char server_ip[MD_NET_IP_LENGTH];
    const size_t id = md_rand() % (sizeof root_ips / sizeof root_ips[0]);
    memcpy(server_name, root_names[id], strlen(root_names[id]) + 1);
    memcpy(server_ip, root_ips[id], strlen(root_ips[id]) + 1);

    while (true) {
        char server_str[512];
        md_sprintf(server_str, "%s (%s)", server_name, server_ip);
        MD_LOG("Attempting lookup of %s with nameserver %s", name, server_str);

        struct md_dns_packet *response = md_dns_service_lookup(
                server_ip, MD_DNS_SERVICE_DEFAULT_PORT, server_timeout,
                true,
                name, type);
        if (!response) return NULL;

        if (response->reply_code == MD_DNS_REPLY_NO_ERROR && response->total_answer_rrs) {
            MD_LOG("Nameserver %s replied %zu %s answer(s)", server_str, response->total_answer_rrs, name);
            return response;
        }

        if (response->reply_code == MD_DNS_REPLY_NAME_ERROR) {
            MD_LOG("Nameserver %s replied %s didn't exist", server_str, name);
            return response;
        }

        if (!response->total_authority_rrs) return response;

        const char *first_new_server_name = NULL, *new_server_name = NULL, *new_server_ip = NULL;
        find_authoritative_nameserver(response, &first_new_server_name, &new_server_name, &new_server_ip, name);
        if (!first_new_server_name) return response;

        if (!new_server_ip) {
            memcpy(server_name, first_new_server_name, MD_DNS_NAME_LENGTH);
            if (!lookup_nameserver_ip(server_timeout, server_name, server_ip)) return response;
        } else {
            memcpy(server_name, new_server_name, MD_DNS_NAME_LENGTH);
            memcpy(server_ip, new_server_ip, MD_NET_IP_LENGTH);
        }

        md_dns_destroy(response);
    }
}

struct md_dns_service *md_dns_service_create(
        uint16_t local_port, size_t local_poll_timeout,
        const char public_dns_ip[MD_NET_IP_LENGTH], uint16_t public_dns_port, size_t public_dns_poll_timeout,
        struct md_thread_pool *thread_pool,
        struct sqlite3 *database) {
    assert(public_dns_ip && thread_pool);

    struct md_dns_service *service = md_malloc(sizeof(struct md_dns_service));

    service->fd = md_net_create_fd(SOCK_DGRAM);
    assert(service->fd);

    service->local_port = local_port;
    service->local_poll_timeout = local_poll_timeout;
    memcpy(service->public_dns_ip, public_dns_ip, MD_NET_IP_LENGTH);
    service->public_dns_port = public_dns_port;
    service->public_dns_poll_timeout = public_dns_poll_timeout;
    service->thread_pool = thread_pool;
    service->database = database;
    service->total_connections = 0;
    md_thread_cond_init(&service->connections_cond);
    md_thread_mutex_init(&service->mutex, mtx_plain);
    service->terminable = false;
    service->running = false;

    for (size_t i = 0; i < sizeof(service->cache) / sizeof(service->cache[0]); ++i) {
        service->cache[i].capacity = default_capacity;
        service->cache[i].total_records = 0;
        service->cache[i].records = md_malloc(sizeof(struct md_dns_record) * default_capacity);
    }

    size_t total_records = 0;
    struct md_dns_record *records = db_get_records(service->database, &total_records);
    for (size_t i = 0; i < total_records; ++i) {
        struct md_dns_table *table = &service->cache[get_cache_index(records[i].type)];

        if (table->total_records == table->capacity) {
            table->capacity += default_capacity;
            md_realloc(table->records, sizeof(struct md_dns_record) * table->capacity);
        }

        memcpy(&table->records[table->total_records], &records[i], sizeof(struct md_dns_record));
        table->total_records++;
    }
    md_free(records);

    return service;
}

void md_dns_service_request_to_terminate(struct md_dns_service *service) {
    assert(service);

    md_thread_lock(&service->mutex);
    assert(service->running);
    service->terminable = true;
    md_thread_unlock(&service->mutex);
}

int md_dns_service_main_loop(struct md_dns_service *service) {
    assert(service);

    md_thread_lock(&service->mutex);

    if (service->terminable || service->running) {
        md_thread_unlock(&service->mutex);
        return EXIT_FAILURE;
    }

    service->running = true;

    md_thread_unlock(&service->mutex);

    MD_LOG("DNS service is running...");

    const bool rc = md_net_bind(service->fd, service->local_port);
    assert(rc);

    while (true) {
        const bool readable = md_net_pollin(service->fd, service->local_poll_timeout);

        md_thread_lock(&service->mutex);

        if (service->terminable) {
            MD_LOG("Terminating DNS service...");

            while (service->total_connections) md_thread_wait(&service->connections_cond, &service->mutex);
            service->running = false;
            md_thread_unlock(&service->mutex);
            break;
        }

        if (readable) service->total_connections++;

        md_thread_unlock(&service->mutex);

        if (readable) md_thread_pool_add_task(service->thread_pool, (void (*)(void *)) receive_request, service);
    }

    for (size_t i = 0; i < sizeof(service->cache) / sizeof(service->cache[0]); ++i)
        md_free(service->cache[i].records);

    md_net_destroy_fd(service->fd);
    cnd_destroy(&service->connections_cond);
    mtx_destroy(&service->mutex);
    md_free(service);

    return EXIT_SUCCESS;
}

bool md_dns_service_add_record(struct md_dns_service *service, const struct md_dns_record *record) {
    assert(service && record);

    md_thread_lock(&service->mutex);

    bool result = false;
    if (service->terminable) goto end;

    struct md_dns_table *table = &service->cache[get_cache_index(record->type)];

    size_t index = 0;
    if (find_existed_record(table, record, &index)) goto end;

    if (!db_add_record(service->database, record)) goto end;

    if (table->total_records == table->capacity) {
        table->capacity += default_capacity;
        md_realloc(table->records, sizeof(struct md_dns_record) * table->capacity);
    }

    memcpy(&table->records[table->total_records], &record, sizeof(struct md_dns_record));
    table->total_records++;

    result = true;

    end:
    md_thread_unlock(&service->mutex);
    return result;
}

bool md_dns_service_remove_record(struct md_dns_service *service, const struct md_dns_record *record) {
    assert(service && record);

    md_thread_lock(&service->mutex);

    bool result = false;
    if (service->terminable) goto end;

    struct md_dns_table *table = &service->cache[get_cache_index(record->type)];

    size_t index = 0;
    if (!find_existed_record(table, record, &index)) goto end;

    if (!db_remove_record(service->database, record)) goto end;

    memmove(&table->records[index], &table->records[table->total_records - 1], sizeof(struct md_dns_record));
    table->total_records--;

    result = true;

    end:
    md_thread_unlock(&service->mutex);
    return result;
}
