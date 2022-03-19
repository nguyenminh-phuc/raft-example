#ifndef MD_DNS_SERVICE_H
#define MD_DNS_SERVICE_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include "minidns/config.h"
#include "minidns/dns.h"
#include "minidns/network.h"
#include "minidns/threads_wrapper.h"

#define MD_DNS_SERVICE_DEFAULT_PORT 53

#ifdef __cplusplus
extern "C" {
#endif

struct sqlite3;
struct md_dns_record;
struct md_thread_pool;

struct md_dns_table {
    size_t capacity;
    size_t total_records;
    struct md_dns_record *records;
};

struct md_dns_service {
    struct md_dns_table cache[5];
    struct md_net_fd *fd;
    uint16_t local_port;
    size_t local_poll_timeout;
    char public_dns_ip[MD_NET_IP_LENGTH];
    uint16_t public_dns_port;
    size_t public_dns_poll_timeout;
    struct md_thread_pool *thread_pool;
    struct sqlite3 *database;
    size_t total_connections;
    cnd_t connections_cond;
    mtx_t mutex;
    bool running;
    bool terminable;
};

MD_API struct md_dns_packet *md_dns_service_lookup(
        const char server_ip[MD_NET_IP_LENGTH], uint16_t server_port, size_t server_timeout,
        bool recursion_desired,
        const char name[MD_DNS_NAME_LENGTH], enum md_dns_type type);

MD_API struct md_dns_packet *md_dns_service_lookup_recursive(
        size_t server_timeout,
        const char name[MD_DNS_NAME_LENGTH], enum md_dns_type type);

MD_API struct md_dns_service *md_dns_service_create(
        uint16_t local_port, size_t local_poll_timeout,
        const char public_dns_ip[MD_NET_IP_LENGTH], uint16_t public_dns_port, size_t public_dns_poll_timeout,
        struct md_thread_pool *thread_pool,
        struct sqlite3 *database);

MD_API void md_dns_service_request_to_terminate(struct md_dns_service *service);

MD_API int md_dns_service_main_loop(struct md_dns_service *service);

MD_API bool md_dns_service_add_record(struct md_dns_service *service, const struct md_dns_record *record);

MD_API bool md_dns_service_remove_record(struct md_dns_service *service, const struct md_dns_record *record);

#ifdef __cplusplus
}
#endif

#endif
