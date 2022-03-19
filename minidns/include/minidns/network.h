#ifndef MD_NETWORK_H
#define MD_NETWORK_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "minidns/config.h"

#ifdef _WIN32

#include <winsock2.h>

typedef SOCKET socket_type;
#else
typedef int socket_type;
#endif

#define MD_NET_IPV6_MIN_LENGTH (3 + 1)
#define MD_NET_IPV4_MIN_LENGTH (7 + 1)
#define MD_NET_IPV6_LENGTH (45 + 1)
#define MD_NET_IPV4_LENGTH (15 + 1)

#ifdef MD_ENABLE_IPV6_STACK
#define MD_IP_STACK AF_INET6
#define MD_NET_IP_MIN_LENGTH MD_NET_IPV6_MIN_LENGTH
#define MD_NET_IP_LENGTH MD_NET_IPV6_LENGTH
#else
#define MD_IP_STACK AF_INET
#define MD_NET_IP_MIN_LENGTH MD_NET_IPV4_MIN_LENGTH
#define MD_NET_IP_LENGTH MD_NET_IPV4_LENGTH
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct md_net_fd {
    int protocol; // SOCK_STREAM or SOCK_DGRAM
    socket_type socket;
};

MD_API void md_net_init_stack(void);

MD_API void md_net_destroy_stack(void);

MD_API bool md_net_is_valid_address(int stack, const char *address);

MD_API struct md_net_fd *md_net_create_fd(int protocol);

MD_API void md_net_destroy_fd(struct md_net_fd *fd);

MD_API bool md_net_bind(struct md_net_fd *fd, uint16_t port);

MD_API void md_net_listen(const struct md_net_fd *fd);

MD_API bool md_net_pollin(const struct md_net_fd *fd, size_t timeout);

MD_API struct md_net_fd *md_net_accept(const struct md_net_fd *fd,
                                       char remote_ip[MD_NET_IP_LENGTH], uint16_t *remote_port);

MD_API bool md_net_connect(const struct md_net_fd *fd, const char remote_ip[MD_NET_IP_LENGTH], uint16_t remote_port);

MD_API bool md_net_udp_send(const struct md_net_fd *fd,
                            const uint8_t *buffer, size_t size,
                            bool direct_response,
                            const char remote_ip[MD_NET_IP_LENGTH], uint16_t remote_port);

MD_API bool md_net_tcp_send_with_u32_size(const struct md_net_fd *fd,
                                          const uint8_t *buffer, size_t size,
                                          size_t total_retries);

MD_API bool md_net_udp_receive(const struct md_net_fd *fd,
                               uint8_t *buffer, size_t *size,
                               char remote_ip[MD_NET_IP_LENGTH], uint16_t *remote_port);

MD_API uint8_t *md_net_tcp_receive_with_u32_size(const struct md_net_fd *fd, size_t *size);

#ifdef __cplusplus
}
#endif

#endif
