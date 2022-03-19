#include "minidns/network.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minidns/utils.h"

#ifdef _WIN32
#include <ws2tcpip.h>
typedef int ssize_type;
typedef int socklen_type;
typedef const char *const_buffer_type;
typedef char *buffer_type;
typedef int buffer_length_type;
typedef ULONG poll_size;
#define CLOSE(s) closesocket(s)
#define POLL(fds, nfds, timeout) WSAPoll(fds, nfds, timeout)
#ifdef _WIN64
#define SOCKET_FORMAT "llu"
#define SSIZE_FORMAT "d"
#else
#define SOCKET_FORMAT "u"
#define SSIZE_FORMAT "zd"
#endif
#else

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
typedef ssize_t ssize_type;
typedef socklen_t socklen_type;
typedef const void *const_buffer_type;
typedef void *buffer_type;
typedef size_t buffer_length_type;
typedef nfds_t poll_size;
#define INVALID_SOCKET (-1)
#define CLOSE(s) close(s)
#define POLL(fds, nfds, timeout) poll(fds, nfds, timeout)
#define SOCKET_FORMAT "d"
#define SSIZE_FORMAT "zd"
#endif

#ifdef MD_ENABLE_IPV6_STACK
#define IP_FORMAT "[%s]"
#else
#define IP_FORMAT "%s"
#endif

#define LOG(syscall) do { \
    int error; \
    char message[256]; \
    get_error_message(&error, message, sizeof message); \
    MD_LOG("%s returned error code %d: %s", syscall, error, message); \
} while (0)

#define ABORT(syscall) do { \
    int error; \
    char message[256]; \
    get_error_message(&error, message, sizeof message); \
    MD_ABORT("%s returned error code %d: %s", syscall, error, message); \
} while (0)

static void get_error_message(int *code, char *message, size_t message_length) {
#ifdef _WIN32
    FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            *code = WSAGetLastError(),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            message, (DWORD) message_length,
            NULL);
#else
    *code = errno;
    strerror_r(*code, message, message_length);
#endif
}

static struct addrinfo *get_address_info(const struct md_net_fd *fd, const char ip[MD_NET_IP_LENGTH], uint16_t port) {
    char port_str[6];
    md_sprintf(port_str, "%u", port);

    const struct addrinfo hints = {.ai_family = MD_IP_STACK, .ai_socktype = fd->protocol, .ai_flags = AI_PASSIVE};
    struct addrinfo *address = NULL;
    const int rc = getaddrinfo(ip, port_str, &hints, &address);
    if (rc) {
#ifdef _WIN32
        (void) rc;
        ABORT("getaddrinfo");
#else
        MD_ABORT("getaddrinfo returned error code %d: %s", rc, gai_strerror(rc));
#endif
    }

    return address;
}

static void get_name_info(const struct sockaddr_storage *address, char ip[MD_NET_IP_LENGTH], uint16_t *port) {
#ifdef MD_ENABLE_IPV6_STACK
    const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *) address;
    if (!inet_ntop(AF_INET6, &sa->sin6_addr, ip, MD_NET_IPV6_LENGTH)) MD_ABORT("inet_ntop returned NULL");
    *port = ntohs(sa->sin6_port);
#else
    const struct sockaddr_in *sa = (const struct sockaddr_in *) address;
    if (!inet_ntop(AF_INET, &sa->sin_addr, ip, MD_NET_IPV4_LENGTH)) MD_ABORT("inet_ntop returned NULL");
    *port = ntohs(sa->sin_port);
#endif
}

void md_net_init_stack(void) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData)) ABORT("WSAStartup");
#endif
}

void md_net_destroy_stack(void) {
#ifdef _WIN32
    if (WSACleanup()) ABORT("WSACleanup");
#endif
}

bool md_net_is_valid_address(int stack, const char *address) {
    assert((stack == AF_INET || stack == AF_INET6) && address);

    char tmp[16];
    return inet_pton(stack, address, tmp) == 1;
}

struct md_net_fd *md_net_create_fd(int protocol) {
    assert(protocol == SOCK_STREAM || protocol == SOCK_DGRAM);

    const socket_type s = socket(MD_IP_STACK, protocol, 0);
    if (s == INVALID_SOCKET) ABORT("socket");

    struct md_net_fd *fd = md_malloc(sizeof(struct md_net_fd));
    fd->protocol = protocol;
    fd->socket = s;

    return fd;
}

void md_net_destroy_fd(struct md_net_fd *fd) {
    if (!fd) return;

    if (CLOSE(fd->socket) == -1) ABORT("CLOSE");
    md_free(fd);
}

bool md_net_bind(struct md_net_fd *fd, uint16_t port) {
    assert(fd);

    const int yes = 1;
    if (setsockopt(fd->socket, SOL_SOCKET, SO_REUSEADDR, (const_buffer_type) &yes, sizeof(int)) == -1)
        ABORT("setsockopt");

    bool result = false;
    struct addrinfo *address = get_address_info(fd, NULL, port);
    if (bind(fd->socket, address->ai_addr, (socklen_type) address->ai_addrlen) == -1) LOG("bind");
    else result = true;

    freeaddrinfo(address);

    return result;
}

void md_net_listen(const struct md_net_fd *fd) {
    assert(fd && fd->protocol == SOCK_STREAM);

    // backlog: how many pending connections one can have before the kernel starts rejecting new ones
    if (listen(fd->socket, 10) == -1) ABORT("listen");
}

// Poll: https://beej.us/guide/bgnet/html/#poll
bool md_net_pollin(const struct md_net_fd *fd, size_t timeout) {
    assert(fd);

    // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll#remarks
    // The POLLIN flag is defined as the combination of the POLLRDNORM and POLLRDBAND flag values.
    // POLLRDNORM: Normal data may be read without blocking.
    // POLLRDBAND: Priority band (out-of-band) data may be read without blocking.
    struct pollfd pollfd = {.fd = fd->socket, .events = POLLIN};
    if (POLL(&pollfd, 1, (int) timeout) == -1) ABORT("POLL");

    return pollfd.revents & POLLIN;
}

struct md_net_fd *md_net_accept(const struct md_net_fd *fd, char remote_ip[MD_NET_IP_LENGTH], uint16_t *remote_port) {
    assert(fd && fd->protocol == SOCK_STREAM && remote_ip && remote_port);

    struct sockaddr_storage remote_address;
    socklen_type length = sizeof remote_address;

    const socket_type new_socket = accept(fd->socket, (struct sockaddr *) &remote_address, &length);
    if (new_socket == INVALID_SOCKET) ABORT("accept");

    struct md_net_fd *new_fd = md_malloc(sizeof(struct md_net_fd));
    new_fd->protocol = fd->protocol;
    new_fd->socket = new_socket;

    get_name_info(&remote_address, remote_ip, remote_port);
    MD_LOG("New TCP connection from " IP_FORMAT ":%u on socket %" SOCKET_FORMAT, remote_ip, *remote_port, fd->socket);
    md_free(remote_ip);

    return new_fd;
}

bool md_net_connect(const struct md_net_fd *fd, const char remote_ip[MD_NET_IP_LENGTH], uint16_t remote_port) {
    assert(fd && remote_ip);

    struct addrinfo *address = get_address_info(fd, remote_ip, remote_port);

    bool result = false;
    if (connect(fd->socket, address->ai_addr, (socklen_type) address->ai_addrlen) == -1) LOG("connect");
    else result = true;

    freeaddrinfo(address);

    return result;
}

bool md_net_udp_send(
        const struct md_net_fd *fd,
        const uint8_t *buffer, size_t size,
        bool direct_response,
        const char remote_ip[MD_NET_IP_LENGTH], uint16_t remote_port) {
    assert(fd && fd->protocol == SOCK_DGRAM && buffer && size && remote_ip);

// https://stackoverflow.com/a/42105469/12247864
#ifdef _WIN32
    (void) direct_response;
    const int flags = 0;
#else
    const int flags = direct_response ? MSG_CONFIRM : 0;
#endif

    struct addrinfo *address = get_address_info(fd, remote_ip, remote_port);

    bool result = false;
    const ssize_type n = sendto(
            fd->socket,
            (const_buffer_type) buffer, (buffer_length_type) size,
            flags,
            address->ai_addr, (socklen_type) address->ai_addrlen);
    if (n != (ssize_type) size) {
        if (n == -1) LOG("sendto");
        else
        MD_LOG("sendto returned %" SSIZE_FORMAT " != %zu", n, size);
    } else result = true;

    freeaddrinfo(address);

    return result;
}

bool md_net_tcp_send_with_u32_size(const struct md_net_fd *fd,
                                   const uint8_t *buffer, size_t size,
                                   size_t total_retries) {
    assert(fd && fd->protocol == SOCK_STREAM && buffer && size);

    const uint32_t real_size = (uint32_t) (size + sizeof size);
    const uint32_t network_size = htonl(real_size);

    uint8_t *real_buffer = md_malloc(size + sizeof network_size);
    memcpy(real_buffer, &network_size, sizeof network_size);
    memcpy(real_buffer + sizeof network_size, buffer, size);

    size_t bytes_sent = 0;
    size_t bytes_left = real_size;
    while (bytes_sent < real_size) {
        const ssize_type n = send(
                fd->socket,
                (const_buffer_type) (real_buffer + bytes_sent), (buffer_length_type) bytes_left,
                0);
        if (n == -1) {
            LOG("send");
            if (!total_retries) goto error;
            --total_retries;
            continue;
        }

        bytes_sent += n;
        bytes_left -= n;
    }

    return true;

    error:
    md_free(real_buffer);
    return false;
}

bool md_net_udp_receive(const struct md_net_fd *fd,
                        uint8_t *buffer, size_t *size,
                        char remote_ip[MD_NET_IP_LENGTH], uint16_t *remote_port) {
    assert(fd && fd->protocol == SOCK_DGRAM && buffer && size && *size && remote_ip && remote_port);

    struct sockaddr_storage remote_address;
    socklen_type length = sizeof remote_address;

    const ssize_type n = recvfrom(
            fd->socket,
            (buffer_type) buffer, (ssize_type) *size,
            0,
            (struct sockaddr *) &remote_address, &length);

    if (n <= 0) {
        if (n == -1) LOG("recvfrom");
        // Ignore n = 0. UDP packet of length 0: https://stackoverflow.com/a/19555993/12247864
        MD_LOG("recvfrom returned 0");

        return false;
    }

    *size = n;

    get_name_info(&remote_address, remote_ip, remote_port);
    MD_LOG("UDP connection from " IP_FORMAT ":%u on socket %" SOCKET_FORMAT, remote_ip, *remote_port, fd->socket);

    return true;
}

uint8_t *md_net_tcp_receive_with_u32_size(const struct md_net_fd *fd, size_t *size) {
    assert(fd && fd->protocol == SOCK_STREAM && size);

    uint8_t *buffer = NULL;
    uint32_t network_size = 0;
    ssize_type n = recv(fd->socket, (buffer_type) &network_size, sizeof network_size, 0);
    if (n <= 0) goto error;
    else *size = ntohl(network_size);

    buffer = md_malloc(*size);
    n = recv(fd->socket, (buffer_type) buffer, (ssize_type) *size, MSG_WAITALL);
    if (n <= 0) goto error;

    return buffer;

    error:
    if (n == -1) LOG("recv");
    else
MD_LOG("Socket %" SOCKET_FORMAT " hung up", fd->socket);
    md_free(buffer);
    return NULL;
}
