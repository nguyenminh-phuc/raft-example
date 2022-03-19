#ifndef MD_DNS_H
#define MD_DNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "minidns/config.h"
#include "minidns/network.h"

#define MD_DNS_MIN_SIZE 12
#define MD_DNS_MAX_SIZE 512

// https://stackoverflow.com/q/32290167/12247864
#define MD_DNS_NAME_LENGTH (253 + 1)

#ifdef __cplusplus
extern "C" {
#endif

// Pack: https://stackoverflow.com/a/3312896/12247864
// Bitfield Packing: http://mjfrazer.org/mjfrazer/bitfields/
#ifdef _MSC_VER
__pragma(pack(push, 1))
#endif
/*
 * DNS RFC: https://tools.ietf.org/html/rfc1035
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct md_dns_raw_header {
    unsigned id: 16;
#if MD_BIG_ENDIAN
    /*
        Sample Flags: 0x8180 Standard query response, No error
            1... .... .... .... = Response: Message is a response
            .000 0... .... .... = Opcode: Standard query (0)
            .... .0.. .... .... = Authoritative: Server is not an authority for domain
            .... ..0. .... .... = Truncated: Message is not truncated
            .... ...1 .... .... = Recursion desired: Do query recursively
            .... .... 1... .... = Recursion available: Server can do recursive queries
            .... .... .000 .... = Z: reserved (0)
            .... .... .... 0000 = Reply code: No error (0)

        qr:1 = 1  ─────┐
        opcode:4 = 0 ──┼───────┐
        aa:1 = 0  ─────┼───────┼──────┐
        tc:1 = 0  ─────┼───────┼──────┼──┐
        rd:1 = 1  ─────┼───────┼──────┼──┼──┐
        ra:1 = 1  ─────┼───────┼──────┼──┼──┼──┐
        z:3 = 0   ─────┼───────┼──────┼──┼──┼──┼─────┐
        rcode:4 = 0 ───┼───────┼──────┼──┼──┼──┼─────┼──────────┐
                       V       V      V  V  V  V     V          V
                      ┌─┐┌──────────┐┌─┐┌─┐┌─┐┌─┐┌───────┐┌──────────┐
                       1  0  0  0  0  0  0  1  1  0  0  0  0  0  0  0
                      └──────────┘└──────────┘└──────────┘└──────────┘
                            8           1           8           0
    */
        unsigned qr : 1;
        unsigned opcode : 4;
        unsigned aa : 1;
        unsigned tc : 1;
        unsigned rd : 1;
        unsigned ra : 1;
        unsigned z : 3;
        unsigned rcode : 4;
#else
/*
    rd:1 = 1  ──────────────────────────────────────────────────┐
    tc:1 = 0  ───────────────────────────────────────────────┐  │
    aa:1 = 0  ────────────────────────────────────────────┐  │  │
    opcode:4 = 0 ──────────────────────────────────┐      │  │  │
    qr:1 = 1  ─────────────────────────────┐       │      │  │  │
    rcode:4 = 0 ────────────────────┐      │       │      │  │  │
    z:3 = 0   ───────────┐          │      │       │      │  │  │
    ra:1 = 1  ─────┐     │          │      │       │      │  │  │
                   V     V          V      V       V      V  V  V
                  ┌─┐┌───────┐┌──────────┐┌─┐┌──────────┐┌─┐┌─┐┌─┐
                   1  0  0  0  0  0  0  0  1  0  0  0  0  0  0  1
                  └──────────┘└──────────┘└──────────┘└──────────┘
                        8           0           8           1
 */
    unsigned rd: 1;
    unsigned tc: 1;
    unsigned aa: 1;
    unsigned opcode: 4;
    unsigned qr: 1;
    unsigned rcode: 4;
    unsigned z: 3;
    unsigned ra: 1;
#endif
    unsigned qdcount: 16;
    unsigned ancount: 16;
    unsigned nscount: 16;
    unsigned arcount: 16;
}
#ifdef _MSC_VER
    __pragma(pack(pop))
#else
    __attribute__((__packed__))
#endif
;

enum md_dns_type {
    MD_DNS_UNKNOWN = 0,
    MD_DNS_A = 1,
    MD_DNS_NS = 2,
    MD_DNS_CNAME = 5,
    MD_DNS_MX = 15,
    MD_DNS_AAAA = 28
};

struct md_dns_question {
    char name[MD_DNS_NAME_LENGTH];
    enum md_dns_type type;
};

struct md_dns_record {
    char name[MD_DNS_NAME_LENGTH];
    enum md_dns_type type;
    uint32_t ttl;
    union {
        struct {
            uint16_t type_id;
            uint16_t data_length;
        } unknown;
        struct {
            char address[MD_NET_IPV4_LENGTH];
        } a;
        struct {
            char name[MD_DNS_NAME_LENGTH];
        } ns;
        struct {
            char name[MD_DNS_NAME_LENGTH];
        } cname;
        struct {
            uint16_t priority;
            char name[MD_DNS_NAME_LENGTH];
        } mx;
        struct {
            char address[MD_NET_IPV6_LENGTH];
        } aaaa;
    } data;
};

struct md_dns_packet {
    uint16_t transaction_id;
    enum {
        MD_DNS_QUERY = 0,
        MD_DNS_RESPONSE = 1
    } response;
    enum {
        MD_DNS_OP_QUERY = 0,
        MD_DNS_OP_IQUERY = 1,
        MD_DNS_OP_STATUS = 2
    } opcode;
    bool authoritative;
    bool truncated;
    bool recursion_desired;
    bool recursion_available;
    enum {
        MD_DNS_REPLY_NO_ERROR = 0,
        MD_DNS_REPLY_FORMAT_ERROR = 1,
        MD_DNS_REPLY_SERVER_FAILURE = 2,
        MD_DNS_REPLY_NAME_ERROR = 3,
        MD_DNS_REPLY_NOT_IMPLEMENTED = 4,
        MD_DNS_REPLY_REFUSED = 5
    } reply_code;
    size_t total_questions;
    struct md_dns_question *questions;
    size_t total_answer_rrs;
    struct md_dns_record *answer_rrs;
    size_t total_authority_rrs;
    struct md_dns_record *authority_rrs;
    size_t total_additional_rrs;
    struct md_dns_record *additional_rrs;
};

MD_API enum md_dns_type md_dns_string_to_type(const char *string);

MD_API struct md_dns_packet *md_dns_parse(const uint8_t *buffer, size_t size);

MD_API void md_dns_destroy(struct md_dns_packet *packet);

MD_API struct md_dns_packet *md_dns_create_request(
        bool recursion_desired,
        const char name[MD_DNS_NAME_LENGTH], enum md_dns_type type);

MD_API void md_dns_serialize(const struct md_dns_packet *packet, uint8_t buffer[MD_DNS_MAX_SIZE], size_t *size);

MD_API char *md_dns_log(const struct md_dns_packet *packet, size_t *size);

#ifdef __cplusplus
}
#endif

#endif
