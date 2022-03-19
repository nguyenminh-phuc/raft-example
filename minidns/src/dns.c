#include "minidns/dns.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "minidns/utils.h"
#include "minidns/network.h"

#ifdef _WIN32

#include <ws2tcpip.h>

#else

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#endif

#define MAX_LABEL_LENGTH 63

static_assert(sizeof(unsigned) == 4 && CHAR_BIT == 8, "Size of unsigned must be 32 bits");
static_assert(sizeof(struct md_dns_raw_header) == MD_DNS_MIN_SIZE, "Size of DNS header must be 12 bytes");

static const char *const reply_code_str[] = {
        "No error",
        "Format error",
        "Server failure",
        "No such name",
        "Not implemented",
        "Refused"
};

static const char *const response_str[] = {
        "Message is a query",
        "Message is a response"
};

static const char *const opcode_str[] = {
        "Standard query",
        "Inverse query",
        "Server status request"
};

static const char *const authoritative_str[] = {
        "Server is not an authority for domain",
        "Server is an authority for domain"
};

static const char *const truncated_str[] = {
        "Message is not truncated",
        "Message is truncated"
};

static const char *const recursion_desired_str[] = {
        "Don't do query recursively",
        "Do query recursively"
};

static const char *const recursion_available_str[] = {
        "Server can't do recursive queries",
        "Server can do recursive queries"
};

static const char *type_to_string(enum md_dns_type type) {
    switch (type) {
        case MD_DNS_UNKNOWN:
            return "UNKNOWN";
        case MD_DNS_A:
            return "A";
        case MD_DNS_NS:
            return "NS";
        case MD_DNS_CNAME:
            return "CNAME";
        case MD_DNS_MX:
            return "MX";
        case MD_DNS_AAAA:
            return "AAAA";
        default:
            MD_ABORT("Unknown md_dns_type case: %d", type);
    }
}

// eg: www->example->com->NULL
struct label_sequence {
    char label[MAX_LABEL_LENGTH];
    size_t length;
    struct label_sequence *next;
};

// - sequence dns->com, base_offset 12
// offset 12: 3dns3com0
// offset 16: 3com0
// - sequence example->com, base_offset X
// offset X:  7example(0xC000|16)
// - sequence www->example->com, base_offset Y
// offset Y:  3www(0xC000|X)
struct label_sequence_list {
    struct label_sequence *sequence;
    size_t base_offset;
    struct label_sequence_list *next;
};

static void destroy_label_sequence(struct label_sequence *sequence) {
    while (sequence) {
        struct label_sequence *current = sequence;
        sequence = sequence->next;
        md_free(current);
    }
}

static struct label_sequence *create_label_sequence(const char name[MD_DNS_NAME_LENGTH]) {
    char *delimited_string = md_malloc(strlen(name) + 1);
    memcpy(delimited_string, name, strlen(name) + 1);

    struct label_sequence *sequence = md_malloc(sizeof(struct label_sequence));

    struct label_sequence *current = sequence;
    char *rest = NULL;
    char *token = md_strtok_r(delimited_string, ".", &rest);
    while (token) {
        current->length = strlen(token);
        memcpy(current->label, token, current->length);
        current->next = NULL;
        if ((token = md_strtok_r(NULL, ".", &rest))) {
            current->next = md_malloc(sizeof(struct label_sequence));
            current = current->next;
        }
    }

    md_free(delimited_string);

    return sequence;
}

static struct label_sequence *clone_label_sequence(const struct label_sequence *sequence) {
    struct label_sequence *clone = md_malloc(sizeof(struct label_sequence));

    struct label_sequence *current = clone;
    while (true) {
        current->length = sequence->length;
        memcpy(current->label, sequence->label, sequence->length);
        current->next = NULL;

        sequence = sequence->next;
        if (sequence) current = current->next = md_malloc(sizeof(struct label_sequence));
        else break;
    }

    return clone;
}

static bool are_identical(const struct label_sequence *MD_RESTRICT a, const struct label_sequence *MD_RESTRICT b) {
    while (a && b) {
        if (a->length != b->length || memcmp(a->label, b->label, a->length) != 0) return false;

        a = a->next;
        b = b->next;
    }

    return !a && !b;
}

static bool find_label_sequence(
        const struct label_sequence_list **list,
        const struct label_sequence *sequence,
        size_t *offset) {
    if (!*list) return false;

    const struct label_sequence_list *current = *list;
    while (current) {
        *offset = current->base_offset;
        const struct label_sequence *current_sequence = current->sequence;
        while (current_sequence) {
            if (are_identical(current_sequence, sequence)) return true;

            *offset += 1 + current_sequence->length;
            current_sequence = current_sequence->next;
        }

        current = current->next;
    }

    return false;
}

static void add_label_sequence(
        struct label_sequence_list **list,
        const struct label_sequence *sequence,
        size_t base_offset) {
    struct label_sequence_list *current = *list;
    if (current) {
        while (true) {
            if (current->next) current = current->next;
            else {
                current = current->next = md_malloc(sizeof(struct label_sequence_list));
                break;
            }
        }
    } else current = *list = md_malloc(sizeof(struct label_sequence_list));

    current->sequence = clone_label_sequence(sequence);
    current->base_offset = base_offset;
    current->next = NULL;
}

static void find_add_serialize_name(
        uint8_t *buffer, size_t *offset,
        struct label_sequence_list **list,
        const char name[MD_DNS_NAME_LENGTH]) {
    const size_t base_offset = *offset;
    struct label_sequence *sequence = create_label_sequence(name);

    bool should_append_null_char = true;
    const struct label_sequence *current = sequence;
    while (current) {
        size_t sequence_offset = 0;
        if (find_label_sequence((const struct label_sequence_list **) list, current, &sequence_offset)) {
            should_append_null_char = false;
            const uint16_t serialized_offset = htons(0xC000 | (uint16_t) sequence_offset);
            memcpy(buffer + *offset, &serialized_offset, sizeof serialized_offset);
            *offset += sizeof serialized_offset;
            break;
        } else {
            buffer[(*offset)++] = (uint8_t) current->length;
            memcpy(buffer + *offset, current->label, current->length);
            *offset += current->length;
        }

        current = current->next;
    }

    if (should_append_null_char) buffer[(*offset)++] = 0;

    add_label_sequence(list, sequence, base_offset);
    destroy_label_sequence(sequence);
}

static void serialize_type(uint8_t *buffer, size_t *offset, enum md_dns_type type) {
    buffer[(*offset)++] = 0;
    buffer[(*offset)++] = type;
}

static void serialize_class(uint8_t *buffer, size_t *offset) {
    buffer[(*offset)++] = 0;
    buffer[(*offset)++] = 1;
}

static void serialize_record(
        uint8_t buffer[MD_DNS_MAX_SIZE], size_t *offset,
        struct label_sequence_list **list,
        const struct md_dns_record *record) {
    if (record->type == MD_DNS_UNKNOWN) MD_ABORT("This should never happen");

    find_add_serialize_name(buffer, offset, list, record->name);

    serialize_type(buffer, offset, record->type);

    serialize_class(buffer, offset);

    const uint32_t serialized_ttl = htonl(record->ttl);
    memcpy(buffer + *offset, &serialized_ttl, sizeof serialized_ttl);
    *offset += sizeof serialized_ttl;

    size_t length_offset = *offset;
    uint16_t length = 0;
    *offset += sizeof length;

    switch (record->type) {
        case MD_DNS_A: {
            length = 4;
            char address[4];
            const int rc = inet_pton(AF_INET, record->data.a.address, address);
            if (rc != 1) MD_ABORT("inet_pton returned %d", rc);
            memcpy(buffer + *offset, address, length);
            break;
        }
        case MD_DNS_NS:
            find_add_serialize_name(buffer, offset, list, record->data.ns.name);
            length = (uint16_t) (*offset - (length_offset + sizeof length));
            break;
        case MD_DNS_CNAME:
            find_add_serialize_name(buffer, offset, list, record->data.cname.name);
            length = (uint16_t) (*offset - (length_offset + sizeof length));
            break;
        case MD_DNS_MX: {
            const uint16_t serialized_priority = htons(record->data.mx.priority);
            memcpy(buffer + *offset, &serialized_priority, sizeof serialized_priority);
            *offset += sizeof record->data.mx.priority;
            find_add_serialize_name(buffer, offset, list, record->data.ns.name);
            length = (uint16_t) (*offset - (length_offset + sizeof length));
            break;
        }
        case MD_DNS_AAAA: {
            length = 16;
            char address[16];
            int rc = inet_pton(AF_INET6, record->data.aaaa.address, address);
            if (rc != 1) MD_ABORT("inet_pton returned %d", rc);
            memcpy(buffer + *offset, address, length);
            break;
        }
        case MD_DNS_UNKNOWN:
            MD_ABORT("This should never happen");
    }

    const uint16_t serialized_length = htons(length);
    memcpy(buffer + length_offset, &serialized_length, sizeof serialized_length);

    *offset += length;
}

static void log_record(char *buffer, size_t *offset, const struct md_dns_record *record) {
    char data[512];
    switch (record->type) {
        case MD_DNS_UNKNOWN:
            md_sprintf(data, "id %u, length %zu", record->data.unknown.type_id, record->data.unknown.data_length);
            break;
        case MD_DNS_A:
            md_sprintf(data, "addr %s", record->data.a.address);
            break;
        case MD_DNS_NS:
            md_sprintf(data, "ns %s", record->data.ns.name);
            break;
        case MD_DNS_CNAME:
            md_sprintf(data, "cname %s", record->data.cname.name);
            break;
        case MD_DNS_MX:
            md_sprintf(data, "preference %u, mx %s", record->data.mx.priority, record->data.mx.name);
            break;
        case MD_DNS_AAAA:
            md_sprintf(data, "addr %s", record->data.aaaa.address);
    }

    *offset += md_sprintf(buffer + *offset, "    %s: type %s, class IN, %s, ttl %d\n",
                          record->name,
                          type_to_string(record->type),
                          data,
                          record->ttl);
}

static uint16_t parse_u16(const uint8_t *buffer, size_t *offset) {
    uint8_t first = buffer[(*offset)++];
    uint8_t second = buffer[(*offset)++];
    return ((uint16_t) first) << 8 | second;
}

static uint16_t parse_u32(const uint8_t *buffer, size_t *offset) {
    uint8_t first = buffer[(*offset)++];
    uint8_t second = buffer[(*offset)++];
    uint8_t third = buffer[(*offset)++];
    uint8_t fourth = buffer[(*offset)++];
    return ((uint32_t) first) << 24 | ((uint32_t) second) << 16 | ((uint32_t) third) << 8 | fourth;
}

static size_t parse_name(const uint8_t *buffer, size_t *offset, char name[MD_DNS_NAME_LENGTH]) {
    size_t length = 0;

    while (true) {
        uint8_t c = buffer[*offset];

        /*
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           | 1  1|                OFFSET                   |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         */
        if ((c & 0xC0) == 0xC0) {
            (*offset)++;
            size_t label_offset = ((uint16_t) (c & 0x3F)) << 8 | buffer[(*offset)++];

            char remainder_of_name[MD_DNS_NAME_LENGTH];
            const size_t labels_length = parse_name(buffer, &label_offset, remainder_of_name);
            memcpy(name + length, remainder_of_name, labels_length);
            length += labels_length;

            return length;
        } else {
            char label[MAX_LABEL_LENGTH];
            const size_t label_length = buffer[(*offset)++];
            size_t i = label_length, label_pos = 0;
            while (i > 0) {
                label[label_pos++] = buffer[(*offset)++];
                --i;
            }
            memcpy(name + length, label, label_length);
            length += label_length;
        }

        if (buffer[*offset] == 0) {
            (*offset)++;
            name[length++] = '\0';

            return length;
        } else name[length++] = '.';
    }
}

static uint16_t parse_type(const uint8_t *buffer, size_t *offset, enum md_dns_type *type) {
    const uint16_t type_id = parse_u16(buffer, offset);

    switch (type_id) {
        case MD_DNS_A:
        case MD_DNS_NS:
        case MD_DNS_CNAME:
        case MD_DNS_MX:
        case MD_DNS_AAAA:
            *type = type_id;
            break;
        default:
            *type = MD_DNS_UNKNOWN;
    }

    return type_id;
}

static bool parse_question(const uint8_t *buffer, size_t *offset, struct md_dns_question *question) {
    parse_name(buffer, offset, question->name);

    parse_type(buffer, offset, &question->type);

    const uint16_t class = parse_u16(buffer, offset);
    if (class != 1) return false;

    return true;
}

static bool parse_record(const uint8_t *buffer, size_t *offset, struct md_dns_record *record) {
    parse_name(buffer, offset, record->name);

    const uint16_t type_id = parse_type(buffer, offset, &record->type);

    const uint16_t class = parse_u16(buffer, offset);
    if (class != 1) return false;

    record->ttl = parse_u32(buffer, offset);

    const uint16_t data_length = parse_u16(buffer, offset);

    switch (record->type) {
        case MD_DNS_UNKNOWN:
            record->data.unknown.type_id = type_id;
            record->data.unknown.data_length = data_length;
            *offset += data_length;
            break;
        case MD_DNS_A: {
            if (data_length != 4) return false;

            struct sockaddr_in sa;
            memcpy(&sa.sin_addr, buffer + *offset, sizeof sa.sin_addr);
            *offset += sizeof sa.sin_addr;
            if (!inet_ntop(AF_INET, &sa.sin_addr, record->data.a.address, MD_NET_IPV4_LENGTH)) return false;
            break;
        }
        case MD_DNS_NS:
            parse_name(buffer, offset, record->data.ns.name);
            break;
        case MD_DNS_CNAME:
            parse_name(buffer, offset, record->data.cname.name);
            break;
        case MD_DNS_MX:
            record->data.mx.priority = parse_u16(buffer, offset);
            parse_name(buffer, offset, record->data.mx.name);
            break;
        case MD_DNS_AAAA: {
            if (data_length != 16) return false;

            struct sockaddr_in6 sa;
            memcpy(&sa.sin6_addr, buffer + *offset, sizeof sa.sin6_addr);
            *offset += sizeof sa.sin6_addr;
            if (!inet_ntop(AF_INET6, &sa.sin6_addr, record->data.aaaa.address, MD_NET_IPV6_LENGTH)) return false;
        }
    }

    return true;
}


enum md_dns_type md_dns_string_to_type(const char *string) {
    assert(string);

    if (strcmp(string, "A") == 0) return MD_DNS_A;
    else if (strcmp(string, "NS") == 0) return MD_DNS_NS;
    else if (strcmp(string, "CNAME") == 0) return MD_DNS_CNAME;
    else if (strcmp(string, "MX") == 0) return MD_DNS_MX;
    else if (strcmp(string, "AAAA") == 0) return MD_DNS_AAAA;
    else return MD_DNS_UNKNOWN;
}

// Ignore parsing errors from malformed packets
struct md_dns_packet *md_dns_parse(const uint8_t *buffer, size_t size) {
    assert(buffer && size >= MD_DNS_MIN_SIZE && size <= MD_DNS_MAX_SIZE);

    struct md_dns_packet *result = md_calloc(1, sizeof(struct md_dns_packet));

    const struct md_dns_raw_header *raw_header = (const struct md_dns_raw_header *) buffer;
    result->transaction_id = ntohs(raw_header->id);
    result->response = raw_header->qr;
    if (raw_header->opcode > 2u) goto error;
    result->opcode = raw_header->opcode;
    result->authoritative = raw_header->aa;
    result->truncated = raw_header->tc;
    result->recursion_desired = raw_header->rd;
    result->recursion_available = raw_header->ra;
    if (raw_header->z != 0u)
    MD_LOG("Z = %u: Reserved for future use. Must be zero in all queries and responses.", raw_header->z);
    if (raw_header->rcode > 5u) goto error;
    result->reply_code = raw_header->rcode;
    result->total_questions = ntohs(raw_header->qdcount);
    result->total_answer_rrs = ntohs(raw_header->ancount);
    result->total_authority_rrs = ntohs(raw_header->nscount);
    result->total_additional_rrs = ntohs(raw_header->arcount);

    size_t offset = sizeof(struct md_dns_raw_header);

    if (result->total_questions) {
        result->questions = md_calloc(1, sizeof(struct md_dns_record) * result->total_questions);
        for (size_t i = 0; i < result->total_questions; ++i)
            if (!parse_question(buffer, &offset, &result->questions[i])) goto error;
    }

    if (result->total_answer_rrs) {
        result->answer_rrs = md_calloc(1, sizeof(struct md_dns_record) * result->total_answer_rrs);
        for (size_t i = 0; i < result->total_answer_rrs; ++i)
            if (!parse_record(buffer, &offset, &result->answer_rrs[i])) goto error;
    }

    if (result->total_authority_rrs) {
        result->authority_rrs = md_calloc(1, sizeof(struct md_dns_record) * result->total_authority_rrs);
        for (size_t i = 0; i < result->total_authority_rrs; ++i)
            if (!parse_record(buffer, &offset, &result->authority_rrs[i])) goto error;
    }

    if (result->total_additional_rrs) {
        result->additional_rrs = md_calloc(1, sizeof(struct md_dns_record) * result->total_additional_rrs);
        for (size_t i = 0; i < result->total_additional_rrs; ++i)
            if (!parse_record(buffer, &offset, &result->additional_rrs[i])) goto error;
    }

    return result;

    error:
    md_dns_destroy(result);

    return NULL;
}

void md_dns_destroy(struct md_dns_packet *packet) {
    if (!packet) return;

    md_free(packet->questions);
    md_free(packet->answer_rrs);
    md_free(packet->authority_rrs);
    md_free(packet->additional_rrs);
    md_free(packet);
}

struct md_dns_packet *md_dns_create_request(
        bool recursion_desired,
        const char name[MD_DNS_NAME_LENGTH], enum md_dns_type type) {
    assert(name && type != MD_DNS_UNKNOWN);

    struct md_dns_packet *request = md_calloc(1, sizeof(struct md_dns_packet));
    request->transaction_id = md_rand();
    request->response = MD_DNS_QUERY;
    request->recursion_desired = recursion_desired;

    request->total_questions = 1;
    request->questions = md_malloc(sizeof(struct md_dns_question));
    request->questions[0].type = type;
    memcpy(request->questions[0].name, name, MD_DNS_NAME_LENGTH);

    return request;
}

void md_dns_serialize(const struct md_dns_packet *packet, uint8_t buffer[MD_DNS_MAX_SIZE], size_t *size) {
    assert(packet && size && buffer && *size >= MD_DNS_MIN_SIZE && *size <= MD_DNS_MAX_SIZE);

    struct md_dns_raw_header raw_header;
    raw_header.id = htons(packet->transaction_id);
    raw_header.qr = packet->response;
    raw_header.opcode = packet->opcode;
    raw_header.aa = packet->authoritative;
    raw_header.tc = packet->truncated;
    raw_header.rd = packet->recursion_desired;
    raw_header.ra = packet->recursion_available;
    raw_header.z = 0;
    raw_header.rcode = packet->reply_code;
    raw_header.qdcount = htons((uint16_t) packet->total_questions);
    raw_header.ancount = htons((uint16_t) packet->total_answer_rrs);
    raw_header.nscount = htons((uint16_t) packet->total_authority_rrs);
    raw_header.arcount = htons((uint16_t) packet->total_additional_rrs);

    *size = sizeof raw_header;
    memcpy(buffer, &raw_header, sizeof raw_header);

    struct label_sequence_list *list = NULL;

    for (size_t i = 0; i < packet->total_questions; ++i) {
        find_add_serialize_name(buffer, size, &list, packet->questions[i].name);

        serialize_type(buffer, size, packet->questions[i].type);

        serialize_class(buffer, size);
    }

    for (size_t i = 0; i < packet->total_answer_rrs; ++i)
        serialize_record(buffer, size, &list, &packet->answer_rrs[i]);

    for (size_t i = 0; i < packet->total_authority_rrs; ++i)
        serialize_record(buffer, size, &list, &packet->authority_rrs[i]);

    for (size_t i = 0; i < packet->total_additional_rrs; ++i)
        serialize_record(buffer, size, &list, &packet->additional_rrs[i]);

    while (list) {
        struct label_sequence_list *current = list;
        list = list->next;
        destroy_label_sequence(current->sequence);
        md_free(current);
    }
}

// The template is based on Wireshark's output
char *md_dns_log(const struct md_dns_packet *packet, size_t *size) {
    assert(packet && size);

    char buffer[4096];

    *size = md_sprintf(buffer, "Transaction ID: 0x%4X\n", packet->transaction_id);

    if (packet->response == MD_DNS_QUERY)
        *size += md_sprintf(buffer + *size, "Flags: %s\n", opcode_str[packet->opcode]);
    else
        *size += md_sprintf(buffer + *size, "Flags: %s response, %s\n",
                            opcode_str[packet->opcode],
                            reply_code_str[packet->reply_code]);

    *size += md_sprintf(buffer + *size, "    Response: %s\n", response_str[packet->response]);
    *size += md_sprintf(buffer + *size, "    Opcode: %s (%d)\n", opcode_str[packet->opcode], packet->opcode);
    *size += md_sprintf(buffer + *size, "    Authoritative: %s\n", authoritative_str[packet->authoritative]);
    *size += md_sprintf(buffer + *size, "    Truncated: %s\n", truncated_str[packet->truncated]);
    *size += md_sprintf(buffer + *size, "    Recursion desired: %s\n",
                        recursion_desired_str[packet->recursion_desired]);
    *size += md_sprintf(buffer + *size, "    Recursion available: %s\n",
                        recursion_available_str[packet->recursion_available]);
    *size += md_sprintf(buffer + *size, "    Reply code: %s (%d)\n",
                        reply_code_str[packet->reply_code],
                        packet->reply_code);

    *size += md_sprintf(buffer + *size, "Questions: %zu\n", packet->total_questions);
    for (size_t i = 0; i < packet->total_questions; ++i) {
        const struct md_dns_question *question = &packet->questions[i];
        *size += md_sprintf(buffer + *size, "    %s: type %s, class IN\n",
                            question->name,
                            type_to_string(question->type));
    }

    *size += md_sprintf(buffer + *size, "Answer RRs: %zu\n", packet->total_answer_rrs);
    for (size_t i = 0; i < packet->total_answer_rrs; ++i) log_record(buffer, size, &packet->answer_rrs[i]);

    *size += md_sprintf(buffer + *size, "Authority RRs: %zu\n", packet->total_authority_rrs);
    for (size_t i = 0; i < packet->total_authority_rrs; ++i) log_record(buffer, size, &packet->authority_rrs[i]);

    *size += md_sprintf(buffer + *size, "Additional RRs: %zu\n", packet->total_additional_rrs);
    for (size_t i = 0; i < packet->total_additional_rrs; ++i) log_record(buffer, size, &packet->additional_rrs[i]);

    buffer[(*size)++] = '\0';

    char *result = md_malloc(*size);
    memcpy(result, buffer, *size);

    return result;
}
