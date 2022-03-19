#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <array>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <argtable3.h>
#include "minidns/minidns.h"

#define DEFAULT_POLL_TIMEOUT 1000
#define TOTAL_RETRIES 3

static int client_main(
        std::array<char, MD_NET_IP_LENGTH> &ip, uint16_t port, size_t timeout,
        const md_rpc_command_request *request);

int main(int argc, char **argv) {
    auto *ip_arg = arg_str1(nullptr, "ip", nullptr, "rpc server's ip");
    auto *port_arg = arg_int1(nullptr, "port", nullptr, "rpc server's port");
    auto *timeout_arg = arg_int0(nullptr, "timeout", "ms", "poll timeout (default: 1000)");
    auto *command_type_arg = arg_str1(nullptr, "command", nullptr, "command type: add, remove");
    auto *name_arg = arg_str1(nullptr, "name", nullptr, "name");
    auto *type_arg = arg_str1(nullptr, "dns-type", nullptr, "dns type: A, NS, CNAME, MX, AAAA");
    auto *ttl_arg = arg_int1(nullptr, "ttl", "s", "time to live");
    auto *address_arg = arg_str0(nullptr, "address", nullptr, "A address or AAAA address");
    auto *record_name_arg = arg_str0(nullptr, "record-name", nullptr, "NS name, CNAME name or MX name");
    auto *priority_arg = arg_int0(nullptr, "priority", nullptr, "MX priority");
    auto *help = arg_lit0(nullptr, "help", "print this help and exit");
    auto *end = arg_end(20);
    void *argtable[] = {
            ip_arg, port_arg, timeout_arg,
            command_type_arg, name_arg, type_arg, ttl_arg, address_arg, record_name_arg, priority_arg,
            help, end};

    auto rc = arg_nullcheck(argtable);
    assert(!rc);

    auto result = EXIT_FAILURE;
    if (argc == 1) {
        std::cerr << "Try 'rpc_client --help' for more information." << std::endl;
        goto end;
    }

    timeout_arg->ival[0] = DEFAULT_POLL_TIMEOUT;

    rc = arg_parse(argc, argv, argtable);
    if (help->count > 0) {
        std::cout << "Usage: rpc_client";
        arg_print_syntax(stdout, argtable, "\n");
        std::cout << "An RPC client for adding and removing DNS records." << std::endl;
        arg_print_glossary(stdout, argtable, " %-25s %s\n");
        result = EXIT_SUCCESS;
    } else if (rc > 0) {
        arg_print_errors(stderr, end, "rpc_client");
        std::cerr << "Try 'rpc_client --help' for more information." << std::endl;
    } else {
        assert(MD_NET_IP_MIN_LENGTH <= strlen(ip_arg->sval[0]) + 1 && strlen(ip_arg->sval[0]) < MD_NET_IP_LENGTH);
        assert(md_net_is_valid_address(MD_IP_STACK, ip_arg->sval[0]));
        std::array<char, MD_NET_IP_LENGTH> ip{};
        memcpy(ip.data(), ip_arg->sval[0], strlen(ip_arg->sval[0]) + 1);

        assert(port_arg->ival[0] >= 0 && port_arg->ival[0] <= UINT16_MAX);

        assert(timeout_arg->ival[0] >= 0);

        md_rpc_command_request request{};

        if (strcmp(command_type_arg->sval[0], "add") == 0)
            request.command.type = md_raft_command::MD_STATE_COMMAND_ADD;
        else if (strcmp(command_type_arg->sval[0], "remove") == 0)
            request.command.type = md_raft_command::MD_STATE_COMMAND_REMOVE;
        else {
            std::cerr << "Invalid command type: " << command_type_arg->sval[0] << std::endl;
            goto end;
        }

        auto *record = &request.command.record;

        assert(strlen(name_arg->sval[0]) < MD_DNS_NAME_LENGTH);
        memcpy(record->name, name_arg->sval[0], strlen(name_arg->sval[0]) + 1);
        for (auto i = 0; record->name[i]; ++i) record->name[i] = static_cast<char>(tolower(record->name[i]));

        record->type = md_dns_string_to_type(type_arg->sval[0]);
        assert(record->type != MD_DNS_UNKNOWN);

        if (record->type == MD_DNS_A || record->type == MD_DNS_AAAA) {
            assert(address_arg->count);
            if (record->type == MD_DNS_A) {
                assert(MD_NET_IPV4_MIN_LENGTH <= strlen(address_arg->sval[0]) + 1 &&
                       strlen(address_arg->sval[0]) < MD_NET_IPV4_LENGTH);
                memcpy(record->data.a.address, name_arg->sval[0], strlen(name_arg->sval[0]) + 1);
                assert(md_net_is_valid_address(AF_INET, record->data.a.address));
            } else {
                assert(MD_NET_IPV6_MIN_LENGTH <= strlen(address_arg->sval[0]) + 1 &&
                       strlen(address_arg->sval[0]) < MD_NET_IPV6_LENGTH);
                memcpy(record->data.aaaa.address, name_arg->sval[0], strlen(name_arg->sval[0]) + 1);
                assert(md_net_is_valid_address(AF_INET6, record->data.aaaa.address));
            }
        } else {
            assert(record_name_arg->count);
            assert(strlen(record_name_arg->sval[0]) < MD_DNS_NAME_LENGTH);
            char *value;
            if (record->type == MD_DNS_NS) value = record->data.ns.name;
            else if (record->type == MD_DNS_CNAME) value = record->data.cname.name;
            else {
                assert(priority_arg->count && priority_arg->ival[0] >= 0);
                record->data.mx.priority = priority_arg->ival[0];
                value = record->data.mx.name;
            }

            memcpy(value, record_name_arg->sval[0], strlen(record_name_arg->sval[0]) + 1);
            for (auto i = 0; value[i]; ++i) value[i] = static_cast<char>(tolower(value[i]));
        }

        result = client_main(ip, port_arg->ival[0], timeout_arg->ival[0], &request);
    }

    end:
    arg_freetable(argtable, sizeof argtable / sizeof argtable[0]);
    return result;
}

int client_main(
        std::array<char, MD_NET_IP_LENGTH> &ip, uint16_t port, size_t timeout,
        const md_rpc_command_request *request) {
    srand(static_cast<unsigned>(time(nullptr)));
    md_net_init_stack();

    auto result = EXIT_FAILURE;
    uint8_t *request_buffer{}, *response_buffer{};
    md_net_fd *fd{};
    md_rpc_type response_type{};
    void *response{};

    try {
        size_t request_size{};
        request_buffer = md_proto_serialize(MD_RPC_COMMAND_REQUEST, request, &request_size);
        if (!request_buffer) throw std::runtime_error("md_proto_serialize returned nullptr");

        fd = md_net_create_fd(SOCK_STREAM);
        if (!fd) throw std::runtime_error("md_net_create_fd returned nullptr");

        if (!md_net_connect(fd, ip.data(), port)) throw std::runtime_error("md_net_connect returned false");

        if (!md_net_tcp_send_with_u32_size(fd, request_buffer, request_size, TOTAL_RETRIES))
            throw std::runtime_error("md_net_tcp_send_with_u32_size returned false");

        if (!md_net_pollin(fd, timeout)) throw std::runtime_error("Socket is not readable");

        size_t response_size{};
        response_buffer = md_net_tcp_receive_with_u32_size(fd, &response_size);
        if (!response_buffer) throw std::runtime_error("md_net_tcp_receive_with_u32_size returned nullplr");

        response = md_proto_deserialize(&response_type, response_buffer, response_size);
        if (!response) throw std::runtime_error("md_proto_deserialize returned nullptr");

        if (response_type != MD_RPC_COMMAND_RESPONSE)
            throw std::runtime_error(std::string("Invalid response type: ") + std::to_string(response_type));

        const auto *command_response = static_cast<const md_rpc_command_response *>(response);
        switch (command_response->type) {
            case md_rpc_command_response::MD_RPC_ENTRY_APPLIED:
                std::cout << "Entry applied to state machine." << std::endl;
                break;
            case md_rpc_command_response::MD_RPC_NO_LEADER:
                std::cerr << "No leader found." << std::endl;
                break;
            case md_rpc_command_response::MD_RPC_REDIRECT_TO_LEADER:
                std::cerr << "The request needs to be redirected to the leader: ";
#ifdef MD_ENABLE_IPV6_STACK
                std::cout << '[' << command_response->leader->ip << "]:" <<command_response->leader->port << std::endl;
#else
                std::cerr << command_response->leader->ip << ':' << command_response->leader->port << std::endl;
#endif
        }

        result = EXIT_SUCCESS;
    } catch (const std::exception &ex) {
        std::cerr << "client_main caught an exception: " << ex.what() << std::endl;
    } catch (...) {
        std::cerr << "client_main caught an exception." << std::endl;
    }

    md_net_destroy_fd(fd);
    if (response_type == MD_RPC_COMMAND_RESPONSE) md_free(static_cast<md_rpc_command_response *>(response)->leader);
    md_free(response);
    md_free(response_buffer);
    md_free(request_buffer);
    md_net_destroy_stack();

    return result;
}