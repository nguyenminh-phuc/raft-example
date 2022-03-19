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
#include <argtable3.h>
#include "minidns/minidns.h"

#ifdef MD_ENABLE_IPV6_STACK
#define DEFAULT_IP "2606:4700:4700::1111"
#define DEFAULT_TYPE MD_DNS_AAAA
#define DEFAULT_TYPE_STR "AAAA"
#else
#define DEFAULT_IP "1.1.1.1"
#define DEFAULT_TYPE MD_DNS_A
#define DEFAULT_TYPE_STR "A"
#endif
#define DEFAULT_POLL_TIMEOUT 1000

static int client_main(std::array<char, MD_NET_IP_LENGTH> &ip, uint16_t port, size_t timeout,
                       bool no_rd, bool recursive,
                       std::array<char, MD_DNS_NAME_LENGTH> &name, md_dns_type type);

int main(int argc, char **argv) {
    auto *ip_arg = arg_str0(nullptr, "ip", nullptr, "dns's ip (default: " DEFAULT_IP ")");
    auto *port_arg = arg_int0(nullptr, "port", nullptr, "dns's port (default: 53)");
    auto *timeout_arg = arg_int0(nullptr, "timeout", "ms", "poll timeout (default: 1000)");
    auto *no_rd_arg = arg_lit0(nullptr, "no-rd", "unset the RD flag");
    auto *recursive_arg = arg_lit0(nullptr, "recursive",
                                   "ignore ip and port, and attempt lookup with root nameservers");
    auto *name_arg = arg_str1(nullptr, "name", nullptr, "name to find");
    auto *type_arg = arg_str0(nullptr, "type", nullptr,
                              "type to find: A, NS, CNAME, MX, AAAA (default: " DEFAULT_TYPE_STR ")");
    auto *help = arg_lit0(nullptr, "help", "print this help and exit");
    auto *end = arg_end(20);
    void *argtable[] = {ip_arg, port_arg, timeout_arg, no_rd_arg, recursive_arg, name_arg, type_arg, help, end};

    auto rc = arg_nullcheck(argtable);
    assert(!rc);

    auto result = EXIT_FAILURE;
    if (argc == 1) {
        std::cerr << "Try 'dns_client --help' for more information." << std::endl;
        goto end;
    }

    ip_arg->sval[0] = DEFAULT_IP;
    port_arg->ival[0] = MD_DNS_SERVICE_DEFAULT_PORT;
    timeout_arg->ival[0] = DEFAULT_POLL_TIMEOUT;
    type_arg->sval[0] = DEFAULT_TYPE_STR;

    rc = arg_parse(argc, argv, argtable);
    if (help->count > 0) {
        std::cout << "Usage: dns_client";
        arg_print_syntax(stdout, argtable, "\n");
        std::cout << "A mini DNS client based on RFC 1035." << std::endl;
        arg_print_glossary(stdout, argtable, " %-25s %s\n");
        result = EXIT_SUCCESS;
    } else if (rc > 0) {
        arg_print_errors(stderr, end, "dns_client");
        std::cerr << "Try 'dns_client --help' for more information." << std::endl;
    } else {
        std::array<char, MD_NET_IP_LENGTH> ip{};
        assert(MD_NET_IP_MIN_LENGTH <= strlen(ip_arg->sval[0]) + 1 && strlen(ip_arg->sval[0]) < MD_NET_IP_LENGTH);
        assert(md_net_is_valid_address(MD_IP_STACK, ip_arg->sval[0]));
        memcpy(ip.data(), ip_arg->sval[0], strlen(ip_arg->sval[0]) + 1);

        assert(port_arg->ival[0] >= 0 && port_arg->ival[0] <= UINT16_MAX);

        assert(timeout_arg->ival[0] >= 0);

        assert(strlen(name_arg->sval[0]) < MD_DNS_NAME_LENGTH);
        std::array<char, MD_DNS_NAME_LENGTH> lower_name{};
        memcpy(lower_name.data(), name_arg->sval[0], strlen(name_arg->sval[0]) + 1);
        for (auto i = 0; lower_name[i]; ++i) lower_name[i] = static_cast<char>(tolower(lower_name[i]));

        const auto type = md_dns_string_to_type(type_arg->sval[0]);
        assert(type != MD_DNS_UNKNOWN);

        result = client_main(ip, port_arg->ival[0], timeout_arg->ival[0],
                             no_rd_arg->count > 0, recursive_arg->count > 0,
                             lower_name, type);
    }

    end:
    arg_freetable(argtable, sizeof argtable / sizeof argtable[0]);
    return result;
}

static int client_main(std::array<char, MD_NET_IP_LENGTH> &ip, uint16_t port, size_t timeout,
                       bool no_rd, bool recursive,
                       std::array<char, MD_DNS_NAME_LENGTH> &name, md_dns_type type) {
    srand(static_cast<unsigned>(time(nullptr)));
    md_net_init_stack();

    auto result = EXIT_FAILURE;
    md_dns_packet *response{};
    char *log{};

    try {
        if (recursive) {
            response = md_dns_service_lookup_recursive(timeout, name.data(), type);
            if (!response) throw std::runtime_error("md_dns_service_lookup_recursive returned nullptr");
        } else {
            response = md_dns_service_lookup(ip.data(), port, timeout, !no_rd, name.data(), type);
            if (!response) throw std::runtime_error("md_dns_service_lookup returned nullptr");
        }

        size_t log_size{};
        log = md_dns_log(response, &log_size);
        if (!log) throw std::runtime_error("md_dns_log returned nullptr");

        std::cout << "====== Lookup Result ======" << std::endl << log << std::endl;
        result = EXIT_SUCCESS;
    } catch (const std::exception &ex) {
        std::cerr << "client_main caught an exception: " << ex.what() << std::endl;
    } catch (...) {
        std::cerr << "client_main caught an exception." << std::endl;
    }

    md_free(log);
    md_dns_destroy(response);
    md_net_destroy_stack();

    return result;
}
