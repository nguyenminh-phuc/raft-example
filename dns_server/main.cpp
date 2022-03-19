#define __STDC_WANT_LIB_EXT1__ 1

#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <array>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <argtable3.h>
#include "minidns/minidns.h"

#ifdef MD_ENABLE_IPV6_STACK
#define DEFAULT_PUBLIC_DNS_IP "2606:4700:4700::1111"
#else
#define DEFAULT_PUBLIC_DNS_IP "1.1.1.1"
#endif
#define DEFAULT_LOCAL_DNS_PORT 5300
#define DEFAULT_POOL_SIZE 10
#define DEFAULT_POLL_TIMEOUT 1000
#define DEFAULT_ELECTION_TIMEOUT 150
#define DEFAULT_DATABASE ":memory:"

static volatile sig_atomic_t terminable = 0;

static void signal_handler(int) { terminable = 1; }

static int server_main(
        uint64_t id, const std::vector<md_raft_peer_arg> &peers,
        uint16_t local_dns_port, size_t local_dns_poll_timeout,
        std::array<char, MD_NET_IP_LENGTH> &public_dns_ip, uint16_t public_dns_port, size_t public_dns_poll_timeout,
        uint16_t rpc_port, size_t rpc_timeout,
        size_t election_timeout,
        size_t thread_pool_size,
        std::string_view db_filename);

int main(int argc, char **argv) {
    auto *id_arg = arg_int1(nullptr, "id", nullptr, "server's id");
    auto *peers_arg = arg_strn(nullptr, "peer", "id,ip,port", 2, 6, "peers (format: <id>,<ip>,<port>)");
    auto *local_dns_port_arg = arg_int0(nullptr, "local-dns-port", nullptr, "local dns's port (default: 5300)");
    auto *local_dns_poll_timeout_arg = arg_int0(nullptr, "local-dns-timeout", "ms",
                                                "local dns's poll timeout (default: 1000)");
    auto *public_dns_ip_arg = arg_str0(nullptr, "public-dns-ip", nullptr,
                                       "public dns's ip (default: " DEFAULT_PUBLIC_DNS_IP ")");
    auto *public_dns_port_arg = arg_int0(nullptr, "public-dns-port", nullptr, "public dns's port (default: 53)");
    auto *public_dns_poll_timeout_arg = arg_int0(nullptr, "public-dns-timeout", "ms",
                                                 "public dns's poll timeout (default: 1000)");
    auto *rpc_port_arg = arg_int1(nullptr, "rpc-port", nullptr, "rpc port");
    auto *rpc_timeout_arg = arg_int0(nullptr, "rpc-timeout", "ms", "rpc poll timeout (default: 1000)");
    auto *election_timeout_arg = arg_int0(nullptr, "election-timeout", "ms", "election timeout (default: 150)");
    auto *pool_size_arg = arg_int0(nullptr, "pool-size", nullptr, "thread pool' size (default: 10)");
    auto *db_filename_arg = arg_file0(nullptr, "db", nullptr, "database's filename (default: " DEFAULT_DATABASE ")");
    auto *help = arg_lit0(nullptr, "help", "print this help and exit");
    auto *end = arg_end(20);
    void *argtable[] = {
            id_arg, peers_arg,
            local_dns_port_arg, local_dns_poll_timeout_arg,
            public_dns_ip_arg, public_dns_port_arg, public_dns_poll_timeout_arg,
            rpc_port_arg, rpc_timeout_arg,
            election_timeout_arg,
            pool_size_arg,
            db_filename_arg,
            help, end};

    auto rc = arg_nullcheck(argtable);
    assert(!rc);

    auto result = EXIT_FAILURE;
    if (argc == 1) {
        std::cerr << "Try 'server --help' for more information." << std::endl;
        goto end;
    }

    local_dns_port_arg->ival[0] = DEFAULT_LOCAL_DNS_PORT;
    local_dns_poll_timeout_arg->ival[0] = DEFAULT_POLL_TIMEOUT;
    public_dns_ip_arg->sval[0] = DEFAULT_PUBLIC_DNS_IP;
    public_dns_port_arg->ival[0] = MD_DNS_SERVICE_DEFAULT_PORT;
    public_dns_poll_timeout_arg->ival[0] = DEFAULT_POLL_TIMEOUT;
    rpc_timeout_arg->ival[0] = DEFAULT_POLL_TIMEOUT;
    election_timeout_arg->ival[0] = DEFAULT_ELECTION_TIMEOUT;
    pool_size_arg->ival[0] = DEFAULT_POOL_SIZE;
    db_filename_arg->filename[0] = DEFAULT_DATABASE;

    rc = arg_parse(argc, argv, argtable);
    if (help->count > 0) {
        std::cout << "Usage: server";
        arg_print_syntax(stdout, argtable, "\n");
        std::cout << "A mini distributed DNS server based on RFC 1035." << std::endl;
        std::cout << "The server uses Raft to achieve consensus across all instances." << std::endl;
        arg_print_glossary(stdout, argtable, " %-25s %s\n");
        result = EXIT_SUCCESS;
    } else if (rc > 0) {
        arg_print_errors(stderr, end, "server");
        std::cerr << "Try 'server --help' for more information." << std::endl;
    } else {
        assert(id_arg->ival[0] >= 0);

        std::vector<md_raft_peer_arg> peers;
        for (size_t i = 0; i < peers_arg->count; ++i) {
            std::string s(peers_arg->sval[0]);

            assert(s.find(',') != std::string::npos);
            const auto peer_id_str = s.substr(0, s.find(','));
            const auto peer_id = std::stoi(peer_id_str);
            assert(peer_id >= 0);

            s.erase(0, s.find(',') + 1);
            assert(s.find(',') != std::string::npos);
            const auto peer_ip = s.substr(0, s.find(','));
            assert(MD_NET_IP_MIN_LENGTH <= peer_ip.length() + 1 && peer_ip.length() < MD_NET_IP_LENGTH);
            assert(md_net_is_valid_address(MD_IP_STACK, peer_ip.c_str()));

            s.erase(0, s.find(',') + 1);
            assert(s.find(',') != std::string::npos);
            const auto peer_port_str = s.substr(0, s.find(','));
            const auto peer_port = std::stoi(peer_port_str);
            assert(peer_port >= 0 && peer_port <= UINT16_MAX);

            md_raft_peer_arg peer{};
            peer.id = peer_id;
            memcpy(peer.ip, peer_ip.c_str(), peer_ip.length() + 1);
            peer.port = peer_port;
            peers.push_back(peer);
        }
        for (size_t i = 0; i < peers.size(); ++i) {
            assert(peers[i].id != id_arg->ival[0]);
            for (size_t j = i + 1; i < peers.size(); ++j) {
                assert(peers[i].id != peers[j].id);
                if (strcmp(peers[i].ip, peers[j].ip) == 0) assert(peers[i].port != peers[j].port);
            }
        }

        assert(local_dns_port_arg->ival[0] >= 0 && local_dns_port_arg->ival[0] <= UINT16_MAX);

        assert(local_dns_poll_timeout_arg->ival[0] >= 0);

        std::array<char, MD_NET_IP_LENGTH> public_dns_ip{};
        assert(MD_NET_IP_MIN_LENGTH <= strlen(public_dns_ip_arg->sval[0]) + 1 &&
               strlen(public_dns_ip_arg->sval[0]) < MD_NET_IP_LENGTH);
        assert(md_net_is_valid_address(MD_IP_STACK, public_dns_ip_arg->sval[0]));
        memcpy(public_dns_ip.data(), public_dns_ip_arg->sval[0], strlen(public_dns_ip_arg->sval[0]) + 1);

        assert(public_dns_port_arg->ival[0] >= 0 && public_dns_port_arg->ival[0] <= UINT16_MAX);

        assert(public_dns_poll_timeout_arg->ival[0] >= 0);

        assert(rpc_port_arg->ival[0] >= 0 && rpc_port_arg->ival[0] <= UINT16_MAX);

        assert(rpc_timeout_arg->ival[0] >= 0);

        assert(election_timeout_arg->ival[0] >= 0);

        assert(pool_size_arg->ival[0] > 0);

        result = server_main(
                id_arg->ival[0],
                peers,
                local_dns_port_arg->ival[0], local_dns_poll_timeout_arg->ival[0],
                public_dns_ip, public_dns_port_arg->ival[0], public_dns_poll_timeout_arg->ival[0],
                rpc_port_arg->ival[0], rpc_timeout_arg->ival[0],
                election_timeout_arg->ival[0],
                pool_size_arg->ival[0],
                db_filename_arg->filename[0]);
    }

    end:
    arg_freetable(argtable, sizeof argtable / sizeof argtable[0]);
    return result;
}

int server_main(
        uint64_t id, const std::vector<md_raft_peer_arg> &peers,
        uint16_t local_dns_port, size_t local_dns_poll_timeout,
        std::array<char, MD_NET_IP_LENGTH> &public_dns_ip, uint16_t public_dns_port, size_t public_dns_poll_timeout,
        uint16_t rpc_port, size_t rpc_timeout,
        size_t election_timeout,
        size_t thread_pool_size,
        std::string_view db_filename) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    srand(static_cast<unsigned>(time(nullptr)));
    md_utils_set_thread_name("Main");
    md_net_init_stack();

    auto result = EXIT_SUCCESS;
    auto *server = md_server_create(
            id, peers.data(), peers.size(),
            local_dns_port, local_dns_poll_timeout,
            public_dns_ip.data(), public_dns_port, public_dns_poll_timeout,
            rpc_port, rpc_timeout,
            election_timeout,
            thread_pool_size,
            db_filename.data(),
            &terminable);
    if (!server) {
        std::cerr << "md_server_create returned nullptr" << std::endl;
        result = EXIT_FAILURE;
        goto end;
    }

    md_server_run_main_loop(server);

    end:
    md_net_destroy_stack();
    return result;
}
