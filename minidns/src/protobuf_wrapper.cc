#include "minidns/protobuf_wrapper.h"
#include <assert.h>
#include <string.h>
#include <stddef.h>
#include <exception>
#include <stdexcept>
#include <vector>
#include "minidns/dns.h"
#include "minidns/network.h"
#include "minidns/rpc2.h"
#include "minidns/raft.h"
#include "minidns/utils.h"

#ifdef _MSC_VER
#pragma warning(push, 0)
#pragma warning(disable: 4996)
#endif

#if !__has_include("rpc.pb.h")
#error "rpc.pb.h" not found
#endif

#include "rpc.pb.h"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

using namespace MiniDns;

static void serialize_command(const md_raft_command &command, Command *proto_command) {
    proto_command->set_name(command.record.name);
    proto_command->set_ttl(command.record.ttl);

    switch (command.type) {
        case md_raft_command::MD_STATE_COMMAND_ADD:
            proto_command->set_type(Command_Type_Add);
            break;
        case md_raft_command::MD_STATE_COMMAND_REMOVE:
            proto_command->set_type(Command_Type_Remove);
    }

    switch (command.record.type) {
        case MD_DNS_A:
            proto_command->mutable_a()->set_address(command.record.data.a.address);
            break;
        case MD_DNS_NS:
            proto_command->mutable_ns()->set_name(command.record.data.ns.name);
            break;
        case MD_DNS_CNAME:
            proto_command->mutable_cname()->set_name(command.record.data.cname.name);
            break;
        case MD_DNS_MX: {
            auto *mx_record = proto_command->mutable_mx();
            mx_record->set_priority(command.record.data.mx.priority);
            mx_record->set_name(command.record.data.mx.name);
            break;
        }
        case MD_DNS_AAAA:
            proto_command->mutable_aaaa()->set_address(command.record.data.aaaa.address);
            break;
        case MD_DNS_UNKNOWN:
            MD_ABORT("This should never happen");
    }
}

static void deserialize_command(md_raft_command &command, const Command &proto_command) {
    const auto proto_type = proto_command.type();
    switch (proto_type) {
        case Command_Type_Add:
            command.type = md_raft_command::MD_STATE_COMMAND_ADD;
            break;
        case Command_Type_Remove:
            command.type = md_raft_command::MD_STATE_COMMAND_REMOVE;
            break;
        default:
            throw std::runtime_error(std::string("Unknown Command_Type case: ") + std::to_string(proto_type));
    }

    assert(proto_command.name().length() < MD_DNS_NAME_LENGTH);
    memcpy(command.record.name, proto_command.name().c_str(), proto_command.name().length() + 1);
    command.record.ttl = proto_command.ttl();

    const auto value_case = proto_command.value_case();
    switch (value_case) {
        case Command::ValueCase::kA:
            assert(MD_NET_IPV4_MIN_LENGTH <= proto_command.a().address().length() + 1 &&
                   proto_command.a().address().length() < MD_NET_IPV4_LENGTH);
            command.record.type = MD_DNS_A;
            memcpy(command.record.data.a.address,
                   proto_command.a().address().c_str(),
                   proto_command.a().address().length() + 1);
            break;
        case Command::ValueCase::kNs:
            assert(proto_command.ns().name().length() < MD_DNS_NAME_LENGTH);
            command.record.type = MD_DNS_NS;
            memcpy(command.record.data.ns.name,
                   proto_command.ns().name().c_str(),
                   proto_command.ns().name().length() + 1);
            break;
        case Command::ValueCase::kCname:
            assert(proto_command.cname().name().length() < MD_DNS_NAME_LENGTH);
            command.record.type = MD_DNS_CNAME;
            memcpy(command.record.data.cname.name,
                   proto_command.cname().name().c_str(),
                   proto_command.cname().name().length() + 1);
            break;
        case Command::ValueCase::kMx:
            assert(proto_command.mx().name().length() < MD_DNS_NAME_LENGTH);
            command.record.type = MD_DNS_MX;
            command.record.data.mx.priority = proto_command.mx().priority();
            memcpy(command.record.data.mx.name,
                   proto_command.mx().name().c_str(),
                   proto_command.mx().name().length() + 1);
            break;
        case Command::ValueCase::kAaaa:
            assert(MD_NET_IPV6_MIN_LENGTH <= proto_command.aaaa().address().length() + 1 &&
                   proto_command.aaaa().address().length() < MD_NET_IPV6_LENGTH);
            command.record.type = MD_DNS_AAAA;
            memcpy(command.record.data.aaaa.address,
                   proto_command.aaaa().address().c_str(),
                   proto_command.aaaa().address().length() + 1);
            break;
        default:
            throw std::runtime_error(std::string("Unknown Command::ValueCase: ") + std::to_string(value_case));
    }
}

uint8_t *md_proto_serialize(enum md_rpc_type type, const void *message, size_t *size) {
    assert(message && size);

    try {
        Message proto_message;

        if (type == MD_RPC_APPEND_ENTRIES_REQUEST) {
            const auto *request = static_cast<const md_rpc_append_entries_request *>(message);
            auto *proto_request = proto_message.mutable_appendentriesrequest();
            proto_request->set_term(request->term);
            proto_request->set_leaderid(request->leader_id);
            proto_request->set_previouslogterm(request->previous_log_index);
            proto_request->set_previouslogterm(request->previous_log_term);
            for (size_t i = 0; i < request->total_entries; ++i) {
                auto *proto_entry = proto_request->add_entries();
                serialize_command(request->entries[i].command, proto_entry->mutable_command());
                proto_entry->set_term(request->entries[i].term);
            }
            proto_request->set_leadercommit(request->leader_commit);
        } else if (type == MD_RPC_APPEND_ENTRIES_RESPONSE) {
            const auto *response = static_cast<const md_rpc_append_entries_response *>(message);
            auto *proto_response = proto_message.mutable_appendentriesresponse();
            proto_response->set_term(response->term);
            proto_response->set_id(response->id);
            proto_response->set_success(response->success);
        } else if (type == MD_RPC_REQUEST_VOTE_REQUEST) {
            const auto *request = static_cast<const md_rpc_request_vote_request *>(message);
            auto *proto_request = proto_message.mutable_requestvoterequest();
            proto_request->set_term(request->term);
            proto_request->set_candidateid(request->candidate_id);
        } else if (type == MD_RPC_REQUEST_VOTE_RESPONSE) {
            const auto *response = static_cast<const md_rpc_request_vote_response *>(message);
            auto *proto_response = proto_message.mutable_requestvoteresponse();
            proto_response->set_term(response->term);
            proto_response->set_votegranted(response->vote_granted);
        } else if (type == MD_RPC_COMMAND_REQUEST) {
            const auto *request = static_cast<const md_rpc_command_request *>(message);
            auto *proto_request = proto_message.mutable_commandrequest();
            serialize_command(request->command, proto_request->mutable_command());
        } else if (type == MD_RPC_COMMAND_RESPONSE) {
            const auto *response = static_cast<const md_rpc_command_response *>(message);
            auto *proto_response = proto_message.mutable_commandresponse();

            switch (response->type) {
                case md_rpc_command_response::MD_RPC_ENTRY_APPLIED:
                    proto_response->mutable_entryappliedresponse();
                    break;
                case md_rpc_command_response::MD_RPC_NO_LEADER:
                    proto_response->noleaderresponse();
                    break;
                case md_rpc_command_response::MD_RPC_REDIRECT_TO_LEADER: {
                    auto *proto_leader = proto_response->mutable_redirecttoleader();
                    proto_leader->set_ip(response->leader->ip);
                    proto_leader->set_port(response->leader->port);
                }
            }
        } else throw std::runtime_error(std::string("Unknown md_rpc_type case: ") + std::to_string(type));

        *size = proto_message.ByteSizeLong();
        std::vector<uint8_t> buffer(*size);

        google::protobuf::io::ArrayOutputStream aos(buffer.data(), static_cast<int>(*size));
        google::protobuf::io::CodedOutputStream cos(&aos);
        if (!proto_message.SerializeToCodedStream(&cos)) {
            MD_TRACE("SerializeToCodedStream returned false");
            return nullptr;
        }

        auto *result = static_cast<uint8_t *>(md_malloc(*size));
        memcpy(result, buffer.data(), *size);

        return result;
    } catch (const std::exception &ex) {
        MD_ABORT("md_proto_serialize caught an exception: %s", ex.what());
    }
    catch (...) {
        MD_ABORT("md_proto_serialize caught an exception");
    }
}

void *md_proto_deserialize(enum md_rpc_type *type, uint8_t *buffer, size_t size) {
    assert(type && buffer);

    try {
        google::protobuf::io::ArrayInputStream ais(buffer, static_cast<int>(size));
        google::protobuf::io::CodedInputStream cis(&ais);
        Message proto_message;
        if (!proto_message.ParseFromCodedStream(&cis)) {
            MD_TRACE("ParseFromCodedStream returned false");
            return nullptr;
        }

        if (!cis.ConsumedEntireMessage()) {
            MD_TRACE("ConsumedEntireMessage returned false");
            return nullptr;
        }

        void *data{};
        const Message::ValueCase proto_type = proto_message.value_case();
        if (proto_type == Message::ValueCase::kAppendEntriesRequest) {
            const auto &proto_request = proto_message.appendentriesrequest();
            *type = MD_RPC_APPEND_ENTRIES_REQUEST;
            data = md_malloc(sizeof(md_rpc_append_entries_request));

            auto *request = static_cast<md_rpc_append_entries_request *>(data);
            request->term = proto_request.term();
            request->leader_id = proto_request.leaderid();
            request->previous_log_index = proto_request.previouslogindex();
            request->previous_log_term = proto_request.previouslogterm();
            if ((request->total_entries = proto_request.entries_size())) {
                request->entries =
                        static_cast<md_raft_entry *>(md_malloc(sizeof(md_raft_entry) * request->total_entries));
                for (size_t i = 0; i < request->total_entries; ++i) {
                    const auto &proto_entry = proto_request.entries(static_cast<int>(i));
                    deserialize_command(request->entries[i].command, proto_entry.command());
                    request->entries[i].term = proto_entry.term();
                }
            } else request->entries = nullptr;
            request->leader_commit = proto_request.leadercommit();
        } else if (proto_type == Message::ValueCase::kAppendEntriesResponse) {
            const auto &proto_response = proto_message.appendentriesresponse();
            *type = MD_RPC_APPEND_ENTRIES_RESPONSE;
            data = md_malloc(sizeof(md_rpc_append_entries_response));

            auto *response = static_cast<md_rpc_append_entries_response *>(data);
            response->term = proto_response.term();
            response->id = proto_response.id();
            response->success = proto_response.success();
        } else if (proto_type == Message::ValueCase::kRequestVoteRequest) {
            const auto &proto_request = proto_message.requestvoterequest();
            *type = MD_RPC_REQUEST_VOTE_REQUEST;
            data = md_malloc(sizeof(md_rpc_request_vote_request));

            auto *request = static_cast<md_rpc_request_vote_request *>(data);
            request->term = proto_request.term();
            request->candidate_id = proto_request.candidateid();
        } else if (proto_type == Message::ValueCase::kRequestVoteResponse) {
            const auto &proto_response = proto_message.requestvoteresponse();
            *type = MD_RPC_REQUEST_VOTE_RESPONSE;
            data = md_malloc(sizeof(md_rpc_request_vote_response));

            auto *response = static_cast<md_rpc_request_vote_response *>(data);
            response->term = proto_response.term();
            response->vote_granted = proto_response.votegranted();
        } else if (proto_type == Message::ValueCase::kCommandRequest) {
            const auto &proto_request = proto_message.commandrequest();
            *type = MD_RPC_COMMAND_REQUEST;
            data = md_malloc(sizeof(md_rpc_command_request));

            auto *request = static_cast<md_rpc_command_request *>(data);
            deserialize_command(request->command, proto_request.command());
        } else if (proto_type == Message::ValueCase::kCommandResponse) {
            const auto &proto_response = proto_message.commandresponse();
            *type = MD_RPC_COMMAND_RESPONSE;
            data = md_malloc(sizeof(md_rpc_command_response));

            auto *response = static_cast<md_rpc_command_response *>(data);

            const auto value_case = proto_response.value_case();
            switch (value_case) {
                case CommandResponse::ValueCase::kEntryAppliedResponse:
                    response->type = md_rpc_command_response::MD_RPC_ENTRY_APPLIED;
                    break;
                case CommandResponse::ValueCase::kNoLeaderResponse:
                    response->type = md_rpc_command_response::MD_RPC_NO_LEADER;
                    break;
                case CommandResponse::ValueCase::kRedirectToLeader: {
                    const auto &proto_leader = proto_response.redirecttoleader();
                    assert(proto_leader.ip().length() < MD_NET_IP_LENGTH);

                    response->type = md_rpc_command_response::MD_RPC_REDIRECT_TO_LEADER;
                    response->leader = static_cast<decltype(response->leader)>(md_malloc(sizeof *response->leader));
                    memcpy(response->leader->ip, proto_leader.ip().c_str(), proto_leader.ip().length() + 1);
                    response->leader->port = proto_leader.port();
                    break;
                }
                default:
                    throw std::runtime_error(
                            std::string("Unknown CommandResponse::ValueCase: ") + std::to_string(value_case));
            }
        } else throw std::runtime_error(std::string("Unknown Message::ValueCase: ") + std::to_string(proto_type));

        return data;
    } catch (const std::exception &ex) {
        MD_ABORT("md_proto_deserialize caught an exception: %s", ex.what());
    } catch (...) {
        MD_ABORT("md_proto_deserialize caught an exception");
    }
}
