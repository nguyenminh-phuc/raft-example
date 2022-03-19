#ifndef MD_PROTOBUF_WRAPPER_H
#define MD_PROTOBUF_WRAPPER_H

#include <stdint.h>
#include <stdlib.h>
#include "minidns/config.h"
#include "minidns/rpc2.h"

#ifdef __cplusplus
extern "C" {
#endif

MD_API uint8_t *md_proto_serialize(enum md_rpc_type type, const void *message, size_t *size);

MD_API void *md_proto_deserialize(enum md_rpc_type *type, uint8_t *buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif
