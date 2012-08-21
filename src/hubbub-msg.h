#ifndef HUBBUB_MSG_H
#define HUBBUB_MSG_H

#include <stdint.h>

struct hubbubmsg_string {
    uint32_t len;
    uint8_t data[];
};

enum hubbubmsg_request_type {
    HUBBUBMSG_CREATE_PARSER,
    HUBBUBMSG_DESTROY_PARSER,
    HUBBUBMSG_PARSE_CHUNK
};

struct hubbubmsg_create_parser_info {
    bool fix_enc;
    struct hubbubmsg_string enc;
};

struct hubbubmsg_parse_chunk_info {
    struct hubbubmsg_string data;
};

union hubbubmsg_request_kind {
    struct hubbubmsg_create_parser_info create_parser_info;
    struct hubbubmsg_parse_chunk_info parse_chunk_info;
};

struct hubbubmsg_request {
    enum hubbubmsg_request_type type;
    union hubbubmsg_request_kind kind;
};

#endif

