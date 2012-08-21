#include <hubbub/hubbub.h>
#include <hubbub/parser.h>
#include <hubbub/tree.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "hubbub-msg.h"

/* #define DEBUG(x, ...)   fprintf(stderr, x, __VA_ARGS__) */
#define DEBUG(x, ...)

/*
 * Tree building
 */

hubbub_error handle_create_comment(void *ctx, const hubbub_string *data, void **result) {
    DEBUG(stderr, "create comment\n");
    return HUBBUB_OK;
}

hubbub_error handle_create_doctype(void *ctx, const hubbub_doctype *doctype, void **result) {
    DEBUG(stderr, "create doctype\n");
    return HUBBUB_OK;
}

hubbub_error handle_create_element(void *ctx, const hubbub_tag *tag, void **result) {
    DEBUG(stderr, "create element\n");
    return HUBBUB_OK;
}

hubbub_error handle_create_text(void *ctx, const hubbub_string *data, void **result) {
    DEBUG(stderr, "create text\n");
    return HUBBUB_OK;
}

hubbub_error handle_ref_node(void *ctx, void *node) {
    DEBUG(stderr, "ref node\n");
    return HUBBUB_OK;
}

hubbub_error handle_unref_node(void *ctx, void *node) {
    DEBUG(stderr, "unref node\n");
    return HUBBUB_OK;
}

hubbub_error handle_append_child(void *ctx, void *parent, void *child, void **result) {
    DEBUG(stderr, "append child\n");
    return HUBBUB_OK;
}

hubbub_error handle_insert_before(void *ctx, void *parent, void *child, void *ref_child,
                                  void **result) {
    DEBUG(stderr, "insert before\n");
    return HUBBUB_OK;
}

hubbub_error handle_remove_child(void *ctx, void *parent, void *child, void **result) {
    DEBUG(stderr, "remove child\n");
    return HUBBUB_OK;
}

hubbub_error handle_clone_node(void *ctx, void *node, bool deep, void **result) {
    DEBUG(stderr, "clone node\n");
    return HUBBUB_OK;
}

hubbub_error handle_reparent_children(void *ctx, void *node, void *new_parent) {
    DEBUG(stderr, "reparent children\n");
    return HUBBUB_OK;
}

hubbub_error handle_get_parent(void *ctx, void *node, bool element_only, void **result) {
    DEBUG(stderr, "get parent\n");
    return HUBBUB_OK;
}

hubbub_error handle_has_children(void *ctx, void *node, bool *result) {
    DEBUG(stderr, "has children\n");
    return HUBBUB_OK;
}

hubbub_error handle_form_associate(void *ctx, void *form, void *node) {
    DEBUG(stderr, "form associate\n");
    return HUBBUB_OK;
}

hubbub_error handle_add_attributes(void *ctx, void *node, const hubbub_attribute *attributes,
                                   uint32_t n_attributes) {
    DEBUG(stderr, "add attributes\n");
    return HUBBUB_OK;
}

hubbub_error handle_set_quirks_mode(void *ctx, hubbub_quirks_mode mode) {
    DEBUG(stderr, "set quirks mode\n");
    return HUBBUB_OK;
}

hubbub_error handle_encoding_change(void *ctx, const char *encname) {
    DEBUG(stderr, "encoding change\n");
    return HUBBUB_OK;
}

hubbub_error handle_complete_script(void *ctx, void *script) {
    DEBUG(stderr, "complete script\n");
    return HUBBUB_OK;
}

static hubbub_tree_handler tree_handler = {
    handle_create_comment,
    handle_create_doctype,
    handle_create_element,
    handle_create_text,
    handle_ref_node,
    handle_unref_node,
    handle_append_child,
    handle_insert_before,
    handle_remove_child,
    handle_clone_node,
    handle_reparent_children,
    handle_get_parent,
    handle_has_children,
    handle_form_associate,
    handle_add_attributes,
    handle_set_quirks_mode,
    handle_encoding_change,
    handle_complete_script,
    NULL
};

/*
 * Message handling
 */

static hubbub_parser *parser = NULL;

static void *myrealloc(void *ptr, size_t len, void *pw) {
	return realloc(ptr, len);
}

void handle_hubbub_request(struct hubbubmsg_request *request) {
    hubbub_error err;
    hubbub_parser_optparams optparams;
    switch (request->type) {
    case HUBBUBMSG_CREATE_PARSER:
        if (parser)
            break;
        DEBUG(stderr, "create parser: %s\n", (char *)request->kind.create_parser_info.enc.data);
        err = hubbub_parser_create((char *)request->kind.create_parser_info.enc.data,
                                   request->kind.create_parser_info.fix_enc,
                                   myrealloc,
                                   NULL,
                                   &parser);
        DEBUG(stderr, "create parser error: %d\n", (int)err);

        optparams.tree_handler = &tree_handler;
        err = hubbub_parser_setopt(parser, HUBBUB_PARSER_TREE_HANDLER, &optparams);
        DEBUG(stderr, "setopt tree handler error: %d\n", (int)err);

        optparams.document_node = (void *)1;
        err = hubbub_parser_setopt(parser, HUBBUB_PARSER_DOCUMENT_NODE,
                                   &optparams);
        DEBUG(stderr, "setopt tree handler error: %d\n", (int)err);
        break;
    case HUBBUBMSG_DESTROY_PARSER:
        if (!parser)
            break;
        DEBUG(stderr, "destroy parser\n");
        hubbub_parser_destroy(parser);
        parser = NULL;
        break;
    case HUBBUBMSG_PARSE_CHUNK:
        DEBUG(stderr, "parse chunk: %s\n", (char *)request->kind.parse_chunk_info.data.data);
        if (!parser) {
            DEBUG(stderr, "no parser\n");
            break;
        }
        hubbub_parser_parse_chunk(parser,
                                  request->kind.parse_chunk_info.data.data,
                                  request->kind.parse_chunk_info.data.len);
    }
}

/*
 * Main loop
 */

void read_all(uint8_t *buf, size_t len) {
    size_t nread;
    while ((nread = read(0, buf, len))) {
        len -= nread;
        buf += len;
        if (len == 0)
            break;
    }
}

int main() {
    /* TODO: Drop into the sandbox here. */

    size_t buf_size = 4096;
    uint8_t *buf = (uint8_t *)malloc(buf_size);
    uint32_t msg_size;

    while (true) {
        read_all((uint8_t *)&msg_size, 4);
        DEBUG(stderr, "msg size is %d\n", (int)msg_size);
        if (buf_size < msg_size) {
            if (!(buf = realloc(buf, msg_size)))
                abort();
            buf_size = msg_size;
        }

        read_all(buf, msg_size);
        handle_hubbub_request((struct hubbubmsg_request *)buf);
    }

    return 0;
}

