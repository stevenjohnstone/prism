#define _GNU_SOURCE
#include <assert.h>
#include <prism.h>
#include "prism/internal/parser.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int8_t start_line;
    uint8_t cmd_flags;
    bool main_script;
    bool freeze;
    bool partial_script;
    bool attach_comments;
    bool encoding_locked;
    const char *version;
    bool has_frozen_string_literal;
    bool frozen_string_literal;
    uint8_t scopes_count;
    uint8_t forwarding;
    bool format_errors;
    pm_errors_format_type_t error_format_type;
    bool prettyprint;
} fuzz_options_t;

static pm_visit_result_t check_node_location(const pm_node_t *node, void *data) {
    size_t size = *(const size_t *) data;
    assert(node->location.start <= size);
    assert(node->location.length <= size - node->location.start);
    return PM_VISIT_DESCEND;
}

__attribute__((noinline)) void harness_parse(const uint8_t *input, size_t size, const fuzz_options_t *opts) {
    uint8_t *source = malloc(size);
    assert(source);
    memcpy(source, input, size);

    struct pm_options_t *options = pm_options_new();
    pm_options_line_set(options, opts->start_line);
    pm_options_command_line_set(options, opts->cmd_flags);
    pm_options_main_script_set(options, opts->main_script);
    pm_options_freeze_set(options, opts->freeze);
    pm_options_partial_script_set(options, opts->partial_script);
    pm_options_attach_comments_set(options, opts->attach_comments);
    pm_options_encoding_locked_set(options, opts->encoding_locked);
    pm_options_version_set(options, opts->version, strlen(opts->version));

    if (opts->has_frozen_string_literal) {
        pm_options_frozen_string_literal_set(options, opts->frozen_string_literal);
    }

    if (opts->scopes_count > 0 && pm_options_scopes_init(options, opts->scopes_count)) {
        static const char * const scope_locals[][2] = {
            { "a", "foo" },
            { "b", "it" },
            { "c", "_1" },
        };

        for (size_t i = 0; i < opts->scopes_count; i++) {
            pm_options_scope_t *scope = pm_options_scope_mut(options, i);
            size_t locals_count = (i == 0 && size > 0) ? 3 : 2;
            pm_options_scope_init(scope, locals_count);
            pm_options_scope_forwarding_set(scope, (i == (size_t) (opts->scopes_count - 1)) ? opts->forwarding : PM_OPTIONS_SCOPE_FORWARDING_NONE);

            for (size_t j = 0; j < 2; j++) {
                const char *name = scope_locals[i][j];
                pm_string_init(pm_options_scope_local_mut(scope, j), (const uint8_t *) name, strlen(name));
            }
            if (locals_count == 3) {
                size_t len = size < 4 ? size : 4;
                pm_string_init(pm_options_scope_local_mut(scope, 2), source, len);
            }
        }
    }

    pm_arena_t *arena = pm_arena_new();
    pm_parser_t *parser = pm_parser_new(arena, source, size, options);
    pm_node_t *node = pm_parse(parser);

    pm_visit_node(node, check_node_location, &size);

    pm_buffer_t *buffer = pm_buffer_new();

    pm_serialize(parser, node, buffer);
    pm_buffer_free(buffer);

    if (opts->format_errors && (parser->error_list.size > 0)) {
        buffer = pm_buffer_new();
        (void) pm_errors_format(parser, buffer, opts->error_format_type);
        pm_buffer_free(buffer);
    }

    if (opts->prettyprint) {
        buffer = pm_buffer_new();
        pm_prettyprint(buffer, parser, node);
        pm_buffer_free(buffer);
    } else {
        buffer = pm_buffer_new();
        pm_dump_json(buffer, parser, node);
        pm_buffer_free(buffer);
    }

    pm_parser_free(parser);
    pm_arena_free(arena);
    pm_options_free(options);
    free(source);
}

__attribute__((noinline)) void harness(const uint8_t *input, size_t size) {
    if (size <= 4) return;

    static const char * const versions[] = {
        "3.3",
        "3.4",
        "3.5",
        "4.1",
    };

    uint8_t opt_flags = input[0];
    fuzz_options_t opts = {
        .start_line = (int8_t) input[3],
        .cmd_flags = input[1] & 0x3f,
        .main_script = (input[1] & 0x40) != 0,
        .freeze = (opt_flags & 1) != 0,
        .partial_script = (opt_flags & 2) != 0,
        .attach_comments = (opt_flags & 4) != 0,
        .encoding_locked = (opt_flags & 8) != 0,
        .version = versions[input[2] & 0x03],
        .has_frozen_string_literal = (opt_flags & 16) != 0,
        .frozen_string_literal = (opt_flags & 32) != 0,
        .scopes_count = (input[2] >> 2) & 0x03,
        .forwarding = (input[2] >> 4) & 0x0f,
        .format_errors = (opt_flags & 128) != 0,
        .error_format_type = (input[1] & 128) ? PM_ERRORS_FORMAT_COLOR : PM_ERRORS_FORMAT_PLAIN,
        .prettyprint = (opt_flags & 64) != 0,
    };

    harness_parse(input + 4, size - 4, &opts);
}

