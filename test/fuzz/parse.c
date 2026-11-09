#define _GNU_SOURCE
#include <assert.h>
#include <prism.h>
#include "prism/internal/buffer.h"
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
} fuzz_options_t;

static pm_visit_result_t check_node_location(const pm_node_t *node, void *data) {
    size_t size = *(const size_t *) data;
    assert(node->location.start <= size);
    assert(node->location.length <= size - node->location.start);
    return PM_VISIT_DESCEND;
}

#ifdef PRISM_FUZZ_IJON
extern void ijon_set(uint32_t addr, uint32_t val);
extern uint32_t ijon_hashstr(uint32_t old, const char *val);

static inline uint32_t fuzz_ijon_mix32(uint32_t h) {
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;
    return h;
}

#define FUZZ_IJON_SET(x) \
    do { \
        static uint32_t loc_hash = 0; \
        if (loc_hash == 0) loc_hash = ijon_hashstr(__LINE__, __FILE__); \
        ijon_set(loc_hash, fuzz_ijon_mix32(loc_hash ^ (uint32_t) (x)) & 0x1ffu); \
    } while (0)

typedef struct {
    uint32_t prev_lex_mode_sig;
    uint32_t prev_ctx_sig;
    uint32_t prev_state_flags;
    uint32_t prev_scope_sig;
    size_t prev_error_count;
} fuzz_ijon_state_t;

static void fuzz_ijon_lex_callback(pm_parser_t *parser, pm_token_t *token, void *data) {
    (void) token;
    fuzz_ijon_state_t *state = (fuzz_ijon_state_t *) data;

    // 1. Lexer mode stack signature (top 4 modes with delimiter-nesting / heredoc flags).
    uint32_t lex_mode_sig = 0;
    uint32_t lex_depth = 0;
    for (const pm_lex_mode_t *m = parser->lex_modes.current; m != NULL && lex_depth < 4; m = m->prev, lex_depth++) {
        uint32_t sub = 0;
        switch (m->mode) {
            case PM_LEX_LIST:    sub = (m->as.list.nesting > 0); break;
            case PM_LEX_REGEXP:  sub = (m->as.regexp.nesting > 0); break;
            case PM_LEX_STRING:  sub = (m->as.string.nesting > 0); break;
            case PM_LEX_HEREDOC: sub = (m->as.heredoc.base.indent != PM_HEREDOC_INDENT_NONE); break;
            default: break;
        }
        uint32_t nibble = (((uint32_t) m->mode + 1u) & 0x07u) | (sub << 3);
        lex_mode_sig = (lex_mode_sig << 4) | nibble;
    }
    if (parser->lex_modes.current != NULL && parser->lex_modes.current->mode == PM_LEX_HEREDOC) {
        const pm_heredoc_lex_mode_t *hd = &parser->lex_modes.current->as.heredoc.base;
        uint32_t hd_bits = ((uint32_t) hd->indent & 0x3u) | (((uint32_t) hd->quote & 0x7u) << 2);
        lex_mode_sig |= (hd_bits << 16);
    }
    if (lex_mode_sig != state->prev_lex_mode_sig) {
        FUZZ_IJON_SET(lex_mode_sig);
        state->prev_lex_mode_sig = lex_mode_sig;
    }

    // 2. Parser context stack signature (current and parent context).
    uint32_t cur_ctx = parser->current_context != NULL ? (uint32_t) parser->current_context->context : 0;
    uint32_t prev_ctx = (parser->current_context != NULL && parser->current_context->prev != NULL)
        ? (uint32_t) parser->current_context->prev->context
        : 0;
    uint32_t ctx_sig = (cur_ctx << 6) | prev_ctx;
    if (ctx_sig != state->prev_ctx_sig) {
        FUZZ_IJON_SET(ctx_sig);
        state->prev_ctx_sig = ctx_sig;
    }

    // 3. Non-CFG parser mode flags and boolean stacks.
    uint32_t mode_flags =
        (uint32_t) (parser->do_loop_stack.top & 0x7u) |
        ((uint32_t) (parser->accepts_block_stack.top & 0x7u) << 3) |
        ((uint32_t) parser->in_keyword_arg << 6) |
        ((uint32_t) parser->in_endless_def_body << 7) |
        ((uint32_t) parser->pattern_matching_newlines << 8) |
        ((uint32_t) (parser->lambda_enclosure_nesting >= 0) << 9);
    if (mode_flags != state->prev_state_flags) {
        FUZZ_IJON_SET(mode_flags);
        state->prev_state_flags = mode_flags;
    }

    // 4. Scope parameter, closed, and shareable_constant flags across current and enclosing scope.
    if (parser->current_scope != NULL && (parser->current_scope->parameters != 0 || parser->current_scope->shareable_constant != 0)) {
        uint32_t cur_scope = ((uint32_t) parser->current_scope->parameters & 0x7fu) |
            ((uint32_t) parser->current_scope->closed << 7);
        uint32_t prev_scope = parser->current_scope->previous != NULL
            ? (((uint32_t) parser->current_scope->previous->parameters & 0x7fu) |
               ((uint32_t) parser->current_scope->previous->closed << 7))
            : 0;
        uint32_t scope_sig = ((uint32_t) parser->current_scope->shareable_constant << 16) |
            (cur_scope << 8) | prev_scope;
        if (scope_sig != state->prev_scope_sig) {
            FUZZ_IJON_SET(scope_sig);
            state->prev_scope_sig = scope_sig;
        }
    }

    // 5. Syntax error and recovery across active context and top lex mode.
    size_t error_count = parser->error_list.size;
    if (error_count != state->prev_error_count || parser->recovering) {
        state->prev_error_count = error_count;
        uint32_t rec_sig = ((uint32_t) parser->recovering << 10) | (cur_ctx << 4) | (lex_mode_sig & 0x0fu);
        FUZZ_IJON_SET(rec_sig);
    }
}
#endif

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
#ifdef PRISM_FUZZ_IJON
    fuzz_ijon_state_t ijon_state = { 0 };
    pm_parser_lex_callback_set(parser, fuzz_ijon_lex_callback, &ijon_state);
#endif
    pm_node_t *node = pm_parse(parser);

    pm_visit_node(node, check_node_location, &size);

#ifdef SLOW
    pm_buffer_t *buffer = pm_buffer_new();

    pm_serialize(parser, node, buffer);
    pm_buffer_clear(buffer);

    if (parser->error_list.size > 0) {
        (void) pm_errors_format(parser, buffer, PM_ERRORS_FORMAT_PLAIN);
        pm_buffer_clear(buffer);
        (void) pm_errors_format(parser, buffer, PM_ERRORS_FORMAT_COLOR);
        pm_buffer_clear(buffer);
    }

    pm_prettyprint(buffer, parser, node);
    pm_buffer_clear(buffer);

    pm_dump_json(buffer, parser, node);
    pm_buffer_free(buffer);
#endif

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
    };

    harness_parse(input + 4, size - 4, &opts);
}

