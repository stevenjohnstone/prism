#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <prism.h>
#include "prism/internal/buffer.h"
#include "prism/internal/parser.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
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
    bool stream_mode;
    bool has_encoding_opts;
    bool has_limit_opts;
    uint8_t aux_byte;
} fuzz_options_t;

#if !defined(PRISM_FUZZ_IJON) || defined(SLOW)
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
    bool eof;
} fuzz_stream_t;

static char *fuzz_stream_fgets(char *buf, int n, void *vp) {
    fuzz_stream_t *s = (fuzz_stream_t *) vp;
    if (n <= 0) return NULL;
    if (s->pos >= s->size) {
        s->eof = true;
        return NULL;
    }
    size_t count = 0;
    size_t limit = (size_t) (n - 1);
    while (count < limit && s->pos < s->size) {
        uint8_t ch = s->data[s->pos++];
        buf[count++] = (char) ch;
        if (ch == '\n') break;
    }
    if (count < limit && (count == 0 || buf[count - 1] != '\n') && s->pos >= s->size) {
        s->eof = true;
    }
    buf[count] = '\0';
    return buf;
}

static int fuzz_stream_feof(void *vp) {
    return ((const fuzz_stream_t *) vp)->eof ? 1 : 0;
}
#endif

static void fuzz_shebang_cb(pm_options_t *options, const uint8_t *source, size_t length, void *shebang_data) {
    (void) options;
    (void) source;
    (void) length;
    (void) shebang_data;
}

typedef struct {
    size_t parsed_size;
    pm_node_type_t parent_type;
} fuzz_node_check_t;

typedef struct {
    const uint8_t *source;
    size_t parsed_size;
    uint32_t probe;
    const char *ctx;
} fuzz_line_offset_ctx_t;

__attribute__((noreturn, noinline, format(printf, 1, 2)))
static void fuzz_invariant_fail(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
    abort();
}

static bool fuzz_loc_in_bounds(pm_location_t loc, size_t parsed_size) {
    return (size_t) loc.start <= parsed_size && (size_t) loc.length <= parsed_size - (size_t) loc.start;
}

static const char *fuzz_span_violation_kind(uint32_t start, uint32_t length, size_t parsed_size) {
    if ((size_t) start <= parsed_size && (size_t) length <= parsed_size - (size_t) start) {
        return NULL;
    }
    if ((uint64_t) parsed_size < 0x80000000ULL && start >= 0x80000000U) {
        return "start_underflow";
    }
    if (((uint64_t) parsed_size < 0x80000000ULL && length >= 0x80000000U) ||
        (uint64_t) start + (uint64_t) length >= 0x100000000ULL) {
        return "length_underflow";
    }
    if ((size_t) start > parsed_size) {
        return "start_oob";
    }
    return "end_oob";
}

static bool fuzz_heredoc_span_contains(
    const uint8_t *source,
    size_t parsed_size,
    pm_location_t opening_loc,
    pm_location_t closing_loc,
    uint32_t probe
) {
    if (opening_loc.length < 2 || !fuzz_loc_in_bounds(opening_loc, parsed_size)) {
        return false;
    }
    if (memcmp(source + opening_loc.start, "<<", 2) != 0) {
        return false;
    }
    size_t end_offset = parsed_size;
    if (closing_loc.length > 0 && fuzz_loc_in_bounds(closing_loc, parsed_size)) {
        end_offset = (size_t) closing_loc.start + (size_t) closing_loc.length;
    }
    return probe >= opening_loc.start && (size_t) probe <= end_offset;
}

static pm_visit_result_t fuzz_line_offset_visit(const pm_node_t *node, void *data) {
    fuzz_line_offset_ctx_t *st = (fuzz_line_offset_ctx_t *) data;
    bool in_node_loc = fuzz_loc_in_bounds(node->location, st->parsed_size) &&
        st->probe >= node->location.start &&
        (size_t) st->probe <= (size_t) node->location.start + (size_t) node->location.length;

    switch (PM_NODE_TYPE(node)) {
        case PM_STRING_NODE: {
            const pm_string_node_t *cast = (const pm_string_node_t *) node;
            if (fuzz_heredoc_span_contains(st->source, st->parsed_size, cast->opening_loc, cast->closing_loc, st->probe)) {
                st->ctx = "heredoc";
            } else if (in_node_loc) {
                st->ctx = pm_node_type(node->type);
            }
            break;
        }
        case PM_INTERPOLATED_STRING_NODE: {
            const pm_interpolated_string_node_t *cast = (const pm_interpolated_string_node_t *) node;
            if (fuzz_heredoc_span_contains(st->source, st->parsed_size, cast->opening_loc, cast->closing_loc, st->probe)) {
                st->ctx = "heredoc";
            } else if (in_node_loc) {
                st->ctx = pm_node_type(node->type);
            }
            break;
        }
        case PM_X_STRING_NODE: {
            const pm_x_string_node_t *cast = (const pm_x_string_node_t *) node;
            if (fuzz_heredoc_span_contains(st->source, st->parsed_size, cast->opening_loc, cast->closing_loc, st->probe)) {
                st->ctx = "heredoc";
            } else if (in_node_loc) {
                st->ctx = pm_node_type(node->type);
            }
            break;
        }
        case PM_INTERPOLATED_X_STRING_NODE: {
            const pm_interpolated_x_string_node_t *cast = (const pm_interpolated_x_string_node_t *) node;
            if (fuzz_heredoc_span_contains(st->source, st->parsed_size, cast->opening_loc, cast->closing_loc, st->probe)) {
                st->ctx = "heredoc";
            } else if (in_node_loc) {
                st->ctx = pm_node_type(node->type);
            }
            break;
        }
        case PM_SYMBOL_NODE:
        case PM_INTERPOLATED_SYMBOL_NODE:
        case PM_REGULAR_EXPRESSION_NODE:
        case PM_INTERPOLATED_REGULAR_EXPRESSION_NODE:
        case PM_MATCH_LAST_LINE_NODE:
        case PM_INTERPOLATED_MATCH_LAST_LINE_NODE:
            if (in_node_loc) {
                st->ctx = pm_node_type(node->type);
            }
            break;
        case PM_ARRAY_NODE: {
            const pm_array_node_t *cast = (const pm_array_node_t *) node;
            if (in_node_loc && cast->opening_loc.length >= 2 &&
                fuzz_loc_in_bounds(cast->opening_loc, st->parsed_size) &&
                st->source[cast->opening_loc.start] == '%') {
                st->ctx = "percent_array";
            }
            break;
        }
        default:
            break;
    }

    return PM_VISIT_DESCEND;
}

static const char *fuzz_line_offset_context(
    const pm_parser_t *parser,
    const pm_node_t *root,
    const uint8_t *source,
    size_t parsed_size,
    uint32_t offset
) {
    uint32_t probe = (size_t) offset <= parsed_size
        ? (offset > 0 ? offset - 1 : 0)
        : (parsed_size > 0 ? (uint32_t) (parsed_size - 1) : 0);

    if (parser->data_loc.length > 0 && fuzz_loc_in_bounds(parser->data_loc, parsed_size) &&
        probe >= parser->data_loc.start &&
        (size_t) probe <= (size_t) parser->data_loc.start + (size_t) parser->data_loc.length) {
        return "data";
    }

    for (const pm_comment_t *c = pm_parser_comments_first(parser); c != NULL; c = pm_comment_next(c)) {
        pm_location_t loc = pm_comment_location(c);
        if (fuzz_loc_in_bounds(loc, parsed_size) &&
            probe >= loc.start &&
            (size_t) probe <= (size_t) loc.start + (size_t) loc.length) {
            return pm_comment_type(c) == PM_COMMENT_EMBDOC ? "embdoc" : "inline_comment";
        }
    }

    fuzz_line_offset_ctx_t st = {
        .source = source,
        .parsed_size = parsed_size,
        .probe = probe,
        .ctx = "default",
    };
    if (root != NULL) {
        pm_visit_node(root, fuzz_line_offset_visit, &st);
    }
    return st.ctx;
}

static pm_visit_result_t check_node_location(const pm_node_t *node, void *data) {
    const fuzz_node_check_t *ctx = (const fuzz_node_check_t *) data;
    const char *kind = fuzz_span_violation_kind(node->location.start, node->location.length, ctx->parsed_size);
    if (kind != NULL) {
        const char *type_name = pm_node_type(node->type);
        const char *parent_name = ctx->parent_type == 0 ? "ROOT" : pm_node_type(ctx->parent_type);
        fuzz_invariant_fail(
            "INVARIANT[node_location]: type=%s kind=%s [detail: parent=%s start=%u length=%u parsed_size=%zu]\n",
            type_name[0] != '\0' ? type_name : "UNKNOWN",
            kind,
            parent_name[0] != '\0' ? parent_name : "UNKNOWN",
            node->location.start,
            node->location.length,
            ctx->parsed_size
        );
    }

    fuzz_node_check_t child_ctx = {
        .parsed_size = ctx->parsed_size,
        .parent_type = node->type,
    };
    pm_visit_child_nodes(node, check_node_location, &child_ctx);
    return PM_VISIT_SKIP;
}

#ifdef PRISM_FUZZ_IJON
extern void ijon_set(uint32_t addr, uint32_t val);
extern void ijon_max(uint32_t addr, uint64_t val);
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
        ijon_set(loc_hash, fuzz_ijon_mix32(loc_hash ^ (uint32_t) (x)) & 0xfffu); \
    } while (0)

#define FUZZ_IJON_MAX(x) \
    do { \
        static uint32_t loc_hash = 0; \
        if (loc_hash == 0) loc_hash = ijon_hashstr(__LINE__, __FILE__); \
        ijon_max(loc_hash, (uint64_t) (x)); \
    } while (0)

typedef struct {
    uint32_t prev_lex_mode_sig;
    uint32_t prev_ctx_sig;
    uint32_t prev_state_flags;
    uint32_t prev_scope_sig;
    size_t prev_error_count;
    uint32_t max_lex_depth;
    uint32_t max_ctx_depth;
} fuzz_ijon_state_t;

static void fuzz_ijon_lex_callback(pm_parser_t *parser, pm_token_t *token, void *data) {
    (void) token;
    fuzz_ijon_state_t *state = (fuzz_ijon_state_t *) data;

    // 1. Lexer mode stack signature (top 4 modes with delimiter-nesting / heredoc flags) + depth.
    uint32_t lex_mode_sig = 0;
    uint32_t top_lex_nibble = 0;
    uint32_t lex_depth = 0;
    for (const pm_lex_mode_t *m = parser->lex_modes.current; m != NULL && lex_depth < 128; m = m->prev, lex_depth++) {
        if (lex_depth < 4) {
            uint32_t sub = 0;
            switch (m->mode) {
                case PM_LEX_LIST:    sub = (m->as.list.nesting > 0); break;
                case PM_LEX_REGEXP:  sub = (m->as.regexp.nesting > 0); break;
                case PM_LEX_STRING:  sub = (m->as.string.nesting > 0); break;
                case PM_LEX_HEREDOC: sub = (m->as.heredoc.base.indent != PM_HEREDOC_INDENT_NONE); break;
                default: break;
            }
            uint32_t nibble = (((uint32_t) m->mode + 1u) & 0x07u) | (sub << 3);
            if (lex_depth == 0) top_lex_nibble = nibble;
            lex_mode_sig = (lex_mode_sig << 4) | nibble;
        }
    }
    if (lex_depth > 1 && lex_depth > state->max_lex_depth) {
        state->max_lex_depth = lex_depth;
        FUZZ_IJON_MAX(lex_depth);
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

    // 2. Parser context stack signature (current and parent context) + nesting depth.
    uint32_t cur_ctx = parser->current_context != NULL ? (uint32_t) parser->current_context->context : 0;
    uint32_t prev_ctx = (parser->current_context != NULL && parser->current_context->prev != NULL)
        ? (uint32_t) parser->current_context->prev->context
        : 0;
    uint32_t ctx_sig = (cur_ctx << 6) | prev_ctx;
    if (ctx_sig != state->prev_ctx_sig) {
        FUZZ_IJON_SET(ctx_sig);
        state->prev_ctx_sig = ctx_sig;
    }
    uint32_t ctx_depth = 0;
    for (const pm_context_node_t *c = parser->current_context; c != NULL && ctx_depth < 128; c = c->prev) {
        ctx_depth++;
    }
    if (ctx_depth > state->max_ctx_depth) {
        state->max_ctx_depth = ctx_depth;
        FUZZ_IJON_MAX(ctx_depth);
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
        uint32_t rec_sig = ((uint32_t) parser->recovering << 10) | (cur_ctx << 4) | top_lex_nibble;
        FUZZ_IJON_SET(rec_sig);
    }
}
#endif

__attribute__((noinline)) void harness_parse(const uint8_t *input, size_t size, const fuzz_options_t *opts) {
    uint8_t *source = malloc(size);
    if (size > 0) {
        assert(source != NULL);
        memcpy(source, input, size);
    }
    const uint8_t *source_buf = (size == 0 && source == NULL) ? (const uint8_t *) "" : source;

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

    if (opts->has_encoding_opts) {
        static const char * const encodings[8] = {
            "UTF-8",
            "ASCII-8BIT",
            "US-ASCII",
            "Windows-31J",
            "EUC-JP",
            "UTF-8-MAC",
            "ISO-8859-1",
            "Shift_JIS",
        };
        pm_options_encoding_set(options, encodings[opts->aux_byte & 0x07]);
        pm_options_filepath_set(options, "fuzz.rb");
        if ((opts->aux_byte & 0x08) != 0) {
            pm_options_shebang_callback_set(options, fuzz_shebang_cb, NULL);
        }
    }

    if (opts->has_limit_opts) {
        static const int32_t extreme_lines[4] = { INT32_MAX, INT32_MAX - 4, INT32_MIN, 0 };
        static const size_t budgets[4] = { SIZE_MAX, 0, 512, 4096 };
        pm_options_line_set(options, extreme_lines[(opts->aux_byte >> 4) & 0x03]);
        pm_options_stack_budget_set(options, budgets[(opts->aux_byte >> 6) & 0x03]);
    }

    if (opts->scopes_count > 0 && pm_options_scopes_init(options, opts->scopes_count)) {
        static const char * const scope_locals[][2] = {
            { "a", "foo" },
            { "b", "it" },
            { "c", "_1" },
        };
        size_t forwarding_scope = opts->has_encoding_opts
            ? (size_t) (opts->aux_byte % opts->scopes_count)
            : (size_t) (opts->scopes_count - 1);

        for (size_t i = 0; i < opts->scopes_count; i++) {
            pm_options_scope_t *scope = pm_options_scope_mut(options, i);
            size_t locals_count = (i == 0 && size > 0) ? 3 : 2;
            if (i == 0 && opts->has_encoding_opts && (opts->aux_byte & 0x10) != 0) {
                locals_count = 0;
            }
            pm_options_scope_init(scope, locals_count);
            pm_options_scope_forwarding_set(scope, (i == forwarding_scope) ? opts->forwarding : PM_OPTIONS_SCOPE_FORWARDING_NONE);

            for (size_t j = 0; j < 2 && j < locals_count; j++) {
                const char *name = scope_locals[i][j];
                pm_string_init(pm_options_scope_local_mut(scope, j), (const uint8_t *) name, strlen(name));
            }
            if (locals_count == 3) {
                size_t len = size < 4 ? size : 4;
                pm_string_init(pm_options_scope_local_mut(scope, 2), source_buf, len);
            }
        }
    }

    pm_arena_t *arena = pm_arena_new();
#ifndef PRISM_FUZZ_IJON
    pm_source_t *stream_src = NULL;
#endif
    pm_parser_t *parser = NULL;
    pm_node_t *node = NULL;
    size_t parsed_size = size;

#ifndef PRISM_FUZZ_IJON
    if (opts->stream_mode) {
        fuzz_stream_t stream_state = {
            .data = source_buf,
            .size = size,
            .pos = 0,
            .eof = false,
        };
        stream_src = pm_source_stream_new(&stream_state, fuzz_stream_fgets, fuzz_stream_feof);
        node = pm_parse_stream(&parser, arena, stream_src, options);
        parsed_size = pm_source_length(stream_src);
        if (parsed_size > size) {
            fuzz_invariant_fail(
                "INVARIANT[stream]: kind=parsed_size_oob [detail: parsed_size=%zu size=%zu]\n",
                parsed_size,
                size
            );
        }
    } else
#endif
    {
        parser = pm_parser_new(arena, source_buf, size, options);
#ifdef PRISM_FUZZ_IJON
        fuzz_ijon_state_t ijon_state = { 0 };
        pm_parser_lex_callback_set(parser, fuzz_ijon_lex_callback, &ijon_state);
#endif
        node = pm_parse(parser);
    }

    // Line offsets must start at 0, be strictly monotonically increasing, and not exceed parsed_size.
    const size_t offset_count = parser->line_offsets.size;
    const int stream_flag = opts->stream_mode ? 1 : 0;
    const int cmd_x_flag = ((opts->cmd_flags & PM_OPTIONS_COMMAND_LINE_X) != 0) ? 1 : 0;
    if (offset_count == 0) {
        fuzz_invariant_fail(
            "INVARIANT[line_offsets]: kind=empty ctx=default stream=%d cmd_x=%d [detail: parsed_size=%zu]\n",
            stream_flag,
            cmd_x_flag,
            parsed_size
        );
    }
    if (parser->line_offsets.offsets[0] != 0) {
        fuzz_invariant_fail(
            "INVARIANT[line_offsets]: kind=nonzero_start ctx=default stream=%d cmd_x=%d [detail: first=%u parsed_size=%zu]\n",
            stream_flag,
            cmd_x_flag,
            parser->line_offsets.offsets[0],
            parsed_size
        );
    }
    for (size_t i = 1; i < offset_count; i++) {
        uint32_t prev = parser->line_offsets.offsets[i - 1];
        uint32_t curr = parser->line_offsets.offsets[i];
        const char *lo_kind = NULL;
        if ((uint64_t) parsed_size < 0x80000000ULL && curr >= 0x80000000U) {
            lo_kind = "underflow";
        } else if (curr == prev) {
            lo_kind = "duplicate";
        } else if (curr < prev) {
            lo_kind = "rewind";
        } else if ((size_t) curr > parsed_size) {
            lo_kind = "oob";
        }
        if (lo_kind != NULL) {
            const char *lo_ctx = fuzz_line_offset_context(parser, node, source_buf, parsed_size, curr);
            fuzz_invariant_fail(
                "INVARIANT[line_offsets]: kind=%s ctx=%s stream=%d cmd_x=%d [detail: idx=%zu prev=%u curr=%u parsed_size=%zu]\n",
                lo_kind,
                lo_ctx,
                stream_flag,
                cmd_x_flag,
                i,
                prev,
                curr,
                parsed_size
            );
        }
    }

    fuzz_node_check_t node_check = {
        .parsed_size = parsed_size,
        .parent_type = 0,
    };
    pm_visit_node(node, check_node_location, &node_check);

    for (const pm_diagnostic_t *d = pm_parser_errors_first(parser); d != NULL; d = pm_diagnostic_next(d)) {
        pm_location_t loc = pm_diagnostic_location(d);
        const char *kind = fuzz_span_violation_kind(loc.start, loc.length, parsed_size);
        if (kind != NULL) {
            const char *diag_type = pm_diagnostic_type(d);
            fuzz_invariant_fail(
                "INVARIANT[diagnostic]: list=error type=%s kind=%s [detail: level=%u start=%u length=%u parsed_size=%zu]\n",
                diag_type[0] != '\0' ? diag_type : "unknown",
                kind,
                (unsigned) pm_diagnostic_error_level(d),
                loc.start,
                loc.length,
                parsed_size
            );
        }
    }
    for (const pm_diagnostic_t *d = pm_parser_warnings_first(parser); d != NULL; d = pm_diagnostic_next(d)) {
        pm_location_t loc = pm_diagnostic_location(d);
        const char *kind = fuzz_span_violation_kind(loc.start, loc.length, parsed_size);
        if (kind != NULL) {
            const char *diag_type = pm_diagnostic_type(d);
            fuzz_invariant_fail(
                "INVARIANT[diagnostic]: list=warning type=%s kind=%s [detail: level=%u start=%u length=%u parsed_size=%zu]\n",
                diag_type[0] != '\0' ? diag_type : "unknown",
                kind,
                (unsigned) pm_diagnostic_warning_level(d),
                loc.start,
                loc.length,
                parsed_size
            );
        }
    }

    uint32_t prev_comment_start = 0;
    const char *prev_comment_type = "none";
    bool first_comment = true;
    for (const pm_comment_t *c = pm_parser_comments_first(parser); c != NULL; c = pm_comment_next(c)) {
        pm_location_t loc = pm_comment_location(c);
        const char *comment_type = pm_comment_type(c) == PM_COMMENT_EMBDOC ? "embdoc" : "inline";
        const char *kind = fuzz_span_violation_kind(loc.start, loc.length, parsed_size);
        if (kind != NULL) {
            fuzz_invariant_fail(
                "INVARIANT[comment]: type=%s kind=%s [detail: start=%u length=%u parsed_size=%zu]\n",
                comment_type,
                kind,
                loc.start,
                loc.length,
                parsed_size
            );
        }
        if (opts->attach_comments && !first_comment && loc.start < prev_comment_start) {
            fuzz_invariant_fail(
                "INVARIANT[comment]: type=%s prev_type=%s kind=unsorted [detail: prev_start=%u start=%u parsed_size=%zu]\n",
                comment_type,
                prev_comment_type,
                prev_comment_start,
                loc.start,
                parsed_size
            );
        }
        prev_comment_start = loc.start;
        prev_comment_type = comment_type;
        first_comment = false;
    }

    for (const pm_magic_comment_t *mc = pm_parser_magic_comments_first(parser); mc != NULL; mc = pm_magic_comment_next(mc)) {
        pm_location_t k = pm_magic_comment_key(mc);
        const char *k_kind = fuzz_span_violation_kind(k.start, k.length, parsed_size);
        if (k_kind != NULL) {
            fuzz_invariant_fail(
                "INVARIANT[magic_comment]: field=key kind=%s [detail: start=%u length=%u parsed_size=%zu]\n",
                k_kind,
                k.start,
                k.length,
                parsed_size
            );
        }
        pm_location_t v = pm_magic_comment_value(mc);
        const char *v_kind = fuzz_span_violation_kind(v.start, v.length, parsed_size);
        if (v_kind != NULL) {
            fuzz_invariant_fail(
                "INVARIANT[magic_comment]: field=value kind=%s [detail: start=%u length=%u parsed_size=%zu]\n",
                v_kind,
                v.start,
                v.length,
                parsed_size
            );
        }
    }

#ifdef SLOW
    pm_buffer_t *buffer = pm_buffer_new();

    pm_serialize(parser, node, buffer);
    pm_buffer_clear(buffer);

    if (opts->stream_mode) {
        fuzz_stream_t stream_state2 = {
            .data = source_buf,
            .size = size,
            .pos = 0,
            .eof = false,
        };
        pm_source_t *stream_src2 = pm_source_stream_new(&stream_state2, fuzz_stream_fgets, fuzz_stream_feof);
        pm_serialize_parse_stream(buffer, stream_src2, NULL);
        pm_buffer_clear(buffer);
        pm_source_free(stream_src2);
    }

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
#ifndef PRISM_FUZZ_IJON
    if (stream_src != NULL) {
        pm_source_free(stream_src);
    }
#endif
    pm_arena_free(arena);
    pm_options_free(options);
    free(source);
}

__attribute__((noinline)) void harness(const uint8_t *input, size_t size) {
    if (size < 4) return;

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
#ifdef PRISM_FUZZ_IJON
        .stream_mode = false,
#else
        .stream_mode = (opt_flags & 0x40) != 0,
#endif
        .has_encoding_opts = (opt_flags & 0x80) != 0,
        .has_limit_opts = (input[1] & 0x80) != 0,
        .aux_byte = input[3],
    };

    harness_parse(input + 4, size - 4, &opts);
}

