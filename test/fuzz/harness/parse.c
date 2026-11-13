#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <prism.h>
#if defined(SLOW) && !defined(PRISM_FUZZ_NO_INTERNAL_BUFFER)
#include "prism/internal/buffer.h"
#endif
#ifdef PRISM_FUZZ_IJON
#include "prism/internal/parser.h"
#endif
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef PRISM_FUZZ_LEGACY_VISIT_BOOL
typedef bool pm_visit_result_t;
#define PM_VISIT_DESCEND true
#define PM_VISIT_SKIP false
#endif

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

#if (!defined(PRISM_FUZZ_IJON) || defined(SLOW)) && !defined(PRISM_FUZZ_NO_STREAM)
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

static inline void fuzz_string_view_init(pm_string_t *str, const uint8_t *buf, size_t len) {
#ifdef PRISM_FUZZ_LEGACY_STRING_INIT
    pm_string_constant_init(str, (const char *) buf, len);
#else
    pm_string_init(str, buf, len);
#endif
}

#ifndef PRISM_FUZZ_NO_SHEBANG_CALLBACK
static void fuzz_shebang_cb(pm_options_t *options, const uint8_t *source, size_t length, void *shebang_data) {
    (void) options;
    (void) source;
    (void) length;
    (void) shebang_data;
}
#endif

static inline const char *fuzz_node_type_name(pm_node_type_t type) {
#ifdef PRISM_FUZZ_NODE_TYPE_TO_STR
    return pm_node_type_to_str(type);
#else
    return pm_node_type(type);
#endif
}

typedef struct {
    uint32_t start;
    uint32_t length;
} fuzz_span_t;

static inline fuzz_span_t fuzz_loc_span(pm_location_t loc, const uint8_t *source) {
#ifdef PRISM_FUZZ_POINTER_LOCATIONS
    if (loc.start == NULL && loc.end == NULL) {
        return (fuzz_span_t) { .start = 0, .length = 0 };
    }
    if (loc.start == NULL || loc.end == NULL || (uintptr_t) loc.start < (uintptr_t) source) {
        return (fuzz_span_t) { .start = UINT32_MAX, .length = 0 };
    }
    uintptr_t s_off = (uintptr_t) loc.start - (uintptr_t) source;
    if ((uintptr_t) loc.end < (uintptr_t) loc.start) {
        return (fuzz_span_t) {
            .start = s_off <= UINT32_MAX ? (uint32_t) s_off : UINT32_MAX,
            .length = UINT32_MAX,
        };
    }
    uintptr_t len = (uintptr_t) loc.end - (uintptr_t) loc.start;
    return (fuzz_span_t) {
        .start = s_off <= UINT32_MAX ? (uint32_t) s_off : UINT32_MAX,
        .length = len <= UINT32_MAX ? (uint32_t) len : UINT32_MAX,
    };
#else
    (void) source;
    return (fuzz_span_t) { .start = loc.start, .length = loc.length };
#endif
}

#ifdef PRISM_FUZZ_LEGACY_MAGIC_COMMENT_START
static inline fuzz_span_t fuzz_raw_ptr_span(const uint8_t *start, uint32_t length, const uint8_t *source) {
    if (start == NULL) {
        return (fuzz_span_t) { .start = 0, .length = 0 };
    }
    if ((uintptr_t) start < (uintptr_t) source) {
        return (fuzz_span_t) { .start = UINT32_MAX, .length = length };
    }
    uintptr_t s_off = (uintptr_t) start - (uintptr_t) source;
    return (fuzz_span_t) {
        .start = s_off <= UINT32_MAX ? (uint32_t) s_off : UINT32_MAX,
        .length = length,
    };
}
#endif

static inline const pm_location_t *fuzz_parser_data_loc(const pm_parser_t *parser) {
#ifdef PRISM_FUZZ_LEGACY_PARSER_DATA_LOC
    return &parser->data_loc;
#else
    return pm_parser_data_loc(parser);
#endif
}

static inline pm_location_t fuzz_diag_location(const pm_diagnostic_t *d) {
#ifdef PRISM_FUZZ_LEGACY_DIAG_FIELDS
    return d->location;
#else
    return pm_diagnostic_location(d);
#endif
}

static inline const char *fuzz_diag_type(const pm_diagnostic_t *d) {
#ifdef PRISM_FUZZ_NO_DIAGNOSTIC_TYPE
    (void) d;
    return "diag";
#else
    return pm_diagnostic_type(d);
#endif
}

static inline unsigned fuzz_diag_error_level(const pm_diagnostic_t *d) {
#ifdef PRISM_FUZZ_LEGACY_DIAG_FIELDS
    return (unsigned) d->level;
#else
    return (unsigned) pm_diagnostic_error_level(d);
#endif
}

static inline unsigned fuzz_diag_warning_level(const pm_diagnostic_t *d) {
#ifdef PRISM_FUZZ_LEGACY_DIAG_FIELDS
    return (unsigned) d->level;
#else
    return (unsigned) pm_diagnostic_warning_level(d);
#endif
}

static inline pm_location_t fuzz_comment_location(const pm_comment_t *c) {
#ifdef PRISM_FUZZ_LEGACY_COMMENT_FIELDS
    return c->location;
#else
    return pm_comment_location(c);
#endif
}

static inline int fuzz_comment_type(const pm_comment_t *c) {
#ifdef PRISM_FUZZ_LEGACY_COMMENT_FIELDS
    return (int) c->type;
#else
    return (int) pm_comment_type(c);
#endif
}

static inline fuzz_span_t fuzz_magic_comment_key_span(const pm_magic_comment_t *mc, const uint8_t *source) {
#ifdef PRISM_FUZZ_LEGACY_MAGIC_COMMENT_START
    return fuzz_raw_ptr_span(mc->key_start, mc->key_length, source);
#elif defined(PRISM_FUZZ_LEGACY_MAGIC_COMMENT_FIELDS)
    return fuzz_loc_span(mc->key, source);
#else
    return fuzz_loc_span(pm_magic_comment_key(mc), source);
#endif
}

static inline fuzz_span_t fuzz_magic_comment_value_span(const pm_magic_comment_t *mc, const uint8_t *source) {
#ifdef PRISM_FUZZ_LEGACY_MAGIC_COMMENT_START
    return fuzz_raw_ptr_span(mc->value_start, mc->value_length, source);
#elif defined(PRISM_FUZZ_LEGACY_MAGIC_COMMENT_FIELDS)
    return fuzz_loc_span(mc->value, source);
#else
    return fuzz_loc_span(pm_magic_comment_value(mc), source);
#endif
}

#ifndef PRISM_DEPTH_MAXIMUM
#define PRISM_DEPTH_MAXIMUM 10000
#endif
#define FUZZ_MAX_NON_ITER_DEPTH ((size_t) (PRISM_DEPTH_MAXIMUM) * 2u + 64u)

typedef struct {
    const uint8_t *source;
    size_t parsed_size;
    pm_node_type_t parent_type;
    pm_parser_t *parser;
    size_t depth;
} fuzz_node_check_t;

typedef struct {
    const uint8_t *source;
    size_t parsed_size;
} fuzz_diag_check_ctx_t;

#ifndef PRISM_FUZZ_NO_VISIT_NODE
typedef struct {
    const uint8_t *source;
    size_t parsed_size;
    uint32_t probe;
    const char *ctx;
} fuzz_line_offset_ctx_t;
#endif

__attribute__((noreturn, noinline, format(printf, 1, 2)))
static void fuzz_invariant_fail(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
    abort();
}

static bool fuzz_loc_in_bounds(fuzz_span_t loc, size_t parsed_size) {
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

#ifndef PRISM_FUZZ_NO_VISIT_NODE
static bool fuzz_heredoc_span_contains(
    const uint8_t *source,
    size_t parsed_size,
    pm_location_t opening_pm_loc,
    pm_location_t closing_pm_loc,
    uint32_t probe
) {
    fuzz_span_t opening_loc = fuzz_loc_span(opening_pm_loc, source);
    fuzz_span_t closing_loc = fuzz_loc_span(closing_pm_loc, source);
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
    fuzz_span_t node_loc = fuzz_loc_span(node->location, st->source);
    bool in_node_loc = fuzz_loc_in_bounds(node_loc, st->parsed_size) &&
        st->probe >= node_loc.start &&
        (size_t) st->probe <= (size_t) node_loc.start + (size_t) node_loc.length;

    switch (PM_NODE_TYPE(node)) {
        case PM_STRING_NODE: {
            const pm_string_node_t *cast = (const pm_string_node_t *) node;
            if (fuzz_heredoc_span_contains(st->source, st->parsed_size, cast->opening_loc, cast->closing_loc, st->probe)) {
                st->ctx = "heredoc";
            } else if (in_node_loc) {
                st->ctx = fuzz_node_type_name(node->type);
            }
            break;
        }
        case PM_INTERPOLATED_STRING_NODE: {
            const pm_interpolated_string_node_t *cast = (const pm_interpolated_string_node_t *) node;
            if (fuzz_heredoc_span_contains(st->source, st->parsed_size, cast->opening_loc, cast->closing_loc, st->probe)) {
                st->ctx = "heredoc";
            } else if (in_node_loc) {
                st->ctx = fuzz_node_type_name(node->type);
            }
            break;
        }
        case PM_X_STRING_NODE: {
            const pm_x_string_node_t *cast = (const pm_x_string_node_t *) node;
            if (fuzz_heredoc_span_contains(st->source, st->parsed_size, cast->opening_loc, cast->closing_loc, st->probe)) {
                st->ctx = "heredoc";
            } else if (in_node_loc) {
                st->ctx = fuzz_node_type_name(node->type);
            }
            break;
        }
        case PM_INTERPOLATED_X_STRING_NODE: {
            const pm_interpolated_x_string_node_t *cast = (const pm_interpolated_x_string_node_t *) node;
            if (fuzz_heredoc_span_contains(st->source, st->parsed_size, cast->opening_loc, cast->closing_loc, st->probe)) {
                st->ctx = "heredoc";
            } else if (in_node_loc) {
                st->ctx = fuzz_node_type_name(node->type);
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
                st->ctx = fuzz_node_type_name(node->type);
            }
            break;
        case PM_ARRAY_NODE: {
            const pm_array_node_t *cast = (const pm_array_node_t *) node;
            fuzz_span_t open_loc = fuzz_loc_span(cast->opening_loc, st->source);
            if (in_node_loc && open_loc.length >= 2 &&
                fuzz_loc_in_bounds(open_loc, st->parsed_size) &&
                st->source[open_loc.start] == '%') {
                st->ctx = "percent_array";
            }
            break;
        }
        default:
            break;
    }

    return PM_VISIT_DESCEND;
}
#endif

typedef struct {
    const uint8_t *source;
    size_t parsed_size;
    uint32_t probe;
    const char *found;
} fuzz_line_offset_comment_ctx_t;

static void fuzz_line_offset_check_comment(const pm_comment_t *c, void *data) {
    fuzz_line_offset_comment_ctx_t *st = (fuzz_line_offset_comment_ctx_t *) data;
    if (st->found != NULL) return;
    fuzz_span_t loc = fuzz_loc_span(fuzz_comment_location(c), st->source);
    if (fuzz_loc_in_bounds(loc, st->parsed_size) &&
        st->probe >= loc.start &&
        (size_t) st->probe <= (size_t) loc.start + (size_t) loc.length) {
        st->found = fuzz_comment_type(c) == PM_COMMENT_EMBDOC ? "embdoc" : "inline_comment";
    }
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

    fuzz_span_t data_loc = fuzz_loc_span(*fuzz_parser_data_loc(parser), source);
    if (data_loc.length > 0 && fuzz_loc_in_bounds(data_loc, parsed_size) &&
        probe >= data_loc.start &&
        (size_t) probe <= (size_t) data_loc.start + (size_t) data_loc.length) {
        return "data";
    }

    fuzz_line_offset_comment_ctx_t comment_ctx = {
        .source = source,
        .parsed_size = parsed_size,
        .probe = probe,
        .found = NULL,
    };
#ifdef PRISM_FUZZ_LIST_ITERATORS
    for (const pm_comment_t *c = (const pm_comment_t *) parser->comment_list.head; c != NULL && comment_ctx.found == NULL; c = (const pm_comment_t *) c->node.next) {
        fuzz_line_offset_check_comment(c, &comment_ctx);
    }
#elif defined(PRISM_FUZZ_ITER_OBJS)
    {
        pm_comments_iter_t *c_iter = pm_parser_comments(parser);
        for (const pm_comment_t *c = pm_comments_iter_next(c_iter); c != NULL && comment_ctx.found == NULL; c = pm_comments_iter_next(c_iter)) {
            fuzz_line_offset_check_comment(c, &comment_ctx);
        }
        pm_comments_iter_free(c_iter);
    }
#elif defined(PRISM_FUZZ_EACH_ITERATORS)
    pm_parser_comments_each(parser, fuzz_line_offset_check_comment, &comment_ctx);
#else
    for (const pm_comment_t *c = pm_parser_comments_first(parser); c != NULL && comment_ctx.found == NULL; c = pm_comment_next(c)) {
        fuzz_line_offset_check_comment(c, &comment_ctx);
    }
#endif
    if (comment_ctx.found != NULL) {
        return comment_ctx.found;
    }

#ifdef PRISM_FUZZ_NO_VISIT_NODE
    (void) root;
    return "default";
#else
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
#endif
}

typedef struct {
    const uint8_t *source;
    size_t parsed_size;
    bool check_order;
    uint32_t prev_start;
    const char *prev_type;
    bool first;
} fuzz_comment_check_state_t;

static void fuzz_check_error_diag(const pm_diagnostic_t *d, void *data) {
    const fuzz_diag_check_ctx_t *ctx = (const fuzz_diag_check_ctx_t *) data;
    fuzz_span_t loc = fuzz_loc_span(fuzz_diag_location(d), ctx->source);
    const char *kind = fuzz_span_violation_kind(loc.start, loc.length, ctx->parsed_size);
    if (kind != NULL) {
        const char *diag_type = fuzz_diag_type(d);
        fuzz_invariant_fail(
            "INVARIANT[diagnostic]: list=error type=%s kind=%s [detail: level=%u start=%u length=%u parsed_size=%zu]\n",
            diag_type[0] != '\0' ? diag_type : "unknown",
            kind,
            fuzz_diag_error_level(d),
            loc.start,
            loc.length,
            ctx->parsed_size
        );
    }

#ifndef PRISM_FUZZ_NO_DIAGNOSTIC_TYPE
    const char *diag_type = fuzz_diag_type(d);
    if (diag_type != NULL) {
        if (strcmp(diag_type, "mixed_encoding") == 0) {
            if (loc.length == 0) {
                fuzz_invariant_fail(
                    "INVARIANT[diagnostic_semantic]: type=mixed_encoding kind=zero_length [detail: level=%u start=%u length=%u parsed_size=%zu]\n",
                    fuzz_diag_error_level(d),
                    loc.start,
                    loc.length,
                    ctx->parsed_size
                );
            }
            bool has_non_ascii_or_escape = false;
            for (uint32_t i = 0; i < loc.length; i++) {
                uint8_t byte = ctx->source[loc.start + i];
                if (byte >= 0x80 || byte == '\\') {
                    has_non_ascii_or_escape = true;
                    break;
                }
            }
            if (!has_non_ascii_or_escape) {
                fuzz_invariant_fail(
                    "INVARIANT[diagnostic_semantic]: type=mixed_encoding kind=wrong_byte [detail: level=%u byte=0x%02x start=%u length=%u parsed_size=%zu]\n",
                    fuzz_diag_error_level(d),
                    (unsigned) ctx->source[loc.start],
                    loc.start,
                    loc.length,
                    ctx->parsed_size
                );
            }
        } else if (strcmp(diag_type, "escape_invalid_unicode_literal") == 0 && loc.length == 0) {
            fuzz_invariant_fail(
                "INVARIANT[diagnostic_semantic]: type=escape_invalid_unicode_literal kind=zero_length [detail: level=%u start=%u length=%u parsed_size=%zu]\n",
                fuzz_diag_error_level(d),
                loc.start,
                loc.length,
                ctx->parsed_size
            );
        }
    }
#endif
}

static void fuzz_check_warning_diag(const pm_diagnostic_t *d, void *data) {
    const fuzz_diag_check_ctx_t *ctx = (const fuzz_diag_check_ctx_t *) data;
    fuzz_span_t loc = fuzz_loc_span(fuzz_diag_location(d), ctx->source);
    const char *kind = fuzz_span_violation_kind(loc.start, loc.length, ctx->parsed_size);
    if (kind != NULL) {
        const char *diag_type = fuzz_diag_type(d);
        fuzz_invariant_fail(
            "INVARIANT[diagnostic]: list=warning type=%s kind=%s [detail: level=%u start=%u length=%u parsed_size=%zu]\n",
            diag_type[0] != '\0' ? diag_type : "unknown",
            kind,
            fuzz_diag_warning_level(d),
            loc.start,
            loc.length,
            ctx->parsed_size
        );
    }
}

static void fuzz_check_comment(const pm_comment_t *c, void *data) {
    fuzz_comment_check_state_t *st = (fuzz_comment_check_state_t *) data;
    fuzz_span_t loc = fuzz_loc_span(fuzz_comment_location(c), st->source);
    const char *comment_type = fuzz_comment_type(c) == PM_COMMENT_EMBDOC ? "embdoc" : "inline";
    const char *kind = fuzz_span_violation_kind(loc.start, loc.length, st->parsed_size);
    if (kind != NULL) {
        fuzz_invariant_fail(
            "INVARIANT[comment]: type=%s kind=%s [detail: start=%u length=%u parsed_size=%zu]\n",
            comment_type,
            kind,
            loc.start,
            loc.length,
            st->parsed_size
        );
    }
    if (st->check_order && !st->first && loc.start < st->prev_start) {
        fuzz_invariant_fail(
            "INVARIANT[comment]: type=%s prev_type=%s kind=unsorted [detail: prev_start=%u start=%u parsed_size=%zu]\n",
            comment_type,
            st->prev_type,
            st->prev_start,
            loc.start,
            st->parsed_size
        );
    }
    st->prev_start = loc.start;
    st->prev_type = comment_type;
    st->first = false;
}

static void fuzz_check_magic_comment(const pm_magic_comment_t *mc, void *data) {
    const fuzz_diag_check_ctx_t *ctx = (const fuzz_diag_check_ctx_t *) data;
    fuzz_span_t k = fuzz_magic_comment_key_span(mc, ctx->source);
    const char *k_kind = fuzz_span_violation_kind(k.start, k.length, ctx->parsed_size);
    if (k_kind != NULL) {
        fuzz_invariant_fail(
            "INVARIANT[magic_comment]: field=key kind=%s [detail: start=%u length=%u parsed_size=%zu]\n",
            k_kind,
            k.start,
            k.length,
            ctx->parsed_size
        );
    }
    fuzz_span_t v = fuzz_magic_comment_value_span(mc, ctx->source);
    const char *v_kind = fuzz_span_violation_kind(v.start, v.length, ctx->parsed_size);
    if (v_kind != NULL) {
        fuzz_invariant_fail(
            "INVARIANT[magic_comment]: field=value kind=%s [detail: start=%u length=%u parsed_size=%zu]\n",
            v_kind,
            v.start,
            v.length,
            ctx->parsed_size
        );
    }
}

static inline const char *fuzz_safe_node_name(pm_node_type_t type) {
    const char *name = fuzz_node_type_name(type);
    return (name != NULL && name[0] != '\0') ? name : "UNKNOWN";
}

#if !defined(PRISM_FUZZ_NO_VISIT_NODE) && !defined(PRISM_FUZZ_POINTER_LOCATIONS) && !defined(PRISM_FUZZ_NO_NODE_RELATIONS)
static void fuzz_check_node_list_relations(
    const pm_node_t *parent,
    fuzz_span_t parent_loc,
    pm_location_t opening_loc,
    pm_location_t closing_loc,
    const pm_node_list_t *list,
    const fuzz_node_check_t *ctx
) {
    fuzz_span_t opening = fuzz_loc_span(opening_loc, ctx->source);
    fuzz_span_t closing = fuzz_loc_span(closing_loc, ctx->source);
    bool opening_valid = opening.length > 0 && fuzz_span_violation_kind(opening.start, opening.length, ctx->parsed_size) == NULL;
    bool closing_valid = closing.length > 0 && fuzz_span_violation_kind(closing.start, closing.length, ctx->parsed_size) == NULL;
    bool is_heredoc = opening_valid && opening.length >= 2 && ctx->source[opening.start] == '<' && ctx->source[opening.start + 1] == '<';
    const char *parent_name = fuzz_safe_node_name(parent->type);
    uint64_t pend = (uint64_t) parent_loc.start + (uint64_t) parent_loc.length;
    uint64_t opening_end = (uint64_t) opening.start + (uint64_t) opening.length;

    bool has_prev = false;
    uint32_t prev_start = 0;
    uint32_t prev_len = 0;
    uint64_t prev_end = 0;

    for (size_t i = 0; i < list->size; i++) {
        const pm_node_t *child = list->nodes[i];
        if (child == NULL) continue;

        fuzz_span_t cloc = fuzz_loc_span(child->location, ctx->source);
        if (fuzz_span_violation_kind(cloc.start, cloc.length, ctx->parsed_size) != NULL) {
            continue;
        }

        const char *child_name = fuzz_safe_node_name(child->type);
        uint64_t cend = (uint64_t) cloc.start + (uint64_t) cloc.length;

        if (has_prev && (uint64_t) cloc.start < prev_end) {
            const char *kind = (cloc.start == prev_start && cloc.length == prev_len && prev_len > 0)
                ? "duplicate_part"
                : "sibling_overlap";
            fuzz_invariant_fail(
                "INVARIANT[node_relation]: parent=%s child=%s kind=%s [detail: idx=%zu prev_start=%u prev_len=%u start=%u len=%u]\n",
                parent_name,
                child_name,
                kind,
                i,
                prev_start,
                prev_len,
                cloc.start,
                cloc.length
            );
        }

        if (!is_heredoc) {
            if (cloc.start < parent_loc.start) {
                fuzz_invariant_fail(
                    "INVARIANT[node_relation]: parent=%s child=%s kind=start_after_child [detail: idx=%zu parent_start=%u child_start=%u]\n",
                    parent_name,
                    child_name,
                    i,
                    parent_loc.start,
                    cloc.start
                );
            }
            if (cend > pend) {
                fuzz_invariant_fail(
                    "INVARIANT[node_relation]: parent=%s child=%s kind=child_oob [detail: idx=%zu parent_end=%llu child_end=%llu]\n",
                    parent_name,
                    child_name,
                    i,
                    (unsigned long long) pend,
                    (unsigned long long) cend
                );
            }
            if (opening_valid && (uint64_t) cloc.start < opening_end) {
                fuzz_invariant_fail(
                    "INVARIANT[node_relation]: parent=%s child=%s kind=child_before_opening [detail: idx=%zu opening_end=%llu child_start=%u]\n",
                    parent_name,
                    child_name,
                    i,
                    (unsigned long long) opening_end,
                    cloc.start
                );
            }
            if (closing_valid && cend > (uint64_t) closing.start) {
                fuzz_invariant_fail(
                    "INVARIANT[node_relation]: parent=%s child=%s kind=child_after_closing [detail: idx=%zu closing_start=%u child_end=%llu]\n",
                    parent_name,
                    child_name,
                    i,
                    closing.start,
                    (unsigned long long) cend
                );
            }
        }

        has_prev = true;
        prev_start = cloc.start;
        prev_len = cloc.length;
        prev_end = cend;
    }
}

static void fuzz_check_node_relations(const pm_node_t *node, fuzz_span_t loc, const fuzz_node_check_t *ctx) {
    switch (node->type) {
        case PM_ARRAY_NODE: {
            const pm_array_node_t *arr = (const pm_array_node_t *) node;
            fuzz_check_node_list_relations(node, loc, arr->opening_loc, arr->closing_loc, &arr->elements, ctx);
            break;
        }
        case PM_INTERPOLATED_SYMBOL_NODE: {
            const pm_interpolated_symbol_node_t *sym = (const pm_interpolated_symbol_node_t *) node;
            fuzz_check_node_list_relations(node, loc, sym->opening_loc, sym->closing_loc, &sym->parts, ctx);
            break;
        }
        case PM_INTERPOLATED_STRING_NODE: {
            const pm_interpolated_string_node_t *str = (const pm_interpolated_string_node_t *) node;
            fuzz_check_node_list_relations(node, loc, str->opening_loc, str->closing_loc, &str->parts, ctx);
            break;
        }
        case PM_INTERPOLATED_X_STRING_NODE: {
            const pm_interpolated_x_string_node_t *xstr = (const pm_interpolated_x_string_node_t *) node;
            fuzz_check_node_list_relations(node, loc, xstr->opening_loc, xstr->closing_loc, &xstr->parts, ctx);
            break;
        }
        case PM_INTERPOLATED_REGULAR_EXPRESSION_NODE: {
            const pm_interpolated_regular_expression_node_t *re = (const pm_interpolated_regular_expression_node_t *) node;
            fuzz_check_node_list_relations(node, loc, re->opening_loc, re->closing_loc, &re->parts, ctx);
            break;
        }
        default:
            break;
    }
}
#endif

static void fuzz_for_each_error_diag(pm_parser_t *parser, void (*fn)(const pm_diagnostic_t *, void *), void *ctx) {
#ifdef PRISM_FUZZ_LIST_ITERATORS
    for (const pm_diagnostic_t *d = (const pm_diagnostic_t *) parser->error_list.head; d != NULL; d = (const pm_diagnostic_t *) d->node.next) {
        fn(d, ctx);
    }
#elif defined(PRISM_FUZZ_ITER_OBJS)
    pm_diagnostics_iter_t *err_iter = pm_parser_errors(parser);
    for (const pm_diagnostic_t *d = pm_diagnostics_iter_next(err_iter); d != NULL; d = pm_diagnostics_iter_next(err_iter)) {
        fn(d, ctx);
    }
    pm_diagnostics_iter_free(err_iter);
#elif defined(PRISM_FUZZ_EACH_ITERATORS)
    pm_parser_errors_each(parser, fn, ctx);
#else
    for (const pm_diagnostic_t *d = pm_parser_errors_first(parser); d != NULL; d = pm_diagnostic_next(d)) {
        fn(d, ctx);
    }
#endif
}

#if !defined(PRISM_FUZZ_NO_VISIT_NODE) && !defined(PRISM_FUZZ_NO_DIAGNOSTIC_TYPE) && !defined(PRISM_FUZZ_NO_NODE_RELATIONS)
static bool fuzz_is_iterative_chain_node(pm_node_type_t parent, pm_node_type_t child) {
    if (parent != child) return false;
    switch (child) {
        case PM_CALL_NODE:
        case PM_AND_NODE:
        case PM_OR_NODE:
        case PM_CONSTANT_PATH_NODE:
        case PM_IF_NODE:
        case PM_RESCUE_NODE:
            return true;
        default:
            return false;
    }
}

static void fuzz_check_depth_or_stack_cb(const pm_diagnostic_t *d, void *data) {
    bool *found = (bool *) data;
    if (*found) return;
    const char *diag_type = fuzz_diag_type(d);
    if (diag_type != NULL && (strcmp(diag_type, "nesting_too_deep") == 0 || strcmp(diag_type, "stack_exhausted") == 0)) {
        *found = true;
    }
}

static bool fuzz_parser_has_depth_or_stack_error(pm_parser_t *parser) {
    bool found = false;
    fuzz_for_each_error_diag(parser, fuzz_check_depth_or_stack_cb, &found);
    return found;
}
#endif

static pm_visit_result_t check_node_location(const pm_node_t *node, void *data) {
    const fuzz_node_check_t *ctx = (const fuzz_node_check_t *) data;
    fuzz_span_t loc = fuzz_loc_span(node->location, ctx->source);
    const char *kind = fuzz_span_violation_kind(loc.start, loc.length, ctx->parsed_size);
    if (kind != NULL) {
        const char *type_name = fuzz_safe_node_name(node->type);
        const char *parent_name = ctx->parent_type == 0 ? "ROOT" : fuzz_safe_node_name(ctx->parent_type);
        fuzz_invariant_fail(
            "INVARIANT[node_location]: type=%s kind=%s [detail: parent=%s start=%u length=%u parsed_size=%zu]\n",
            type_name,
            kind,
            parent_name,
            loc.start,
            loc.length,
            ctx->parsed_size
        );
    }

#ifdef PRISM_FUZZ_NO_VISIT_NODE
    (void) node;
    (void) ctx;
#else
#if !defined(PRISM_FUZZ_POINTER_LOCATIONS) && !defined(PRISM_FUZZ_NO_NODE_RELATIONS)
    fuzz_check_node_relations(node, loc, ctx);
#endif
#if !defined(PRISM_FUZZ_NO_DIAGNOSTIC_TYPE) && !defined(PRISM_FUZZ_NO_NODE_RELATIONS)
    size_t cur_depth = ctx->depth + (fuzz_is_iterative_chain_node(ctx->parent_type, node->type) ? 0u : 1u);
    if (cur_depth > FUZZ_MAX_NON_ITER_DEPTH && ctx->parser != NULL && !fuzz_parser_has_depth_or_stack_error(ctx->parser)) {
        fuzz_invariant_fail(
            "INVARIANT[recursion_depth]: type=%s kind=depth_exceeded [detail: depth=%zu limit=%zu max=%u]\n",
            fuzz_safe_node_name(node->type),
            cur_depth,
            (size_t) FUZZ_MAX_NON_ITER_DEPTH,
            (unsigned) (PRISM_DEPTH_MAXIMUM)
        );
    }
#else
    size_t cur_depth = ctx->depth + 1u;
#endif
    fuzz_node_check_t child_ctx = {
        .source = ctx->source,
        .parsed_size = ctx->parsed_size,
        .parent_type = node->type,
        .parser = ctx->parser,
        .depth = cur_depth,
    };
    pm_visit_child_nodes(node, check_node_location, &child_ctx);
#endif
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

#ifdef SLOW
static inline void fuzz_buffer_reset(pm_buffer_t *buffer) {
#ifdef PRISM_FUZZ_NO_BUFFER_CLEAR
    buffer->length = 0;
#else
    pm_buffer_clear(buffer);
#endif
}

#if !defined(PRISM_FUZZ_IJON) && !defined(PRISM_FUZZ_NO_STREAM) && !defined(PRISM_FUZZ_NO_STREAM_DIFF) && \
    !defined(PRISM_FUZZ_LEGACY_NO_ARENA) && !defined(PRISM_FUZZ_LEGACY_ARENA_STRUCT) && !defined(PRISM_FUZZ_LEGACY_PARSER_INIT) && \
    !defined(PRISM_FUZZ_LEGACY_PARSER_DATA_LOC) && !defined(PRISM_FUZZ_LEGACY_BUFFER_STRUCT) && !defined(PRISM_FUZZ_NO_PARSER_ERRORS_SIZE)
static void fuzz_check_stream_diff(
    pm_parser_t *parser,
    pm_node_t *node,
    const uint8_t *source_buf,
    size_t size,
    size_t parsed_size,
    const pm_options_t *options,
    pm_buffer_t *stream_buf
) {
    pm_arena_t *ref_arena = pm_arena_new();
    pm_parser_t *ref_parser = pm_parser_new(ref_arena, source_buf, size, options);
    pm_node_t *ref_node = pm_parse(ref_parser);
    pm_buffer_t *ref_buf = pm_buffer_new();

    if ((node == NULL) != (ref_node == NULL)) {
        fuzz_invariant_fail(
            "INVARIANT[stream_diff]: kind=null_node [detail: stream_null=%d full_null=%d parsed_size=%zu size=%zu]\n",
            node == NULL ? 1 : 0,
            ref_node == NULL ? 1 : 0,
            parsed_size,
            size
        );
    }

    if (parsed_size == size) {
        if (node != NULL) {
            pm_serialize(ref_parser, ref_node, ref_buf);
            size_t stream_len = pm_buffer_length(stream_buf);
            size_t ref_len = pm_buffer_length(ref_buf);
            if (stream_len != ref_len || memcmp(pm_buffer_value(stream_buf), pm_buffer_value(ref_buf), stream_len) != 0) {
                fuzz_invariant_fail(
                    "INVARIANT[stream_diff]: kind=serialize_mismatch [detail: parsed_size=%zu size=%zu stream_len=%zu ref_len=%zu]\n",
                    parsed_size,
                    size,
                    stream_len,
                    ref_len
                );
            }
        }
    } else {
        const pm_location_t *stream_data = pm_parser_data_loc(parser);
        const pm_location_t *full_data = pm_parser_data_loc(ref_parser);
        if (stream_data->length == 0) {
            fuzz_invariant_fail(
                "INVARIANT[stream_diff]: kind=spurious_stop [detail: parsed_size=%zu size=%zu]\n",
                parsed_size,
                size
            );
        }
        if (full_data->length == 0 || stream_data->start != full_data->start) {
            fuzz_invariant_fail(
                "INVARIANT[stream_diff]: kind=data_loc_mismatch [detail: stream_start=%u stream_len=%u full_start=%u full_len=%u parsed_size=%zu size=%zu]\n",
                stream_data->start,
                stream_data->length,
                full_data->start,
                full_data->length,
                parsed_size,
                size
            );
        }
        size_t stream_errs = pm_parser_errors_size(parser);
        size_t full_errs = pm_parser_errors_size(ref_parser);
        if (stream_errs != full_errs) {
            fuzz_invariant_fail(
                "INVARIANT[stream_diff]: kind=error_count_mismatch [detail: stream=%zu full=%zu parsed_size=%zu size=%zu]\n",
                stream_errs,
                full_errs,
                parsed_size,
                size
            );
        }
        size_t stream_warns = pm_parser_warnings_size(parser);
        size_t full_warns = pm_parser_warnings_size(ref_parser);
        if (stream_warns != full_warns) {
            fuzz_invariant_fail(
                "INVARIANT[stream_diff]: kind=warning_count_mismatch [detail: stream=%zu full=%zu parsed_size=%zu size=%zu]\n",
                stream_warns,
                full_warns,
                parsed_size,
                size
            );
        }

        if (node != NULL) {
            fuzz_buffer_reset(stream_buf);
            pm_prettyprint(stream_buf, parser, node);
            pm_prettyprint(ref_buf, ref_parser, ref_node);
            size_t stream_pp = pm_buffer_length(stream_buf);
            size_t ref_pp = pm_buffer_length(ref_buf);
            if (stream_pp != ref_pp || memcmp(pm_buffer_value(stream_buf), pm_buffer_value(ref_buf), stream_pp) != 0) {
                fuzz_invariant_fail(
                    "INVARIANT[stream_diff]: kind=ast_mismatch [detail: parsed_size=%zu size=%zu stream_pp=%zu full_pp=%zu]\n",
                    parsed_size,
                    size,
                    stream_pp,
                    ref_pp
                );
            }

            pm_arena_t *prefix_arena = pm_arena_new();
            pm_parser_t *prefix_parser = pm_parser_new(prefix_arena, source_buf, parsed_size, options);
            pm_node_t *prefix_node = pm_parse(prefix_parser);
            fuzz_buffer_reset(stream_buf);
            fuzz_buffer_reset(ref_buf);
            pm_serialize(parser, node, stream_buf);
            pm_serialize(prefix_parser, prefix_node, ref_buf);
            size_t stream_len = pm_buffer_length(stream_buf);
            size_t prefix_len = pm_buffer_length(ref_buf);
            if (stream_len != prefix_len || memcmp(pm_buffer_value(stream_buf), pm_buffer_value(ref_buf), stream_len) != 0) {
                fuzz_invariant_fail(
                    "INVARIANT[stream_diff]: kind=prefix_serialize_mismatch [detail: parsed_size=%zu size=%zu stream_len=%zu prefix_len=%zu]\n",
                    parsed_size,
                    size,
                    stream_len,
                    prefix_len
                );
            }
            pm_parser_free(prefix_parser);
            pm_arena_free(prefix_arena);
        }
    }

    pm_buffer_free(ref_buf);
    pm_parser_free(ref_parser);
    pm_arena_free(ref_arena);
}
#endif
#endif

__attribute__((noinline)) void harness_parse(const uint8_t *input, size_t size, const fuzz_options_t *opts) {
    uint8_t *source = malloc(size);
    if (size > 0) {
        assert(source != NULL);
        memcpy(source, input, size);
    }
    const uint8_t *source_buf = (size == 0 && source == NULL) ? (const uint8_t *) "" : source;

#ifdef PRISM_FUZZ_LEGACY_OPTIONS_STRUCT
    pm_options_t options_storage = { 0 };
    pm_options_t *options = &options_storage;
#else
    pm_options_t *options = pm_options_new();
#endif
    pm_options_line_set(options, opts->start_line);
#ifndef PRISM_FUZZ_NO_COMMAND_LINE
    pm_options_command_line_set(options, opts->cmd_flags);
#endif
#ifndef PRISM_FUZZ_NO_MAIN_SCRIPT
    pm_options_main_script_set(options, opts->main_script);
#endif
#ifndef PRISM_FUZZ_NO_FREEZE
    pm_options_freeze_set(options, opts->freeze);
#endif
#ifndef PRISM_FUZZ_NO_PARTIAL_SCRIPT
    pm_options_partial_script_set(options, opts->partial_script);
#endif
#ifndef PRISM_FUZZ_NO_ATTACH_COMMENTS
    pm_options_attach_comments_set(options, opts->attach_comments);
#endif
#ifndef PRISM_FUZZ_NO_ENCODING_LOCKED
    pm_options_encoding_locked_set(options, opts->encoding_locked);
#endif
#ifndef PRISM_FUZZ_NO_VERSION_SET
    pm_options_version_set(options, opts->version, strlen(opts->version));
#endif

#ifndef PRISM_FUZZ_NO_FROZEN_STRING_LITERAL
    if (opts->has_frozen_string_literal) {
        pm_options_frozen_string_literal_set(options, opts->frozen_string_literal);
    }
#endif

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
#ifndef PRISM_FUZZ_NO_SHEBANG_CALLBACK
        if ((opts->aux_byte & 0x08) != 0) {
            pm_options_shebang_callback_set(options, fuzz_shebang_cb, NULL);
        }
#endif
    }

    if (opts->has_limit_opts) {
        static const int32_t extreme_lines[4] = { INT32_MAX, INT32_MAX - 4, INT32_MIN, 0 };
        pm_options_line_set(options, extreme_lines[(opts->aux_byte >> 4) & 0x03]);
#ifndef PRISM_FUZZ_NO_STACK_BUDGET
        static const size_t budgets[4] = { SIZE_MAX, 0, 512, 4096 };
        pm_options_stack_budget_set(options, budgets[(opts->aux_byte >> 6) & 0x03]);
#endif
    }

    if (opts->scopes_count > 0) {
#ifdef PRISM_FUZZ_VOID_SCOPES_INIT
        pm_options_scopes_init(options, opts->scopes_count);
        bool scopes_ok = true;
#else
        bool scopes_ok = pm_options_scopes_init(options, opts->scopes_count);
#endif
        if (scopes_ok) {
            static const char * const scope_locals[][2] = {
                { "a", "foo" },
                { "b", "it" },
                { "c", "_1" },
            };
#ifndef PRISM_FUZZ_NO_SCOPE_FORWARDING
            size_t forwarding_scope = opts->has_encoding_opts
                ? (size_t) (opts->aux_byte % opts->scopes_count)
                : (size_t) (opts->scopes_count - 1);
#endif

            for (size_t i = 0; i < opts->scopes_count; i++) {
#ifdef PRISM_FUZZ_SCOPE_DIRECT
                pm_options_scope_t *scope = &options->scopes[i];
#elif defined(PRISM_FUZZ_SCOPE_GET_MUT)
                pm_options_scope_t *scope = pm_options_scope_get_mut(options, i);
#else
                pm_options_scope_t *scope = pm_options_scope_mut(options, i);
#endif
                size_t locals_count = (i == 0 && size > 0) ? 3 : 2;
                if (i == 0 && opts->has_encoding_opts && (opts->aux_byte & 0x10) != 0) {
                    locals_count = 0;
                }
                pm_options_scope_init(scope, locals_count);
#ifndef PRISM_FUZZ_NO_SCOPE_FORWARDING
                pm_options_scope_forwarding_set(scope, (i == forwarding_scope) ? opts->forwarding : PM_OPTIONS_SCOPE_FORWARDING_NONE);
#endif

                for (size_t j = 0; j < 2 && j < locals_count; j++) {
                    const char *name = scope_locals[i][j];
#ifdef PRISM_FUZZ_LOCAL_DIRECT
                    pm_string_t *local = &scope->locals[j];
#elif defined(PRISM_FUZZ_LOCAL_GET_MUT)
                    pm_string_t *local = pm_options_scope_local_get_mut(scope, j);
#else
                    pm_string_t *local = pm_options_scope_local_mut(scope, j);
#endif
                    fuzz_string_view_init(local, (const uint8_t *) name, strlen(name));
                }
                if (locals_count == 3) {
                    size_t len = size < 4 ? size : 4;
#ifdef PRISM_FUZZ_LOCAL_DIRECT
                    pm_string_t *local = &scope->locals[2];
#elif defined(PRISM_FUZZ_LOCAL_GET_MUT)
                    pm_string_t *local = pm_options_scope_local_get_mut(scope, 2);
#else
                    pm_string_t *local = pm_options_scope_local_mut(scope, 2);
#endif
                    fuzz_string_view_init(local, source_buf, len);
                }
            }
        }
    }

#ifdef PRISM_FUZZ_LEGACY_ARENA_STRUCT
    pm_arena_t arena_storage = { 0 };
    pm_arena_t *arena = &arena_storage;
#elif !defined(PRISM_FUZZ_LEGACY_NO_ARENA)
    pm_arena_t *arena = pm_arena_new();
#endif
#if !defined(PRISM_FUZZ_IJON) && !defined(PRISM_FUZZ_NO_STREAM)
    pm_source_t *stream_src = NULL;
#endif
#ifdef PRISM_FUZZ_LEGACY_PARSER_INIT
    pm_parser_t parser_storage;
    pm_parser_t *parser = &parser_storage;
#else
    pm_parser_t *parser = NULL;
#endif
    pm_node_t *node = NULL;
    size_t parsed_size = size;

#if !defined(PRISM_FUZZ_IJON) && !defined(PRISM_FUZZ_NO_STREAM)
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
#ifdef PRISM_FUZZ_LEGACY_PARSER_INIT
#ifdef PRISM_FUZZ_PARSER_INIT_ARENA
        pm_parser_init(arena, parser, source_buf, size, options);
#else
        pm_parser_init(parser, source_buf, size, options);
#endif
#else
        parser = pm_parser_new(arena, source_buf, size, options);
#endif
#ifdef PRISM_FUZZ_IJON
        fuzz_ijon_state_t ijon_state = { 0 };
        pm_parser_lex_callback_set(parser, fuzz_ijon_lex_callback, &ijon_state);
#endif
        node = pm_parse(parser);
    }

    // Line offsets must start at 0, be strictly monotonically increasing, and not exceed parsed_size.
#ifdef PRISM_FUZZ_PARSER_NEWLINE_LIST
    const pm_newline_list_t *line_offsets = &parser->newline_list;
#elif defined(PRISM_FUZZ_LEGACY_PARSER_LINE_OFFSETS)
    const pm_line_offset_list_t *line_offsets = &parser->line_offsets;
#else
    const pm_line_offset_list_t *line_offsets = pm_parser_line_offsets(parser);
#endif
    const size_t offset_count = line_offsets->size;
    const int stream_flag = opts->stream_mode ? 1 : 0;
#ifdef PRISM_FUZZ_NO_COMMAND_LINE
    const int cmd_x_flag = 0;
#else
    const int cmd_x_flag = ((opts->cmd_flags & PM_OPTIONS_COMMAND_LINE_X) != 0) ? 1 : 0;
#endif
    if (offset_count == 0) {
        fuzz_invariant_fail(
            "INVARIANT[line_offsets]: kind=empty ctx=default stream=%d cmd_x=%d [detail: parsed_size=%zu]\n",
            stream_flag,
            cmd_x_flag,
            parsed_size
        );
    }
    if (line_offsets->offsets[0] != 0) {
        fuzz_invariant_fail(
            "INVARIANT[line_offsets]: kind=nonzero_start ctx=default stream=%d cmd_x=%d [detail: first=%llu parsed_size=%zu]\n",
            stream_flag,
            cmd_x_flag,
            (unsigned long long) line_offsets->offsets[0],
            parsed_size
        );
    }
    for (size_t i = 1; i < offset_count; i++) {
        uint64_t prev = (uint64_t) line_offsets->offsets[i - 1];
        uint64_t curr = (uint64_t) line_offsets->offsets[i];
        const char *lo_kind = NULL;
        if ((uint64_t) parsed_size < 0x80000000ULL && curr >= 0x80000000ULL) {
            lo_kind = "underflow";
        } else if (curr == prev) {
            lo_kind = "duplicate";
        } else if (curr < prev) {
            lo_kind = "rewind";
        } else if (curr > (uint64_t) parsed_size) {
            lo_kind = "oob";
        }
        if (lo_kind != NULL) {
            const char *lo_ctx = fuzz_line_offset_context(parser, node, source_buf, parsed_size, (uint32_t) curr);
            fuzz_invariant_fail(
                "INVARIANT[line_offsets]: kind=%s ctx=%s stream=%d cmd_x=%d [detail: idx=%zu prev=%llu curr=%llu parsed_size=%zu]\n",
                lo_kind,
                lo_ctx,
                stream_flag,
                cmd_x_flag,
                i,
                (unsigned long long) prev,
                (unsigned long long) curr,
                parsed_size
            );
        }
    }

    fuzz_node_check_t node_check = {
        .source = source_buf,
        .parsed_size = parsed_size,
        .parent_type = 0,
        .parser = parser,
        .depth = 0,
    };
    if (node != NULL) {
#ifdef PRISM_FUZZ_NO_VISIT_NODE
        (void) check_node_location(node, &node_check);
#else
        pm_visit_node(node, check_node_location, &node_check);
#endif
    }

    fuzz_diag_check_ctx_t diag_ctx = {
        .source = source_buf,
        .parsed_size = parsed_size,
    };
    fuzz_for_each_error_diag(parser, fuzz_check_error_diag, &diag_ctx);
#ifdef PRISM_FUZZ_LIST_ITERATORS
    for (const pm_diagnostic_t *d = (const pm_diagnostic_t *) parser->warning_list.head; d != NULL; d = (const pm_diagnostic_t *) d->node.next) {
        fuzz_check_warning_diag(d, &diag_ctx);
    }
#elif defined(PRISM_FUZZ_ITER_OBJS)
    {
        pm_diagnostics_iter_t *warn_iter = pm_parser_warnings(parser);
        for (const pm_diagnostic_t *d = pm_diagnostics_iter_next(warn_iter); d != NULL; d = pm_diagnostics_iter_next(warn_iter)) {
            fuzz_check_warning_diag(d, &diag_ctx);
        }
        pm_diagnostics_iter_free(warn_iter);
    }
#elif defined(PRISM_FUZZ_EACH_ITERATORS)
    pm_parser_warnings_each(parser, fuzz_check_warning_diag, &diag_ctx);
#else
    for (const pm_diagnostic_t *d = pm_parser_warnings_first(parser); d != NULL; d = pm_diagnostic_next(d)) {
        fuzz_check_warning_diag(d, &diag_ctx);
    }
#endif

    fuzz_comment_check_state_t comment_state = {
        .source = source_buf,
        .parsed_size = parsed_size,
#ifdef PRISM_FUZZ_NO_ATTACH_COMMENTS
        .check_order = false,
#else
        .check_order = opts->attach_comments,
#endif
        .prev_start = 0,
        .prev_type = "none",
        .first = true,
    };
#ifdef PRISM_FUZZ_LIST_ITERATORS
    for (const pm_comment_t *c = (const pm_comment_t *) parser->comment_list.head; c != NULL; c = (const pm_comment_t *) c->node.next) {
        fuzz_check_comment(c, &comment_state);
    }
    for (const pm_magic_comment_t *mc = (const pm_magic_comment_t *) parser->magic_comment_list.head; mc != NULL; mc = (const pm_magic_comment_t *) mc->node.next) {
        fuzz_check_magic_comment(mc, &diag_ctx);
    }
#elif defined(PRISM_FUZZ_ITER_OBJS)
    {
        pm_comments_iter_t *c_iter = pm_parser_comments(parser);
        for (const pm_comment_t *c = pm_comments_iter_next(c_iter); c != NULL; c = pm_comments_iter_next(c_iter)) {
            fuzz_check_comment(c, &comment_state);
        }
        pm_comments_iter_free(c_iter);

        pm_magic_comments_iter_t *mc_iter = pm_parser_magic_comments(parser);
        for (const pm_magic_comment_t *mc = pm_magic_comments_iter_next(mc_iter); mc != NULL; mc = pm_magic_comments_iter_next(mc_iter)) {
            fuzz_check_magic_comment(mc, &diag_ctx);
        }
        pm_magic_comments_iter_free(mc_iter);
    }
#elif defined(PRISM_FUZZ_EACH_ITERATORS)
    pm_parser_comments_each(parser, fuzz_check_comment, &comment_state);
    pm_parser_magic_comments_each(parser, fuzz_check_magic_comment, &diag_ctx);
#else
    for (const pm_comment_t *c = pm_parser_comments_first(parser); c != NULL; c = pm_comment_next(c)) {
        fuzz_check_comment(c, &comment_state);
    }
    for (const pm_magic_comment_t *mc = pm_parser_magic_comments_first(parser); mc != NULL; mc = pm_magic_comment_next(mc)) {
        fuzz_check_magic_comment(mc, &diag_ctx);
    }
#endif

#ifdef SLOW
#ifdef PRISM_FUZZ_LEGACY_BUFFER_STRUCT
    pm_buffer_t buffer_storage = { 0 };
    pm_buffer_t *buffer = &buffer_storage;
    pm_buffer_init(buffer);
#else
    pm_buffer_t *buffer = pm_buffer_new();
#endif

    if (node != NULL) {
        pm_serialize(parser, node, buffer);
    }

#if !defined(PRISM_FUZZ_IJON) && !defined(PRISM_FUZZ_NO_STREAM) && !defined(PRISM_FUZZ_NO_STREAM_DIFF) && \
    !defined(PRISM_FUZZ_LEGACY_NO_ARENA) && !defined(PRISM_FUZZ_LEGACY_ARENA_STRUCT) && !defined(PRISM_FUZZ_LEGACY_PARSER_INIT) && \
    !defined(PRISM_FUZZ_LEGACY_PARSER_DATA_LOC) && !defined(PRISM_FUZZ_LEGACY_BUFFER_STRUCT) && !defined(PRISM_FUZZ_NO_PARSER_ERRORS_SIZE)
    if (opts->stream_mode) {
        fuzz_check_stream_diff(parser, node, source_buf, size, parsed_size, options, buffer);
    }
#endif
    fuzz_buffer_reset(buffer);

#ifndef PRISM_FUZZ_NO_STREAM
    if (opts->stream_mode) {
        fuzz_stream_t stream_state2 = {
            .data = source_buf,
            .size = size,
            .pos = 0,
            .eof = false,
        };
        pm_source_t *stream_src2 = pm_source_stream_new(&stream_state2, fuzz_stream_fgets, fuzz_stream_feof);
        pm_serialize_parse_stream(buffer, stream_src2, NULL);
        fuzz_buffer_reset(buffer);
        pm_source_free(stream_src2);
    }
#endif

#ifndef PRISM_FUZZ_NO_ERRORS_FORMAT
#ifdef PRISM_FUZZ_NO_PARSER_ERRORS_SIZE
    if (parser->error_list.size > 0) {
#else
    if (pm_parser_errors_size(parser) > 0) {
#endif
        (void) pm_errors_format(parser, buffer, PM_ERRORS_FORMAT_PLAIN);
        fuzz_buffer_reset(buffer);
        (void) pm_errors_format(parser, buffer, PM_ERRORS_FORMAT_COLOR);
        fuzz_buffer_reset(buffer);
    }
#endif

    if (node != NULL) {
        pm_prettyprint(buffer, parser, node);
        fuzz_buffer_reset(buffer);

#ifndef PRISM_FUZZ_NO_JSON
        pm_dump_json(buffer, parser, node);
#endif
    }

#if defined(PRISM_FUZZ_LEGACY_BUFFER_STRUCT) && defined(PRISM_FUZZ_BUFFER_CLEANUP)
    pm_buffer_cleanup(buffer);
#else
    pm_buffer_free(buffer);
#endif
#endif

#ifdef PRISM_FUZZ_LEGACY_NO_ARENA
    if (node != NULL) {
        pm_node_destroy(parser, node);
    }
#endif
#if defined(PRISM_FUZZ_LEGACY_PARSER_INIT) && defined(PRISM_FUZZ_PARSER_CLEANUP)
    pm_parser_cleanup(parser);
#else
    pm_parser_free(parser);
#endif
#if !defined(PRISM_FUZZ_IJON) && !defined(PRISM_FUZZ_NO_STREAM)
    if (stream_src != NULL) {
        pm_source_free(stream_src);
    }
#endif
#if defined(PRISM_FUZZ_LEGACY_ARENA_STRUCT)
#ifdef PRISM_FUZZ_ARENA_CLEANUP
    pm_arena_cleanup(arena);
#else
    pm_arena_free(arena);
#endif
#elif !defined(PRISM_FUZZ_LEGACY_NO_ARENA)
    pm_arena_free(arena);
#endif
#if defined(PRISM_FUZZ_LEGACY_OPTIONS_STRUCT) && defined(PRISM_FUZZ_OPTIONS_CLEANUP)
    pm_options_cleanup(options);
#else
    pm_options_free(options);
#endif
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
#if defined(PRISM_FUZZ_IJON) || defined(PRISM_FUZZ_NO_STREAM)
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

