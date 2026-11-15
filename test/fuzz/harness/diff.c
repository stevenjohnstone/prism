#define _POSIX_C_SOURCE 200809L

#include <prism.h>

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ruby.h>

#ifndef FUZZ_MAX_INPUT_SIZE
#define FUZZ_MAX_INPUT_SIZE 1024
#endif

/* CRuby internal helpers in thread.c / vm_dump.c (not exposed in public ruby.h). */
extern void rb_thread_stop_timer_thread(void);
extern void rb_print_backtrace(FILE *errout);

/* TRIAGE_SLICE_BEGIN(diff_core) */
static void diff_invariant_fail(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void diff_invariant_fail(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
    abort();
}

static VALUE diff_warning_warn(int argc, VALUE *argv, VALUE self) {
    (void) argc;
    (void) argv;
    (void) self;
    return Qnil;
}

static bool diff_is_valid_utf8(const uint8_t *s, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t b0 = s[i];
        if (b0 <= 0x7F) {
            i += 1;
        } else if (b0 >= 0xC2 && b0 <= 0xDF) {
            if (i + 2 > len || (s[i + 1] & 0xC0) != 0x80) return false;
            i += 2;
        } else if (b0 == 0xE0) {
            if (i + 3 > len || s[i + 1] < 0xA0 || s[i + 1] > 0xBF || (s[i + 2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if ((b0 >= 0xE1 && b0 <= 0xEC) || (b0 >= 0xEE && b0 <= 0xEF)) {
            if (i + 3 > len || (s[i + 1] & 0xC0) != 0x80 || (s[i + 2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if (b0 == 0xED) {
            if (i + 3 > len || s[i + 1] < 0x80 || s[i + 1] > 0x9F || (s[i + 2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if (b0 == 0xF0) {
            if (i + 4 > len || s[i + 1] < 0x90 || s[i + 1] > 0xBF || (s[i + 2] & 0xC0) != 0x80 || (s[i + 3] & 0xC0) != 0x80) return false;
            i += 4;
        } else if (b0 >= 0xF1 && b0 <= 0xF3) {
            if (i + 4 > len || (s[i + 1] & 0xC0) != 0x80 || (s[i + 2] & 0xC0) != 0x80 || (s[i + 3] & 0xC0) != 0x80) return false;
            i += 4;
        } else if (b0 == 0xF4) {
            if (i + 4 > len || s[i + 1] < 0x80 || s[i + 1] > 0x8F || (s[i + 2] & 0xC0) != 0x80 || (s[i + 3] & 0xC0) != 0x80) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

static bool diff_has_nul(const uint8_t *s, size_t len) {
    return len > 0 && memchr(s, '\0', len) != NULL;
}

static bool diff_starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static void diff_sanitize_ident(const char *src, char *dst, size_t cap, const char *fallback) {
    if (cap == 0) return;
    size_t out = 0;
    if (src != NULL) {
        for (size_t i = 0; src[i] != '\0' && out + 1 < cap; i++) {
            char c = src[i];
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
                dst[out++] = c;
            }
        }
    }
    if (out == 0) {
        snprintf(dst, cap, "%s", fallback);
    } else {
        dst[out] = '\0';
    }
}

static void diff_classify_cruby_msg(const char *cls, const char *line, char *tag_buf, size_t tag_cap) {
    /* RubyVM::InstructionSequence.compile prefixes diagnostics with "<compiled>:<line>: ". */
    if (diff_starts_with(line, "<compiled>:")) {
        const char *p = line + 11;
        if (*p >= '0' && *p <= '9') {
            while (*p >= '0' && *p <= '9') {
                p++;
            }
            if (p[0] == ':' && p[1] == ' ') {
                line = p + 2;
            }
        }
    }

    static const struct {
        const char *prefix;
        const char *tag;
    } prefix_tags[] = {
        { "unknown encoding name:",                        "unknown_encoding" },
        { "invalid multibyte char (UTF-8)",                "invalid_multibyte_utf8" },
        { "invalid multibyte char (US-ASCII)",             "invalid_multibyte_us_ascii" },
        { "invalid multibyte char",                        "invalid_multibyte" },
        { "string literal encodings differ",               "string_encodings_differ" },
        { "invalid symbol",                                "invalid_symbol" },
        { "premature end of char-class",                   "regexp_char_class" },
        { "invalid character property name",               "regexp_property" },
        { "invalid POSIX bracket type",                    "regexp_char_class" },
        { "char-class value at ",                          "regexp_char_class" },
        { "unmatched range specifier in char-class",       "regexp_char_class" },
        { "empty range in char class",                     "regexp_char_class" },
        { "mismatch multibyte code length in char-class range", "regexp_char_class" },
        { "too many multibyte code ranges",                "regexp_char_class" },
        { "empty char-class",                              "regexp_char_class" },
        { "invalid backref number",                        "regexp_backref" },
        { "too big backref number",                        "regexp_backref" },
        { "numbered backref/call is not allowed",          "regexp_backref" },
        { "too short escape sequence:",                    "regexp_escape" },
        { "invalid escape:",                               "regexp_escape" },
        { "invalid meta-code syntax",                      "regexp_escape" },
        { "invalid control-code syntax",                   "regexp_escape" },
        { "invalid code point value",                      "regexp_escape" },
        { "too long wide-char value",                      "regexp_escape" },
        { "too big wide-char value",                       "regexp_escape" },
        { "too short digits",                              "regexp_escape" },
        { "too short multibyte code string",               "regexp_escape" },
        { "end pattern",                                   "regexp_pattern" },
        { "unmatched close parenthesis",                   "regexp_pattern" },
        { "invalid conditional pattern",                   "regexp_pattern" },
        { "never ending recursion",                        "regexp_pattern" },
        { "parse depth limit over",                        "regexp_pattern" },
        { "too big compiled program",                      "regexp_pattern" },
        { "too many null check",                           "regexp_pattern" },
        { "target of repeat-operator",                     "regexp_repeat" },
        { "target of repeat operator",                     "regexp_repeat" },
        { "nested repeat operator",                        "regexp_repeat" },
        { "invalid repeat range",                          "regexp_repeat" },
        { "too big number",                                "regexp_repeat" },
        { "upper is smaller than lower in repeat range",   "regexp_repeat" },
        { "too many range repeat",                         "regexp_repeat" },
        { "invalid pattern in look-behind",                "regexp_lookbehind" },
        { "invalid group name",                            "regexp_group" },
        { "invalid char in group ",                        "regexp_group" },
        { "undefined name <",                              "regexp_group" },
        { "undefined group <",                             "regexp_group" },
        { "multiplex defined name <",                      "regexp_group" },
        { "multiplex definition name <",                   "regexp_group" },
        { "group name is empty",                           "regexp_group" },
        { "group number is too big",                       "regexp_group" },
        { "too many capture groups",                       "regexp_group" },
        { "undefined group option",                        "regexp_options" },
        { "invalid combination of options",                "regexp_options" },
        { "not supported encoding combination",            "regexp_options" },
        { "unterminated string meets end of file",         "unterminated_string" },
        { "unterminated regexp meets end of file",         "unterminated_regexp" },
        { "can't find string \"",                          "unterminated_heredoc" },
        { "embedded document meets end of file",           "unterminated_embdoc" },
        { "dynamic constant assignment",                   "dynamic_constant_assign" },
        { "formal argument cannot be",                     "invalid_formal_arg" },
        { "duplicated argument name",                      "duplicate_arg_name" },
        { "circular argument reference",                   "circular_arg_ref" },
        { "Invalid break",                                 "invalid_break" },
        { "Invalid next",                                  "invalid_next" },
        { "Invalid redo",                                  "invalid_redo" },
        { "Invalid retry",                                 "invalid_retry" },
        { "Invalid yield",                                 "invalid_yield" },
        { "numbered parameter",                            "numbered_param" },
        { "ordinary parameter is defined",                 "ordinary_param_conflict" },
        { "no .<digit> floating literal anymore",          "float_literal_method" },
        { "syntax error, unexpected 'do' for block",       "unexpected_do_block" },
        { "syntax error, unexpected '\\n'",                "unexpected_newline" }
    };

    for (size_t i = 0; i < sizeof(prefix_tags) / sizeof(prefix_tags[0]); i++) {
        if (diff_starts_with(line, prefix_tags[i].prefix)) {
            snprintf(tag_buf, tag_cap, "%s:%s", cls, prefix_tags[i].tag);
            return;
        }
    }

    if (diff_starts_with(line, "identifier ")) {
        if (strstr(line, " is not valid to get") != NULL) {
            snprintf(tag_buf, tag_cap, "%s:invalid_identifier_get", cls);
            return;
        }
        if (strstr(line, " is not valid to set") != NULL) {
            snprintf(tag_buf, tag_cap, "%s:invalid_identifier_set", cls);
            return;
        }
    }

    static const char unexpected_pfx[] = "syntax error, unexpected ";
    if (diff_starts_with(line, unexpected_pfx)) {
        const char *p = line + sizeof(unexpected_pfx) - 1;
        char tok[48];
        size_t len = 0;
        bool has_alnum = false;
        while (*p != '\0' && *p != ',' && len + 1 < sizeof(tok)) {
            unsigned char ch = (unsigned char) *p++;
            if (ch >= 'A' && ch <= 'Z') {
                tok[len++] = (char) (ch + ('a' - 'A'));
                has_alnum = true;
            } else if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) {
                tok[len++] = (char) ch;
                has_alnum = true;
            } else if ((ch == ' ' || ch == '-' || ch == '_') && len > 0 && tok[len - 1] != '_') {
                tok[len++] = '_';
            }
        }
        while (len > 0 && tok[len - 1] == '_') {
            len--;
        }
        tok[len] = '\0';
        snprintf(tag_buf, tag_cap, "%s:unexpected_%s", cls, has_alnum ? tok : "punct");
        return;
    }

    if (strcmp(cls, "RegexpError") == 0 || strstr(line, ": /") != NULL) {
        snprintf(tag_buf, tag_cap, "%s:regexp_other", cls);
        return;
    }

    snprintf(tag_buf, tag_cap, "%s:other", cls);
}

static VALUE diff_ast_parse_cb(VALUE src_str) {
    static VALUE rb_mAST = Qnil;
    static ID id_parse = 0;
    if (NIL_P(rb_mAST)) {
        VALUE rb_cRubyVM = rb_const_get(rb_cObject, rb_intern("RubyVM"));
        rb_mAST = rb_const_get(rb_cRubyVM, rb_intern("AbstractSyntaxTree"));
        rb_gc_register_mark_object(rb_mAST);
        id_parse = rb_intern("parse");
    }
    return rb_funcall(rb_mAST, id_parse, 1, src_str);
}

static VALUE diff_iseq_compile_cb(VALUE src_str) {
    static VALUE rb_cISeq = Qnil;
    static ID id_compile = 0;
    if (NIL_P(rb_cISeq)) {
        VALUE rb_cRubyVM = rb_const_get(rb_cObject, rb_intern("RubyVM"));
        rb_cISeq = rb_const_get(rb_cRubyVM, rb_intern("InstructionSequence"));
        rb_gc_register_mark_object(rb_cISeq);
        id_compile = rb_intern("compile");
    }
    return rb_funcall(rb_cISeq, id_compile, 1, src_str);
}

static void diff_format_exception(
    VALUE err,
    char *exc_buf,
    size_t exc_cap,
    char *tag_buf,
    size_t tag_cap
) {
    if (NIL_P(err)) {
        if (exc_cap > 0) snprintf(exc_buf, exc_cap, "nil");
        if (tag_cap > 0) snprintf(tag_buf, tag_cap, "nil");
        return;
    }

    char cls_buf[48];
    diff_sanitize_ident(rb_obj_classname(err), cls_buf, sizeof(cls_buf), "Exception");

    static ID id_message = 0;
    if (id_message == 0) {
        id_message = rb_intern("message");
    }
    volatile VALUE msg = rb_funcall(err, id_message, 0);
    const char *mptr = (RB_TYPE_P(msg, T_STRING) && RSTRING_LEN(msg) > 0) ? RSTRING_PTR(msg) : "";
    long mlen = RB_TYPE_P(msg, T_STRING) ? RSTRING_LEN(msg) : 0;

    char line[128];
    long line_len = 0;
    while (line_len < mlen && line_len < (long) (sizeof(line) - 1) &&
           mptr[line_len] != '\n' && mptr[line_len] != '\r') {
        line[line_len] = (mptr[line_len] != '\0') ? mptr[line_len] : ' ';
        line_len++;
    }
    line[line_len] = '\0';

    if (exc_cap > 0) {
        int detail_len = (int) (line_len > 96 ? 96 : line_len);
        snprintf(exc_buf, exc_cap, "%s: %.*s", cls_buf, detail_len, line);
    }
    if (tag_cap > 0) {
        diff_classify_cruby_msg(cls_buf, line, tag_buf, tag_cap);
    }
    RB_GC_GUARD(msg);
}

static VALUE diff_run_cruby_callback(
    VALUE (*cb)(VALUE),
    const char *source,
    size_t size,
    bool *out_ok,
    char *exc_buf,
    size_t exc_cap,
    char *tag_buf,
    size_t tag_cap
) {
    if (size > (size_t) LONG_MAX) {
        abort();
    }
    volatile VALUE src_str = rb_utf8_str_new(source != NULL ? source : "", (long) size);
    int state = 0;
    volatile VALUE res = rb_protect(cb, src_str, &state);
    if (state != 0) {
        VALUE err = rb_errinfo();
        rb_set_errinfo(Qnil);
        *out_ok = false;
        diff_format_exception(err, exc_buf, exc_cap, tag_buf, tag_cap);
        RB_GC_GUARD(src_str);
        return Qnil;
    }

    *out_ok = true;
    if (exc_cap > 0) exc_buf[0] = '\0';
    if (tag_cap > 0) snprintf(tag_buf, tag_cap, "ok");
    RB_GC_GUARD(src_str);
    return res;
}

static VALUE diff_run_cruby(
    const char *source,
    size_t size,
    bool *out_ok,
    char *exc_buf,
    size_t exc_cap,
    char *tag_buf,
    size_t tag_cap
) {
    return diff_run_cruby_callback(diff_ast_parse_cb, source, size, out_ok, exc_buf, exc_cap, tag_buf, tag_cap);
}

static void diff_run_cruby_compile(
    const char *source,
    size_t size,
    bool *out_ok,
    char *exc_buf,
    size_t exc_cap,
    char *tag_buf,
    size_t tag_cap
) {
    volatile VALUE iseq = diff_run_cruby_callback(diff_iseq_compile_cb, source, size, out_ok, exc_buf, exc_cap, tag_buf, tag_cap);
    RB_GC_GUARD(iseq);
}

static void diff_fail_syntax_mismatch(
    const uint8_t *source,
    size_t source_size,
    bool prism_ok,
    size_t prism_errs,
    const char *prism_diag,
    bool cruby_ok,
    const char *cruby_tag,
    const char *exc_buf
) __attribute__((noreturn));
static void diff_fail_syntax_mismatch(
    const uint8_t *source,
    size_t source_size,
    bool prism_ok,
    size_t prism_errs,
    const char *prism_diag,
    bool cruby_ok,
    const char *cruby_tag,
    const char *exc_buf
) {
    const char *sub = prism_ok ? "prism_ok_cruby_err" : "prism_err_cruby_ok";
    int has_nul = diff_has_nul(source, source_size) ? 1 : 0;
    int valid_utf8 = diff_is_valid_utf8(source, source_size) ? 1 : 0;
    diff_invariant_fail(
        "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=%s nul=%d utf8=%d prism=%s cruby=%s [detail: prism_errs=%zu cruby=%s]\n",
        sub,
        has_nul,
        valid_utf8,
        prism_diag,
        cruby_ok ? "ok" : cruby_tag,
        prism_errs,
        cruby_ok ? "ok" : exc_buf
    );
}
/* TRIAGE_SLICE_END(diff_core) */

/* TRIAGE_SLICE_BEGIN(diff_ast) */
#define DIFF_STACK_STR_BYTES 1024
#define DIFF_STACK_SPANS     32
#define DIFF_STACK_SCOPES    16
#define DIFF_MAX_AST_DEPTH   4096

typedef enum {
    DIFF_SCOPE_PROGRAM = 0,
    DIFF_SCOPE_DEF,
    DIFF_SCOPE_CLASS,
    DIFF_SCOPE_MODULE,
    DIFF_SCOPE_SCLASS,
    DIFF_SCOPE_BLOCK,
    DIFF_SCOPE_LAMBDA
} diff_scope_kind_t;

typedef enum {
    DIFF_CNT_CLASS = 0,
    DIFF_CNT_MODULE,
    DIFF_CNT_SCLASS,
    DIFF_CNT_FOR,
    DIFF_CNT_IF,
    DIFF_CNT_UNLESS,
    DIFF_CNT_WHILE,
    DIFF_CNT_UNTIL,
    DIFF_CNT_YIELD,
    DIFF_CNT_RETURN,
    DIFF_CNT_SUPER,
    DIFF_CNT_DEFINED,
    DIFF_CNT_ALIAS,
    DIFF_CNT_UNDEF,
    DIFF_CNT_CASE,
    DIFF_CNT_BREAK,
    DIFF_CNT_NEXT,
    DIFF_CNT_REDO,
    DIFF_CNT_RETRY,
    DIFF_CNT_POSTEXE,
    DIFF_CNT_CASE_MATCH,
    DIFF_CNT_IN,
    DIFF_CNT_RESCUE,
    DIFF_CNT_ENSURE,
    DIFF_CNT_LEN
} diff_count_kind_t;

typedef struct {
    uint32_t offset;
    uint32_t length;
} diff_span_t;

typedef struct {
    char *data;
    size_t used;
    size_t cap;
    bool on_heap;
    char stack[DIFF_STACK_STR_BYTES];
} diff_strbuf_t;

typedef struct {
    diff_span_t *items;
    size_t count;
    size_t cap;
    bool on_heap;
    diff_span_t stack[DIFF_STACK_SPANS];
} diff_span_vec_t;

typedef struct {
    uint8_t kind;
    uint32_t local_start;
    uint32_t local_count;
} diff_scope_t;

typedef struct {
    diff_scope_t *items;
    size_t count;
    size_t cap;
    bool on_heap;
    diff_scope_t stack[DIFF_STACK_SCOPES];
} diff_scope_vec_t;

typedef struct {
    diff_strbuf_t strbuf;
    diff_scope_vec_t scopes;
    diff_span_vec_t locals;
    diff_span_vec_t defs;
    diff_span_vec_t block_owners;
    size_t counts[DIFF_CNT_LEN];
} diff_summary_t;

typedef struct {
    ID scope, defn, defs, cls, mod, scls, iter, lambda, for_n, postexe;
    ID if_n, unless_n, while_n, until_n, yield_n, return_n, break_n, next_n, redo_n, retry_n;
    ID super_n, zsuper_n, defined_n, alias_n, valias_n, undef_n, case_n, case2_n;
    ID case3_n, in_n, resbody, ensure_n;
    ID masgn;
    ID fcall, vcall, call, qcall, opcall;
} diff_cruby_ids_t;

static VALUE rb_cASTNode = Qnil;
static ID id_children = 0;
static ID id_type = 0;
static diff_cruby_ids_t diff_ids;

static void diff_ast_ids_init(void) {
    static int initialized = 0;
    if (initialized) {
        return;
    }

    VALUE rb_cRubyVM = rb_const_get(rb_cObject, rb_intern("RubyVM"));
    VALUE rb_mAST = rb_const_get(rb_cRubyVM, rb_intern("AbstractSyntaxTree"));
    rb_cASTNode = rb_const_get(rb_mAST, rb_intern("Node"));
    rb_gc_register_mark_object(rb_cASTNode);

    id_children = rb_intern("children");
    id_type = rb_intern("type");

    static const struct {
        ID *slot;
        const char *name;
    } id_map[] = {
        { &diff_ids.scope,     "SCOPE" },
        { &diff_ids.defn,      "DEFN" },
        { &diff_ids.defs,      "DEFS" },
        { &diff_ids.cls,       "CLASS" },
        { &diff_ids.mod,       "MODULE" },
        { &diff_ids.scls,      "SCLASS" },
        { &diff_ids.iter,      "ITER" },
        { &diff_ids.lambda,    "LAMBDA" },
        { &diff_ids.for_n,     "FOR" },
        { &diff_ids.postexe,   "POSTEXE" },
        { &diff_ids.if_n,      "IF" },
        { &diff_ids.unless_n,  "UNLESS" },
        { &diff_ids.while_n,   "WHILE" },
        { &diff_ids.until_n,   "UNTIL" },
        { &diff_ids.yield_n,   "YIELD" },
        { &diff_ids.return_n,  "RETURN" },
        { &diff_ids.break_n,   "BREAK" },
        { &diff_ids.next_n,    "NEXT" },
        { &diff_ids.redo_n,    "REDO" },
        { &diff_ids.retry_n,   "RETRY" },
        { &diff_ids.super_n,   "SUPER" },
        { &diff_ids.zsuper_n,  "ZSUPER" },
        { &diff_ids.defined_n, "DEFINED" },
        { &diff_ids.alias_n,   "ALIAS" },
        { &diff_ids.valias_n,  "VALIAS" },
        { &diff_ids.undef_n,   "UNDEF" },
        { &diff_ids.case_n,    "CASE" },
        { &diff_ids.case2_n,   "CASE2" },
        { &diff_ids.case3_n,   "CASE3" },
        { &diff_ids.in_n,      "IN" },
        { &diff_ids.resbody,   "RESBODY" },
        { &diff_ids.ensure_n,  "ENSURE" },
        { &diff_ids.masgn,     "MASGN" },
        { &diff_ids.fcall,     "FCALL" },
        { &diff_ids.vcall,     "VCALL" },
        { &diff_ids.call,      "CALL" },
        { &diff_ids.qcall,     "QCALL" },
        { &diff_ids.opcall,    "OPCALL" }
    };
    for (size_t i = 0; i < sizeof(id_map) / sizeof(id_map[0]); i++) {
        *id_map[i].slot = rb_intern(id_map[i].name);
    }

    initialized = 1;
}

static const char *diff_scope_kind_name(diff_scope_kind_t kind) {
    static const char *const names[] = {
        "program", "def", "class", "module", "sclass", "block", "lambda"
    };
    size_t idx = (size_t) kind;
    return idx < (sizeof(names) / sizeof(names[0])) ? names[idx] : "unknown";
}

static const char *diff_count_kind_name(diff_count_kind_t kind) {
    static const char *const names[] = {
        "class", "module", "sclass", "for", "if", "unless", "while", "until",
        "yield", "return", "super", "defined", "alias", "undef", "case",
        "break", "next", "redo", "retry", "postexe", "case_match", "in", "rescue", "ensure"
    };
    size_t idx = (size_t) kind;
    return idx < (sizeof(names) / sizeof(names[0])) ? names[idx] : "unknown";
}

static void diff_strbuf_init(diff_strbuf_t *b) {
    b->data = b->stack;
    b->used = 0;
    b->cap = sizeof(b->stack);
    b->on_heap = false;
}

static void diff_ensure_cap(
    void **buf,
    size_t *cap,
    bool *on_heap,
    const void *stack_buf,
    size_t used_count,
    size_t elem_size,
    size_t needed
) {
    if (needed <= *cap) {
        return;
    }
    size_t new_cap = *cap;
    while (new_cap < needed) {
        if (new_cap > SIZE_MAX / 2) {
            abort();
        }
        new_cap *= 2;
    }
    if (new_cap > SIZE_MAX / elem_size) {
        abort();
    }
    void *next = NULL;
    if (*on_heap) {
        next = realloc(*buf, new_cap * elem_size);
    } else {
        next = malloc(new_cap * elem_size);
        if (next != NULL && used_count > 0) {
            memcpy(next, stack_buf, used_count * elem_size);
        }
    }
    if (next == NULL) {
        abort();
    }
    *buf = next;
    *cap = new_cap;
    *on_heap = true;
}

static void diff_strbuf_free(diff_strbuf_t *b) {
    if (b->on_heap) {
        free(b->data);
    }
    diff_strbuf_init(b);
}

static diff_span_t diff_strbuf_add(diff_strbuf_t *b, const char *ptr, size_t len) {
    if (len > UINT32_MAX || b->used > (size_t) UINT32_MAX - len) {
        abort();
    }
    void *data_ptr = b->data;
    diff_ensure_cap(&data_ptr, &b->cap, &b->on_heap, b->stack, b->used, 1, b->used + len);
    b->data = (char *) data_ptr;

    diff_span_t span;
    span.offset = (uint32_t) b->used;
    span.length = (uint32_t) len;
    if (len > 0) {
        memcpy(b->data + b->used, ptr, len);
        b->used += len;
    }
    return span;
}

static void diff_span_vec_init(diff_span_vec_t *v) {
    v->items = v->stack;
    v->count = 0;
    v->cap = DIFF_STACK_SPANS;
    v->on_heap = false;
}

static void diff_span_vec_free(diff_span_vec_t *v) {
    if (v->on_heap) {
        free(v->items);
    }
    diff_span_vec_init(v);
}

static void diff_span_vec_push(diff_span_vec_t *v, diff_span_t span) {
    void *items_ptr = v->items;
    diff_ensure_cap(&items_ptr, &v->cap, &v->on_heap, v->stack, v->count, sizeof(diff_span_t), v->count + 1);
    v->items = (diff_span_t *) items_ptr;
    v->items[v->count++] = span;
}

static void diff_scope_vec_init(diff_scope_vec_t *v) {
    v->items = v->stack;
    v->count = 0;
    v->cap = DIFF_STACK_SCOPES;
    v->on_heap = false;
}

static void diff_scope_vec_free(diff_scope_vec_t *v) {
    if (v->on_heap) {
        free(v->items);
    }
    diff_scope_vec_init(v);
}

static void diff_scope_vec_push(diff_scope_vec_t *v, diff_scope_t scope) {
    void *items_ptr = v->items;
    diff_ensure_cap(&items_ptr, &v->cap, &v->on_heap, v->stack, v->count, sizeof(diff_scope_t), v->count + 1);
    v->items = (diff_scope_t *) items_ptr;
    v->items[v->count++] = scope;
}

static void diff_summary_init(diff_summary_t *s) {
    diff_strbuf_init(&s->strbuf);
    diff_scope_vec_init(&s->scopes);
    diff_span_vec_init(&s->locals);
    diff_span_vec_init(&s->defs);
    diff_span_vec_init(&s->block_owners);
    memset(s->counts, 0, sizeof(s->counts));
}

static void diff_summary_free(diff_summary_t *s) {
    diff_strbuf_free(&s->strbuf);
    diff_scope_vec_free(&s->scopes);
    diff_span_vec_free(&s->locals);
    diff_span_vec_free(&s->defs);
    diff_span_vec_free(&s->block_owners);
    memset(s->counts, 0, sizeof(s->counts));
}

static int diff_span_cmp(diff_span_t a, diff_span_t b, const char *buf) {
    size_t min_len = a.length < b.length ? a.length : b.length;
    int cmp = min_len > 0 ? memcmp(buf + a.offset, buf + b.offset, min_len) : 0;
    if (cmp != 0) {
        return cmp;
    }
    return (a.length > b.length) - (a.length < b.length);
}

static void diff_sift_down(diff_span_t *arr, size_t start, size_t end, const char *buf) {
    size_t root = start;
    while (root * 2 + 1 <= end) {
        size_t child = root * 2 + 1;
        size_t swap_idx = root;
        if (diff_span_cmp(arr[swap_idx], arr[child], buf) < 0) {
            swap_idx = child;
        }
        if (child + 1 <= end && diff_span_cmp(arr[swap_idx], arr[child + 1], buf) < 0) {
            swap_idx = child + 1;
        }
        if (swap_idx == root) {
            return;
        }
        diff_span_t tmp = arr[root];
        arr[root] = arr[swap_idx];
        arr[swap_idx] = tmp;
        root = swap_idx;
    }
}

/* Portable in-place O(N log N) sort over spans indexed into a string buffer. */
static void diff_sort_spans(diff_span_t *arr, size_t n, const char *buf) {
    if (n < 2) {
        return;
    }
    for (size_t start = n / 2; start > 0; start--) {
        diff_sift_down(arr, start - 1, n - 1, buf);
    }
    for (size_t end = n - 1; end > 0; end--) {
        diff_span_t tmp = arr[0];
        arr[0] = arr[end];
        arr[end] = tmp;
        diff_sift_down(arr, 0, end - 1, buf);
    }
}

/* Sort and deduplicate locals per scope and sort block owners for traversal invariance. */
static void diff_finalize_summary(diff_summary_t *s) {
    for (size_t i = 0; i < s->scopes.count; i++) {
        diff_scope_t *sc = &s->scopes.items[i];
        size_t n = sc->local_count;
        if (n < 2) {
            continue;
        }
        diff_span_t *slice = &s->locals.items[sc->local_start];
        diff_sort_spans(slice, n, s->strbuf.data);
        size_t unique = 1;
        for (size_t j = 1; j < n; j++) {
            if (diff_span_cmp(slice[j], slice[unique - 1], s->strbuf.data) != 0) {
                slice[unique++] = slice[j];
            }
        }
        sc->local_count = (uint32_t) unique;
    }
    /* Keep block_owners in AST traversal order rather than sorting them. */
}

/* Ignore CRuby synthetic parameter table entries (*, **, &, ..., <it>) so scope locals align. */
static bool diff_is_synthetic_local(const char *s, size_t len) {
    switch (len) {
        case 1: return s[0] == '*' || s[0] == '&';
        case 2: return memcmp(s, "**", 2) == 0;
        case 3: return memcmp(s, "...", 3) == 0;
        case 4: return memcmp(s, "<it>", 4) == 0;
        default: return false;
    }
}

typedef struct {
    const pm_parser_t *parser;
    diff_summary_t *out;
    size_t depth;
} diff_prism_ctx_t;

static void diff_prism_push_scope(
    const pm_parser_t *parser,
    diff_summary_t *out,
    diff_scope_kind_t kind,
    const pm_constant_id_list_t *list
) {
    if (out->locals.count > UINT32_MAX) {
        abort();
    }
    diff_scope_t sc;
    sc.kind = (uint8_t) kind;
    sc.local_start = (uint32_t) out->locals.count;
    uint32_t added = 0;
    for (size_t i = 0; i < list->size; i++) {
        const pm_constant_t *c = pm_parser_constant(parser, list->ids[i]);
        const char *ptr = (const char *) pm_constant_start(c);
        size_t len = pm_constant_length(c);
        if (diff_is_synthetic_local(ptr, len)) {
            continue;
        }
        diff_span_vec_push(&out->locals, diff_strbuf_add(&out->strbuf, ptr, len));
        added++;
    }
    sc.local_count = added;
    diff_scope_vec_push(&out->scopes, sc);
}

static void diff_prism_add_const(const pm_parser_t *parser, diff_summary_t *out, pm_constant_id_t id, diff_span_vec_t *vec) {
    const pm_constant_t *c = pm_parser_constant(parser, id);
    const char *ptr = (const char *) pm_constant_start(c);
    size_t len = pm_constant_length(c);
    diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, ptr, len));
}

static pm_visit_result_t diff_prism_visit_cb(const pm_node_t *node, void *data);

static void diff_prism_visit_child(const pm_node_t *child, diff_prism_ctx_t *ctx) {
    if (child != NULL && ctx->depth < DIFF_MAX_AST_DEPTH) {
        pm_visit_node(child, diff_prism_visit_cb, ctx);
    }
}

static pm_visit_result_t diff_prism_visit_cb(const pm_node_t *node, void *data) {
    diff_prism_ctx_t *ctx = (diff_prism_ctx_t *) data;
    if (ctx->depth >= DIFF_MAX_AST_DEPTH) {
        return PM_VISIT_SKIP;
    }
    ctx->depth++;

    switch (PM_NODE_TYPE(node)) {
        case PM_PROGRAM_NODE: {
            const pm_program_node_t *prog = (const pm_program_node_t *) node;
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_PROGRAM, &prog->locals);
            if (prog->statements != NULL) {
                /*
                 * CRuby parse.y hoists top-level BEGIN{} (NODE_BEGIN) blocks
                 * ahead of all other top-level statements in source order.
                 */
                const pm_node_list_t *stmts = &prog->statements->body;
                for (int pass = 0; pass < 2; pass++) {
                    bool want_pre = (pass == 0);
                    for (size_t i = 0; i < stmts->size; i++) {
                        const pm_node_t *stmt = stmts->nodes[i];
                        if (stmt != NULL && (PM_NODE_TYPE_P(stmt, PM_PRE_EXECUTION_NODE) != 0) == want_pre) {
                            pm_visit_node(stmt, diff_prism_visit_cb, ctx);
                        }
                    }
                }
            }
            break;
        }
        case PM_DEF_NODE: {
            const pm_def_node_t *def_n = (const pm_def_node_t *) node;
            diff_prism_visit_child(def_n->receiver, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_DEF, &def_n->locals);
            diff_prism_add_const(ctx->parser, ctx->out, def_n->name, &ctx->out->defs);
            if (def_n->parameters != NULL) {
                diff_prism_visit_child(&def_n->parameters->base, ctx);
            }
            diff_prism_visit_child(def_n->body, ctx);
            break;
        }
        case PM_CLASS_NODE: {
            const pm_class_node_t *cls = (const pm_class_node_t *) node;
            ctx->out->counts[DIFF_CNT_CLASS]++;
            diff_prism_visit_child(cls->constant_path, ctx);
            diff_prism_visit_child(cls->superclass, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_CLASS, &cls->locals);
            diff_prism_visit_child(cls->body, ctx);
            break;
        }
        case PM_MODULE_NODE: {
            const pm_module_node_t *mod = (const pm_module_node_t *) node;
            ctx->out->counts[DIFF_CNT_MODULE]++;
            diff_prism_visit_child(mod->constant_path, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_MODULE, &mod->locals);
            diff_prism_visit_child(mod->body, ctx);
            break;
        }
        case PM_SINGLETON_CLASS_NODE: {
            const pm_singleton_class_node_t *scls = (const pm_singleton_class_node_t *) node;
            ctx->out->counts[DIFF_CNT_SCLASS]++;
            diff_prism_visit_child(scls->expression, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_SCLASS, &scls->locals);
            diff_prism_visit_child(scls->body, ctx);
            break;
        }
        case PM_FOR_NODE: {
            const pm_for_node_t *for_n = (const pm_for_node_t *) node;
            ctx->out->counts[DIFF_CNT_FOR]++;
            diff_prism_visit_child(for_n->collection, ctx);
            diff_prism_visit_child(for_n->index, ctx);
            if (for_n->statements != NULL) {
                diff_prism_visit_child(&for_n->statements->base, ctx);
            }
            break;
        }
        case PM_BLOCK_NODE: {
            const pm_block_node_t *blk = (const pm_block_node_t *) node;
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_BLOCK, &blk->locals);
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
        }
        case PM_LAMBDA_NODE: {
            const pm_lambda_node_t *lam = (const pm_lambda_node_t *) node;
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_LAMBDA, &lam->locals);
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
        }
        case PM_CALL_NODE: {
            const pm_call_node_t *call = (const pm_call_node_t *) node;
            if (call->block != NULL && PM_NODE_TYPE_P(call->block, PM_BLOCK_NODE)) {
                diff_prism_add_const(ctx->parser, ctx->out, call->name, &ctx->out->block_owners);
            }
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
        }
        case PM_SUPER_NODE: {
            const pm_super_node_t *sup = (const pm_super_node_t *) node;
            ctx->out->counts[DIFF_CNT_SUPER]++;
            if (sup->block != NULL && PM_NODE_TYPE_P(sup->block, PM_BLOCK_NODE)) {
                diff_span_vec_push(&ctx->out->block_owners, diff_strbuf_add(&ctx->out->strbuf, "super", 5));
            }
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
        }
        case PM_FORWARDING_SUPER_NODE: {
            const pm_forwarding_super_node_t *fsup = (const pm_forwarding_super_node_t *) node;
            ctx->out->counts[DIFF_CNT_SUPER]++;
            if (fsup->block != NULL && PM_NODE_TYPE_P(&fsup->block->base, PM_BLOCK_NODE)) {
                diff_span_vec_push(&ctx->out->block_owners, diff_strbuf_add(&ctx->out->strbuf, "super", 5));
            }
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
        }
        case PM_IF_NODE:     ctx->out->counts[DIFF_CNT_IF]++;     pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_UNLESS_NODE: ctx->out->counts[DIFF_CNT_UNLESS]++; pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_WHILE_NODE:  ctx->out->counts[DIFF_CNT_WHILE]++;  pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_UNTIL_NODE:  ctx->out->counts[DIFF_CNT_UNTIL]++;  pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_YIELD_NODE:  ctx->out->counts[DIFF_CNT_YIELD]++;  pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_RETURN_NODE: ctx->out->counts[DIFF_CNT_RETURN]++; pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_DEFINED_NODE: ctx->out->counts[DIFF_CNT_DEFINED]++; pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_ALIAS_METHOD_NODE:
        case PM_ALIAS_GLOBAL_VARIABLE_NODE:
            ctx->out->counts[DIFF_CNT_ALIAS]++;
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
        case PM_UNDEF_NODE:  ctx->out->counts[DIFF_CNT_UNDEF]++;  pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_CASE_NODE:   ctx->out->counts[DIFF_CNT_CASE]++;   pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_BREAK_NODE:  ctx->out->counts[DIFF_CNT_BREAK]++;  pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_NEXT_NODE:   ctx->out->counts[DIFF_CNT_NEXT]++;   pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_REDO_NODE:   ctx->out->counts[DIFF_CNT_REDO]++;   pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_RETRY_NODE:  ctx->out->counts[DIFF_CNT_RETRY]++;  pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_POST_EXECUTION_NODE: ctx->out->counts[DIFF_CNT_POSTEXE]++; pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_CASE_MATCH_NODE: ctx->out->counts[DIFF_CNT_CASE_MATCH]++; pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_IN_NODE:     ctx->out->counts[DIFF_CNT_IN]++;     pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_MATCH_PREDICATE_NODE:
        case PM_MATCH_REQUIRED_NODE:
            ctx->out->counts[DIFF_CNT_CASE_MATCH]++;
            ctx->out->counts[DIFF_CNT_IN]++;
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
        case PM_RESCUE_NODE:
        case PM_RESCUE_MODIFIER_NODE:
            ctx->out->counts[DIFF_CNT_RESCUE]++;
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
        case PM_ENSURE_NODE: ctx->out->counts[DIFF_CNT_ENSURE]++; pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
        case PM_ERROR_RECOVERY_NODE: {
            uint32_t start = node->location.start;
            uint32_t length = node->location.length;
            diff_summary_free(ctx->out);
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=ast_zero_error_recovery [detail: start=%u length=%u]\n",
                start,
                length
            );
        }
        default:
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
    }

    ctx->depth--;
    return PM_VISIT_SKIP;
}

static void diff_collect_prism_summary(
    const pm_parser_t *parser,
    const pm_node_t *root,
    diff_summary_t *out
) {
    if (root == NULL) {
        return;
    }
    diff_prism_ctx_t ctx = { .parser = parser, .out = out, .depth = 0 };
    pm_visit_node(root, diff_prism_visit_cb, &ctx);
    diff_finalize_summary(out);
}

static bool diff_cruby_is_ast_node(VALUE v) {
    return RB_TYPE_P(v, T_DATA) && rb_obj_is_kind_of(v, rb_cASTNode);
}

static void diff_cruby_add_sym(VALUE sym, diff_summary_t *out, diff_span_vec_t *vec) {
    if (!SYMBOL_P(sym)) {
        diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, "<nil>", 5));
        return;
    }
    volatile VALUE sym_str = rb_sym2str(sym);
    if (RB_TYPE_P(sym_str, T_STRING)) {
        diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, RSTRING_PTR(sym_str), (size_t) RSTRING_LEN(sym_str)));
    } else {
        diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, "<sym>", 5));
    }
    RB_GC_GUARD(sym_str);
}

static void diff_cruby_record_block_owner(VALUE target, diff_summary_t *out) {
    volatile VALUE cur = target;
    for (int hop = 0; hop < 32 && diff_cruby_is_ast_node(cur); hop++) {
        volatile VALUE type_sym = rb_funcall(cur, id_type, 0);
        ID tid = SYMBOL_P(type_sym) ? SYM2ID(type_sym) : 0;
        volatile VALUE ch = rb_funcall(cur, id_children, 0);
        if (!RB_TYPE_P(ch, T_ARRAY)) {
            RB_GC_GUARD(ch);
            RB_GC_GUARD(type_sym);
            break;
        }
        long len = RARRAY_LEN(ch);
        if ((tid == diff_ids.return_n || tid == diff_ids.break_n || tid == diff_ids.next_n) && len >= 1) {
            cur = RARRAY_AREF(ch, 0);
            RB_GC_GUARD(ch);
            RB_GC_GUARD(type_sym);
            continue;
        }
        if ((tid == diff_ids.fcall || tid == diff_ids.vcall) && len >= 1) {
            diff_cruby_add_sym(RARRAY_AREF(ch, 0), out, &out->block_owners);
        } else if ((tid == diff_ids.call || tid == diff_ids.qcall || tid == diff_ids.opcall) && len >= 2) {
            diff_cruby_add_sym(RARRAY_AREF(ch, 1), out, &out->block_owners);
        } else if (tid == diff_ids.super_n || tid == diff_ids.zsuper_n) {
            diff_span_vec_push(&out->block_owners, diff_strbuf_add(&out->strbuf, "super", 5));
        } else {
            const char *tname = SYMBOL_P(type_sym) ? rb_id2name(tid) : "unknown";
            diff_span_vec_push(&out->block_owners, diff_strbuf_add(&out->strbuf, tname ? tname : "unknown", tname ? strlen(tname) : 7));
        }
        RB_GC_GUARD(ch);
        RB_GC_GUARD(type_sym);
        RB_GC_GUARD(cur);
        return;
    }
    diff_span_vec_push(&out->block_owners, diff_strbuf_add(&out->strbuf, "<unknown>", 9));
    RB_GC_GUARD(cur);
}

static void diff_cruby_extract_scope_locals(VALUE tbl, diff_scope_kind_t kind, diff_summary_t *out) {
    if (!RB_TYPE_P(tbl, T_ARRAY)) {
        int t = (int) TYPE(tbl);
        diff_summary_free(out);
        diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_tbl_type [detail: type=%d]\n", t);
    }
    if (out->locals.count > UINT32_MAX) {
        abort();
    }
    diff_scope_t sc;
    sc.kind = (uint8_t) kind;
    sc.local_start = (uint32_t) out->locals.count;
    uint32_t added = 0;

    long tbl_len = RARRAY_LEN(tbl);
    for (long i = 0; i < tbl_len; i++) {
        VALUE sym = RARRAY_AREF(tbl, i);
        if (!SYMBOL_P(sym)) {
            continue;
        }
        volatile VALUE sym_str = rb_sym2str(sym);
        if (!RB_TYPE_P(sym_str, T_STRING)) {
            RB_GC_GUARD(sym_str);
            continue;
        }
        const char *ptr = RSTRING_PTR(sym_str);
        size_t len = (size_t) RSTRING_LEN(sym_str);
        if (!diff_is_synthetic_local(ptr, len)) {
            diff_span_vec_push(&out->locals, diff_strbuf_add(&out->strbuf, ptr, len));
            added++;
        }
        RB_GC_GUARD(sym_str);
    }
    sc.local_count = added;
    diff_scope_vec_push(&out->scopes, sc);
}

static void diff_cruby_visit_val(VALUE val, diff_summary_t *out, int depth);

static void diff_cruby_visit_scope_child(VALUE sc, int scope_kind, diff_summary_t *out, int depth) {
    if (depth >= DIFF_MAX_AST_DEPTH) {
        return;
    }
    if (!diff_cruby_is_ast_node(sc)) {
        diff_cruby_visit_val(sc, out, depth);
        return;
    }
    volatile VALUE type_sym = rb_funcall(sc, id_type, 0);
    ID tid = SYMBOL_P(type_sym) ? SYM2ID(type_sym) : 0;
    if (tid != diff_ids.scope) {
        RB_GC_GUARD(type_sym);
        diff_cruby_visit_val(sc, out, depth);
        return;
    }
    volatile VALUE ch = rb_funcall(sc, id_children, 0);
    if (!RB_TYPE_P(ch, T_ARRAY) || RARRAY_LEN(ch) < 1) {
        long clen = RB_TYPE_P(ch, T_ARRAY) ? RARRAY_LEN(ch) : -1L;
        RB_GC_GUARD(ch);
        RB_GC_GUARD(type_sym);
        diff_summary_free(out);
        diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_shape [detail: node=SCOPE children_len=%ld]\n", clen);
    }
    if (scope_kind >= 0) {
        diff_cruby_extract_scope_locals(RARRAY_AREF(ch, 0), (diff_scope_kind_t) scope_kind, out);
    }
    long clen = RARRAY_LEN(ch);
    for (long i = 1; i < clen; i++) {
        diff_cruby_visit_val(RARRAY_AREF(ch, i), out, depth + 1);
    }
    RB_GC_GUARD(ch);
    RB_GC_GUARD(type_sym);
}

static void diff_cruby_count_if_matched(ID tid, diff_summary_t *out) {
    if      (tid == diff_ids.if_n)      out->counts[DIFF_CNT_IF]++;
    else if (tid == diff_ids.unless_n)  out->counts[DIFF_CNT_UNLESS]++;
    else if (tid == diff_ids.while_n)   out->counts[DIFF_CNT_WHILE]++;
    else if (tid == diff_ids.until_n)   out->counts[DIFF_CNT_UNTIL]++;
    else if (tid == diff_ids.yield_n)   out->counts[DIFF_CNT_YIELD]++;
    else if (tid == diff_ids.return_n)  out->counts[DIFF_CNT_RETURN]++;
    else if (tid == diff_ids.super_n || tid == diff_ids.zsuper_n) out->counts[DIFF_CNT_SUPER]++;
    else if (tid == diff_ids.defined_n) out->counts[DIFF_CNT_DEFINED]++;
    else if (tid == diff_ids.alias_n || tid == diff_ids.valias_n) out->counts[DIFF_CNT_ALIAS]++;
    else if (tid == diff_ids.undef_n)   out->counts[DIFF_CNT_UNDEF]++;
    else if (tid == diff_ids.case_n || tid == diff_ids.case2_n)   out->counts[DIFF_CNT_CASE]++;
    else if (tid == diff_ids.break_n)                              out->counts[DIFF_CNT_BREAK]++;
    else if (tid == diff_ids.next_n)                               out->counts[DIFF_CNT_NEXT]++;
    else if (tid == diff_ids.redo_n)                               out->counts[DIFF_CNT_REDO]++;
    else if (tid == diff_ids.retry_n)                              out->counts[DIFF_CNT_RETRY]++;
    else if (tid == diff_ids.postexe)                              out->counts[DIFF_CNT_POSTEXE]++;
    else if (tid == diff_ids.case3_n)                              out->counts[DIFF_CNT_CASE_MATCH]++;
    else if (tid == diff_ids.in_n)                                 out->counts[DIFF_CNT_IN]++;
    else if (tid == diff_ids.resbody)                              out->counts[DIFF_CNT_RESCUE]++;
    else if (tid == diff_ids.ensure_n)                             out->counts[DIFF_CNT_ENSURE]++;
}

static void diff_cruby_visit_node(VALUE node, diff_summary_t *out, int depth) {
    if (depth >= DIFF_MAX_AST_DEPTH) {
        return;
    }
    volatile VALUE type_sym = rb_funcall(node, id_type, 0);
    ID tid = SYMBOL_P(type_sym) ? SYM2ID(type_sym) : 0;
    volatile VALUE ch = rb_funcall(node, id_children, 0);
    if (!RB_TYPE_P(ch, T_ARRAY)) {
        const char *tname = SYMBOL_P(type_sym) ? rb_id2name(tid) : "unknown";
        RB_GC_GUARD(ch);
        RB_GC_GUARD(type_sym);
        diff_summary_free(out);
        diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_shape [detail: node=%s children_len=-1]\n", tname ? tname : "unknown");
    }
    long len = RARRAY_LEN(ch);

    if (tid == diff_ids.scope) {
        diff_cruby_visit_scope_child(node, depth == 0 ? (int) DIFF_SCOPE_PROGRAM : -1, out, depth);
    } else if (tid == diff_ids.defn && len >= 2) {
        diff_cruby_add_sym(RARRAY_AREF(ch, 0), out, &out->defs);
        diff_cruby_visit_scope_child(RARRAY_AREF(ch, 1), DIFF_SCOPE_DEF, out, depth + 1);
    } else if (tid == diff_ids.defs && len >= 3) {
        diff_cruby_visit_val(RARRAY_AREF(ch, 0), out, depth + 1);
        diff_cruby_add_sym(RARRAY_AREF(ch, 1), out, &out->defs);
        diff_cruby_visit_scope_child(RARRAY_AREF(ch, 2), DIFF_SCOPE_DEF, out, depth + 1);
    } else if (tid == diff_ids.cls && len >= 3) {
        out->counts[DIFF_CNT_CLASS]++;
        diff_cruby_visit_val(RARRAY_AREF(ch, 0), out, depth + 1);
        diff_cruby_visit_val(RARRAY_AREF(ch, 1), out, depth + 1);
        diff_cruby_visit_scope_child(RARRAY_AREF(ch, 2), DIFF_SCOPE_CLASS, out, depth + 1);
    } else if (tid == diff_ids.mod && len >= 2) {
        out->counts[DIFF_CNT_MODULE]++;
        diff_cruby_visit_val(RARRAY_AREF(ch, 0), out, depth + 1);
        diff_cruby_visit_scope_child(RARRAY_AREF(ch, 1), DIFF_SCOPE_MODULE, out, depth + 1);
    } else if (tid == diff_ids.scls && len >= 2) {
        out->counts[DIFF_CNT_SCLASS]++;
        diff_cruby_visit_val(RARRAY_AREF(ch, 0), out, depth + 1);
        diff_cruby_visit_scope_child(RARRAY_AREF(ch, 1), DIFF_SCOPE_SCLASS, out, depth + 1);
    } else if (tid == diff_ids.iter && len >= 2) {
        diff_cruby_record_block_owner(RARRAY_AREF(ch, 0), out);
        diff_cruby_visit_val(RARRAY_AREF(ch, 0), out, depth + 1);
        diff_cruby_visit_scope_child(RARRAY_AREF(ch, 1), DIFF_SCOPE_BLOCK, out, depth + 1);
    } else if (tid == diff_ids.lambda && len >= 1) {
        diff_cruby_visit_scope_child(RARRAY_AREF(ch, 0), DIFF_SCOPE_LAMBDA, out, depth + 1);
    } else if (tid == diff_ids.for_n && len >= 2) {
        out->counts[DIFF_CNT_FOR]++;
        diff_cruby_visit_val(RARRAY_AREF(ch, 0), out, depth + 1);
        diff_cruby_visit_scope_child(RARRAY_AREF(ch, 1), -1, out, depth + 1);
    } else if (tid == diff_ids.postexe && len >= 1) {
        out->counts[DIFF_CNT_POSTEXE]++;
        diff_cruby_visit_scope_child(RARRAY_AREF(ch, 0), -1, out, depth + 1);
    } else if (tid == diff_ids.masgn && len >= 2) {
        /* RubyVM::AbstractSyntaxTree stores MASGN as [rhs_value, lhs_targets, ...],
         * whereas Prism's MultiWriteNode visits targets before value. */
        for (long i = 1; i < len; i++) {
            diff_cruby_visit_val(RARRAY_AREF(ch, i), out, depth + 1);
        }
        diff_cruby_visit_val(RARRAY_AREF(ch, 0), out, depth + 1);
    } else {
        diff_cruby_count_if_matched(tid, out);
        for (long i = 0; i < len; i++) {
            diff_cruby_visit_val(RARRAY_AREF(ch, i), out, depth + 1);
        }
    }

    RB_GC_GUARD(ch);
    RB_GC_GUARD(type_sym);
}

static void diff_cruby_visit_val(VALUE val, diff_summary_t *out, int depth) {
    if (depth >= DIFF_MAX_AST_DEPTH) {
        return;
    }
    if (diff_cruby_is_ast_node(val)) {
        diff_cruby_visit_node(val, out, depth);
    } else if (RB_TYPE_P(val, T_ARRAY)) {
        long len = RARRAY_LEN(val);
        for (long i = 0; i < len; i++) {
            diff_cruby_visit_val(RARRAY_AREF(val, i), out, depth + 1);
        }
    }
}

static void diff_collect_cruby_summary(VALUE ast_node, diff_summary_t *out) {
    if (NIL_P(ast_node)) {
        return;
    }
    diff_ast_ids_init();
    diff_cruby_visit_val(ast_node, out, 0);
    diff_finalize_summary(out);
}

static const char *diff_block_mismatch_sub(
    const char *p_ptr,
    size_t p_len,
    const char *c_ptr,
    size_t c_len
) {
    if ((p_len == 5 && memcmp(p_ptr, "super", 5) == 0) ||
        (c_len == 5 && memcmp(c_ptr, "super", 5) == 0)) {
        return "super";
    }
    if (p_len > 0) {
        char p0 = p_ptr[0];
        if (!((p0 >= 'a' && p0 <= 'z') || (p0 >= 'A' && p0 <= 'Z') || p0 == '_')) {
            return "operator";
        }
    }
    if (c_len > 0) {
        char c0 = c_ptr[0];
        if (!((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') || c0 == '_')) {
            return "operator";
        }
    }
    return "method";
}

static bool diff_span_equal(const char *pbuf, diff_span_t pspan, const char *cbuf, diff_span_t cspan) {
    return pspan.length == cspan.length &&
           (pspan.length == 0 || memcmp(pbuf + pspan.offset, cbuf + cspan.offset, pspan.length) == 0);
}

static size_t diff_copy_span(const char *buf, diff_span_t span, char dst[97]) {
    size_t len = span.length > 96 ? 96 : (size_t) span.length;
    if (len > 0) {
        memcpy(dst, buf + span.offset, len);
    }
    dst[len] = '\0';
    return len;
}

static void diff_compare_locals(diff_summary_t *prism, diff_summary_t *cruby) {
    for (size_t s = 0; s < prism->scopes.count; s++) {
        const diff_scope_t *ps = &prism->scopes.items[s];
        const diff_scope_t *cs = &cruby->scopes.items[s];
        const char *sname = diff_scope_kind_name((diff_scope_kind_t) ps->kind);
        if (ps->local_count != cs->local_count) {
            size_t pc = ps->local_count;
            size_t cc = cs->local_count;
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=locals_count_mismatch scope=%s [detail: scope_idx=%zu prism=%zu cruby=%zu]\n",
                sname,
                s,
                pc,
                cc
            );
        }
        for (uint32_t j = 0; j < ps->local_count; j++) {
            diff_span_t pspan = prism->locals.items[ps->local_start + j];
            diff_span_t cspan = cruby->locals.items[cs->local_start + j];
            if (!diff_span_equal(prism->strbuf.data, pspan, cruby->strbuf.data, cspan)) {
                char pcopy[97];
                char ccopy[97];
                diff_copy_span(prism->strbuf.data, pspan, pcopy);
                diff_copy_span(cruby->strbuf.data, cspan, ccopy);
                diff_summary_free(prism);
                diff_summary_free(cruby);
                diff_invariant_fail(
                    "INVARIANT[diff_parse_y]: kind=locals_name_mismatch scope=%s [detail: scope_idx=%zu idx=%zu prism=%s cruby=%s]\n",
                    sname,
                    s,
                    (size_t) j,
                    pcopy,
                    ccopy
                );
            }
        }
    }
}

static void diff_compare_asts(diff_summary_t *prism, diff_summary_t *cruby) {
    size_t common_scopes = prism->scopes.count < cruby->scopes.count ? prism->scopes.count : cruby->scopes.count;
    for (size_t i = 0; i < common_scopes; i++) {
        if (prism->scopes.items[i].kind != cruby->scopes.items[i].kind) {
            const char *pk = diff_scope_kind_name((diff_scope_kind_t) prism->scopes.items[i].kind);
            const char *ck = diff_scope_kind_name((diff_scope_kind_t) cruby->scopes.items[i].kind);
            size_t pc = prism->scopes.count;
            size_t cc = cruby->scopes.count;
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=ast_scope_kind_mismatch prism=%s cruby=%s [detail: scope_idx=%zu prism_scopes=%zu cruby_scopes=%zu]\n",
                pk,
                ck,
                i,
                pc,
                cc
            );
        }
    }

    if (prism->scopes.count != cruby->scopes.count) {
        size_t pc = prism->scopes.count;
        size_t cc = cruby->scopes.count;
        diff_summary_free(prism);
        diff_summary_free(cruby);
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=ast_scope_count_mismatch [detail: prism=%zu cruby=%zu]\n",
            pc,
            cc
        );
    }

    diff_compare_locals(prism, cruby);

    for (size_t k = 0; k < DIFF_CNT_LEN; k++) {
        if (prism->counts[k] != cruby->counts[k]) {
            size_t pc = prism->counts[k];
            size_t cc = cruby->counts[k];
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=ast_node_count_mismatch node=%s [detail: prism=%zu cruby=%zu]\n",
                diff_count_kind_name((diff_count_kind_t) k),
                pc,
                cc
            );
        }
    }

    size_t common_defs = prism->defs.count < cruby->defs.count ? prism->defs.count : cruby->defs.count;
    for (size_t i = 0; i < common_defs; i++) {
        diff_span_t ps = prism->defs.items[i];
        diff_span_t cs = cruby->defs.items[i];
        if (!diff_span_equal(prism->strbuf.data, ps, cruby->strbuf.data, cs)) {
            char pcopy[97];
            char ccopy[97];
            diff_copy_span(prism->strbuf.data, ps, pcopy);
            diff_copy_span(cruby->strbuf.data, cs, ccopy);
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=ast_def_name_mismatch [detail: idx=%zu prism=%s cruby=%s]\n",
                i,
                pcopy,
                ccopy
            );
        }
    }
    if (prism->defs.count != cruby->defs.count) {
        size_t pc = prism->defs.count;
        size_t cc = cruby->defs.count;
        diff_summary_free(prism);
        diff_summary_free(cruby);
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=ast_node_count_mismatch node=def [detail: prism=%zu cruby=%zu]\n",
            pc,
            cc
        );
    }

    if (prism->block_owners.count != cruby->block_owners.count) {
        size_t pc = prism->block_owners.count;
        size_t cc = cruby->block_owners.count;
        diff_summary_free(prism);
        diff_summary_free(cruby);
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=ast_block_owner_mismatch sub=count [detail: prism=%zu cruby=%zu]\n",
            pc,
            cc
        );
    }
    for (size_t i = 0; i < prism->block_owners.count; i++) {
        diff_span_t ps = prism->block_owners.items[i];
        diff_span_t cs = cruby->block_owners.items[i];
        if (!diff_span_equal(prism->strbuf.data, ps, cruby->strbuf.data, cs)) {
            char pcopy[97];
            char ccopy[97];
            size_t plen = diff_copy_span(prism->strbuf.data, ps, pcopy);
            size_t clen = diff_copy_span(cruby->strbuf.data, cs, ccopy);
            const char *sub = diff_block_mismatch_sub(pcopy, plen, ccopy, clen);
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=ast_block_owner_mismatch sub=%s [detail: idx=%zu prism=%s cruby=%s]\n",
                sub,
                i,
                pcopy,
                ccopy
            );
        }
    }
}
/* TRIAGE_SLICE_END(diff_ast) */

static int diff_oracle_initialized = 0;

static const int diff_crash_signals[] = { SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGPIPE };
static const int diff_fatal_signals[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE };

static void diff_write_stderr_str(const char *s, size_t len) {
    while (len > 0) {
        ssize_t written = write(STDERR_FILENO, s, len);
        if (written <= 0) {
            if (written < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
        s += written;
        len -= (size_t) written;
    }
}

static void diff_fatal_signal_handler(int sig) {
    const char *msg = "CRASH[diff_parse_y]: signal=SIGNAL\n";
    switch (sig) {
        case SIGSEGV: msg = "CRASH[diff_parse_y]: signal=SIGSEGV (11)\n"; break;
        case SIGBUS:  msg = "CRASH[diff_parse_y]: signal=SIGBUS (7)\n"; break;
        case SIGILL:  msg = "CRASH[diff_parse_y]: signal=SIGILL (4)\n"; break;
        case SIGFPE:  msg = "CRASH[diff_parse_y]: signal=SIGFPE (8)\n"; break;
        default:      break;
    }
    diff_write_stderr_str(msg, strlen(msg));
    rb_print_backtrace(stderr);
    fflush(stderr);
    raise(sig);
    _exit(128 + sig);
}

static void diff_snapshot_signals(struct sigaction saved[5]) {
    for (size_t i = 0; i < sizeof(diff_crash_signals) / sizeof(diff_crash_signals[0]); i++) {
        sigaction(diff_crash_signals[i], NULL, &saved[i]);
    }
}

static void diff_restore_signals(const struct sigaction saved[5]) {
    for (size_t i = 0; i < sizeof(diff_crash_signals) / sizeof(diff_crash_signals[0]); i++) {
        sigaction(diff_crash_signals[i], &saved[i], NULL);
    }
}

static void diff_install_fatal_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = diff_fatal_signal_handler;
    sigemptyset(&sa.sa_mask);
    /* Reset to SIG_DFL on delivery so raise(sig) kills with WTERMSIG == sig and nested faults cannot loop. */
    sa.sa_flags = SA_RESETHAND;
    for (size_t i = 0; i < sizeof(diff_fatal_signals) / sizeof(diff_fatal_signals[0]); i++) {
        sigaction(diff_fatal_signals[i], &sa, NULL);
    }
}

static void diff_oracle_init(void) {
    if (diff_oracle_initialized) {
        return;
    }

    struct sigaction saved[5];
    diff_snapshot_signals(saved);

    RUBY_INIT_STACK;
    if (ruby_setup() != 0) {
        fprintf(stderr, "fuzz.diff: ruby_setup() failed\n");
        abort();
    }

    // Boot Ruby prelude once (without running user code) so RubyVM::AbstractSyntaxTree.parse is loaded.
    char *opts[] = {
        (char *) "ruby",
        (char *) "--disable=gems",
        (char *) "--parser=parse.y",
        (char *) "-e",
        (char *) ""
    };
    (void) ruby_options(5, opts);

    diff_restore_signals(saved);
    diff_install_fatal_signal_handlers();

    VALUE warning_mod = rb_const_get(rb_cObject, rb_intern("Warning"));
    rb_define_singleton_method(warning_mod, "warn", diff_warning_warn, -1);

    diff_ast_ids_init();

    rb_thread_stop_timer_thread();
    diff_oracle_initialized = 1;
}

static void diff_run_prism(
    const uint8_t *source,
    size_t size,
    bool *out_ok,
    size_t *out_err_count,
    const char **out_first_diag,
    diff_summary_t *out_summary
) {
    *out_ok = false;
    *out_err_count = 0;
    *out_first_diag = "ok";

    uint8_t *copy = size > 0 ? (uint8_t *) malloc(size) : NULL;
    if (size > 0 && copy == NULL) {
        abort();
    }
    if (size > 0) {
        memcpy(copy, source, size);
    }
    const uint8_t *source_buf = (size == 0) ? (const uint8_t *) "" : copy;

    pm_options_t *options = pm_options_new();
    if (!pm_options_version_set(options, "4.0", 3)) {
        abort();
    }

    pm_arena_t *arena = pm_arena_new();
    pm_parser_t *parser = pm_parser_new(arena, source_buf, size, options);
    pm_node_t *root = pm_parse(parser);

    size_t err_count = pm_parser_errors_size(parser);
    *out_err_count = err_count;
    *out_ok = (err_count == 0);

    if (*out_ok) {
        if (root != NULL && PM_NODE_TYPE_P(root, PM_PROGRAM_NODE)) {
            diff_collect_prism_summary(parser, root, out_summary);
        }
    } else {
        const pm_diagnostic_t *first = pm_parser_errors_first(parser);
        *out_first_diag = (first != NULL) ? pm_diagnostic_type(first) : "error";
    }

    pm_parser_free(parser);
    pm_arena_free(arena);
    pm_options_free(options);
    free(copy);
}

static bool
diff_ignore_syntax_mismatch(bool prism_ok, bool cruby_ok, const char *cruby_tag, const char *exc_buf) {
    if (!(prism_ok && !cruby_ok)) {
        return false;
    }

    // Prism intentionally defers full Onigmo regexp compilation errors and
    // tolerates raw invalid UTF-8 bytes in string/regexp literals.
    if (strcmp(cruby_tag, "SyntaxError:invalid_multibyte_utf8") == 0) {
        return true;
    }
    if (strncmp(cruby_tag, "SyntaxError:regexp_", 19) == 0) {
        return true;
    }

    // Documented Prism vs CRuby 4.0 parse.y divergences (test/prism/fixtures_test.rb):
    // 3.4/command_call_do_block_in_arguments.txt, 3.4-4.0/command_call_do_block_in_index_arguments.txt,
    // and pattern_alternation_non_captures.txt (Ruby #22310).
    if (strcmp(cruby_tag, "SyntaxError:unexpected_do_block") == 0) {
        return true;
    }
    if (strstr(exc_buf, "alternative pattern after variable capture") != NULL) {
        return true;
    }

    // RubyVM::AbstractSyntaxTree.parse (ast.c) fails converting valid parse.y
    // NODE_ITER(NODE_DASGN) even when `ruby --parser=parse.y` accepts the code.
    if (strstr(exc_buf, "get_nd_args: unexpected node:") != NULL) {
        return true;
    }

    return false;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!diff_oracle_initialized) {
        diff_oracle_init();
    }

    // Share the 4-byte option header + FUZZ_MAX_INPUT_SIZE cap with parse.c corpus/seeds.
    if (size < 4 || size > FUZZ_MAX_INPUT_SIZE) {
        return 0;
    }

    const uint8_t *source = data + 4;
    size_t source_size = size - 4;

    // CRuby parse.y treats NUL bytes as EOF in lexing and truncates C strings in
    // magic-comment/error helpers, making NUL-containing inputs non-comparable.
    if (diff_has_nul(source, source_size)) {
        return 0;
    }

    bool prism_ok = false;
    size_t prism_errs = 0;
    const char *prism_diag = "ok";
    diff_summary_t prism_ast;
    diff_summary_init(&prism_ast);

    diff_run_prism(source, source_size, &prism_ok, &prism_errs, &prism_diag, &prism_ast);

    bool cruby_ok = false;
    char exc_buf[160];
    char cruby_tag[128];
    volatile VALUE ast_node = diff_run_cruby(
        (const char *) source,
        source_size,
        &cruby_ok,
        exc_buf,
        sizeof(exc_buf),
        cruby_tag,
        sizeof(cruby_tag)
    );

    if (!prism_ok && cruby_ok) {
        diff_run_cruby_compile(
            (const char *) source,
            source_size,
            &cruby_ok,
            exc_buf,
            sizeof(exc_buf),
            cruby_tag,
            sizeof(cruby_tag)
        );
    }

    if (prism_ok != cruby_ok) {
        diff_summary_free(&prism_ast);
        if (diff_ignore_syntax_mismatch(prism_ok, cruby_ok, cruby_tag, exc_buf)) {
            return 0;
        }
        diff_fail_syntax_mismatch(source, source_size, prism_ok, prism_errs, prism_diag, cruby_ok, cruby_tag, exc_buf);
    }

    if (prism_ok && cruby_ok) {
        diff_summary_t cruby_ast;
        diff_summary_init(&cruby_ast);
        diff_collect_cruby_summary(ast_node, &cruby_ast);
        diff_compare_asts(&prism_ast, &cruby_ast);
        diff_summary_free(&cruby_ast);
    }

    RB_GC_GUARD(ast_node);
    diff_summary_free(&prism_ast);
    return 0;
}

#ifndef PRISM_DIFF_NO_MAIN
#ifdef __AFL_FUZZ_INIT
__AFL_FUZZ_INIT();
#endif

static int diff_run_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "fuzz.diff: failed to open '%s': %s\n", path, strerror(errno));
        return 1;
    }

    struct stat st;
    if (fstat(fileno(fp), &st) != 0 || st.st_size < 0) {
        fclose(fp);
        return 1;
    }

    size_t size = (size_t) st.st_size;
    uint8_t *buf = (uint8_t *) malloc(size > 0 ? size : 1);
    if (buf == NULL) {
        fclose(fp);
        return 1;
    }

    size_t read_bytes = size > 0 ? fread(buf, 1, size, fp) : 0;
    int had_error = ferror(fp);
    fclose(fp);

    if (!had_error) {
        LLVMFuzzerTestOneInput(buf, read_bytes);
    }

    free(buf);
    return had_error ? 1 : 0;
}

static int diff_run_stdin(void) {
    size_t cap = 4096;
    size_t len = 0;
    uint8_t *buf = (uint8_t *) malloc(cap);
    if (buf == NULL) {
        return EXIT_FAILURE;
    }

    size_t n;
    while ((n = fread(buf + len, 1, cap - len, stdin)) > 0) {
        len += n;
        if (len == cap) {
            if (cap > SIZE_MAX / 2) {
                free(buf);
                return EXIT_FAILURE;
            }
            cap *= 2;
            uint8_t *next = (uint8_t *) realloc(buf, cap);
            if (next == NULL) {
                free(buf);
                return EXIT_FAILURE;
            }
            buf = next;
        }
    }

    if (ferror(stdin)) {
        free(buf);
        return EXIT_FAILURE;
    }

    LLVMFuzzerTestOneInput(buf, len);
    free(buf);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    diff_oracle_init();

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

#ifdef __AFL_FUZZ_TESTCASE_BUF
    if (__afl_fuzz_ptr != NULL) {
        const uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
        size_t len = (size_t) __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, len);
        return 0;
    }
#endif

    if (argc >= 2) {
        int rc = 0;
        for (int i = 1; i < argc; i++) {
            if (diff_run_file(argv[i]) != 0) {
                rc = 1;
            }
        }
        return rc;
    }

    return diff_run_stdin();
}
#endif

