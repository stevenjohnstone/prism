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

#ifndef FUZZ_DIFF_PERSISTENT_ITERS
#define FUZZ_DIFF_PERSISTENT_ITERS 1000
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

static VALUE diff_rb_mAST = Qnil;
static ID diff_id_parse = 0;
static VALUE diff_rb_cISeq = Qnil;
static ID diff_id_compile = 0;
static ID diff_id_message = 0;

/* Pre-resolve RubyVM constants and IDs so persistent worker forks avoid lazy writes. */
static void diff_core_ids_init(void) {
    if (!NIL_P(diff_rb_mAST)) {
        return;
    }

    VALUE rb_cRubyVM = rb_const_get(rb_cObject, rb_intern("RubyVM"));
    diff_rb_mAST = rb_const_get(rb_cRubyVM, rb_intern("AbstractSyntaxTree"));
    rb_gc_register_mark_object(diff_rb_mAST);
    diff_id_parse = rb_intern("parse");

    diff_rb_cISeq = rb_const_get(rb_cRubyVM, rb_intern("InstructionSequence"));
    rb_gc_register_mark_object(diff_rb_cISeq);
    diff_id_compile = rb_intern("compile");

    diff_id_message = rb_intern("message");
}

static VALUE diff_ast_parse_cb(VALUE src_str) {
    diff_core_ids_init();
    return rb_funcall(diff_rb_mAST, diff_id_parse, 1, src_str);
}

static VALUE diff_iseq_compile_cb(VALUE src_str) {
    diff_core_ids_init();
    return rb_funcall(diff_rb_cISeq, diff_id_compile, 1, src_str);
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

    diff_core_ids_init();
    volatile VALUE msg = rb_funcall(err, diff_id_message, 0);
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
#define DIFF_STACK_TREE_TOKS 128
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

typedef enum {
    DIFF_TOK_CLOSE = 0,
    DIFF_TOK_SCOPE,
    DIFF_TOK_SLOT,
    DIFF_TOK_DEF,
    DIFF_TOK_DEFS,
    DIFF_TOK_CLASS,
    DIFF_TOK_MODULE,
    DIFF_TOK_SCLASS,
    DIFF_TOK_PARAMS,
    DIFF_TOK_PARAM,
    DIFF_TOK_IF,
    DIFF_TOK_UNLESS,
    DIFF_TOK_WHILE,
    DIFF_TOK_UNTIL,
    DIFF_TOK_CASE,
    DIFF_TOK_CASE_MATCH,
    DIFF_TOK_WHEN,
    DIFF_TOK_IN,
    DIFF_TOK_AND,
    DIFF_TOK_OR,
    DIFF_TOK_FOR,
    DIFF_TOK_RESCUE,
    DIFF_TOK_RESBODY,
    DIFF_TOK_ENSURE,
    DIFF_TOK_RETURN,
    DIFF_TOK_BREAK,
    DIFF_TOK_NEXT,
    DIFF_TOK_REDO,
    DIFF_TOK_RETRY,
    DIFF_TOK_YIELD,
    DIFF_TOK_SUPER,
    DIFF_TOK_ZSUPER,
    DIFF_TOK_DEFINED,
    DIFF_TOK_ALIAS,
    DIFF_TOK_VALIAS,
    DIFF_TOK_UNDEF,
    DIFF_TOK_POSTEXE,
    DIFF_TOK_ITER,
    DIFF_TOK_LAMBDA,
    DIFF_TOK_CALL,
    DIFF_TOK_QCALL,
    DIFF_TOK_ATTRASGN,
    DIFF_TOK_OP_ASGN_OR,
    DIFF_TOK_OP_ASGN_AND,
    DIFF_TOK_OP_ASGN1,
    DIFF_TOK_OP_ASGN2,
    DIFF_TOK_OP_CDECL,
    DIFF_TOK_ASGN,
    DIFF_TOK_CDECL,
    DIFF_TOK_MASGN,
    DIFF_TOK_MTARGET,
    DIFF_TOK_TARGET,
    DIFF_TOK_TARGET_SPLAT,
    DIFF_TOK_TARGET_NONE,
    DIFF_TOK_SPLAT,
    DIFF_TOK_BLOCK_PASS,
    DIFF_TOK_ARRAY,
    DIFF_TOK_HASH,
    DIFF_TOK_PAIR,
    DIFF_TOK_PAIR_SPLAT,
    DIFF_TOK_RANGE,
    DIFF_TOK_FLIP,
    DIFF_TOK_CONST,
    DIFF_TOK_COLON2,
    DIFF_TOK_COLON3,
    DIFF_TOK_LVAR,
    DIFF_TOK_IVAR,
    DIFF_TOK_CVAR,
    DIFF_TOK_GVAR,
    DIFF_TOK_NTH_REF,
    DIFF_TOK_BACK_REF,
    DIFF_TOK_SELF,
    DIFF_TOK_NIL,
    DIFF_TOK_TRUE,
    DIFF_TOK_FALSE,
    DIFF_TOK_FILE,
    DIFF_TOK_LINE,
    DIFF_TOK_ENCODING,
    DIFF_TOK_INT,
    DIFF_TOK_FLOAT,
    DIFF_TOK_RATIONAL,
    DIFF_TOK_IMAGINARY,
    DIFF_TOK_STR,
    DIFF_TOK_SYM,
    DIFF_TOK_REGX,
    DIFF_TOK_XSTR,
    DIFF_TOK_DSTR,
    DIFF_TOK_DREGX,
    DIFF_TOK_DXSTR,
    DIFF_TOK_DSYM,
    DIFF_TOK_MATCH_LAST_LINE,
    DIFF_TOK_MATCH_WRITE,
    DIFF_TOK_ARYPTN,
    DIFF_TOK_FNDPTN,
    DIFF_TOK_HSHPTN,
    DIFF_TOK_CAPTURE
} diff_tok_tag_t;

typedef struct {
    uint32_t offset;
    uint32_t length;
} diff_span_t;

typedef struct {
    uint16_t tag;
    diff_span_t label;
} diff_tree_tok_t;

typedef struct {
    diff_tree_tok_t *items;
    size_t count;
    size_t cap;
    bool on_heap;
    diff_tree_tok_t stack[DIFF_STACK_TREE_TOKS];
} diff_tree_tok_vec_t;

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
    diff_tree_tok_vec_t tree;
    size_t counts[DIFF_CNT_LEN];
} diff_summary_t;

typedef struct {
    ID scope, defn, defs, cls, mod, scls, iter, lambda, for_n, postexe;
    ID if_n, unless_n, while_n, until_n, yield_n, return_n, break_n, next_n, redo_n, retry_n;
    ID super_n, zsuper_n, defined_n, alias_n, valias_n, undef_n, case_n, case2_n;
    ID case3_n, in_n, resbody, ensure_n;
    ID masgn;
    ID fcall, vcall, call, qcall, opcall;
    ID and_n, or_n, argscat, argspush, args, opt_arg, kw_arg, postarg;
    ID aryptn, fndptn, hshptn, attrasgn, back_ref, begin_n, block_n, block_pass;
    ID colon2, colon3, const_n, cdecl, cvar, cvasgn, dasgn, dregx, dstr, dsym, dvar, dxstr;
    ID dot2, dot3, encoding_n, errinfo, evstr, false_n, file_n, flip2, flip3, float_n;
    ID for_masgn, gasgn, gvar, hash_n, iasgn, imaginary_n, integer_n, ivar, lasgn, line_n;
    ID list_n, lvar, match_n, match2, match3, nil_n, nth_ref, once_n;
    ID op_asgn1, op_asgn2, op_asgn_and, op_asgn_or, op_cdecl;
    ID rational_n, regx, rescue_n, self_n, splat, str_n, sym_n, true_n, when_n, xstr, zlist;
    ID no_name_rest, no_kw_rest, req_kw, excessive_comma;
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
        { &diff_ids.scope,           "SCOPE" },
        { &diff_ids.defn,            "DEFN" },
        { &diff_ids.defs,            "DEFS" },
        { &diff_ids.cls,             "CLASS" },
        { &diff_ids.mod,             "MODULE" },
        { &diff_ids.scls,            "SCLASS" },
        { &diff_ids.iter,            "ITER" },
        { &diff_ids.lambda,          "LAMBDA" },
        { &diff_ids.for_n,           "FOR" },
        { &diff_ids.postexe,         "POSTEXE" },
        { &diff_ids.if_n,            "IF" },
        { &diff_ids.unless_n,        "UNLESS" },
        { &diff_ids.while_n,         "WHILE" },
        { &diff_ids.until_n,         "UNTIL" },
        { &diff_ids.yield_n,         "YIELD" },
        { &diff_ids.return_n,        "RETURN" },
        { &diff_ids.break_n,         "BREAK" },
        { &diff_ids.next_n,          "NEXT" },
        { &diff_ids.redo_n,          "REDO" },
        { &diff_ids.retry_n,         "RETRY" },
        { &diff_ids.super_n,         "SUPER" },
        { &diff_ids.zsuper_n,        "ZSUPER" },
        { &diff_ids.defined_n,       "DEFINED" },
        { &diff_ids.alias_n,         "ALIAS" },
        { &diff_ids.valias_n,        "VALIAS" },
        { &diff_ids.undef_n,         "UNDEF" },
        { &diff_ids.case_n,          "CASE" },
        { &diff_ids.case2_n,         "CASE2" },
        { &diff_ids.case3_n,         "CASE3" },
        { &diff_ids.in_n,            "IN" },
        { &diff_ids.resbody,         "RESBODY" },
        { &diff_ids.ensure_n,        "ENSURE" },
        { &diff_ids.masgn,           "MASGN" },
        { &diff_ids.fcall,           "FCALL" },
        { &diff_ids.vcall,           "VCALL" },
        { &diff_ids.call,            "CALL" },
        { &diff_ids.qcall,           "QCALL" },
        { &diff_ids.opcall,          "OPCALL" },
        { &diff_ids.and_n,           "AND" },
        { &diff_ids.or_n,            "OR" },
        { &diff_ids.argscat,         "ARGSCAT" },
        { &diff_ids.argspush,        "ARGSPUSH" },
        { &diff_ids.args,            "ARGS" },
        { &diff_ids.opt_arg,         "OPT_ARG" },
        { &diff_ids.kw_arg,          "KW_ARG" },
        { &diff_ids.postarg,         "POSTARG" },
        { &diff_ids.aryptn,          "ARYPTN" },
        { &diff_ids.fndptn,          "FNDPTN" },
        { &diff_ids.hshptn,          "HSHPTN" },
        { &diff_ids.attrasgn,        "ATTRASGN" },
        { &diff_ids.back_ref,        "BACK_REF" },
        { &diff_ids.begin_n,         "BEGIN" },
        { &diff_ids.block_n,         "BLOCK" },
        { &diff_ids.block_pass,      "BLOCK_PASS" },
        { &diff_ids.colon2,          "COLON2" },
        { &diff_ids.colon3,          "COLON3" },
        { &diff_ids.const_n,         "CONST" },
        { &diff_ids.cdecl,           "CDECL" },
        { &diff_ids.cvar,            "CVAR" },
        { &diff_ids.cvasgn,          "CVASGN" },
        { &diff_ids.dasgn,           "DASGN" },
        { &diff_ids.dregx,           "DREGX" },
        { &diff_ids.dstr,            "DSTR" },
        { &diff_ids.dsym,            "DSYM" },
        { &diff_ids.dvar,            "DVAR" },
        { &diff_ids.dxstr,           "DXSTR" },
        { &diff_ids.dot2,            "DOT2" },
        { &diff_ids.dot3,            "DOT3" },
        { &diff_ids.encoding_n,      "ENCODING" },
        { &diff_ids.errinfo,         "ERRINFO" },
        { &diff_ids.evstr,           "EVSTR" },
        { &diff_ids.false_n,         "FALSE" },
        { &diff_ids.file_n,          "FILE" },
        { &diff_ids.flip2,           "FLIP2" },
        { &diff_ids.flip3,           "FLIP3" },
        { &diff_ids.float_n,         "FLOAT" },
        { &diff_ids.for_masgn,       "FOR_MASGN" },
        { &diff_ids.gasgn,           "GASGN" },
        { &diff_ids.gvar,            "GVAR" },
        { &diff_ids.hash_n,          "HASH" },
        { &diff_ids.iasgn,           "IASGN" },
        { &diff_ids.imaginary_n,     "IMAGINARY" },
        { &diff_ids.integer_n,       "INTEGER" },
        { &diff_ids.ivar,            "IVAR" },
        { &diff_ids.lasgn,           "LASGN" },
        { &diff_ids.line_n,          "LINE" },
        { &diff_ids.list_n,          "LIST" },
        { &diff_ids.lvar,            "LVAR" },
        { &diff_ids.match_n,         "MATCH" },
        { &diff_ids.match2,          "MATCH2" },
        { &diff_ids.match3,          "MATCH3" },
        { &diff_ids.nil_n,           "NIL" },
        { &diff_ids.nth_ref,         "NTH_REF" },
        { &diff_ids.once_n,          "ONCE" },
        { &diff_ids.op_asgn1,        "OP_ASGN1" },
        { &diff_ids.op_asgn2,        "OP_ASGN2" },
        { &diff_ids.op_asgn_and,     "OP_ASGN_AND" },
        { &diff_ids.op_asgn_or,      "OP_ASGN_OR" },
        { &diff_ids.op_cdecl,        "OP_CDECL" },
        { &diff_ids.rational_n,      "RATIONAL" },
        { &diff_ids.regx,            "REGX" },
        { &diff_ids.rescue_n,        "RESCUE" },
        { &diff_ids.self_n,          "SELF" },
        { &diff_ids.splat,           "SPLAT" },
        { &diff_ids.str_n,           "STR" },
        { &diff_ids.sym_n,           "SYM" },
        { &diff_ids.true_n,          "TRUE" },
        { &diff_ids.when_n,          "WHEN" },
        { &diff_ids.xstr,            "XSTR" },
        { &diff_ids.zlist,           "ZLIST" },
        { &diff_ids.no_name_rest,    "NODE_SPECIAL_NO_NAME_REST" },
        { &diff_ids.no_kw_rest,      "NODE_SPECIAL_NO_REST_KEYWORD" },
        { &diff_ids.req_kw,          "NODE_SPECIAL_REQUIRED_KEYWORD" },
        { &diff_ids.excessive_comma, "NODE_SPECIAL_EXCESSIVE_COMMA" }
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

static const char *diff_tok_tag_name(diff_tok_tag_t tag) {
    static const char *const names[] = {
        "CLOSE", "SCOPE", "SLOT", "DEF", "DEFS", "CLASS", "MODULE", "SCLASS",
        "PARAMS", "PARAM", "IF", "UNLESS", "WHILE", "UNTIL", "CASE", "CASE_MATCH",
        "WHEN", "IN", "AND", "OR", "FOR", "RESCUE", "RESBODY", "ENSURE",
        "RETURN", "BREAK", "NEXT", "REDO", "RETRY", "YIELD", "SUPER", "ZSUPER",
        "DEFINED", "ALIAS", "VALIAS", "UNDEF", "POSTEXE", "ITER", "LAMBDA",
        "CALL", "QCALL", "ATTRASGN", "OP_ASGN_OR", "OP_ASGN_AND",
        "OP_ASGN1", "OP_ASGN2", "OP_CDECL", "ASGN", "CDECL", "MASGN", "MTARGET",
        "TARGET", "TARGET_SPLAT", "TARGET_NONE", "SPLAT", "BLOCK_PASS",
        "ARRAY", "HASH", "PAIR", "PAIR_SPLAT", "RANGE", "FLIP",
        "CONST", "COLON2", "COLON3", "LVAR", "IVAR", "CVAR", "GVAR",
        "NTH_REF", "BACK_REF", "SELF", "NIL", "TRUE", "FALSE", "FILE", "LINE",
        "ENCODING", "INT", "FLOAT", "RATIONAL", "IMAGINARY",
        "STR", "SYM", "REGX", "XSTR", "DSTR", "DREGX", "DXSTR", "DSYM",
        "MATCH_LAST_LINE", "MATCH_WRITE", "ARYPTN", "FNDPTN", "HSHPTN", "CAPTURE"
    };
    size_t idx = (size_t) tag;
    return idx < (sizeof(names) / sizeof(names[0])) ? names[idx] : "UNKNOWN";
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

static void diff_tree_tok_vec_init(diff_tree_tok_vec_t *v) {
    v->items = v->stack;
    v->count = 0;
    v->cap = DIFF_STACK_TREE_TOKS;
    v->on_heap = false;
}

static void diff_tree_tok_vec_free(diff_tree_tok_vec_t *v) {
    if (v->on_heap) {
        free(v->items);
    }
    diff_tree_tok_vec_init(v);
}

static void diff_tree_tok_vec_push(diff_tree_tok_vec_t *v, diff_tree_tok_t tok) {
    void *items_ptr = v->items;
    diff_ensure_cap(&items_ptr, &v->cap, &v->on_heap, v->stack, v->count, sizeof(diff_tree_tok_t), v->count + 1);
    v->items = (diff_tree_tok_t *) items_ptr;
    v->items[v->count++] = tok;
}

static void diff_tree_open(diff_summary_t *out, diff_tok_tag_t tag, const char *label, size_t len) {
    diff_tree_tok_t tok;
    tok.tag = (uint16_t) tag;
    tok.label = (label != NULL && len > 0) ? diff_strbuf_add(&out->strbuf, label, len) : (diff_span_t) { 0, 0 };
    diff_tree_tok_vec_push(&out->tree, tok);
}

static void diff_tree_open_cstr(diff_summary_t *out, diff_tok_tag_t tag, const char *cstr) {
    diff_tree_open(out, tag, cstr, cstr != NULL ? strlen(cstr) : 0);
}

static void diff_tree_close(diff_summary_t *out) {
    diff_tree_tok_t tok = { (uint16_t) DIFF_TOK_CLOSE, { 0, 0 } };
    diff_tree_tok_vec_push(&out->tree, tok);
}

static void diff_tree_leaf(diff_summary_t *out, diff_tok_tag_t tag, const char *label, size_t len) {
    diff_tree_open(out, tag, label, len);
    diff_tree_close(out);
}

static void diff_tree_leaf_cstr(diff_summary_t *out, diff_tok_tag_t tag, const char *cstr) {
    diff_tree_leaf(out, tag, cstr, cstr != NULL ? strlen(cstr) : 0);
}

static void diff_tree_open_slot(diff_summary_t *out, const char *name) {
    diff_tree_open_cstr(out, DIFF_TOK_SLOT, name);
}

static void diff_tree_open_attrasgn(diff_summary_t *out, const char *name, size_t len) {
    if (len > 1 && name[len - 1] == '=' && !(len == 3 && memcmp(name, "[]=", 3) == 0)) {
        len--;
    }
    diff_tree_open(out, DIFF_TOK_ATTRASGN, name, len);
}

static void diff_summary_init(diff_summary_t *s) {
    diff_strbuf_init(&s->strbuf);
    diff_scope_vec_init(&s->scopes);
    diff_span_vec_init(&s->locals);
    diff_span_vec_init(&s->defs);
    diff_span_vec_init(&s->block_owners);
    diff_tree_tok_vec_init(&s->tree);
    memset(s->counts, 0, sizeof(s->counts));
}

static void diff_summary_free(diff_summary_t *s) {
    diff_strbuf_free(&s->strbuf);
    diff_scope_vec_free(&s->scopes);
    diff_span_vec_free(&s->locals);
    diff_span_vec_free(&s->defs);
    diff_span_vec_free(&s->block_owners);
    diff_tree_tok_vec_free(&s->tree);
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

static void diff_prism_const_buf(
    const pm_parser_t *parser,
    pm_constant_id_t id,
    const char **ptr_out,
    size_t *len_out
) {
    if (id == 0) {
        *ptr_out = NULL;
        *len_out = 0;
        return;
    }
    const pm_constant_t *c = pm_parser_constant(parser, id);
    *ptr_out = (const char *) pm_constant_start(c);
    *len_out = pm_constant_length(c);
}

static void diff_prism_tree_open_const(diff_prism_ctx_t *ctx, diff_tok_tag_t tag, pm_constant_id_t id) {
    const char *ptr = NULL;
    size_t len = 0;
    diff_prism_const_buf(ctx->parser, id, &ptr, &len);
    diff_tree_open(ctx->out, tag, ptr, len);
}

static void diff_prism_tree_leaf_const(diff_prism_ctx_t *ctx, diff_tok_tag_t tag, pm_constant_id_t id) {
    const char *ptr = NULL;
    size_t len = 0;
    diff_prism_const_buf(ctx->parser, id, &ptr, &len);
    diff_tree_leaf(ctx->out, tag, ptr, len);
}

static void diff_prism_emit_tagged_id(
    diff_prism_ctx_t *ctx,
    diff_tok_tag_t tag,
    char prefix,
    pm_constant_id_t id
) {
    const char *ptr = NULL;
    size_t len = 0;
    diff_prism_const_buf(ctx->parser, id, &ptr, &len);
    char stack_buf[128];
    if (len + 2 <= sizeof(stack_buf)) {
        stack_buf[0] = prefix;
        stack_buf[1] = ':';
        if (len > 0) {
            memcpy(stack_buf + 2, ptr, len);
        }
        diff_tree_open(ctx->out, tag, stack_buf, len + 2);
    } else {
        char *heap_buf = (char *) malloc(len + 2);
        if (heap_buf == NULL) {
            abort();
        }
        heap_buf[0] = prefix;
        heap_buf[1] = ':';
        memcpy(heap_buf + 2, ptr, len);
        diff_tree_open(ctx->out, tag, heap_buf, len + 2);
        free(heap_buf);
    }
}

static void diff_prism_visit_expr(const pm_node_t *node, diff_prism_ctx_t *ctx, bool in_args);

static pm_visit_result_t diff_prism_visit_cb(const pm_node_t *node, void *data) {
    diff_prism_visit_expr(node, (diff_prism_ctx_t *) data, false);
    return PM_VISIT_SKIP;
}

static void diff_prism_visit_child(const pm_node_t *child, diff_prism_ctx_t *ctx) {
    if (child != NULL && ctx->depth < DIFF_MAX_AST_DEPTH) {
        diff_prism_visit_expr(child, ctx, false);
    }
}

static void diff_prism_visit_slot(const char *slot, const pm_node_t *child, diff_prism_ctx_t *ctx) {
    diff_tree_open_slot(ctx->out, slot);
    if (child != NULL) {
        diff_prism_visit_child(child, ctx);
    }
    diff_tree_close(ctx->out);
}

static void diff_prism_visit_stmt_list(const pm_statements_node_t *stmts, diff_prism_ctx_t *ctx) {
    if (stmts == NULL) {
        return;
    }
    for (size_t i = 0; i < stmts->body.size; i++) {
        diff_prism_visit_child(stmts->body.nodes[i], ctx);
    }
}

static bool diff_prism_node_is_static_str(const pm_node_t *node) {
    if (node == NULL) {
        return true;
    }
    switch (PM_NODE_TYPE(node)) {
        case PM_STRING_NODE:
            return true;
        case PM_EMBEDDED_STATEMENTS_NODE: {
            const pm_embedded_statements_node_t *emb = (const pm_embedded_statements_node_t *) node;
            if (emb->statements == NULL || emb->statements->body.size != 1) {
                return false;
            }
            return diff_prism_node_is_static_str(emb->statements->body.nodes[0]);
        }
        case PM_INTERPOLATED_STRING_NODE: {
            const pm_interpolated_string_node_t *istr = (const pm_interpolated_string_node_t *) node;
            for (size_t i = 0; i < istr->parts.size; i++) {
                if (!diff_prism_node_is_static_str(istr->parts.nodes[i])) {
                    return false;
                }
            }
            return true;
        }
        default:
            return false;
    }
}

static void diff_prism_visit_interpolated_parts(const pm_node_list_t *parts, diff_prism_ctx_t *ctx) {
    for (size_t i = 0; i < parts->size; i++) {
        const pm_node_t *part = parts->nodes[i];
        if (part == NULL) {
            continue;
        }
        switch (PM_NODE_TYPE(part)) {
            case PM_STRING_NODE:
                break;
            case PM_INTERPOLATED_STRING_NODE: {
                const pm_interpolated_string_node_t *nested = (const pm_interpolated_string_node_t *) part;
                diff_prism_visit_interpolated_parts(&nested->parts, ctx);
                break;
            }
            case PM_EMBEDDED_STATEMENTS_NODE: {
                const pm_embedded_statements_node_t *emb = (const pm_embedded_statements_node_t *) part;
                if (diff_prism_node_is_static_str(part)) {
                    break;
                }
                diff_prism_visit_stmt_list(emb->statements, ctx);
                break;
            }
            case PM_EMBEDDED_VARIABLE_NODE: {
                const pm_embedded_variable_node_t *embv = (const pm_embedded_variable_node_t *) part;
                diff_prism_visit_child(embv->variable, ctx);
                break;
            }
            default:
                diff_prism_visit_child(part, ctx);
                break;
        }
    }
}

static void diff_prism_visit_interpolated(
    const pm_node_list_t *parts,
    diff_tok_tag_t dyn_tag,
    diff_tok_tag_t leaf_tag,
    diff_prism_ctx_t *ctx
) {
    bool all_static = true;
    for (size_t i = 0; i < parts->size; i++) {
        if (!diff_prism_node_is_static_str(parts->nodes[i])) {
            all_static = false;
            break;
        }
    }
    if (all_static) {
        diff_tree_leaf_cstr(ctx->out, leaf_tag, NULL);
        return;
    }
    diff_tree_open_cstr(ctx->out, dyn_tag, NULL);
    diff_prism_visit_interpolated_parts(parts, ctx);
    diff_tree_close(ctx->out);
}

static void diff_prism_emit_forwarding_args(diff_prism_ctx_t *ctx) {
    diff_tree_open_slot(ctx->out, "arg");
    diff_tree_open_cstr(ctx->out, DIFF_TOK_SPLAT, NULL);
    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "*");
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);

    diff_tree_open_slot(ctx->out, "arg");
    diff_tree_open_cstr(ctx->out, DIFF_TOK_HASH, NULL);
    diff_tree_open_cstr(ctx->out, DIFF_TOK_PAIR_SPLAT, NULL);
    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "**");
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);
}

static void diff_prism_emit_arguments(
    const pm_arguments_node_t *args,
    const pm_node_t *block,
    diff_prism_ctx_t *ctx,
    bool emit_blk_slot
) {
    diff_tree_open_slot(ctx->out, "args");
    bool has_fwd = false;
    if (args != NULL) {
        for (size_t i = 0; i < args->arguments.size; i++) {
            const pm_node_t *arg = args->arguments.nodes[i];
            if (arg != NULL && PM_NODE_TYPE_P(arg, PM_FORWARDING_ARGUMENTS_NODE)) {
                has_fwd = true;
                diff_prism_emit_forwarding_args(ctx);
            } else {
                diff_tree_open_slot(ctx->out, "arg");
                if (arg != NULL) {
                    diff_prism_visit_expr(arg, ctx, true);
                }
                diff_tree_close(ctx->out);
            }
        }
    }
    diff_tree_close(ctx->out);

    if (emit_blk_slot) {
        diff_tree_open_slot(ctx->out, "blk");
        if (block != NULL) {
            diff_prism_visit_child(block, ctx);
        } else if (has_fwd) {
            diff_tree_open_cstr(ctx->out, DIFF_TOK_BLOCK_PASS, NULL);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "&");
            diff_tree_close(ctx->out);
        }
        diff_tree_close(ctx->out);
    }
}

static void diff_prism_visit_begin_parts(
    const pm_statements_node_t *statements,
    const pm_rescue_node_t *rescue_clause,
    const pm_else_node_t *else_clause,
    const pm_ensure_node_t *ensure_clause,
    diff_prism_ctx_t *ctx
) {
    if (ensure_clause != NULL) {
        ctx->out->counts[DIFF_CNT_ENSURE]++;
        diff_tree_open_cstr(ctx->out, DIFF_TOK_ENSURE, NULL);
        diff_tree_open_slot(ctx->out, "body");
    }
    if (rescue_clause != NULL) {
        diff_tree_open_cstr(ctx->out, DIFF_TOK_RESCUE, NULL);
        diff_tree_open_slot(ctx->out, "body");
        diff_prism_visit_stmt_list(statements, ctx);
        diff_tree_close(ctx->out);

        diff_tree_open_slot(ctx->out, "resq");
        for (const pm_rescue_node_t *r = rescue_clause; r != NULL; r = r->subsequent) {
            ctx->out->counts[DIFF_CNT_RESCUE]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_RESBODY, NULL);
            diff_tree_open_slot(ctx->out, "exc");
            for (size_t i = 0; i < r->exceptions.size; i++) {
                diff_tree_open_slot(ctx->out, "elem");
                diff_prism_visit_child(r->exceptions.nodes[i], ctx);
                diff_tree_close(ctx->out);
            }
            diff_tree_close(ctx->out);
            diff_prism_visit_slot("var", r->reference, ctx);
            diff_tree_open_slot(ctx->out, "body");
            diff_prism_visit_stmt_list(r->statements, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
        }
        diff_tree_close(ctx->out);

        diff_tree_open_slot(ctx->out, "else");
        if (else_clause != NULL) {
            diff_prism_visit_stmt_list(else_clause->statements, ctx);
        }
        diff_tree_close(ctx->out);
        diff_tree_close(ctx->out);
    } else {
        diff_prism_visit_stmt_list(statements, ctx);
        if (else_clause != NULL) {
            diff_prism_visit_stmt_list(else_clause->statements, ctx);
        }
    }
    if (ensure_clause != NULL) {
        diff_tree_close(ctx->out);
        diff_tree_open_slot(ctx->out, "ens");
        diff_prism_visit_stmt_list(ensure_clause->statements, ctx);
        diff_tree_close(ctx->out);
        diff_tree_close(ctx->out);
    }
}

static bool diff_prism_params_all_empty(const pm_parameters_node_t *p) {
    return p == NULL || (
        p->requireds.size == 0 && p->optionals.size == 0 && p->rest == NULL &&
        p->posts.size == 0 && p->keywords.size == 0 && p->keyword_rest == NULL && p->block == NULL
    );
}

static void diff_prism_visit_params_node(const pm_node_t *pnode, diff_prism_ctx_t *ctx) {
    if (pnode == NULL) {
        return;
    }
    if (PM_NODE_TYPE_P(pnode, PM_BLOCK_PARAMETERS_NODE)) {
        const pm_block_parameters_node_t *bp = (const pm_block_parameters_node_t *) pnode;
        pnode = bp->parameters != NULL ? &bp->parameters->base : NULL;
        if (pnode == NULL) {
            return;
        }
    }
    if (PM_NODE_TYPE_P(pnode, PM_IT_PARAMETERS_NODE)) {
        diff_tree_open_cstr(ctx->out, DIFF_TOK_PARAMS, NULL);
        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "pre=1");
        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "post=0");
        diff_tree_close(ctx->out);
        return;
    }
    if (PM_NODE_TYPE_P(pnode, PM_NUMBERED_PARAMETERS_NODE)) {
        const pm_numbered_parameters_node_t *np = (const pm_numbered_parameters_node_t *) pnode;
        char buf[32];
        snprintf(buf, sizeof(buf), "pre=%u", (unsigned) np->maximum);
        diff_tree_open_cstr(ctx->out, DIFF_TOK_PARAMS, NULL);
        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, buf);
        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "post=0");
        diff_tree_close(ctx->out);
        return;
    }
    if (!PM_NODE_TYPE_P(pnode, PM_PARAMETERS_NODE)) {
        diff_prism_visit_child(pnode, ctx);
        return;
    }
    const pm_parameters_node_t *p = (const pm_parameters_node_t *) pnode;
    if (diff_prism_params_all_empty(p)) {
        return;
    }

    char count_buf[32];
    diff_tree_open_cstr(ctx->out, DIFF_TOK_PARAMS, NULL);
    snprintf(count_buf, sizeof(count_buf), "pre=%zu", p->requireds.size);
    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, count_buf);
    snprintf(count_buf, sizeof(count_buf), "post=%zu", p->posts.size);
    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, count_buf);

    for (size_t i = 0; i < p->requireds.size; i++) {
        if (PM_NODE_TYPE_P(p->requireds.nodes[i], PM_MULTI_TARGET_NODE)) {
            diff_prism_visit_child(p->requireds.nodes[i], ctx);
        }
    }
    for (size_t i = 0; i < p->optionals.size; i++) {
        const pm_node_t *opt = p->optionals.nodes[i];
        if (opt != NULL && PM_NODE_TYPE_P(opt, PM_OPTIONAL_PARAMETER_NODE)) {
            const pm_optional_parameter_node_t *op = (const pm_optional_parameter_node_t *) opt;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_PARAM, 'o', op->name);
            diff_prism_visit_child(op->value, ctx);
            diff_tree_close(ctx->out);
        }
    }
    for (size_t i = 0; i < p->posts.size; i++) {
        if (PM_NODE_TYPE_P(p->posts.nodes[i], PM_MULTI_TARGET_NODE)) {
            diff_prism_visit_child(p->posts.nodes[i], ctx);
        }
    }

    bool has_fwd = p->keyword_rest != NULL && PM_NODE_TYPE_P(p->keyword_rest, PM_FORWARDING_PARAMETER_NODE);
    if (p->rest != NULL) {
        if (PM_NODE_TYPE_P(p->rest, PM_IMPLICIT_REST_NODE)) {
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "comma");
        } else if (PM_NODE_TYPE_P(p->rest, PM_REST_PARAMETER_NODE)) {
            const pm_rest_parameter_node_t *rp = (const pm_rest_parameter_node_t *) p->rest;
            if (rp->name != 0) {
                diff_prism_emit_tagged_id(ctx, DIFF_TOK_PARAM, 'r', rp->name);
                diff_tree_close(ctx->out);
            } else {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "r:*");
            }
        }
    } else if (has_fwd) {
        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "r:*");
    }

    for (size_t i = 0; i < p->keywords.size; i++) {
        const pm_node_t *kw = p->keywords.nodes[i];
        if (kw == NULL) {
            continue;
        }
        if (PM_NODE_TYPE_P(kw, PM_REQUIRED_KEYWORD_PARAMETER_NODE)) {
            const pm_required_keyword_parameter_node_t *rkw = (const pm_required_keyword_parameter_node_t *) kw;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_PARAM, 'k', rkw->name);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SLOT, "req");
            diff_tree_close(ctx->out);
        } else if (PM_NODE_TYPE_P(kw, PM_OPTIONAL_KEYWORD_PARAMETER_NODE)) {
            const pm_optional_keyword_parameter_node_t *okw = (const pm_optional_keyword_parameter_node_t *) kw;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_PARAM, 'k', okw->name);
            diff_prism_visit_child(okw->value, ctx);
            diff_tree_close(ctx->out);
        }
    }

    if (p->keyword_rest != NULL) {
        if (PM_NODE_TYPE_P(p->keyword_rest, PM_NO_KEYWORDS_PARAMETER_NODE)) {
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "nokw");
        } else if (PM_NODE_TYPE_P(p->keyword_rest, PM_FORWARDING_PARAMETER_NODE)) {
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "K:**");
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "b:&");
        } else if (PM_NODE_TYPE_P(p->keyword_rest, PM_KEYWORD_REST_PARAMETER_NODE)) {
            const pm_keyword_rest_parameter_node_t *krp = (const pm_keyword_rest_parameter_node_t *) p->keyword_rest;
            if (krp->name != 0) {
                diff_prism_emit_tagged_id(ctx, DIFF_TOK_PARAM, 'K', krp->name);
                diff_tree_close(ctx->out);
            } else {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "K:**");
            }
        }
    }

    if (p->block != NULL && PM_NODE_TYPE_P(p->block, PM_BLOCK_PARAMETER_NODE)) {
        const pm_block_parameter_node_t *bp = (const pm_block_parameter_node_t *) p->block;
        if (bp->name != 0) {
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_PARAM, 'b', bp->name);
            diff_tree_close(ctx->out);
        } else {
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "b:&");
        }
    }

    diff_tree_close(ctx->out);
}

static void diff_prism_visit_hash_elems(const pm_node_list_t *elements, diff_prism_ctx_t *ctx) {
    diff_tree_open_cstr(ctx->out, DIFF_TOK_HASH, NULL);
    for (size_t i = 0; i < elements->size; i++) {
        const pm_node_t *elem = elements->nodes[i];
        /* CRuby parse.y drops non-initial `**{}` (empty hash splat) during hash construction. */
        if (i > 0 && elem != NULL && PM_NODE_TYPE_P(elem, PM_ASSOC_SPLAT_NODE)) {
            const pm_assoc_splat_node_t *as = (const pm_assoc_splat_node_t *) elem;
            if (as->value != NULL && PM_NODE_TYPE_P(as->value, PM_HASH_NODE) &&
                ((const pm_hash_node_t *) as->value)->elements.size == 0) {
                continue;
            }
        }
        diff_prism_visit_child(elem, ctx);
    }
    diff_tree_close(ctx->out);
}

static void diff_prism_visit_logical(const pm_node_t *node, diff_tok_tag_t tag, pm_node_type_t ntype, diff_prism_ctx_t *ctx) {
    /*
     * CRuby AST::Node#children flattens right-nested AND/OR chains (a && (b && c) vs a && b && c),
     * whereas Prism left-nests unparenthesized chains. Flatten unparenthesized left chains to match.
     */
    const pm_node_t *stack_items[16];
    const pm_node_t **items = stack_items;
    size_t chain_cap = 16;
    size_t chain_len = 0;
    const pm_node_t *cur = node;
    while (cur != NULL && PM_NODE_TYPE_P(cur, ntype)) {
        const pm_node_t *left = NULL;
        const pm_node_t *right = NULL;
        if (ntype == PM_AND_NODE) {
            left = ((const pm_and_node_t *) cur)->left;
            right = ((const pm_and_node_t *) cur)->right;
        } else if (ntype == PM_OR_NODE) {
            left = ((const pm_or_node_t *) cur)->left;
            right = ((const pm_or_node_t *) cur)->right;
        } else {
            left = ((const pm_alternation_pattern_node_t *) cur)->left;
            right = ((const pm_alternation_pattern_node_t *) cur)->right;
        }
        if (chain_len == chain_cap) {
            chain_cap *= 2;
            const pm_node_t **next = (const pm_node_t **) (
                items == stack_items
                    ? malloc(chain_cap * sizeof(const pm_node_t *))
                    : realloc(items, chain_cap * sizeof(const pm_node_t *))
            );
            if (next == NULL) {
                if (items != stack_items) {
                    free(items);
                }
                abort();
            }
            if (items == stack_items) {
                memcpy(next, stack_items, chain_len * sizeof(const pm_node_t *));
            }
            items = next;
        }
        items[chain_len++] = right;
        cur = left;
    }
    diff_tree_open_cstr(ctx->out, tag, NULL);
    diff_prism_visit_child(cur, ctx);
    for (size_t i = chain_len; i > 0; i--) {
        diff_prism_visit_child(items[i - 1], ctx);
    }
    diff_tree_close(ctx->out);
    if (items != stack_items) {
        free(items);
    }
}

static void diff_prism_visit_ret_like(const pm_arguments_node_t *args, diff_tok_tag_t tag, diff_prism_ctx_t *ctx) {
    diff_tree_open_cstr(ctx->out, tag, NULL);
    if (args != NULL) {
        if (args->arguments.size == 1) {
            diff_prism_visit_child(args->arguments.nodes[0], ctx);
        } else if (args->arguments.size > 1) {
            diff_tree_open_cstr(ctx->out, DIFF_TOK_ARRAY, NULL);
            for (size_t i = 0; i < args->arguments.size; i++) {
                diff_tree_open_slot(ctx->out, "elem");
                diff_prism_visit_child(args->arguments.nodes[i], ctx);
                diff_tree_close(ctx->out);
            }
            diff_tree_close(ctx->out);
        }
    }
    diff_tree_close(ctx->out);
}

static void diff_prism_visit_multi_targets(
    const pm_node_list_t *lefts,
    const pm_node_t *rest,
    const pm_node_list_t *rights,
    diff_prism_ctx_t *ctx
) {
    diff_tree_open_slot(ctx->out, "lhs");
    for (size_t i = 0; i < lefts->size; i++) {
        diff_prism_visit_child(lefts->nodes[i], ctx);
    }
    diff_tree_close(ctx->out);

    diff_tree_open_slot(ctx->out, "rest");
    if (rest != NULL && !PM_NODE_TYPE_P(rest, PM_IMPLICIT_REST_NODE)) {
        diff_tree_open_cstr(ctx->out, DIFF_TOK_TARGET_SPLAT, NULL);
        if (PM_NODE_TYPE_P(rest, PM_SPLAT_NODE)) {
            const pm_splat_node_t *sp = (const pm_splat_node_t *) rest;
            if (sp->expression == NULL) {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TARGET_NONE, NULL);
            } else {
                diff_prism_visit_child(sp->expression, ctx);
            }
        } else {
            diff_prism_visit_child(rest, ctx);
        }
        diff_tree_close(ctx->out);
    }
    for (size_t i = 0; i < rights->size; i++) {
        diff_prism_visit_child(rights->nodes[i], ctx);
    }
    diff_tree_close(ctx->out);
}

static void diff_prism_emit_desugared_op_write(
    diff_prism_ctx_t *ctx,
    char var_prefix,
    pm_constant_id_t name,
    pm_constant_id_t bin_op,
    const pm_node_t *value,
    diff_tok_tag_t read_tag,
    bool is_const
) {
    if (is_const) {
        diff_tree_open_cstr(ctx->out, DIFF_TOK_CDECL, NULL);
        diff_prism_tree_leaf_const(ctx, DIFF_TOK_CONST, name);
    } else {
        diff_prism_emit_tagged_id(ctx, DIFF_TOK_ASGN, var_prefix, name);
    }
    diff_prism_tree_open_const(ctx, DIFF_TOK_CALL, bin_op);
    diff_tree_open_slot(ctx->out, "recv");
    diff_prism_tree_leaf_const(ctx, read_tag, name);
    diff_tree_close(ctx->out);
    diff_tree_open_slot(ctx->out, "args");
    diff_tree_open_slot(ctx->out, "arg");
    diff_prism_visit_child(value, ctx);
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);
    diff_tree_open_slot(ctx->out, "blk");
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);
}

static void diff_prism_emit_short_circuit_write(
    diff_prism_ctx_t *ctx,
    diff_tok_tag_t outer_tag,
    char var_prefix,
    pm_constant_id_t name,
    const pm_node_t *value,
    diff_tok_tag_t read_tag,
    bool is_const
) {
    diff_tree_open_cstr(ctx->out, outer_tag, NULL);
    diff_prism_tree_leaf_const(ctx, read_tag, name);
    if (is_const) {
        diff_tree_open_cstr(ctx->out, DIFF_TOK_CDECL, NULL);
        diff_prism_tree_leaf_const(ctx, DIFF_TOK_CONST, name);
    } else {
        diff_prism_emit_tagged_id(ctx, DIFF_TOK_ASGN, var_prefix, name);
    }
    diff_prism_visit_child(value, ctx);
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);
}

static void diff_prism_visit_expr(const pm_node_t *node, diff_prism_ctx_t *ctx, bool in_args) {
    if (node == NULL || ctx->depth >= DIFF_MAX_AST_DEPTH) {
        return;
    }
    ctx->depth++;

    switch (PM_NODE_TYPE(node)) {
        case PM_PROGRAM_NODE: {
            const pm_program_node_t *prog = (const pm_program_node_t *) node;
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_PROGRAM, &prog->locals);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "program");
            if (prog->statements != NULL) {
                const pm_node_list_t *stmts = &prog->statements->body;
                for (int pass = 0; pass < 2; pass++) {
                    bool want_pre = (pass == 0);
                    for (size_t i = 0; i < stmts->size; i++) {
                        const pm_node_t *stmt = stmts->nodes[i];
                        if (stmt != NULL && (PM_NODE_TYPE_P(stmt, PM_PRE_EXECUTION_NODE) != 0) == want_pre) {
                            diff_prism_visit_child(stmt, ctx);
                        }
                    }
                }
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_STATEMENTS_NODE: {
            diff_prism_visit_stmt_list((const pm_statements_node_t *) node, ctx);
            break;
        }
        case PM_PARENTHESES_NODE: {
            const pm_parentheses_node_t *p = (const pm_parentheses_node_t *) node;
            diff_prism_visit_child(p->body, ctx);
            break;
        }
        case PM_ELSE_NODE: {
            const pm_else_node_t *e = (const pm_else_node_t *) node;
            diff_prism_visit_stmt_list(e->statements, ctx);
            break;
        }
        case PM_BEGIN_NODE: {
            const pm_begin_node_t *b = (const pm_begin_node_t *) node;
            diff_prism_visit_begin_parts(b->statements, b->rescue_clause, b->else_clause, b->ensure_clause, ctx);
            break;
        }
        case PM_RESCUE_MODIFIER_NODE: {
            const pm_rescue_modifier_node_t *rm = (const pm_rescue_modifier_node_t *) node;
            ctx->out->counts[DIFF_CNT_RESCUE]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_RESCUE, NULL);
            diff_prism_visit_slot("body", rm->expression, ctx);
            diff_tree_open_slot(ctx->out, "resq");
            diff_tree_open_cstr(ctx->out, DIFF_TOK_RESBODY, NULL);
            diff_tree_open_slot(ctx->out, "exc");
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "var");
            diff_tree_close(ctx->out);
            diff_prism_visit_slot("body", rm->rescue_expression, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "else");
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_PRE_EXECUTION_NODE: {
            const pm_pre_execution_node_t *pre = (const pm_pre_execution_node_t *) node;
            diff_prism_visit_stmt_list(pre->statements, ctx);
            break;
        }
        case PM_POST_EXECUTION_NODE: {
            const pm_post_execution_node_t *post = (const pm_post_execution_node_t *) node;
            ctx->out->counts[DIFF_CNT_POSTEXE]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_POSTEXE, NULL);
            diff_prism_visit_stmt_list(post->statements, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_DEF_NODE: {
            const pm_def_node_t *def_n = (const pm_def_node_t *) node;
            if (def_n->receiver != NULL) {
                diff_prism_tree_open_const(ctx, DIFF_TOK_DEFS, def_n->name);
                diff_prism_visit_slot("recv", def_n->receiver, ctx);
            } else {
                diff_prism_tree_open_const(ctx, DIFF_TOK_DEF, def_n->name);
            }
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_DEF, &def_n->locals);
            diff_prism_add_const(ctx->parser, ctx->out, def_n->name, &ctx->out->defs);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "def");
            if (def_n->parameters != NULL) {
                diff_prism_visit_params_node(&def_n->parameters->base, ctx);
            }
            diff_prism_visit_slot("body", def_n->body, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CLASS_NODE: {
            const pm_class_node_t *cls = (const pm_class_node_t *) node;
            ctx->out->counts[DIFF_CNT_CLASS]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CLASS, NULL);
            diff_prism_visit_slot("cpath", cls->constant_path, ctx);
            diff_prism_visit_slot("super", cls->superclass, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_CLASS, &cls->locals);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "class");
            diff_prism_visit_slot("body", cls->body, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_MODULE_NODE: {
            const pm_module_node_t *mod = (const pm_module_node_t *) node;
            ctx->out->counts[DIFF_CNT_MODULE]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_MODULE, NULL);
            diff_prism_visit_slot("cpath", mod->constant_path, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_MODULE, &mod->locals);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "module");
            diff_prism_visit_slot("body", mod->body, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_SINGLETON_CLASS_NODE: {
            const pm_singleton_class_node_t *scls = (const pm_singleton_class_node_t *) node;
            ctx->out->counts[DIFF_CNT_SCLASS]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCLASS, NULL);
            diff_prism_visit_slot("expr", scls->expression, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_SCLASS, &scls->locals);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "sclass");
            diff_prism_visit_slot("body", scls->body, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_FOR_NODE: {
            const pm_for_node_t *for_n = (const pm_for_node_t *) node;
            ctx->out->counts[DIFF_CNT_FOR]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_FOR, NULL);
            diff_prism_visit_slot("col", for_n->collection, ctx);
            diff_prism_visit_slot("idx", for_n->index, ctx);
            diff_prism_visit_slot("body", for_n->statements != NULL ? &for_n->statements->base : NULL, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_BLOCK_NODE: {
            const pm_block_node_t *blk = (const pm_block_node_t *) node;
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_BLOCK, &blk->locals);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "block");
            diff_prism_visit_params_node(blk->parameters, ctx);
            diff_prism_visit_slot("body", blk->body, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_LAMBDA_NODE: {
            const pm_lambda_node_t *lam = (const pm_lambda_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_LAMBDA, NULL);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_LAMBDA, &lam->locals);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "lambda");
            diff_prism_visit_params_node(lam->parameters, ctx);
            diff_prism_visit_slot("body", lam->body, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CALL_NODE: {
            const pm_call_node_t *call = (const pm_call_node_t *) node;
            if (call->block != NULL && PM_NODE_TYPE_P(call->block, PM_BLOCK_NODE)) {
                diff_prism_add_const(ctx->parser, ctx->out, call->name, &ctx->out->block_owners);
            }
            if (PM_NODE_FLAG_P(call, PM_CALL_NODE_FLAGS_ATTRIBUTE_WRITE)) {
                const char *ptr = NULL;
                size_t len = 0;
                diff_prism_const_buf(ctx->parser, call->name, &ptr, &len);
                if (PM_NODE_FLAG_P(call, PM_CALL_NODE_FLAGS_SAFE_NAVIGATION)) {
                    diff_tree_open_attrasgn(ctx->out, ptr, len);
                } else {
                    diff_tree_open(ctx->out, DIFF_TOK_ATTRASGN, ptr, len);
                }
                diff_prism_visit_slot("recv", call->receiver, ctx);
                diff_prism_emit_arguments(call->arguments, call->block, ctx, false);
                diff_tree_close(ctx->out);
            } else {
                diff_tok_tag_t tag = PM_NODE_FLAG_P(call, PM_CALL_NODE_FLAGS_SAFE_NAVIGATION)
                    ? DIFF_TOK_QCALL
                    : DIFF_TOK_CALL;
                const char *cname = NULL;
                size_t clen = 0;
                diff_prism_const_buf(ctx->parser, call->name, &cname, &clen);
                diff_prism_tree_open_const(ctx, tag, call->name);
                /* CRuby parse.y lowers empty `not()` to `(OPCALL (NIL) :! nil)`. */
                bool is_empty_not = clen == 1 && cname[0] == '!' &&
                    call->message_loc.length == 3 &&
                    call->receiver != NULL &&
                    PM_NODE_TYPE_P(call->receiver, PM_PARENTHESES_NODE) &&
                    ((const pm_parentheses_node_t *) call->receiver)->body == NULL;
                if (is_empty_not) {
                    diff_tree_open_slot(ctx->out, "recv");
                    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_NIL, NULL);
                    diff_tree_close(ctx->out);
                } else {
                    diff_prism_visit_slot("recv", call->receiver, ctx);
                }
                diff_prism_emit_arguments(call->arguments, call->block, ctx, true);
                diff_tree_close(ctx->out);
            }
            break;
        }
        case PM_BLOCK_ARGUMENT_NODE: {
            const pm_block_argument_node_t *ba = (const pm_block_argument_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_BLOCK_PASS, NULL);
            if (ba->expression != NULL) {
                diff_prism_visit_child(ba->expression, ctx);
            } else {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "&");
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_SUPER_NODE: {
            const pm_super_node_t *sup = (const pm_super_node_t *) node;
            ctx->out->counts[DIFF_CNT_SUPER]++;
            if (sup->block != NULL && PM_NODE_TYPE_P(sup->block, PM_BLOCK_NODE)) {
                diff_span_vec_push(&ctx->out->block_owners, diff_strbuf_add(&ctx->out->strbuf, "super", 5));
            }
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SUPER, NULL);
            diff_prism_emit_arguments(sup->arguments, sup->block, ctx, true);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_FORWARDING_SUPER_NODE: {
            const pm_forwarding_super_node_t *fsup = (const pm_forwarding_super_node_t *) node;
            ctx->out->counts[DIFF_CNT_SUPER]++;
            if (fsup->block != NULL && PM_NODE_TYPE_P(&fsup->block->base, PM_BLOCK_NODE)) {
                diff_span_vec_push(&ctx->out->block_owners, diff_strbuf_add(&ctx->out->strbuf, "super", 5));
            }
            diff_tree_open_cstr(ctx->out, DIFF_TOK_ZSUPER, NULL);
            diff_prism_visit_slot("blk", fsup->block != NULL ? &fsup->block->base : NULL, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_YIELD_NODE: {
            const pm_yield_node_t *yn = (const pm_yield_node_t *) node;
            ctx->out->counts[DIFF_CNT_YIELD]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_YIELD, NULL);
            diff_prism_emit_arguments(yn->arguments, NULL, ctx, false);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_RETURN_NODE: {
            const pm_return_node_t *rn = (const pm_return_node_t *) node;
            ctx->out->counts[DIFF_CNT_RETURN]++;
            diff_prism_visit_ret_like(rn->arguments, DIFF_TOK_RETURN, ctx);
            break;
        }
        case PM_BREAK_NODE: {
            const pm_break_node_t *bn = (const pm_break_node_t *) node;
            ctx->out->counts[DIFF_CNT_BREAK]++;
            diff_prism_visit_ret_like(bn->arguments, DIFF_TOK_BREAK, ctx);
            break;
        }
        case PM_NEXT_NODE: {
            const pm_next_node_t *nn = (const pm_next_node_t *) node;
            ctx->out->counts[DIFF_CNT_NEXT]++;
            diff_prism_visit_ret_like(nn->arguments, DIFF_TOK_NEXT, ctx);
            break;
        }
        case PM_REDO_NODE:  ctx->out->counts[DIFF_CNT_REDO]++;  diff_tree_leaf_cstr(ctx->out, DIFF_TOK_REDO, NULL);  break;
        case PM_RETRY_NODE: ctx->out->counts[DIFF_CNT_RETRY]++; diff_tree_leaf_cstr(ctx->out, DIFF_TOK_RETRY, NULL); break;
        case PM_IF_NODE: {
            const pm_if_node_t *ifn = (const pm_if_node_t *) node;
            ctx->out->counts[DIFF_CNT_IF]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_IF, NULL);
            diff_prism_visit_slot("cond", ifn->predicate, ctx);
            diff_tree_open_slot(ctx->out, "then");
            diff_prism_visit_stmt_list(ifn->statements, ctx);
            diff_tree_close(ctx->out);
            diff_prism_visit_slot("else", ifn->subsequent, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_UNLESS_NODE: {
            const pm_unless_node_t *un = (const pm_unless_node_t *) node;
            ctx->out->counts[DIFF_CNT_UNLESS]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_UNLESS, NULL);
            diff_prism_visit_slot("cond", un->predicate, ctx);
            diff_tree_open_slot(ctx->out, "then");
            diff_prism_visit_stmt_list(un->statements, ctx);
            diff_tree_close(ctx->out);
            diff_prism_visit_slot("else", un->else_clause != NULL ? &un->else_clause->base : NULL, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_WHILE_NODE: {
            const pm_while_node_t *wn = (const pm_while_node_t *) node;
            ctx->out->counts[DIFF_CNT_WHILE]++;
            bool post = !PM_NODE_FLAG_P(wn, PM_LOOP_FLAGS_BEGIN_MODIFIER);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_WHILE, post ? "post" : "pre");
            diff_prism_visit_slot("cond", wn->predicate, ctx);
            diff_tree_open_slot(ctx->out, "body");
            diff_prism_visit_stmt_list(wn->statements, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_UNTIL_NODE: {
            const pm_until_node_t *un = (const pm_until_node_t *) node;
            ctx->out->counts[DIFF_CNT_UNTIL]++;
            bool post = !PM_NODE_FLAG_P(un, PM_LOOP_FLAGS_BEGIN_MODIFIER);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_UNTIL, post ? "post" : "pre");
            diff_prism_visit_slot("cond", un->predicate, ctx);
            diff_tree_open_slot(ctx->out, "body");
            diff_prism_visit_stmt_list(un->statements, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CASE_NODE: {
            const pm_case_node_t *cn = (const pm_case_node_t *) node;
            ctx->out->counts[DIFF_CNT_CASE]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CASE, NULL);
            diff_prism_visit_slot("head", cn->predicate, ctx);
            for (size_t i = 0; i < cn->conditions.size; i++) {
                diff_prism_visit_child(cn->conditions.nodes[i], ctx);
            }
            diff_prism_visit_slot("else", cn->else_clause != NULL ? &cn->else_clause->base : NULL, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_WHEN_NODE: {
            const pm_when_node_t *wn = (const pm_when_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_WHEN, NULL);
            diff_tree_open_slot(ctx->out, "conds");
            for (size_t i = 0; i < wn->conditions.size; i++) {
                diff_tree_open_slot(ctx->out, "elem");
                diff_prism_visit_expr(wn->conditions.nodes[i], ctx, true);
                diff_tree_close(ctx->out);
            }
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "body");
            diff_prism_visit_stmt_list(wn->statements, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CASE_MATCH_NODE: {
            const pm_case_match_node_t *cm = (const pm_case_match_node_t *) node;
            ctx->out->counts[DIFF_CNT_CASE_MATCH]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CASE_MATCH, NULL);
            diff_prism_visit_slot("head", cm->predicate, ctx);
            for (size_t i = 0; i < cm->conditions.size; i++) {
                diff_prism_visit_child(cm->conditions.nodes[i], ctx);
            }
            diff_prism_visit_slot("else", cm->else_clause != NULL ? &cm->else_clause->base : NULL, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_IN_NODE: {
            const pm_in_node_t *in_n = (const pm_in_node_t *) node;
            ctx->out->counts[DIFF_CNT_IN]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_IN, NULL);
            diff_prism_visit_slot("pat", in_n->pattern, ctx);
            diff_tree_open_slot(ctx->out, "body");
            diff_prism_visit_stmt_list(in_n->statements, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_MATCH_PREDICATE_NODE: {
            const pm_match_predicate_node_t *mp = (const pm_match_predicate_node_t *) node;
            ctx->out->counts[DIFF_CNT_CASE_MATCH]++;
            ctx->out->counts[DIFF_CNT_IN]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CASE_MATCH, NULL);
            diff_prism_visit_slot("head", mp->value, ctx);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_IN, NULL);
            diff_prism_visit_slot("pat", mp->pattern, ctx);
            diff_tree_open_slot(ctx->out, "body");
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TRUE, NULL);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "else");
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_FALSE, NULL);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_MATCH_REQUIRED_NODE: {
            const pm_match_required_node_t *mr = (const pm_match_required_node_t *) node;
            ctx->out->counts[DIFF_CNT_CASE_MATCH]++;
            ctx->out->counts[DIFF_CNT_IN]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CASE_MATCH, NULL);
            diff_prism_visit_slot("head", mr->value, ctx);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_IN, NULL);
            diff_prism_visit_slot("pat", mr->pattern, ctx);
            diff_tree_open_slot(ctx->out, "body");
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "else");
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_AND_NODE:
            diff_prism_visit_logical(node, DIFF_TOK_AND, PM_AND_NODE, ctx);
            break;
        case PM_OR_NODE:
            diff_prism_visit_logical(node, DIFF_TOK_OR, PM_OR_NODE, ctx);
            break;
        case PM_ALTERNATION_PATTERN_NODE:
            diff_prism_visit_logical(node, DIFF_TOK_OR, PM_ALTERNATION_PATTERN_NODE, ctx);
            break;
        case PM_DEFINED_NODE: {
            const pm_defined_node_t *dn = (const pm_defined_node_t *) node;
            ctx->out->counts[DIFF_CNT_DEFINED]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_DEFINED, NULL);
            diff_prism_visit_child(dn->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_ALIAS_METHOD_NODE: {
            const pm_alias_method_node_t *am = (const pm_alias_method_node_t *) node;
            ctx->out->counts[DIFF_CNT_ALIAS]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_ALIAS, NULL);
            diff_prism_visit_child(am->new_name, ctx);
            diff_prism_visit_child(am->old_name, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_ALIAS_GLOBAL_VARIABLE_NODE: {
            const pm_alias_global_variable_node_t *ag = (const pm_alias_global_variable_node_t *) node;
            ctx->out->counts[DIFF_CNT_ALIAS]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_VALIAS, NULL);
            const pm_node_t *sides[2] = { ag->new_name, ag->old_name };
            for (int si = 0; si < 2; si++) {
                const pm_node_t *sn = sides[si];
                if (sn != NULL && PM_NODE_TYPE_P(sn, PM_BACK_REFERENCE_READ_NODE)) {
                    diff_prism_tree_leaf_const(ctx, DIFF_TOK_GVAR, ((const pm_back_reference_read_node_t *) sn)->name);
                } else if (sn != NULL && PM_NODE_TYPE_P(sn, PM_NUMBERED_REFERENCE_READ_NODE)) {
                    char buf[32];
                    snprintf(buf, sizeof(buf), "$%u", ((const pm_numbered_reference_read_node_t *) sn)->number);
                    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_GVAR, buf);
                } else {
                    diff_prism_visit_child(sn, ctx);
                }
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_UNDEF_NODE: {
            const pm_undef_node_t *un = (const pm_undef_node_t *) node;
            ctx->out->counts[DIFF_CNT_UNDEF]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_UNDEF, NULL);
            for (size_t i = 0; i < un->names.size; i++) {
                diff_prism_visit_child(un->names.nodes[i], ctx);
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_ARRAY_NODE: {
            const pm_array_node_t *an = (const pm_array_node_t *) node;
            if (!in_args && an->elements.size == 1 &&
                PM_NODE_TYPE_P(an->elements.nodes[0], PM_SPLAT_NODE)) {
                diff_prism_visit_child(an->elements.nodes[0], ctx);
                break;
            }
            diff_tree_open_cstr(ctx->out, DIFF_TOK_ARRAY, NULL);
            for (size_t i = 0; i < an->elements.size; i++) {
                diff_tree_open_slot(ctx->out, "elem");
                diff_prism_visit_expr(an->elements.nodes[i], ctx, true);
                diff_tree_close(ctx->out);
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_SPLAT_NODE: {
            const pm_splat_node_t *sp = (const pm_splat_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SPLAT, NULL);
            if (sp->expression != NULL) {
                diff_prism_visit_child(sp->expression, ctx);
            } else {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "*");
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_HASH_NODE:
            diff_prism_visit_hash_elems(&((const pm_hash_node_t *) node)->elements, ctx);
            break;
        case PM_KEYWORD_HASH_NODE:
            diff_prism_visit_hash_elems(&((const pm_keyword_hash_node_t *) node)->elements, ctx);
            break;
        case PM_ASSOC_NODE: {
            const pm_assoc_node_t *assoc = (const pm_assoc_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_PAIR, NULL);
            diff_prism_visit_child(assoc->key, ctx);
            diff_prism_visit_child(assoc->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_ASSOC_SPLAT_NODE: {
            const pm_assoc_splat_node_t *as = (const pm_assoc_splat_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_PAIR_SPLAT, NULL);
            if (as->value != NULL) {
                diff_prism_visit_child(as->value, ctx);
            } else {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "**");
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_IMPLICIT_NODE:
            diff_prism_visit_child(((const pm_implicit_node_t *) node)->value, ctx);
            break;
        case PM_SHAREABLE_CONSTANT_NODE:
            diff_prism_visit_child(((const pm_shareable_constant_node_t *) node)->write, ctx);
            break;
        case PM_PINNED_VARIABLE_NODE:
            diff_prism_visit_child(((const pm_pinned_variable_node_t *) node)->variable, ctx);
            break;
        case PM_PINNED_EXPRESSION_NODE:
            diff_prism_visit_child(((const pm_pinned_expression_node_t *) node)->expression, ctx);
            break;
        case PM_RANGE_NODE: {
            const pm_range_node_t *rn = (const pm_range_node_t *) node;
            bool excl = PM_NODE_FLAG_P(rn, PM_RANGE_FLAGS_EXCLUDE_END);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_RANGE, excl ? "..." : "..");
            const pm_node_t *left = (rn->left != NULL && PM_NODE_TYPE_P(rn->left, PM_NIL_NODE)) ? NULL : rn->left;
            const pm_node_t *right = (rn->right != NULL && PM_NODE_TYPE_P(rn->right, PM_NIL_NODE)) ? NULL : rn->right;
            diff_prism_visit_slot("beg", left, ctx);
            diff_prism_visit_slot("end", right, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_FLIP_FLOP_NODE: {
            const pm_flip_flop_node_t *fn = (const pm_flip_flop_node_t *) node;
            bool excl = PM_NODE_FLAG_P(fn, PM_RANGE_FLAGS_EXCLUDE_END);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_FLIP, excl ? "..." : "..");
            const pm_node_t *left = (fn->left != NULL && PM_NODE_TYPE_P(fn->left, PM_NIL_NODE)) ? NULL : fn->left;
            const pm_node_t *right = (fn->right != NULL && PM_NODE_TYPE_P(fn->right, PM_NIL_NODE)) ? NULL : fn->right;
            diff_prism_visit_slot("beg", left, ctx);
            diff_prism_visit_slot("end", right, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_REQUIRED_PARAMETER_NODE:
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_TARGET, 'l', ((const pm_required_parameter_node_t *) node)->name);
            diff_tree_close(ctx->out);
            break;
        case PM_CONSTANT_READ_NODE:
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_CONST, ((const pm_constant_read_node_t *) node)->name);
            break;
        case PM_CONSTANT_TARGET_NODE:
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_TARGET, 'C', ((const pm_constant_target_node_t *) node)->name);
            diff_tree_close(ctx->out);
            break;
        case PM_CONSTANT_WRITE_NODE: {
            const pm_constant_write_node_t *cw = (const pm_constant_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CDECL, NULL);
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_CONST, cw->name);
            diff_prism_visit_child(cw->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CONSTANT_PATH_NODE: {
            const pm_constant_path_node_t *cp = (const pm_constant_path_node_t *) node;
            if (cp->parent == NULL) {
                diff_prism_tree_leaf_const(ctx, DIFF_TOK_COLON3, cp->name);
            } else {
                diff_prism_tree_open_const(ctx, DIFF_TOK_COLON2, cp->name);
                diff_prism_visit_child(cp->parent, ctx);
                diff_tree_close(ctx->out);
            }
            break;
        }
        case PM_CONSTANT_PATH_TARGET_NODE: {
            const pm_constant_path_target_node_t *cpt = (const pm_constant_path_target_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_TARGET, "cp");
            if (cpt->parent == NULL) {
                diff_prism_tree_leaf_const(ctx, DIFF_TOK_COLON3, cpt->name);
            } else {
                diff_prism_tree_open_const(ctx, DIFF_TOK_COLON2, cpt->name);
                diff_prism_visit_child(cpt->parent, ctx);
                diff_tree_close(ctx->out);
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CONSTANT_PATH_WRITE_NODE: {
            const pm_constant_path_write_node_t *cpw = (const pm_constant_path_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CDECL, NULL);
            diff_prism_visit_child(&cpw->target->base, ctx);
            diff_prism_visit_child(cpw->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CONSTANT_AND_WRITE_NODE: {
            const pm_constant_and_write_node_t *n = (const pm_constant_and_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_AND, 'C', n->name, n->value, DIFF_TOK_CONST, true);
            break;
        }
        case PM_CONSTANT_OR_WRITE_NODE: {
            const pm_constant_or_write_node_t *n = (const pm_constant_or_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_OR, 'C', n->name, n->value, DIFF_TOK_CONST, true);
            break;
        }
        case PM_CONSTANT_OPERATOR_WRITE_NODE: {
            const pm_constant_operator_write_node_t *n = (const pm_constant_operator_write_node_t *) node;
            diff_prism_emit_desugared_op_write(ctx, 'C', n->name, n->binary_operator, n->value, DIFF_TOK_CONST, true);
            break;
        }
        case PM_CONSTANT_PATH_AND_WRITE_NODE: {
            const pm_constant_path_and_write_node_t *n = (const pm_constant_path_and_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_OP_CDECL, "&&");
            diff_prism_visit_slot("target", &n->target->base, ctx);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CONSTANT_PATH_OR_WRITE_NODE: {
            const pm_constant_path_or_write_node_t *n = (const pm_constant_path_or_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_OP_CDECL, "||");
            diff_prism_visit_slot("target", &n->target->base, ctx);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CONSTANT_PATH_OPERATOR_WRITE_NODE: {
            const pm_constant_path_operator_write_node_t *n = (const pm_constant_path_operator_write_node_t *) node;
            diff_prism_tree_open_const(ctx, DIFF_TOK_OP_CDECL, n->binary_operator);
            diff_prism_visit_slot("target", &n->target->base, ctx);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_LOCAL_VARIABLE_READ_NODE:
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_LVAR, ((const pm_local_variable_read_node_t *) node)->name);
            break;
        case PM_IT_LOCAL_VARIABLE_READ_NODE:
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "<it>");
            break;
        case PM_LOCAL_VARIABLE_TARGET_NODE:
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_TARGET, 'l', ((const pm_local_variable_target_node_t *) node)->name);
            diff_tree_close(ctx->out);
            break;
        case PM_LOCAL_VARIABLE_WRITE_NODE: {
            const pm_local_variable_write_node_t *lw = (const pm_local_variable_write_node_t *) node;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_ASGN, 'l', lw->name);
            diff_prism_visit_child(lw->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_LOCAL_VARIABLE_AND_WRITE_NODE: {
            const pm_local_variable_and_write_node_t *n = (const pm_local_variable_and_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_AND, 'l', n->name, n->value, DIFF_TOK_LVAR, false);
            break;
        }
        case PM_LOCAL_VARIABLE_OR_WRITE_NODE: {
            const pm_local_variable_or_write_node_t *n = (const pm_local_variable_or_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_OR, 'l', n->name, n->value, DIFF_TOK_LVAR, false);
            break;
        }
        case PM_LOCAL_VARIABLE_OPERATOR_WRITE_NODE: {
            const pm_local_variable_operator_write_node_t *n = (const pm_local_variable_operator_write_node_t *) node;
            diff_prism_emit_desugared_op_write(ctx, 'l', n->name, n->binary_operator, n->value, DIFF_TOK_LVAR, false);
            break;
        }
        case PM_INSTANCE_VARIABLE_READ_NODE:
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_IVAR, ((const pm_instance_variable_read_node_t *) node)->name);
            break;
        case PM_INSTANCE_VARIABLE_TARGET_NODE:
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_TARGET, 'i', ((const pm_instance_variable_target_node_t *) node)->name);
            diff_tree_close(ctx->out);
            break;
        case PM_INSTANCE_VARIABLE_WRITE_NODE: {
            const pm_instance_variable_write_node_t *n = (const pm_instance_variable_write_node_t *) node;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_ASGN, 'i', n->name);
            diff_prism_visit_child(n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_INSTANCE_VARIABLE_AND_WRITE_NODE: {
            const pm_instance_variable_and_write_node_t *n = (const pm_instance_variable_and_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_AND, 'i', n->name, n->value, DIFF_TOK_IVAR, false);
            break;
        }
        case PM_INSTANCE_VARIABLE_OR_WRITE_NODE: {
            const pm_instance_variable_or_write_node_t *n = (const pm_instance_variable_or_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_OR, 'i', n->name, n->value, DIFF_TOK_IVAR, false);
            break;
        }
        case PM_INSTANCE_VARIABLE_OPERATOR_WRITE_NODE: {
            const pm_instance_variable_operator_write_node_t *n = (const pm_instance_variable_operator_write_node_t *) node;
            diff_prism_emit_desugared_op_write(ctx, 'i', n->name, n->binary_operator, n->value, DIFF_TOK_IVAR, false);
            break;
        }
        case PM_CLASS_VARIABLE_READ_NODE:
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_CVAR, ((const pm_class_variable_read_node_t *) node)->name);
            break;
        case PM_CLASS_VARIABLE_TARGET_NODE:
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_TARGET, 'c', ((const pm_class_variable_target_node_t *) node)->name);
            diff_tree_close(ctx->out);
            break;
        case PM_CLASS_VARIABLE_WRITE_NODE: {
            const pm_class_variable_write_node_t *n = (const pm_class_variable_write_node_t *) node;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_ASGN, 'c', n->name);
            diff_prism_visit_child(n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CLASS_VARIABLE_AND_WRITE_NODE: {
            const pm_class_variable_and_write_node_t *n = (const pm_class_variable_and_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_AND, 'c', n->name, n->value, DIFF_TOK_CVAR, false);
            break;
        }
        case PM_CLASS_VARIABLE_OR_WRITE_NODE: {
            const pm_class_variable_or_write_node_t *n = (const pm_class_variable_or_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_OR, 'c', n->name, n->value, DIFF_TOK_CVAR, false);
            break;
        }
        case PM_CLASS_VARIABLE_OPERATOR_WRITE_NODE: {
            const pm_class_variable_operator_write_node_t *n = (const pm_class_variable_operator_write_node_t *) node;
            diff_prism_emit_desugared_op_write(ctx, 'c', n->name, n->binary_operator, n->value, DIFF_TOK_CVAR, false);
            break;
        }
        case PM_GLOBAL_VARIABLE_READ_NODE:
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_GVAR, ((const pm_global_variable_read_node_t *) node)->name);
            break;
        case PM_GLOBAL_VARIABLE_TARGET_NODE:
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_TARGET, 'g', ((const pm_global_variable_target_node_t *) node)->name);
            diff_tree_close(ctx->out);
            break;
        case PM_GLOBAL_VARIABLE_WRITE_NODE: {
            const pm_global_variable_write_node_t *n = (const pm_global_variable_write_node_t *) node;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_ASGN, 'g', n->name);
            diff_prism_visit_child(n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_GLOBAL_VARIABLE_AND_WRITE_NODE: {
            const pm_global_variable_and_write_node_t *n = (const pm_global_variable_and_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_AND, 'g', n->name, n->value, DIFF_TOK_GVAR, false);
            break;
        }
        case PM_GLOBAL_VARIABLE_OR_WRITE_NODE: {
            const pm_global_variable_or_write_node_t *n = (const pm_global_variable_or_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_OR, 'g', n->name, n->value, DIFF_TOK_GVAR, false);
            break;
        }
        case PM_GLOBAL_VARIABLE_OPERATOR_WRITE_NODE: {
            const pm_global_variable_operator_write_node_t *n = (const pm_global_variable_operator_write_node_t *) node;
            diff_prism_emit_desugared_op_write(ctx, 'g', n->name, n->binary_operator, n->value, DIFF_TOK_GVAR, false);
            break;
        }
        case PM_CALL_AND_WRITE_NODE: {
            const pm_call_and_write_node_t *n = (const pm_call_and_write_node_t *) node;
            bool q = PM_NODE_FLAG_P(n, PM_CALL_NODE_FLAGS_SAFE_NAVIGATION);
            const char *vid = NULL;
            size_t vlen = 0;
            diff_prism_const_buf(ctx->parser, n->read_name, &vid, &vlen);
            diff_tree_open(ctx->out, DIFF_TOK_OP_ASGN2, vid, vlen);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SLOT, q ? "1" : "0");
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SLOT, "&&");
            diff_prism_visit_slot("recv", n->receiver, ctx);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CALL_OR_WRITE_NODE: {
            const pm_call_or_write_node_t *n = (const pm_call_or_write_node_t *) node;
            bool q = PM_NODE_FLAG_P(n, PM_CALL_NODE_FLAGS_SAFE_NAVIGATION);
            const char *vid = NULL;
            size_t vlen = 0;
            diff_prism_const_buf(ctx->parser, n->read_name, &vid, &vlen);
            diff_tree_open(ctx->out, DIFF_TOK_OP_ASGN2, vid, vlen);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SLOT, q ? "1" : "0");
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SLOT, "||");
            diff_prism_visit_slot("recv", n->receiver, ctx);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CALL_OPERATOR_WRITE_NODE: {
            const pm_call_operator_write_node_t *n = (const pm_call_operator_write_node_t *) node;
            bool q = PM_NODE_FLAG_P(n, PM_CALL_NODE_FLAGS_SAFE_NAVIGATION);
            const char *vid = NULL, *op = NULL;
            size_t vlen = 0, olen = 0;
            diff_prism_const_buf(ctx->parser, n->read_name, &vid, &vlen);
            diff_prism_const_buf(ctx->parser, n->binary_operator, &op, &olen);
            diff_tree_open(ctx->out, DIFF_TOK_OP_ASGN2, vid, vlen);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SLOT, q ? "1" : "0");
            diff_tree_leaf(ctx->out, DIFF_TOK_SLOT, op, olen);
            diff_prism_visit_slot("recv", n->receiver, ctx);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CALL_TARGET_NODE: {
            const pm_call_target_node_t *ct = (const pm_call_target_node_t *) node;
            const char *ptr = NULL;
            size_t len = 0;
            diff_prism_const_buf(ctx->parser, ct->name, &ptr, &len);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_TARGET, "attr");
            if (PM_NODE_FLAG_P(ct, PM_CALL_NODE_FLAGS_SAFE_NAVIGATION)) {
                diff_prism_const_buf(ctx->parser, ct->name, &ptr, &len);
                diff_tree_open_attrasgn(ctx->out, ptr, len);
            } else {
                diff_tree_open(ctx->out, DIFF_TOK_ATTRASGN, ptr, len);
            }
            diff_prism_visit_slot("recv", ct->receiver, ctx);
            diff_tree_open_slot(ctx->out, "args");
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_INDEX_AND_WRITE_NODE: {
            const pm_index_and_write_node_t *n = (const pm_index_and_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_OP_ASGN1, "&&");
            diff_prism_visit_slot("recv", n->receiver, ctx);
            diff_prism_emit_arguments(n->arguments, n->block != NULL ? &n->block->base : NULL, ctx, false);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_INDEX_OR_WRITE_NODE: {
            const pm_index_or_write_node_t *n = (const pm_index_or_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_OP_ASGN1, "||");
            diff_prism_visit_slot("recv", n->receiver, ctx);
            diff_prism_emit_arguments(n->arguments, n->block != NULL ? &n->block->base : NULL, ctx, false);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_INDEX_OPERATOR_WRITE_NODE: {
            const pm_index_operator_write_node_t *n = (const pm_index_operator_write_node_t *) node;
            diff_prism_tree_open_const(ctx, DIFF_TOK_OP_ASGN1, n->binary_operator);
            diff_prism_visit_slot("recv", n->receiver, ctx);
            diff_prism_emit_arguments(n->arguments, n->block != NULL ? &n->block->base : NULL, ctx, false);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_INDEX_TARGET_NODE: {
            const pm_index_target_node_t *it = (const pm_index_target_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_TARGET, "attr");
            diff_tree_open_cstr(ctx->out, DIFF_TOK_ATTRASGN, "[]=");
            diff_prism_visit_slot("recv", it->receiver, ctx);
            diff_prism_emit_arguments(it->arguments, it->block != NULL ? &it->block->base : NULL, ctx, false);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_MULTI_WRITE_NODE: {
            const pm_multi_write_node_t *mw = (const pm_multi_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_MASGN, NULL);
            diff_prism_visit_multi_targets(&mw->lefts, mw->rest, &mw->rights, ctx);
            diff_prism_visit_slot("rhs", mw->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_MULTI_TARGET_NODE: {
            const pm_multi_target_node_t *mt = (const pm_multi_target_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_MTARGET, NULL);
            diff_prism_visit_multi_targets(&mt->lefts, mt->rest, &mt->rights, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_MATCH_WRITE_NODE: {
            const pm_match_write_node_t *mw = (const pm_match_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_MATCH_WRITE, NULL);
            diff_prism_visit_child(&mw->call->base, ctx);
            for (size_t i = 0; i < mw->targets.size; i++) {
                diff_prism_visit_child(mw->targets.nodes[i], ctx);
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_NUMBERED_REFERENCE_READ_NODE: {
            const pm_numbered_reference_read_node_t *nr = (const pm_numbered_reference_read_node_t *) node;
            char buf[32];
            snprintf(buf, sizeof(buf), "$%u", nr->number);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_NTH_REF, buf);
            break;
        }
        case PM_BACK_REFERENCE_READ_NODE:
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_BACK_REF, ((const pm_back_reference_read_node_t *) node)->name);
            break;
        case PM_SELF_NODE:            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SELF, NULL);     break;
        case PM_NIL_NODE:             diff_tree_leaf_cstr(ctx->out, DIFF_TOK_NIL, NULL);      break;
        case PM_TRUE_NODE:            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TRUE, NULL);     break;
        case PM_FALSE_NODE:           diff_tree_leaf_cstr(ctx->out, DIFF_TOK_FALSE, NULL);    break;
        case PM_SOURCE_FILE_NODE:     diff_tree_leaf_cstr(ctx->out, DIFF_TOK_FILE, NULL);     break;
        case PM_SOURCE_LINE_NODE:     diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LINE, NULL);     break;
        case PM_SOURCE_ENCODING_NODE: diff_tree_leaf_cstr(ctx->out, DIFF_TOK_ENCODING, NULL); break;
        case PM_INTEGER_NODE:         diff_tree_leaf_cstr(ctx->out, DIFF_TOK_INT, NULL);      break;
        case PM_FLOAT_NODE:           diff_tree_leaf_cstr(ctx->out, DIFF_TOK_FLOAT, NULL);    break;
        case PM_RATIONAL_NODE:        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_RATIONAL, NULL); break;
        case PM_IMAGINARY_NODE:       diff_tree_leaf_cstr(ctx->out, DIFF_TOK_IMAGINARY, NULL); break;
        case PM_STRING_NODE:          diff_tree_leaf_cstr(ctx->out, DIFF_TOK_STR, NULL);      break;
        case PM_SYMBOL_NODE:          diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SYM, NULL);      break;
        case PM_REGULAR_EXPRESSION_NODE: diff_tree_leaf_cstr(ctx->out, DIFF_TOK_REGX, NULL);  break;
        case PM_X_STRING_NODE:        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_XSTR, NULL);     break;
        case PM_MATCH_LAST_LINE_NODE: diff_tree_leaf_cstr(ctx->out, DIFF_TOK_MATCH_LAST_LINE, NULL); break;
        case PM_INTERPOLATED_STRING_NODE:
            diff_prism_visit_interpolated(&((const pm_interpolated_string_node_t *) node)->parts, DIFF_TOK_DSTR, DIFF_TOK_STR, ctx);
            break;
        case PM_INTERPOLATED_SYMBOL_NODE:
            diff_prism_visit_interpolated(&((const pm_interpolated_symbol_node_t *) node)->parts, DIFF_TOK_DSYM, DIFF_TOK_SYM, ctx);
            break;
        case PM_INTERPOLATED_REGULAR_EXPRESSION_NODE:
            diff_prism_visit_interpolated(&((const pm_interpolated_regular_expression_node_t *) node)->parts, DIFF_TOK_DREGX, DIFF_TOK_REGX, ctx);
            break;
        case PM_INTERPOLATED_X_STRING_NODE:
            diff_prism_visit_interpolated(&((const pm_interpolated_x_string_node_t *) node)->parts, DIFF_TOK_DXSTR, DIFF_TOK_XSTR, ctx);
            break;
        case PM_INTERPOLATED_MATCH_LAST_LINE_NODE:
            diff_prism_visit_interpolated(&((const pm_interpolated_match_last_line_node_t *) node)->parts, DIFF_TOK_DREGX, DIFF_TOK_MATCH_LAST_LINE, ctx);
            break;
        case PM_ARRAY_PATTERN_NODE: {
            const pm_array_pattern_node_t *ap = (const pm_array_pattern_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_ARYPTN, NULL);
            diff_prism_visit_slot("const", ap->constant, ctx);
            diff_tree_open_slot(ctx->out, "pre");
            for (size_t i = 0; i < ap->requireds.size; i++) {
                diff_tree_open_slot(ctx->out, "elem");
                diff_prism_visit_child(ap->requireds.nodes[i], ctx);
                diff_tree_close(ctx->out);
            }
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "rest");
            if (ap->rest != NULL) {
                if (PM_NODE_TYPE_P(ap->rest, PM_IMPLICIT_REST_NODE)) {
                    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TARGET_NONE, NULL);
                } else if (PM_NODE_TYPE_P(ap->rest, PM_SPLAT_NODE)) {
                    const pm_splat_node_t *sp = (const pm_splat_node_t *) ap->rest;
                    if (sp->expression == NULL) {
                        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TARGET_NONE, NULL);
                    } else {
                        diff_prism_visit_child(sp->expression, ctx);
                    }
                } else {
                    diff_prism_visit_child(ap->rest, ctx);
                }
            }
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "post");
            for (size_t i = 0; i < ap->posts.size; i++) {
                diff_tree_open_slot(ctx->out, "elem");
                diff_prism_visit_child(ap->posts.nodes[i], ctx);
                diff_tree_close(ctx->out);
            }
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_FIND_PATTERN_NODE: {
            const pm_find_pattern_node_t *fp = (const pm_find_pattern_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_FNDPTN, NULL);
            diff_prism_visit_slot("const", fp->constant, ctx);
            diff_tree_open_slot(ctx->out, "pre");
            if (fp->left != NULL) {
                if (fp->left->expression == NULL) {
                    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TARGET_NONE, NULL);
                } else {
                    diff_prism_visit_child(fp->left->expression, ctx);
                }
            }
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "mid");
            for (size_t i = 0; i < fp->requireds.size; i++) {
                diff_tree_open_slot(ctx->out, "elem");
                diff_prism_visit_child(fp->requireds.nodes[i], ctx);
                diff_tree_close(ctx->out);
            }
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "post");
            if (fp->right != NULL) {
                if (fp->right->expression == NULL) {
                    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TARGET_NONE, NULL);
                } else {
                    diff_prism_visit_child(fp->right->expression, ctx);
                }
            }
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_HASH_PATTERN_NODE: {
            const pm_hash_pattern_node_t *hp = (const pm_hash_pattern_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_HSHPTN, NULL);
            diff_prism_visit_slot("const", hp->constant, ctx);
            diff_tree_open_slot(ctx->out, "kw");
            diff_prism_visit_hash_elems(&hp->elements, ctx);
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "kwrest");
            if (hp->rest != NULL) {
                if (PM_NODE_TYPE_P(hp->rest, PM_NO_KEYWORDS_PARAMETER_NODE)) {
                    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TARGET_NONE, "nokw");
                } else if (PM_NODE_TYPE_P(hp->rest, PM_ASSOC_SPLAT_NODE)) {
                    const pm_assoc_splat_node_t *as = (const pm_assoc_splat_node_t *) hp->rest;
                    if (as->value != NULL) {
                        diff_prism_visit_child(as->value, ctx);
                    }
                } else {
                    diff_prism_visit_child(hp->rest, ctx);
                }
            }
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CAPTURE_PATTERN_NODE: {
            const pm_capture_pattern_node_t *cp = (const pm_capture_pattern_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CAPTURE, NULL);
            diff_prism_visit_child(cp->value, ctx);
            diff_prism_visit_child(&cp->target->base, ctx);
            diff_tree_close(ctx->out);
            break;
        }
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
    diff_prism_visit_expr(root, &ctx, false);
    diff_finalize_summary(out);
}

static bool diff_cruby_is_ast_node(VALUE v) {
    return RB_TYPE_P(v, T_DATA) && rb_obj_is_kind_of(v, rb_cASTNode);
}

static ID diff_cruby_node_tid(VALUE node) {
    if (!diff_cruby_is_ast_node(node)) {
        return 0;
    }
    volatile VALUE type_sym = rb_funcall(node, id_type, 0);
    ID tid = SYMBOL_P(type_sym) ? SYM2ID(type_sym) : 0;
    RB_GC_GUARD(type_sym);
    return tid;
}

static bool diff_cruby_sym_bytes(VALUE sym, const char **ptr_out, size_t *len_out) {
    if (!SYMBOL_P(sym)) {
        return false;
    }
    volatile VALUE sym_str = rb_sym2str(sym);
    if (sym_str && RB_TYPE_P(sym_str, T_STRING)) {
        *ptr_out = RSTRING_PTR(sym_str);
        *len_out = (size_t) RSTRING_LEN(sym_str);
        RB_GC_GUARD(sym_str);
        return true;
    }
    RB_GC_GUARD(sym_str);
    return false;
}

static void diff_cruby_add_sym(VALUE sym, diff_summary_t *out, diff_span_vec_t *vec) {
    const char *ptr = NULL;
    size_t len = 0;
    if (!SYMBOL_P(sym)) {
        diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, "<nil>", 5));
        return;
    }
    if (diff_cruby_sym_bytes(sym, &ptr, &len)) {
        diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, ptr, len));
    } else {
        diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, "<sym>", 5));
    }
}

static void diff_cruby_tree_open_sym(VALUE sym, diff_tok_tag_t tag, diff_summary_t *out) {
    const char *ptr = NULL;
    size_t len = 0;
    if (diff_cruby_sym_bytes(sym, &ptr, &len)) {
        diff_tree_open(out, tag, ptr, len);
    } else {
        diff_tree_open_cstr(out, tag, "<sym>");
    }
}

static void diff_cruby_tree_leaf_sym(VALUE sym, diff_tok_tag_t tag, diff_summary_t *out) {
    diff_cruby_tree_open_sym(sym, tag, out);
    diff_tree_close(out);
}

static void diff_cruby_emit_tagged_sym(VALUE sym, diff_tok_tag_t tag, char prefix, diff_summary_t *out) {
    const char *ptr = NULL;
    size_t len = 0;
    if (!diff_cruby_sym_bytes(sym, &ptr, &len)) {
        ptr = "<sym>";
        len = 5;
    }
    char stack_buf[128];
    if (len + 2 <= sizeof(stack_buf)) {
        stack_buf[0] = prefix;
        stack_buf[1] = ':';
        if (len > 0) {
            memcpy(stack_buf + 2, ptr, len);
        }
        diff_tree_open(out, tag, stack_buf, len + 2);
    } else {
        char *heap_buf = (char *) malloc(len + 2);
        if (heap_buf == NULL) {
            abort();
        }
        heap_buf[0] = prefix;
        heap_buf[1] = ':';
        memcpy(heap_buf + 2, ptr, len);
        diff_tree_open(out, tag, heap_buf, len + 2);
        free(heap_buf);
    }
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
        const char *ptr = NULL;
        size_t len = 0;
        if (!diff_cruby_sym_bytes(sym, &ptr, &len)) {
            continue;
        }
        if (!diff_is_synthetic_local(ptr, len)) {
            diff_span_vec_push(&out->locals, diff_strbuf_add(&out->strbuf, ptr, len));
            added++;
        }
    }
    sc.local_count = added;
    diff_scope_vec_push(&out->scopes, sc);
}

typedef struct {
    diff_summary_t *out;
    int depth;
    bool in_target;
    bool in_pattern;
    bool in_container;
} diff_cruby_ctx_t;

static void diff_cruby_visit_val_ctx(VALUE val, diff_cruby_ctx_t ctx);

static void diff_cruby_visit_slot(const char *slot, VALUE val, diff_cruby_ctx_t ctx) {
    diff_tree_open_slot(ctx.out, slot);
    if (!NIL_P(val)) {
        diff_cruby_visit_val_ctx(val, ctx);
    }
    diff_tree_close(ctx.out);
}

static bool diff_cruby_sym_is(VALUE v, ID expected) {
    return SYMBOL_P(v) && SYM2ID(v) == expected;
}

static VALUE diff_cruby_get_children(VALUE node, diff_summary_t *out, ID *tid_out) {
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
    *tid_out = tid;
    RB_GC_GUARD(type_sym);
    return ch;
}

static void diff_cruby_emit_seq_elems(VALUE val, const char *slot_name, diff_cruby_ctx_t ctx, bool skip_errinfo) {
    if (ctx.depth >= DIFF_MAX_AST_DEPTH || NIL_P(val) || !diff_cruby_is_ast_node(val)) {
        return;
    }
    ID tid = 0;
    volatile VALUE ch = diff_cruby_get_children(val, ctx.out, &tid);
    long len = RARRAY_LEN(ch);

    if (tid == diff_ids.zlist) {
        /* empty */
    } else if (tid == diff_ids.list_n) {
        diff_cruby_ctx_t elem_ctx = ctx;
        elem_ctx.depth = ctx.depth + 1;
        elem_ctx.in_container = true;
        for (long i = 0; i < len; i++) {
            VALUE item = RARRAY_AREF(ch, i);
            if (NIL_P(item)) {
                continue;
            }
            if (skip_errinfo && diff_cruby_node_tid(item) == diff_ids.errinfo) {
                continue;
            }
            diff_tree_open_slot(ctx.out, slot_name);
            diff_cruby_visit_val_ctx(item, elem_ctx);
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.argscat && len >= 2) {
        diff_cruby_ctx_t sub = ctx;
        sub.depth = ctx.depth + 1;
        VALUE head = RARRAY_AREF(ch, 0);
        ID htid = diff_cruby_node_tid(head);
        if (htid == diff_ids.splat) {
            diff_tree_open_slot(ctx.out, slot_name);
            diff_cruby_visit_val_ctx(head, sub);
            diff_tree_close(ctx.out);
        } else {
            diff_cruby_emit_seq_elems(head, slot_name, sub, skip_errinfo);
        }
        diff_tree_open_slot(ctx.out, slot_name);
        diff_tree_open_cstr(ctx.out, DIFF_TOK_SPLAT, NULL);
        sub.in_container = false;
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 1), sub);
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.argspush && len >= 2) {
        diff_cruby_ctx_t sub = ctx;
        sub.depth = ctx.depth + 1;
        VALUE head = RARRAY_AREF(ch, 0);
        VALUE tail_item = RARRAY_AREF(ch, 1);
        ID htid = diff_cruby_node_tid(head);
        if (htid == diff_ids.splat) {
            diff_tree_open_slot(ctx.out, slot_name);
            diff_cruby_visit_val_ctx(head, sub);
            diff_tree_close(ctx.out);
        } else {
            diff_cruby_emit_seq_elems(head, slot_name, sub, skip_errinfo);
        }
        if (!(skip_errinfo && diff_cruby_node_tid(tail_item) == diff_ids.errinfo)) {
            diff_tree_open_slot(ctx.out, slot_name);
            sub.in_container = true;
            diff_cruby_visit_val_ctx(tail_item, sub);
            diff_tree_close(ctx.out);
        }
    } else {
        diff_cruby_ctx_t sub = ctx;
        sub.depth = ctx.depth + 1;
        sub.in_container = false;
        diff_tree_open_slot(ctx.out, slot_name);
        diff_cruby_visit_val_ctx(val, sub);
        diff_tree_close(ctx.out);
    }
    RB_GC_GUARD(ch);
}

static void diff_cruby_emit_call_args_and_blk(VALUE args_node, VALUE iter_block, diff_cruby_ctx_t ctx, bool emit_blk_slot) {
    VALUE blk_pass_body = Qnil;
    VALUE real_args = args_node;
    if (diff_cruby_is_ast_node(args_node) && diff_cruby_node_tid(args_node) == diff_ids.block_pass) {
        ID bt = 0;
        volatile VALUE bch = diff_cruby_get_children(args_node, ctx.out, &bt);
        if (RARRAY_LEN(bch) >= 2) {
            real_args = RARRAY_AREF(bch, 0);
            blk_pass_body = RARRAY_AREF(bch, 1);
        }
        RB_GC_GUARD(bch);
    }

    diff_tree_open_slot(ctx.out, "args");
    diff_cruby_emit_seq_elems(real_args, "arg", ctx, false);
    diff_tree_close(ctx.out);

    if (emit_blk_slot) {
        diff_tree_open_slot(ctx.out, "blk");
        if (!NIL_P(iter_block)) {
            diff_cruby_ctx_t bctx = ctx;
            bctx.depth = ctx.depth + 1;
            bctx.in_target = false;
            bctx.in_pattern = false;
            bctx.in_container = false;
            if (diff_cruby_node_tid(iter_block) == diff_ids.scope) {
                /* handled cleanly via scope child */
                ID st = 0;
                volatile VALUE sch = diff_cruby_get_children(iter_block, ctx.out, &st);
                if (RARRAY_LEN(sch) >= 3) {
                    diff_cruby_extract_scope_locals(RARRAY_AREF(sch, 0), DIFF_SCOPE_BLOCK, ctx.out);
                    diff_tree_open_cstr(ctx.out, DIFF_TOK_SCOPE, "block");
                    if (!NIL_P(RARRAY_AREF(sch, 1))) {
                        diff_cruby_visit_val_ctx(RARRAY_AREF(sch, 1), bctx);
                    }
                    diff_cruby_visit_slot("body", RARRAY_AREF(sch, 2), bctx);
                    diff_tree_close(ctx.out);
                }
                RB_GC_GUARD(sch);
            } else {
                diff_cruby_visit_val_ctx(iter_block, bctx);
            }
        } else if (!NIL_P(blk_pass_body)) {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_BLOCK_PASS, NULL);
            diff_cruby_ctx_t bpctx = ctx;
            bpctx.depth = ctx.depth + 1;
            bpctx.in_container = false;
            diff_cruby_visit_val_ctx(blk_pass_body, bpctx);
            diff_tree_close(ctx.out);
        }
        diff_tree_close(ctx.out);
    }
    RB_GC_GUARD(real_args);
    RB_GC_GUARD(blk_pass_body);
}

static bool diff_cruby_args_is_empty(VALUE ch) {
    if (!RB_TYPE_P(ch, T_ARRAY) || RARRAY_LEN(ch) < 10) {
        return true;
    }
    long pre_num = FIXNUM_P(RARRAY_AREF(ch, 0)) ? FIX2LONG(RARRAY_AREF(ch, 0)) : 0;
    long post_num = FIXNUM_P(RARRAY_AREF(ch, 4)) ? FIX2LONG(RARRAY_AREF(ch, 4)) : 0;
    return pre_num == 0 && post_num == 0 &&
        NIL_P(RARRAY_AREF(ch, 1)) &&
        NIL_P(RARRAY_AREF(ch, 2)) &&
        NIL_P(RARRAY_AREF(ch, 5)) &&
        NIL_P(RARRAY_AREF(ch, 6)) &&
        RARRAY_AREF(ch, 7) == Qnil &&
        RARRAY_AREF(ch, 8) == Qnil &&
        NIL_P(RARRAY_AREF(ch, 9));
}

static void diff_cruby_emit_args_chain(VALUE node, ID wrapper_id, char tag_prefix, diff_cruby_ctx_t ctx) {
    volatile VALUE cur = node;
    while (diff_cruby_is_ast_node(cur)) {
        ID tid = 0;
        volatile VALUE ch = diff_cruby_get_children(cur, ctx.out, &tid);
        long len = RARRAY_LEN(ch);
        if (tid != wrapper_id || len < 2) {
            RB_GC_GUARD(ch);
            break;
        }
        VALUE assign = RARRAY_AREF(ch, 0);
        if (diff_cruby_is_ast_node(assign)) {
            ID atid = 0;
            volatile VALUE ach = diff_cruby_get_children(assign, ctx.out, &atid);
            if (RARRAY_LEN(ach) >= 2) {
                diff_cruby_emit_tagged_sym(RARRAY_AREF(ach, 0), DIFF_TOK_PARAM, tag_prefix, ctx.out);
                VALUE rhs = RARRAY_AREF(ach, 1);
                if (diff_cruby_sym_is(rhs, diff_ids.req_kw)) {
                    diff_tree_leaf_cstr(ctx.out, DIFF_TOK_SLOT, "req");
                } else {
                    diff_cruby_ctx_t sub = ctx;
                    sub.depth = ctx.depth + 1;
                    sub.in_target = false;
                    sub.in_pattern = false;
                    diff_cruby_visit_val_ctx(rhs, sub);
                }
                diff_tree_close(ctx.out);
            }
            RB_GC_GUARD(ach);
        }
        cur = RARRAY_AREF(ch, 1);
        RB_GC_GUARD(ch);
    }
    RB_GC_GUARD(cur);
}

static void diff_cruby_emit_args_node(VALUE args_node, diff_cruby_ctx_t ctx) {
    ID tid = 0;
    volatile VALUE ch = diff_cruby_get_children(args_node, ctx.out, &tid);
    if (diff_cruby_args_is_empty(ch)) {
        RB_GC_GUARD(ch);
        return;
    }

    long pre_num = FIXNUM_P(RARRAY_AREF(ch, 0)) ? FIX2LONG(RARRAY_AREF(ch, 0)) : 0;
    long post_num = FIXNUM_P(RARRAY_AREF(ch, 4)) ? FIX2LONG(RARRAY_AREF(ch, 4)) : 0;
    char buf[32];

    diff_tree_open_cstr(ctx.out, DIFF_TOK_PARAMS, NULL);
    snprintf(buf, sizeof(buf), "pre=%ld", pre_num);
    diff_tree_leaf_cstr(ctx.out, DIFF_TOK_PARAM, buf);
    snprintf(buf, sizeof(buf), "post=%ld", post_num);
    diff_tree_leaf_cstr(ctx.out, DIFF_TOK_PARAM, buf);

    diff_cruby_ctx_t sub = ctx;
    sub.depth = ctx.depth + 1;
    sub.in_target = true;
    sub.in_pattern = false;

    if (!NIL_P(RARRAY_AREF(ch, 1))) {
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 1), sub);
    }
    if (!NIL_P(RARRAY_AREF(ch, 2))) {
        diff_cruby_emit_args_chain(RARRAY_AREF(ch, 2), diff_ids.opt_arg, 'o', ctx);
    }
    if (!NIL_P(RARRAY_AREF(ch, 5))) {
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 5), sub);
    }

    VALUE rest = RARRAY_AREF(ch, 6);
    if (!NIL_P(rest)) {
        if (diff_cruby_sym_is(rest, diff_ids.excessive_comma)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_PARAM, "comma");
        } else if (SYMBOL_P(rest)) {
            diff_cruby_emit_tagged_sym(rest, DIFF_TOK_PARAM, 'r', ctx.out);
            diff_tree_close(ctx.out);
        }
    }

    VALUE kw = RARRAY_AREF(ch, 7);
    VALUE kw_rest = RARRAY_AREF(ch, 8);
    if (kw == Qfalse) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_PARAM, "nokw");
    } else {
        if (!NIL_P(kw)) {
            diff_cruby_emit_args_chain(kw, diff_ids.kw_arg, 'k', ctx);
        }
        if (diff_cruby_is_ast_node(kw_rest)) {
            ID kt = 0;
            volatile VALUE kch = diff_cruby_get_children(kw_rest, ctx.out, &kt);
            if (RARRAY_LEN(kch) >= 1 && SYMBOL_P(RARRAY_AREF(kch, 0))) {
                diff_cruby_emit_tagged_sym(RARRAY_AREF(kch, 0), DIFF_TOK_PARAM, 'K', ctx.out);
                diff_tree_close(ctx.out);
            }
            RB_GC_GUARD(kch);
        } else if (diff_cruby_sym_is(kw_rest, diff_ids.no_kw_rest)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_PARAM, "nokw");
        }
    }

    VALUE blk = RARRAY_AREF(ch, 9);
    if (SYMBOL_P(blk)) {
        diff_cruby_emit_tagged_sym(blk, DIFF_TOK_PARAM, 'b', ctx.out);
        diff_tree_close(ctx.out);
    }

    diff_tree_close(ctx.out);
    RB_GC_GUARD(ch);
}

static void diff_cruby_visit_scope_child_ctx(VALUE sc, int scope_kind, diff_cruby_ctx_t ctx) {
    if (ctx.depth >= DIFF_MAX_AST_DEPTH) {
        return;
    }
    if (!diff_cruby_is_ast_node(sc)) {
        diff_cruby_visit_val_ctx(sc, ctx);
        return;
    }
    ID tid = diff_cruby_node_tid(sc);
    if (tid != diff_ids.scope) {
        diff_cruby_visit_val_ctx(sc, ctx);
        return;
    }
    volatile VALUE ch = rb_funcall(sc, id_children, 0);
    if (!RB_TYPE_P(ch, T_ARRAY) || RARRAY_LEN(ch) < 3) {
        long clen = RB_TYPE_P(ch, T_ARRAY) ? RARRAY_LEN(ch) : -1L;
        RB_GC_GUARD(ch);
        diff_summary_free(ctx.out);
        diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_shape [detail: node=SCOPE children_len=%ld]\n", clen);
    }
    diff_cruby_ctx_t sub = ctx;
    sub.depth = ctx.depth + 1;
    sub.in_target = false;
    sub.in_pattern = false;
    sub.in_container = false;

    if (scope_kind >= 0) {
        diff_cruby_extract_scope_locals(RARRAY_AREF(ch, 0), (diff_scope_kind_t) scope_kind, ctx.out);
        diff_tree_open_cstr(ctx.out, DIFF_TOK_SCOPE, diff_scope_kind_name((diff_scope_kind_t) scope_kind));
        if (!NIL_P(RARRAY_AREF(ch, 1))) {
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 1), sub);
        }
        if ((diff_scope_kind_t) scope_kind == DIFF_SCOPE_PROGRAM) {
            if (!NIL_P(RARRAY_AREF(ch, 2))) {
                diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 2), sub);
            }
        } else {
            diff_cruby_visit_slot("body", RARRAY_AREF(ch, 2), sub);
        }
        diff_tree_close(ctx.out);
    } else {
        for (long i = 1; i < RARRAY_LEN(ch); i++) {
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, i), sub);
        }
    }
    RB_GC_GUARD(ch);
}

static bool diff_cruby_hash_is_pattern_capture(VALUE list_val, diff_summary_t *out) {
    if (!diff_cruby_is_ast_node(list_val)) {
        return false;
    }
    ID lt = 0;
    volatile VALUE lch = diff_cruby_get_children(list_val, out, &lt);
    bool is_cap = false;
    if (lt == diff_ids.list_n && RARRAY_LEN(lch) >= 2) {
        VALUE target = RARRAY_AREF(lch, 1);
        ID tt = diff_cruby_node_tid(target);
        if (tt == diff_ids.lasgn || tt == diff_ids.dasgn) {
            ID at = 0;
            volatile VALUE ach = diff_cruby_get_children(target, out, &at);
            if (RARRAY_LEN(ach) >= 2 && NIL_P(RARRAY_AREF(ach, 1))) {
                is_cap = true;
            }
            RB_GC_GUARD(ach);
        }
    }
    RB_GC_GUARD(lch);
    return is_cap;
}

static void diff_cruby_visit_hash_node(VALUE hash_node, bool maybe_pattern_capture, diff_cruby_ctx_t ctx) {
    ID tid = 0;
    volatile VALUE ch = diff_cruby_get_children(hash_node, ctx.out, &tid);
    VALUE list_val = RARRAY_LEN(ch) >= 1 ? RARRAY_AREF(ch, 0) : Qnil;
    RB_GC_GUARD(ch);

    if (maybe_pattern_capture && diff_cruby_hash_is_pattern_capture(list_val, ctx.out)) {
        /* Inside pattern matching (outside HSHPTN kwargs), NODE_HASH encodes CapturePattern (val => var) */
        if (diff_cruby_is_ast_node(list_val)) {
            ID lt = 0;
            volatile VALUE lch = diff_cruby_get_children(list_val, ctx.out, &lt);
            long lcount = RARRAY_LEN(lch);
            if (lcount >= 2) {
                diff_tree_open_cstr(ctx.out, DIFF_TOK_CAPTURE, NULL);
                diff_cruby_ctx_t pctx = ctx;
                pctx.depth = ctx.depth + 1;
                pctx.in_target = false;
                diff_cruby_visit_val_ctx(RARRAY_AREF(lch, 0), pctx);
                diff_cruby_ctx_t tctx = ctx;
                tctx.depth = ctx.depth + 1;
                tctx.in_target = true;
                diff_cruby_visit_val_ctx(RARRAY_AREF(lch, 1), tctx);
                diff_tree_close(ctx.out);
                RB_GC_GUARD(lch);
                return;
            }
            RB_GC_GUARD(lch);
        }
        diff_tree_open_cstr(ctx.out, DIFF_TOK_CAPTURE, NULL);
        diff_tree_close(ctx.out);
        return;
    }

    diff_tree_open_cstr(ctx.out, DIFF_TOK_HASH, NULL);
    if (diff_cruby_is_ast_node(list_val)) {
        ID lt = 0;
        volatile VALUE lch = diff_cruby_get_children(list_val, ctx.out, &lt);
        if (lt == diff_ids.list_n) {
            long lcount = RARRAY_LEN(lch);
            /* Last element of dump_array LIST is trailing nd_next (usually Qnil) */
            long usable = (lcount > 0 && NIL_P(RARRAY_AREF(lch, lcount - 1))) ? lcount - 1 : lcount;
            diff_cruby_ctx_t sub = ctx;
            sub.depth = ctx.depth + 1;
            sub.in_container = false;
            for (long i = 0; i + 1 < usable; i += 2) {
                VALUE k = RARRAY_AREF(lch, i);
                VALUE v = RARRAY_AREF(lch, i + 1);
                if (NIL_P(k)) {
                    diff_tree_open_cstr(ctx.out, DIFF_TOK_PAIR_SPLAT, NULL);
                    diff_cruby_ctx_t vctx = sub;
                    vctx.in_target = false;
                    diff_cruby_visit_val_ctx(v, vctx);
                    diff_tree_close(ctx.out);
                } else {
                    diff_tree_open_cstr(ctx.out, DIFF_TOK_PAIR, NULL);
                    diff_cruby_ctx_t kctx = sub;
                    kctx.in_target = false;
                    diff_cruby_visit_val_ctx(k, kctx);
                    diff_cruby_visit_val_ctx(v, sub);
                    diff_tree_close(ctx.out);
                }
            }
        }
        RB_GC_GUARD(lch);
    }
    diff_tree_close(ctx.out);
}

static bool diff_cruby_dstr_val_has_dynamic(VALUE val, int depth) {
    if (depth >= DIFF_MAX_AST_DEPTH || NIL_P(val)) {
        return false;
    }
    if (RB_TYPE_P(val, T_ARRAY)) {
        for (long i = 0; i < RARRAY_LEN(val); i++) {
            if (diff_cruby_dstr_val_has_dynamic(RARRAY_AREF(val, i), depth + 1)) {
                return true;
            }
        }
        return false;
    }
    if (!diff_cruby_is_ast_node(val)) {
        return false;
    }
    ID tid = diff_cruby_node_tid(val);
    if (tid == diff_ids.str_n) {
        return false;
    }
    if (tid == diff_ids.list_n) {
        volatile VALUE ch = rb_funcall(val, id_children, 0);
        bool dyn = RB_TYPE_P(ch, T_ARRAY) && diff_cruby_dstr_val_has_dynamic(ch, depth + 1);
        RB_GC_GUARD(ch);
        return dyn;
    }
    if (tid == diff_ids.dstr || tid == diff_ids.dregx || tid == diff_ids.dsym || tid == diff_ids.dxstr) {
        volatile VALUE ch = rb_funcall(val, id_children, 0);
        bool dyn = false;
        if (RB_TYPE_P(ch, T_ARRAY)) {
            if (RARRAY_LEN(ch) >= 2 && diff_cruby_dstr_val_has_dynamic(RARRAY_AREF(ch, 1), depth + 1)) {
                dyn = true;
            } else if (RARRAY_LEN(ch) >= 3 && diff_cruby_dstr_val_has_dynamic(RARRAY_AREF(ch, 2), depth + 1)) {
                dyn = true;
            }
        }
        RB_GC_GUARD(ch);
        return dyn;
    }
    return true;
}

static void diff_cruby_emit_dstr_dyn_parts(VALUE val, diff_cruby_ctx_t ctx) {
    if (ctx.depth >= DIFF_MAX_AST_DEPTH || NIL_P(val)) {
        return;
    }
    if (RB_TYPE_P(val, T_ARRAY)) {
        for (long i = 0; i < RARRAY_LEN(val); i++) {
            diff_cruby_emit_dstr_dyn_parts(RARRAY_AREF(val, i), ctx);
        }
        return;
    }
    if (!diff_cruby_is_ast_node(val)) {
        return;
    }
    ID tid = diff_cruby_node_tid(val);
    if (tid == diff_ids.str_n) {
        return;
    }
    if (tid == diff_ids.list_n) {
        volatile VALUE ch = rb_funcall(val, id_children, 0);
        if (RB_TYPE_P(ch, T_ARRAY)) {
            diff_cruby_ctx_t sub = ctx;
            sub.depth = ctx.depth + 1;
            for (long i = 0; i < RARRAY_LEN(ch); i++) {
                diff_cruby_emit_dstr_dyn_parts(RARRAY_AREF(ch, i), sub);
            }
        }
        RB_GC_GUARD(ch);
        return;
    }
    if (tid == diff_ids.dstr || tid == diff_ids.dregx || tid == diff_ids.dsym || tid == diff_ids.dxstr) {
        volatile VALUE ch = rb_funcall(val, id_children, 0);
        if (RB_TYPE_P(ch, T_ARRAY)) {
            diff_cruby_ctx_t sub = ctx;
            sub.depth = ctx.depth + 1;
            if (RARRAY_LEN(ch) >= 2) {
                diff_cruby_emit_dstr_dyn_parts(RARRAY_AREF(ch, 1), sub);
            }
            if (RARRAY_LEN(ch) >= 3) {
                diff_cruby_emit_dstr_dyn_parts(RARRAY_AREF(ch, 2), sub);
            }
        }
        RB_GC_GUARD(ch);
        return;
    }
    diff_cruby_visit_val_ctx(val, ctx);
}

static void diff_cruby_visit_dstr_like(
    VALUE ch,
    diff_tok_tag_t dyn_tag,
    diff_tok_tag_t leaf_tag,
    diff_cruby_ctx_t ctx
) {
    VALUE head = RARRAY_LEN(ch) >= 2 ? RARRAY_AREF(ch, 1) : Qnil;
    VALUE tail = RARRAY_LEN(ch) >= 3 ? RARRAY_AREF(ch, 2) : Qnil;
    bool has_dyn = diff_cruby_dstr_val_has_dynamic(head, ctx.depth + 1) ||
                   diff_cruby_dstr_val_has_dynamic(tail, ctx.depth + 1);
    if (!has_dyn) {
        diff_tree_leaf_cstr(ctx.out, leaf_tag, NULL);
        return;
    }
    diff_tree_open_cstr(ctx.out, dyn_tag, NULL);
    diff_cruby_ctx_t sub = ctx;
    sub.depth = ctx.depth + 1;
    sub.in_target = false;
    sub.in_pattern = false;
    sub.in_container = false;
    diff_cruby_emit_dstr_dyn_parts(head, sub);
    diff_cruby_emit_dstr_dyn_parts(tail, sub);
    diff_tree_close(ctx.out);
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

static void diff_cruby_visit_var_assign(VALUE ch, char prefix, diff_cruby_ctx_t ctx) {
    if (RARRAY_LEN(ch) < 2) {
        return;
    }
    VALUE name_sym = RARRAY_AREF(ch, 0);
    VALUE val = RARRAY_AREF(ch, 1);
    if (ctx.in_target || (NIL_P(val) && !ctx.in_target) || diff_cruby_node_tid(val) == diff_ids.errinfo) {
        if (NIL_P(name_sym)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, NULL);
        } else {
            diff_cruby_emit_tagged_sym(name_sym, DIFF_TOK_TARGET, prefix, ctx.out);
            diff_tree_close(ctx.out);
        }
        return;
    }
    diff_cruby_emit_tagged_sym(name_sym, DIFF_TOK_ASGN, prefix, ctx.out);
    diff_cruby_ctx_t sub = ctx;
    sub.depth = ctx.depth + 1;
    sub.in_container = false;
    diff_cruby_visit_val_ctx(val, sub);
    diff_tree_close(ctx.out);
}

static void diff_cruby_visit_masgn_targets(VALUE head, VALUE args, diff_cruby_ctx_t ctx) {
    diff_cruby_ctx_t tctx = ctx;
    tctx.depth = ctx.depth + 1;
    tctx.in_target = true;
    tctx.in_container = false;

    diff_tree_open_slot(ctx.out, "lhs");
    if (diff_cruby_is_ast_node(head)) {
        ID ht = 0;
        volatile VALUE hch = diff_cruby_get_children(head, ctx.out, &ht);
        if (ht == diff_ids.list_n) {
            for (long i = 0; i < RARRAY_LEN(hch); i++) {
                VALUE item = RARRAY_AREF(hch, i);
                if (!NIL_P(item)) {
                    diff_cruby_visit_val_ctx(item, tctx);
                }
            }
        } else {
            diff_cruby_visit_val_ctx(head, tctx);
        }
        RB_GC_GUARD(hch);
    }
    diff_tree_close(ctx.out);

    diff_tree_open_slot(ctx.out, "rest");
    if (!NIL_P(args)) {
        if (diff_cruby_sym_is(args, diff_ids.no_name_rest)) {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_TARGET_SPLAT, NULL);
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, NULL);
            diff_tree_close(ctx.out);
        } else if (diff_cruby_is_ast_node(args) && diff_cruby_node_tid(args) == diff_ids.postarg) {
            ID pt = 0;
            volatile VALUE pch = diff_cruby_get_children(args, ctx.out, &pt);
            if (RARRAY_LEN(pch) >= 2) {
                VALUE rpart = RARRAY_AREF(pch, 0);
                diff_tree_open_cstr(ctx.out, DIFF_TOK_TARGET_SPLAT, NULL);
                if (diff_cruby_sym_is(rpart, diff_ids.no_name_rest)) {
                    diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, NULL);
                } else {
                    diff_cruby_visit_val_ctx(rpart, tctx);
                }
                diff_tree_close(ctx.out);

                VALUE post_list = RARRAY_AREF(pch, 1);
                if (diff_cruby_is_ast_node(post_list)) {
                    ID plt = 0;
                    volatile VALUE plch = diff_cruby_get_children(post_list, ctx.out, &plt);
                    if (plt == diff_ids.list_n) {
                        for (long i = 0; i < RARRAY_LEN(plch); i++) {
                            VALUE item = RARRAY_AREF(plch, i);
                            if (!NIL_P(item)) {
                                diff_cruby_visit_val_ctx(item, tctx);
                            }
                        }
                    } else {
                        diff_cruby_visit_val_ctx(post_list, tctx);
                    }
                    RB_GC_GUARD(plch);
                }
            }
            RB_GC_GUARD(pch);
        } else {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_TARGET_SPLAT, NULL);
            diff_cruby_visit_val_ctx(args, tctx);
            diff_tree_close(ctx.out);
        }
    }
    diff_tree_close(ctx.out);
}

static bool diff_cruby_emit_call_like(VALUE target, VALUE iter_block, diff_cruby_ctx_t ctx) {
    if (!diff_cruby_is_ast_node(target)) {
        return false;
    }
    ID tid = 0;
    volatile VALUE ch = diff_cruby_get_children(target, ctx.out, &tid);
    long len = RARRAY_LEN(ch);
    diff_cruby_ctx_t sub = ctx;
    sub.depth = ctx.depth + 1;
    sub.in_container = false;

    if ((tid == diff_ids.call || tid == diff_ids.opcall || tid == diff_ids.qcall) && len >= 3) {
        diff_tok_tag_t tag = (tid == diff_ids.qcall) ? DIFF_TOK_QCALL : DIFF_TOK_CALL;
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 1), tag, ctx.out);
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 0), sub);
        diff_cruby_emit_call_args_and_blk(RARRAY_AREF(ch, 2), iter_block, sub, true);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(ch);
        return true;
    }
    if (tid == diff_ids.fcall && len >= 2) {
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 0), DIFF_TOK_CALL, ctx.out);
        diff_cruby_visit_slot("recv", Qnil, sub);
        diff_cruby_emit_call_args_and_blk(RARRAY_AREF(ch, 1), iter_block, sub, true);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(ch);
        return true;
    }
    if (tid == diff_ids.vcall && len >= 1) {
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 0), DIFF_TOK_CALL, ctx.out);
        diff_cruby_visit_slot("recv", Qnil, sub);
        diff_cruby_emit_call_args_and_blk(Qnil, iter_block, sub, true);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(ch);
        return true;
    }
    if (tid == diff_ids.super_n && len >= 1) {
        ctx.out->counts[DIFF_CNT_SUPER]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_SUPER, NULL);
        diff_cruby_emit_call_args_and_blk(RARRAY_AREF(ch, 0), iter_block, sub, true);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(ch);
        return true;
    }
    if (tid == diff_ids.zsuper_n) {
        ctx.out->counts[DIFF_CNT_SUPER]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_ZSUPER, NULL);
        diff_tree_open_slot(ctx.out, "blk");
        if (!NIL_P(iter_block)) {
            diff_cruby_visit_scope_child_ctx(iter_block, DIFF_SCOPE_BLOCK, sub);
        }
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(ch);
        return true;
    }
    RB_GC_GUARD(ch);
    return false;
}

static void diff_cruby_visit_node_ctx(VALUE node, diff_cruby_ctx_t ctx) {
    if (ctx.depth >= DIFF_MAX_AST_DEPTH) {
        return;
    }
    ID tid = 0;
    volatile VALUE ch = diff_cruby_get_children(node, ctx.out, &tid);
    long len = RARRAY_LEN(ch);
    diff_cruby_ctx_t sub = ctx;
    sub.depth = ctx.depth + 1;
    sub.in_container = false;

    if (tid == diff_ids.scope) {
        diff_cruby_visit_scope_child_ctx(node, ctx.depth == 0 ? (int) DIFF_SCOPE_PROGRAM : -1, ctx);
    } else if (tid == diff_ids.defn && len >= 2) {
        diff_cruby_add_sym(RARRAY_AREF(ch, 0), ctx.out, &ctx.out->defs);
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 0), DIFF_TOK_DEF, ctx.out);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 1), DIFF_SCOPE_DEF, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.defs && len >= 3) {
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 1), DIFF_TOK_DEFS, ctx.out);
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 0), sub);
        diff_cruby_add_sym(RARRAY_AREF(ch, 1), ctx.out, &ctx.out->defs);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 2), DIFF_SCOPE_DEF, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.cls && len >= 3) {
        ctx.out->counts[DIFF_CNT_CLASS]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_CLASS, NULL);
        diff_cruby_visit_slot("cpath", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("super", RARRAY_AREF(ch, 1), sub);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 2), DIFF_SCOPE_CLASS, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.mod && len >= 2) {
        ctx.out->counts[DIFF_CNT_MODULE]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_MODULE, NULL);
        diff_cruby_visit_slot("cpath", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 1), DIFF_SCOPE_MODULE, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.scls && len >= 2) {
        ctx.out->counts[DIFF_CNT_SCLASS]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_SCLASS, NULL);
        diff_cruby_visit_slot("expr", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 1), DIFF_SCOPE_SCLASS, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.iter && len >= 2) {
        diff_cruby_record_block_owner(RARRAY_AREF(ch, 0), ctx.out);
        if (!diff_cruby_emit_call_like(RARRAY_AREF(ch, 0), RARRAY_AREF(ch, 1), ctx)) {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_ITER, NULL);
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
            diff_tree_open_slot(ctx.out, "blk");
            diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 1), DIFF_SCOPE_BLOCK, sub);
            diff_tree_close(ctx.out);
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.lambda && len >= 1) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_LAMBDA, NULL);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 0), DIFF_SCOPE_LAMBDA, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.for_n && len >= 2) {
        ctx.out->counts[DIFF_CNT_FOR]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_FOR, NULL);
        diff_cruby_visit_slot("col", RARRAY_AREF(ch, 0), sub);
        VALUE sc = RARRAY_AREF(ch, 1);
        VALUE idx_node = Qnil;
        VALUE body_node = Qnil;
        if (diff_cruby_is_ast_node(sc) && diff_cruby_node_tid(sc) == diff_ids.scope) {
            ID st = 0;
            volatile VALUE sch = diff_cruby_get_children(sc, ctx.out, &st);
            if (RARRAY_LEN(sch) >= 3) {
                VALUE fargs = RARRAY_AREF(sch, 1);
                body_node = RARRAY_AREF(sch, 2);
                if (diff_cruby_is_ast_node(fargs) && diff_cruby_node_tid(fargs) == diff_ids.args) {
                    ID at = 0;
                    volatile VALUE ach = diff_cruby_get_children(fargs, ctx.out, &at);
                    if (RARRAY_LEN(ach) >= 2) {
                        idx_node = RARRAY_AREF(ach, 1);
                    }
                    RB_GC_GUARD(ach);
                }
            }
            RB_GC_GUARD(sch);
        }
        diff_cruby_ctx_t idx_ctx = sub;
        idx_ctx.in_target = true;
        diff_cruby_visit_slot("idx", idx_node, idx_ctx);
        diff_cruby_visit_slot("body", body_node, sub);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(idx_node);
        RB_GC_GUARD(body_node);
    } else if (tid == diff_ids.for_masgn && len >= 1) {
        diff_cruby_ctx_t tctx = sub;
        tctx.in_target = true;
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), tctx);
    } else if (tid == diff_ids.postexe && len >= 1) {
        ctx.out->counts[DIFF_CNT_POSTEXE]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_POSTEXE, NULL);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 0), -1, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.masgn && len >= 3) {
        VALUE rhs = RARRAY_AREF(ch, 0);
        VALUE head = RARRAY_AREF(ch, 1);
        VALUE args = RARRAY_AREF(ch, 2);
        bool is_target_only = ctx.in_target || NIL_P(rhs) || diff_cruby_node_tid(rhs) == diff_ids.for_masgn;
        diff_tree_open_cstr(ctx.out, is_target_only ? DIFF_TOK_MTARGET : DIFF_TOK_MASGN, NULL);
        diff_cruby_visit_masgn_targets(head, args, ctx);
        if (!is_target_only) {
            diff_cruby_visit_slot("rhs", rhs, sub);
        }
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.args) {
        diff_cruby_emit_args_node(node, ctx);
    } else if (tid == diff_ids.block_n || tid == diff_ids.begin_n || tid == diff_ids.once_n) {
        for (long i = 0; i < len; i++) {
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, i), sub);
        }
    } else if (tid == diff_ids.errinfo) {
        /* stripped synthetic $! reference */
    } else if (tid == diff_ids.if_n && len >= 3) {
        ctx.out->counts[DIFF_CNT_IF]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_IF, NULL);
        diff_cruby_visit_slot("cond", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("then", RARRAY_AREF(ch, 1), ctx);
        diff_cruby_visit_slot("else", RARRAY_AREF(ch, 2), ctx);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.unless_n && len >= 3) {
        ctx.out->counts[DIFF_CNT_UNLESS]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_UNLESS, NULL);
        diff_cruby_visit_slot("cond", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("then", RARRAY_AREF(ch, 1), ctx);
        diff_cruby_visit_slot("else", RARRAY_AREF(ch, 2), ctx);
        diff_tree_close(ctx.out);
    } else if ((tid == diff_ids.while_n || tid == diff_ids.until_n) && len >= 3) {
        ctx.out->counts[tid == diff_ids.while_n ? DIFF_CNT_WHILE : DIFF_CNT_UNTIL]++;
        bool post = RTEST(RARRAY_AREF(ch, 2));
        diff_tree_open_cstr(ctx.out, tid == diff_ids.while_n ? DIFF_TOK_WHILE : DIFF_TOK_UNTIL, post ? "post" : "pre");
        diff_cruby_visit_slot("cond", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("body", RARRAY_AREF(ch, 1), sub);
        diff_tree_close(ctx.out);
    } else if ((tid == diff_ids.case_n || tid == diff_ids.case2_n) && len >= 2) {
        ctx.out->counts[DIFF_CNT_CASE]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_CASE, NULL);
        diff_cruby_visit_slot("head", RARRAY_AREF(ch, 0), sub);
        volatile VALUE cur = RARRAY_AREF(ch, 1);
        while (diff_cruby_is_ast_node(cur) && diff_cruby_node_tid(cur) == diff_ids.when_n) {
            ID wt = 0;
            volatile VALUE wch = diff_cruby_get_children(cur, ctx.out, &wt);
            if (RARRAY_LEN(wch) < 3) {
                RB_GC_GUARD(wch);
                break;
            }
            diff_tree_open_cstr(ctx.out, DIFF_TOK_WHEN, NULL);
            diff_tree_open_slot(ctx.out, "conds");
            diff_cruby_emit_seq_elems(RARRAY_AREF(wch, 0), "elem", sub, false);
            diff_tree_close(ctx.out);
            diff_cruby_visit_slot("body", RARRAY_AREF(wch, 1), sub);
            diff_tree_close(ctx.out);
            cur = RARRAY_AREF(wch, 2);
            RB_GC_GUARD(wch);
        }
        diff_cruby_visit_slot("else", cur, sub);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(cur);
    } else if (tid == diff_ids.case3_n && len >= 2) {
        ctx.out->counts[DIFF_CNT_CASE_MATCH]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_CASE_MATCH, NULL);
        diff_cruby_visit_slot("head", RARRAY_AREF(ch, 0), sub);
        volatile VALUE cur = RARRAY_AREF(ch, 1);
        while (diff_cruby_is_ast_node(cur) && diff_cruby_node_tid(cur) == diff_ids.in_n) {
            ctx.out->counts[DIFF_CNT_IN]++;
            ID it = 0;
            volatile VALUE ich = diff_cruby_get_children(cur, ctx.out, &it);
            if (RARRAY_LEN(ich) < 3) {
                RB_GC_GUARD(ich);
                break;
            }
            diff_cruby_ctx_t pat_ctx = sub;
            pat_ctx.in_pattern = true;
            pat_ctx.in_target = false;
            diff_tree_open_cstr(ctx.out, DIFF_TOK_IN, NULL);
            diff_cruby_visit_slot("pat", RARRAY_AREF(ich, 0), pat_ctx);
            diff_cruby_visit_slot("body", RARRAY_AREF(ich, 1), sub);
            diff_tree_close(ctx.out);
            cur = RARRAY_AREF(ich, 2);
            RB_GC_GUARD(ich);
        }
        diff_cruby_visit_slot("else", cur, sub);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(cur);
    } else if ((tid == diff_ids.and_n || tid == diff_ids.or_n)) {
        diff_tree_open_cstr(ctx.out, tid == diff_ids.and_n ? DIFF_TOK_AND : DIFF_TOK_OR, NULL);
        for (long i = 0; i < len; i++) {
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, i), sub);
        }
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.rescue_n && len >= 3) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_RESCUE, NULL);
        diff_cruby_visit_slot("body", RARRAY_AREF(ch, 0), sub);
        diff_tree_open_slot(ctx.out, "resq");
        volatile VALUE cur = RARRAY_AREF(ch, 1);
        while (diff_cruby_is_ast_node(cur) && diff_cruby_node_tid(cur) == diff_ids.resbody) {
            ctx.out->counts[DIFF_CNT_RESCUE]++;
            ID rt = 0;
            volatile VALUE rch = diff_cruby_get_children(cur, ctx.out, &rt);
            if (RARRAY_LEN(rch) < 4) {
                RB_GC_GUARD(rch);
                break;
            }
            diff_tree_open_cstr(ctx.out, DIFF_TOK_RESBODY, NULL);
            diff_tree_open_slot(ctx.out, "exc");
            diff_cruby_emit_seq_elems(RARRAY_AREF(rch, 0), "elem", sub, false);
            diff_tree_close(ctx.out);
            diff_cruby_ctx_t var_ctx = sub;
            var_ctx.in_target = true;
            diff_cruby_visit_slot("var", RARRAY_AREF(rch, 1), var_ctx);
            diff_cruby_visit_slot("body", RARRAY_AREF(rch, 2), sub);
            diff_tree_close(ctx.out);
            cur = RARRAY_AREF(rch, 3);
            RB_GC_GUARD(rch);
        }
        diff_tree_close(ctx.out);
        diff_cruby_visit_slot("else", RARRAY_AREF(ch, 2), sub);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(cur);
    } else if (tid == diff_ids.ensure_n && len >= 2) {
        ctx.out->counts[DIFF_CNT_ENSURE]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_ENSURE, NULL);
        diff_cruby_visit_slot("body", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("ens", RARRAY_AREF(ch, 1), sub);
        diff_tree_close(ctx.out);
    } else if ((tid == diff_ids.return_n || tid == diff_ids.break_n || tid == diff_ids.next_n) && len >= 1) {
        diff_tok_tag_t tag = tid == diff_ids.return_n ? DIFF_TOK_RETURN
            : (tid == diff_ids.break_n ? DIFF_TOK_BREAK : DIFF_TOK_NEXT);
        ctx.out->counts[tid == diff_ids.return_n ? DIFF_CNT_RETURN
            : (tid == diff_ids.break_n ? DIFF_CNT_BREAK : DIFF_CNT_NEXT)]++;
        diff_tree_open_cstr(ctx.out, tag, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.redo_n) {
        ctx.out->counts[DIFF_CNT_REDO]++;
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_REDO, NULL);
    } else if (tid == diff_ids.retry_n) {
        ctx.out->counts[DIFF_CNT_RETRY]++;
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_RETRY, NULL);
    } else if (tid == diff_ids.yield_n && len >= 1) {
        ctx.out->counts[DIFF_CNT_YIELD]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_YIELD, NULL);
        diff_cruby_emit_call_args_and_blk(RARRAY_AREF(ch, 0), Qnil, sub, false);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.defined_n && len >= 1) {
        ctx.out->counts[DIFF_CNT_DEFINED]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_DEFINED, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.alias_n && len >= 2) {
        ctx.out->counts[DIFF_CNT_ALIAS]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_ALIAS, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 1), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.valias_n && len >= 2) {
        ctx.out->counts[DIFF_CNT_ALIAS]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_VALIAS, NULL);
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_GVAR, ctx.out);
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 1), DIFF_TOK_GVAR, ctx.out);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.undef_n && len >= 1) {
        ctx.out->counts[DIFF_CNT_UNDEF]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_UNDEF, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.call || tid == diff_ids.opcall || tid == diff_ids.qcall ||
               tid == diff_ids.fcall || tid == diff_ids.vcall ||
               tid == diff_ids.super_n || tid == diff_ids.zsuper_n) {
        diff_cruby_emit_call_like(node, Qnil, ctx);
    } else if (tid == diff_ids.attrasgn && len >= 3) {
        if (ctx.in_target) {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_TARGET, "attr");
        }
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 1), DIFF_TOK_ATTRASGN, ctx.out);
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 0), sub);
        diff_tree_open_slot(ctx.out, "args");
        diff_cruby_emit_seq_elems(RARRAY_AREF(ch, 2), "arg", sub, ctx.in_target);
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
        if (ctx.in_target) {
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.lasgn || tid == diff_ids.dasgn) {
        diff_cruby_visit_var_assign(ch, 'l', ctx);
    } else if (tid == diff_ids.iasgn) {
        diff_cruby_visit_var_assign(ch, 'i', ctx);
    } else if (tid == diff_ids.cvasgn) {
        diff_cruby_visit_var_assign(ch, 'c', ctx);
    } else if (tid == diff_ids.gasgn) {
        diff_cruby_visit_var_assign(ch, 'g', ctx);
    } else if (tid == diff_ids.cdecl && len >= 2) {
        if (len == 2) {
            if (ctx.in_target) {
                diff_cruby_emit_tagged_sym(RARRAY_AREF(ch, 0), DIFF_TOK_TARGET, 'C', ctx.out);
                diff_tree_close(ctx.out);
            } else {
                diff_tree_open_cstr(ctx.out, DIFF_TOK_CDECL, NULL);
                diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_CONST, ctx.out);
                diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 1), sub);
                diff_tree_close(ctx.out);
            }
        } else {
            /*
             * IMPORTANT: Never inspect RARRAY_AREF(ch, 1) on 3-element NODE_CDECL;
             * CRuby ast.c reads RNODE_COLON2(nd_else)->nd_mid even on NODE_COLON3 (::C = 1),
             * producing a bogus Symbol whose rb_sym2str crashes CRuby. ch[0] already has COLON2/COLON3.
             */
            if (ctx.in_target) {
                diff_tree_open_cstr(ctx.out, DIFF_TOK_TARGET, "cp");
                diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
                diff_tree_close(ctx.out);
            } else {
                diff_tree_open_cstr(ctx.out, DIFF_TOK_CDECL, NULL);
                diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
                diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 2), sub);
                diff_tree_close(ctx.out);
            }
        }
    } else if (tid == diff_ids.op_asgn_and && len >= 3) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_OP_ASGN_AND, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 2), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.op_asgn_or && len >= 3) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_OP_ASGN_OR, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 2), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.op_cdecl && len >= 3) {
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 1), DIFF_TOK_OP_CDECL, ctx.out);
        diff_cruby_visit_slot("target", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("val", RARRAY_AREF(ch, 2), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.op_asgn1 && len >= 4) {
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 1), DIFF_TOK_OP_ASGN1, ctx.out);
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 0), sub);
        diff_tree_open_slot(ctx.out, "args");
        diff_cruby_emit_seq_elems(RARRAY_AREF(ch, 2), "arg", sub, false);
        diff_tree_close(ctx.out);
        diff_cruby_visit_slot("val", RARRAY_AREF(ch, 3), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.op_asgn2 && len >= 5) {
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 2), DIFF_TOK_OP_ASGN2, ctx.out);
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_SLOT, RTEST(RARRAY_AREF(ch, 1)) ? "1" : "0");
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 3), DIFF_TOK_SLOT, ctx.out);
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("val", RARRAY_AREF(ch, 4), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.zlist || tid == diff_ids.list_n || tid == diff_ids.argscat || tid == diff_ids.argspush) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_ARRAY, NULL);
        diff_cruby_emit_seq_elems(node, "elem", ctx, false);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.splat && len >= 1) {
        if (ctx.in_container) {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_ARRAY, NULL);
            diff_tree_open_slot(ctx.out, "elem");
        }
        diff_tree_open_cstr(ctx.out, DIFF_TOK_SPLAT, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_tree_close(ctx.out);
        if (ctx.in_container) {
            diff_tree_close(ctx.out);
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.hash_n) {
        diff_cruby_visit_hash_node(node, ctx.in_pattern, ctx);
    } else if (tid == diff_ids.dot2 || tid == diff_ids.dot3) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_RANGE, tid == diff_ids.dot3 ? "..." : "..");
        VALUE beg = len >= 1 ? RARRAY_AREF(ch, 0) : Qnil;
        VALUE end = len >= 2 ? RARRAY_AREF(ch, 1) : Qnil;
        if (diff_cruby_node_tid(beg) == diff_ids.nil_n) beg = Qnil;
        if (diff_cruby_node_tid(end) == diff_ids.nil_n) end = Qnil;
        diff_cruby_visit_slot("beg", beg, sub);
        diff_cruby_visit_slot("end", end, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.flip2 || tid == diff_ids.flip3) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_FLIP, tid == diff_ids.flip3 ? "..." : "..");
        VALUE eps[2] = { len >= 1 ? RARRAY_AREF(ch, 0) : Qnil, len >= 2 ? RARRAY_AREF(ch, 1) : Qnil };
        const char *slots[2] = { "beg", "end" };
        for (int ei = 0; ei < 2; ei++) {
            VALUE ep = eps[ei];
            if (diff_cruby_node_tid(ep) == diff_ids.nil_n) {
                ep = Qnil;
            } else if (diff_cruby_node_tid(ep) == diff_ids.call) {
                /* CRuby parse.y lowers integer flip-flop endpoints `n` to `n == $.` */
                ID ct = 0;
                volatile VALUE cch = diff_cruby_get_children(ep, ctx.out, &ct);
                if (RARRAY_LEN(cch) >= 3 &&
                    diff_cruby_node_tid(RARRAY_AREF(cch, 0)) == diff_ids.integer_n) {
                    const char *mptr = NULL;
                    size_t mlen = 0;
                    if (diff_cruby_sym_bytes(RARRAY_AREF(cch, 1), &mptr, &mlen) &&
                        mlen == 2 && memcmp(mptr, "==", 2) == 0 &&
                        diff_cruby_node_tid(RARRAY_AREF(cch, 2)) == diff_ids.list_n) {
                        ID at = 0;
                        volatile VALUE ach = diff_cruby_get_children(RARRAY_AREF(cch, 2), ctx.out, &at);
                        if (RARRAY_LEN(ach) >= 1 && diff_cruby_node_tid(RARRAY_AREF(ach, 0)) == diff_ids.gvar) {
                            ep = RARRAY_AREF(cch, 0);
                        }
                        RB_GC_GUARD(ach);
                    }
                }
                RB_GC_GUARD(cch);
            }
            diff_cruby_visit_slot(slots[ei], ep, sub);
        }
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.colon2 && len >= 2) {
        if (NIL_P(RARRAY_AREF(ch, 0))) {
            diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 1), DIFF_TOK_CONST, ctx.out);
        } else {
            diff_cruby_tree_open_sym(RARRAY_AREF(ch, 1), DIFF_TOK_COLON2, ctx.out);
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.colon3 && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_COLON3, ctx.out);
    } else if (tid == diff_ids.const_n && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_CONST, ctx.out);
    } else if ((tid == diff_ids.lvar || tid == diff_ids.dvar) && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_LVAR, ctx.out);
    } else if (tid == diff_ids.ivar && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_IVAR, ctx.out);
    } else if (tid == diff_ids.cvar && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_CVAR, ctx.out);
    } else if (tid == diff_ids.gvar && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_GVAR, ctx.out);
    } else if (tid == diff_ids.nth_ref && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_NTH_REF, ctx.out);
    } else if (tid == diff_ids.back_ref && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_BACK_REF, ctx.out);
    } else if (tid == diff_ids.self_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_SELF, NULL);
    } else if (tid == diff_ids.nil_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_NIL, NULL);
    } else if (tid == diff_ids.true_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TRUE, NULL);
    } else if (tid == diff_ids.false_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_FALSE, NULL);
    } else if (tid == diff_ids.file_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_FILE, NULL);
    } else if (tid == diff_ids.line_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_LINE, NULL);
    } else if (tid == diff_ids.encoding_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_ENCODING, NULL);
    } else if (tid == diff_ids.integer_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_INT, NULL);
    } else if (tid == diff_ids.float_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_FLOAT, NULL);
    } else if (tid == diff_ids.rational_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_RATIONAL, NULL);
    } else if (tid == diff_ids.imaginary_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_IMAGINARY, NULL);
    } else if (tid == diff_ids.str_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_STR, NULL);
    } else if (tid == diff_ids.sym_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_SYM, NULL);
    } else if (tid == diff_ids.regx) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_REGX, NULL);
    } else if (tid == diff_ids.xstr) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_XSTR, NULL);
    } else if (tid == diff_ids.match_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_MATCH_LAST_LINE, NULL);
    } else if (tid == diff_ids.dstr) {
        diff_cruby_visit_dstr_like(ch, DIFF_TOK_DSTR, DIFF_TOK_STR, ctx);
    } else if (tid == diff_ids.dsym) {
        diff_cruby_visit_dstr_like(ch, DIFF_TOK_DSYM, DIFF_TOK_SYM, ctx);
    } else if (tid == diff_ids.dregx) {
        diff_cruby_visit_dstr_like(ch, DIFF_TOK_DREGX, DIFF_TOK_REGX, ctx);
    } else if (tid == diff_ids.dxstr) {
        diff_cruby_visit_dstr_like(ch, DIFF_TOK_DXSTR, DIFF_TOK_XSTR, ctx);
    } else if (tid == diff_ids.match2 && len >= 2) {
        bool has_targets = len >= 3 && !NIL_P(RARRAY_AREF(ch, 2));
        if (has_targets) {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_MATCH_WRITE, NULL);
        }
        diff_tree_open_cstr(ctx.out, DIFF_TOK_CALL, "=~");
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 0), sub);
        diff_tree_open_slot(ctx.out, "args");
        diff_cruby_visit_slot("arg", RARRAY_AREF(ch, 1), sub);
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "blk");
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
        if (has_targets) {
            diff_cruby_ctx_t tctx = sub;
            tctx.in_target = true;
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 2), tctx);
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.match3 && len >= 2) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_CALL, "=~");
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 1), sub);
        diff_tree_open_slot(ctx.out, "args");
        diff_cruby_visit_slot("arg", RARRAY_AREF(ch, 0), sub);
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "blk");
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.aryptn && len >= 4) {
        diff_cruby_ctx_t pctx = sub;
        pctx.in_pattern = true;
        pctx.in_target = true;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_ARYPTN, NULL);
        diff_cruby_ctx_t cctx = sub;
        cctx.in_pattern = false;
        cctx.in_target = false;
        diff_cruby_visit_slot("const", RARRAY_AREF(ch, 0), cctx);
        diff_tree_open_slot(ctx.out, "pre");
        diff_cruby_emit_seq_elems(RARRAY_AREF(ch, 1), "elem", pctx, false);
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "rest");
        VALUE rval = RARRAY_AREF(ch, 2);
        if (diff_cruby_sym_is(rval, diff_ids.no_name_rest)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, NULL);
        } else if (!NIL_P(rval)) {
            diff_cruby_visit_val_ctx(rval, pctx);
        }
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "post");
        diff_cruby_emit_seq_elems(RARRAY_AREF(ch, 3), "elem", pctx, false);
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.fndptn && len >= 4) {
        diff_cruby_ctx_t pctx = sub;
        pctx.in_pattern = true;
        pctx.in_target = true;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_FNDPTN, NULL);
        diff_cruby_ctx_t cctx = sub;
        cctx.in_pattern = false;
        cctx.in_target = false;
        diff_cruby_visit_slot("const", RARRAY_AREF(ch, 0), cctx);
        diff_tree_open_slot(ctx.out, "pre");
        VALUE r1 = RARRAY_AREF(ch, 1);
        if (diff_cruby_sym_is(r1, diff_ids.no_name_rest)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, NULL);
        } else if (!NIL_P(r1)) {
            diff_cruby_visit_val_ctx(r1, pctx);
        }
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "mid");
        diff_cruby_emit_seq_elems(RARRAY_AREF(ch, 2), "elem", pctx, false);
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "post");
        VALUE r2 = RARRAY_AREF(ch, 3);
        if (diff_cruby_sym_is(r2, diff_ids.no_name_rest)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, NULL);
        } else if (!NIL_P(r2)) {
            diff_cruby_visit_val_ctx(r2, pctx);
        }
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.hshptn && len >= 3) {
        diff_cruby_ctx_t pctx = sub;
        pctx.in_pattern = true;
        pctx.in_target = true;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_HSHPTN, NULL);
        diff_cruby_ctx_t cctx = sub;
        cctx.in_pattern = false;
        cctx.in_target = false;
        diff_cruby_visit_slot("const", RARRAY_AREF(ch, 0), cctx);
        diff_tree_open_slot(ctx.out, "kw");
        if (diff_cruby_is_ast_node(RARRAY_AREF(ch, 1))) {
            diff_cruby_visit_hash_node(RARRAY_AREF(ch, 1), false, pctx);
        } else {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_HASH, NULL);
            diff_tree_close(ctx.out);
        }
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "kwrest");
        VALUE kwrest = RARRAY_AREF(ch, 2);
        if (diff_cruby_sym_is(kwrest, diff_ids.no_kw_rest)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, "nokw");
        } else if (!NIL_P(kwrest)) {
            diff_cruby_visit_val_ctx(kwrest, pctx);
        }
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
    } else {
        diff_cruby_count_if_matched(tid, ctx.out);
        for (long i = 0; i < len; i++) {
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, i), sub);
        }
    }

    RB_GC_GUARD(ch);
}

static void diff_cruby_visit_val_ctx(VALUE val, diff_cruby_ctx_t ctx) {
    if (ctx.depth >= DIFF_MAX_AST_DEPTH) {
        return;
    }
    if (diff_cruby_is_ast_node(val)) {
        diff_cruby_visit_node_ctx(val, ctx);
    } else if (RB_TYPE_P(val, T_ARRAY)) {
        long len = RARRAY_LEN(val);
        diff_cruby_ctx_t sub = ctx;
        sub.depth = ctx.depth + 1;
        for (long i = 0; i < len; i++) {
            diff_cruby_visit_val_ctx(RARRAY_AREF(val, i), sub);
        }
    }
}

static void diff_collect_cruby_summary(VALUE ast_node, diff_summary_t *out) {
    if (NIL_P(ast_node)) {
        return;
    }
    diff_ast_ids_init();
    diff_cruby_ctx_t ctx = {
        .out = out,
        .depth = 0,
        .in_target = false,
        .in_pattern = false,
        .in_container = false
    };
    diff_cruby_visit_val_ctx(ast_node, ctx);
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

static void diff_format_tok_full(const diff_summary_t *s, diff_tree_tok_t tok, char dst[97]) {
    const char *tname = diff_tok_tag_name((diff_tok_tag_t) tok.tag);
    size_t tlen = strlen(tname);
    if (tlen > 40) {
        tlen = 40;
    }
    memcpy(dst, tname, tlen);
    size_t pos = tlen;
    if (tok.label.length > 0 && pos + 2 < 96) {
        dst[pos++] = ':';
        const char *lptr = s->strbuf.data + tok.label.offset;
        size_t lmax = 96 - pos;
        size_t llen = tok.label.length < lmax ? (size_t) tok.label.length : lmax;
        for (size_t i = 0; i < llen; i++) {
            unsigned char ch = (unsigned char) lptr[i];
            dst[pos++] = (ch >= 0x21 && ch <= 0x7e && ch != '[' && ch != ']') ? (char) ch : '_';
        }
    }
    dst[pos] = '\0';
}

static void diff_compare_tree(diff_summary_t *prism, diff_summary_t *cruby) {
    size_t plen = prism->tree.count;
    size_t clen = cruby->tree.count;
    size_t common = plen < clen ? plen : clen;

    for (size_t i = 0; i < common; i++) {
        diff_tree_tok_t pt = prism->tree.items[i];
        diff_tree_tok_t ct = cruby->tree.items[i];
        if (pt.tag == ct.tag && diff_span_equal(prism->strbuf.data, pt.label, cruby->strbuf.data, ct.label)) {
            continue;
        }
        const char *sub = (pt.tag != ct.tag) ? "tag" : "label";
        const char *ptag = diff_tok_tag_name((diff_tok_tag_t) pt.tag);
        const char *ctag = diff_tok_tag_name((diff_tok_tag_t) ct.tag);
        char pfull[97];
        char cfull[97];
        char prev_tok[97];
        diff_format_tok_full(prism, pt, pfull);
        diff_format_tok_full(cruby, ct, cfull);
        if (i > 0) {
            diff_format_tok_full(prism, prism->tree.items[i - 1], prev_tok);
        } else {
            snprintf(prev_tok, sizeof(prev_tok), "START");
        }
        const char *phead = (pt.tag != ct.tag) ? ptag : pfull;
        const char *chead = (pt.tag != ct.tag) ? ctag : cfull;
        char phead_buf[97];
        char chead_buf[97];
        snprintf(phead_buf, sizeof(phead_buf), "%s", phead);
        snprintf(chead_buf, sizeof(chead_buf), "%s", chead);
        diff_summary_free(prism);
        diff_summary_free(cruby);
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=%s prism=%s cruby=%s [detail: idx=%zu prev=%s prism_len=%zu cruby_len=%zu prism_tok=%s cruby_tok=%s]\n",
            sub,
            phead_buf,
            chead_buf,
            i,
            prev_tok,
            plen,
            clen,
            pfull,
            cfull
        );
    }

    if (plen != clen) {
        const char *phead = plen > clen ? diff_tok_tag_name((diff_tok_tag_t) prism->tree.items[common].tag) : "EOF";
        const char *chead = clen > plen ? diff_tok_tag_name((diff_tok_tag_t) cruby->tree.items[common].tag) : "EOF";
        char pfull[97];
        char cfull[97];
        if (plen > clen) {
            diff_format_tok_full(prism, prism->tree.items[common], pfull);
        } else {
            snprintf(pfull, sizeof(pfull), "EOF");
        }
        if (clen > plen) {
            diff_format_tok_full(cruby, cruby->tree.items[common], cfull);
        } else {
            snprintf(cfull, sizeof(cfull), "EOF");
        }
        diff_summary_free(prism);
        diff_summary_free(cruby);
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=len prism=%s cruby=%s [detail: idx=%zu prism_len=%zu cruby_len=%zu prism_tok=%s cruby_tok=%s]\n",
            phead,
            chead,
            common,
            plen,
            clen,
            pfull,
            cfull
        );
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

    diff_compare_tree(prism, cruby);
}
/* TRIAGE_SLICE_END(diff_ast) */

static int diff_oracle_initialized = 0;

static const int diff_crash_signals[] = { SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGTRAP, SIGPIPE };
static const int diff_fatal_signals[] = { SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE };
#define DIFF_CRASH_SIGNAL_COUNT (sizeof(diff_crash_signals) / sizeof(diff_crash_signals[0]))

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
        case SIGTRAP: msg = "CRASH[diff_parse_y]: signal=SIGTRAP (5)\n"; break;
        case SIGFPE:  msg = "CRASH[diff_parse_y]: signal=SIGFPE (8)\n"; break;
        default:      break;
    }
    diff_write_stderr_str(msg, strlen(msg));
    rb_print_backtrace(stderr);
    fflush(stderr);
    sigset_t unblock;
    sigemptyset(&unblock);
    sigaddset(&unblock, sig);
    sigprocmask(SIG_UNBLOCK, &unblock, NULL);
    raise(sig);
    _exit(128 + sig);
}

static void diff_snapshot_signals(struct sigaction saved[DIFF_CRASH_SIGNAL_COUNT]) {
    for (size_t i = 0; i < DIFF_CRASH_SIGNAL_COUNT; i++) {
        sigaction(diff_crash_signals[i], NULL, &saved[i]);
    }
}

static void diff_restore_signals(const struct sigaction saved[DIFF_CRASH_SIGNAL_COUNT]) {
    for (size_t i = 0; i < DIFF_CRASH_SIGNAL_COUNT; i++) {
        sigaction(diff_crash_signals[i], &saved[i], NULL);
    }
}

static void diff_install_fatal_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = diff_fatal_signal_handler;
    sigemptyset(&sa.sa_mask);
    /* Reset to SIG_DFL and unmask on delivery so raise(sig) kills with WTERMSIG == sig. */
    sa.sa_flags = SA_RESETHAND | SA_NODEFER;
    for (size_t i = 0; i < sizeof(diff_fatal_signals) / sizeof(diff_fatal_signals[0]); i++) {
        sigaction(diff_fatal_signals[i], &sa, NULL);
    }
}

static void diff_oracle_init(void) {
    if (diff_oracle_initialized) {
        return;
    }

    struct sigaction saved[DIFF_CRASH_SIGNAL_COUNT];
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

    diff_core_ids_init();
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
#ifdef __AFL_LOOP
        while (__AFL_LOOP(FUZZ_DIFF_PERSISTENT_ITERS))
#endif
        {
            const uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
            size_t len = (size_t) __AFL_FUZZ_TESTCASE_LEN;
            LLVMFuzzerTestOneInput(buf, len);
        }
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

