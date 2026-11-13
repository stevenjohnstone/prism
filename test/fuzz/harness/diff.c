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

#include <ruby.h>

#ifndef FUZZ_MAX_INPUT_SIZE
#define FUZZ_MAX_INPUT_SIZE 1024
#endif

#define DIFF_STACK_LOCAL_SLOTS 64
#define DIFF_STACK_LOCAL_BYTES 2048

/* CRuby internal helper in thread.c; stops timer thread cleanly before fork(). */
extern void rb_thread_stop_timer_thread(void);

typedef struct {
    uint32_t offset;
    uint32_t length;
} diff_local_span_t;

typedef struct {
    size_t count;
    diff_local_span_t stack_spans[DIFF_STACK_LOCAL_SLOTS];
    diff_local_span_t *spans;
    char stack_buf[DIFF_STACK_LOCAL_BYTES];
    char *buf;
    size_t bytes_used;
    bool spans_heap;
    bool buf_heap;
} diff_locals_t;

static int diff_oracle_initialized = 0;
static VALUE rb_mAST = Qnil;
static ID id_parse = 0;
static ID id_children = 0;

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

static const int diff_crash_signals[] = { SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGPIPE };

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

    VALUE warning_mod = rb_const_get(rb_cObject, rb_intern("Warning"));
    rb_define_singleton_method(warning_mod, "warn", diff_warning_warn, -1);

    VALUE rb_cRubyVM = rb_const_get(rb_cObject, rb_intern("RubyVM"));
    rb_mAST = rb_const_get(rb_cRubyVM, rb_intern("AbstractSyntaxTree"));
    rb_gc_register_mark_object(rb_mAST);
    id_parse = rb_intern("parse");
    id_children = rb_intern("children");

    rb_thread_stop_timer_thread();
    diff_oracle_initialized = 1;
}

static void diff_locals_init(diff_locals_t *locals) {
    locals->count = 0;
    locals->spans = locals->stack_spans;
    locals->buf = locals->stack_buf;
    locals->bytes_used = 0;
    locals->spans_heap = false;
    locals->buf_heap = false;
}

static void diff_locals_free(diff_locals_t *locals) {
    if (locals->spans_heap) {
        free(locals->spans);
    }
    if (locals->buf_heap) {
        free(locals->buf);
    }
    diff_locals_init(locals);
}

static void diff_extract_prism_locals(
    const pm_parser_t *parser,
    const pm_program_node_t *program,
    diff_locals_t *locals
) {
    size_t count = program->locals.size;
    if (count == 0) {
        return;
    }

    if (count > DIFF_STACK_LOCAL_SLOTS) {
        locals->spans = (diff_local_span_t *) malloc(count * sizeof(diff_local_span_t));
        if (locals->spans == NULL) {
            abort();
        }
        locals->spans_heap = true;
    }

    size_t total_bytes = 0;
    for (size_t i = 0; i < count; i++) {
        const pm_constant_t *c = pm_parser_constant(parser, program->locals.ids[i]);
        size_t len = pm_constant_length(c);
        if (len > UINT32_MAX || total_bytes > SIZE_MAX - len) {
            abort();
        }
        total_bytes += len;
    }

    if (total_bytes > DIFF_STACK_LOCAL_BYTES) {
        locals->buf = (char *) malloc(total_bytes);
        if (locals->buf == NULL) {
            abort();
        }
        locals->buf_heap = true;
    }

    size_t off = 0;
    for (size_t i = 0; i < count; i++) {
        const pm_constant_t *c = pm_parser_constant(parser, program->locals.ids[i]);
        const uint8_t *start = pm_constant_start(c);
        size_t len = pm_constant_length(c);
        locals->spans[i].offset = (uint32_t) off;
        locals->spans[i].length = (uint32_t) len;
        if (len > 0) {
            memcpy(locals->buf + off, start, len);
            off += len;
        }
    }
    locals->count = count;
    locals->bytes_used = off;
}

static void diff_run_prism(
    const uint8_t *source,
    size_t size,
    bool *out_ok,
    size_t *out_err_count,
    diff_locals_t *out_locals
) {
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

    if (*out_ok && root != NULL && PM_NODE_TYPE_P(root, PM_PROGRAM_NODE)) {
        diff_extract_prism_locals(parser, (const pm_program_node_t *) root, out_locals);
    }

    pm_parser_free(parser);
    pm_arena_free(arena);
    pm_options_free(options);
    free(copy);
}

static VALUE diff_ast_parse_cb(VALUE src_str) {
    return rb_funcall(rb_mAST, id_parse, 1, src_str);
}

static void diff_format_exception(VALUE err, char *buf, size_t cap) {
    if (cap == 0) {
        return;
    }
    if (NIL_P(err)) {
        snprintf(buf, cap, "nil");
        return;
    }
    const char *cname = rb_obj_classname(err);
    VALUE msg = rb_funcall(err, rb_intern("message"), 0);
    const char *mptr = (RB_TYPE_P(msg, T_STRING) && RSTRING_LEN(msg) > 0) ? RSTRING_PTR(msg) : "";
    long mlen = RB_TYPE_P(msg, T_STRING) ? RSTRING_LEN(msg) : 0;

    long first_line_len = 0;
    while (first_line_len < mlen && first_line_len < 96 &&
           mptr[first_line_len] != '\n' && mptr[first_line_len] != '\r') {
        first_line_len++;
    }
    snprintf(buf, cap, "%s: %.*s", cname ? cname : "Exception", (int) first_line_len, mptr);
    RB_GC_GUARD(msg);
}

static VALUE diff_run_cruby(const char *source, size_t size, bool *out_ok, char *exc_buf, size_t exc_cap) {
    if (size > (size_t) LONG_MAX) {
        abort();
    }
    volatile VALUE src_str = rb_utf8_str_new(source != NULL ? source : "", (long) size);
    int state = 0;
    volatile VALUE ast_node = rb_protect(diff_ast_parse_cb, src_str, &state);
    if (state != 0) {
        VALUE err = rb_errinfo();
        rb_set_errinfo(Qnil);
        *out_ok = false;
        diff_format_exception(err, exc_buf, exc_cap);
        RB_GC_GUARD(src_str);
        return Qnil;
    }

    *out_ok = true;
    exc_buf[0] = '\0';
    RB_GC_GUARD(src_str);
    return ast_node;
}

static void diff_compare_locals(VALUE ast_node, const diff_locals_t *prism_locals) {
    volatile VALUE children = rb_funcall(ast_node, id_children, 0);
    if (!RB_TYPE_P(children, T_ARRAY) || RARRAY_LEN(children) < 1) {
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=ast_shape [detail: children_len=%ld]\n",
            RB_TYPE_P(children, T_ARRAY) ? RARRAY_LEN(children) : -1L
        );
    }

    volatile VALUE tbl = RARRAY_AREF(children, 0);
    if (!RB_TYPE_P(tbl, T_ARRAY)) {
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=ast_tbl_type [detail: type=%d]\n",
            (int) TYPE(tbl)
        );
    }

    long cruby_count = RARRAY_LEN(tbl);
    if ((size_t) cruby_count != prism_locals->count) {
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=locals_count_mismatch [detail: prism=%zu cruby=%ld]\n",
            prism_locals->count,
            cruby_count
        );
    }

    for (long i = 0; i < cruby_count; i++) {
        VALUE sym = RARRAY_AREF(tbl, i);
        volatile VALUE sym_str = SYMBOL_P(sym) ? rb_sym2str(sym) : Qnil;
        const diff_local_span_t *span = &prism_locals->spans[i];
        const char *p_ptr = prism_locals->buf + span->offset;
        size_t p_len = span->length;

        if (!RB_TYPE_P(sym_str, T_STRING) ||
            (size_t) RSTRING_LEN(sym_str) != p_len ||
            (p_len > 0 && memcmp(RSTRING_PTR(sym_str), p_ptr, p_len) != 0)) {
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=locals_name_mismatch [detail: idx=%ld prism=%.*s cruby=%.*s]\n",
                i,
                (int) p_len,
                p_ptr,
                RB_TYPE_P(sym_str, T_STRING) ? (int) RSTRING_LEN(sym_str) : 3,
                RB_TYPE_P(sym_str, T_STRING) ? RSTRING_PTR(sym_str) : "nil"
            );
        }
        RB_GC_GUARD(sym_str);
    }

    RB_GC_GUARD(tbl);
    RB_GC_GUARD(children);
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

    bool prism_ok = false;
    size_t prism_errs = 0;
    diff_locals_t prism_locals;
    diff_locals_init(&prism_locals);

    diff_run_prism(source, source_size, &prism_ok, &prism_errs, &prism_locals);

    bool cruby_ok = false;
    char exc_buf[160];
    volatile VALUE ast_node = diff_run_cruby((const char *) source, source_size, &cruby_ok, exc_buf, sizeof(exc_buf));

    if (prism_ok != cruby_ok) {
        const char *sub = prism_ok ? "prism_ok_cruby_err" : "prism_err_cruby_ok";
        diff_locals_free(&prism_locals);
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=%s [detail: prism_errs=%zu cruby=%s]\n",
            sub,
            prism_errs,
            cruby_ok ? "ok" : exc_buf
        );
    }

    if (prism_ok && cruby_ok) {
        diff_compare_locals(ast_node, &prism_locals);
    }

    RB_GC_GUARD(ast_node);
    diff_locals_free(&prism_locals);
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

