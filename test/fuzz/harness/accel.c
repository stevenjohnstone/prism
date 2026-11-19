/*
 * Minimal differential libFuzzer PASS/FAIL target comparing Prism's native
 * SIMD (NEON/SSE2) scan_identifier_ascii against the portable SWAR fallback
 * (both compiled from untouched src/prism.c into isolated DSOs).
 *
 * Each fuzz input is fed directly as raw identifier bytes into an exact-sized
 * buffer (no trailing NUL so ASAN catches vector over-reads), and both fast
 * paths must finish at the exact same position once completed by the scalar
 * identifier tail loop.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern size_t accel_native_scan_identifier(const uint8_t *start, const uint8_t *end);
extern size_t accel_native_scan_tail_limit(void);
extern size_t accel_swar_scan_identifier(const uint8_t *start, const uint8_t *end);
extern size_t accel_swar_scan_tail_limit(void);

static size_t g_native_tail_limit = 16;
static size_t g_swar_tail_limit = 8;

static int
is_ascii_ident(uint8_t c) {
    return (c == '_') ||
           (c >= '0' && c <= '9') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z');
}

static size_t
ascii_ident_end(const uint8_t *start, const uint8_t *end, size_t initial) {
    size_t idx = initial;
    size_t len = (size_t) (end - start);
    while (idx < len && is_ascii_ident(start[idx])) {
        idx++;
    }
    return idx;
}

static void
fprint_escaped(FILE *out, const uint8_t *buf, size_t len, size_t max_bytes) {
    size_t n = len < max_bytes ? len : max_bytes;
    fputc('"', out);
    for (size_t i = 0; i < n; i++) {
        uint8_t c = buf[i];
        switch (c) {
            case '\\': fputs("\\\\", out); break;
            case '"': fputs("\\\"", out); break;
            case '\n': fputs("\\n", out); break;
            case '\r': fputs("\\r", out); break;
            case '\t': fputs("\\t", out); break;
            default:
                if (c >= 0x20 && c <= 0x7E) {
                    fputc((int) c, out);
                } else {
                    fprintf(out, "\\x%02x", c);
                }
                break;
        }
    }
    fputc('"', out);
    if (len > max_bytes) {
        fprintf(out, " ... (%zu bytes total)", len);
    }
}

static void
fprint_byte_desc(FILE *out, const uint8_t *buf, size_t len, size_t idx) {
    if (idx >= len) {
        fputs("<EOF>", out);
        return;
    }
    uint8_t b = buf[idx];
    if (b >= 0x20 && b <= 0x7E) {
        fprintf(out, "0x%02x ('%c')", b, (int) b);
    } else {
        fprintf(out, "0x%02x", b);
    }
}

static void
fprint_result(FILE *out, const char *name, const uint8_t *text, size_t len, size_t n, size_t expected, size_t width) {
    fprintf(out, "  %-6s => %zu", name, n);
    if (n > expected) {
        fprintf(out, " (OVER-SCANNED +%zu bytes past text[%zu]=", n - expected, expected);
        fprint_byte_desc(out, text, len, expected);
        fprintf(out, ": wrongly accepted ");
        fprint_escaped(out, text + expected, n - expected, 32);
        fputc(')', out);
    } else if (width > 1) {
        size_t rem = expected - n;
        fprintf(out, " (remaining=%zu, chunk_width=%zu%s)", rem, width, rem >= width ? ", UNDER-SCANNED" : "");
    } else {
        fprintf(out, " (remaining=%zu)", expected - n);
    }
    fputc('\n', out);
}

/*
 * Verify that scan_identifier_ascii's return count `scanned` satisfies the
 * contract expected by lex_identifier. Fast paths only process full
 * `chunk_width`-byte blocks, so `scanned` may stop short of `expected` due to
 * remaining identifier bytes outside those chunks (< chunk_width), which the
 * caller's byte-at-a-time fallback loop finishes scanning.
 */
static int
ident_scan_valid(const uint8_t *text, size_t size, size_t scanned, size_t expected, size_t chunk_width) {
    // the scan should never go beyond the expected
    if (scanned > expected) return 0;
    // the scan can fall short of expected but it must only do so when
    // a. there's less than a chunk_width of data left
    if (chunk_width > 1 && (expected - scanned) >= chunk_width) return 0;
    // b. it stops inside an identifier
    return ascii_ident_end(text, text + size, scanned) == expected;
}

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    g_native_tail_limit = accel_native_scan_tail_limit();
    g_swar_tail_limit = accel_swar_scan_tail_limit();
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Exact-sized copy (no trailing NUL) so ASAN catches 1-byte or SIMD over-reads. */
    uint8_t *text = (uint8_t *) malloc(size > 0 ? size : 1);
    assert(text != NULL);
    if (size > 0) memcpy(text, data, size);

    size_t expected = ascii_ident_end(text, text + size, 0);
    size_t n_native = accel_native_scan_identifier(text, text + size);
    size_t n_swar = accel_swar_scan_identifier(text, text + size);

    int native_ok = ident_scan_valid(text, size, n_native, expected, g_native_tail_limit);
    int swar_ok = ident_scan_valid(text, size, n_swar, expected, g_swar_tail_limit);

    if (!native_ok || !swar_ok) {
        const char *outlier = "both native and swar failed";
        if (!native_ok && swar_ok) outlier = "native (swar satisfies contract)";
        else if (native_ok && !swar_ok) outlier = "swar (native satisfies contract)";

        fprintf(stderr, "\n=== ACCEL DIFFERENTIAL FAILURE [scan_identifier_ascii] ===\n");
        fprintf(stderr, "Outlier : %s\n", outlier);
        fprintf(stderr, "Len     : %zu bytes (no trailing NUL)\n", size);
        fprintf(stderr, "Text    : ");
        fprint_escaped(stderr, text, size, 96);
        fputc('\n', stderr);
        fprintf(stderr, "Contract: prefix of [a-zA-Z0-9_] <= expected (%zu; stopped at ", expected);
        fprint_byte_desc(stderr, text, size, expected);
        fprintf(stderr, "), leaving < chunk_width for scalar tail\n");
        fprint_result(stderr, "native", text, size, n_native, expected, g_native_tail_limit);
        fprint_result(stderr, "swar", text, size, n_swar, expected, g_swar_tail_limit);
        fflush(stderr);
        free(text);
        abort();
    }

    free(text);
    return 0;
}
