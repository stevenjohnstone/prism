/*
 * Per-backend shared-library wrapper for differential fuzzing of
 * scan_identifier_ascii (native NEON/SSE2 vs SWAR).
 *
 * Includes untouched src/prism.c directly so static scan_identifier_ascii is in
 * scope; a linker version script hides all internal pm_* symbols inside each
 * DSO so both variants link cleanly into accel.c without colliding.
 */

#ifndef ACCEL_BACKEND
#error "ACCEL_BACKEND must be defined (e.g. native or swar)"
#endif

#include "../../../src/prism.c"

#define ACCEL_CAT_IMPL(a, b) a##_##b
#define ACCEL_CAT(a, b) ACCEL_CAT_IMPL(a, b)
#define ACCEL_SYM(name) ACCEL_CAT(accel, ACCEL_CAT(ACCEL_BACKEND, name))

size_t ACCEL_SYM(scan_identifier)(const uint8_t *start, const uint8_t *end);
size_t ACCEL_SYM(scan_tail_limit)(void);

size_t
ACCEL_SYM(scan_identifier)(const uint8_t *start, const uint8_t *end) {
    (void) start;
    (void) end;
    return (size_t) scan_identifier_ascii(start, end);
}

size_t
ACCEL_SYM(scan_tail_limit)(void) {
#if defined(PRISM_HAS_NEON) || defined(PRISM_HAS_SSE2)
    return 16;
#elif defined(PRISM_HAS_SWAR)
    return 8;
#else
    return 1;
#endif
}
