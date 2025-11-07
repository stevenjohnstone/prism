#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef IGNORE_ASSERTS
void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function) __attribute__((noreturn));

void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function) {
    fprintf(stderr, "%s: %s:%d %s\n", assertion, file, line, function);
    _exit(0);
}
#endif

// causes an abort when an ASAN error occurs. When
// something else calls abort() (e.g. an assert), the
// asan error handler will kick in giving a nice
// backtrace
extern const char *__asan_default_option(void);


const char* __asan_default_options(void) {
    return "abort_on_error=1:handle_abort=1";
}
extern void harness(const uint8_t *input, size_t size);

int
LLVMFuzzerTestOneInput(const char *data, size_t size) {
    harness((const uint8_t *) data, size);
    return 0;
}
