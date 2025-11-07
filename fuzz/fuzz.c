#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef IGNORE_ASSERTS
// Set our own assertion handler which does a clean exit. This signals to AFL++ that the input is not interesting. Can
// be used to focus the fuzzer on non-assert issues.
void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function) __attribute__((noreturn));

void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function) {
    printf("%s: %s:%d %s", assertion, file, line, function);
    _exit(0);
}
#endif

void harness(const uint8_t *input, size_t size);

int
LLVMFuzzerTestOneInput(const char *data, size_t size) {
    harness((const uint8_t *) data, size);
    return 0;
}
