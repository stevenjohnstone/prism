#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__has_feature)
#  if __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
#define MSAN_ENABLED
#  endif
#endif

#ifdef IGNORE_ASSERTS
void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function) __attribute__((noreturn));

void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function) {
    fprintf(stderr, "%s: %s:%d %s\n", assertion, file, line, function);
    _exit(0);
}
#endif

static size_t allocated = 0;

#ifndef FUZZ_MAX_ALLOCATED
#define FUZZ_MAX_ALLOCATED 64
#endif

#ifndef FUZZ_HARD_RSS_LIMIT
#define FUZZ_HARD_RSS_LIMIT 2048
#endif

#define FUZZ_MAX_ALLOCATED_BYTES ((size_t) FUZZ_MAX_ALLOCATED * 1024 * 1024)
#define FUZZ_STR_HELPER(x) #x
#define FUZZ_STR(x) FUZZ_STR_HELPER(x)

#ifdef PRISM_XALLOCATOR
__attribute__((noinline))
void *fuzz_malloc(size_t s) {
    assert(s <= FUZZ_MAX_ALLOCATED_BYTES && allocated <= FUZZ_MAX_ALLOCATED_BYTES - s);
    void *ptr = malloc(s + sizeof(size_t));
    if (ptr == NULL) {
        return NULL;
    }
    memcpy(ptr, (void *)&s, sizeof(size_t));
    allocated += s;
    return (char *)ptr + sizeof(size_t);
}

__attribute__((noinline))
void fuzz_free(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    size_t s;
    memcpy((void *)&s, (char *)ptr - sizeof(size_t), sizeof(size_t));
    allocated -= s;
    free((char *)ptr - sizeof(size_t));
}

__attribute__((noinline))
void *fuzz_calloc(size_t n, size_t s) {
    assert(s == 0 || n <= FUZZ_MAX_ALLOCATED_BYTES / s);
    void *ptr = fuzz_malloc(n * s);
    if (ptr == NULL) {
        return NULL;
    }
    memset(ptr, 0, n * s);
    return ptr;
}

__attribute__((noinline))
void *fuzz_realloc(void *ptr, size_t s) {
    if (ptr == NULL) {
        return fuzz_malloc(s);
    }
    if (s == 0) {
        fuzz_free(ptr);
        return NULL;
    }
    char *raw_ptr = (char *)ptr - sizeof(size_t);
    size_t old_size;
    memcpy((void *)&old_size, raw_ptr, sizeof(size_t));
    assert(s <= FUZZ_MAX_ALLOCATED_BYTES && allocated - old_size <= FUZZ_MAX_ALLOCATED_BYTES - s);

    char *new_raw_ptr = realloc(raw_ptr, s + sizeof(size_t));
    if (new_raw_ptr == NULL) {
        return NULL;
    }
    memcpy(new_raw_ptr, (void *)&s, sizeof(size_t));
    allocated = allocated - old_size + s;
    return new_raw_ptr + sizeof(size_t);
}

#endif

// causes an abort when an ASAN error occurs. When
// something else calls abort() (e.g. an assert), the
// asan error handler will kick in giving a nice
// backtrace
extern const char *__asan_default_options(void);


const char* __asan_default_options(void) {
    return "abort_on_error=1:handle_abort=1:max_allocation_size_mb=" FUZZ_STR(FUZZ_MAX_ALLOCATED) ":hard_rss_limit_mb=" FUZZ_STR(FUZZ_HARD_RSS_LIMIT);
}
extern void harness(const uint8_t *input, size_t size);

int
LLVMFuzzerTestOneInput(const char *data, size_t size) {

#ifdef MSAN_ENABLED
    // It appears that AFL++ is a bit broken when it comes to MSAN.
    // The driver is built without MSAN enabled so malloc'ed
    // buffers passed to this function appear to be uninitialized
    __msan_unpoison(data, size);
#endif
    harness((const uint8_t *) data, size);
    assert(allocated == 0);
    return 0;
}
