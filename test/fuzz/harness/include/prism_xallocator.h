#ifndef PRISM_XALLOCATOR_H
#define PRISM_XALLOCATOR_H
#include <stddef.h>

void *fuzz_malloc(size_t);
void *fuzz_realloc(void *, size_t);
void *fuzz_realloc_sized(void *, size_t, size_t);
void *fuzz_calloc(size_t, size_t);
void fuzz_free(void *);
void fuzz_free_sized(void *, size_t);

#define xmalloc         fuzz_malloc
#define xrealloc        fuzz_realloc
#define xrealloc_sized  fuzz_realloc_sized
#define xcalloc         fuzz_calloc
#define xfree           fuzz_free
#define xfree_sized     fuzz_free_sized
#endif
