#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef PROFILE
#include <signal.h>
#include <unistd.h>

extern int __llvm_profile_write_file(void);

static void handle_crash_signal(int signum) {
    (void) signum;
    __llvm_profile_write_file();
    _exit(1);
}

static void setup_signal_handlers(void) {
    signal(SIGSEGV, handle_crash_signal);
    signal(SIGABRT, handle_crash_signal);
    signal(SIGBUS,  handle_crash_signal);
    signal(SIGILL,  handle_crash_signal);
    signal(SIGFPE,  handle_crash_signal);
}
#endif

extern void harness(const uint8_t *input, size_t size);

static int run_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
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
        harness(buf, read_bytes);
    }

    free(buf);
    return had_error ? 1 : 0;
}

static int run_stdin(void) {
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
        perror("Error reading from stdin");
        free(buf);
        return EXIT_FAILURE;
    }

    harness(buf, len);
    free(buf);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
#ifdef PROFILE
    setup_signal_handlers();
#endif

    if (argc <= 1) {
        return run_stdin();
    }

    int status = EXIT_SUCCESS;
    for (int i = 1; i < argc; i++) {
        if (run_file(argv[i]) != 0) {
            status = EXIT_FAILURE;
        }
    }
    return status;
}
