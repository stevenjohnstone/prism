#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#ifdef PROFILE
#include <signal.h>

extern int __llvm_profile_write_file(void);

void handle_crash_signal(int signum) {
    fprintf(stderr, "Caught signal %d, flushing coverage...\n", signum);
    __llvm_profile_write_file();
    exit(0);
}

void setup_signal_handlers(void) {
    signal(SIGSEGV, handle_crash_signal);
    signal(SIGABRT, handle_crash_signal);
    signal(SIGBUS,  handle_crash_signal);
    signal(SIGILL,  handle_crash_signal);
    signal(SIGFPE,  handle_crash_signal);
}
#endif

extern void harness(const uint8_t *input, size_t size);

int main(int argc, char **argv) {
#ifdef PROFILE
    setup_signal_handlers();
#endif

    char input[512];
    ssize_t n = 0;
    ssize_t bytes_read = 0;

    while ((n = fread(input + bytes_read, 1, sizeof(input) - bytes_read, stdin)) > 0) {
        bytes_read += n;
    }

    if (ferror(stdin)) {
        perror("Error reading from stdin");
        return EXIT_FAILURE;
    }

    harness((const uint8_t *) input, bytes_read);
    return 0;
}

