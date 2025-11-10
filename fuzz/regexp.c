#include <prism.h>

void
harness(const uint8_t *input, size_t size) {
    if (size >= 32) {
        return;
    }
    const char *suffix = "/ =~ \"foo\"";
    const size_t suffix_size = strlen(suffix);
    const size_t regexp_size = size + 1 + suffix_size;
    uint8_t *regexp = malloc(regexp_size);
    regexp[0] = '/';
    memcpy(regexp + 1, input, size);
    memcpy(regexp + 1 + size, suffix, suffix_size);
    pm_parse_success_p(regexp, regexp_size, NULL);
    free(regexp);
}
