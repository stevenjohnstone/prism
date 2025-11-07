#include <prism.h>

void
harness(const uint8_t *input, size_t size) {
    pm_parse_success_p(input, size, NULL);
}
