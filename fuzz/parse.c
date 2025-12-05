#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <prism.h>


extern FILE *fmemopen(void *buf, size_t size, const char *mode);

static char *s_fgets(char *string, int size, void *stream) {
    return fgets(string, size, (FILE *)stream);
}

static int s_feof(void *stream) {
    return feof((FILE *)stream);
}

static void *open_stream(const uint8_t *input, size_t size) {
    return (void *)fmemopen((void *)input, size, "r");
}

static void close_stream(void *s) {
    fclose((FILE *)s);
}


__attribute__((noinline)) void
harness(const uint8_t *input, size_t size) {
    // parser will be initialized by pm_parse_stream
    pm_parser_t parser;

    void *s = open_stream(input, size);
    assert(s != NULL);

    // buffer will be initialized by pm_parse_stream
    pm_buffer_t buffer;


    pm_node_t *node = pm_parse_stream(&parser, &buffer, s, s_fgets, s_feof, NULL);
    assert(node != NULL);

    {
        pm_buffer_t b;
        pm_buffer_init(&b);
        pm_prettyprint(&b, &parser, node);
        pm_buffer_free(&b);
    }
    {
        pm_buffer_t b;
        pm_buffer_init(&b);
        pm_serialize(&parser, node, &b);
        pm_buffer_free(&b);
    }

    pm_node_destroy(&parser, node);
    pm_parser_free(&parser);
    pm_buffer_free(&buffer);
    close_stream(s);
}
