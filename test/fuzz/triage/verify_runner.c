#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#  ifdef MAP_ANON
#    define MAP_ANONYMOUS MAP_ANON
#  endif
#endif

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct {
    char *name;
    uint8_t *data;
    size_t size;
} verify_entry_t;

typedef struct {
    verify_entry_t *items;
    size_t count;
    size_t cap;
} entry_list_t;

typedef struct {
    char *name;
    size_t size;
    bool timed_out;
    int exit_status;
    int term_signal;
    char *output;
    size_t output_len;
} verify_failure_t;

typedef struct {
    volatile size_t current_idx;
    volatile sig_atomic_t finished_loop;
} verify_shared_t;

static void die_oom(void) {
    fprintf(stderr, "verify_runner: out of memory\n");
    exit(2);
}

static void *xmalloc_local(size_t n) {
    void *p = malloc(n > 0 ? n : 1);
    if (!p) die_oom();
    return p;
}

static void *xrealloc_local(void *ptr, size_t n) {
    void *p = realloc(ptr, n > 0 ? n : 1);
    if (!p) die_oom();
    return p;
}

static char *xstrdup_local(const char *s) {
    size_t len = strlen(s);
    char *out = xmalloc_local(len + 1);
    memcpy(out, s, len + 1);
    return out;
}

static const char *path_basename_local(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void entry_list_push(entry_list_t *list, const char *name, uint8_t *data, size_t size) {
    if (list->count == list->cap) {
        size_t new_cap = list->cap == 0 ? 64 : list->cap * 2;
        if (new_cap < list->cap || new_cap > SIZE_MAX / sizeof(verify_entry_t)) die_oom();
        list->items = xrealloc_local(list->items, new_cap * sizeof(verify_entry_t));
        list->cap = new_cap;
    }
    list->items[list->count].name = xstrdup_local(name);
    list->items[list->count].data = data;
    list->items[list->count].size = size;
    list->count++;
}

static bool read_exact(FILE *fp, void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < n) {
        size_t got = fread(p + off, 1, n - off, fp);
        if (got == 0) return false;
        off += got;
    }
    return true;
}

static bool skip_exact(FILE *fp, size_t n) {
    uint8_t scratch[4096];
    size_t rem = n;
    while (rem > 0) {
        size_t chunk = rem > sizeof(scratch) ? sizeof(scratch) : rem;
        if (!read_exact(fp, scratch, chunk)) return false;
        rem -= chunk;
    }
    return true;
}

static bool is_zero_block(const uint8_t blk[512]) {
    for (size_t i = 0; i < 512; i++) {
        if (blk[i] != 0) return false;
    }
    return true;
}

static bool parse_tar_size(const uint8_t hdr[512], size_t *out_size) {
    /* GNU base-256 extension uses high bit 0x80 on first byte */
    if ((hdr[124] & 0x80) != 0) {
        uint64_t val = hdr[124] & 0x7f;
        for (size_t i = 125; i < 136; i++) {
            if (val > (UINT64_MAX >> 8)) return false;
            val = (val << 8) | hdr[i];
        }
        if (val > SIZE_MAX) return false;
        *out_size = (size_t)val;
        return true;
    }

    uint64_t val = 0;
    bool seen = false;
    for (size_t i = 124; i < 136; i++) {
        unsigned char c = hdr[i];
        if (c == '\0' || c == ' ') {
            if (seen) break;
            continue;
        }
        if (c < '0' || c > '7') return false;
        seen = true;
        if (val > (UINT64_MAX >> 3)) return false;
        val = (val << 3) | (uint64_t)(c - '0');
    }
    if (val > SIZE_MAX) return false;
    *out_size = (size_t)val;
    return true;
}

static int load_file_entry(entry_list_t *list, const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "verify_runner: cannot open '%s': %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        fprintf(stderr, "verify_runner: fseek failed on '%s'\n", path);
        return -1;
    }
    long len = ftell(fp);
    if (len < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        fprintf(stderr, "verify_runner: ftell failed on '%s'\n", path);
        return -1;
    }
    size_t sz = (size_t)len;
    uint8_t *buf = xmalloc_local(sz > 0 ? sz : 1);
    if (sz > 0 && !read_exact(fp, buf, sz)) {
        free(buf);
        fclose(fp);
        fprintf(stderr, "verify_runner: short read on '%s'\n", path);
        return -1;
    }
    fclose(fp);
    entry_list_push(list, path_basename_local(path), buf, sz);
    return 0;
}

static int load_tar_entries(entry_list_t *list, const char *tar_path) {
    FILE *fp = strcmp(tar_path, "-") == 0 ? stdin : fopen(tar_path, "rb");
    if (!fp) {
        fprintf(stderr, "verify_runner: cannot open tar '%s': %s\n", tar_path, strerror(errno));
        return -1;
    }

    char *gnu_longname = NULL;
    uint8_t hdr[512];
    while (read_exact(fp, hdr, sizeof(hdr))) {
        if (is_zero_block(hdr)) break;

        size_t sz = 0;
        if (!parse_tar_size(hdr, &sz)) {
            fprintf(stderr, "verify_runner: invalid tar header size in '%s'\n", tar_path);
            free(gnu_longname);
            if (fp != stdin) fclose(fp);
            return -1;
        }
        size_t pad = (512 - (sz % 512)) % 512;
        uint8_t typeflag = hdr[156];

        if (typeflag == 'L') {
            free(gnu_longname);
            gnu_longname = xmalloc_local(sz + 1);
            if ((sz > 0 && !read_exact(fp, gnu_longname, sz)) || (pad > 0 && !skip_exact(fp, pad))) {
                free(gnu_longname);
                if (fp != stdin) fclose(fp);
                return -1;
            }
            gnu_longname[sz] = '\0';
            continue;
        }

        if (typeflag == 'x' || typeflag == 'g' || typeflag == 'K') {
            if ((sz > 0 && !skip_exact(fp, sz)) || (pad > 0 && !skip_exact(fp, pad))) {
                free(gnu_longname);
                if (fp != stdin) fclose(fp);
                return -1;
            }
            continue;
        }

        char namebuf[257];
        const char *entry_name = gnu_longname;
        if (!entry_name) {
            char raw_prefix[156];
            char raw_name[101];
            memcpy(raw_prefix, hdr + 345, 155);
            raw_prefix[155] = '\0';
            memcpy(raw_name, hdr + 0, 100);
            raw_name[100] = '\0';
            if (raw_prefix[0] != '\0') {
                snprintf(namebuf, sizeof(namebuf), "%s/%s", raw_prefix, raw_name);
            } else {
                snprintf(namebuf, sizeof(namebuf), "%s", raw_name);
            }
            entry_name = namebuf;
        }

        if (typeflag == '\0' || typeflag == '0') {
            uint8_t *data = xmalloc_local(sz > 0 ? sz : 1);
            if ((sz > 0 && !read_exact(fp, data, sz)) || (pad > 0 && !skip_exact(fp, pad))) {
                free(data);
                free(gnu_longname);
                if (fp != stdin) fclose(fp);
                return -1;
            }
            entry_list_push(list, path_basename_local(entry_name), data, sz);
        } else {
            if ((sz > 0 && !skip_exact(fp, sz)) || (pad > 0 && !skip_exact(fp, pad))) {
                free(gnu_longname);
                if (fp != stdin) fclose(fp);
                return -1;
            }
        }

        free(gnu_longname);
        gnu_longname = NULL;
    }

    free(gnu_longname);
    if (fp != stdin) fclose(fp);
    return 0;
}

static int load_pack_entries(entry_list_t *list, const char *pack_path) {
    FILE *fp = strcmp(pack_path, "-") == 0 ? stdin : fopen(pack_path, "rb");
    if (!fp) {
        fprintf(stderr, "verify_runner: cannot open pack '%s': %s\n", pack_path, strerror(errno));
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t llen = strlen(line);
        if (llen > 0 && line[llen - 1] == '\n') line[--llen] = '\0';
        if (llen == 0) continue;

        char *tab = strchr(line, '\t');
        if (!tab) {
            fprintf(stderr, "verify_runner: malformed pack header in '%s'\n", pack_path);
            if (fp != stdin) fclose(fp);
            return -1;
        }
        *tab = '\0';
        const char *name = line;
        char *endp = NULL;
        errno = 0;
        unsigned long long raw_sz = strtoull(tab + 1, &endp, 10);
        if (errno != 0 || endp == tab + 1 || *endp != '\0' || raw_sz > SIZE_MAX) {
            fprintf(stderr, "verify_runner: malformed pack size in '%s'\n", pack_path);
            if (fp != stdin) fclose(fp);
            return -1;
        }
        size_t sz = (size_t)raw_sz;
        uint8_t *data = xmalloc_local(sz > 0 ? sz : 1);
        if (sz > 0 && !read_exact(fp, data, sz)) {
            free(data);
            fprintf(stderr, "verify_runner: truncated pack entry in '%s'\n", pack_path);
            if (fp != stdin) fclose(fp);
            return -1;
        }
        int trailing = fgetc(fp);
        if (trailing != '\n' && trailing != EOF) {
            ungetc(trailing, fp);
        }
        entry_list_push(list, path_basename_local(name), data, sz);
    }

    if (fp != stdin) fclose(fp);
    return 0;
}

static void write_safe_extract(const char *extract_dir, const verify_entry_t *entry) {
    if (!extract_dir) return;

    char safe[256];
    size_t j = 0;
    for (size_t i = 0; entry->name[i] != '\0' && j + 1 < sizeof(safe); i++) {
        unsigned char c = (unsigned char)entry->name[i];
        if (isalnum(c) || c == '.' || c == '_' || c == '-' || c == ':' || c == ',') {
            safe[j++] = (char)c;
        } else {
            safe[j++] = '_';
        }
    }
    if (j == 0 || strcmp(safe, ".") == 0 || strcmp(safe, "..") == 0) {
        snprintf(safe, sizeof(safe), "input");
    } else {
        safe[j] = '\0';
    }

    size_t path_len = strlen(extract_dir) + 1 + strlen(safe) + 1;
    char *out_path = xmalloc_local(path_len);
    snprintf(out_path, path_len, "%s/%s", extract_dir, safe);

    FILE *fp = fopen(out_path, "wb");
    if (fp) {
        if (entry->size > 0) fwrite(entry->data, 1, entry->size, fp);
        fclose(fp);
    } else {
        fprintf(stderr, "verify_runner: warning: could not extract '%s': %s\n", out_path, strerror(errno));
    }
    free(out_path);
}

static const char *extract_headline(const char *output, size_t len, char *buf, size_t buf_sz) {
    if (!output || len == 0) {
        buf[0] = '\0';
        return buf;
    }

    const char *prefixes[] = {
        "INVARIANT[",
        "SUMMARY: ",
        "ERROR: ",
    };
    for (size_t p = 0; p < sizeof(prefixes) / sizeof(prefixes[0]); p++) {
        const char *hit = NULL;
        const char *cur = output;
        const char *end = output + len;
        size_t plen = strlen(prefixes[p]);
        while (cur < end) {
            const char *nl = memchr(cur, '\n', (size_t)(end - cur));
            size_t llen = nl ? (size_t)(nl - cur) : (size_t)(end - cur);
            if (llen >= plen && strncmp(cur, prefixes[p], plen) == 0) {
                hit = cur;
                size_t copy = llen < buf_sz - 1 ? llen : buf_sz - 1;
                memcpy(buf, hit, copy);
                buf[copy] = '\0';
                return buf;
            }
            if (!nl) break;
            cur = nl + 1;
        }
    }

    /* Fall back to runtime error / Assertion / first non-empty line */
    const char *cur = output;
    const char *end = output + len;
    const char *first_nonempty = NULL;
    size_t first_len = 0;
    while (cur < end) {
        const char *nl = memchr(cur, '\n', (size_t)(end - cur));
        size_t llen = nl ? (size_t)(nl - cur) : (size_t)(end - cur);
        if (llen > 0 && !first_nonempty) {
            first_nonempty = cur;
            first_len = llen;
        }
        if (llen > 0) {
            /* simple substring check inside bounded line copy */
            char tmp[256];
            size_t cpy = llen < sizeof(tmp) - 1 ? llen : sizeof(tmp) - 1;
            memcpy(tmp, cur, cpy);
            tmp[cpy] = '\0';
            if (strstr(tmp, "runtime error:") || strstr(tmp, "Assertion `") || strstr(tmp, "Assertion failed")) {
                size_t out_cpy = cpy < buf_sz - 1 ? cpy : buf_sz - 1;
                memcpy(buf, tmp, out_cpy);
                buf[out_cpy] = '\0';
                return buf;
            }
        }
        if (!nl) break;
        cur = nl + 1;
    }

    if (first_nonempty) {
        size_t copy = first_len < buf_sz - 1 ? first_len : buf_sz - 1;
        memcpy(buf, first_nonempty, copy);
        buf[copy] = '\0';
    } else {
        buf[0] = '\0';
    }
    return buf;
}

static void print_json_string(const char *s, size_t len) {
    putchar('"');
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  fputs("\\\"", stdout); break;
            case '\\': fputs("\\\\", stdout); break;
            case '\b': fputs("\\b", stdout); break;
            case '\f': fputs("\\f", stdout); break;
            case '\n': fputs("\\n", stdout); break;
            case '\r': fputs("\\r", stdout); break;
            case '\t': fputs("\\t", stdout); break;
            default:
                if (c < 0x20 || c >= 0x7f) {
                    printf("\\u%04x", (unsigned)c);
                } else {
                    putchar((int)c);
                }
                break;
        }
    }
    putchar('"');
}

static void print_usage(FILE *out) {
    fprintf(out,
        "Usage: verify_runner [OPTIONS] [FILE...]\n"
        "  --tar PATH         Read inputs from POSIX tar archive ('-' for stdin)\n"
        "  --pack PATH        Read inputs from length-prefixed pack ('-' for stdin)\n"
        "  --timeout SEC      Per-input alarm timeout in seconds (default: 5, 0 disables)\n"
        "  --max-failures N   Stop after N failing inputs (default: 0 = unlimited)\n"
        "  --extract-dir DIR  Copy any failing inputs into DIR\n"
        "  --quiet            Suppress stderr snippets for failing inputs\n"
        "  --verbose          Print full captured stderr for failing inputs\n"
        "  --json             Print machine-readable JSON summary\n"
    );
}

int main(int argc, char **argv) {
    int timeout_sec = 5;
    size_t max_failures = 0;
    const char *extract_dir = NULL;
    bool quiet = false;
    bool verbose = false;
    bool json_mode = false;
    entry_list_t entries = {0};

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_usage(stdout);
            return 0;
        } else if (strcmp(arg, "--tar") == 0 && i + 1 < argc) {
            if (load_tar_entries(&entries, argv[++i]) != 0) return 2;
        } else if (strcmp(arg, "--pack") == 0 && i + 1 < argc) {
            if (load_pack_entries(&entries, argv[++i]) != 0) return 2;
        } else if (strcmp(arg, "--timeout") == 0 && i + 1 < argc) {
            timeout_sec = atoi(argv[++i]);
            if (timeout_sec < 0) timeout_sec = 0;
        } else if (strcmp(arg, "--max-failures") == 0 && i + 1 < argc) {
            max_failures = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(arg, "--extract-dir") == 0 && i + 1 < argc) {
            extract_dir = argv[++i];
        } else if (strcmp(arg, "--quiet") == 0) {
            quiet = true;
        } else if (strcmp(arg, "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(arg, "--json") == 0) {
            json_mode = true;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "verify_runner: unknown option '%s'\n", arg);
            print_usage(stderr);
            return 2;
        } else {
            if (load_file_entry(&entries, arg) != 0) return 2;
        }
    }

    if (extract_dir) {
        if (mkdir(extract_dir, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "verify_runner: cannot create extract dir '%s': %s\n", extract_dir, strerror(errno));
            return 2;
        }
    }

    verify_shared_t *shared = mmap(NULL, sizeof(verify_shared_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) {
        perror("verify_runner: mmap");
        return 2;
    }

    verify_failure_t *failures = NULL;
    size_t fail_count = 0;
    size_t fail_cap = 0;
    size_t timed_out_count = 0;

    size_t pos = 0;
    size_t suspect_end = 0; /* > pos when isolating an atexit/LSan failure inside [pos, suspect_end) */

    while (pos < entries.count) {
        size_t batch_end;
        if (suspect_end > pos) {
            size_t span = suspect_end - pos;
            batch_end = span > 1 ? pos + (span / 2) : pos + 1;
        } else {
            batch_end = entries.count;
        }

        shared->current_idx = pos;
        shared->finished_loop = 0;
        fflush(NULL);

        int pipefd[2];
        if (pipe(pipefd) != 0) {
            perror("verify_runner: pipe");
            return 2;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("verify_runner: fork");
            return 2;
        }

        if (pid == 0) {
            close(pipefd[0]);
            dup2(pipefd[1], STDERR_FILENO);
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]);

            for (size_t i = pos; i < batch_end; i++) {
                shared->current_idx = i;
                __sync_synchronize();
                if (timeout_sec > 0) alarm((unsigned int)timeout_sec);
                static const uint8_t empty_input[1] = { 0 };
                const uint8_t *ptr = entries.items[i].size > 0 ? entries.items[i].data : empty_input;
                LLVMFuzzerTestOneInput(ptr, entries.items[i].size);
                if (timeout_sec > 0) alarm(0);
            }
            shared->finished_loop = 1;
            __sync_synchronize();
            fflush(NULL);
            exit(0);
        }

        close(pipefd[1]);
        size_t max_cap_bytes = 16384;
        char *err_buf = xmalloc_local(max_cap_bytes + 1);
        size_t err_len = 0;
        uint8_t drain[4096];
        for (;;) {
            ssize_t r = read(pipefd[0], drain, sizeof(drain));
            if (r < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (r == 0) break;
            if (err_len < max_cap_bytes) {
                size_t room = max_cap_bytes - err_len;
                size_t copy = (size_t)r < room ? (size_t)r : room;
                memcpy(err_buf + err_len, drain, copy);
                err_len += copy;
            }
        }
        close(pipefd[0]);
        err_buf[err_len] = '\0';

        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}

        bool child_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (child_ok) {
            free(err_buf);
            pos = batch_end;
            if (pos >= suspect_end) suspect_end = 0;
            continue;
        }

        if (shared->finished_loop && (batch_end - pos) > 1) {
            /* Failure occurred at process exit (e.g. LSan leak); bisect [pos, batch_end). */
            free(err_buf);
            suspect_end = batch_end;
            continue;
        }

        size_t fail_idx = shared->current_idx;
        if (fail_idx < pos || fail_idx >= batch_end) {
            fail_idx = pos;
        }

        bool is_timeout = WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM;
        if (is_timeout) timed_out_count++;

        if (fail_count == fail_cap) {
            fail_cap = fail_cap == 0 ? 16 : fail_cap * 2;
            failures = xrealloc_local(failures, fail_cap * sizeof(verify_failure_t));
        }
        verify_failure_t *f = &failures[fail_count++];
        f->name = xstrdup_local(entries.items[fail_idx].name);
        f->size = entries.items[fail_idx].size;
        f->timed_out = is_timeout;
        f->exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        f->term_signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
        f->output = err_buf;
        f->output_len = err_len;

        write_safe_extract(extract_dir, &entries.items[fail_idx]);

        pos = fail_idx + 1;
        if (pos >= suspect_end) suspect_end = 0;

        if (max_failures > 0 && fail_count >= max_failures) {
            break;
        }
    }

    size_t passed_count = (max_failures > 0 && fail_count >= max_failures)
        ? (pos - fail_count)
        : (entries.count - fail_count);
    size_t checked_count = passed_count + fail_count;

    if (json_mode) {
        printf("{\"total\":%zu,\"checked\":%zu,\"passed\":%zu,\"failed\":%zu,\"timed_out\":%zu,\"failures\":[",
               entries.count, checked_count, passed_count, fail_count, timed_out_count);
        for (size_t i = 0; i < fail_count; i++) {
            const verify_failure_t *f = &failures[i];
            char headline[256];
            extract_headline(f->output, f->output_len, headline, sizeof(headline));
            if (i > 0) putchar(',');
            putchar('{');
            fputs("\"name\":", stdout);
            print_json_string(f->name, strlen(f->name));
            printf(",\"size_bytes\":%zu,\"timed_out\":%s,\"exit_status\":%d,\"signal\":%d,\"headline\":",
                   f->size,
                   f->timed_out ? "true" : "false",
                   f->exit_status,
                   f->term_signal);
            print_json_string(headline, strlen(headline));
            fputs(",\"output\":", stdout);
            size_t snippet = verbose ? f->output_len : (f->output_len < 1024 ? f->output_len : 1024);
            print_json_string(f->output, snippet);
            putchar('}');
        }
        puts("]}");
    } else {
        if (fail_count == 0) {
            printf("PASS: %zu/%zu inputs passed\n", passed_count, entries.count);
        } else {
            printf("FAIL: %zu/%zu inputs failed (%zu passed, %zu timed out; %zu total)\n",
                   fail_count, checked_count, passed_count, timed_out_count, entries.count);
            for (size_t i = 0; i < fail_count; i++) {
                const verify_failure_t *f = &failures[i];
                char headline[256];
                extract_headline(f->output, f->output_len, headline, sizeof(headline));
                if (f->timed_out) {
                    printf("  [%zu] %s (%zu B) TIMEOUT (%ds)\n", i + 1, f->name, f->size, timeout_sec);
                } else {
                    printf("  [%zu] %s (%zu B) sig=%d exit=%d %s\n",
                           i + 1, f->name, f->size, f->term_signal, f->exit_status, headline);
                }
                if (!quiet && f->output_len > 0 && (verbose || i < 3)) {
                    size_t show = verbose ? f->output_len : (f->output_len < 1024 ? f->output_len : 1024);
                    fwrite("    ", 1, 4, stdout);
                    for (size_t k = 0; k < show; k++) {
                        putchar((unsigned char)f->output[k]);
                        if (f->output[k] == '\n' && k + 1 < show) fputs("    ", stdout);
                    }
                    if (f->output[show - 1] != '\n') putchar('\n');
                }
            }
        }
    }

    for (size_t i = 0; i < fail_count; i++) {
        free(failures[i].name);
        free(failures[i].output);
    }
    free(failures);
    for (size_t i = 0; i < entries.count; i++) {
        free(entries.items[i].name);
        free(entries.items[i].data);
    }
    free(entries.items);
    munmap(shared, sizeof(verify_shared_t));

    return fail_count == 0 ? 0 : 1;
}

