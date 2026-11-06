#!/usr/bin/env bash
# Verifies test/fuzz/aflplusplus.patch by:
# 1. Compiling a multi-stage nested-if target under none, ubsan, asan+ubsan, and
#    msan with both unpatched and patched AFL++ LTO instrumentation.
# 2. Asserting that sanitizer edge inflation is stripped so patched edge counts
#    closely match the un-sanitized binary.
# 3. Running afl-showmap across progressive prefixes ("aaaaaaaa" .. "PRISM_OK")
#    to verify that every nested branch produces a distinct new coverage edge
#    in every sanitizer mode.
# 4. Running live afl-fuzz (without CmpLog or dictionaries) from "aaaaaaaa"
#    against the ASAN+UBSAN and MSAN binaries to verify coverage guidance solves
#    the 8-byte (2^64) nested conditions and triggers the target abort().

set -euo pipefail

WORKDIR="$(mktemp -d /tmp/test-afl-patch.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

cat << 'EOF' > "$WORKDIR/maze.c"
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

struct state_t {
    uint8_t  b8;
    uint16_t b16;
    uint32_t b32;
    uint64_t b64;
    int32_t  signed_val;
    uint32_t arr[4];
};

__attribute__((noinline))
static void touch_state(struct state_t *s, uint8_t v, int step) {
    /* Triggers ASAN 1/2/4/8-byte stores and UAR prologue/epilogue, UBSAN shift,
       signed addition, array bounds, and alignment checks, MSAN shadow select
       propagation, and compound assert() trap checks. */
    s->b8  = v;
    s->b16 = (uint16_t)v << (step & 7);
    s->b32 = (uint32_t)v + (uint32_t)step;
    s->b64 = (uint64_t)s->b16 ^ (uint64_t)s->b32;
    s->signed_val += (int32_t)v;
    s->arr[step & 3] = (v & 1) ? s->b32 : (uint32_t)s->b16;
    assert(s->signed_val >= 0 && (s->b64 ^ (uint64_t)s->signed_val) != 0xdeadbeefcafebabeULL);
}

__attribute__((noinline))
static int classify_tag(struct state_t *s, uint8_t c) {
    /* Multi-branch if/else-if sinking stores into a common merge block:
       exercises sanitizer checks inside branch-only blocks before a
       multi-predecessor merge block. */
    if (c == 'A') {
        s->b32 = 10;
    } else if (c == 'E') {
        s->b32 = 20;
    } else if (c == 'I') {
        s->b32 = 30;
    } else if (c == 'O') {
        s->b32 = 40;
    } else {
        return 0;
    }
    assert(s->b32 >= 10 && s->b32 <= 40);
    return (int)s->b32;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    struct state_t s = {0};

    /* 8 nested single-byte conditions (2^64 search space: unsolvable by brute
       force without step-by-step edge coverage feedback). */
    if (data[0] == 'P') {
        touch_state(&s, data[0], 0);
        if (data[1] == 'R') {
            touch_state(&s, data[1], 1);
            if (data[2] == 'I') {
                touch_state(&s, data[2], 2);
                if (data[3] == 'S') {
                    touch_state(&s, data[3], 3);
                    if (data[4] == 'M') {
                        touch_state(&s, data[4], 4);
                        if (data[5] == '_') {
                            touch_state(&s, data[5], 5);
                            if (classify_tag(&s, data[6]) == 40) {
                                touch_state(&s, data[6], 6);
                                if (data[7] == 'K') {
                                    touch_state(&s, data[7], 7);
                                    if (s.b8 == 'K') {
                                        abort();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}
EOF

extract_locations() {
    sed -n 's/.*Instrumented \([0-9][0-9]*\) locations.*/\1/p' | tail -n 1
}

compile_mode() {
    local afl_path="$1"
    local mode="$2"
    local out_bin="$3"
    local flags="-O2 -std=c99 -fsanitize=fuzzer"
    local env_vars="AFL_DEBUG=1 AFL_PATH=$afl_path"

    case "$mode" in
        ubsan)
            env_vars="$env_vars AFL_USE_UBSAN=1 AFL_UBSAN_VERBOSE=1"
            ;;
        asan_ubsan)
            env_vars="$env_vars AFL_USE_UBSAN=1 AFL_UBSAN_VERBOSE=1"
            flags="$flags -mllvm -asan-instrument-reads=0 -Wl,-mllvm,-asan-instrument-reads=0 -fsanitize=address"
            ;;
        msan)
            env_vars="$env_vars AFL_USE_MSAN=1"
            ;;
    esac

    env $env_vars afl-clang-lto $flags -o "$out_bin" "$WORKDIR/maze.c" 2>&1 | extract_locations
}

echo "[1/3] Checking instrumented edge counts (unpatched vs patched AFL++)..."
unpatched_none=$(compile_mode /usr/local/lib/afl none "$WORKDIR/unpatched_none")
unpatched_ubsan=$(compile_mode /usr/local/lib/afl ubsan "$WORKDIR/unpatched_ubsan")
unpatched_asan=$(compile_mode /usr/local/lib/afl asan_ubsan "$WORKDIR/unpatched_asan_ubsan")
unpatched_msan=$(compile_mode /usr/local/lib/afl msan "$WORKDIR/unpatched_msan")

patched_none=$(compile_mode "$(pwd)/build/afl" none "$WORKDIR/patched_none")
patched_ubsan=$(compile_mode "$(pwd)/build/afl" ubsan "$WORKDIR/patched_ubsan")
patched_asan=$(compile_mode "$(pwd)/build/afl" asan_ubsan "$WORKDIR/patched_asan_ubsan")
patched_msan=$(compile_mode "$(pwd)/build/afl" msan "$WORKDIR/patched_msan")

printf "  %-12s : unpatched=%-4s  patched=%-4s\n" "none" "$unpatched_none" "$patched_none"
printf "  %-12s : unpatched=%-4s  patched=%-4s\n" "ubsan" "$unpatched_ubsan" "$patched_ubsan"
printf "  %-12s : unpatched=%-4s  patched=%-4s\n" "asan_ubsan" "$unpatched_asan" "$patched_asan"
printf "  %-12s : unpatched=%-4s  patched=%-4s\n" "msan" "$unpatched_msan" "$patched_msan"

if [ "$patched_none" -ge "$unpatched_none" ]; then
    echo "FAIL: patched none locations ($patched_none) >= unpatched none ($unpatched_none); assert() edges were not stripped"
    exit 1
fi
if [ "$patched_msan" != "$patched_none" ]; then
    echo "FAIL: patched msan locations ($patched_msan) != patched none ($patched_none)"
    exit 1
fi
if [ "$patched_asan" -ge "$unpatched_asan" ] || [ "$patched_asan" -gt $((patched_none + 4)) ]; then
    echo "FAIL: patched asan_ubsan locations ($patched_asan) not within expected range of none ($patched_none)"
    exit 1
fi

echo "[2/3] Verifying step-by-step edge discovery via afl-showmap..."
prefixes=("aaaaaaaa" "Paaaaaaa" "PRaaaaaa" "PRIaaaaa" "PRISaaaa" "PRISMaaa" "PRISM_aa" "PRISM_Oa" "PRISM_OK")

for mode in none ubsan asan_ubsan msan; do
    seen_file="$WORKDIR/seen_$mode.txt"
    : > "$seen_file"
    prev_total=0

    for inp in "${prefixes[@]}"; do
        printf "%s" "$inp" > "$WORKDIR/input"
        afl-showmap -q -o "$WORKDIR/map" -- "$WORKDIR/patched_$mode" "$WORKDIR/input" >/dev/null 2>&1 || true
        awk -F: '{print $1}' "$WORKDIR/map" >> "$seen_file"
        sort -u -o "$seen_file" "$seen_file"
        cur_total=$(wc -l < "$seen_file" | tr -d ' ')
        if [ "$cur_total" -le "$prev_total" ]; then
            echo "FAIL ($mode): prefix '$inp' did not discover a new coverage edge (cumulative edges stayed at $cur_total)"
            exit 1
        fi
        prev_total=$cur_total
    done
    echo "  $mode: all ${#prefixes[@]} prefixes discovered strictly increasing unique edges (total: $prev_total)"
done

echo "[3/3] Running live afl-fuzz coverage-guided solve (8-byte / 2^64 search space)..."
mkdir -p "$WORKDIR/in"
printf "aaaaaaaa" > "$WORKDIR/in/seed"

for mode in asan_ubsan msan; do
    out_dir="$WORKDIR/out_$mode"
    AFL_NO_UI=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_BENCH_UNTIL_CRASH=1 \
        timeout 30s afl-fuzz -d -i "$WORKDIR/in" -o "$out_dir" -- "$WORKDIR/patched_$mode" >"$WORKDIR/fuzz_$mode.log" 2>&1 || true

    crash_file=$(find "$out_dir/default/crashes" -name 'id:*' 2>/dev/null | head -n 1 || true)
    if [ -z "$crash_file" ]; then
        echo "FAIL ($mode): afl-fuzz did not solve the nested conditions within 30s"
        tail -n 20 "$WORKDIR/fuzz_$mode.log"
        exit 1
    fi

    crash_prefix=$(head -c 8 "$crash_file")
    execs_done=$(awk '/execs_done/ {print $3}' "$out_dir/default/fuzzer_stats")
    if [ "$crash_prefix" != "PRISM_OK" ]; then
        echo "FAIL ($mode): unexpected crash input '$crash_prefix' (expected 'PRISM_OK')"
        exit 1
    fi
    echo "  $mode: solved 'PRISM_OK' in $execs_done executions"
done

echo "PASS: AFL++ sanitizer coverage patch verified."

