#!/usr/bin/env bash
# Builds and runs a minimal PASS/FAIL differential libFuzzer target comparing
# native SIMD (NEON/SSE2) vs SWAR scan_identifier_ascii under ASAN + UBSAN.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CC_BIN="${CC:-clang}"
WORKDIR="$(mktemp -d /tmp/test-fuzz-accel.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

OUT_BIN="${ACCEL_BIN:-$WORKDIR/fuzz.accel}"
OUT_DIR="$(dirname "$OUT_BIN")"
mkdir -p "$OUT_DIR" "$WORKDIR/obj"

CFLAGS_COMMON=(
    -std=c99
    -O1
    -g
    -fPIC
    -Wall
    -Wextra
    -Werror
    -Wundef
    -Wconversion
    -Wno-missing-braces
    -Wimplicit-fallthrough
    -Wno-unused-function
    -I"$ROOT_DIR/include"
    -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    -fsanitize=fuzzer-no-link,address,undefined
    -fno-sanitize-recover=all
)

build_variant_so() {
    local backend="$1"
    shift
    local obj_dir="$WORKDIR/obj/$backend"
    local map_file="$WORKDIR/${backend}.map"
    local so_file="$OUT_DIR/libprism_${backend}.so"
    mkdir -p "$obj_dir"

    cat > "$map_file" <<EOF
{
    global:
        accel_${backend}_*;
    local:
        *;
};
EOF

    local objs=()
    for src in "$ROOT_DIR"/src/*.c; do
        local base
        base="$(basename "$src" .c)"
        # src/prism.c is #included directly by accel_backend.c so static scan_identifier_ascii stays in scope.
        if [ "$base" = "prism" ]; then
            continue
        fi
        local obj="$obj_dir/${base}.o"
        "$CC_BIN" "${CFLAGS_COMMON[@]}" "$@" -c "$src" -o "$obj"
        objs+=("$obj")
    done

    "$CC_BIN" "${CFLAGS_COMMON[@]}" "$@" -DACCEL_BACKEND="$backend" \
        -c "$ROOT_DIR/test/fuzz/harness/accel_backend.c" -o "$obj_dir/accel_backend.o"
    objs+=("$obj_dir/accel_backend.o")

    "$CC_BIN" -shared -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all \
        -Wl,--version-script="$map_file" -Wl,-Bsymbolic \
        "${objs[@]}" -o "$so_file"
}

echo "[1/3] Building isolated native and SWAR libprism shared libraries..."
build_variant_so native &
pid_native=$!
build_variant_so swar -DPRISM_ACCEL_SWAR &
pid_swar=$!
wait "$pid_native" "$pid_swar"

echo "[2/3] Linking $OUT_BIN..."
"$CC_BIN" -std=c99 -O1 -g -Wall -Wextra -Werror -Wundef -Wconversion \
    -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
    "$ROOT_DIR/test/fuzz/harness/accel.c" \
    "$OUT_DIR/libprism_native.so" \
    "$OUT_DIR/libprism_swar.so" \
    -Wl,-rpath,'$ORIGIN' \
    -o "$OUT_BIN"

CORPUS_DIR="$WORKDIR/corpus"
ARTIFACT_DIR="${ACCEL_ARTIFACT_DIR:-$WORKDIR/artifacts}"
mkdir -p "$CORPUS_DIR" "$ARTIFACT_DIR"

ruby - "$CORPUS_DIR" <<'RUBY'
dir = ARGV[0]
seeds = [
  "",
  "a",
  "abc_0123456789abcdef",
  "AbBa_1234567890" * 3,
  "________+tail",
  "x_" * 12 + "\x82\xa0!",
].map(&:b)
seeds.each_with_index do |s, i|
  File.binwrite(File.join(dir, "seed_#{i}"), s)
end
RUBY

if [ -n "${ACCEL_FUZZ_ARGS:-}" ]; then
    # Intentional word splitting when caller supplies custom libFuzzer flags/paths.
    read -r -a FUZZ_ARGS <<< "$ACCEL_FUZZ_ARGS"
    has_positional=0
    for arg in "${FUZZ_ARGS[@]}"; do
        case "$arg" in
            -*) ;;
            *) has_positional=1; break ;;
        esac
    done
    if [ "$has_positional" -eq 0 ]; then
        FUZZ_ARGS+=("$CORPUS_DIR")
    fi
else
    FUZZ_ARGS=(-max_len=4096 -max_total_time="${ACCEL_TIME:-10}" "$CORPUS_DIR")
fi

echo "[3/3] Running PASS/FAIL accel differential fuzzer (${FUZZ_ARGS[*]})..."
if ! "$OUT_BIN" -artifact_prefix="$ARTIFACT_DIR/" "${FUZZ_ARGS[@]}"; then
    if [ -z "${ACCEL_ARTIFACT_DIR:-}" ] && find "$ARTIFACT_DIR" -maxdepth 1 -type f | grep -q .; then
        FAIL_DIR="$ROOT_DIR/tmp/fuzz/accel-failures"
        mkdir -p "$FAIL_DIR"
        cp -f "$ARTIFACT_DIR"/* "$FAIL_DIR"/
        echo "FAIL: saved accel divergence/crash artifact(s) to $FAIL_DIR" >&2
    fi
    exit 1
fi
echo "PASS: accel differential fuzzer completed with zero divergences or sanitizer errors."
