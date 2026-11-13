#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OSS_DIR="$ROOT_DIR/test/fuzz/oss-fuzz"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "=== OSS-Fuzz integration test suite ==="

echo "[1/6] Checking OSS-Fuzz metadata, Dockerfile, build.sh, and .options..."
[ -f "$OSS_DIR/Dockerfile" ] || { echo "missing Dockerfile" >&2; exit 1; }
grep -q "^FROM gcr.io/oss-fuzz-base/base-builder" "$OSS_DIR/Dockerfile" || {
  echo "Dockerfile must build FROM gcr.io/oss-fuzz-base/base-builder" >&2
  exit 1
}
bash -n "$OSS_DIR/build.sh"

ruby -ryaml -e '
  data = YAML.safe_load(File.read(ARGV[0]))
  raise "missing language: c" unless data["language"] == "c"
  engines = Array(data["fuzzing_engines"])
  %w[libfuzzer afl honggfuzz centipede].each do |eng|
    raise "missing engine #{eng}" unless engines.include?(eng)
  end
  sanitizers = Array(data["sanitizers"])
  %w[address undefined memory].each do |san|
    raise "missing sanitizer #{san}" unless sanitizers.include?(san)
  end
' "$OSS_DIR/project.yaml"

for target in prism_parse_fuzzer prism_full_fuzzer; do
  opt="$OSS_DIR/${target}.options"
  [ -f "$opt" ] || { echo "missing options file: $opt" >&2; exit 1; }
  grep -q "^\[libfuzzer\]" "$opt" || { echo "$opt missing [libfuzzer]" >&2; exit 1; }
  grep -q "^dict = ${target}\.dict$" "$opt" || { echo "$opt missing dict = ${target}.dict" >&2; exit 1; }
  grep -Eq "^max_len = [0-9]+$" "$opt" || { echo "$opt missing max_len" >&2; exit 1; }
done

echo "[2/6] Checking corpus.rb --no-minimize and PRISM_OSS_FUZZ option guards..."
TEST_CORPUS_DIR="$WORKDIR/corpus_nomin"
FUZZ_MAX_INPUT_SIZE=1024 ruby "$ROOT_DIR/test/fuzz/runtime/corpus.rb" --no-minimize "$TEST_CORPUS_DIR" >/dev/null
seed_count="$(find "$TEST_CORPUS_DIR" -maxdepth 1 -type f | wc -l | tr -d ' ')"
[ "$seed_count" -gt 100 ] || { echo "expected >100 generated seeds, got $seed_count" >&2; exit 1; }

CC="${CC:-clang}"
CXX="${CXX:-clang++}"

"$CC" -std=c99 -O1 -DPRISM_OSS_FUZZ -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
  -c "$ROOT_DIR/test/fuzz/harness/fuzz.c" -o "$WORKDIR/fuzz_oss.o"
fuzz_oss_syms="$(nm "$WORKDIR/fuzz_oss.o")"
if grep -Eq ' T (__asan_default_options|__ubsan_default_options)$' <<< "$fuzz_oss_syms"; then
  echo "fuzz.c with -DPRISM_OSS_FUZZ must not define __asan_default_options or __ubsan_default_options" >&2
  exit 1
fi
grep -q ' T LLVMFuzzerTestOneInput$' <<< "$fuzz_oss_syms" || {
  echo "fuzz.c missing LLVMFuzzerTestOneInput symbol" >&2
  exit 1
}

"$CC" -std=c99 -O1 -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
  -c "$ROOT_DIR/test/fuzz/harness/fuzz.c" -o "$WORKDIR/fuzz_local.o"
fuzz_local_syms="$(nm "$WORKDIR/fuzz_local.o")"
grep -q ' T __asan_default_options$' <<< "$fuzz_local_syms" || {
  echo "local fuzz.c build must retain __asan_default_options even with FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION" >&2
  exit 1
}

echo "[3/6] Running test/fuzz/oss-fuzz/build.sh (ASan + UBSan + libFuzzer)..."
export OUT="$WORKDIR/out"
export WORK="$WORKDIR/work"
export SRC="$WORKDIR/src"
mkdir -p "$OUT" "$WORK" "$SRC"

export CC CXX
export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address,undefined -fno-sanitize-recover=all -fsanitize=fuzzer-no-link"
export CXXFLAGS="$CFLAGS"
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"

"$OSS_DIR/build.sh" > "$WORKDIR/build.log" 2>&1 || {
  cat "$WORKDIR/build.log" >&2
  exit 1
}

echo "[4/6] Verifying artifacts and replaying seed corpora (-runs=0, LSan enabled)..."
for target in prism_parse_fuzzer prism_full_fuzzer; do
  [ -x "$OUT/$target" ] || { echo "missing executable $OUT/$target" >&2; exit 1; }
  [ -f "$OUT/${target}.dict" ] || { echo "missing $OUT/${target}.dict" >&2; exit 1; }
  [ -f "$OUT/${target}.options" ] || { echo "missing $OUT/${target}.options" >&2; exit 1; }
  [ -f "$OUT/${target}_seed_corpus.zip" ] || { echo "missing $OUT/${target}_seed_corpus.zip" >&2; exit 1; }

  target_syms="$(nm "$OUT/$target")"
  if grep -Eq ' T (__asan_default_options|__ubsan_default_options)$' <<< "$target_syms"; then
    echo "$target unexpectedly exported strong __asan_default_options or __ubsan_default_options" >&2
    exit 1
  fi
  grep -q ' T pm_strncasecmp$' <<< "$target_syms" || {
    echo "$target expected pm_strncasecmp when AFL_LLVM_CMPLOG is unset" >&2
    exit 1
  }

  unzip_dir="$WORKDIR/unzip-$target"
  mkdir -p "$unzip_dir"
  unzip -q "$OUT/${target}_seed_corpus.zip" -d "$unzip_dir"

  min_seed_bytes="$(python3 -c '
import os, sys
d = sys.argv[1]
files = [os.path.join(d, f) for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))]
assert files, "empty unzipped seed corpus"
print(min(os.path.getsize(f) for f in files))
' "$unzip_dir")"
  [ "$min_seed_bytes" -ge 4 ] || { echo "$target seed smaller than 4-byte option header: $min_seed_bytes" >&2; exit 1; }

  max_len="$(awk -F'= *' '/^max_len/{print $2}' "$OUT/${target}.options")"
  if ! ASAN_OPTIONS=detect_leaks=1:handle_abort=1:abort_on_error=1 \
       UBSAN_OPTIONS=abort_on_error=1:print_stacktrace=1 \
       "$OUT/$target" -artifact_prefix="$WORKDIR/" -dict="$OUT/${target}.dict" -max_len="$max_len" -runs=0 "$unzip_dir" > "$WORKDIR/run-$target.log" 2>&1; then
    tail -n 40 "$WORKDIR/run-$target.log" >&2
    exit 1
  fi
done

echo "[5/6] Verifying MSan C99 compilation of fuzz harness..."
mkdir -p "$WORKDIR/msan"
for f in "$ROOT_DIR/test/fuzz/harness/fuzz.c" "$ROOT_DIR/test/fuzz/harness/parse.c"; do
  "$CC" -std=c99 -I"$ROOT_DIR/include" -O1 -fno-omit-frame-pointer \
    -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
    -fsanitize=memory -fsanitize-memory-track-origins -fsanitize=fuzzer-no-link \
    -DPRISM_OSS_FUZZ -DPM_ARENA_INITIAL_SIZE=0 -DPM_INTEGER_DIVIDE_THRESHOLD=8 -DPRISM_DEPTH_MAXIMUM=128 -DSLOW \
    -c "$f" -o "$WORKDIR/msan/$(basename "$f").o"
done

echo "[6/6] Verifying AFL_LLVM_CMPLOG=1 swaps pm_strncasecmp for libc strncasecmp..."
CMPLOG_OUT="$WORKDIR/cmplog_out"
CMPLOG_WORK="$WORKDIR/cmplog_work"
mkdir -p "$CMPLOG_OUT" "$CMPLOG_WORK"
OUT="$CMPLOG_OUT" WORK="$CMPLOG_WORK" AFL_LLVM_CMPLOG=1 \
  "$OSS_DIR/build.sh" > "$WORKDIR/cmplog_build.log" 2>&1 || {
  cat "$WORKDIR/cmplog_build.log" >&2
  exit 1
}
for target in prism_parse_fuzzer prism_full_fuzzer; do
  [ -x "$CMPLOG_OUT/$target" ] || { echo "missing cmplog executable $CMPLOG_OUT/$target" >&2; exit 1; }
  cmplog_syms="$(nm "$CMPLOG_OUT/$target")"
  if grep -q ' pm_strncasecmp$' <<< "$cmplog_syms"; then
    echo "$target unexpectedly kept pm_strncasecmp under AFL_LLVM_CMPLOG=1" >&2
    exit 1
  fi
  grep -q 'strncasecmp' <<< "$cmplog_syms" || {
    echo "$target missing strncasecmp reference under AFL_LLVM_CMPLOG=1" >&2
    exit 1
  }
  max_len="$(awk -F'= *' '/^max_len/{print $2}' "$CMPLOG_OUT/${target}.options")"
  if ! ASAN_OPTIONS=detect_leaks=1:handle_abort=1:abort_on_error=1 \
       UBSAN_OPTIONS=abort_on_error=1:print_stacktrace=1 \
       "$CMPLOG_OUT/$target" -artifact_prefix="$WORKDIR/" -dict="$CMPLOG_OUT/${target}.dict" -max_len="$max_len" -runs=0 "$WORKDIR/unzip-$target" > "$WORKDIR/cmplog-run-$target.log" 2>&1; then
    tail -n 40 "$WORKDIR/cmplog-run-$target.log" >&2
    exit 1
  fi
done

echo "All OSS-Fuzz integration checks passed!"
