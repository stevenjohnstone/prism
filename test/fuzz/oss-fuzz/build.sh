#!/bin/bash -eu

REPO_ROOT="${SRC:-.}/prism"
if [ ! -f "$REPO_ROOT/templates/template.rb" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
fi

cd "$REPO_ROOT"

# Generate C parser headers and sources from templates using Ruby stdlib only.
ruby templates/template.rb

WORK_DIR="${WORK:-}"
CLEANUP_WORK=0
if [ -z "$WORK_DIR" ]; then
  WORK_DIR="$(mktemp -d)"
  CLEANUP_WORK=1
fi
trap 'if [ "$CLEANUP_WORK" -eq 1 ]; then rm -rf "$WORK_DIR"; fi' EXIT

mkdir -p "$OUT" "$WORK_DIR"

shopt -s nullglob
SRCS=(
  src/*.c
  src/*/*.c
  test/fuzz/harness/parse.c
  test/fuzz/harness/fuzz.c
)
shopt -u nullglob

COMMON_DEFINES=(
  -DPRISM_OSS_FUZZ
  -DPM_ARENA_INITIAL_SIZE=0
  -DPM_INTEGER_DIVIDE_THRESHOLD=8
  -DPRISM_DEPTH_MAXIMUM=128
  -Wno-gnu-statement-expression-from-macro-expansion
  -Wno-switch
)

if [ "${AFL_LLVM_CMPLOG:-}" = "1" ]; then
  # Match test/fuzz/Makefile CmpLog builds so AFL++ Redqueen hooks libc strncasecmp.
  CMPLOG_SRCS=()
  for src in "${SRCS[@]}"; do
    [ "$src" = "src/strncasecmp.c" ] && continue
    CMPLOG_SRCS+=("$src")
  done
  SRCS=("${CMPLOG_SRCS[@]}")
  COMMON_DEFINES+=(
    -Dpm_strncasecmp=strncasecmp
    -Wno-implicit-function-declaration
  )
fi

pack_seed_zip() {
  local src_dir="$1"
  local zip_path="$2"
  rm -f "$zip_path"
  if command -v zip >/dev/null 2>&1; then
    zip -r -j -q "$zip_path" "$src_dir"
  else
    python3 -c '
import os, sys, zipfile
src_dir, zip_path = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for root, _, files in os.walk(src_dir):
        for fn in sorted(files):
            zf.write(os.path.join(root, fn), arcname=fn)
' "$src_dir" "$zip_path"
  fi
}

build_target() {
  local name="$1"
  local max_input_size="$2"
  shift 2

  local obj_dir="$WORK_DIR/obj-$name"
  local seed_dir="$WORK_DIR/seeds-$name"
  rm -rf "$obj_dir" "$seed_dir"
  mkdir -p "$obj_dir"

  local objs=()
  local pids=()
  local nproc_count
  nproc_count="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"

  # Compile C99 sources with $CC/$CFLAGS; link C++ fuzzing engine with $CXX/$CXXFLAGS.
  for src in "${SRCS[@]}"; do
    local rel="${src#./}"
    local obj="$obj_dir/${rel//\//_}.o"
    "$CC" -std=c99 -Iinclude $CFLAGS "${COMMON_DEFINES[@]}" "$@" -c "$src" -o "$obj" &
    pids+=("$!")
    objs+=("$obj")
    if [ "${#pids[@]}" -ge "$nproc_count" ]; then
      wait "${pids[0]}"
      pids=("${pids[@]:1}")
    fi
  done
  for pid in "${pids[@]}"; do
    wait "$pid"
  done

  "$CXX" $CXXFLAGS "${objs[@]}" -o "$OUT/$name" $LIB_FUZZING_ENGINE

  cp "$REPO_ROOT/test/fuzz/dict" "$OUT/${name}.dict"
  if [ -f "$REPO_ROOT/test/fuzz/oss-fuzz/${name}.options" ]; then
    cp "$REPO_ROOT/test/fuzz/oss-fuzz/${name}.options" "$OUT/${name}.options"
  elif [ -f "${SRC:-}/${name}.options" ]; then
    cp "${SRC}/${name}.options" "$OUT/${name}.options"
  fi

  FUZZ_MAX_INPUT_SIZE="$max_input_size" ruby "$REPO_ROOT/test/fuzz/runtime/corpus.rb" --no-minimize "$seed_dir"
  pack_seed_zip "$seed_dir" "$OUT/${name}_seed_corpus.zip"
}

build_target \
  prism_parse_fuzzer \
  4096 \
  -DPRISM_EXCLUDE_SERIALIZATION \
  -DPRISM_EXCLUDE_JSON \
  -DPRISM_EXCLUDE_PRETTYPRINT

build_target \
  prism_full_fuzzer \
  1024 \
  -DSLOW

