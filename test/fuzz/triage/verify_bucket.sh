#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=""
BUCKET_DIR=""
PROFILE=""
RUNNER=""
BUILD_ONLY=0
REBUILD=0
SKIP_MIN=0
TIMEOUT_SEC="${VERIFY_TIMEOUT:-5}"
MAX_FAILURES="${VERIFY_MAX_FAILURES:-0}"
EXTRACT_DIR=""
QUIET=0
VERBOSE=0
JSON_MODE=0
SYMBOLIZE="${VERIFY_SYMBOLIZE:-0}"

usage() {
  cat <<'EOF'
Usage: verify_bucket.sh --repo-root DIR [--bucket-dir DIR] [OPTIONS]
  --profile NAME            asan_ubsan | msan_slow | lsan_slow | xallocator
  --runner PATH             Use a precompiled verify_runner binary
  --build-only              Build (if stale) and print the runner binary path
  --rebuild                 Force rebuild of verify_runner
  --timeout SEC             Per-input timeout in seconds (default: 5)
  --max-failures N          Stop checking after N failing inputs (default: 0 = all)
  --extract-survivors DIR   Copy any still-failing inputs into DIR
  --skip-min                Skip checking input.min
  --symbolize               Enable external llvm-symbolizer (slower on many crashes)
  --quiet                   Suppress stderr dumps on failures
  --verbose                 Print full captured stderr for failures
  --json                    Emit machine-readable JSON output
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo-root)
      REPO_ROOT="${2:-}"; shift 2 ;;
    --bucket-dir)
      BUCKET_DIR="${2:-}"; shift 2 ;;
    --profile)
      PROFILE="${2:-}"; shift 2 ;;
    --runner)
      RUNNER="${2:-}"; shift 2 ;;
    --build-only)
      BUILD_ONLY=1; shift ;;
    --rebuild)
      REBUILD=1; shift ;;
    --skip-min)
      SKIP_MIN=1; shift ;;
    --symbolize)
      SYMBOLIZE=1; shift ;;
    --timeout)
      TIMEOUT_SEC="${2:-}"; shift 2 ;;
    --max-failures)
      MAX_FAILURES="${2:-}"; shift 2 ;;
    --extract-survivors)
      EXTRACT_DIR="${2:-}"; shift 2 ;;
    --quiet)
      QUIET=1; shift ;;
    --verbose)
      VERBOSE=1; shift ;;
    --json)
      JSON_MODE=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "verify_bucket.sh: unknown option '$1'" >&2
      usage >&2
      exit 2 ;;
  esac
done

if [ -z "$REPO_ROOT" ]; then
  echo "verify_bucket.sh: --repo-root is required" >&2
  usage >&2
  exit 2
fi

if [ "$BUILD_ONLY" -eq 0 ] && [ -z "$BUCKET_DIR" ]; then
  echo "verify_bucket.sh: --bucket-dir is required" >&2
  usage >&2
  exit 2
fi

if [ ! -f "$REPO_ROOT/include/prism.h" ] || [ ! -d "$REPO_ROOT/src" ]; then
  echo "verify_bucket.sh: invalid Prism root '$REPO_ROOT'" >&2
  exit 2
fi

if [ "$BUILD_ONLY" -eq 0 ] && [ ! -d "$BUCKET_DIR" ]; then
  echo "verify_bucket.sh: bucket directory not found: '$BUCKET_DIR'" >&2
  exit 2
fi

if [ -z "$PROFILE" ]; then
  if [ -n "$BUCKET_DIR" ]; then
    reason="$(basename "$(dirname "$BUCKET_DIR")")"
    if [ "$reason" = "use-of-uninitialized-value" ]; then
      PROFILE="msan_slow"
    elif [ "$reason" = "memory-leak" ]; then
      PROFILE="lsan_slow"
    elif [ "$reason" = "allocation-size-too-big" ]; then
      PROFILE="xallocator"
    elif [ -f "$BUCKET_DIR/build.sh" ]; then
      if grep -q -- "-fsanitize=memory" "$BUCKET_DIR/build.sh" 2>/dev/null; then
        PROFILE="msan_slow"
      elif grep -q -- "-fsanitize=leak" "$BUCKET_DIR/build.sh" 2>/dev/null; then
        PROFILE="lsan_slow"
      else
        PROFILE="asan_ubsan"
      fi
    else
      PROFILE="asan_ubsan"
    fi
  else
    PROFILE="asan_ubsan"
  fi
fi

build_verify_runner() {
  local profile="$1"
  local cache_dir="${VERIFY_BUILD_DIR:-$REPO_ROOT/build/verify}"
  if ! mkdir -p "$cache_dir" 2>/dev/null || [ ! -w "$cache_dir" ]; then
    cache_dir="${TMPDIR:-/tmp}/prism-fuzz-verify"
    mkdir -p "$cache_dir"
  fi

  local bin="$cache_dir/verify_runner.$profile"
  local needs_build=0
  if [ "$REBUILD" -eq 1 ] || [ ! -x "$bin" ]; then
    needs_build=1
  elif [ -n "$(find "$REPO_ROOT/src" "$REPO_ROOT/include" "$REPO_ROOT/test/fuzz/harness" "$REPO_ROOT/test/fuzz/triage/verify_runner.c" -type f -newer "$bin" -print -quit 2>/dev/null)" ]; then
    needs_build=1
  fi

  if [ "$needs_build" -eq 1 ]; then
    local cc="${CC:-clang}"
    local max_input="${FUZZ_MAX_INPUT_SIZE:-1024}"
    local max_alloc="${FUZZ_MAX_ALLOCATED:-128}"
    local hard_rss="${FUZZ_HARD_RSS_LIMIT:-$((max_alloc * 16))}"

    local flags=(
      -O1 -fno-omit-frame-pointer -ggdb3 -std=c99
      -Wno-gnu-statement-expression-from-macro-expansion
      -Wno-shorten-64-to-32
      -Wno-switch
      -Wno-implicit-function-declaration
      "-I$REPO_ROOT/include"
      "-DPM_INTEGER_DIVIDE_THRESHOLD=8"
      "-DPRISM_DEPTH_MAXIMUM=128"
      "-DFUZZ_MAX_INPUT_SIZE=$max_input"
      "-DFUZZ_MAX_ALLOCATED=$max_alloc"
      "-DFUZZ_HARD_RSS_LIMIT=$hard_rss"
    )

    case "$profile" in
      asan_ubsan)
        flags+=(-DPM_ARENA_INITIAL_SIZE=0 -fsanitize=address,undefined -fno-sanitize-recover=all) ;;
      msan_slow)
        if [ "$(uname -s)" = "Darwin" ]; then
          echo "verify_bucket.sh: MSan verification requires Linux (run 'make fuzz-verify BUCKET=...' in Docker)" >&2
          exit 2
        fi
        flags+=(-DPM_ARENA_INITIAL_SIZE=0 -DSLOW -fsanitize=memory -fsanitize-memory-track-origins -fno-sanitize-recover=all) ;;
      lsan_slow)
        flags+=(-DPM_ARENA_INITIAL_SIZE=0 -DSLOW -fsanitize=leak -fno-sanitize-recover=all) ;;
      xallocator)
        flags+=("-I$REPO_ROOT/test/fuzz/harness/include" -DPRISM_XALLOCATOR) ;;
      *)
        echo "verify_bucket.sh: unknown profile '$profile'" >&2
        exit 2 ;;
    esac

    shopt -s nullglob
    local srcs=(
      "$REPO_ROOT"/src/*.c
      "$REPO_ROOT"/src/*/*.c
      "$REPO_ROOT/test/fuzz/harness/parse.c"
      "$REPO_ROOT/test/fuzz/harness/fuzz.c"
      "$REPO_ROOT/test/fuzz/triage/verify_runner.c"
    )

    local tmp_bin="$bin.tmp.$$"
    rm -f "$tmp_bin"
    if [ "$JSON_MODE" -eq 0 ] && [ "$BUILD_ONLY" -eq 0 ]; then
      echo "Building verify_runner ($profile)..." >&2
    fi
    "$cc" "${flags[@]}" "${srcs[@]}" -o "$tmp_bin"
    mv -f "$tmp_bin" "$bin"
  fi

  printf '%s\n' "$bin"
}

if [ -z "$RUNNER" ]; then
  RUNNER="$(build_verify_runner "$PROFILE")"
fi

if [ "$BUILD_ONLY" -eq 1 ]; then
  printf '%s\n' "$RUNNER"
  exit 0
fi

max_alloc="${FUZZ_MAX_ALLOCATED:-128}"
hard_rss="${FUZZ_HARD_RSS_LIMIT:-$((max_alloc * 16))}"
sym_flag=""
if [ "$SYMBOLIZE" != "1" ]; then
  sym_flag=":symbolize=0"
fi
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:handle_abort=1:max_allocation_size_mb=${max_alloc}:hard_rss_limit_mb=${hard_rss}${sym_flag}}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-abort_on_error=1:print_stacktrace=1${sym_flag}}"
export MSAN_OPTIONS="${MSAN_OPTIONS:-abort_on_error=1:handle_abort=1:max_allocation_size_mb=${max_alloc}:hard_rss_limit_mb=${hard_rss}${sym_flag}}"
export LSAN_OPTIONS="${LSAN_OPTIONS:-handle_abort=1:max_allocation_size_mb=${max_alloc}:hard_rss_limit_mb=${hard_rss}${sym_flag}}"

args=(--timeout "$TIMEOUT_SEC" --max-failures "$MAX_FAILURES")
if [ -n "$EXTRACT_DIR" ]; then
  mkdir -p "$EXTRACT_DIR"
  args+=(--extract-dir "$EXTRACT_DIR")
fi
[ "$QUIET" -eq 1 ] && args+=(--quiet)
[ "$VERBOSE" -eq 1 ] && args+=(--verbose)
[ "$JSON_MODE" -eq 1 ] && args+=(--json)

if [ "$SKIP_MIN" -eq 0 ] && [ -f "$BUCKET_DIR/input.min" ]; then
  args+=("$BUCKET_DIR/input.min")
fi

if [ -f "$BUCKET_DIR/.inputs.pending" ] && [ -s "$BUCKET_DIR/.inputs.pending" ]; then
  args+=(--pack "$BUCKET_DIR/.inputs.pending")
fi

if [ -f "$BUCKET_DIR/inputs.tar.gz" ]; then
  gzip -dc "$BUCKET_DIR/inputs.tar.gz" | "$RUNNER" "${args[@]}" --tar -
  exit $?
fi

shopt -s nullglob
raw_files=("$BUCKET_DIR"/id*)
for f in "${raw_files[@]}"; do
  if [ -f "$f" ]; then
    args+=("$f")
  fi
done

exec "$RUNNER" "${args[@]}"
