#!/usr/bin/env bash
set -euo pipefail

MODE="fuzz"
PRISM_ROOT=""
FUZZ_ROOT=""
RUBY_DIR="${RUBY_ORACLE_DIR:-/opt/ruby}"
ORACLE_DIR=""
SOURCE_ARG=""
OUTPUT=""
AFL_PATH_ARG=""
CC_BIN="${CC:-clang}"
MAX_INPUT_SIZE="${FUZZ_MAX_INPUT_SIZE:-1024}"
EXTRA_CFLAGS=()

usage() {
  cat <<'EOF'
Usage: build_diff.sh --mode {fuzz|verify|testcase} --prism-root DIR --output FILE [OPTIONS]
  --mode MODE             fuzz (AFL PCGUARD), verify (verify_runner), or testcase (standalone C)
  --prism-root DIR        Prism repository root containing include/ and src/
  --fuzz-root DIR         Fuzz harness repository root (defaults to --prism-root)
  --ruby-dir DIR          Built CRuby static source tree (default: /opt/ruby)
  --oracle-dir DIR        Cache directory for libcruby_oracle.a and objects
  --source FILE           Standalone C reproducer source path (required for --mode testcase)
  --afl-path DIR          AFL++ instrumentation directory (required for --mode fuzz)
  --cc BIN                C compiler (for --mode verify|testcase; default: $CC or clang)
  --max-input-size N      FUZZ_MAX_INPUT_SIZE value (default: 1024)
  --cflag FLAG            Extra C compiler flag for Prism/harness sources (repeatable)
  --output FILE           Output binary path
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode)
      MODE="${2:-}"; shift 2 ;;
    --prism-root)
      PRISM_ROOT="${2:-}"; shift 2 ;;
    --fuzz-root)
      FUZZ_ROOT="${2:-}"; shift 2 ;;
    --ruby-dir)
      RUBY_DIR="${2:-}"; shift 2 ;;
    --oracle-dir)
      ORACLE_DIR="${2:-}"; shift 2 ;;
    --source)
      SOURCE_ARG="${2:-}"; shift 2 ;;
    --afl-path)
      AFL_PATH_ARG="${2:-}"; shift 2 ;;
    --cc)
      CC_BIN="${2:-}"; shift 2 ;;
    --max-input-size)
      MAX_INPUT_SIZE="${2:-}"; shift 2 ;;
    --cflag)
      EXTRA_CFLAGS+=("${2:-}"); shift 2 ;;
    --output)
      OUTPUT="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "build_diff.sh: unknown option '$1'" >&2
      usage >&2
      exit 2 ;;
  esac
done

if [ -z "$PRISM_ROOT" ] || [ -z "$OUTPUT" ]; then
  echo "build_diff.sh: --prism-root and --output are required" >&2
  usage >&2
  exit 2
fi

if [ "$MODE" = "testcase" ] && [ -z "$SOURCE_ARG" ]; then
  echo "build_diff.sh: --source is required for --mode testcase" >&2
  usage >&2
  exit 2
fi

if [ -z "$FUZZ_ROOT" ]; then
  FUZZ_ROOT="$PRISM_ROOT"
fi

if [ -z "$ORACLE_DIR" ]; then
  if [ "$MODE" = "fuzz" ]; then
    ORACLE_DIR="$PRISM_ROOT/build/diff-oracle"
  elif [ "$MODE" = "testcase" ]; then
    ORACLE_DIR="$PRISM_ROOT/build/diff-testcase-oracle"
  else
    ORACLE_DIR="$(dirname "$OUTPUT")/diff-oracle"
  fi
fi

if [ ! -f "$RUBY_DIR/libruby-static.a" ] || [ ! -f "$RUBY_DIR/parse.c" ]; then
  echo "build_diff.sh: CRuby static tree not found under '$RUBY_DIR' (missing libruby-static.a or parse.c)" >&2
  exit 2
fi

if ! ar t "$RUBY_DIR/libruby-static.a" | grep -qx "parse.o"; then
  echo "build_diff.sh: parse.o member not found in '$RUBY_DIR/libruby-static.a'" >&2
  exit 2
fi

if [ "$MODE" = "fuzz" ] && [ -z "$AFL_PATH_ARG" ]; then
  AFL_PATH_ARG="$PRISM_ROOT/build/afl"
fi

mkdir -p "$ORACLE_DIR" "$(dirname "$OUTPUT")"

# Query CRuby build config dynamically so architecture (aarch64/x86_64) and libs stay portable.
RUBY_ARCH="$(ruby -rrbconfig -e 'puts RbConfig::CONFIG.fetch("arch")')"
mapfile -t MAINLIBS_ARR < <(ruby -rrbconfig -rshellwords -e 'Shellwords.split(RbConfig::CONFIG["MAINLIBS"] || "").each { |t| puts t }')
mapfile -t PARSE_CPP_FLAGS < <(ruby -rshellwords -e '
  ruby_dir = ARGV[0]
  make_out = IO.popen(["make", "-C", ruby_dir, "-n", "-W", "parse.c", "parse.o"], err: [:child, :out], &:read)
  compile_line = make_out.lines.reverse.find { |l| l.include?(" -c ") && l.include?("parse.c") }
  abort "Failed to inspect parse.c compile flags from #{ruby_dir}/Makefile" unless compile_line

  Shellwords.split(compile_line).each do |tok|
    if tok.start_with?("-I")
      path = tok[2..]
      full = path.start_with?("/") ? path : File.expand_path(path, ruby_dir)
      puts "-I#{full}"
    elsif tok.start_with?("-D", "-U")
      puts tok
    end
  end
' "$RUBY_DIR")
RUBY_PARSE_FLAGS="${PARSE_CPP_FLAGS[*]}"

RUBY_EMBED_INC=(
  "-I$RUBY_DIR/.ext/include/$RUBY_ARCH"
  "-I$RUBY_DIR/include"
)

if [ "$MODE" = "fuzz" ]; then
  PARSE_CC=(env "AFL_PATH=$AFL_PATH_ARG" "AFL_LLVM_INSTRUMENT=PCGUARD" afl-clang-fast)
  ORACLE_DEP="$AFL_PATH_ARG/SanitizerCoveragePCGUARD.so"
  if [ ! -f "$ORACLE_DEP" ]; then
    echo "build_diff.sh: missing AFL PCGUARD pass '$ORACLE_DEP' (run make fuzz-build / afl stamp first)" >&2
    exit 2
  fi
else
  PARSE_CC=("$CC_BIN")
  ORACLE_DEP="$(command -v "$CC_BIN" 2>/dev/null || printf '%s' "$CC_BIN")"
fi

ORACLE_MODE="host"
if [ "$MODE" = "fuzz" ]; then
  ORACLE_MODE="fuzz"
fi

ORACLE_STAMP_FILE="$ORACLE_DIR/.oracle.stamp"
ORACLE_ARCHIVE="$ORACLE_DIR/libcruby_oracle.a"

oracle_fp="$(ruby -rdigest -e '
  files = ARGV[2..]
  d = Digest::SHA256.new
  d.update("#{ARGV[0]}\0#{ARGV[1]}\0")
  files.each do |f|
    if File.file?(f)
      st = File.stat(f)
      d.update("#{f}\0#{st.size}\0#{st.mtime.tv_sec}\0#{st.mtime.nsec}\0")
    else
      d.update("missing:#{f}\0")
    end
  end
  puts d.hexdigest
' "$ORACLE_MODE" "$RUBY_PARSE_FLAGS" "$RUBY_DIR/libruby-static.a" "$RUBY_DIR/parse.c" "$ORACLE_DEP")"

if [ ! -f "$ORACLE_ARCHIVE" ] || [ ! -f "$ORACLE_STAMP_FILE" ] || [ "$(cat "$ORACLE_STAMP_FILE" 2>/dev/null)" != "$oracle_fp" ]; then
  tmp_parse_o="$ORACLE_DIR/parse.o.tmp.$$"
  tmp_sym_map="$ORACLE_DIR/pm_syms.map.tmp.$$"
  tmp_archive="$ORACLE_ARCHIVE.tmp.$$"
  rm -f "$tmp_parse_o" "$tmp_sym_map" "$tmp_archive"

  "${PARSE_CC[@]}" \
    -O3 -ggdb3 -fno-strict-overflow -fvisibility=hidden -fPIE -w \
    "${PARSE_CPP_FLAGS[@]}" \
    -c "$RUBY_DIR/parse.c" -o "$tmp_parse_o"

  cp "$RUBY_DIR/libruby-static.a" "$tmp_archive"
  # Replace parse.o inside the archive copy before renaming pm_* so any internal
  # references from parse.o to CRuby's bundled Prism stay isolated from workspace Prism.
  (cd "$ORACLE_DIR" && cp "$tmp_parse_o" parse.o && ar r "$tmp_archive" parse.o && rm -f parse.o)
  rm -f "$tmp_parse_o"
  nm --defined-only -g -P "$tmp_archive" \
    | awk '$1 ~ /^pm_/ { print $1 " __cruby_" $1 }' \
    | sort -u > "$tmp_sym_map"
  objcopy --redefine-syms="$tmp_sym_map" "$tmp_archive"
  ranlib "$tmp_archive"
  rm -f "$tmp_sym_map"

  mv -f "$tmp_archive" "$ORACLE_ARCHIVE"
  printf '%s\n' "$oracle_fp" > "$ORACLE_STAMP_FILE"
fi

shopt -s nullglob
PRISM_SRCS=("$PRISM_ROOT"/src/*.c "$PRISM_ROOT"/src/*/*.c)
if [ "${#PRISM_SRCS[@]}" -eq 0 ]; then
  echo "build_diff.sh: no C sources found under '$PRISM_ROOT/src'" >&2
  exit 2
fi

compile_prism_objs() {
  local obj_dir=$1
  local incremental=$2
  mkdir -p "$obj_dir"

  local newest_header=""
  local force_objs=1
  local flags_stamp="$obj_dir/.flags.stamp"
  local cur_stamp="$PRISM_ROOT|${PRISM_CC[*]}|${PRISM_CFLAGS[*]}"

  if [ "$incremental" -eq 1 ]; then
    newest_header="$(find "$PRISM_ROOT/include" -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2- || true)"
    force_objs=0
    if [ ! -f "$flags_stamp" ] || [ "$(cat "$flags_stamp" 2>/dev/null)" != "$cur_stamp" ]; then
      force_objs=1
    fi
  fi

  PRISM_OBJS=()
  for src in "${PRISM_SRCS[@]}"; do
    local rel="${src#"$PRISM_ROOT/src/"}"
    local obj="$obj_dir/${rel%.c}.o"
    mkdir -p "$(dirname "$obj")"
    if [ "$force_objs" -eq 1 ] || [ ! -f "$obj" ] || [ "$src" -nt "$obj" ] || [ "$0" -nt "$obj" ] || { [ -n "$newest_header" ] && [ "$newest_header" -nt "$obj" ]; }; then
      "${PRISM_CC[@]}" "${PRISM_CFLAGS[@]}" -c "$src" -o "$obj"
    fi
    PRISM_OBJS+=("$obj")
  done
  printf '%s\n' "$cur_stamp" > "$flags_stamp"
}

LINK_EXPORT_FLAGS=()
if [ "$(uname -s)" = "Linux" ]; then
  LINK_EXPORT_FLAGS=(-Wl,--export-dynamic)
fi

if [ "$MODE" = "fuzz" ]; then
  PRISM_CC=(env "AFL_PATH=$AFL_PATH_ARG" "AFL_LLVM_INSTRUMENT=PCGUARD" afl-clang-fast)
  PRISM_CFLAGS=(
    -g -gdwarf-4 -O2 -std=c99
    -Wall -Werror -Wextra -Wpedantic -Wundef -Wconversion -Wno-missing-braces
    -Wno-gnu-statement-expression-from-macro-expansion -Wno-shorten-64-to-32
    -Wno-switch -Wno-implicit-function-declaration
    -fPIC -fvisibility=hidden -Wimplicit-fallthrough
    "-I$PRISM_ROOT/include"
    -DPRISM_EXCLUDE_SERIALIZATION -DPRISM_EXCLUDE_JSON -DPRISM_EXCLUDE_PRETTYPRINT
    -DPM_INTEGER_DIVIDE_THRESHOLD=8
    "-DFUZZ_MAX_INPUT_SIZE=$MAX_INPUT_SIZE"
    ${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"}
  )
  compile_prism_objs "$ORACLE_DIR/prism_objs" 1

  DIFF_OBJ="$ORACLE_DIR/diff.o"
  "${PRISM_CC[@]}" \
    -g -gdwarf-4 -O2 -std=gnu99 -Wall -Wextra -Wno-unused-parameter -fPIE \
    "-I$PRISM_ROOT/include" \
    "${RUBY_EMBED_INC[@]}" \
    "-DFUZZ_MAX_INPUT_SIZE=$MAX_INPUT_SIZE" \
    -c "$FUZZ_ROOT/test/fuzz/harness/diff.c" -o "$DIFF_OBJ"

  tmp_out="$OUTPUT.tmp.$$"
  rm -f "$tmp_out"
  "${PRISM_CC[@]}" \
    -g -gdwarf-4 -O2 -fPIE "${LINK_EXPORT_FLAGS[@]}" \
    "$DIFF_OBJ" "${PRISM_OBJS[@]}" "$ORACLE_ARCHIVE" \
    "${MAINLIBS_ARR[@]}" \
    -o "$tmp_out"
  mv -f "$tmp_out" "$OUTPUT"
elif [ "$MODE" = "verify" ] || [ "$MODE" = "testcase" ]; then
  OBJ_DIR="$ORACLE_DIR/${MODE}_objs"
  PRISM_CC=("$CC_BIN")
  PRISM_CFLAGS=(
    -O1 -fno-omit-frame-pointer -ggdb3 -gdwarf-4 -std=c99
    -Wno-gnu-statement-expression-from-macro-expansion -Wno-shorten-64-to-32
    -Wno-switch -Wno-implicit-function-declaration
    "-I$PRISM_ROOT/include"
    -DPM_INTEGER_DIVIDE_THRESHOLD=8
    "-DFUZZ_MAX_INPUT_SIZE=$MAX_INPUT_SIZE"
    ${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"}
  )
  if [ "$MODE" = "testcase" ]; then
    compile_prism_objs "$OBJ_DIR" 1
    TC_OBJ="$(dirname "$OUTPUT")/.testcase.$$.o"
    rm -f "$TC_OBJ"
    "$CC_BIN" \
      -O1 -fno-omit-frame-pointer -ggdb3 -gdwarf-4 -std=gnu99 \
      -Wall -Wextra -Wno-unused-parameter -fPIE \
      "-I$PRISM_ROOT/include" \
      "${RUBY_EMBED_INC[@]}" \
      ${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"} \
      -c "$SOURCE_ARG" -o "$TC_OBJ"

    tmp_out="$OUTPUT.tmp.$$"
    rm -f "$tmp_out"
    "$CC_BIN" \
      -O1 -fno-omit-frame-pointer -ggdb3 -gdwarf-4 -fPIE "${LINK_EXPORT_FLAGS[@]}" \
      "$TC_OBJ" "${PRISM_OBJS[@]}" "$ORACLE_ARCHIVE" \
      "${MAINLIBS_ARR[@]}" \
      -o "$tmp_out"
    rm -f "$TC_OBJ"
    mv -f "$tmp_out" "$OUTPUT"
  else
    compile_prism_objs "$OBJ_DIR" 0

    DIFF_OBJ="$OBJ_DIR/diff.o"
    "$CC_BIN" \
      -O1 -fno-omit-frame-pointer -ggdb3 -gdwarf-4 -std=gnu99 \
      -Wall -Wextra -Wno-unused-parameter -fPIE -DPRISM_DIFF_NO_MAIN \
      "-I$PRISM_ROOT/include" \
      "${RUBY_EMBED_INC[@]}" \
      "-DFUZZ_MAX_INPUT_SIZE=$MAX_INPUT_SIZE" \
      -c "$FUZZ_ROOT/test/fuzz/harness/diff.c" -o "$DIFF_OBJ"

    RUNNER_OBJ="$OBJ_DIR/verify_runner.o"
    "$CC_BIN" \
      -O1 -fno-omit-frame-pointer -ggdb3 -gdwarf-4 -std=gnu99 \
      -Wall -Wextra -Wno-unused-parameter -fPIE \
      -c "$FUZZ_ROOT/test/fuzz/triage/verify_runner.c" -o "$RUNNER_OBJ"

    tmp_out="$OUTPUT.tmp.$$"
    rm -f "$tmp_out"
    "$CC_BIN" \
      -O1 -fno-omit-frame-pointer -ggdb3 -gdwarf-4 -fPIE "${LINK_EXPORT_FLAGS[@]}" \
      "$RUNNER_OBJ" "$DIFF_OBJ" "${PRISM_OBJS[@]}" "$ORACLE_ARCHIVE" \
      "${MAINLIBS_ARR[@]}" \
      -o "$tmp_out"
    mv -f "$tmp_out" "$OUTPUT"
  fi
else
  echo "build_diff.sh: invalid --mode '$MODE' (expected fuzz, verify, or testcase)" >&2
  exit 2
fi
