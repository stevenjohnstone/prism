#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=""
FUZZ_ROOT=""
BUCKET_DIR=""
PROFILE=""
RUNNER=""
BUILD_ONLY=0
REBUILD=0
SKIP_MIN="${VERIFY_SKIP_MIN:-0}"
INPUT_MIN_ONLY="${VERIFY_INPUT_MIN_ONLY:-0}"
TIMEOUT_SEC="${VERIFY_TIMEOUT:-5}"
MAX_FAILURES="${VERIFY_MAX_FAILURES:-0}"
EXTRACT_DIR=""
QUIET=0
VERBOSE=0
JSON_MODE=0
SYMBOLIZE="${VERIFY_SYMBOLIZE:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_FUZZ_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

usage() {
  cat <<'EOF'
Usage: verify_bucket.sh --repo-root DIR [--fuzz-root DIR] [--bucket-dir DIR] [OPTIONS]
  --repo-root DIR           Target Prism source directory (alias: --target DIR)
  --fuzz-root DIR           Fuzzer root containing test/fuzz/harness (default: script repo)
  --profile NAME            asan_ubsan | msan_slow | lsan_slow | xallocator
  --runner PATH             Use a precompiled verify_runner binary
  --build-only              Build (if stale) and print the runner binary path
  --rebuild                 Force rebuild of verify_runner
  --timeout SEC             Per-input timeout in seconds (default: 5)
  --max-failures N          Stop checking after N failing inputs (default: 0 = all)
  --extract-survivors DIR   Copy any still-failing inputs into DIR
  --input-min-only          Check only input.min (skip pending/archived inputs)
  --skip-min                Skip checking input.min
  --symbolize               Enable external llvm-symbolizer (slower on many crashes)
  --quiet                   Suppress stderr dumps on failures
  --verbose                 Print full captured stderr for failures
  --json                    Emit machine-readable JSON output
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo-root|--target)
      REPO_ROOT="${2:-}"; shift 2 ;;
    --fuzz-root)
      FUZZ_ROOT="${2:-}"; shift 2 ;;
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
    --input-min-only)
      INPUT_MIN_ONLY=1; shift ;;
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

if [ -z "$FUZZ_ROOT" ]; then
  FUZZ_ROOT="$DEFAULT_FUZZ_ROOT"
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

if [ ! -f "$FUZZ_ROOT/test/fuzz/harness/parse.c" ] || [ ! -f "$FUZZ_ROOT/test/fuzz/triage/verify_runner.c" ]; then
  echo "verify_bucket.sh: invalid fuzz root '$FUZZ_ROOT'" >&2
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

ensure_target_templates() {
  local target_root="$1"
  local cache_dir="$2"
  local tpl_script="$target_root/templates/template.rb"
  local cfg="$target_root/config.yml"
  [ -f "$tpl_script" ] && [ -f "$cfg" ] || return 0

  local stamp="$cache_dir/.templates.sha256"
  local check_out
  if ! check_out="$(ruby -rdigest -e '
    target, stamp = ARGV
    cfg = File.join(target, "config.yml")
    tpl_dir = File.join(target, "templates")
    inputs = ([cfg] + Dir.glob(File.join(tpl_dir, "**", "*")).select { |p| File.file?(p) }).uniq.sort
    digest = Digest::SHA256.new
    inputs.each do |p|
      rel = p.delete_prefix(target + "/")
      digest.update("#{rel}\0#{File.size(p)}\0")
      digest.update(File.binread(p))
      digest.update("\0")
    end
    cur_sha = digest.hexdigest
    max_in_mtime = inputs.map { |p| File.mtime(p) }.max

    expected = []
    %w[src include].each do |sub|
      base = File.join(tpl_dir, sub)
      next unless File.directory?(base)
      Dir.glob(File.join(base, "**", "*.erb")).each do |erb|
        rel = erb.delete_prefix(tpl_dir + "/").delete_suffix(".erb")
        expected << File.join(target, rel)
      end
    end

    missing = expected.any? { |p| !File.file?(p) }
    stale_out = !missing && expected.any? { |p| File.mtime(p) < max_in_mtime }
    stale_stamp = File.file?(stamp) && File.read(stamp).strip != cur_sha
    need = (missing || stale_out || stale_stamp) ? 1 : 0
    puts "#{need} #{cur_sha}"
  ' "$target_root" "$stamp")"; then
    echo "verify_bucket.sh: failed to inspect templates under '$target_root'" >&2
    exit 125
  fi

  local need_gen="${check_out%% *}"
  local tpl_sha="${check_out#* }"
  if [ "$need_gen" -eq 1 ]; then
    if [ ! -w "$target_root" ]; then
      echo "verify_bucket.sh: target '$target_root' is not writable for template generation" >&2
      exit 125
    fi
    if [ "$JSON_MODE" -eq 0 ] && [ "$BUILD_ONLY" -eq 0 ]; then
      echo "Generating templates for $target_root..." >&2
    fi
    if ! (cd "$target_root" && (ruby templates/template.rb || rake templates)) >&2; then
      echo "verify_bucket.sh: template generation failed under '$target_root'" >&2
      exit 125
    fi
  fi

  local tmp_stamp="$stamp.tmp.$$"
  if printf '%s\n' "$tpl_sha" > "$tmp_stamp" 2>/dev/null; then
    mv -f "$tmp_stamp" "$stamp"
  else
    rm -f "$tmp_stamp"
  fi
}

check_target_api_support() {
  local target_root="$1"
  if [ ! -f "$target_root/include/prism.h" ] ||
     ! grep -rqE '\bpm_parse\(' "$target_root/include" 2>/dev/null ||
     { ! grep -rqE '\bpm_parser_new\(' "$target_root/include" 2>/dev/null &&
       ! grep -rqE '\bpm_parser_init\(' "$target_root/include" 2>/dev/null; }; then
    echo "verify_bucket.sh: target Prism at '$target_root' lacks Prism C parser APIs (pm_parse/pm_parser_new/pm_parser_init)" >&2
    exit 125
  fi
}

compute_build_fingerprint() {
  local target_root="$1"
  local fuzz_root="$2"
  local cc="$3"
  shift 3
  ruby -rdigest -e '
    target, fuzz, cc, *flags = ARGV
    paths = []
    [
      File.join(target, "src"),
      File.join(target, "include"),
      File.join(fuzz, "test/fuzz/harness")
    ].each do |dir|
      next unless File.directory?(dir)
      Dir.glob(File.join(dir, "**", "*")).each do |p|
        paths << p if File.file?(p)
      end
    end
    runner_c = File.join(fuzz, "test/fuzz/triage/verify_runner.c")
    paths << runner_c if File.file?(runner_c)
    d = Digest::SHA256.new
    d.update("#{target}\0#{fuzz}\0#{cc}\0#{flags.join("\0")}\0")
    paths.uniq.sort.each do |p|
      st = File.stat(p)
      d.update("#{p}\0#{st.size}\0#{st.mtime.tv_sec}\0#{st.mtime.nsec}\n")
    end
    puts d.hexdigest
  ' "$target_root" "$fuzz_root" "$cc" "$@"
}

build_verify_runner() {
  local profile="$1"
  local cache_dir="${VERIFY_BUILD_DIR:-$REPO_ROOT/build/verify}"
  if ! mkdir -p "$cache_dir" 2>/dev/null || [ ! -w "$cache_dir" ]; then
    local target_key
    target_key="$(ruby -rdigest -e 'puts Digest::SHA256.hexdigest(File.expand_path(ARGV[0]))[0, 12]' "$REPO_ROOT")"
    cache_dir="${TMPDIR:-/tmp}/prism-fuzz-verify/$target_key"
    mkdir -p "$cache_dir"
  fi

  ensure_target_templates "$REPO_ROOT" "$cache_dir"
  check_target_api_support "$REPO_ROOT"

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

  # Probe historical Prism C API differences across 2024–2026 commits so older commits compile cleanly.
  local probe_flags
  probe_flags="$(ruby -e '
    inc = ARGV[0]
    hdrs = Dir.glob(File.join(inc, "**", "*.h")).sort.map { |p| File.read(p, encoding: "BINARY") }.join("\n")
    code = hdrs.gsub(%r{//[^\n]*|/\*.*?\*/}m, " ")

    out = []
    has_arena_initial_ifndef = code.match?(/#\s*ifndef\s+PM_ARENA_INITIAL_SIZE\b/)
    out << "-DPM_ARENA_INITIAL_SIZE=0" if has_arena_initial_ifndef

    unless File.file?(File.join(inc, "prism", "internal", "buffer.h"))
      out << "-DPRISM_FUZZ_NO_INTERNAL_BUFFER"
    end

    # Options API
    unless code.match?(/\bpm_options_new\b/)
      out << "-DPRISM_FUZZ_LEGACY_OPTIONS_STRUCT"
      out << "-DPRISM_FUZZ_OPTIONS_CLEANUP" if code.match?(/\bpm_options_cleanup\b/)
    end
    out << "-DPRISM_FUZZ_NO_COMMAND_LINE" unless code.match?(/\bpm_options_command_line_set\b/)
    out << "-DPRISM_FUZZ_NO_MAIN_SCRIPT" unless code.match?(/\bpm_options_main_script_set\b/)
    out << "-DPRISM_FUZZ_NO_FREEZE" unless code.match?(/\bpm_options_freeze_set\b/)
    out << "-DPRISM_FUZZ_NO_PARTIAL_SCRIPT" unless code.match?(/\bpm_options_partial_script_set\b/)
    out << "-DPRISM_FUZZ_NO_ATTACH_COMMENTS" unless code.match?(/\bpm_options_attach_comments_set\b/)
    out << "-DPRISM_FUZZ_NO_ENCODING_LOCKED" unless code.match?(/\bpm_options_encoding_locked_set\b/)
    out << "-DPRISM_FUZZ_NO_VERSION_SET" unless code.match?(/\bpm_options_version_set\b/)
    out << "-DPRISM_FUZZ_NO_FROZEN_STRING_LITERAL" unless code.match?(/\bpm_options_frozen_string_literal_set\b/)
    out << "-DPRISM_FUZZ_NO_SHEBANG_CALLBACK" unless code.match?(/\bpm_options_shebang_callback_set\b/)
    out << "-DPRISM_FUZZ_NO_STACK_BUDGET" unless code.match?(/\bpm_options_stack_budget_set\b/)
    out << "-DPRISM_FUZZ_NO_SCOPE_FORWARDING" unless code.match?(/\bpm_options_scope_forwarding_set\b/)
    out << "-DPRISM_FUZZ_VOID_SCOPES_INIT" if code.match?(/\bvoid\s+pm_options_scopes_init\b/)
    out << "-DPRISM_FUZZ_VOID_SCOPE_INIT" if code.match?(/\bvoid\s+pm_options_scope_init\b/)
    unless code.match?(/\bpm_options_scope_mut\b/)
      out << (code.match?(/\bpm_options_scope_get_mut\b/) ? "-DPRISM_FUZZ_SCOPE_GET_MUT" : "-DPRISM_FUZZ_SCOPE_DIRECT")
    end
    unless code.match?(/\bpm_options_scope_local_mut\b/)
      out << (code.match?(/\bpm_options_scope_local_get_mut\b/) ? "-DPRISM_FUZZ_LOCAL_GET_MUT" : "-DPRISM_FUZZ_LOCAL_DIRECT")
    end

    # String init
    if !code.match?(/\bpm_string_init\b/) && code.match?(/\bpm_string_constant_init\b/)
      out << "-DPRISM_FUZZ_LEGACY_STRING_INIT"
    end

    # Arena API
    if !code.match?(/\bpm_arena_t\b/)
      out << "-DPRISM_FUZZ_LEGACY_NO_ARENA"
    elsif !code.match?(/\bpm_arena_new\b/)
      out << "-DPRISM_FUZZ_LEGACY_ARENA_STRUCT"
      out << "-DPRISM_FUZZ_ARENA_CLEANUP" if code.match?(/\bpm_arena_cleanup\b/)
    end

    # Parser, line offsets, locations, iterators, node type name
    has_parser_new = code.match?(/\bpm_parser_new\b/)
    unless has_parser_new
      out << "-DPRISM_FUZZ_LEGACY_PARSER_INIT"
      if (m = code.match(/\bpm_parser_init\s*\(([^)]*)\)/m)) && m[1].include?("arena")
        out << "-DPRISM_FUZZ_PARSER_INIT_ARENA"
      end
      out << "-DPRISM_FUZZ_PARSER_CLEANUP" if code.match?(/\bpm_parser_cleanup\b/)
    end
    out << "-DPRISM_FUZZ_LEGACY_PARSER_DATA_LOC" unless code.match?(/\bpm_parser_data_loc\b/)
    unless code.match?(/\bpm_parser_line_offsets\b/)
      out << (code.match?(/\bpm_newline_list_t\b/) ? "-DPRISM_FUZZ_PARSER_NEWLINE_LIST" : "-DPRISM_FUZZ_LEGACY_PARSER_LINE_OFFSETS")
    end
    if (m = code.match(/typedef\s+struct\b[^{]*\{([^}]*)\}\s*pm_location_t\s*;/m)) && m[1].match?(/\*\s*start\b/)
      out << "-DPRISM_FUZZ_POINTER_LOCATIONS"
    end
    unless code.match?(/\bpm_magic_comment_key\b/)
      if (m = code.match(/typedef\s+struct\b[^{]*\{([^}]*)\}\s*pm_magic_comment_t\s*;/m)) && m[1].match?(/\bkey_start\b/)
        out << "-DPRISM_FUZZ_LEGACY_MAGIC_COMMENT_START"
      else
        out << "-DPRISM_FUZZ_LEGACY_MAGIC_COMMENT_FIELDS"
      end
    end
    out << "-DPRISM_FUZZ_LEGACY_DIAG_FIELDS" unless code.match?(/\bpm_diagnostic_location\b/)
    out << "-DPRISM_FUZZ_NO_DIAGNOSTIC_TYPE" unless code.match?(/\bpm_diagnostic_type\b/)
    out << "-DPRISM_FUZZ_LEGACY_COMMENT_FIELDS" unless code.match?(/\bpm_comment_location\b/)
    unless code.match?(/\bpm_parser_errors_first\b/)
      if code.match?(/\bpm_parser_errors_each\b/)
        out << "-DPRISM_FUZZ_EACH_ITERATORS"
      elsif code.match?(/\bpm_diagnostics_iter_t\b/)
        out << "-DPRISM_FUZZ_ITER_OBJS"
      else
        out << "-DPRISM_FUZZ_LIST_ITERATORS"
      end
    end
    if !code.match?(/\bpm_node_type\s*\(/) && code.match?(/\bpm_node_type_to_str\s*\(/)
      out << "-DPRISM_FUZZ_NODE_TYPE_TO_STR"
    end
    out << "-DPRISM_FUZZ_NO_VISIT_NODE" unless code.match?(/\bpm_visit_node\b/)
    out << "-DPRISM_FUZZ_LEGACY_VISIT_BOOL" unless code.match?(/\bpm_visit_result_t\b/)

    # Buffer, stream, errors_format, json
    unless code.match?(/\bpm_buffer_new\b/)
      out << "-DPRISM_FUZZ_LEGACY_BUFFER_STRUCT"
      out << "-DPRISM_FUZZ_BUFFER_CLEANUP" if code.match?(/\bpm_buffer_cleanup\b/)
    end
    out << "-DPRISM_FUZZ_NO_BUFFER_CLEAR" unless code.match?(/\bpm_buffer_clear\b/)
    out << "-DPRISM_FUZZ_NO_ERRORS_FORMAT" unless code.match?(/\bpm_errors_format\b/)
    out << "-DPRISM_FUZZ_NO_PARSER_ERRORS_SIZE" unless code.match?(/\bpm_parser_errors_size\b/)
    if !has_parser_new || !File.file?(File.join(inc, "prism", "stream.h")) || !code.match?(/\bpm_source_stream_new\b/)
      out << "-DPRISM_FUZZ_NO_STREAM"
    end
    out << "-DPRISM_FUZZ_NO_JSON" unless code.match?(/\bpm_dump_json\b/)

    puts out.join(" ")
  ' "$REPO_ROOT/include")"
  if [ -n "$probe_flags" ]; then
    # shellcheck disable=SC2206
    flags+=($probe_flags)
  fi

  case "$profile" in
    asan_ubsan)
      flags+=(-fsanitize=address,undefined -fno-sanitize-recover=all) ;;
    msan_slow)
      if [ "$(uname -s)" = "Darwin" ]; then
        echo "verify_bucket.sh: MSan verification requires Linux (run 'make fuzz-verify BUCKET=...' in Docker)" >&2
        exit 2
      fi
      flags+=(-DSLOW -fsanitize=memory -fsanitize-memory-track-origins -fno-sanitize-recover=all) ;;
    lsan_slow)
      flags+=(-DSLOW -fsanitize=leak -fno-sanitize-recover=all) ;;
    xallocator)
      flags+=("-I$FUZZ_ROOT/test/fuzz/harness/include" -DPRISM_XALLOCATOR) ;;
    *)
      echo "verify_bucket.sh: unknown profile '$profile'" >&2
      exit 2 ;;
  esac

  local bin="$cache_dir/verify_runner.$profile"
  local fp_file="$bin.fingerprint"
  local current_fp=""
  local needs_build=0
  if [ "$REBUILD" -eq 1 ] || [ ! -x "$bin" ]; then
    needs_build=1
  elif [ -f "$fp_file" ]; then
    current_fp="$(compute_build_fingerprint "$REPO_ROOT" "$FUZZ_ROOT" "$cc" "${flags[@]}")"
    if [ "$(cat "$fp_file" 2>/dev/null)" != "$current_fp" ]; then
      needs_build=1
    fi
  elif [ -n "$(find "$REPO_ROOT/src" "$REPO_ROOT/include" "$FUZZ_ROOT/test/fuzz/harness" "$FUZZ_ROOT/test/fuzz/triage/verify_runner.c" -type f -newer "$bin" -print -quit 2>/dev/null)" ]; then
    needs_build=1
  fi

  if [ "$needs_build" -eq 1 ]; then
    shopt -s nullglob
    local srcs=(
      "$REPO_ROOT"/src/*.c
      "$REPO_ROOT"/src/*/*.c
      "$FUZZ_ROOT/test/fuzz/harness/parse.c"
      "$FUZZ_ROOT/test/fuzz/harness/fuzz.c"
      "$FUZZ_ROOT/test/fuzz/triage/verify_runner.c"
    )

    local tmp_bin="$bin.tmp.$$"
    rm -f "$tmp_bin"
    if [ "$JSON_MODE" -eq 0 ] && [ "$BUILD_ONLY" -eq 0 ]; then
      echo "Building verify_runner ($profile)..." >&2
    fi
    if ! "$cc" "${flags[@]}" "${srcs[@]}" -o "$tmp_bin"; then
      rm -f "$tmp_bin"
      echo "verify_bucket.sh: failed to compile verify_runner ($profile) against '$REPO_ROOT'" >&2
      exit 125
    fi
    mv -f "$tmp_bin" "$bin"
    current_fp="$(compute_build_fingerprint "$REPO_ROOT" "$FUZZ_ROOT" "$cc" "${flags[@]}")"
    local tmp_fp="$fp_file.tmp.$$"
    printf '%s\n' "$current_fp" > "$tmp_fp"
    mv -f "$tmp_fp" "$fp_file"
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

if [ "$BUILD_ONLY" -eq 0 ] && [ "$SKIP_MIN" -eq 1 ] && [ "$INPUT_MIN_ONLY" -eq 1 ]; then
  echo "verify_bucket.sh: --input-min-only and --skip-min cannot be combined" >&2
  exit 2
fi

if [ "$INPUT_MIN_ONLY" -eq 1 ]; then
  if [ -f "$BUCKET_DIR/input.min" ]; then
    args+=("$BUCKET_DIR/input.min")
  fi
  exec "$RUNNER" "${args[@]}"
fi

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
