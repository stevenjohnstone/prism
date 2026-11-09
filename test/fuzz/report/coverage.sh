#!/bin/bash -e

if [ -n "$LLVM_VERSION" ] && [ -d "/usr/lib/llvm-${LLVM_VERSION}/bin" ]; then
  export PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:${PATH}"
fi

REPO_ROOT="$(pwd)"

# 1. Build with LTO + section GC (at -O0 so static helpers are not inlined away)
#    to discover the exact set of library functions reachable from the harness.
read -r -a extra_flags <<< "$FUZZ_FLAGS"
src_files=()
while IFS= read -r -d '' file; do
  src_files+=("$file")
done < <(find src -name '*.c' -print0)

echo "Building reachability binary..."
clang -O0 -Iinclude -DSLOW -flto -ffunction-sections -fdata-sections "${extra_flags[@]}" -Wl,--gc-sections \
  "${src_files[@]}" test/fuzz/harness/coverage.c test/fuzz/harness/parse.c -o build/fuzz.coverage

keeplist=$(mktemp)
# Keep reachable static (t) and global (T) functions; exclude harness entrypoints.
llvm-nm --defined-only build/fuzz.coverage | grep " [Tt] " | grep -Ev '[Tt] (main|run_file|run_stdin|setup_signal_handlers|handle_crash_signal|harness|harness_parse|check_node_location)$' | awk '{print $3}' | sed 's/^/fun:/' > "$keeplist"

echo "Building coverage-instrumented binary..."
# Map REPO_ROOT (/prism in Docker) to '.' so exported LCOV/profdata paths are
# workspace-relative (e.g. SF:src/prism.c) and work directly in host IDEs.
clang -O1 -Iinclude -DSLOW -DPROFILE "${extra_flags[@]}" \
  -fcoverage-prefix-map="${REPO_ROOT}=." \
  -fprofile-instr-generate -fcoverage-mapping \
  -fprofile-list="$keeplist" \
  "${src_files[@]}" test/fuzz/harness/coverage.c test/fuzz/harness/parse.c -o build/fuzz.coverage

rm -f "$keeplist"

COVERAGE_DIR="tmp/fuzz/coverage"
REPORT_DIR="$COVERAGE_DIR/report"
PROFDATA_FILE="$COVERAGE_DIR/coverage.profdata"
LCOV_FILE="$COVERAGE_DIR/lcov.info"
SUMMARY_FILE="$COVERAGE_DIR/summary.txt"

WORK_DIR=$(mktemp -d)
PROFRAW_DIR="$WORK_DIR/profraw"
QUEUE_LIST="$WORK_DIR/queue.list"
CRASH_LIST="$WORK_DIR/crash.list"
trap 'rm -rf "$WORK_DIR"' EXIT

# Use an online-merged pool of .profraw files across parallel workers.
JOBS=$(nproc 2>/dev/null || echo 4)
export LLVM_PROFILE_FILE="$PROFRAW_DIR/coverage-%${JOBS}m.profraw"
rm -rf "$COVERAGE_DIR"
mkdir -p "$PROFRAW_DIR" "$COVERAGE_DIR"

# Collect unique queue and crash/hang inputs across all workers (deduplicated by content).
ruby -rdigest -e '
  seen = {}
  queue_out = File.open(ARGV[0], "wb")
  crash_out = File.open(ARGV[1], "wb")

  Dir.glob("tmp/fuzz/afl/*/queue/id*").sort.each do |path|
    next unless File.file?(path)
    digest = Digest::SHA256.file(path).digest
    next if seen[digest]
    seen[digest] = true
    queue_out.write(path)
    queue_out.write("\0")
  end

  Dir.glob("tmp/fuzz/afl/*/{crashes,hangs}/id*").sort.each do |path|
    next unless File.file?(path)
    next if path.end_with?(".bt", ".min", ".md")
    digest = Digest::SHA256.file(path).digest
    next if seen[digest]
    seen[digest] = true
    crash_out.write(path)
    crash_out.write("\0")
  end

  queue_out.close
  crash_out.close
  puts "Collected #{seen.size} unique inputs across tmp/fuzz/afl."
' "$QUEUE_LIST" "$CRASH_LIST"

if [ ! -s "$QUEUE_LIST" ] && [ ! -s "$CRASH_LIST" ]; then
  echo "No fuzz inputs found in tmp/fuzz/afl. Run 'make fuzz-run' first." >&2
  exit 1
fi

run_queue_batch() {
  if ! timeout -k 1s 15s ./build/fuzz.coverage "$@" 2>/dev/null; then
    for f in "$@"; do
      timeout -k 1s 0.2s ./build/fuzz.coverage "$f" 2>/dev/null || true
    done
  fi
}
export -f run_queue_batch

if [ -s "$QUEUE_LIST" ]; then
  echo "Running queue inputs (${JOBS} parallel workers)..."
  xargs -0 -P "$JOBS" -n 256 bash -c 'run_queue_batch "$@"' _ < "$QUEUE_LIST"
fi

if [ -s "$CRASH_LIST" ]; then
  echo "Running crash and hang inputs..."
  xargs -0 -P "$JOBS" -n 1 bash -c 'timeout -k 1s 0.2s ./build/fuzz.coverage "$1" 2>/dev/null || true' _ < "$CRASH_LIST"
fi

FILELIST="$WORK_DIR/profraw.list"
find "$PROFRAW_DIR" -name "coverage-*.profraw" -print > "$FILELIST"

if [ ! -s "$FILELIST" ]; then
  echo "Error: no coverage profile data was produced." >&2
  exit 1
fi

echo "Merging profile data..."
llvm-profdata merge -sparse -f "$FILELIST" -o "$PROFDATA_FILE"

IGNORE_REGEX='^test/fuzz/'

echo "Exporting LCOV and HTML reports..."
llvm-cov export ./build/fuzz.coverage \
  -instr-profile="$PROFDATA_FILE" \
  --format=lcov \
  --ignore-filename-regex="$IGNORE_REGEX" \
  > "$LCOV_FILE"

llvm-cov show ./build/fuzz.coverage \
  -instr-profile="$PROFDATA_FILE" \
  --format=html \
  --show-branches=count \
  --show-line-counts-or-regions \
  --ignore-filename-regex="$IGNORE_REGEX" \
  -o "$REPORT_DIR"

llvm-cov report ./build/fuzz.coverage \
  -instr-profile="$PROFDATA_FILE" \
  --ignore-filename-regex="$IGNORE_REGEX" \
  | tee "$SUMMARY_FILE"

echo ""
echo "Coverage artifacts written to $COVERAGE_DIR:"
echo "  - LCOV (IDE integration): $LCOV_FILE"
echo "  - HTML (browser report):  $REPORT_DIR/index.html"
echo "  - LLVM profdata:          $PROFDATA_FILE"
echo "  - Text summary:           $SUMMARY_FILE"
