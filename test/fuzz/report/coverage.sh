#!/bin/bash -e

if [ -n "$LLVM_VERSION" ] && [ -d "/usr/lib/llvm-${LLVM_VERSION}/bin" ]; then
  export PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:${PATH}"
fi

# build the coverage executable with unused function pruned to get a list of functions we should mark for profiling
read -r -a extra_flags <<< "$FUZZ_FLAGS"
src_files=()
while IFS= read -r -d '' file; do
  src_files+=("$file")
done < <(find src -name '*.c' -print0)
clang -Iinclude -DSLOW -flto -ffunction-sections -fdata-sections "${extra_flags[@]}" -Wl,--gc-section "${src_files[@]}" test/fuzz/harness/coverage.c test/fuzz/harness/parse.c -o build/fuzz.coverage
keeplist=$(mktemp)
# keep static (t) and global (T) functions. filter out main, harness, and harness_parse
llvm-nm --defined-only build/fuzz.coverage | grep " [Tt] " | grep -Ev '[Tt] (main|harness|harness_parse)$' | awk '{print $3}' | sed 's/^/fun:/' > "$keeplist"

clang -Iinclude -include assert.h -DSLOW -DPROFILE "${extra_flags[@]}" -fprofile-instr-generate -fcoverage-mapping \
    -fprofile-list="$keeplist" "${src_files[@]}" test/fuzz/harness/coverage.c test/fuzz/harness/parse.c -o build/fuzz.coverage

rm "$keeplist"



COVERAGE_DIR="tmp/fuzz/coverage"
REPORT_DIR="$COVERAGE_DIR/report"
WORK_DIR=$(mktemp -d)
PROFRAW_DIR="$WORK_DIR/profraw"
PROFDATA_FILE="$WORK_DIR/coverage.profdata"
trap 'rm -rf "$WORK_DIR"' EXIT

export LLVM_PROFILE_FILE="$PROFRAW_DIR/coverage-%m.profraw"
rm -rf "$COVERAGE_DIR"
mkdir -p "$PROFRAW_DIR" "$COVERAGE_DIR"

# Main timeout: 0.1 second
# Kill grace period: 1 second
TIMEOUT_CMD="timeout -k 1s 0.1s"

echo "Processing main queue, crashes, and hangs..."

for f in tmp/fuzz/afl/main/queue/* tmp/fuzz/afl/*/{crashes/*,hangs/*}; do
  [ -f "$f" ] || continue

  # Run with the robust timeout command
  $TIMEOUT_CMD ./build/fuzz.coverage < "$f" || echo "$f failed"
done

FILELIST=$(mktemp)

find "$PROFRAW_DIR" -name "coverage-*.profraw" -print > "$FILELIST"

echo "Merging profile data..."
llvm-profdata merge -sparse -f "$FILELIST" -o "$PROFDATA_FILE"
echo "Creating html"
llvm-cov show ./build/fuzz.coverage -instr-profile="$PROFDATA_FILE" --format=html -o "$REPORT_DIR"
echo "Run \`open $REPORT_DIR/index.html\` to view coverage report"

rm "$FILELIST"

