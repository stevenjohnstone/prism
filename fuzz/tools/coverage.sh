#!/bin/bash -e

# build the coverage executable with unused function pruned to get a list of functions we should mark for profiling
clang -Iinclude -flto -ffunction-sections -fdata-sections -Wl,--gc-section $(find src -name "*.c") fuzz/coverage.c fuzz/parse.c -o build/fuzz.coverage
keeplist=$(mktemp)
# keep static (t) and global (T) functions. filter out main and harness
llvm-nm --defined-only build/fuzz.coverage | grep " [Tt] " | grep -Ev '[Tt] (main|harness)$' | awk '{print $3}' | sed 's/^/fun:/' > "$keeplist"

clang -Iinclude -DPROFILE -fprofile-instr-generate -fcoverage-mapping \
    -fprofile-list="$keeplist" $(find src -name "*.c") fuzz/coverage.c fuzz/parse.c -o build/fuzz.coverage

rm "$keeplist"



export LLVM_PROFILE_FILE="fuzz/output/profraw_files/coverage-%p.profraw"
rm -rf "fuzz/output/profraw_files"
mkdir -p "fuzz/output/profraw_files"

# Main timeout: 0.1 second
# Kill grace period: 1 second
TIMEOUT_CMD="timeout -k 1s 0.1s"

echo "Processing queue, crashes, and hangs..."

for f in fuzz/output/*/{queue/*,crashes/*,hangs/*}; do
  [ -f "$f" ] || continue

  # Run with the robust timeout command
  $TIMEOUT_CMD ./build/fuzz.coverage < "$f" || true
done

FILELIST=$(mktemp)

find fuzz/output/profraw_files -name "coverage-*.profraw" -print > "$FILELIST"

echo "Merging profile data..."
llvm-profdata merge -sparse -f "$FILELIST" -o coverage.profdata
echo "Creating html"
llvm-cov show ./build/fuzz.coverage -instr-profile=coverage.profdata --format=html -o ./build/fuzz-coverage-report

rm "$FILELIST"

