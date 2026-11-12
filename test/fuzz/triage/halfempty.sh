#!/bin/bash
set -euo pipefail

export UBSAN_OPTIONS="${UBSAN_OPTIONS:-abort_on_error=1:print_stacktrace=1}"
: "${SIGLINES:=10}"
: "${HALFEMPTY_THREADS:=2}"

FUZZ_EXE=$1
INPUT=$2
OUTPUT=$3

if [ ! -f "$INPUT" ] || [ "$(wc -c < "$INPUT")" -lt 4 ]; then
  exit 1
fi

set +e
initial_out=$(timeout -k 1 5 "$FUZZ_EXE" "$INPUT" 2>&1)
initial_rc=$?
set -e

if [ "$initial_rc" -eq 0 ] || [ "$initial_rc" -eq 124 ] || [ "$initial_rc" -eq 137 ]; then
  echo "Input $INPUT did not crash cleanly (rc=$initial_rc); skipping halfempty" >&2
  exit 1
fi

FUZZ_SIG=$(printf '%s\n' "$initial_out" | ./test/fuzz/triage/signature.sh)
if [ -z "$FUZZ_SIG" ]; then
  exit 1
fi

workdir=$(mktemp -d "${TMPDIR:-/tmp}/halfempty_work.XXXXXX")
trap 'rm -rf "$workdir"' EXIT

head -c 4 "$INPUT" > "$workdir/header.bin"
tail -c +5 "$INPUT" > "$workdir/body.bin"

if [ -s "$workdir/body.bin" ]; then
  if FUZZ_SIG="$FUZZ_SIG" \
      FUZZ_EXE="$FUZZ_EXE" \
      FUZZ_HEADER_FILE="$workdir/header.bin" \
      FUZZ_WORKDIR="$workdir" \
      halfempty \
        --stable \
        -T 3 \
        -P "$HALFEMPTY_THREADS" \
        --zero-skip-multiplier=0.0005 \
        --bisect-skip-multiplier=0.0005 \
        --zero-char=32 \
        ./test/fuzz/triage/halfempty_compare.sh "$workdir/body.bin" \
        -o "$workdir/body.min"; then
    :
  else
    cp "$workdir/body.bin" "$workdir/body.min"
  fi
else
  cp "$workdir/body.bin" "$workdir/body.min"
fi

cat "$workdir/header.bin" "$workdir/body.min" > "$OUTPUT"
