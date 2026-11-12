#!/bin/sh

# FUZZ_SIG, FUZZ_EXE, FUZZ_HEADER_FILE, and FUZZ_WORKDIR are passed via environment variables.
tmpfile="${FUZZ_WORKDIR:-${TMPDIR:-/tmp}}/he_cand.$$"
cleanup() {
  rm -f "$tmpfile"
}
trap cleanup EXIT
trap 'cleanup; exit 143' TERM INT

cat "$FUZZ_HEADER_FILE" - > "$tmpfile" || exit 1

out=$("$FUZZ_EXE" "$tmpfile" 2>&1)
rc=$?

if [ "$rc" -eq 0 ]; then
  exit 1
fi

sig=$(printf '%s\n' "$out" | ./test/fuzz/triage/signature.sh)
[ "$sig" = "$FUZZ_SIG" ]
