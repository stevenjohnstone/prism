#!/bin/bash

export UBSAN_OPTIONS=print_stacktrace=1
FUZZ_EXE=$1
INPUT=$2
OUTPUT=$3

echo "halfempty output dir = $OUTPUT"

FUZZ_SIG=$("$FUZZ_EXE" "$INPUT" 2>&1 | ./test/fuzz/tools/signature.sh)

FUZZ_SIG=$FUZZ_SIG FUZZ_EXE=$FUZZ_EXE halfempty --zero-skip-multiplier=0.0005 --bisect-skip-multiplier=0.0005 --noverify --zero-char=32 ./test/fuzz/tools/halfempty_compare.sh "$INPUT" -o "$OUTPUT"
