#!/bin/bash

FUZZ_EXE=$1
INPUT=$2
OUTPUT=$3

FUZZ_SIG=($("$FUZZ_EXE" "$INPUT" |& sed -r 's/0x[0-9a-fA-F]*|==[[:digit:]]*==|[[:digit:]]* bytes|[[:digit:]]*-byte//g' | xxh64sum -))

FUZZ_SIG=$FUZZ_SIG FUZZ_EXE=$FUZZ_EXE halfempty --zero-skip-multiplier=0.0005 --bisect-skip-multiplier=0.0005 --noverify --zero-char=32 ./fuzz/tools/halfempty_compare.sh "$INPUT" -o "$OUTPUT"
