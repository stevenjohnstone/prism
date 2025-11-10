#!/bin/bash

# FUZZ_SIG and FUZZ_EXE are passed as environment variables

signature=($("$FUZZ_EXE" /dev/stdin |& sed -r 's/0x[0-9a-fA-F]*|==[[:digit:]]*==|[[:digit:]]* bytes|[[:digit:]]*-byte//g' | xxh64sum -))

[ "$signature" = "$FUZZ_SIG" ] && {
	exit 0
}
exit 1
