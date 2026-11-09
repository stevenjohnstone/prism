#!/bin/bash

# FUZZ_SIG and FUZZ_EXE are passed as environment variables
[ "$($FUZZ_EXE /dev/stdin 2>&1 | ./test/fuzz/triage/signature.sh )" = "$FUZZ_SIG" ] && {
    exit 0
}
exit 1
