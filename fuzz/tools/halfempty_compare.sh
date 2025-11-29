#!/bin/bash

# FUZZ_SIG and FUZZ_EXE are passed as environment variables
[ "$($FUZZ_EXE /dev/stdin |& ./fuzz/tools/signature.sh )" = "$FUZZ_SIG" ] && {
    exit 0
}
exit 1
