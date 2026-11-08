#!/bin/bash -x

testcase=$1
output=${2:-testcase}

src_files=()
while IFS= read -r -d '' file; do
  src_files+=("$file")
done < <(find src -name '*.c' -print0)
clang -O1 -fno-omit-frame-pointer -Iinclude -DSLOW -DPM_ARENA_INITIAL_SIZE=0 -DPM_INTEGER_DIVIDE_THRESHOLD=8 -DPRISM_DEPTH_MAXIMUM=128 -fsanitize=address,undefined -ggdb3 "${src_files[@]}" "$testcase" -o "$output"
