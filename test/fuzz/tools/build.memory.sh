#!/bin/bash -x

testcase=$1
output=${2:-testcase}

src_files=()
while IFS= read -r -d '' file; do
  src_files+=("$file")
done < <(find src -name '*.c' -print0)
clang -Iinclude -DPM_ARENA_INITIAL_SIZE=0 -DPM_INTEGER_DIVIDE_THRESHOLD=8 -fsanitize=memory -fsanitize-memory-track-origins=2 -ggdb3 "${src_files[@]}" "$testcase" -o "$output"
