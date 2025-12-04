#!/bin/bash -x

testcase=$1
output=${2:-testcase}

clang -Iinclude -fsanitize=address,undefined -ggdb3 $(find src -name '*.c') "$testcase" -o "$output"
