#!/bin/bash

testcase=$1
output=${2:-testcase}

clang -Iinclude -ggdb3 $(find src -name '*.c') "$testcase" -o "$output"
