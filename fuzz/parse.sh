#!/bin/bash

OUTPUT_DIR=$1
MAX_INPUT_SIZE=128


screen -S noread  -d -m /bin/bash -c "afl-fuzz -x ./fuzz/dict -G $MAX_INPUT_SIZE -i ./fuzz/corpus/parse -o $OUTPUT_DIR -S noread_parse -- ./build/fuzz.parse.noread"

screen -S grammar -d -m  /bin/bash -c "AFL_CUSTOM_MUTATOR_LIBRARY=/usr/local/lib/libgrammarmutator-ruby.so AFL_CUSTOM_MUTATOR_ONLY=1 afl-fuzz -G $MAX_INPUT_SIZE -i fuzz/corpus/parse -o $OUTPUT_DIR -S grammar_parse -- ./build/fuzz.parse"

screen -S main -m /bin/bash -c "afl-fuzz -x ./fuzz/dict -G $MAX_INPUT_SIZE -c ./build/fuzz.parse.cmplog -i ./fuzz/corpus/parse -M main_parse -o $OUTPUT_DIR ./build/fuzz.parse || read -n 1"

exec /bin/bash
