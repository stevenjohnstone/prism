#!/bin/bash

OUTPUT_DIR=$1
MAX_INPUT_SIZE=128
SESSION="fuzzer"

export AFL_AUTORESUME=1


cleanup() {
    exit 0
}

[ -d "$OUTPUT_DIR"/corpus ] || {
    mkdir -p "$OUTPUT_DIR/corpus"
    ruby fuzz/tools/corpus.rb "$OUTPUT_DIR/corpus"
}

# --- Trap Signals ---
# Trap SIGINT (Ctrl+C) and SIGTERM (docker stop)
# SIGTERM is now the main one, for docker stop.
trap cleanup TERM INT EXIT

CMD_NOREAD="/bin/bash -c 'afl-fuzz -x ./fuzz/dict -G $MAX_INPUT_SIZE -i ${OUTPUT_DIR}/corpus -o $OUTPUT_DIR -S noread -p coe -- ./build/fuzz.noread'"
CMD_UBSAN="/bin/bash -c 'afl-fuzz -x ./fuzz/dict -G $MAX_INPUT_SIZE -i ${OUTPUT_DIR}/corpus -o $OUTPUT_DIR -S ubsan -p exploit -- ./build/fuzz.ubsan'"
CMD_GRAMMAR="/bin/bash -c 'AFL_CUSTOM_MUTATOR_LIBRARY=/usr/local/lib/libgrammarmutator-ruby.so afl-fuzz -G $MAX_INPUT_SIZE -i ${OUTPUT_DIR}/corpus -o $OUTPUT_DIR -S grammar -p rare -- ./build/fuzz'"
CMD_MAIN="/bin/bash -c 'afl-fuzz -x ./fuzz/dict -G $MAX_INPUT_SIZE -c ./build/fuzz.cmplog -i ${OUTPUT_DIR}/corpus -M main -o $OUTPUT_DIR ./build/fuzz|| read -n 1'"

echo "Starting tmux session with 2x2 grid..."

# 1. Start session
if [[ -n $TERM ]]; then
    export TERM="xterm-256color"
fi

tmux -2 -vv new-session -d -s "$SESSION" -n "fuzzers" "$CMD_MAIN"
tmux set-option -g default-terminal "tmux-256color"
tmux set-option remain-on-exit on
# 2. Split vertically
tmux split-window -v -t "$SESSION:0" "$CMD_GRAMMAR"
# 3. Split top pane
tmux select-pane -t "$SESSION:0.0"
tmux split-window -h -t "$SESSION:0.0" "$CMD_UBSAN"
# 4. Split bottom pane
tmux select-pane -t "$SESSION:0.1"
tmux split-window -h -t "$SESSION:0.1" "$CMD_NOREAD"
# 5. Equalize layout
tmux select-layout -t "$SESSION:0" tiled

tmux bind-key -n C-c run-shell 'bash ./fuzz/tools/kill.sh' 

tmux set-hook -g client-resized "run-shell './fuzz/resize.sh'"


echo "Fuzzers started."
echo "Attaching to 2x2 grid."
echo "Press (Ctrl+B, then Arrow Keys) to switch panes."
echo "Press (Ctrl+B, then D) to detach."
echo "Press (Ctrl+C) to stop everything."

# Attach to the session.
tmux -2 attach-session -t "$SESSION"

# If the user detached cleanly (Ctrl+B, D), we want the script to wait
# so the container doesn't exit.
while tmux has-session -t "$SESSION" 2>/dev/null; do
    sleep 1
done


