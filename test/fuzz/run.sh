#!/bin/bash

AFL_DIR=${1:-./tmp/fuzz/afl}
CORPUS_DIR=${2:-./tmp/fuzz/corpus}
MAX_INPUT_SIZE=${FUZZ_MAX_INPUT_SIZE:-1024}
SESSION="fuzzer"

DEFAULT_WORKERS=$(( $(nproc) / 2 ))
if [ "$DEFAULT_WORKERS" -lt 4 ]; then
    DEFAULT_WORKERS=4
fi
FUZZ_WORKERS=${FUZZ_WORKERS:-$DEFAULT_WORKERS}
if [ "$FUZZ_WORKERS" -lt 1 ]; then
    FUZZ_WORKERS=1
fi

export AFL_AUTORESUME=1
export AFL_FUZZER_STATS_UPDATE_INTERVAL=1

FUZZ_MAX_ALLOCATED=${FUZZ_MAX_ALLOCATED:-64}
FUZZ_HARD_RSS_LIMIT=$(( FUZZ_MAX_ALLOCATED * 32 ))
FUZZ_ASAN_OPTIONS="abort_on_error=1:handle_abort=1:quarantine_size_mb=16:malloc_context_size=5:max_allocation_size_mb=${FUZZ_MAX_ALLOCATED}:hard_rss_limit_mb=${FUZZ_HARD_RSS_LIMIT}:symbolize=0"
FUZZ_MSAN_OPTIONS="exit_code=86:abort_on_error=1:max_allocation_size_mb=${FUZZ_MAX_ALLOCATED}:hard_rss_limit_mb=${FUZZ_HARD_RSS_LIMIT}:symbolize=0"

cleanup() {
    exit 0
}

[ -d "$CORPUS_DIR" ] || {
    ruby test/fuzz/tools/corpus.rb "$CORPUS_DIR"
}

mkdir -p "$AFL_DIR"

# --- Trap Signals ---
# Trap SIGINT (Ctrl+C) and SIGTERM (docker stop)
trap cleanup TERM INT EXIT

SCHEDULES=("explore" "coe" "fast")
WORKER_NAMES=()
WORKER_CMDS=()

add_worker() {
    local name=$1
    local cmd=$2
    mkdir -p "/tmp/afl-tmpdir/$name"
    WORKER_NAMES+=("$name")
    WORKER_CMDS+=("/bin/bash -c 'AFL_TMPDIR=/tmp/afl-tmpdir/$name $cmd'")
}

for (( i = 0; i < FUZZ_WORKERS; i++ )); do
    case $i in
        0)
            add_worker "main" "ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS afl-fuzz -t 250+ -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -c ./build/fuzz.cmplog -i $CORPUS_DIR -M main -p exploit -o $AFL_DIR ./build/fuzz || read -r -n 1"
            ;;
        1)
            mkdir -p "/tmp/afl-tmpdir/grammar/seeds" "/tmp/afl-tmpdir/grammar/trees"
            ./build/grammar_generator-ruby 100 500 "/tmp/afl-tmpdir/grammar/seeds" "/tmp/afl-tmpdir/grammar/trees" >/dev/null
            add_worker "grammar" "ulimit -v 4194304 && AFL_CRASH_EXITCODE=23 AFL_CUSTOM_MUTATOR_ONLY=1 AFL_CUSTOM_MUTATOR_LIBRARY=./build/libgrammarmutator-ruby.so afl-fuzz -t 250+ -m $FUZZ_HARD_RSS_LIMIT -G $MAX_INPUT_SIZE -i /tmp/afl-tmpdir/grammar/seeds -o $AFL_DIR -S grammar -p explore -- ./build/fuzz.ldet"
            ;;
        2)
            add_worker "msan" "AFL_CRASH_EXITCODE=23 MSAN_OPTIONS=$FUZZ_MSAN_OPTIONS ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS afl-fuzz -t 250+ -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i $CORPUS_DIR -o $AFL_DIR -S msan -p fast -- ./build/fuzz.msan"
            ;;
        *)
            sched=${SCHEDULES[$(( (i - 3) % ${#SCHEDULES[@]} ))]}
            name="main-$(( i - 1 ))"
            add_worker "$name" "ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS afl-fuzz -t 250+ -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i $CORPUS_DIR -o $AFL_DIR -S $name -p $sched -- ./build/fuzz"
            ;;
    esac
done

echo "Starting tmux session with $FUZZ_WORKERS fuzzer workers..."

if [[ -n $TERM ]]; then
    export TERM="xterm-256color"
fi

# Window 0: Fleet status dashboard
tmux -2 new-session -d -s "$SESSION" -n "dashboard" "ruby ./test/fuzz/tools/status.rb '$AFL_DIR' ${WORKER_NAMES[*]}"
tmux set-option -g default-terminal "tmux-256color"
tmux set-option -g remain-on-exit on

# Windows 1..N: One window per fuzzer
for (( i = 0; i < ${#WORKER_NAMES[@]}; i++ )); do
    tmux new-window -d -t "$SESSION" -n "${WORKER_NAMES[$i]}" "${WORKER_CMDS[$i]}"
done

tmux select-window -t "$SESSION:0"
tmux bind-key -n C-c run-shell 'bash ./test/fuzz/tools/kill.sh'

echo "Fuzzers started."
echo "Attaching to dashboard (Window 0)."

tmux -2 attach-session -t "$SESSION"

# If the user detached cleanly (Ctrl+B, D), wait so the container doesn't exit.
while tmux has-session -t "$SESSION" 2>/dev/null; do
    sleep 1
done
