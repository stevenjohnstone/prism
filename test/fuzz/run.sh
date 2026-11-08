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
export AFL_FUZZER_LOOPCOUNT=10000

FUZZ_MAX_ALLOCATED=${FUZZ_MAX_ALLOCATED:-128}
FUZZ_HARD_RSS_LIMIT=$(( FUZZ_MAX_ALLOCATED * 16 ))
FUZZ_ASAN_OPTIONS="abort_on_error=1:handle_abort=1:quarantine_size_mb=16:malloc_context_size=5:max_allocation_size_mb=${FUZZ_MAX_ALLOCATED}:hard_rss_limit_mb=${FUZZ_HARD_RSS_LIMIT}:symbolize=0"
FUZZ_UBSAN_OPTIONS="abort_on_error=1:symbolize=0"
FUZZ_MSAN_OPTIONS="exit_code=86:abort_on_error=1:max_allocation_size_mb=${FUZZ_MAX_ALLOCATED}:hard_rss_limit_mb=${FUZZ_HARD_RSS_LIMIT}:symbolize=0"

cleanup() {
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        bash ./test/fuzz/tools/kill.sh "$SESSION"
    fi
    if [ -d "/tmp/afl-tmpdir/grammar/trees" ] && [ -d "$AFL_DIR/grammar" ]; then
        rm -rf "$AFL_DIR/.grammar-trees"
        cp -r "/tmp/afl-tmpdir/grammar/trees" "$AFL_DIR/.grammar-trees"
    fi
    exit 0
}

if [ -z "$(ls -A "$CORPUS_DIR" 2>/dev/null)" ]; then
    ruby test/fuzz/tools/corpus.rb "$CORPUS_DIR" || exit 1
fi

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
            add_worker "main" "ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS UBSAN_OPTIONS=$FUZZ_UBSAN_OPTIONS afl-fuzz -t 250+ -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -c ./build/fuzz.cmplog -i $CORPUS_DIR -M main -p exploit -o $AFL_DIR ./build/fuzz || read -r -n 1"
            ;;
        1)
            mkdir -p "/tmp/afl-tmpdir/grammar/seeds" "/tmp/afl-tmpdir/grammar/trees"
            if [ -f "$AFL_DIR/grammar/fuzzer_stats" ] && [ -d "$AFL_DIR/.grammar-trees" ]; then
                cp -r "$AFL_DIR/.grammar-trees/." "/tmp/afl-tmpdir/grammar/trees/"
                printf '\x00\x00\x00\x001\n' > "/tmp/afl-tmpdir/grammar/seeds/seed_1"
            else
                rm -rf "$AFL_DIR/grammar" "$AFL_DIR/.grammar-trees"
                ./build/grammar_generator-ruby 500 500 "/tmp/afl-tmpdir/grammar/seeds" "/tmp/afl-tmpdir/grammar/trees" >/dev/null
            fi
            add_worker "grammar" "ulimit -v 4194304 && AFL_NO_IJON=1 AFL_NO_SYNC=1 AFL_CRASH_EXITCODE=23 AFL_CUSTOM_MUTATOR_ONLY=1 AFL_CUSTOM_MUTATOR_LIBRARY=./build/libgrammarmutator-ruby.so afl-fuzz -t 250+ -m $FUZZ_HARD_RSS_LIMIT -G $MAX_INPUT_SIZE -i /tmp/afl-tmpdir/grammar/seeds -o $AFL_DIR -S grammar -p explore -- ./build/fuzz.ldet"
            ;;
        2)
            add_worker "msan" "AFL_CRASH_EXITCODE=23 MSAN_OPTIONS=$FUZZ_MSAN_OPTIONS ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS afl-fuzz -t 250+ -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i $CORPUS_DIR -o $AFL_DIR -S msan -p fast -- ./build/fuzz.msan"
            ;;
        3)
            add_worker "ldet" "ulimit -v 4194304 && AFL_CRASH_EXITCODE=23 afl-fuzz -t 250+ -m $FUZZ_HARD_RSS_LIMIT -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i $CORPUS_DIR -o $AFL_DIR -S ldet -p explore -- ./build/fuzz.ldet"
            ;;
        *)
            sched=${SCHEDULES[$(( (i - 4) % ${#SCHEDULES[@]} ))]}
            name="main-$(( i - 2 ))"
            add_worker "$name" "ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS UBSAN_OPTIONS=$FUZZ_UBSAN_OPTIONS afl-fuzz -t 250+ -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i $CORPUS_DIR -o $AFL_DIR -S $name -p $sched -- ./build/fuzz"
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
tmux bind-key -n C-c confirm-before -p "Stop all fuzzers and exit? (y/n) [Tip: press Ctrl+B then d to detach]" "run-shell 'bash ./test/fuzz/tools/kill.sh'"

echo "Fuzzers started."

if [ -t 0 ] && [ -t 1 ] && [ -z "${FUZZ_DAEMON:-}" ]; then
    echo "Attaching to dashboard (Window 0)."
    tmux -2 attach-session -t "$SESSION"
else
    echo "Running in daemon mode. Attach with: docker exec -it \${CONTAINER} tmux -2 attach-session -t $SESSION"
fi

# If the user detached cleanly (Ctrl+B, D) or started in daemon mode, wait so the container doesn't exit.
# Using wait with sleep in the background allows trapped signals (e.g. SIGTERM from docker stop) to run immediately.
while tmux has-session -t "$SESSION" 2>/dev/null; do
    sleep 1 &
    wait $!
done
