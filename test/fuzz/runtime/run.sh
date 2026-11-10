#!/bin/bash -x

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
export AFL_SYNC_TIME=2

FUZZ_MAX_ALLOCATED=${FUZZ_MAX_ALLOCATED:-128}
FUZZ_HARD_RSS_LIMIT=$(( FUZZ_MAX_ALLOCATED * 16 ))
FUZZ_ASAN_OPTIONS="abort_on_error=1:handle_abort=1:detect_leaks=0:quarantine_size_mb=16:malloc_context_size=0:max_allocation_size_mb=${FUZZ_MAX_ALLOCATED}:hard_rss_limit_mb=${FUZZ_HARD_RSS_LIMIT}:symbolize=0"
FUZZ_UBSAN_OPTIONS="abort_on_error=1:symbolize=0"
FUZZ_MSAN_OPTIONS="exit_code=86:abort_on_error=1:max_allocation_size_mb=${FUZZ_MAX_ALLOCATED}:hard_rss_limit_mb=${FUZZ_HARD_RSS_LIMIT}:symbolize=0"

cleanup() {
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        bash ./test/fuzz/runtime/kill.sh "$SESSION"
    fi
    exit 0
}

if [ -z "$(ls -A "$CORPUS_DIR" 2>/dev/null)" ]; then
    ruby test/fuzz/runtime/corpus.rb "$CORPUS_DIR" || exit 1
fi

mkdir -p "$AFL_DIR"

# --- Trap Signals ---
# Trap SIGINT (Ctrl+C) and SIGTERM (docker stop)
trap cleanup TERM INT EXIT

SCHEDULES=("explore" "fast" "coe" "lin" "quad" "exploit" "rare" "mmopt")
INPUT_FORMATS=("" "-a text" "-a binary")
MUTATION_STRATEGIES=("-P explore" "" "-P exploit" "-P explore" "")
WORKER_NAMES=()
WORKER_CMDS=()

shopt -s nullglob
CORPUS_FILES=("$CORPUS_DIR"/*)
shopt -u nullglob
NUM_SHARDS=$(( FUZZ_WORKERS > 2 ? FUZZ_WORKERS - 2 : 1 ))

prepare_seed_shard() {
    local name=$1
    local shard_idx=$2
    local shard_dir="/tmp/afl-tmpdir/$name/seeds"
    rm -rf "$shard_dir"
    mkdir -p "$shard_dir"

    local total=${#CORPUS_FILES[@]}
    local files=()
    local idx
    for (( idx = shard_idx; idx < total; idx += NUM_SHARDS )); do
        files+=("${CORPUS_FILES[$idx]}")
    done
    if [ "${#files[@]}" -eq 0 ] && [ "$total" -gt 0 ]; then
        files+=("${CORPUS_FILES[$(( shard_idx % total ))]}")
    fi
    if [ "${#files[@]}" -gt 0 ]; then
        cp "${files[@]}" "$shard_dir/"
    fi
}

add_worker() {
    local name=$1
    local cmd=$2
    mkdir -p "/tmp/afl-tmpdir/$name"
    WORKER_NAMES+=("$name")
    WORKER_CMDS+=("/bin/bash -c 'AFL_TMPDIR=/tmp/afl-tmpdir/$name $cmd'")
}

mkdir -p "/tmp/afl-tmpdir/grammar/seeds"

# When ldet (worker 3) is active, let ldet (-M ldet -F ...) ingest grammar seeds
# so IJON state-transition coverage + fast native execution filter them before
# syncing winners to main, msan, and SAND workers; fall back to main when < 4 workers.
if [ "$FUZZ_WORKERS" -ge 4 ]; then
    MAIN_FOREIGN_FLAGS=""
    LDET_SYNC_FLAGS="-M ldet -F /tmp/afl-tmpdir/grammar/seeds"
else
    MAIN_FOREIGN_FLAGS="-F /tmp/afl-tmpdir/grammar/seeds"
    LDET_SYNC_FLAGS="-S ldet"
fi

for (( i = 0; i < FUZZ_WORKERS; i++ )); do
    case $i in
        0)
            add_worker "main" "ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS UBSAN_OPTIONS=$FUZZ_UBSAN_OPTIONS afl-fuzz -M main $MAIN_FOREIGN_FLAGS -t 250+ -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -c ./build/fuzz.cmplog -i $CORPUS_DIR -p exploit -o $AFL_DIR ./build/fuzz || read -r -n 1"
            ;;
        1)
            add_worker "grammar" "ulimit -v 4194304 && ruby ./test/fuzz/runtime/grammar.rb '$AFL_DIR' '/tmp/afl-tmpdir/grammar/seeds'"
            ;;
        2)
            prepare_seed_shard "msan" 0
            add_worker "msan" "AFL_DISABLE_TRIM=1 AFL_CRASH_EXITCODE=23 MSAN_OPTIONS=$FUZZ_MSAN_OPTIONS ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS afl-fuzz -t 250+ -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i /tmp/afl-tmpdir/msan/seeds -o $AFL_DIR -S msan -p fast -- ./build/fuzz.msan"
            ;;
        3)
            prepare_seed_shard "ldet" 1
            add_worker "ldet" "ulimit -v 4194304 && AFL_CRASH_EXITCODE=23 afl-fuzz -t 250+ -m $FUZZ_HARD_RSS_LIMIT -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i /tmp/afl-tmpdir/ldet/seeds -o $AFL_DIR $LDET_SYNC_FLAGS -p explore -- ./build/fuzz.ldet"
            ;;
        *)
            idx=$(( i - 4 ))
            name="main-$(( i - 2 ))"
            prepare_seed_shard "$name" $(( i - 2 ))
            sched=${SCHEDULES[$(( idx % ${#SCHEDULES[@]} ))]}
            fmt=${INPUT_FORMATS[$(( idx % ${#INPUT_FORMATS[@]} ))]}
            strat=${MUTATION_STRATEGIES[$(( idx % ${#MUTATION_STRATEGIES[@]} ))]}
            extra_flags="$fmt $strat"
            if [ "$idx" -eq 0 ]; then
                extra_flags="$extra_flags -L 0"
            elif [ "$idx" -eq 1 ]; then
                extra_flags="$extra_flags -Z"
            fi
            extra_env=""
            if [ $(( idx % 2 )) -eq 0 ]; then
                extra_env="AFL_DISABLE_TRIM=1 "
            fi
            add_worker "$name" "${extra_env}AFL_SAN_ABSTRACTION=coverage_increase AFL_CRASH_EXITCODE=23 ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS UBSAN_OPTIONS=$FUZZ_UBSAN_OPTIONS afl-fuzz -t 250+ -m none -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i /tmp/afl-tmpdir/$name/seeds -o $AFL_DIR -S $name -p $sched $extra_flags -w ./build/fuzz.sand -- ./build/fuzz.native"
            ;;
    esac
done

echo "Starting tmux session with $FUZZ_WORKERS fuzzer workers..."

if [[ -n $TERM ]]; then
    export TERM="xterm-256color"
fi

# Window 0: Fleet status dashboard
tmux -2 new-session -d -s "$SESSION" -n "dashboard" "ruby ./test/fuzz/runtime/status.rb '$AFL_DIR' ${WORKER_NAMES[*]}"
tmux set-option -g default-terminal "tmux-256color"
tmux set-option -g remain-on-exit on

# Windows 1..N: One window per fuzzer
for (( i = 0; i < ${#WORKER_NAMES[@]}; i++ )); do
    tmux new-window -d -t "$SESSION" -n "${WORKER_NAMES[$i]}" "${WORKER_CMDS[$i]}"
done

tmux select-window -t "$SESSION:0"
tmux bind-key -n C-c confirm-before -p "Stop all fuzzers and exit? (y/n) [Tip: press Ctrl+B then d to detach]" "run-shell 'bash ./test/fuzz/runtime/kill.sh'"

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
