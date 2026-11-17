#!/bin/bash -x

AFL_DIR=${1:-./tmp/fuzz/afl}
AFL_IJON_DIR="${AFL_DIR}-ijon"
CORPUS_DIR=${2:-./tmp/fuzz/corpus}
SEEDS_BACKUP_DIR="$(dirname "$AFL_DIR")/seeds"
BIN_DIR="$(dirname "$AFL_DIR")/bin"
MAX_INPUT_SIZE=${FUZZ_MAX_INPUT_SIZE:-1024}
SESSION="fuzzer"

DEFAULT_WORKERS=$(( $(nproc) / 2 ))
if [ "$DEFAULT_WORKERS" -lt 6 ]; then
    DEFAULT_WORKERS=6
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
    trap '' TERM INT
    trap - EXIT
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        bash ./test/fuzz/runtime/kill.sh "$SESSION"
    fi
    rm -rf "$SEEDS_BACKUP_DIR"
    if [ -d "/tmp/afl-tmpdir/grammar/seeds" ]; then
        ruby -rfileutils -e '
          src, dst = ARGV
          unread = []
          Dir.children(src).each do |f|
            next if f.start_with?(".")
            p = File.join(src, f)
            st = File.stat(p) rescue next
            unread << p if st.file? && (st.atime.to_i <= 1 || st.atime == st.mtime)
            break if unread.size >= 5000
          end
          if unread.any?
            FileUtils.mkdir_p(dst)
            unread.each { |p| FileUtils.cp(p, File.join(dst, File.basename(p))) }
          end
        ' "/tmp/afl-tmpdir/grammar/seeds" "$SEEDS_BACKUP_DIR" || true
    fi
    exit 0
}

if [ -z "$(ls -A "$CORPUS_DIR" 2>/dev/null)" ]; then
    ruby test/fuzz/runtime/corpus.rb "$CORPUS_DIR" || exit 1
fi

mkdir -p "$AFL_DIR"

# Snapshot compiled fuzzer binaries and provenance into $BIN_DIR so later edits
# or rebuilds in ./build do not mutate the campaign binaries used by triage.
ruby ./test/fuzz/runtime/provenance.rb snapshot "./build" "$BIN_DIR" || exit 1

# --- Trap Signals ---
# Trap SIGINT (Ctrl+C) and SIGTERM (docker stop)
trap cleanup TERM INT EXIT

DIFF_SCHEDULES=("fast" "coe" "lin" "quad" "exploit" "rare" "mmopt" "explore")
DIFF_FORMATS=("" "-a text")
MUTATION_STRATEGIES=("-P explore" "" "-P exploit" "-P explore" "")
WORKER_NAMES=()
WORKER_CMDS=()

shopt -s nullglob
CORPUS_FILES=("$CORPUS_DIR"/*)
shopt -u nullglob
if [ "$FUZZ_WORKERS" -ge 7 ]; then
    NUM_SHARDS=4
elif [ "$FUZZ_WORKERS" -ge 5 ]; then
    NUM_SHARDS=3
elif [ "$FUZZ_WORKERS" -eq 4 ]; then
    NUM_SHARDS=2
else
    NUM_SHARDS=1
fi

prepare_diff_seeds() {
    local name=$1
    local base_seed_dir="/tmp/afl-tmpdir/diff/seeds"
    local seed_dir="/tmp/afl-tmpdir/$name/seeds"
    rm -rf "$seed_dir"
    mkdir -p "$seed_dir"

    if [ "$name" != "diff" ] && [ -d "$base_seed_dir" ]; then
        cp "$base_seed_dir"/* "$seed_dir/" 2>/dev/null || true
        return
    fi

    ruby -retc -rfileutils -e '
      corpus_dir, seed_dir, diff_bin = ARGV
      files = Dir.children(corpus_dir).map { |f| File.join(corpus_dir, f) }.select { |p| File.file?(p) }.sort
      queue = Queue.new
      files.each { |f| queue << f }
      threads = [Etc.nprocessors, 1].max.times.map do
        Thread.new do
          while (f = queue.pop(true) rescue nil)
            if system(diff_bin, f, [:out, :err] => File::NULL)
              FileUtils.cp(f, File.join(seed_dir, File.basename(f)))
            end
          end
        end
      end
      threads.each(&:join)
    ' "$CORPUS_DIR" "$seed_dir" "$BIN_DIR/fuzz.diff"
}

add_diff_worker() {
    local name=$1
    local extra_env=$2
    local afl_opts=$3
    prepare_diff_seeds "$name"
    add_worker "$name" "${extra_env}afl-fuzz -t 250+ -m none -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i /tmp/afl-tmpdir/$name/seeds -o $AFL_DIR -S $name $afl_opts -- $BIN_DIR/fuzz.diff"
}

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
if [ -d "$SEEDS_BACKUP_DIR" ]; then
    for f in "$SEEDS_BACKUP_DIR"/*; do
        [ -f "$f" ] && cp "$f" "/tmp/afl-tmpdir/grammar/seeds/"
    done
    rm -rf "$SEEDS_BACKUP_DIR"
fi

# When ijon (worker 3) is active, run ijon as a standalone master (-M ijon) in its
# own sync directory ($AFL_IJON_DIR) with grammar seeds as its foreign queue (-F),
# and expose ijon's queue to main via a one-way shadow peer directory
# ($AFL_DIR/ijon_peer/queue -> ../../$(basename "$AFL_IJON_DIR")/ijon/queue) without
# an is_main_node marker. That lets -M main sync every id:%06u entry sequentially via
# .synced/ijon_peer (with zero 1-second st_mtime foreign-sync loss) while -S
# secondaries skip ijon_peer; fall back to main directly when < 4 workers.
if [ "$FUZZ_WORKERS" -ge 4 ]; then
    if [ -f "$AFL_DIR/ijon/fuzzer_stats" ] && [ ! -e "$AFL_IJON_DIR/ijon" ]; then
        mkdir -p "$AFL_IJON_DIR"
        mv "$AFL_DIR/ijon" "$AFL_IJON_DIR/ijon"
    fi
    rm -rf "$AFL_IJON_DIR/.foreign"
    mkdir -p "$AFL_IJON_DIR/ijon/queue" "$AFL_DIR/ijon_peer"
    ln -sfn "../../$(basename "$AFL_IJON_DIR")/ijon/queue" "$AFL_DIR/ijon_peer/queue"
    rm -f "$AFL_DIR/ijon_peer/is_main_node"
    MAIN_FOREIGN_FLAGS=""
    IJON_OUT_DIR="$AFL_IJON_DIR"
    IJON_SYNC_FLAGS="-M ijon -F /tmp/afl-tmpdir/grammar/seeds"
else
    rm -rf "$AFL_DIR/ijon_peer"
    MAIN_FOREIGN_FLAGS="-F /tmp/afl-tmpdir/grammar/seeds"
    IJON_OUT_DIR="$AFL_DIR"
    IJON_SYNC_FLAGS="-S ijon"
fi

# diff (worker 5) runs as a standard secondary (-S diff) in $AFL_DIR so it
# syncs bidirectionally with -M main while seeding from parse.y-compatible
# corpus inputs. Remove any legacy diff_peer symlink and migrate an existing
# isolated ${AFL_DIR}-diff/diff directory into $AFL_DIR/diff if present.
rm -rf "$AFL_DIR/diff_peer"
if [ -d "${AFL_DIR}-diff/diff" ] && [ ! -d "$AFL_DIR/diff" ]; then
    mkdir -p "$AFL_DIR"
    mv "${AFL_DIR}-diff/diff" "$AFL_DIR/diff"
    rm -f "$AFL_DIR/diff/is_main_node"
    rmdir "${AFL_DIR}-diff" 2>/dev/null || true
fi

diff_extra_idx=0

for (( i = 0; i < FUZZ_WORKERS; i++ )); do
    case $i in
        0)
            add_worker "main" "AFL_FUZZER_LOOPCOUNT=2000 ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS UBSAN_OPTIONS=$FUZZ_UBSAN_OPTIONS afl-fuzz -M main $MAIN_FOREIGN_FLAGS -t 250+ -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -c $BIN_DIR/fuzz.cmplog -i $CORPUS_DIR -p exploit -o $AFL_DIR $BIN_DIR/fuzz || read -r -n 1"
            ;;
        1)
            add_worker "grammar" "ulimit -v 4194304 && FUZZ_BIN_DIR=$BIN_DIR FUZZ_RUBY_EXT_DIR=$BIN_DIR/fuzz-ruby-ext ruby ./test/fuzz/runtime/grammar.rb '$AFL_DIR' '/tmp/afl-tmpdir/grammar/seeds'"
            ;;
        2)
            prepare_seed_shard "msan" 0
            add_worker "msan" "AFL_FUZZER_LOOPCOUNT=2000 AFL_DISABLE_TRIM=1 MSAN_OPTIONS=$FUZZ_MSAN_OPTIONS ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS afl-fuzz -t 250+ -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i /tmp/afl-tmpdir/msan/seeds -o $AFL_DIR -S msan -p fast -- $BIN_DIR/fuzz.msan"
            ;;
        3)
            prepare_seed_shard "ijon" 1
            add_worker "ijon" "ulimit -v 4194304 && AFL_SYNC_TIME=1 AFL_CRASH_EXITCODE=23 afl-fuzz -t 250+ -m $FUZZ_HARD_RSS_LIMIT -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i /tmp/afl-tmpdir/ijon/seeds -o $IJON_OUT_DIR $IJON_SYNC_FLAGS -p explore -- $BIN_DIR/fuzz.ijon"
            ;;
        4)
            prepare_seed_shard "slow" 2
            add_worker "slow" "AFL_FUZZER_LOOPCOUNT=2000 AFL_DISABLE_TRIM=1 ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS UBSAN_OPTIONS=$FUZZ_UBSAN_OPTIONS afl-fuzz -t 250+ -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i /tmp/afl-tmpdir/slow/seeds -o $AFL_DIR -S slow -p fast -- $BIN_DIR/fuzz.slow"
            ;;
        5)
            add_diff_worker "diff" "" "-p explore"
            ;;
        6)
            prepare_seed_shard "main-2" 3
            add_worker "main-2" "AFL_DISABLE_TRIM=1 AFL_SAN_ABSTRACTION=coverage_increase AFL_CRASH_EXITCODE=23 ASAN_OPTIONS=$FUZZ_ASAN_OPTIONS UBSAN_OPTIONS=$FUZZ_UBSAN_OPTIONS afl-fuzz -t 250+ -m none -x ./test/fuzz/dict -G $MAX_INPUT_SIZE -i /tmp/afl-tmpdir/main-2/seeds -o $AFL_DIR -S main-2 -p explore -P explore -L 0 -w $BIN_DIR/fuzz.sand -- $BIN_DIR/fuzz.native"
            ;;
        *)
            idx=$diff_extra_idx
            name="diff-$(( diff_extra_idx + 2 ))"
            diff_extra_idx=$(( diff_extra_idx + 1 ))
            sched=${DIFF_SCHEDULES[$(( idx % ${#DIFF_SCHEDULES[@]} ))]}
            fmt=${DIFF_FORMATS[$(( idx % ${#DIFF_FORMATS[@]} ))]}
            afl_opts="-p $sched"
            if [ -n "$fmt" ]; then
                afl_opts="$afl_opts $fmt"
            fi
            if [ "$idx" -eq 0 ]; then
                afl_opts="$afl_opts -L 0"
            elif [ "$idx" -eq 1 ]; then
                afl_opts="$afl_opts -Z"
            else
                strat=${MUTATION_STRATEGIES[$(( idx % ${#MUTATION_STRATEGIES[@]} ))]}
                if [ -n "$strat" ]; then
                    afl_opts="$afl_opts $strat"
                fi
            fi
            extra_env=""
            if [ $(( idx % 2 )) -eq 0 ]; then
                extra_env="AFL_DISABLE_TRIM=1 "
            fi
            add_diff_worker "$name" "$extra_env" "$afl_opts"
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
