#!/usr/bin/env bash
# Verifies test/fuzz/runtime/grammar.rb and test/fuzz/runtime/grammar_bench.rb:
# 1. Library-mode require safety (no side effects or supervisor startup on require).
# 2. write_atomic_seed atomicity, SHA1 dedup, header separation, and eviction cap.
# 3. prune_synced_seeds / seed_was_read? read cleanup, stranded mtime bumping,
#    and MAX_PENDING_SEEDS eviction.
# 4. build_guarded_evaluators + supervisor crash breadcrumb recovery via
#    FUZZ_GRAMMAR_TEST_CRASH_SIG=ABRT and clean SIGINT shutdown.
# 5. grammar_bench.rb end-to-end smoke execution, JSON schema, and --compare mode.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKDIR="$(mktemp -d /tmp/test-fuzz-grammar.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "[1/5] Checking grammar.rb library require safety..."
ruby -I"$ROOT_DIR/test/fuzz/runtime" -e '
  Dir.chdir(ARGV[0]) do
    require "'"$ROOT_DIR"'/test/fuzz/runtime/grammar"
    raise "unexpected tmp directory created" if Dir.exist?("tmp")
    raise "DEFAULT_HEADER missing" unless defined?(DEFAULT_HEADER) && DEFAULT_HEADER.bytesize == 4
    raise "PrismComposer missing" unless defined?(PrismComposer)
  end
' "$WORKDIR"

echo "[2/5] Checking write_atomic_seed atomicity, SHA1 dedup, and eviction..."
ruby -e '
  require "'"$ROOT_DIR"'/test/fuzz/runtime/grammar"
  root = ARGV[0]
  q = File.join(root, "q")
  s = File.join(root, "s")
  FileUtils.mkdir_p([q, s])
  seen = {}

  raise "expected first write true" unless write_atomic_seed(q, s, DEFAULT_HEADER, "x = 1\n", seen, max_seen_digests: 5)
  raise "expected duplicate false" if write_atomic_seed(q, s, DEFAULT_HEADER, "x = 1\n", seen, max_seen_digests: 5)
  raise "expected header change true" unless write_atomic_seed(q, s, ATTACH_COMMENTS_HEADER, "x = 1\n", seen, max_seen_digests: 5)

  expected_name = Digest::SHA1.hexdigest(DEFAULT_HEADER + "x = 1\n".b)
  expected_path = File.join(q, expected_name)
  raise "missing expected SHA1 seed" unless File.exist?(expected_path)
  raise "corrupt seed bytes" unless File.binread(expected_path) == (DEFAULT_HEADER + "x = 1\n".b)
  raise "leftover staging files" unless Dir.children(s).empty?

  # Trigger max_seen_digests eviction and confirm filesystem dedup still blocks re-writes
  10.times { |i| write_atomic_seed(q, s, DEFAULT_HEADER, "y = #{i}\n", seen, max_seen_digests: 5) }
  raise "seen_digests exceeded cap" if seen.size > 5
  raise "expected on-disk File.exist? dedup after seen clear" if write_atomic_seed(q, s, DEFAULT_HEADER, "x = 1\n", seen, max_seen_digests: 5)
' "$WORKDIR"

echo "[3/5] Checking prune_synced_seeds lifecycle and backpressure..."
ruby -e '
  require "'"$ROOT_DIR"'/test/fuzz/runtime/grammar"
  reset_max_synced_mtime!
  q = File.join(ARGV[0], "prune_q")
  FileUtils.mkdir_p(q)
  now = Time.now

  fresh_unread = File.join(q, "a_fresh_unread")
  recent_read = File.join(q, "b_recent_read")
  old_read = File.join(q, "c_old_read")
  stranded_unread = File.join(q, "d_stranded_unread")
  [fresh_unread, recent_read, old_read, stranded_unread].each { |p| File.binwrite(p, "seed") }

  t_fresh = Time.at(now.to_i)
  File.utime(t_fresh, t_fresh, fresh_unread)
  File.utime(Time.at(now.to_i - 0.5), Time.at(now.to_i - 1), recent_read)
  old_read_mtime = Time.at(now.to_i - 5)
  File.utime(Time.at(now.to_i - 3), old_read_mtime, old_read)
  old_stranded_mtime = Time.at(now.to_i - 10)
  File.utime(old_stranded_mtime, old_stranded_mtime, stranded_unread)

  remaining, pruned = prune_synced_seeds(q, max_pending: 50)
  raise "expected pruned=1 (old_read), got #{pruned}" unless pruned == 1
  raise "expected remaining=3, got #{remaining}" unless remaining == 3
  raise "old_read should be deleted" if File.exist?(old_read)
  raise "fresh_unread should survive" unless File.exist?(fresh_unread)
  raise "recent_read (<2s) should survive" unless File.exist?(recent_read)
  raise "stranded_unread should survive under cap" unless File.exist?(stranded_unread)

  st_bumped = File.stat(stranded_unread)
  raise "stranded_unread atime sentinel not set to 1" unless st_bumped.atime.to_i == 1
  raise "stranded_unread mtime not bumped past @max_synced_mtime" unless st_bumped.mtime.to_i > old_read_mtime.to_i

  # Over-cap stranded eviction check
  File.utime(old_stranded_mtime, old_stranded_mtime, stranded_unread)
  s2 = File.join(q, "e_stranded_2")
  File.binwrite(s2, "seed2")
  File.utime(Time.at(now.to_i - 9), Time.at(now.to_i - 9), s2)
  rem2, pruned2 = prune_synced_seeds(q, max_pending: 2)
  raise "expected excess stranded eviction, got remaining=#{rem2} pruned=#{pruned2}" unless pruned2 >= 1 && rem2 <= 3
' "$WORKDIR"

echo "[4/5] Checking guarded evaluators & supervisor crash recovery..."
ruby -e '
  require "'"$ROOT_DIR"'/test/fuzz/runtime/grammar"
  io = File.open(File.join(ARGV[0], "unit_in_flight"), File::RDWR | File::CREAT | File::BINARY, 0o600)
  io.sync = true
  fit, val, parse_fn = build_guarded_evaluators(io)
  raise "valid code should score >= 1.0" unless fit.call("x = 1 + 2\n") >= 1.0
  raise "invalid code should score < 0.5" unless fit.call("def broken(\n") < 0.5
  raise "validator mismatch" unless val.call("x = 1\n") && !val.call("class =\n")
  raise "parse_fn failed" unless parse_fn.call("x = 1\n")&.success?
  raise "in_flight was not truncated back to 0" unless File.size(io.path) == 0
  io.close
' "$WORKDIR"

SUP_AFL="$WORKDIR/sup/afl"
SUP_SEEDS="$WORKDIR/sup/work/seeds"
RUBY_SRC_ARG=()
FUZZ_GRAMMAR_TEST_CRASH_SIG=ABRT timeout 20 ruby "$ROOT_DIR/test/fuzz/runtime/grammar.rb" "$SUP_AFL" "$SUP_SEEDS" >"$WORKDIR/sup.out" 2>"$WORKDIR/sup.err" &
SUP_PID=$!

deadline=$((SECONDS + 12))
crash_file=""
while [ "$SECONDS" -lt "$deadline" ]; do
    crash_file="$(find "$SUP_AFL/grammar/crashes" -name 'id:000000,sig:06,*' -print -quit 2>/dev/null || true)"
    if [ -n "$crash_file" ] && [ -s "$SUP_AFL/grammar/fuzzer_stats" ] && grep -q '^saved_crashes[[:space:]]*: 1$' "$SUP_AFL/grammar/fuzzer_stats" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$SUP_PID" 2>/dev/null; then
        cat "$WORKDIR/sup.err" >&2 || true
        fail "grammar supervisor exited unexpectedly before crash capture"
    fi
    sleep 0.2
done

kill -INT "$SUP_PID" 2>/dev/null || true
wait "$SUP_PID" || true

[ -n "$crash_file" ] || { cat "$WORKDIR/sup.err" >&2 || true; fail "supervisor did not save FUZZ_GRAMMAR_TEST_CRASH_SIG crash"; }
[ -s "$SUP_AFL/grammar/fuzzer_stats" ] || fail "missing fuzzer_stats after supervisor shutdown"
[ -s "$SUP_AFL/grammar/plot_data" ] || fail "missing plot_data after supervisor shutdown"
[ "$(cat "$SUP_AFL/grammar/cmdline")" = "./build/fuzz.native" ] || fail "unexpected cmdline content"
grep -q '^files_created' "$SUP_AFL/grammar/fuzzer_stats" || fail "fuzzer_stats missing files_created"

ruby -rdigest -e '
  raw = File.binread(ARGV[0])
  expected = ("\x00\x00\x03\x01".b + "def crash_test; end\n".b)
  raise "unexpected crash payload: #{raw.inspect}" unless raw == expected
  seed_name = Digest::SHA1.hexdigest(raw)
  seed_path = File.join(ARGV[1], seed_name)
  raise "crash seed not forwarded to queue_dir (#{seed_path})" unless File.exist?(seed_path)
' "$crash_file" "$SUP_SEEDS"

echo "[5/5] Checking grammar_bench.rb smoke run, JSON output, and --compare..."
BENCH_ARGS=(--epochs 1 --gens 5 --variant-trials 20 --seed 42 --max-seconds 20 --json "$WORKDIR/bench.json")
if [ "${GRAMMAR_TEST_STRICT:-0}" = "1" ]; then
    BENCH_ARGS+=(--strict)
fi
"$ROOT_DIR/test/fuzz/runtime/grammar_bench.rb" "${BENCH_ARGS[@]}" >"$WORKDIR/bench.out"

ruby -rjson -e '
  data = JSON.parse(File.read(ARGV[0]))
  %w[schema_version env regexp_audit literals_and_terminals heredoc_audit variants_audit simulation].each do |k|
    raise "missing key #{k}" unless data.key?(k)
  end
  sim = data.fetch("simulation")
  raise "expected 5 generations completed, got #{sim["generations_completed"]}" unless sim["generations_completed"] == 5
  raise "expected positive attempts_per_sec" unless sim.dig("throughput", "attempts_per_sec").to_f > 0
  raise "expected non-empty rule coverage" unless sim.dig("coverage", "peak_combined_used").to_i > 0
' "$WORKDIR/bench.json"

"$ROOT_DIR/test/fuzz/runtime/grammar_bench.rb" --epochs 1 --gens 2 --variant-trials 10 --seed 42 --max-seconds 20 --json "$WORKDIR/bench.json" --compare "$WORKDIR/bench.json" >"$WORKDIR/bench_cmp.out"
grep -q "=== Baseline Comparison ===" "$WORKDIR/bench_cmp.out" || fail "missing comparison table in grammar_bench output"

echo "ALL GRAMMAR FRAMEWORK TESTS PASSED"
