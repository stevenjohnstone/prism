#!/bin/bash -e

if [ -n "$LLVM_VERSION" ] && [ -d "/usr/lib/llvm-${LLVM_VERSION}/bin" ]; then
  export PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:${PATH}"
fi

REPO_ROOT="$(pwd)"
mkdir -p build tmp/fuzz

WORK_DIR=$(mktemp -d)
ORIGINS_DIR="$WORK_DIR/origins"
ORIGINS_META="$WORK_DIR/origins.json"
COVERAGE_TMP_BIN="build/.fuzz.coverage.tmp.$$"
FINAL_COVERAGE_DIR="tmp/fuzz/coverage"
COVERAGE_DIR="tmp/fuzz/.coverage.tmp.$$"
OLD_COVERAGE_DIR="tmp/fuzz/.coverage.old.$$"

cleanup_coverage() {
  local rc=$?
  if [ ! -e "$FINAL_COVERAGE_DIR" ] && [ -d "$OLD_COVERAGE_DIR" ]; then
    mv "$OLD_COVERAGE_DIR" "$FINAL_COVERAGE_DIR" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR" "$COVERAGE_TMP_BIN" "$COVERAGE_DIR" "$OLD_COVERAGE_DIR"
  exit "$rc"
}
trap cleanup_coverage EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Verify that a coverage binary is non-empty, runnable on /dev/null, and emits
# profile data (rejecting 0-byte truncated files and un-instrumented binaries).
smoke_check_coverage_bin() {
  local bin="$1"
  local smoke_prof="$WORK_DIR/smoke.profraw"
  rm -f "$smoke_prof"
  if [ -s "$bin" ] && LLVM_PROFILE_FILE="$smoke_prof" "$bin" /dev/null >/dev/null 2>&1 && [ -s "$smoke_prof" ]; then
    rm -f "$smoke_prof"
    return 0
  fi
  rm -f "$smoke_prof"
  return 1
}

read -r -a extra_flags <<< "$FUZZ_FLAGS"
FLAGS_STAMP="build/.fuzz.coverage.flags"
NEED_BUILD=0

if [ ! -f "$FLAGS_STAMP" ]; then
  NEED_BUILD=1
elif [ "$(cat "$FLAGS_STAMP" 2>/dev/null)" != "$FUZZ_FLAGS" ]; then
  NEED_BUILD=1
elif [ ! -s build/fuzz.coverage ] || [ -n "$(find src include test/fuzz/harness -type f -newer build/fuzz.coverage -print -quit 2>/dev/null)" ]; then
  NEED_BUILD=1
elif ! smoke_check_coverage_bin ./build/fuzz.coverage; then
  echo "Existing build/fuzz.coverage failed smoke check; rebuilding..."
  NEED_BUILD=1
fi

if [ "$NEED_BUILD" -eq 1 ]; then
  src_files=()
  while IFS= read -r -d '' file; do
    src_files+=("$file")
  done < <(find src -name '*.c' -print0)

  reach_bin="$WORK_DIR/fuzz.reach"
  keeplist="$WORK_DIR/keeplist"

  echo "Building reachability binary..."
  clang -O0 -Iinclude -DSLOW -flto -ffunction-sections -fdata-sections "${extra_flags[@]}" -Wl,--gc-sections \
    "${src_files[@]}" test/fuzz/harness/coverage.c test/fuzz/harness/parse.c -o "$reach_bin"

  # Keep reachable static (t) and global (T) functions; exclude harness entrypoints.
  llvm-nm --defined-only "$reach_bin" | grep " [Tt] " | grep -Ev '[Tt] (main|run_file|run_stdin|setup_signal_handlers|handle_crash_signal|harness|harness_parse|check_node_location)$' | awk '{print $3}' | sed 's/^/fun:/' > "$keeplist"
  rm -f "$reach_bin"

  echo "Building coverage-instrumented binary..."
  # Map REPO_ROOT (/prism in Docker) to '.' so exported LCOV/profdata paths are
  # workspace-relative (e.g. SF:src/prism.c) and work directly in host IDEs.
  rm -f "$COVERAGE_TMP_BIN"
  clang -O1 -Iinclude -DSLOW -DPROFILE "${extra_flags[@]}" \
    -fcoverage-prefix-map="${REPO_ROOT}=." \
    -fprofile-instr-generate -fcoverage-mapping \
    -fprofile-list="$keeplist" \
    "${src_files[@]}" test/fuzz/harness/coverage.c test/fuzz/harness/parse.c -o "$COVERAGE_TMP_BIN"

  rm -f "$keeplist"
  if ! smoke_check_coverage_bin "$COVERAGE_TMP_BIN"; then
    echo "Error: newly built coverage binary failed smoke check." >&2
    exit 1
  fi
  mv -f "$COVERAGE_TMP_BIN" build/fuzz.coverage
  printf '%s' "$FUZZ_FLAGS" > "$FLAGS_STAMP"
else
  echo "Using existing coverage-instrumented binary (build/fuzz.coverage)..."
fi

REPORT_DIR="$COVERAGE_DIR/report"
WORKERS_DIR="$COVERAGE_DIR/workers"
PROFDATA_FILE="$COVERAGE_DIR/coverage.profdata"
LCOV_FILE="$COVERAGE_DIR/lcov.info"
SUMMARY_FILE="$COVERAGE_DIR/summary.txt"
JSON_FILE="$COVERAGE_DIR/coverage.json"

if [ -n "${FUZZ_LIVE_SEEDS_TAR:-}" ]; then
  if [ -s "$FUZZ_LIVE_SEEDS_TAR" ]; then
    mkdir -p /tmp/afl-tmpdir/grammar/seeds
    tar -C /tmp/afl-tmpdir/grammar/seeds -xf "$FUZZ_LIVE_SEEDS_TAR" 2>/dev/null || rm -rf /tmp/afl-tmpdir/grammar/seeds
  fi
  rm -f "$FUZZ_LIVE_SEEDS_TAR"
fi

JOBS=$(nproc 2>/dev/null || echo 4)
rm -rf "$COVERAGE_DIR"
mkdir -p "$ORIGINS_DIR" "$COVERAGE_DIR" "$WORKERS_DIR"

# Partition all inputs across tmp/fuzz/afl by their root origin:
# - "corpus":  initial seed corpus inputs (,orig:)
# - "grammar": grammar-generated seeds imported via -F (,sync:seeds / ,sync:grammar),
#              crashes caught in tmp/fuzz/afl/grammar/crashes, and up to 5,000 live
#              pending seeds in /tmp/afl-tmpdir/grammar/seeds if present
# - "<worker>": self-originated queue/crash/hang inputs discovered by that fuzzer worker
#               (including synced copies in other queues traced back to their root worker)
ruby -rdigest -rjson -rfileutils -e '
  origins_dir = ARGV[0]
  meta_path = ARGV[1]

  def normalize_source(src)
    return "grammar" if src =~ /\A(?:grammar|seeds)(?:_\d+)?\z/
    return "ijon" if src =~ /\Aijon(?:_\d+|_peer)?\z/
    src
  end

  worker_dirs = []
  seen_workers = {}
  ["tmp/fuzz/afl", "tmp/fuzz/afl-ijon"].each do |root|
    next unless Dir.exist?(root)
    Dir.glob(File.join(root, "*")).sort.each do |d|
      w = File.basename(d)
      next if w.start_with?(".") || !File.directory?(d) || File.symlink?(File.join(d, "queue")) || seen_workers[w]
      seen_workers[w] = d
      worker_dirs << d
    end
  end
  worker_names = worker_dirs.map { |d| File.basename(d) }

  # 1. Index all queue entries by [worker, id] so transitive sync:<peer>,src:<id>
  #    chains can be resolved back to their root origin.
  parent_map = {}
  kind_map = {}
  path_map = {}

  worker_dirs.each do |d|
    w = File.basename(d)
    q_dir = File.join(d, "queue")
    next unless Dir.exist?(q_dir)

    Dir.children(q_dir).each do |fname|
      id = fname[/\Aid:(\d+),/, 1]&.to_i
      next unless id
      full = File.join(q_dir, fname)
      next unless File.file?(full)

      key = [w, id]
      path_map[key] = full

      if fname =~ /\Aid:\d+,sync:([^,]+),src:(?:id:)?(\d+)/
        src_w = normalize_source($1)
        src_id = $2.to_i
        if src_w == "grammar"
          kind_map[key] = "grammar"
        else
          kind_map[key] = :sync
          parent_map[key] = [src_w, src_id]
        end
      elsif fname =~ /\Aid:\d+,sync:([^,]+)/
        src_w = normalize_source($1)
        kind_map[key] = src_w == "grammar" ? "grammar" : src_w
      elsif fname =~ /\Aid:\d+(?:,time:\d+,execs:\d+)?,orig:/
        kind_map[key] = "corpus"
      else
        kind_map[key] = w
      end
    end
  end

  root_cache = {}
  resolve_root = lambda do |key|
    return root_cache[key] if root_cache.key?(key)
    visited = {}
    curr = key
    root = nil
    while curr
      if root_cache.key?(curr)
        root = root_cache[curr]
        break
      end
      if visited[curr]
        root = curr[0]
        break
      end
      visited[curr] = true
      k = kind_map[curr]
      if k.nil?
        root = curr[0]
        break
      elsif k != :sync
        root = k
        break
      else
        curr = parent_map[curr]
      end
    end
    root ||= key[0]
    visited.each_key { |v| root_cache[v] = root }
    root
  end

  buckets = Hash.new { |h, k| h[k] = { queue: [], crash: [], seen: {}, imported_seeds: 0, pending_seeds: 0 } }

  # Ensure "corpus" and all discovered worker directories have entries
  buckets["corpus"]
  worker_names.each { |w| buckets[w] }

  # 2. First pass: attribute non-synced files in each queue so canonical copies win deduplication
  path_map.keys.sort.each do |key|
    next if kind_map[key] == :sync
    full = path_map[key]
    origin = resolve_root.call(key)
    digest = Digest::SHA256.file(full).digest rescue next
    b = buckets[origin]
    next if b[:seen][digest]
    b[:seen][digest] = true
    b[:queue] << full
    b[:imported_seeds] += 1 if origin == "grammar"
  end

  # 3. Second pass: attribute synced files whose content differs (e.g. due to in-place trimming)
  path_map.keys.sort.each do |key|
    next unless kind_map[key] == :sync
    full = path_map[key]
    origin = resolve_root.call(key)
    digest = Digest::SHA256.file(full).digest rescue next
    b = buckets[origin]
    next if b[:seen][digest]
    b[:seen][digest] = true
    b[:queue] << full
    b[:imported_seeds] += 1 if origin == "grammar"
  end

  # 4. Attribute crashes and hangs to their worker directory
  worker_dirs.each do |d|
    w = File.basename(d)
    Dir.glob(File.join(d, "{crashes,hangs}/id*")).sort.each do |full|
      next unless File.file?(full)
      next if full.end_with?(".bt", ".min", ".md")
      digest = Digest::SHA256.file(full).digest rescue next
      b = buckets[w]
      next if b[:seen][digest]
      b[:seen][digest] = true
      b[:crash] << full
    end
  end

  # 5. If /tmp/afl-tmpdir/grammar/seeds (live snapshot / container) or tmp/fuzz/seeds
  #    (saved on exit) has pending seeds, sample up to 5,000 into origins_dir so
  #    concurrently starting/stopping a fuzz run neither alters seed atimes nor
  #    removes files while batches are executing.
  live_seeds_dir = ["/tmp/afl-tmpdir/grammar/seeds", "tmp/fuzz/seeds"].find do |d|
    Dir.exist?(d) && Dir.children(d).any? { |f| !f.start_with?(".") }
  end
  if live_seeds_dir
    b = buckets["grammar"]
    staged_seeds_dir = File.join(origins_dir, "_pending_seeds")
    FileUtils.mkdir_p(staged_seeds_dir)
    rd_flags = File::RDONLY | (defined?(File::NOATIME) ? File::NOATIME : 0)
    pending_paths = Dir.children(live_seeds_dir)
      .reject { |f| f.start_with?(".") }
      .sort
      .first(5000)
      .map { |f| File.join(live_seeds_dir, f) }
    pending_paths.each_with_index do |full, idx|
      next unless File.file?(full)
      data = (File.open(full, rd_flags, &:read) rescue File.binread(full)) rescue next
      digest = Digest::SHA256.digest(data)
      next if b[:seen][digest]
      b[:seen][digest] = true
      staged = File.join(staged_seeds_dir, "#{idx}_#{File.basename(full)}")
      File.binwrite(staged, data)
      b[:queue] << staged
      b[:pending_seeds] += 1
    end
  end

  # Sort origins in canonical display order: corpus, grammar, main, msan, ijon, main-2..N
  priority = { "corpus" => 0, "grammar" => 1, "main" => 2, "msan" => 3, "ijon" => 4 }
  sorted_origins = buckets.keys.sort_by do |name|
    if priority.key?(name)
      [0, priority[name], 0, name]
    elsif name =~ /\Amain-(\d+)\z/
      [1, $1.to_i, 0, name]
    else
      [2, 0, 0, name]
    end
  end

  meta_list = []
  total_unique = 0

  sorted_origins.each do |origin|
    b = buckets[origin]
    total_count = b[:queue].size + b[:crash].size
    next if total_count == 0 && !worker_names.include?(origin)

    odir = File.join(origins_dir, origin)
    FileUtils.mkdir_p(odir)
    File.open(File.join(odir, "queue.list"), "wb") do |f|
      b[:queue].each { |p| f.write(p); f.write("\0") }
    end
    File.open(File.join(odir, "crash.list"), "wb") do |f|
      b[:crash].each { |p| f.write(p); f.write("\0") }
    end

    w_stats = seen_workers[origin] && File.join(seen_workers[origin], "fuzzer_stats")
    kind = if origin == "corpus"
             "corpus"
           elsif origin == "grammar" || (w_stats && File.exist?(w_stats) && File.read(w_stats).include?("generator"))
             "generator"
           else
             "fuzzer"
           end

    total_unique += total_count
    meta_list << {
      "name" => origin,
      "kind" => kind,
      "queue_count" => b[:queue].size,
      "crash_count" => b[:crash].size,
      "input_count" => total_count,
      "imported_seeds_count" => b[:imported_seeds],
      "pending_seeds_count" => b[:pending_seeds]
    }
  end

  File.write(meta_path, JSON.pretty_generate(meta_list))
  puts "Partitioned #{total_unique} inputs across #{meta_list.size} origins."
' "$ORIGINS_DIR" "$ORIGINS_META"

TOTAL_INPUTS=$(ruby -rjson -e 'puts JSON.parse(File.read(ARGV[0])).sum { |o| o["input_count"] }' "$ORIGINS_META")
if [ "$TOTAL_INPUTS" -eq 0 ]; then
  echo "No fuzz inputs found in tmp/fuzz/afl. Run 'make fuzz-run' first." >&2
  exit 1
fi

run_queue_batch() {
  if ! timeout -k 1s 15s ./build/fuzz.coverage "$@" 2>/dev/null; then
    for f in "$@"; do
      timeout -k 1s 0.2s ./build/fuzz.coverage "$f" 2>/dev/null || true
    done
  fi
}
export -f run_queue_batch

ORIGINS=$(ruby -rjson -e 'JSON.parse(File.read(ARGV[0])).each { |o| puts o["name"] if o["input_count"] > 0 }' "$ORIGINS_META")

for origin in $ORIGINS; do
  O_WORK="$ORIGINS_DIR/$origin"
  O_PROFRAW="$O_WORK/profraw"
  O_OUT="$WORKERS_DIR/$origin"
  mkdir -p "$O_PROFRAW" "$O_OUT"

  export LLVM_PROFILE_FILE="$O_PROFRAW/coverage-%${JOBS}m.profraw"
  Q_LIST="$O_WORK/queue.list"
  C_LIST="$O_WORK/crash.list"

  echo "Running inputs for origin '${origin}' (${JOBS} parallel workers)..."
  if [ -s "$Q_LIST" ]; then
    xargs -0 -P "$JOBS" -n 256 bash -c 'run_queue_batch "$@"' _ < "$Q_LIST"
  fi
  if [ -s "$C_LIST" ]; then
    xargs -0 -P "$JOBS" -n 1 bash -c 'timeout -k 1s 0.2s ./build/fuzz.coverage "$1" 2>/dev/null || true' _ < "$C_LIST"
  fi

  O_FILELIST="$O_WORK/profraw.list"
  find "$O_PROFRAW" -name "coverage-*.profraw" -print > "$O_FILELIST"
  if [ -s "$O_FILELIST" ]; then
    llvm-profdata merge -sparse -f "$O_FILELIST" -o "$O_OUT/coverage.profdata"
    rm -rf "$O_PROFRAW"
  fi
done

ALL_PROFDATA=()
while IFS= read -r -d '' pf; do
  ALL_PROFDATA+=("$pf")
done < <(find "$WORKERS_DIR" -name "coverage.profdata" -print0)

if [ "${#ALL_PROFDATA[@]}" -eq 0 ]; then
  echo "Error: no coverage profile data was produced." >&2
  exit 1
fi

echo "Merging per-worker profiles into combined coverage.profdata..."
llvm-profdata merge -sparse "${ALL_PROFDATA[@]}" -o "$PROFDATA_FILE"

IGNORE_REGEX='^test/fuzz/'
export IGNORE_REGEX COVERAGE_DIR WORKERS_DIR PROFDATA_FILE ORIGINS_DIR

process_origin_reports() {
  local origin="$1"
  local o_out="$WORKERS_DIR/$origin"
  local o_work="$ORIGINS_DIR/$origin"
  local pf="$o_out/coverage.profdata"
  [ -f "$pf" ] || return 0

  # 1. Standalone summary JSON, text summary, and HTML report
  llvm-cov export ./build/fuzz.coverage \
    -instr-profile="$pf" \
    --summary-only \
    --ignore-filename-regex="$IGNORE_REGEX" \
    > "$o_work/standalone.json"

  llvm-cov report ./build/fuzz.coverage \
    -instr-profile="$pf" \
    --ignore-filename-regex="$IGNORE_REGEX" \
    > "$o_out/summary.txt"

  llvm-cov show ./build/fuzz.coverage \
    -instr-profile="$pf" \
    --format=html \
    --show-branches=count \
    --show-line-counts-or-regions \
    --ignore-filename-regex="$IGNORE_REGEX" \
    -o "$o_out/report"

  # 2. Marginal coverage over initial corpus (merge(corpus, origin))
  local corpus_pf="$WORKERS_DIR/corpus/coverage.profdata"
  if [ "$origin" != "corpus" ] && [ -f "$corpus_pf" ]; then
    llvm-profdata merge -sparse "$corpus_pf" "$pf" -o "$o_work/with_corpus.profdata"
    llvm-cov export ./build/fuzz.coverage \
      -instr-profile="$o_work/with_corpus.profdata" \
      --summary-only \
      --ignore-filename-regex="$IGNORE_REGEX" \
      > "$o_work/with_corpus.json"
    rm -f "$o_work/with_corpus.profdata"
  fi

  # 3. Leave-one-out profile (merge of all other origins) to measure exclusive coverage
  local others=()
  for other_pf in "$WORKERS_DIR"/*/coverage.profdata; do
    [ "$other_pf" = "$pf" ] && continue
    [ -f "$other_pf" ] && others+=("$other_pf")
  done
  if [ "${#others[@]}" -gt 0 ]; then
    llvm-profdata merge -sparse "${others[@]}" -o "$o_work/without.profdata"
    llvm-cov export ./build/fuzz.coverage \
      -instr-profile="$o_work/without.profdata" \
      --summary-only \
      --ignore-filename-regex="$IGNORE_REGEX" \
      > "$o_work/without.json"
    llvm-cov export ./build/fuzz.coverage \
      -instr-profile="$o_work/without.profdata" \
      --format=lcov \
      --ignore-filename-regex="$IGNORE_REGEX" \
      > "$o_work/without.lcov"
  fi
}
export -f process_origin_reports

echo "Generating per-worker and combined LCOV/HTML/JSON reports..."
printf '%s\0' $ORIGINS | xargs -0 -P "$JOBS" -n 1 bash -c 'process_origin_reports "$1"' _

llvm-cov export ./build/fuzz.coverage \
  -instr-profile="$PROFDATA_FILE" \
  --format=lcov \
  --ignore-filename-regex="$IGNORE_REGEX" \
  > "$LCOV_FILE"

llvm-cov export ./build/fuzz.coverage \
  -instr-profile="$PROFDATA_FILE" \
  --summary-only \
  --ignore-filename-regex="$IGNORE_REGEX" \
  > "$WORK_DIR/combined.json"

llvm-cov show ./build/fuzz.coverage \
  -instr-profile="$PROFDATA_FILE" \
  --format=html \
  --show-branches=count \
  --show-line-counts-or-regions \
  --ignore-filename-regex="$IGNORE_REGEX" \
  -o "$REPORT_DIR"

llvm-cov report ./build/fuzz.coverage \
  -instr-profile="$PROFDATA_FILE" \
  --ignore-filename-regex="$IGNORE_REGEX" \
  | tee "$SUMMARY_FILE"

# Assemble tmp/fuzz/coverage/coverage.json for plot.rb and external tooling
ruby -retc -rjson -rtime -e '
  work_dir, origins_meta_path, out_json_path, lcov_path, coverage_dir, profdata_path, ignore_regex = ARGV
  origins_meta = JSON.parse(File.read(origins_meta_path))
  combined_raw = JSON.parse(File.read(File.join(work_dir, "combined.json"))).dig("data", 0) || {}

  METRICS = %w[lines functions instantiations regions branches].freeze
  C_KEYWORDS = %w[if for while switch return sizeof].freeze
  C_RETURN_TYPE_LINE_RE = /\A(?:static|inline|extern|const|struct|enum|union|PRISM_\w+|[a-zA-Z_]\w*)[\w\s\*]*\z/

  def run_parallel_map(items, max_workers = [Etc.nprocessors, 1].max)
    return [] if items.empty?
    return items.map { |item| yield(item) } if items.size == 1 || max_workers <= 1

    results = Array.new(items.size)
    queue = Queue.new
    items.each_with_index { |item, idx| queue << [item, idx] }
    workers = [max_workers, items.size].min.times.map do
      Thread.new do
        while (pair = queue.pop(true) rescue nil)
          item, idx = pair
          results[idx] = yield(item)
        end
      end
    end
    workers.each(&:join)
    results
  end

  def parse_lcov(path)
    lines = Hash.new { |h, k| h[k] = {} }
    branches = Hash.new { |h, k| h[k] = {} }
    return [lines, branches] unless path && File.exist?(path)

    cur = nil
    File.foreach(path) do |line|
      line.chomp!
      if line.start_with?("SF:")
        cur = line[3..].sub(%r{\A\./}, "")
      elsif cur && line.start_with?("DA:")
        ln, cnt = line[3..].split(",")
        lines[cur][ln.to_i] = cnt.to_i
      elsif cur && line.start_with?("BRDA:")
        ln, blk, br, cnt = line[5..].split(",")
        branches[cur][[ln.to_i, blk, br]] = (cnt == "-" ? 0 : cnt.to_i)
      end
    end
    [lines, branches]
  end

  SOURCE_CACHE = {}
  def read_source_lines(fname)
    SOURCE_CACHE[fname] ||= File.exist?(fname) ? File.readlines(fname, chomp: true) : []
  end

  def export_profile_branches(profdata_file, ignore_regex, only_files = nil)
    return nil unless profdata_file && File.exist?(profdata_file)
    return {} if only_files && only_files.empty?

    cmd = [
      "llvm-cov", "export", "./build/fuzz.coverage",
      "-instr-profile=#{profdata_file}",
      "--skip-functions",
      "--ignore-filename-regex=#{ignore_regex}"
    ]
    if only_files && only_files.any?
      cmd << "--path-equivalence=.,#{Dir.pwd}"
      cmd << "--sources"
      cmd.concat(only_files)
    end
    raw = IO.popen(cmd, &:read)
    return nil if raw.to_s.empty?
    data = JSON.parse(raw)
    res = {}
    (data.dig("data", 0, "files") || []).each do |f|
      fn = f["filename"].to_s.sub(%r{\A\./}, "")
      top = (f["branches"] || []).map do |b|
        { line: b[0], col1: b[1], line2: b[2], col2: b[3], t: b[4], f: b[5] }
      end
      exp = []
      (f["expansions"] || []).each do |e|
        sr = e["source_region"] || []
        fnames = e["filenames"] || []
        (e["branches"] || []).each do |b|
          def_fn = (fnames[b[6]] || fn).to_s.sub(%r{\A\./}, "")
          exp << {
            line: sr[0], col1: sr[1], line2: sr[2], col2: sr[3],
            t: b[4], f: b[5],
            def_file: def_fn, def_line: b[0], def_col1: b[1], def_col2: b[3]
          }
        end
      end
      res[fn] = { top: top, exp: exp }
    end
    res
  rescue StandardError
    nil
  end

  def diff_file_branches(fname, comb_br_file, wo_br_file, comb_brda_file, wo_brda_file)
    by_line = {}
    if comb_br_file && wo_br_file
      lines = read_source_lines(fname)
      macro_defs_covered = {}
      exp_items = []

      (comb_br_file[:exp] || []).each_with_index do |b, i|
        wb = (wo_br_file[:exp] || [])[i]
        next unless wb
        t_ex = b[:t].to_i > 0 && wb[:t].to_i == 0
        f_ex = b[:f].to_i > 0 && wb[:f].to_i == 0
        next unless t_ex || f_ex

        macro_defs_covered[[b[:def_file], b[:def_line], b[:def_col1], b[:def_col2]]] = true
        def_lines = read_source_lines(b[:def_file])
        call_expr = lines[b[:line] - 1] ? lines[b[:line] - 1][(b[:col1] - 1)...(b[:col2] - 1)].to_s.strip : ""
        def_expr = def_lines[b[:def_line] - 1] ? def_lines[b[:def_line] - 1][(b[:def_col1] - 1)...(b[:def_col2] - 1)].to_s.strip : ""

        [[t_ex, "True", b[:t].to_i, b[:f].to_i], [f_ex, "False", b[:f].to_i, b[:t].to_i]].each do |is_ex, label, cnt, other_cnt|
          next unless is_ex
          exp_items << {
            "line" => b[:line],
            "taken" => label,
            "count" => cnt,
            "other_count" => other_cnt,
            "col_start" => b[:col1],
            "col_end" => b[:col2],
            "expr" => call_expr,
            "macro" => true,
            "macro_def" => def_expr
          }
        end
      end

      (comb_br_file[:top] || []).each_with_index do |b, i|
        wb = (wo_br_file[:top] || [])[i]
        next unless wb
        t_ex = b[:t].to_i > 0 && wb[:t].to_i == 0
        f_ex = b[:f].to_i > 0 && wb[:f].to_i == 0
        next unless t_ex || f_ex
        next if macro_defs_covered[[fname, b[:line], b[:col1], b[:col2]]]

        expr = lines[b[:line] - 1] ? lines[b[:line] - 1][(b[:col1] - 1)...(b[:col2] - 1)].to_s.strip : ""
        [[t_ex, "True", b[:t].to_i, b[:f].to_i], [f_ex, "False", b[:f].to_i, b[:t].to_i]].each do |is_ex, label, cnt, other_cnt|
          next unless is_ex
          (by_line[b[:line]] ||= []) << {
            "line" => b[:line],
            "taken" => label,
            "count" => cnt,
            "other_count" => other_cnt,
            "col_start" => b[:col1],
            "col_end" => b[:col2],
            "expr" => expr,
            "macro" => false,
            "macro_def" => nil
          }
        end
      end

      exp_items.each do |item|
        (by_line[item["line"]] ||= []) << item
      end
    elsif comb_brda_file && wo_brda_file
      comb_brda_file.each do |(ln, blk, br), cnt|
        next unless cnt > 0 && wo_brda_file[[ln, blk, br]].to_i == 0
        taken = br.to_i.even? ? "True" : "False"
        (by_line[ln] ||= []) << {
          "line" => ln,
          "taken" => taken,
          "count" => cnt,
          "other_count" => nil,
          "col_start" => nil,
          "col_end" => nil,
          "expr" => nil,
          "macro" => false,
          "macro_def" => nil
        }
      end
    end
    by_line
  end

  def find_enclosing_function(src_lines, line_no)
    idx = [line_no - 1, src_lines.size - 1].min
    idx.downto(0) do |i|
      ln = src_lines[i].to_s
      if ln =~ /\A(?:static\s+|inline\s+|extern\s+|const\s+|struct\s+|enum\s+|union\s+|\w+\s+\**\s*)+([a-zA-Z_]\w*)\s*\([^;]*\z/
        fn = $1
        return fn unless C_KEYWORDS.include?(fn)
      elsif i > 0 && ln =~ /\A([a-zA-Z_]\w*)\s*\([^;]*\z/
        fn = $1
        return fn if !C_KEYWORDS.include?(fn) && src_lines[i - 1].to_s.strip =~ C_RETURN_TYPE_LINE_RE
      elsif i > 0 && ln.start_with?("{") && src_lines[i - 1].to_s =~ /\A([a-zA-Z_]\w*)\s*\(/
        return $1
      end
    end
    nil
  end

  def build_exclusive_hunks(fname, excl_line_counts, excl_branch_details)
    target_lines = (excl_line_counts.keys | excl_branch_details.keys).sort
    return [] if target_lines.empty?

    src_lines = read_source_lines(fname)
    return [] if src_lines.empty?

    max_line = src_lines.size
    ranges = []
    target_lines.each do |ln|
      s = [ln - 2, 1].max
      e = [ln + 2, max_line].min
      if ranges.any? && s <= ranges.last[1] + 2
        ranges.last[1] = [ranges.last[1], e].max
      else
        ranges << [s, e]
      end
    end

    ranges.map do |s, e|
      fn_name = find_enclosing_function(src_lines, s)
      first_hit = target_lines.find { |ln| ln >= s && ln <= e } || s
      rows = (s..e).map do |ln|
        l_cnt = excl_line_counts[ln]
        b_list = excl_branch_details[ln]
        b_list = nil if b_list && b_list.empty?
        kind = if l_cnt && b_list
                 "both"
               elsif l_cnt
                 "line"
               elsif b_list
                 "branch"
               else
                 "context"
               end
        {
          "line" => ln,
          "kind" => kind,
          "line_count" => l_cnt,
          "branch_hits" => b_list ? b_list.size : 0,
          "branch_count" => b_list ? b_list.sum { |b| b["count"].to_i } : 0,
          "branches" => b_list || [],
          "code" => src_lines[ln - 1].to_s
        }
      end
      {
        "start_line" => s,
        "end_line" => e,
        "anchor_line" => first_hit,
        "function" => fn_name,
        "lines" => rows
      }
    end
  end

  def annotate_llvm_cov_html(html_path, origin_label, excl_line_counts, excl_branch_details)
    return unless File.exist?(html_path)
    targets = (excl_line_counts.keys | excl_branch_details.keys).sort
    return if targets.empty?

    html = File.read(html_path)
    # Strip any older injection if re-running
    html.gsub!(/<style>\s*tr\.exclusive-row.*?<\/script>\s*/m, "")
    html.gsub!(/, <a href=\x27javascript:next_exclusive\(\)\x27.*?<\/a>/, "")
    html.gsub!(/ <span class=\x27excl-inline-tag[^\x27]*\x27>.*?<\/span>/, "")
    html.gsub!(/<tr class=\x27exclusive-(?:branch-)?row\x27>/, "<tr>")

    style_and_js = <<~INJECT
      <style>
        tr.exclusive-row td { background: rgba(16, 185, 129, 0.14) !important; }
        tr.exclusive-row td.line-number { border-left: 4px solid #10b981 !important; font-weight: 700; }
        tr.exclusive-branch-row td { background: rgba(56, 189, 248, 0.12) !important; }
        tr.exclusive-branch-row td.line-number { border-left: 4px solid #38bdf8 !important; font-weight: 700; }
        .excl-inline-tag {
          display: inline-block;
          margin-left: 10px;
          padding: 1px 7px;
          border-radius: 999px;
          font-family: -apple-system, BlinkMacSystemFont, sans-serif;
          font-size: 11px;
          font-weight: 700;
          background: #065f46;
          color: #ecfdf5;
          vertical-align: middle;
        }
        .excl-inline-tag.branch-only {
          background: #075985;
          color: #e0f2fe;
        }
      </style>
      <script>
        var exclusive_anchors = #{JSON.generate(targets.map { |ln| "L#{ln}" })};
        var exclusive_idx = -1;
        function next_exclusive() {
          if (!exclusive_anchors.length) return;
          exclusive_idx = (exclusive_idx + 1) % exclusive_anchors.length;
          window.location.hash = "#" + exclusive_anchors[exclusive_idx];
        }
        document.addEventListener("keydown", function(e) {
          if (e.target && (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA")) return;
          if (e.key === "e" || e.key === "E") { next_exclusive(); }
        });
      </script>
    INJECT

    html.sub!("</head>", "#{style_and_js}</head>")
    html.sub!(
      "next uncovered branch (B)</a>",
      "next uncovered branch (B)</a>, <a href=\x27javascript:next_exclusive()\x27 style=\x27font-weight:bold;color:#059669\x27>next exclusive to #{origin_label} (E) [#{targets.size}]</a>"
    )

    targets.each do |ln|
      is_line = excl_line_counts.key?(ln)
      b_hits = excl_branch_details[ln]
      row_cls = is_line ? "exclusive-row" : "exclusive-branch-row"
      tag_cls = is_line ? "excl-inline-tag" : "excl-inline-tag branch-only"
      parts = []
      parts << "LINE (#{excl_line_counts[ln]}x)" if is_line
      if b_hits && b_hits.any?
        b_strs = b_hits.map do |b|
          if b["macro"] && b["macro_def"].to_s != ""
            "#{b["macro_def"]} \u2192 #{b["taken"]} (#{b["count"]}x)"
          elsif b_hits.size > 1 && b["expr"].to_s != ""
            "#{b["expr"]} \u2192 #{b["taken"]} (#{b["count"]}x)"
          else
            "#{b["taken"]} (#{b["count"]}x)"
          end
        end
        parts << "BR: #{b_strs.join(", ")}"
      end
      joined_parts = parts.join(" + ").gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;")
      badge = "<span class=\x27#{tag_cls}\x27>\u2605 #{origin_label}: #{joined_parts}</span>"

      html.sub!(
        /<tr>(<td class=\x27line-number\x27><a name=\x27L#{ln}\x27 href=\x27#L#{ln}\x27><pre>\s*#{ln}<\/pre><\/a><\/td><td class=\x27[^\x27]*?\x27>(?:<pre>.*?<\/pre>)?<\/td><td class=\x27code\x27><pre>)(.*?)<\/pre>/m
      ) do
        "<tr class=\x27#{row_cls}\x27>#{$1}#{$2} #{badge}</pre>"
      end
    end

    File.write(html_path, html)
  rescue StandardError
    # ignore annotation errors
  end

  def extract_summary(summary_hash)
    return {} unless summary_hash
    out = {}
    METRICS.each do |m|
      next unless summary_hash[m]
      out[m] = {
        "count" => summary_hash[m]["count"].to_i,
        "covered" => summary_hash[m]["covered"].to_i,
        "percent" => summary_hash[m]["percent"].to_f.round(2)
      }
    end
    out
  end

  def extract_files_map(data_hash)
    map = {}
    (data_hash["files"] || []).each do |f|
      fname = f["filename"].to_s.sub(%r{\A\./}, "")
      map[fname] = extract_summary(f["summary"])
    end
    map
  end

  def diff_summaries(upper, lower)
    return {} unless upper && lower
    out = {}
    METRICS.each do |m|
      next unless upper[m] && lower[m]
      diff = [upper[m]["covered"].to_i - lower[m]["covered"].to_i, 0].max
      total = upper[m]["count"].to_i
      pct = total > 0 ? (diff * 100.0 / total).round(2) : 0.0
      out[m] = { "covered" => diff, "percent" => pct }
    end
    out
  end

  comb_da, comb_brda = parse_lcov(lcov_path)
  combined_totals = extract_summary(combined_raw["totals"])
  combined_files = extract_files_map(combined_raw)

  corpus_standalone_path = File.join(work_dir, "origins", "corpus", "standalone.json")
  corpus_raw = File.exist?(corpus_standalone_path) ? (JSON.parse(File.read(corpus_standalone_path)).dig("data", 0) || {}) : nil
  corpus_totals = corpus_raw ? extract_summary(corpus_raw["totals"]) : nil
  corpus_files = corpus_raw ? extract_files_map(corpus_raw) : {}

  prepared_origins = origins_meta.map do |meta|
    name = meta["name"]
    o_work = File.join(work_dir, "origins", name)
    st_path = File.join(o_work, "standalone.json")
    wc_path = File.join(o_work, "with_corpus.json")
    wo_path = File.join(o_work, "without.json")
    wo_lcov_path = File.join(o_work, "without.lcov")
    wo_pf_path = File.join(o_work, "without.profdata")

    next { meta: meta, present: false } unless File.exist?(st_path)

    st_raw = JSON.parse(File.read(st_path)).dig("data", 0) || {}
    st_totals = extract_summary(st_raw["totals"])
    st_files = extract_files_map(st_raw)

    wc_raw = File.exist?(wc_path) ? (JSON.parse(File.read(wc_path)).dig("data", 0) || {}) : nil
    wc_totals = wc_raw ? extract_summary(wc_raw["totals"]) : nil
    wc_files = wc_raw ? extract_files_map(wc_raw) : {}

    wo_raw = File.exist?(wo_path) ? (JSON.parse(File.read(wo_path)).dig("data", 0) || {}) : nil
    wo_totals = wo_raw ? extract_summary(wo_raw["totals"]) : nil
    wo_files = wo_raw ? extract_files_map(wo_raw) : {}

    vs_corpus = if name == "corpus"
                  {}
                elsif wc_totals && corpus_totals
                  diff_summaries(wc_totals, corpus_totals)
                else
                  {}
                end

    exclusive = if wo_totals
                  diff_summaries(combined_totals, wo_totals)
                else
                  diff_summaries(combined_totals, {})
                end

    excl_branch_files = if exclusive.dig("branches", "covered").to_i > 0 && File.exist?(wo_pf_path)
                          st_files.keys.sort.select do |fname|
                            f_comb = combined_files[fname] || st_files[fname]
                            f_wo = wo_files[fname]
                            f_wo && diff_summaries(f_comb, f_wo).dig("branches", "covered").to_i > 0
                          end
                        else
                          []
                        end

    {
      meta: meta,
      present: true,
      name: name,
      st_totals: st_totals,
      st_files: st_files,
      wc_files: wc_files,
      wo_files: wo_files,
      wo_lcov_path: wo_lcov_path,
      wo_pf_path: wo_pf_path,
      vs_corpus: vs_corpus,
      exclusive: exclusive,
      excl_branch_files: excl_branch_files
    }
  end

  branch_jobs = []
  union_excl_branch_files = prepared_origins.select { |o| o[:present] }.flat_map { |o| o[:excl_branch_files] }.uniq.sort
  if union_excl_branch_files.any?
    branch_jobs << [:combined, profdata_path, union_excl_branch_files]
    prepared_origins.each do |o|
      next unless o[:present] && o[:excl_branch_files].any?
      branch_jobs << [o[:name], o[:wo_pf_path], o[:excl_branch_files]]
    end
  end

  branch_exports = {}
  run_parallel_map(branch_jobs) { |key, pf, files| [key, export_profile_branches(pf, ignore_regex, files)] }.each do |key, res|
    branch_exports[key] = res
  end
  comb_full_branches = branch_exports[:combined]

  origins_out = prepared_origins.map do |o|
    meta = o[:meta]
    if o[:present]
      name = o[:name]
      st_totals = o[:st_totals]
      st_files = o[:st_files]
      wc_files = o[:wc_files]
      wo_files = o[:wo_files]
      wo_lcov_path = o[:wo_lcov_path]
      vs_corpus = o[:vs_corpus]
      exclusive = o[:exclusive]
      wo_da, wo_brda = parse_lcov(wo_lcov_path)
      wo_full_branches = comb_full_branches ? branch_exports[name] : nil

      per_file = st_files.keys.sort.map do |fname|
        f_st = st_files[fname]
        f_comb = combined_files[fname] || f_st
        f_wo = wo_files[fname]
        f_wc = wc_files[fname]
        f_corp = corpus_files[fname]
        ex_diff = f_wo ? diff_summaries(f_comb, f_wo) : {}

        excl_line_counts = {}
        excl_branch_details = {}
        if File.exist?(wo_lcov_path)
          (comb_da[fname] || {}).each do |ln, cnt|
            excl_line_counts[ln] = cnt if cnt > 0 && wo_da[fname][ln].to_i == 0
          end
        end
        if ex_diff.dig("branches", "covered").to_i > 0
          excl_branch_details = diff_file_branches(
            fname,
            comb_full_branches && comb_full_branches[fname],
            wo_full_branches && wo_full_branches[fname],
            comb_brda[fname],
            wo_brda[fname]
          )
        end

        hunks = build_exclusive_hunks(fname, excl_line_counts, excl_branch_details)
        if hunks.any?
          worker_file_html = File.join(coverage_dir, "workers", name, "report", "coverage", "#{fname}.html")
          annotate_llvm_cov_html(worker_file_html, name, excl_line_counts, excl_branch_details)
        end

        {
          "filename" => fname,
          "summary" => f_st,
          "vs_corpus" => (name != "corpus" && f_wc && f_corp) ? diff_summaries(f_wc, f_corp) : {},
          "exclusive" => ex_diff,
          "exclusive_hunks" => hunks
        }
      end

      meta.merge(
        "has_coverage" => true,
        "report_rel_path" => "../coverage/workers/#{name}/report/index.html",
        "summary_rel_path" => "../coverage/workers/#{name}/summary.txt",
        "totals" => st_totals,
        "vs_corpus" => vs_corpus,
        "exclusive" => exclusive,
        "files" => per_file
      )
    else
      meta.merge(
        "has_coverage" => false,
        "report_rel_path" => nil,
        "summary_rel_path" => nil,
        "totals" => {},
        "vs_corpus" => {},
        "exclusive" => {},
        "files" => []
      )
    end
  end

  payload = {
    "generated_at" => Time.now.iso8601,
    "combined" => {
      "input_count" => origins_meta.sum { |m| m["input_count"].to_i },
      "report_rel_path" => "../coverage/report/index.html",
      "lcov_rel_path" => "../coverage/lcov.info",
      "summary_rel_path" => "../coverage/summary.txt",
      "totals" => combined_totals,
      "files" => combined_files.keys.sort.map { |fname| { "filename" => fname, "summary" => combined_files[fname] } }
    },
    "origins" => origins_out
  }

  File.write(out_json_path, JSON.pretty_generate(payload))
' "$WORK_DIR" "$ORIGINS_META" "$JSON_FILE" "$LCOV_FILE" "$COVERAGE_DIR" "$PROFDATA_FILE" "$IGNORE_REGEX"

rm -rf "$OLD_COVERAGE_DIR"
if [ -d "$FINAL_COVERAGE_DIR" ]; then
  mv "$FINAL_COVERAGE_DIR" "$OLD_COVERAGE_DIR"
fi
mv "$COVERAGE_DIR" "$FINAL_COVERAGE_DIR"
rm -rf "$OLD_COVERAGE_DIR"

echo ""
echo "Coverage artifacts written to $FINAL_COVERAGE_DIR:"
echo "  - LCOV (IDE integration): $FINAL_COVERAGE_DIR/lcov.info"
echo "  - Combined HTML report:   $FINAL_COVERAGE_DIR/report/index.html"
echo "  - Per-worker HTML reports:$FINAL_COVERAGE_DIR/workers/<worker>/report/index.html"
echo "  - JSON breakdown:         $FINAL_COVERAGE_DIR/coverage.json"
echo "  - LLVM profdata:          $FINAL_COVERAGE_DIR/coverage.profdata"
echo "  - Text summary:           $FINAL_COVERAGE_DIR/summary.txt"
