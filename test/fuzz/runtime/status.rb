#!/usr/bin/env ruby
# frozen_string_literal: true

afl_dir = ARGV[0] || "./tmp/fuzz/afl"
expected_fuzzers = ARGV[1..] || []

BOLD = "\e[1m"
DIM = "\e[2m"
RED = "\e[31m"
GREEN = "\e[32m"
YELLOW = "\e[33m"
CYAN = "\e[36m"
RESET = "\e[0m"

GRAMMAR_SEEDS_DIR = "/tmp/afl-tmpdir/grammar/seeds"

def format_int(num)
  num.to_i.to_s.reverse.gsub(/(\d{3})(?=\d)/, '\\1,').reverse
end

def format_fit(num, width)
  full = format_int(num)
  return full if full.length <= width

  n = num.to_f
  if n >= 1_000_000_000
    format("%.1fB", n / 1_000_000_000.0)
  elsif n >= 1_000_000
    s = format("%.2fM", n / 1_000_000.0)
    s.length <= width ? s : format("%.1fM", n / 1_000_000.0)
  elsif n >= 1_000
    s = format("%.1fK", n / 1_000.0)
    s.length <= width ? s : format("%dK", (n / 1_000.0).round)
  else
    full
  end
end

def format_rate(rate)
  r = rate.to_f
  if r >= 10.0
    "#{format_int(r.round)}/s"
  else
    format("%.1f/s", r)
  end
end

def format_duration(seconds)
  seconds = seconds.to_i
  return "0s" if seconds <= 0

  hours = seconds / 3600
  mins = (seconds % 3600) / 60
  secs = seconds % 60

  if hours > 0
    format("%dh %02dm %02ds", hours, mins, secs)
  elsif mins > 0
    format("%dm %02ds", mins, secs)
  else
    format("%ds", secs)
  end
end

def normalize_origin(origin)
  return "grammar" if origin =~ /\A(?:grammar|seeds)(?:_\d+)?\z/

  origin
end

def pid_alive?(pid)
  return false if pid <= 0

  Process.kill(0, pid)
  true
rescue Errno::ESRCH
  false
rescue Errno::EPERM
  true
end

def parse_stats_file(path)
  stats = {}
  File.foreach(path) do |line|
    key, val = line.split(":", 2)
    next unless key && val

    stats[key.strip] = val.strip
  end
  stats
rescue StandardError
  {}
end

def compute_contributions(afl_dir)
  origin = Hash.new { |h, k| h[k] = {} }
  sync_items = []
  local_items = []
  grammar_shared_srcs = {}

  Dir.glob(File.join(afl_dir, "*/queue")).each do |qdir|
    fuzzer = File.basename(File.dirname(qdir))
    entries = Dir.children(qdir).sort rescue next
    entries.each do |f|
      id = f[/^id:(\d+)/, 1]
      next unless id

      if f.include?("orig:")
        origin[fuzzer][id] = :seed
      elsif f =~ /sync:([^,]+),src:([^,]+)/
        peer = normalize_origin(Regexp.last_match(1))
        src_ref = Regexp.last_match(2)
        if peer == "grammar"
          origin[fuzzer][id] = "grammar"
          grammar_shared_srcs[src_ref] = true
        else
          origin[fuzzer][id] = peer
          sync_items << [fuzzer, id, peer, src_ref]
        end
      else
        srcs = f[/src:([0-9+]+)/, 1]&.split("+") || []
        origin[fuzzer][id] = fuzzer
        local_items << [fuzzer, id, srcs]
      end
    end
  end

  # Propagate transitive origins across multi-hop syncs (e.g. grammar -> ldet -> main -> main-2)
  3.times do
    sync_items.each do |fuzzer, id, peer, src_ref|
      src_orig = origin[peer][src_ref]
      origin[fuzzer][id] = (src_orig && src_orig != :seed) ? src_orig : peer
    end
    local_items.each do |fuzzer, id, srcs|
      foreign = srcs.filter_map { |s| origin[fuzzer][s] }.reject { |o| o == :seed || o == fuzzer }.uniq
      origin[fuzzer][id] = foreign.first || fuzzer
    end
  end

  shared_ids = Hash.new { |h, k| h[k] = {} }
  sync_items.each do |_fuzzer, _id, peer, src_ref|
    src_orig = origin[peer][src_ref]
    if src_orig.nil? || src_orig == :seed || src_orig == peer
      shared_ids[peer][src_ref] = true
    end
  end

  shared = Hash.new(0)
  shared_ids.each { |peer, ids| shared[peer] = ids.size }
  shared["grammar"] = grammar_shared_srcs.size

  descendants = Hash.new(0)
  local_items.each do |fuzzer, _id, srcs|
    foreign = srcs.filter_map { |s| origin[fuzzer][s] }.reject { |o| o == :seed || o == fuzzer }.uniq
    foreign.each { |o| descendants[o] += 1 }
  end

  { shared: shared, descendants: descendants }
rescue StandardError
  { shared: Hash.new(0), descendants: Hash.new(0) }
end

def collect_fuzzer_rows(afl_dir, expected_fuzzers, started_at, now)
  discovered = Dir.glob(File.join(afl_dir, "*/fuzzer_stats")).map { |p| File.basename(File.dirname(p)) }
  names = (expected_fuzzers + discovered).uniq

  names.map do |name|
    stats_path = File.join(afl_dir, name, "fuzzer_stats")
    if File.exist?(stats_path)
      stats = parse_stats_file(stats_path)
      pid = stats["fuzzer_pid"].to_i
      alive = pid_alive?(pid)
      sched = stats["power_mode"] || stats["command_line"]&.[](/-p\s+(\S+)/, 1) || "fast"
      is_generator = stats["fuzzer_role"] == "generator"
      files_created = (stats["files_created"] || stats["corpus_count"]).to_i
      start_t = stats["start_time"].to_i
      elapsed = start_t > 0 ? [now - start_t, 1].max : [now - started_at, 1].max
      avg_files_rate = if stats["avg_files_per_sec"]
                         stats["avg_files_per_sec"].to_f
                       else
                         files_created.to_f / elapsed
                       end
      files_rate = stats["files_per_sec"] ? stats["files_per_sec"].to_f : avg_files_rate
      {
        name: name,
        role: is_generator ? :generator : :fuzzer,
        state: alive ? :alive : :dead,
        sched: sched,
        execs_per_sec: stats["execs_per_sec"].to_f,
        execs_done: stats["execs_done"].to_i,
        attempts_done: (stats["attempts_done"] || stats["execs_done"]).to_i,
        files_created: files_created,
        pending_files: stats["pending_files"].to_i,
        max_pending_files: (stats["max_pending_files"] || "50000").to_i,
        files_pruned: stats["files_pruned"].to_i,
        duplicates_skipped: stats["duplicates_skipped"].to_i,
        files_per_sec: files_rate,
        avg_files_per_sec: avg_files_rate,
        cycles_done: stats["cycles_done"].to_i,
        corpus_count: stats["corpus_count"].to_i,
        pending_total: stats["pending_total"].to_i,
        pending_favs: stats["pending_favs"].to_i,
        bitmap_cvg: stats["bitmap_cvg"] || "0.00%",
        edges_found: stats["edges_found"].to_i,
        total_edges: stats["total_edges"].to_i,
        saved_crashes: stats["saved_crashes"].to_i,
        saved_hangs: stats["saved_hangs"].to_i,
        last_find: stats["last_find"].to_i,
        start_time: start_t
      }
    elsif name == "grammar" && Dir.exist?(GRAMMAR_SEEDS_DIR)
      pending = Dir.children(GRAMMAR_SEEDS_DIR).count { |f| !f.start_with?(".") } rescue 0
      elapsed = [now - started_at, 1].max
      rate = pending.to_f / elapsed
      {
        name: name,
        role: :generator,
        state: pending > 0 ? :alive : :starting,
        sched: "lrama",
        execs_per_sec: 0.0,
        execs_done: 0,
        attempts_done: pending,
        files_created: pending,
        pending_files: pending,
        max_pending_files: 50_000,
        files_pruned: 0,
        duplicates_skipped: 0,
        files_per_sec: rate,
        avg_files_per_sec: rate,
        cycles_done: 0,
        corpus_count: pending,
        pending_total: 0,
        pending_favs: 0,
        bitmap_cvg: "-",
        edges_found: 0,
        total_edges: 0,
        saved_crashes: 0,
        saved_hangs: 0,
        last_find: pending > 0 ? now : 0,
        start_time: started_at
      }
    else
      {
        name: name,
        role: name == "grammar" ? :generator : :fuzzer,
        state: :starting,
        sched: name == "grammar" ? "lrama" : "-",
        execs_per_sec: 0.0,
        execs_done: 0,
        attempts_done: 0,
        files_created: 0,
        pending_files: 0,
        max_pending_files: 50_000,
        files_pruned: 0,
        duplicates_skipped: 0,
        files_per_sec: 0.0,
        avg_files_per_sec: 0.0,
        cycles_done: 0,
        corpus_count: 0,
        pending_total: 0,
        pending_favs: 0,
        bitmap_cvg: "0.00%",
        edges_found: 0,
        total_edges: 0,
        saved_crashes: 0,
        saved_hangs: 0,
        last_find: 0,
        start_time: 0
      }
    end
  end
end

def state_badge(state, pad = nil)
  label = case state
          when :alive then "RUNNING"
          when :starting then "STARTING"
          else "STOPPED"
          end
  color = case state
          when :alive then GREEN
          when :starting then YELLOW
          else RED
          end
  formatted = pad ? format("%-#{pad}s", label) : label
  "#{color}#{formatted}#{RESET}"
end

def render(afl_dir, expected_fuzzers, started_at, page, contribs)
  now = Time.now.to_i
  rows = collect_fuzzer_rows(afl_dir, expected_fuzzers, started_at, now)
  afl_rows = rows.reject { |r| r[:role] == :generator }
  gen_rows = rows.select { |r| r[:role] == :generator }

  alive_count = afl_rows.count { |r| r[:state] == :alive }
  total_execs_sec = afl_rows.select { |r| r[:state] == :alive }.sum { |r| r[:execs_per_sec] }
  total_execs = afl_rows.sum { |r| r[:execs_done] }
  max_corpus = afl_rows.map { |r| r[:corpus_count] }.max || 0
  max_cvg = afl_rows.map { |r| r[:bitmap_cvg].to_f }.max || 0.0
  total_crashes = rows.sum { |r| r[:saved_crashes] }
  total_hangs = afl_rows.sum { |r| r[:saved_hangs] }
  earliest_start = rows.map { |r| r[:start_time] }.reject(&:zero?).min || started_at
  uptime = format_duration(now - earliest_start)

  page1_tab = page == 1 ? "#{BOLD}#{CYAN}[1: Overview]#{RESET}" : "#{DIM} 1: Overview #{RESET}"
  page2_tab = page == 2 ? "#{BOLD}#{CYAN}[2: Queue & Sync]#{RESET}" : "#{DIM} 2: Queue & Sync #{RESET}"

  out = +"\e[H\e[J"
  out << "#{BOLD}#{CYAN}Prism AFL++ Fleet Dashboard#{RESET} "
  out << "#{DIM}(uptime: #{uptime}, dir: #{afl_dir})#{RESET}   #{page1_tab} #{page2_tab}\n\n"

  crash_color = total_crashes > 0 ? "#{BOLD}#{RED}" : GREEN
  hang_color = total_hangs > 0 ? "#{BOLD}#{YELLOW}" : GREEN
  out << format(
    "  #{BOLD}Fuzzers:#{RESET} %d/%d alive   " \
    "#{BOLD}Speed:#{RESET} %s/s   " \
    "#{BOLD}Execs:#{RESET} %s   " \
    "#{BOLD}Corpus:#{RESET} %s   " \
    "#{BOLD}Max Cov:#{RESET} %.2f%%   " \
    "#{BOLD}Crashes:#{RESET} #{crash_color}%d#{RESET}   " \
    "#{BOLD}Hangs:#{RESET} #{hang_color}%d#{RESET}\n\n",
    alive_count, afl_rows.size,
    format_int(total_execs_sec.round),
    format_int(total_execs),
    format_int(max_corpus),
    max_cvg,
    total_crashes,
    total_hangs
  )

  header = if page == 1
             format(
               "%-10s %-9s %-8s %12s %8s %17s %8s %6s",
               "FUZZER", "STATE", "SCHED", "EXEC/S", "COV %", "EDGES", "CRASHES", "HANGS"
             )
           else
             format(
               "%-10s %-9s %-8s %12s %14s %6s %8s %8s %11s %14s %8s %8s",
               "FUZZER", "STATE", "SCHED", "EXEC/S", "TOTAL EXECS", "CYCLES",
               "CORPUS", "SHARED", "DESCENDANTS", "LAST FIND", "PENDING", "PEND FAV"
             )
           end
  out << "#{BOLD}#{header}#{RESET}\n"
  out << ("-" * header.length) << "\n"

  afl_rows.each do |r|
    state_str = state_badge(r[:state], 9)

    if page == 1
      crashes_str = if r[:saved_crashes] > 0
                      "#{BOLD}#{RED}#{format('%8d', r[:saved_crashes])}#{RESET}"
                    else
                      format("%8d", 0)
                    end

      hangs_str = if r[:saved_hangs] > 0
                    "#{BOLD}#{YELLOW}#{format('%6d', r[:saved_hangs])}#{RESET}"
                  else
                    format("%6d", 0)
                  end

      edges_str = if r[:total_edges] > 0
                    "#{format_int(r[:edges_found])} / #{format_int(r[:total_edges])}"
                  else
                    "-"
                  end

      out << format(
        "%-10s %s %-8s %12s %8s %17s %s %s\n",
        r[:name],
        state_str,
        r[:sched],
        "#{format_int(r[:execs_per_sec].round)}/s",
        r[:bitmap_cvg],
        edges_str,
        crashes_str,
        hangs_str
      )
    else
      last_find_str = if r[:last_find] > 0 && now >= r[:last_find]
                        "#{format_duration(now - r[:last_find])} ago"
                      else
                        "-"
                      end

      shared_count = contribs[:shared][r[:name]] || 0
      desc_count = contribs[:descendants][r[:name]] || 0

      out << format(
        "%-10s %s %-8s %12s %14s %6d %8s %8s %11s %14s %8s %8s\n",
        r[:name],
        state_str,
        r[:sched],
        "#{format_int(r[:execs_per_sec].round)}/s",
        format_int(r[:execs_done]),
        r[:cycles_done],
        format_int(r[:corpus_count]),
        format_int(shared_count),
        format_int(desc_count),
        last_find_str,
        format_int(r[:pending_total]),
        format_int(r[:pending_favs])
      )
    end
  end

  out << ("-" * header.length) << "\n"

  if gen_rows.any?
    gen_header = if page == 1
                   format(
                     "%-10s %-9s %-8s %12s %8s %17s %8s %6s",
                     "GENERATOR", "STATE", "MODE", "FILES/S", "CREATED", "PENDING", "CRASHES", "PRUNED"
                   )
                 else
                   format(
                     "%-10s %-9s %-8s %12s %14s %6s %8s %8s %11s %14s %8s %8s",
                     "GENERATOR", "STATE", "MODE", "FILES/S", "ATTEMPTS", "UNIQ %",
                     "CREATED", "SHARED", "DESCENDANTS", "LAST FIND", "PENDING", "PRUNED"
                   )
                 end
    out << "\n#{BOLD}#{gen_header}#{RESET}\n"
    out << ("-" * gen_header.length) << "\n"

    gen_rows.each do |g|
      state_str = state_badge(g[:state], 9)
      pend_raw = format("%17s", "#{format_int(g[:pending_files])} / #{format_int(g[:max_pending_files])}")
      pend_str = g[:pending_files] >= g[:max_pending_files] ? "#{YELLOW}#{pend_raw}#{RESET}" : pend_raw
      crashes_str = if g[:saved_crashes] > 0
                      "#{BOLD}#{RED}#{format('%8d', g[:saved_crashes])}#{RESET}"
                    else
                      format("%8d", 0)
                    end

      if page == 1
        out << format(
          "%-10s %s %-8s %12s %8s %s %s %6s\n",
          g[:name],
          state_str,
          g[:sched],
          format_rate(g[:files_per_sec]),
          format_fit(g[:files_created], 8),
          pend_str,
          crashes_str,
          format_fit(g[:files_pruned], 6)
        )
      else
        last_find_str = if g[:last_find] > 0 && now >= g[:last_find]
                          "#{format_duration(now - g[:last_find])} ago"
                        else
                          "-"
                        end
        uniq_pct = g[:attempts_done] > 0 ? format("%.1f%%", g[:files_created] * 100.0 / g[:attempts_done]) : "-"
        shared_count = contribs[:shared][g[:name]] || 0
        desc_count = contribs[:descendants][g[:name]] || 0

        out << format(
          "%-10s %s %-8s %12s %14s %6s %8s %8s %11s %14s %8s %8s\n",
          g[:name],
          state_str,
          g[:sched],
          format_rate(g[:files_per_sec]),
          format_fit(g[:attempts_done], 14),
          uniq_pct,
          format_fit(g[:files_created], 8),
          format_fit(shared_count, 8),
          format_fit(desc_count, 11),
          last_find_str,
          format_fit(g[:pending_files], 8),
          format_fit(g[:files_pruned], 8)
        )
      end
    end
    out << ("-" * gen_header.length) << "\n"
  end

  out << "#{DIM}[Tab/Space/1/2] Switch page   [Ctrl+B, w] Fuzzer window   [Ctrl+B, n/p] Next/Prev   [Ctrl+B, 0] Dashboard   [Ctrl+B, d] Detach   [Ctrl+C] Stop all#{RESET}\n"
  $stdout.write(out)
  $stdout.flush
end

if $stdin.tty?
  system("stty -icanon -echo 2>/dev/null")
end
$stdout.write("\e[?25l")
at_exit do
  if $stdin.tty?
    system("stty icanon echo 2>/dev/null")
  end
  $stdout.write("\e[?25h\n")
  $stdout.flush
end

Signal.trap("INT") { exit(0) }
Signal.trap("TERM") { exit(0) }

started_at = Time.now.to_i
script_mtime = File.mtime(__FILE__)
page = 1
contribs = { shared: Hash.new(0), descendants: Hash.new(0) }
last_contrib_update = 0

loop do
  if File.exist?(__FILE__) && File.mtime(__FILE__) != script_mtime
    exec(RbConfig.ruby, __FILE__, *ARGV)
  end
  now = Time.now.to_i
  if page == 2 && (now - last_contrib_update >= 15)
    contribs = compute_contributions(afl_dir)
    last_contrib_update = Time.now.to_i
  end
  render(afl_dir, expected_fuzzers, started_at, page, contribs)
  if IO.select([$stdin], nil, nil, 1.0)
    begin
      key = $stdin.read_nonblock(16)
      case key
      when "1"
        page = 1
      when "2"
        page = 2
      when "\t", " ", "\e[C", "\e[D", "h", "l", "n", "p"
        page = page == 1 ? 2 : 1
      end
    rescue IO::WaitReadable, EOFError
      # ignore
    end
  end
end
