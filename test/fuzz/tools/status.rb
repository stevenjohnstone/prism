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

def format_int(num)
  num.to_i.to_s.reverse.gsub(/(\d{3})(?=\d)/, '\\1,').reverse
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
  shared = Hash.new(0)
  descendants = Hash.new(0)
  main_origin = {}

  main_q_dir = File.join(afl_dir, "main", "queue")
  main_q = Dir.exist?(main_q_dir) ? Dir.children(main_q_dir).sort : []
  main_q.each do |f|
    id = f[/^id:(\d+)/, 1]
    next unless id

    if f =~ /sync:([^,]+)/
      origin = Regexp.last_match(1)
      main_origin[id] = origin
      shared[origin] += 1
    elsif !f.include?("orig:")
      srcs = f[/src:([0-9+]+)/, 1]&.split("+") || []
      parent_origins = srcs.filter_map { |s| main_origin[s] }.uniq
      non_main = parent_origins.reject { |o| o == "main" }
      if non_main.any?
        non_main.each { |o| descendants[o] += 1 }
        main_origin[id] = non_main.first
      else
        main_origin[id] = "main"
      end
    end
  end

  main_shared_ids = {}
  Dir.glob(File.join(afl_dir, "*/queue")).each do |qdir|
    fuzzer = File.basename(File.dirname(qdir))
    next if fuzzer == "main"

    local_origin = {}
    entries = Dir.children(qdir).sort rescue next
    entries.each do |f|
      id = f[/^id:(\d+)/, 1]
      next unless id

      if f =~ /sync:main,src:(\d+)/
        src_id = Regexp.last_match(1)
        orig = main_origin[src_id]
        local_origin[id] = orig if orig
        main_shared_ids[src_id] = true if orig == "main"
      elsif !f.include?("orig:") && !f.include?("sync:")
        srcs = f[/src:([0-9+]+)/, 1]&.split("+") || []
        p_origins = srcs.filter_map { |s| local_origin[s] }.uniq.reject { |o| o == fuzzer }
        if p_origins.any?
          p_origins.each { |o| descendants[o] += 1 }
          local_origin[id] = p_origins.first
        end
      end
    end
  end
  shared["main"] = main_shared_ids.size

  { shared: shared, descendants: descendants }
rescue StandardError
  { shared: Hash.new(0), descendants: Hash.new(0) }
end

def collect_fuzzer_rows(afl_dir, expected_fuzzers)
  discovered = Dir.glob(File.join(afl_dir, "*/fuzzer_stats")).map { |p| File.basename(File.dirname(p)) }
  names = (expected_fuzzers + discovered).uniq

  names.map do |name|
    stats_path = File.join(afl_dir, name, "fuzzer_stats")
    if File.exist?(stats_path)
      stats = parse_stats_file(stats_path)
      pid = stats["fuzzer_pid"].to_i
      alive = pid_alive?(pid)
      sched = stats["power_mode"] || stats["command_line"]&.[](/-p\s+(\S+)/, 1) || "fast"
      {
        name: name,
        state: alive ? :alive : :dead,
        sched: sched,
        execs_per_sec: stats["execs_per_sec"].to_f,
        execs_done: stats["execs_done"].to_i,
        cycles_done: stats["cycles_done"].to_i,
        corpus_count: stats["corpus_count"].to_i,
        pending_total: stats["pending_total"].to_i,
        pending_favs: stats["pending_favs"].to_i,
        bitmap_cvg: stats["bitmap_cvg"] || "0.00%",
        saved_crashes: stats["saved_crashes"].to_i,
        saved_hangs: stats["saved_hangs"].to_i,
        last_find: stats["last_find"].to_i,
        start_time: stats["start_time"].to_i
      }
    else
      {
        name: name,
        state: :starting,
        sched: "-",
        execs_per_sec: 0.0,
        execs_done: 0,
        cycles_done: 0,
        corpus_count: 0,
        pending_total: 0,
        pending_favs: 0,
        bitmap_cvg: "0.00%",
        saved_crashes: 0,
        saved_hangs: 0,
        last_find: 0,
        start_time: 0
      }
    end
  end
end

def render(afl_dir, expected_fuzzers, started_at, page, contribs)
  now = Time.now.to_i
  rows = collect_fuzzer_rows(afl_dir, expected_fuzzers)

  alive_count = rows.count { |r| r[:state] == :alive }
  total_execs_sec = rows.select { |r| r[:state] == :alive }.sum { |r| r[:execs_per_sec] }
  total_execs = rows.sum { |r| r[:execs_done] }
  max_corpus = rows.map { |r| r[:corpus_count] }.max || 0
  max_cvg = rows.map { |r| r[:bitmap_cvg].to_f }.max || 0.0
  total_crashes = rows.sum { |r| r[:saved_crashes] }
  total_hangs = rows.sum { |r| r[:saved_hangs] }
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
    "  #{BOLD}Workers:#{RESET} %d/%d alive   " \
    "#{BOLD}Speed:#{RESET} %s/s   " \
    "#{BOLD}Execs:#{RESET} %s   " \
    "#{BOLD}Corpus:#{RESET} %s   " \
    "#{BOLD}Max Cov:#{RESET} %.2f%%   " \
    "#{BOLD}Crashes:#{RESET} #{crash_color}%d#{RESET}   " \
    "#{BOLD}Hangs:#{RESET} #{hang_color}%d#{RESET}\n\n",
    alive_count, rows.size,
    format_int(total_execs_sec.round),
    format_int(total_execs),
    format_int(max_corpus),
    max_cvg,
    total_crashes,
    total_hangs
  )

  header = if page == 1
             format(
               "%-10s %-9s %-8s %12s %8s %8s %6s",
               "FUZZER", "STATE", "SCHED", "EXEC/S", "COV %", "CRASHES", "HANGS"
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

  rows.each do |r|
    state_str = case r[:state]
                when :alive
                  "#{GREEN}#{format('%-9s', 'RUNNING')}#{RESET}"
                when :starting
                  "#{YELLOW}#{format('%-9s', 'STARTING')}#{RESET}"
                else
                  "#{RED}#{format('%-9s', 'STOPPED')}#{RESET}"
                end

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

      out << format(
        "%-10s %s %-8s %12s %8s %s %s\n",
        r[:name],
        state_str,
        r[:sched],
        "#{format_int(r[:execs_per_sec].round)}/s",
        r[:bitmap_cvg],
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

