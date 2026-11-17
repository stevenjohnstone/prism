#!/usr/bin/env ruby
# frozen_string_literal: true

# Generates edgeID -> (Domain, Source, Function) documentation (build/fuzz.diff.ids)
# for PCGUARD-instrumented build/fuzz.diff by matching linker -Map __sancov_guards
# slices against each object's ELF COMDAT section groups.
#
# Output format ends with `Function=<fn> edgeID=<id>` so load_coverage_ids parses it
# uniformly alongside AFL_LLVM_DOCUMENT_IDS (.ids) files from afl-clang-lto.

require "fileutils"
require "open3"
require "optparse"
require "tmpdir"

def find_readelf
  %w[llvm-readelf readelf].find do |cmd|
    ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).any? do |dir|
      cand = File.join(dir, cmd)
      File.executable?(cand) && !File.directory?(cand)
    end
  end
end

def parse_object_guard_groups(readelf_bin, obj_path)
  secs_out, secs_st = Open3.capture2e(readelf_bin, "-S", "-W", obj_path)
  abort "gen_diff_ids: #{readelf_bin} -S failed on #{obj_path}:\n#{secs_out}" unless secs_st.success?

  secs = {}
  secs_out.each_line do |line|
    next unless line =~ /^\s*\[\s*(\d+)\]\s+(\S+)\s+\S+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)/

    secs[Regexp.last_match(1).to_i] = [Regexp.last_match(2), Regexp.last_match(3).to_i(16)]
  end

  grp_out, grp_st = Open3.capture2e(readelf_bin, "-g", obj_path)
  abort "gen_diff_ids: #{readelf_bin} -g failed on #{obj_path}:\n#{grp_out}" unless grp_st.success?

  groups = []
  cur_sig = nil
  cur_text = nil
  cur_guard = nil

  grp_out.each_line do |line|
    if line =~ /group section\s+\[\s*\d+\]\s+\S+\s+\[([^\]]*)\]/
      groups << [cur_sig, cur_text, cur_guard] if cur_guard
      cur_sig = Regexp.last_match(1)
      cur_text = nil
      cur_guard = nil
      next
    end

    next unless line =~ /^\s*\[\s*(\d+)\]\s+(\S+)/

    idx = Regexp.last_match(1).to_i
    name = Regexp.last_match(2)
    if name == "__sancov_guards"
      sec = secs[idx] or abort "gen_diff_ids: missing section [#{idx}] in #{obj_path}"
      cur_guard = [idx, sec[1]]
    elsif name.start_with?(".text")
      cur_text = name
    end
  end
  groups << [cur_sig, cur_text, cur_guard] if cur_guard

  all_guards = secs.select { |_, (name, _)| name == "__sancov_guards" }.keys.sort
  group_idxs = groups.map { |g| g[2][0] }
  if group_idxs != all_guards
    abort "gen_diff_ids: __sancov_guards COMDAT group mismatch in #{obj_path} " \
          "(#{group_idxs.size} grouped vs #{all_guards.size} sections)"
  end

  groups.map do |sig, txt, (_idx, size)|
    fn = sig.to_s
    fn = txt.delete_prefix(".text.") if fn.empty? && txt&.start_with?(".text.")
    abort "gen_diff_ids: missing function name for __sancov_guards group in #{obj_path}" if fn.empty?

    [fn, size]
  end
end

def parse_sancov_map(map_path)
  in_sancov = false
  start_addr = nil
  total_size = nil
  slices = []

  File.foreach(map_path) do |line|
    if !in_sancov
      if line =~ /^__sancov_guards\b(?:\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+))?/
        in_sancov = true
        if Regexp.last_match(1) && Regexp.last_match(2)
          start_addr = Regexp.last_match(1).to_i(16)
          total_size = Regexp.last_match(2).to_i(16)
        end
      end
      next
    end

    break if !line.empty? && line[0] !~ /\s/

    if start_addr.nil? && line =~ /^\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s*$/
      start_addr = Regexp.last_match(1).to_i(16)
      total_size = Regexp.last_match(2).to_i(16)
      next
    end

    if line =~ /^\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(.+?)\s*$/
      addr = Regexp.last_match(1).to_i(16)
      size = Regexp.last_match(2).to_i(16)
      src = Regexp.last_match(3)
      next if src.start_with?("*fill*")

      slices << [addr, size, src]
    end
  end

  abort "gen_diff_ids: __sancov_guards section not found in linker map #{map_path}" if start_addr.nil? || slices.empty?

  [start_addr, total_size, slices]
end

def detect_base_edge_id(bin_path, expected_edges)
  return 5 unless bin_path && File.executable?(bin_path)

  out, = Open3.capture2e(
    {
      "AFL_DEBUG" => "1",
      "ASAN_OPTIONS" => "abort_on_error=0:detect_leaks=0",
      "MSAN_OPTIONS" => "abort_on_error=0"
    },
    bin_path,
    "/dev/null"
  )
  init_edges = out[/Running __sanitizer_cov_trace_pc_guard_init:.*?\((\d+) edges\)/, 1]&.to_i
  final_loc = out[/Done __sanitizer_cov_trace_pc_guard_init: __afl_final_loc = (\d+)/, 1]&.to_i
  return 5 unless init_edges && final_loc && init_edges > 0

  if expected_edges && init_edges != expected_edges
    abort "gen_diff_ids: runtime PCGUARD edges (#{init_edges}) != linker map edges (#{expected_edges})"
  end

  final_loc - init_edges + 1
end

def classify_domain(src, archive_path)
  base = File.basename(src)
  return "harness" if base == "diff.o"

  if archive_path
    arch_base = File.basename(archive_path)
    if src.start_with?("#{archive_path}(") || src.include?("/#{arch_base}(") || src.include?("(parse.o)")
      return "parse_y"
    end
  end

  "prism"
end

def format_source_label(src)
  if src =~ /\(([^()]+)\)\z/
    Regexp.last_match(1).sub(/\.o\z/, ".c")
  else
    File.basename(src).sub(/\.o\z/, ".c")
  end
end

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: gen_diff_ids.rb --map PATH --output PATH [--bin PATH] [--archive PATH]"
  opts.on("--bin PATH", "Linked fuzz.diff binary (used to verify base edge ID)") { |v| options[:bin] = v }
  opts.on("--map PATH", "Linker -Map output path") { |v| options[:map] = v }
  opts.on("--archive PATH", "Path to libcruby_oracle.a") { |v| options[:archive] = v }
  opts.on("-o", "--output PATH", "Output .ids path") { |v| options[:output] = v }
end.parse!

abort "gen_diff_ids: --map and --output are required" unless options[:map] && options[:output]

readelf_bin = find_readelf or abort "gen_diff_ids: neither llvm-readelf nor readelf found in PATH"
start_addr, total_size, slices = parse_sancov_map(options[:map])
abort "gen_diff_ids: __sancov_guards size #{total_size} not divisible by 4" unless (total_size % 4).zero?

expected_edges = total_size / 4
base_edge_id = detect_base_edge_id(options[:bin], expected_edges)

Dir.mktmpdir("gen-diff-ids-") do |tmpdir|
  obj_queues = {}
  unique_srcs = slices.map { |_, _, s| s }.uniq

  unique_srcs.each do |src|
    obj_path =
      if src =~ /\A(.+\.a)\(([^()]+)\)\z/
        ar_path = Regexp.last_match(1)
        member = Regexp.last_match(2)
        extracted = File.join(tmpdir, member)
        unless File.file?(extracted)
          out, st = Open3.capture2e("ar", "p", ar_path, member)
          abort "gen_diff_ids: ar p #{ar_path} #{member} failed:\n#{out}" unless st.success?
          File.binwrite(extracted, out)
        end
        extracted
      else
        src
      end
    obj_queues[src] = parse_object_guard_groups(readelf_bin, obj_path)
  end

  cursors = Hash.new(0)
  lines = []
  mapped_count = 0

  slices.each do |addr, size, src|
    abort "gen_diff_ids: unaligned slice addr #{addr.to_s(16)} relative to #{start_addr.to_s(16)}" unless ((addr - start_addr) % 4).zero?
    abort "gen_diff_ids: unaligned slice size #{size} in #{src}" unless (size % 4).zero?

    queue = obj_queues.fetch(src)
    idx = cursors[src]
    abort "gen_diff_ids: ran out of COMDAT groups in #{src} at #{idx}" if idx >= queue.size

    fn, group_size = queue[idx]
    cursors[src] = idx + 1
    if group_size != size
      abort "gen_diff_ids: size mismatch in #{src} for #{fn}: map=#{size} obj=#{group_size}"
    end

    domain = classify_domain(src, options[:archive])
    source_label = format_source_label(src)
    first_id = base_edge_id + ((addr - start_addr) / 4)
    count = size / 4
    count.times do |off|
      lines << "Domain=#{domain} Source=#{source_label} Function=#{fn} edgeID=#{first_id + off}\n"
    end
    mapped_count += count
  end

  cursors.each do |src, used|
    total = obj_queues[src].size
    abort "gen_diff_ids: unconsumed COMDAT groups in #{src}: #{used}/#{total}" unless used == total
  end

  if mapped_count != expected_edges
    abort "gen_diff_ids: mapped #{mapped_count} edges, expected #{expected_edges}"
  end

  FileUtils.mkdir_p(File.dirname(options[:output]))
  tmp_out = "#{options[:output]}.tmp.#{Process.pid}"
  File.write(tmp_out, lines.join)
  File.rename(tmp_out, options[:output])
end
