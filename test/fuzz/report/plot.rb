#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "cgi"
require "fileutils"
require "json"
require "time"

PRISM_LOUPE_BASE_URL = "https://stevenjohnstone.github.io/prism-loupe/"

afl_dir = ARGV[0] || "./tmp/fuzz/afl"
out_path = ARGV[1] || "./tmp/fuzz/plots/index.html"
cov_json_path = ARGV[2] || "./tmp/fuzz/coverage/coverage.json"

coverage_data = if File.exist?(cov_json_path)
                  begin
                    JSON.parse(File.read(cov_json_path))
                  rescue StandardError
                    nil
                  end
                end

PLOT_COLUMNS = %i[
  relative_time
  cycles_done
  cur_item
  corpus_count
  pending_total
  pending_favs
  map_size
  saved_crashes
  saved_hangs
  max_depth
  execs_per_sec
  total_execs
  edges_found
  total_crashes
  servers_count
].freeze

PALETTE = [
  "#60a5fa", # blue
  "#34d399", # emerald
  "#f472b6", # pink
  "#fbbf24", # amber
  "#a78bfa", # purple
  "#38bdf8", # sky
  "#fb7185", # rose
  "#4ade80", # green
  "#f97316", # orange
  "#2dd4bf", # teal
  "#e879f9", # fuchsia
  "#facc15"  # yellow
].freeze

def parse_fuzzer_stats(path)
  return {} unless File.exist?(path)

  stats = {}
  File.foreach(path) do |line|
    k, v = line.split(":", 2)
    next unless k && v

    stats[k.strip] = v.strip
  end
  stats
rescue StandardError
  {}
end

def normalize_sync_source(src)
  return "grammar" if src =~ /\A(?:grammar|seeds)(?:_\d+)?\z/
  return "ijon" if src =~ /\Aijon(?:_\d+|_peer)?\z/

  src
end

def worker_root_dirs(afl_dir)
  [afl_dir, "#{afl_dir}-ijon"].select { |d| Dir.exist?(d) }
end

def discover_fuzzer_dirs(afl_dir)
  by_name = {}
  worker_root_dirs(afl_dir).each do |root|
    Dir.glob(File.join(root, "*")).sort.each do |d|
      name = File.basename(d)
      next if name.start_with?(".") || !File.directory?(d)
      next unless File.exist?(File.join(d, "fuzzer_stats")) || File.exist?(File.join(d, "plot_data"))

      by_name[name] ||= d
    end
  end
  by_name
end

def parse_generator_plot_data(path)
  return [] unless File.exist?(path)

  rows = []
  File.foreach(path) do |line|
    line = line.strip
    next if line.empty? || line.start_with?("#")

    parts = line.split(",").map(&:strip)
    next if parts.size < 4

    rows << {
      relative_time: parts[0].to_i,
      files_created: parts[1].to_i,
      files_per_sec: parts[2].to_f,
      avg_files_per_sec: parts[3].to_f,
      attempts_done: (parts[4] || parts[1]).to_i,
      files_valid: parts[5].to_i,
      files_invalid: parts[6].to_i,
      corpus_count: parts[1].to_i,
      execs_per_sec: parts[2].to_f,
      total_execs: (parts[4] || parts[1]).to_i,
      cycles_done: 0,
      cur_item: 0,
      pending_total: 0,
      pending_favs: 0,
      map_size: 0.0,
      saved_crashes: 0,
      saved_hangs: 0,
      max_depth: 0,
      edges_found: 0,
      total_crashes: 0
    }
  end
  rows
rescue StandardError
  []
end

def parse_plot_data(path)
  return [] unless File.exist?(path)

  rows = []
  File.foreach(path) do |line|
    line = line.strip
    next if line.empty? || line.start_with?("#")

    parts = line.split(",").map(&:strip)
    next if parts.size < 13

    rows << {
      relative_time: parts[0].to_i,
      cycles_done: parts[1].to_i,
      cur_item: parts[2].to_i,
      corpus_count: parts[3].to_i,
      pending_total: parts[4].to_i,
      pending_favs: parts[5].to_i,
      map_size: parts[6].delete_suffix("%").to_f,
      saved_crashes: parts[7].to_i,
      saved_hangs: parts[8].to_i,
      max_depth: parts[9].to_i,
      execs_per_sec: parts[10].to_f,
      total_execs: parts[11].to_i,
      edges_found: parts[12].to_i,
      total_crashes: parts[13].to_i
    }
  end
  rows
rescue StandardError
  []
end

# Scan <fuzzer>/queue/id:* filenames to classify each queue ID (0..N-1) as
# :seed (orig:), :sync (sync:<source>), or :local (mutated locally), and record
# the source fuzzer for synced entries. Because AFL++ assigns sequential 0-based
# IDs as items enter the queue, corpus_count at any plot_data sample t corresponds
# to queue IDs 0...(corpus_count - 1).
def parse_queue_origins(queue_dir)
  return { prefix_sync: [0], prefix_local: [0], prefix_seed: [0], by_source: {}, max_src_by_source: {} } unless Dir.exist?(queue_dir)

  max_id = -1
  item_kind = {}
  item_source = {}
  max_src_by_source = Hash.new(0)

  Dir.children(queue_dir).each do |fname|
    id = fname[/\Aid:(\d+),/, 1]&.to_i
    next unless id

    max_id = id if id > max_id
    if fname =~ /\Aid:\d+,sync:([^,]+)/
      src_name = normalize_sync_source(Regexp.last_match(1))
      item_kind[id] = :sync
      item_source[id] = src_name
      if fname =~ /\Aid:\d+,sync:[^,]+,src:(?:id:)?(\d+)(?:[,+]|$)/
        src_end = Regexp.last_match(1).to_i + 1
        max_src_by_source[src_name] = src_end if src_end > max_src_by_source[src_name]
      end
    elsif fname =~ /\Aid:\d+(?:,time:\d+,execs:\d+)?,orig:/
      item_kind[id] = :seed
    else
      item_kind[id] = :local
    end
  end

  return { prefix_sync: [0], prefix_local: [0], prefix_seed: [0], by_source: {}, max_src_by_source: {} } if max_id < 0

  prefix_sync = Array.new(max_id + 2, 0)
  prefix_local = Array.new(max_id + 2, 0)
  prefix_seed = Array.new(max_id + 2, 0)
  sources = item_source.values.uniq
  by_source = sources.to_h { |src| [src, Array.new(max_id + 2, 0)] }

  (0..max_id).each do |id|
    kind = item_kind[id] || :local
    prefix_sync[id + 1] = prefix_sync[id] + (kind == :sync ? 1 : 0)
    prefix_local[id + 1] = prefix_local[id] + (kind == :local ? 1 : 0)
    prefix_seed[id + 1] = prefix_seed[id] + (kind == :seed ? 1 : 0)
    src = item_source[id]
    sources.each do |s|
      by_source[s][id + 1] = by_source[s][id] + (src == s ? 1 : 0)
    end
  end

  {
    prefix_sync: prefix_sync,
    prefix_local: prefix_local,
    prefix_seed: prefix_seed,
    by_source: by_source,
    max_src_by_source: max_src_by_source
  }
rescue StandardError
  { prefix_sync: [0], prefix_local: [0], prefix_seed: [0], by_source: {}, max_src_by_source: {} }
end

def parse_synced_cursors(fuzzer_dir)
  synced_dir = File.join(fuzzer_dir, ".synced")
  return {} unless Dir.exist?(synced_dir)

  cursors = {}
  Dir.children(synced_dir).each do |fname|
    next if fname.start_with?(".") || fname.end_with?(".max")

    raw = File.binread(File.join(synced_dir, fname))
    val = raw.bytesize >= 4 ? raw.unpack1("V") : 0
    cursors[fname] = val
    norm = normalize_sync_source(fname)
    cursors[norm] = [cursors[norm].to_i, val].max
  end
  cursors
rescue StandardError
  {}
end

def lookup_prefix(prefix_arr, count)
  return 0 if prefix_arr.empty? || count <= 0

  idx = [count, prefix_arr.size - 1].min
  prefix_arr[idx]
end

def sort_fuzzer_names(names)
  priority = { "main" => 0, "grammar" => 1, "msan" => 2, "ijon" => 3 }
  names.sort_by do |name|
    if priority.key?(name)
      [0, priority[name], 0, name]
    elsif name =~ /\Amain-(\d+)\z/
      [1, Regexp.last_match(1).to_i, 0, name]
    else
      [2, 0, 0, name]
    end
  end
end

def format_int(num)
  num.to_i.to_s.reverse.gsub(/(\d{3})(?=\d)/, '\\1,').reverse
end

def format_compact(num)
  n = num.to_f
  return "0" if n.zero?

  if n.abs >= 1_000_000_000
    format("%.2fB", n / 1_000_000_000.0).sub(/\.?0+B$/, "B")
  elsif n.abs >= 1_000_000
    format("%.2fM", n / 1_000_000.0).sub(/\.?0+M$/, "M")
  elsif n.abs >= 10_000
    format("%.1fK", n / 1_000.0).sub(/\.?0+K$/, "K")
  elsif n == n.to_i
    format_int(n.to_i)
  else
    format("%.2f", n).sub(/\.?0+$/, "")
  end
end

def format_duration(seconds)
  seconds = seconds.to_i
  return "0s" if seconds <= 0

  hours = seconds / 3600
  mins = (seconds % 3600) / 60
  secs = seconds % 60

  if hours > 0
    format("%dh %02dm", hours, mins)
  elsif mins > 0
    format("%dm %02ds", mins, secs)
  else
    format("%ds", secs)
  end
end

def downsample(rows, max_points = 350)
  return rows if rows.size <= max_points

  step = (rows.size - 1).to_f / (max_points - 1)
  (0...max_points).map { |i| rows[(i * step).round] }.uniq { |r| r[:relative_time] }
end

def nice_ceil(val)
  return 1.0 if val <= 0

  exp = Math.log10(val).floor
  f = val / (10.0**exp)
  nf = if f <= 1.0
         1.0
       elsif f <= 2.0
         2.0
       elsif f <= 2.5
         2.5
       elsif f <= 5.0
         5.0
       else
         10.0
       end
  nf * (10.0**exp)
end

def render_svg_chart(title:, subtitle:, series:, y_format: :compact, fill_area: false, zero_base: true, chart_id: nil)
  width = 580
  height = 270
  pad_l = 62
  pad_r = 22
  pad_t = 22
  pad_b = 40
  plot_w = width - pad_l - pad_r
  plot_h = height - pad_t - pad_b

  non_empty = series.reject { |s| s[:points].empty? }
  if non_empty.empty?
    return <<~HTML
      <div class="chart-card">
        <div class="chart-header">
          <div>
            <h3>#{CGI.escapeHTML(title)}</h3>
            <p class="chart-sub">#{CGI.escapeHTML(subtitle)}</p>
          </div>
        </div>
        <div class="empty-chart">No plot_data samples recorded yet</div>
      </div>
    HTML
  end

  all_x = non_empty.flat_map { |s| s[:points].map { |p| p[0] } }
  all_y = non_empty.flat_map { |s| s[:points].map { |p| p[1] } }

  min_x = all_x.min.to_f
  max_x = all_x.max.to_f
  max_x = min_x + 1.0 if (max_x - min_x).abs < 1e-9

  raw_min_y = zero_base ? [0.0, all_y.min.to_f].min : all_y.min.to_f
  raw_max_y = all_y.max.to_f

  if (raw_max_y - raw_min_y).abs < 1e-9
    min_y = zero_base ? 0.0 : raw_min_y - 1.0
    max_y = raw_max_y + (raw_max_y.zero? ? 1.0 : raw_max_y.abs * 0.1)
  elsif zero_base
    min_y = 0.0
    max_y = nice_ceil(raw_max_y * 1.05)
  else
    span = raw_max_y - raw_min_y
    min_y = [0.0, raw_min_y - span * 0.08].max
    max_y = raw_max_y + span * 0.08
  end

  format_y = lambda do |v|
    case y_format
    when :percent
      format("%.2f%%", v).sub(/\.00%$/, "%")
    when :int
      format_int(v.round)
    when :rate
      "#{format_compact(v)}/s"
    when :file_rate
      "#{format_compact(v)} files/s"
    else
      format_compact(v)
    end
  end

  x_to_px = ->(x) { pad_l + ((x - min_x) / (max_x - min_x)) * plot_w }
  y_to_px = ->(y) { pad_t + plot_h - ((y - min_y) / (max_y - min_y)) * plot_h }

  y_ticks = 4
  grid_svg = +""
  (0..y_ticks).each do |i|
    val = min_y + ((max_y - min_y) * i / y_ticks.to_f)
    py = y_to_px.call(val).round(2)
    grid_svg << %(<line x1="#{pad_l}" y1="#{py}" x2="#{width - pad_r}" y2="#{py}" class="grid-line" />\n)
    grid_svg << %(<text x="#{pad_l - 8}" y="#{py + 4}" text-anchor="end" class="axis-label">#{CGI.escapeHTML(format_y.call(val))}</text>\n)
  end

  x_ticks = 5
  (0..x_ticks).each do |i|
    val = min_x + ((max_x - min_x) * i / x_ticks.to_f)
    px = x_to_px.call(val).round(2)
    grid_svg << %(<line x1="#{px}" y1="#{pad_t + plot_h}" x2="#{px}" y2="#{pad_t + plot_h + 5}" class="axis-tick" />\n)
    grid_svg << %(<text x="#{px}" y="#{height - 12}" text-anchor="middle" class="axis-label">#{CGI.escapeHTML(format_duration(val))}</text>\n)
  end

  defs_svg = +""
  paths_svg = +""
  legend_html = +""

  non_empty.each_with_index do |s, idx|
    color = s[:color] || PALETTE[idx % PALETTE.size]
    safe_s_name = CGI.escapeHTML(s[:name])
    pts = s[:points]
    coords = pts.map { |x, y| [x_to_px.call(x).round(2), y_to_px.call(y).round(2)] }
    line_d = coords.each_with_index.map { |(px, py), i| "#{i.zero? ? 'M' : 'L'}#{px},#{py}" }.join(" ")
    paths_svg << %(<g class="series-group" data-series-name="#{safe_s_name}">\n)

    if fill_area && coords.size >= 2
      grad_id = "grad-#{chart_id}-#{idx}"
      defs_svg << <<~SVG
        <linearGradient id="#{grad_id}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#{color}" stop-opacity="0.28" />
          <stop offset="100%" stop-color="#{color}" stop-opacity="0.02" />
        </linearGradient>
      SVG
      base_y = (pad_t + plot_h).round(2)
      area_d = "#{line_d} L#{coords.last[0]},#{base_y} L#{coords.first[0]},#{base_y} Z"
      paths_svg << %(<path d="#{area_d}" fill="url(##{grad_id})" class="series-area" />\n)
    end

    stroke_w = non_empty.size > 4 ? 1.8 : 2.2
    paths_svg << %(<path d="#{line_d}" fill="none" stroke="#{color}" stroke-width="#{stroke_w}" stroke-linecap="round" stroke-linejoin="round" class="series-line" />\n)
    paths_svg << %(<path d="#{line_d}" fill="none" stroke="transparent" stroke-width="14" stroke-linecap="round" stroke-linejoin="round" class="series-hit" data-series-name="#{safe_s_name}"><title>#{safe_s_name}</title></path>\n)

    last_x, last_y = coords.last
    last_val = pts.last[1]
    paths_svg << %(<circle cx="#{last_x}" cy="#{last_y}" r="3.2" fill="#{color}" class="series-dot" />\n)
    paths_svg << %(</g>\n)

    legend_html << <<~HTML
      <span class="legend-item" data-series-name="#{safe_s_name}">
        <span class="legend-dot" style="background:#{color}"></span>
        <span class="legend-name">#{safe_s_name}</span>
        <span class="legend-val">#{CGI.escapeHTML(format_y.call(last_val))}</span>
      </span>
    HTML
  end

  series_json = non_empty.each_with_index.map do |s, idx|
    {
      name: s[:name],
      color: s[:color] || PALETTE[idx % PALETTE.size],
      points: s[:points].map { |x, y| [x, y.round(2), format_y.call(y), y_to_px.call(y).round(2)] }
    }
  end.to_json

  <<~HTML
    <div class="chart-card" data-series="#{CGI.escapeHTML(series_json)}" data-min-x="#{min_x}" data-max-x="#{max_x}" data-pad-l="#{pad_l}" data-plot-w="#{plot_w}">
      <div class="chart-header">
        <div>
          <h3>#{CGI.escapeHTML(title)}</h3>
          <p class="chart-sub">#{CGI.escapeHTML(subtitle)}</p>
        </div>
        <div class="chart-legend">#{legend_html}</div>
      </div>
      <div class="svg-wrap">
        <svg viewBox="0 0 #{width} #{height}" preserveAspectRatio="none" class="plot-svg">
          <defs>#{defs_svg}</defs>
          #{grid_svg}
          #{paths_svg}
          <line x1="0" y1="#{pad_t}" x2="0" y2="#{pad_t + plot_h}" class="hover-line" style="display:none" />
          <circle cx="0" cy="0" r="5" class="hover-dot" style="display:none" />
        </svg>
        <div class="line-badge" style="display:none"></div>
        <div class="chart-tooltip" style="display:none"></div>
      </div>
    </div>
  HTML
end

unless Dir.exist?(afl_dir)
  warn "AFL directory not found: #{afl_dir}"
  exit 1
end

fuzzer_dir_by_name = discover_fuzzer_dirs(afl_dir)
fuzzer_names = sort_fuzzer_names(fuzzer_dir_by_name.keys)
if fuzzer_names.empty?
  warn "No fuzzer directories with fuzzer_stats or plot_data found in #{afl_dir}"
  exit 1
end

fuzzers = fuzzer_names.each_with_index.map do |name, idx|
  dir = fuzzer_dir_by_name[name]
  stats = parse_fuzzer_stats(File.join(dir, "fuzzer_stats"))
  is_generator = stats["fuzzer_role"] == "generator"
  raw_plot = if is_generator
               parse_generator_plot_data(File.join(dir, "plot_data"))
             else
               parse_plot_data(File.join(dir, "plot_data"))
             end
  origins = parse_queue_origins(File.join(dir, "queue"))
  synced_cursors = parse_synced_cursors(dir)

  run_time = stats["run_time"]&.to_i || raw_plot.last&.dig(:relative_time) || 0
  if is_generator && raw_plot.size < 2 && stats["files_created"]
    fc = stats["files_created"].to_i
    fps = (stats["files_per_sec"] || stats["avg_files_per_sec"]).to_f
    avg_fps = (stats["avg_files_per_sec"] || fps).to_f
    att = (stats["attempts_done"] || fc).to_i
    fv = stats["files_valid"].to_i
    fi = stats["files_invalid"].to_i
    raw_plot = [
      { relative_time: 0, files_created: 0, files_per_sec: fps, avg_files_per_sec: avg_fps, attempts_done: 0, files_valid: 0, files_invalid: 0, corpus_count: 0, execs_per_sec: fps, total_execs: 0, cycles_done: 0, cur_item: 0, pending_total: 0, pending_favs: 0, map_size: 0.0, saved_crashes: 0, saved_hangs: 0, max_depth: 0, edges_found: 0, total_crashes: 0 },
      { relative_time: [run_time, 1].max, files_created: fc, files_per_sec: fps, avg_files_per_sec: avg_fps, attempts_done: att, files_valid: fv, files_invalid: fi, corpus_count: fc, execs_per_sec: fps, total_execs: att, cycles_done: 0, cur_item: 0, pending_total: 0, pending_favs: 0, map_size: 0.0, saved_crashes: 0, saved_hangs: 0, max_depth: 0, edges_found: 0, total_crashes: 0 }
    ]
  end

  sampled = downsample(raw_plot).map do |r|
    cc = r[:corpus_count]
    if is_generator
      r.merge(synced_count: 0, local_count: cc, seed_count: 0)
    else
      r.merge(
        synced_count: lookup_prefix(origins[:prefix_sync], cc),
        local_count: lookup_prefix(origins[:prefix_local], cc),
        seed_count: lookup_prefix(origins[:prefix_seed], cc)
      )
    end
  end

  sched = stats["power_mode"] || stats["command_line"]&.[](/-p\s+(\S+)/, 1) || "default"
  edges_found = stats["edges_found"]&.to_i || sampled.last&.dig(:edges_found) || 0
  total_edges = stats["total_edges"]&.to_i || 0
  bitmap_cvg = stats["bitmap_cvg"]&.delete_suffix("%")&.to_f || sampled.last&.dig(:map_size) || 0.0
  execs_done = stats["execs_done"]&.to_i || sampled.last&.dig(:total_execs) || 0
  execs_per_sec = stats["execs_per_sec"]&.to_f || sampled.last&.dig(:execs_per_sec) || 0.0
  corpus_count = stats["corpus_count"]&.to_i || sampled.last&.dig(:corpus_count) || 0
  corpus_found = stats["corpus_found"]&.to_i || sampled.last&.dig(:local_count) || 0
  corpus_imported = stats["corpus_imported"]&.to_i || sampled.last&.dig(:synced_count) || 0
  pending_total = stats["pending_total"]&.to_i || sampled.last&.dig(:pending_total) || 0
  pending_favs = stats["pending_favs"]&.to_i || sampled.last&.dig(:pending_favs) || 0
  saved_crashes = stats["saved_crashes"]&.to_i || sampled.last&.dig(:saved_crashes) || 0
  saved_hangs = stats["saved_hangs"]&.to_i || sampled.last&.dig(:saved_hangs) || 0
  cycles_done = stats["cycles_done"]&.to_i || sampled.last&.dig(:cycles_done) || 0
  max_depth = stats["max_depth"]&.to_i || sampled.last&.dig(:max_depth) || 0
  stability = stats["stability"] || "100.00%"
  banner = stats["afl_banner"] || "./build/fuzz"

  files_created = (stats["files_created"] || corpus_count).to_i
  pending_files = stats["pending_files"].to_i
  max_pending_files = (stats["max_pending_files"] || "50000").to_i
  files_pruned = stats["files_pruned"].to_i
  files_per_sec = (stats["files_per_sec"] || stats["avg_files_per_sec"] || execs_per_sec).to_f
  avg_files_per_sec = (stats["avg_files_per_sec"] || files_per_sec).to_f
  attempts_done = (stats["attempts_done"] || execs_done).to_i
  files_valid = stats["files_valid"].to_i
  files_invalid = stats["files_invalid"].to_i
  duplicates_skipped = stats["duplicates_skipped"].to_i

  {
    name: name,
    dir: dir,
    role: is_generator ? :generator : :fuzzer,
    color: PALETTE[idx % PALETTE.size],
    sched: sched,
    banner: banner,
    stats: stats,
    origins: origins,
    synced_cursors: synced_cursors,
    samples: sampled,
    sample_count: raw_plot.size,
    edges_found: edges_found,
    total_edges: total_edges,
    bitmap_cvg: bitmap_cvg,
    execs_done: execs_done,
    execs_per_sec: execs_per_sec,
    corpus_count: corpus_count,
    corpus_found: corpus_found,
    corpus_imported: corpus_imported,
    pending_total: pending_total,
    pending_favs: pending_favs,
    saved_crashes: saved_crashes,
    saved_hangs: saved_hangs,
    cycles_done: cycles_done,
    max_depth: max_depth,
    run_time: run_time,
    stability: stability,
    files_created: files_created,
    pending_files: pending_files,
    max_pending_files: max_pending_files,
    files_pruned: files_pruned,
    files_per_sec: files_per_sec,
    avg_files_per_sec: avg_files_per_sec,
    attempts_done: attempts_done,
    files_valid: files_valid,
    files_invalid: files_invalid,
    duplicates_skipped: duplicates_skipped
  }
end

color_by_name = fuzzers.to_h { |f| [f[:name], f[:color]] }
afl_fuzzers = fuzzers.reject { |f| f[:role] == :generator }
gen_fuzzers = fuzzers.select { |f| f[:role] == :generator }

# Compute Fleet Overview KPIs
fleet_execs = afl_fuzzers.sum { |f| f[:execs_done] }
fleet_speed = afl_fuzzers.sum { |f| f[:execs_per_sec] }
fleet_crashes = fuzzers.sum { |f| f[:saved_crashes] }
fleet_hangs = afl_fuzzers.sum { |f| f[:saved_hangs] }
fleet_max_corpus = afl_fuzzers.map { |f| f[:corpus_count] }.max || 0
fleet_max_runtime = fuzzers.map { |f| f[:run_time] }.max || 0
main_fuzzer = afl_fuzzers.find { |f| f[:name] == "main" } || afl_fuzzers.first || fuzzers.first

# Compute snapshot sync progress across each upstream generator (-F), foreign fuzzer (-F), and peer queue (.synced/<peer>)
main_name = main_fuzzer[:name]
main_synced_cursors = main_fuzzer[:synced_cursors] || {}
main_max_src = main_fuzzer[:origins][:max_src_by_source] || {}
main_by_source = main_fuzzer[:origins][:by_source] || {}
expanded_afl_dir = File.expand_path(afl_dir)

peer_sync_by_name = {}
fuzzers.each do |f|
  next if f[:name] == main_name

  peer_name = f[:name]
  if f[:role] == :generator
    intake_fuzzer = afl_fuzzers.max_by { |af| lookup_prefix(af[:origins][:by_source][peer_name] || [], af[:corpus_count]) }
    if intake_fuzzer.nil? || lookup_prefix(intake_fuzzer[:origins][:by_source][peer_name] || [], intake_fuzzer[:corpus_count]).zero?
      intake_fuzzer = afl_fuzzers.find { |af| af[:name] == "ijon" } || main_fuzzer
    end
    peer_total = [f[:files_created].to_i, 0].max
    imported_count = lookup_prefix(intake_fuzzer[:origins][:by_source][peer_name] || [], intake_fuzzer[:corpus_count])
    pending = [f[:pending_files].to_i, 0].max
    scanned = [peer_total - pending, imported_count].max
    peer_total = [peer_total, scanned].max
    backlog = [peer_total - scanned, 0].max
    sync_pct = peer_total > 0 ? (scanned * 100.0 / peer_total) : 100.0
    tested_count = [scanned, imported_count].max
    rejected_count = [tested_count - imported_count, 0].max
    yield_pct = tested_count > 0 ? (imported_count * 100.0 / tested_count) : 0.0
    peer_sync_by_name[peer_name] = {
      is_generator: true,
      sync_mode: :foreign_seeds,
      intake_fuzzer: intake_fuzzer,
      intake_name: intake_fuzzer[:name],
      consumer_name: intake_fuzzer[:name],
      peer_total: peer_total,
      watermark: scanned,
      cursor: scanned,
      skipped_from_main: 0,
      tested_by_main: tested_count,
      imported_by_main: imported_count,
      rejected_by_main: rejected_count,
      unsynced_backlog: backlog,
      sync_pct: sync_pct,
      yield_pct: yield_pct,
      peer_from_main_cursor: 0,
      peer_from_main_pct: 0.0
    }
    next
  end

  is_isolated_root = File.expand_path(File.dirname(f[:dir])) != expanded_afl_dir
  shadow_synced_path = peer_name == "ijon" ? File.join(main_fuzzer[:dir], ".synced", "ijon_peer") : nil
  has_shadow_peer = !!(shadow_synced_path && File.file?(shadow_synced_path))
  is_foreign_queue = is_isolated_root && !has_shadow_peer
  peer_total = f[:corpus_count]
  watermark = main_synced_cursors[peer_name] || 0
  if has_shadow_peer
    raw_cursor = File.binread(shadow_synced_path) rescue "".b
    shadow_wm = raw_cursor.bytesize >= 4 ? raw_cursor.unpack1("V") : 0
    watermark = [watermark, shadow_wm].max
  end
  in_flight = main_max_src[peer_name] || 0
  if is_foreign_queue && in_flight > 0
    # Foreign-synced fuzzer (-F, legacy fallback when .synced/ijon_peer is absent):
    # main scanned every peer queue file whose mtime was <= the mtime of the highest imported peer item.
    qdir = File.join(f[:dir], "queue")
    last_imp_prefix = format("id:%06d", in_flight - 1)
    if Dir.exist?(qdir)
      qfiles = Dir.children(qdir).select { |fn| fn.start_with?("id:") }
      imp_fn = qfiles.find { |fn| fn.start_with?(last_imp_prefix) }
      if imp_fn
        imp_mtime = File.mtime(File.join(qdir, imp_fn)).to_i rescue 0
        if imp_mtime > 0
          scanned = qfiles.count { |fn| (File.mtime(File.join(qdir, fn)).to_i rescue (imp_mtime + 1)) <= imp_mtime }
          watermark = [watermark, scanned].max
        end
      end
    end
  end
  cursor = [[watermark, in_flight].max, peer_total].min

  # Items in peer's queue[0...cursor] that originally came from `main` (sync:main) are skipped by `main` without running
  skipped_from_main = is_isolated_root ? 0 : lookup_prefix(f[:origins][:by_source][main_name] || [], cursor)
  tested_by_main = [cursor - skipped_from_main, 0].max
  imported_by_main = lookup_prefix(main_by_source[peer_name] || [], main_fuzzer[:corpus_count])
  rejected_by_main = [tested_by_main - imported_by_main, 0].max
  unsynced_backlog = [peer_total - cursor, 0].max
  sync_pct = peer_total > 0 ? (cursor * 100.0 / peer_total) : 100.0
  yield_pct = tested_by_main > 0 ? (imported_by_main * 100.0 / tested_by_main) : 0.0

  # Also track how far this peer has synced through `main`'s queue (`<peer>/.synced/main`)
  peer_from_main_wm = f[:synced_cursors][main_name] || 0
  peer_from_main_max = f[:origins][:max_src_by_source][main_name] || 0
  peer_from_main_cursor = [[peer_from_main_wm, peer_from_main_max].max, main_fuzzer[:corpus_count]].min
  peer_from_main_pct = main_fuzzer[:corpus_count] > 0 ? (peer_from_main_cursor * 100.0 / main_fuzzer[:corpus_count]) : 100.0

  peer_sync_by_name[peer_name] = {
    is_generator: false,
    sync_mode: has_shadow_peer ? :shadow_peer : (is_foreign_queue ? :foreign_queue : :peer),
    consumer_name: main_name,
    peer_total: peer_total,
    watermark: watermark,
    cursor: cursor,
    skipped_from_main: skipped_from_main,
    tested_by_main: tested_by_main,
    imported_by_main: imported_by_main,
    rejected_by_main: rejected_by_main,
    unsynced_backlog: unsynced_backlog,
    sync_pct: sync_pct,
    yield_pct: yield_pct,
    peer_from_main_cursor: peer_from_main_cursor,
    peer_from_main_pct: peer_from_main_pct
  }
end

peer_sync_rows_html = fuzzers.reject { |f| f[:name] == main_name }.map do |f|
  ps = peer_sync_by_name[f[:name]]
  consumer = ps[:consumer_name] || main_name
  total = [ps[:peer_total], 1].max.to_f
  imp_w = (ps[:imported_by_main] * 100.0 / total).round(2)
  rej_w = (ps[:rejected_by_main] * 100.0 / total).round(2)
  skp_w = (ps[:skipped_from_main] * 100.0 / total).round(2)
  uns_w = [100.0 - imp_w - rej_w - skp_w, 0.0].max.round(2)
  tip = case ps[:sync_mode]
        when :foreign_seeds
          "#{f[:name]} → #{consumer} (-F foreign seeds, created: #{format_int(ps[:peer_total])}) — " \
          "Tested by #{consumer}: #{format_int(ps[:tested_by_main])} (#{format('%.1f%%', ps[:sync_pct])}) | " \
          "Imported by #{consumer}: #{format_int(ps[:imported_by_main])} (#{format('%.2f%%', ps[:yield_pct])} of tested) | " \
          "Rejected by #{consumer}: #{format_int(ps[:rejected_by_main])} | " \
          "Pending backlog: #{format_int(ps[:unsynced_backlog])}"
        when :foreign_queue
          "#{f[:name]} → #{consumer} (-F foreign queue: #{format_int(ps[:peer_total])}) — " \
          "Scanned (mtime watermark): #{format_int(ps[:cursor])} (#{format('%.1f%%', ps[:sync_pct])}) | " \
          "Tested by #{consumer}: #{format_int(ps[:tested_by_main])} | " \
          "Imported by #{consumer}: #{format_int(ps[:imported_by_main])} (#{format('%.2f%%', ps[:yield_pct])} of tested) | " \
          "Rejected by #{consumer}: #{format_int(ps[:rejected_by_main])} | " \
          "Unsynced backlog: #{format_int(ps[:unsynced_backlog])}"
        when :shadow_peer
          "#{f[:name]} → #{consumer} (#{consumer}/.synced/ijon_peer, queue: #{format_int(ps[:peer_total])}) — " \
          "Cursor: #{format_int(ps[:cursor])} (#{format('%.1f%%', ps[:sync_pct])}) | " \
          "Tested by #{consumer}: #{format_int(ps[:tested_by_main])} | " \
          "Imported by #{consumer}: #{format_int(ps[:imported_by_main])} (#{format('%.2f%%', ps[:yield_pct])} of tested) | " \
          "Rejected by #{consumer}: #{format_int(ps[:rejected_by_main])} | " \
          "Unsynced backlog: #{format_int(ps[:unsynced_backlog])}"
        else
          "#{f[:name]} → #{consumer} (#{consumer}/.synced/#{f[:name]}, queue: #{format_int(ps[:peer_total])}) — " \
          "Cursor: #{format_int(ps[:cursor])} (#{format('%.1f%%', ps[:sync_pct])}) | " \
          "Tested by #{consumer}: #{format_int(ps[:tested_by_main])} | " \
          "Imported by #{consumer}: #{format_int(ps[:imported_by_main])} (#{format('%.2f%%', ps[:yield_pct])} of tested) | " \
          "Rejected by #{consumer}: #{format_int(ps[:rejected_by_main])} | " \
          "Skipped (sync:#{consumer}): #{format_int(ps[:skipped_from_main])} | " \
          "Unsynced backlog: #{format_int(ps[:unsynced_backlog])}"
        end
  route_suffix = (ps[:sync_mode] == :foreign_seeds || ps[:sync_mode] == :foreign_queue) ? " (-F)" : ""
  <<~HTML
    <div class="sync-row" title="#{CGI.escapeHTML(tip)}" onclick="selectTab('#{CGI.escapeHTML(f[:name])}')">
      <div class="sync-peer">
        <span class="legend-dot" style="background:#{f[:color]}"></span>
        <strong>#{CGI.escapeHTML(f[:name])}</strong>
        <span class="muted" style="font-size:0.75rem;font-weight:400">&rarr; #{CGI.escapeHTML(consumer)}#{route_suffix}</span>
      </div>
      <div class="sync-bar-wrap">
        <div class="sync-bar">
          <div class="sync-seg sync-seg-imported" style="width:#{imp_w}%"></div>
          <div class="sync-seg sync-seg-rejected" style="width:#{rej_w}%"></div>
          <div class="sync-seg sync-seg-skipped" style="width:#{skp_w}%"></div>
          <div class="sync-seg sync-seg-unsynced" style="width:#{uns_w}%"></div>
        </div>
      </div>
      <div class="sync-stat">
        <span class="sync-primary">#{format_int(ps[:cursor])} / #{format_int(ps[:peer_total])}</span>
        <span class="sync-pct">(#{format("%.0f%%", ps[:sync_pct])})</span>
      </div>
      <div class="sync-stat">
        <span class="sync-imported">+#{format_int(ps[:imported_by_main])}</span>
        <span class="sync-secondary">/ #{format_int(ps[:tested_by_main])} tested (#{format("%.1f%%", ps[:yield_pct])})</span>
      </div>
    </div>
  HTML
end.join("\n")

peer_sync_card_html = if peer_sync_by_name.any?
  main_feeds = peer_sync_by_name.select { |_k, ps| ps[:consumer_name] == main_name }.values
  upstream_feeds = peer_sync_by_name.reject { |_k, ps| ps[:consumer_name] == main_name }
  total_main_tested = main_feeds.sum { |ps| ps[:tested_by_main] }
  total_main_imported = main_feeds.sum { |ps| ps[:imported_by_main] }
  total_main_backlog = main_feeds.sum { |ps| ps[:unsynced_backlog] }
  overall_yield = total_main_tested > 0 ? (total_main_imported * 100.0 / total_main_tested) : 0.0
  upstream_summary = upstream_feeds.map do |src_name, ps|
    "; <code>#{CGI.escapeHTML(src_name)} &rarr; #{CGI.escapeHTML(ps[:consumer_name])}</code>: " \
      "<strong>+#{format_int(ps[:imported_by_main])}</strong> / <strong>#{format_int(ps[:tested_by_main])}</strong> " \
      "(<strong>#{format('%.2f%%', ps[:yield_pct])}</strong> yield)"
  end.join
  <<~HTML
    <div class="chart-card sync-overview-card">
      <div class="chart-header">
        <div>
          <h3>Queue &amp; Foreign Sync Snapshot</h3>
          <p class="chart-sub">How far each source has been scanned by its consumer via foreign sync (<code>-F</code>) or peer sync (<code>#{CGI.escapeHTML(main_name)}/.synced/&lt;peer&gt;</code>), and how many inputs yielded novel coverage vs. were rejected or skipped (into <code>#{CGI.escapeHTML(main_name)}</code>: <strong>+#{format_int(total_main_imported)}</strong> imported / <strong>#{format_int(total_main_tested)}</strong> tested = <strong>#{format("%.2f%%", overall_yield)}</strong> yield, <strong>#{format_int(total_main_backlog)}</strong> unsynced backlog#{upstream_summary})</p>
        </div>
        <div class="chart-legend">
          <span class="legend-item"><span class="legend-dot" style="background:#34d399"></span><span class="legend-name">Imported (Novel)</span></span>
          <span class="legend-item"><span class="legend-dot" style="background:#3b82f6"></span><span class="legend-name">Tested &amp; Rejected</span></span>
          <span class="legend-item"><span class="legend-dot" style="background:#475569"></span><span class="legend-name">Skipped (sync:#{CGI.escapeHTML(main_name)})</span></span>
          <span class="legend-item"><span class="legend-dot" style="background:#1e293b;border:1px solid #475569"></span><span class="legend-name">Unsynced Backlog</span></span>
        </div>
      </div>
      <div class="sync-rows-head">
        <div>Source &rarr; Consumer</div>
        <div>Sync Breakdown</div>
        <div style="text-align:right">Scanned / Total</div>
        <div style="text-align:right">Imported / Tested (Yield)</div>
      </div>
      <div class="sync-rows">
        #{peer_sync_rows_html}
      </div>
    </div>
  HTML
else
  ""
end

FUZZ_OPT_VERSIONS = ["3.3", "3.4", "3.5", "4.1"].freeze
FUZZ_OPT_ENCODINGS = ["UTF-8", "ASCII-8BIT", "US-ASCII", "Windows-31J", "EUC-JP", "UTF-8-MAC", "ISO-8859-1", "Shift_JIS"].freeze
FUZZ_OPT_EXTREME_LINES = [2_147_483_647, 2_147_483_643, -2_147_483_648, 0].freeze
FUZZ_OPT_STACK_BUDGETS = ["SIZE_MAX", "0", "512", "4096"].freeze
FUZZ_OPT_SCOPE_BASE_LOCALS = [["a", "foo"], ["b", "it"], ["c", "_1"]].freeze
FUZZ_OPT_CMD_CHARS = [[0x01, "a"], [0x02, "e"], [0x04, "l"], [0x08, "n"], [0x10, "p"], [0x20, "x"]].freeze
FUZZ_OPT_FWD_CHARS = [[0x01, "p"], [0x02, "k"], [0x04, "b"], [0x08, "a"]].freeze

def decode_fuzz_header(raw)
  return nil if raw.nil? || raw.bytesize < 4

  b0, b1, b2, b3 = raw.bytes[0, 4]
  ver = FUZZ_OPT_VERSIONS[b2 & 0x03]
  has_limit_opts = (b1 & 0x80) != 0
  start_line = has_limit_opts ? FUZZ_OPT_EXTREME_LINES[(b3 >> 4) & 0x03] : [b3].pack("C").unpack1("c")
  scopes = (b2 >> 2) & 0x03
  fwd = (b2 >> 4) & 0x0f

  flags = ["v#{ver}"]
  flags << "stream" if (b0 & 0x40) != 0
  flags << "line=#{start_line}" if start_line != 1
  if (b0 & 0x80) != 0
    flags << "enc=#{FUZZ_OPT_ENCODINGS[b3 & 0x07]}"
    flags << "shebang_cb" if (b3 & 0x08) != 0
    flags << "scope0_empty" if scopes > 0 && (b3 & 0x10) != 0
  end
  flags << "stack_budget=#{FUZZ_OPT_STACK_BUDGETS[(b3 >> 6) & 0x03]}" if has_limit_opts
  flags << "scopes=#{scopes}" if scopes > 0
  if fwd > 0
    fwd_scope = scopes > 0 ? ((b0 & 0x80) != 0 ? (b3 % scopes) : (scopes - 1)) : nil
    flags << (fwd_scope ? "fwd[#{fwd_scope}]=0x#{fwd.to_s(16)}" : "fwd=0x#{fwd.to_s(16)}")
  end
  flags << "freeze" if (b0 & 1) != 0
  flags << "partial" if (b0 & 2) != 0
  flags << "comments" if (b0 & 4) != 0
  flags << "enc_lock" if (b0 & 8) != 0
  flags << ((b0 & 32) != 0 ? "frozen_lit=true" : "frozen_lit=false") if (b0 & 16) != 0
  cmd = []
  cmd << "-a" if (b1 & 0x01) != 0
  cmd << "-e" if (b1 & 0x02) != 0
  cmd << "-l" if (b1 & 0x04) != 0
  cmd << "-n" if (b1 & 0x08) != 0
  cmd << "-p" if (b1 & 0x10) != 0
  cmd << "-x" if (b1 & 0x20) != 0
  flags << cmd.join if cmd.any?
  flags << "main" if (b1 & 0x40) != 0
  flags.join(", ")
end

def encode_loupe_scope_local(bytes)
  if bytes.match?(/\A[A-Za-z0-9_]+\z/n)
    bytes
  else
    "~#{Base64.urlsafe_encode64(bytes, padding: false)}"
  end
end

def build_prism_loupe_url(raw)
  return nil if raw.nil? || raw.empty?
  if raw.bytesize < 4
    return "#{PRISM_LOUPE_BASE_URL}?code=#{CGI.escape(Base64.strict_encode64(raw))}"
  end

  b0, b1, b2, b3 = raw.bytes[0, 4]
  source = raw.bytesize > 4 ? raw.byteslice(4..) : "".b
  has_encoding_opts = (b0 & 0x80) != 0
  has_limit_opts = (b1 & 0x80) != 0

  params = [["code", Base64.strict_encode64(source)]]
  params << ["enc", FUZZ_OPT_ENCODINGS[b3 & 0x07]] if has_encoding_opts
  params << ["ruby_ver", FUZZ_OPT_VERSIONS[b2 & 0x03]]

  start_line = has_limit_opts ? FUZZ_OPT_EXTREME_LINES[(b3 >> 4) & 0x03] : [b3].pack("C").unpack1("c")
  params << ["line", start_line.to_s] if start_line != 1

  cmd = FUZZ_OPT_CMD_CHARS.filter_map { |bit, ch| ch if (b1 & bit) != 0 }.join
  params << ["cmd", cmd] unless cmd.empty?

  params << ["main", "1"] if (b1 & 0x40) != 0
  params << ["partial", "1"] if (b0 & 0x02) != 0
  params << ["freeze", "1"] if (b0 & 0x01) != 0
  params << ["comments", "1"] if (b0 & 0x04) != 0
  params << ["enc_lock", "1"] if (b0 & 0x08) != 0
  params << ["frozen_lit", (b0 & 0x20) != 0 ? "1" : "0"] if (b0 & 0x10) != 0
  params << ["stream", "1"] if (b0 & 0x40) != 0

  if has_encoding_opts
    params << ["filepath", "fuzz.rb"]
    params << ["shebang_cb", "1"] if (b3 & 0x08) != 0
  end

  if has_limit_opts
    budget = FUZZ_OPT_STACK_BUDGETS[(b3 >> 6) & 0x03]
    params << ["budget", budget] unless budget == "SIZE_MAX"
  end

  scopes_count = (b2 >> 2) & 0x03
  if scopes_count > 0
    fwd_bits = (b2 >> 4) & 0x0f
    fwd_chars = FUZZ_OPT_FWD_CHARS.filter_map { |bit, ch| ch if (fwd_bits & bit) != 0 }.join
    forwarding_scope = has_encoding_opts ? (b3 % scopes_count) : (scopes_count - 1)

    scope_segments = (0...scopes_count).map do |i|
      locals_count = (i == 0 && source.bytesize > 0) ? 3 : 2
      locals_count = 0 if i == 0 && has_encoding_opts && (b3 & 0x10) != 0
      locals = (0...[2, locals_count].min).map { |j| FUZZ_OPT_SCOPE_BASE_LOCALS[i][j].b }
      locals << source.byteslice(0, [source.bytesize, 4].min) if locals_count == 3
      encoded_locals = locals.map { |loc| encode_loupe_scope_local(loc) }
      fwd = (i == forwarding_scope) ? fwd_chars : ""
      if encoded_locals.empty?
        fwd.empty? ? ":" : "#{fwd}:"
      else
        fwd.empty? ? encoded_locals.join(",") : "#{fwd}:#{encoded_locals.join(",")}"
      end
    end
    params << ["scopes", scope_segments.join(";")]
  end

  query = params.map { |k, v| "#{k}=#{CGI.escape(v)}" }.join("&")
  "#{PRISM_LOUPE_BASE_URL}?#{query}"
end

def parse_testcase_file(path, max_preview_bytes = 512)
  return { preview: nil, opts_desc: nil, loupe_url: nil } unless path && File.file?(path)

  raw = File.binread(path) || "".b
  opts_desc = decode_fuzz_header(raw)
  ruby_bytes = raw.bytesize > 4 ? raw.byteslice(4..) : "".b
  loupe_url = build_prism_loupe_url(raw)

  slice = ruby_bytes.bytesize > max_preview_bytes ? ruby_bytes.byteslice(0, max_preview_bytes) : ruby_bytes
  formatted = slice.bytes.map do |b|
    case b
    when 0x0A then "\n"
    when 0x09 then "\t"
    when 0x20..0x7E then b.chr
    else format("\\x%02X", b)
    end
  end.join
  formatted << "\n... (#{ruby_bytes.bytesize - max_preview_bytes} more bytes)" if ruby_bytes.bytesize > max_preview_bytes

  {
    preview: formatted,
    opts_desc: opts_desc,
    loupe_url: loupe_url
  }
rescue StandardError
  { preview: nil, opts_desc: nil, loupe_url: nil }
end

def describe_afl_step_op(base, kind)
  return "Root Corpus Seed" if kind == "corpus"
  return "Grammar Generated Seed (lrama-fuzz)" if kind == "seed"

  parts = []
  is_sync = false
  if base =~ /\Aid:\d+(?:,sig:\d+)?,sync:([^,]+),src:(?:id:)?([^,+]+)/
    is_sync = true
    raw_src = $1
    src_w = normalize_sync_source(raw_src)
    is_foreign = raw_src != src_w || src_w == "grammar"
    parts << if src_w == "grammar"
               "Foreign Sync (-F) from grammar (#{$2})"
             elsif is_foreign
               "Foreign Sync (-F) from #{src_w} (id:#{$2})"
             else
               "Peer Sync from #{src_w} (id:#{$2})"
             end
  elsif base =~ /\Aid:\d+(?:,sig:\d+)?,src:(\d+)\+(\d+)/
    parts << "Splice (id:#{$1} + id:#{$2})"
  elsif base =~ /\Aid:\d+(?:,sig:\d+)?,src:lrama-fuzz\b/
    parts << "Grammar Evolution (lrama-fuzz)"
  elsif base =~ /\Aid:\d+(?:,time:\d+,execs:\d+)?,orig:([^,]+)/
    parts << "Initial Seed (#{$1})"
  end
  if !is_sync && base =~ /,op:([^,]+)/
    op = $1
    rep = base[/,rep:(\d+)/, 1]
    pos = base[/,pos:(\d+)/, 1]
    detail = op
    detail += " (rep:#{rep})" if rep
    detail += " @ byte #{pos}" if pos
    parts << "Mutate: #{detail}"
  end
  parts << "+cov" if base.include?(",+cov")
  if base =~ /\Aid:\d+,sig:(\d+),/
    parts << "CRASH (sig:#{$1})"
  elsif kind == "hangs"
    parts << "HANG"
  end
  parts.empty? ? kind : parts.join(" &bull; ")
end

def hydrate_chain_steps(chain)
  hydrated = chain.map do |s|
    p = s[:path]
    sz = (p && File.file?(p)) ? File.size(p) : nil
    parsed = parse_testcase_file(p)
    s.merge(
      size: sz,
      op_desc: describe_afl_step_op(s[:base].to_s, s[:kind].to_s),
      preview: parsed[:preview],
      opts_desc: parsed[:opts_desc],
      loupe_url: parsed[:loupe_url]
    )
  end
  # If Step 0 is a virtual root node (corpus or grammar) and Step 1 is its imported seed copy, share Step 1's source/metadata
  if hydrated.size >= 2
    hydrated[0][:preview] ||= hydrated[1][:preview]
    hydrated[0][:opts_desc] ||= hydrated[1][:opts_desc]
    hydrated[0][:size] ||= hydrated[1][:size]
    hydrated[0][:loupe_url] ||= hydrated[1][:loupe_url]
  end
  hydrated
end

def analyze_fleet_lineage(afl_dir)
  fuzz_root = File.dirname(afl_dir)
  corpus_dir = File.join(fuzz_root, "corpus")
  seeds_dirs = ["/tmp/afl-tmpdir/grammar/seeds", File.join(fuzz_root, "seeds")].select { |d| Dir.exist?(d) }
  seed_by_prefix = {}
  seeds_dirs.each do |sd|
    Dir.children(sd).each do |sf|
      next if sf.start_with?(".")
      full = File.join(sd, sf)
      next unless File.file?(full)
      seed_by_prefix[sf] ||= full
      seed_by_prefix[sf[0, 20]] ||= full if sf.length > 20
    end
  rescue StandardError
    nil
  end
  roots = worker_root_dirs(afl_dir)

  q_index = {}
  roots.flat_map { |r| Dir.glob(File.join(r, "*/queue")) }.each do |qdir|
    next if File.symlink?(qdir)

    w = File.basename(File.dirname(qdir))
    Dir.glob(File.join(qdir, "id:*")).each do |p|
      next unless File.file?(p)
      id = File.basename(p)[/\Aid:(\d+)/, 1]
      q_index[[w, id.to_i]] = p if id
    end
  end

  rank_parent_chain = lambda do |ch|
    return [-1, 0, 0] if ch.nil? || ch.empty?
    is_grammar = ch.first[:worker] == "grammar" ? 1 : 0
    distinct_workers = ch.map { |s| s[:worker] }.uniq.size
    [is_grammar, distinct_workers, ch.size]
  end

  memo = {}
  trace_chain = lambda do |path, seen = {}|
    return memo[path] if memo.key?(path)
    return [] if seen[path]

    seen = seen.merge(path => true)
    base = File.basename(path)
    w = File.basename(File.dirname(File.dirname(path)))
    kind = File.basename(File.dirname(path))
    step = { path: path, worker: w, kind: kind, base: base, id: base[/\Aid:(\d+)/, 1] }

    chain = if base =~ /\Aid:\d+(?:,sig:\d+)?,sync:seeds(?:_\d+)?,src:([^,+]+)/ ||
               base =~ /\Aid:\d+(?:,sig:\d+)?,sync:grammar(?:_\d+)?,src:([^,+]+)/ ||
               base =~ /\Aid:\d+(?:,time:\d+,execs:\d+)?,orig:(seed_[^,]+)/
              seed_id = $1
              root_path = seed_by_prefix[seed_id] || path
              [{ path: root_path, worker: "grammar", kind: "seed", base: seed_id, id: seed_id }, step]
            elsif base =~ /\Aid:\d+(?:,sig:\d+)?,sync:([^,]+),src:(?:id:)?(\d+)/
              peer = normalize_sync_source($1)
              src_id = $2
              parent = q_index[[peer, src_id.to_i]]
              parent ? (trace_chain.call(parent, seen) + [step]) : [{ path: path, worker: peer, kind: "sync_root", base: "id:#{src_id}", id: src_id }, step]
            elsif base =~ /\Aid:\d+(?:,sig:\d+)?,src:(\d+)(?:\+(\d+))?/
              p1 = q_index[[w, $1.to_i]]
              p2 = $2 ? q_index[[w, $2.to_i]] : nil
              ch1 = p1 ? trace_chain.call(p1, seen) : nil
              ch2 = p2 ? trace_chain.call(p2, seen) : nil
              best = if ch1 && ch2
                       (rank_parent_chain.call(ch2) <=> rank_parent_chain.call(ch1)) > 0 ? ch2 : ch1
                     else
                       ch1 || ch2
                     end
              best && !best.empty? ? (best + [step]) : [step]
            elsif base =~ /\Aid:\d+(?:,time:\d+,execs:\d+)?,orig:([^,]+)/
              orig_name = $1
              corpus_file = File.join(corpus_dir, orig_name)
              root_path = File.file?(corpus_file) ? corpus_file : path
              [{ path: root_path, worker: "corpus", kind: "corpus", base: orig_name, id: orig_name }, step]
            else
              [step]
            end
    memo[path] = chain if kind == "queue"
    chain
  end

  # 1. Grammar queue propagation pathways across the fleet
  grammar_queue_pathways = {}
  total_grammar_queue_items = 0
  q_index.each_value do |qpath|
    ch = trace_chain.call(qpath)
    next unless ch.first && ch.first[:worker] == "grammar"
    total_grammar_queue_items += 1
    hops = []
    ch.each { |s| hops << s[:worker] if hops.empty? || hops.last != s[:worker] }
    qp_entry = (grammar_queue_pathways[hops] ||= {
      hops: hops,
      count: 0,
      sample_raw_chain: ch
    })
    qp_entry[:count] += 1
    qp_entry[:sample_raw_chain] = ch if ch.size > qp_entry[:sample_raw_chain].size
  end

  # 2. Crash & hang lineage across all workers
  crash_files = roots.flat_map { |r| Dir.glob(File.join(r, "*/{crashes,hangs}/id:*")) }.select do |p|
    File.file?(p) && !p.end_with?(".bt", ".min", ".md")
  end.sort

  pathways = {}
  grammar_seed_crashes = {}
  corpus_roots = Hash.new(0)
  grammar_roots = Hash.new(0)
  total_grammar_crashes = 0
  total_corpus_crashes = 0
  total_multi_worker_crashes = 0

  crash_files.each do |cpath|
    ch = trace_chain.call(cpath)
    next if ch.empty?

    hops = []
    ch.each { |s| hops << s[:worker] if hops.empty? || hops.last != s[:worker] }
    root_origin = hops.first
    root_seed = ch.first[:base].to_s
    crash_worker = hops.last
    parent_step = ch[-2] || ch.first

    # Number of distinct fuzzer workers (excluding "corpus" and "grammar" seed origins)
    fuzzer_hops = hops.reject { |h| h == "corpus" || h == "grammar" }.uniq
    total_multi_worker_crashes += 1 if fuzzer_hops.size >= 2

    if root_origin == "grammar"
      total_grammar_crashes += 1
      grammar_roots[root_seed] += 1
      g_entry = (grammar_seed_crashes[root_seed] ||= {
        seed: root_seed,
        count: 0,
        hops: hops,
        parents: {},
        sample_raw_chain: ch
      })
      g_entry[:count] += 1
      g_entry[:parents][[parent_step[:worker], parent_step[:id]]] = true
      if ch.size > g_entry[:sample_raw_chain].size
        g_entry[:sample_raw_chain] = ch
        g_entry[:hops] = hops
      end
    elsif root_origin == "corpus"
      total_corpus_crashes += 1
      corpus_roots[root_seed] += 1
    end

    p_entry = (pathways[hops] ||= {
      hops: hops,
      root_origin: root_origin,
      crash_worker: crash_worker,
      fuzzer_hop_count: fuzzer_hops.size,
      count: 0,
      parents: {},
      roots: Hash.new(0),
      max_steps: 0,
      sample_raw_chain: ch
    })
    p_entry[:count] += 1
    p_entry[:parents][[parent_step[:worker], parent_step[:id]]] = true
    p_entry[:roots][root_seed] += 1
    if ch.size > p_entry[:max_steps]
      p_entry[:max_steps] = ch.size
      p_entry[:sample_raw_chain] = ch
    end
  end

  pathways.each_value do |p|
    p[:sample_chain] = hydrate_chain_steps(p[:sample_raw_chain])
    p.delete(:sample_raw_chain)
  end
  grammar_seed_crashes.each_value do |g|
    g[:sample_chain] = hydrate_chain_steps(g[:sample_raw_chain])
    g.delete(:sample_raw_chain)
  end
  grammar_queue_pathways.each_value do |qp|
    qp[:sample_chain] = hydrate_chain_steps(qp[:sample_raw_chain])
    qp.delete(:sample_raw_chain)
  end

  sorted_pathways = pathways.values.sort_by do |p|
    [p[:root_origin] == "grammar" ? 0 : 1, -p[:count], -p[:fuzzer_hop_count], p[:hops].join("->")]
  end

  {
    total_crashes: crash_files.size,
    total_grammar_crashes: total_grammar_crashes,
    total_corpus_crashes: total_corpus_crashes,
    total_multi_worker_crashes: total_multi_worker_crashes,
    unique_grammar_crash_seeds: grammar_roots.size,
    unique_corpus_crash_seeds: corpus_roots.size,
    total_grammar_queue_items: total_grammar_queue_items,
    grammar_queue_pathways: grammar_queue_pathways.values.sort_by { |qp| -qp[:count] },
    pathways: sorted_pathways,
    grammar_seed_crashes: grammar_seed_crashes.values.sort_by { |g| [-g[:count], g[:seed]] }
  }
rescue StandardError
  {
    total_crashes: 0,
    total_grammar_crashes: 0,
    total_corpus_crashes: 0,
    total_multi_worker_crashes: 0,
    unique_grammar_crash_seeds: 0,
    unique_corpus_crash_seeds: 0,
    total_grammar_queue_items: 0,
    grammar_queue_pathways: [],
    pathways: [],
    grammar_seed_crashes: []
  }
end

def render_pathway_pills(hops, color_by_name)
  hops.map do |w|
    color = if w == "corpus"
              "#fbbf24"
            elsif w == "grammar"
              color_by_name["grammar"] || "#34d399"
            else
              color_by_name[w] || "#9ca3af"
            end
    star = w == "grammar" ? "&#9733; " : ""
    if color_by_name.key?(w)
      %(<span class="hop-pill clickable-pill" onclick="event.stopPropagation(); selectTab('#{CGI.escapeHTML(w)}')" title="Open #{CGI.escapeHTML(w)} tab"><span class="legend-dot" style="background:#{color}"></span>#{star}#{CGI.escapeHTML(w)}</span>)
    elsif w == "corpus"
      %(<span class="hop-pill" title="Initial Seed Corpus"><span class="legend-dot" style="background:#{color}"></span>corpus</span>)
    else
      %(<span class="hop-pill"><span class="legend-dot" style="background:#{color}"></span>#{CGI.escapeHTML(w)}</span>)
    end
  end.join('<span class="hop-arrow">&rarr;</span>')
end

def render_evolution_chain_steps(chain, color_by_name)
  return "" if chain.nil? || chain.empty?

  steps_html = chain.each_with_index.map do |s, idx|
    w = s[:worker].to_s
    color = if w == "corpus"
              "#fbbf24"
            elsif w == "grammar"
              color_by_name["grammar"] || "#34d399"
            else
              color_by_name[w] || "#9ca3af"
            end
    is_last = (idx == chain.size - 1)
    step_cls = if idx == 0
                 "evo-step evo-step-root"
               elsif is_last && (s[:kind] == "crashes" || s[:kind] == "hangs")
                 "evo-step evo-step-crash"
               else
                 "evo-step"
               end
    opts_badge = s[:opts_desc] ? %(<span class="sched-pill" title="4-byte fuzz_options_t header (decoded into pm_options_t query params for Prism Loupe)">opts: #{CGI.escapeHTML(s[:opts_desc])}</span>) : ""
    size_badge = s[:size] ? %(<span class="evo-size">#{format_int(s[:size])} B</span>) : ""
    loupe_btn = if s[:loupe_url]
                  %(<a class="cov-link" href="#{CGI.escapeHTML(s[:loupe_url])}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="Animate this step's Ruby parse in Prism Loupe with its exact pm_options_t">Animate in Prism Loupe &nearr;</a>)
                else
                  ""
                end
    preview_block = if s[:preview]
                      %(<pre class="evo-preview">#{CGI.escapeHTML(s[:preview])}</pre>)
                    else
                      ""
                    end
    <<~STEP
      <div class="#{step_cls}">
        <div class="evo-step-head">
          <span class="evo-step-num">Step #{idx}</span>
          <span class="hop-pill"><span class="legend-dot" style="background:#{color}"></span>#{CGI.escapeHTML(w)}</span>
          <code class="evo-fname">#{CGI.escapeHTML(s[:base].to_s)}</code>
          <span class="evo-op">#{s[:op_desc]}</span>
          #{opts_badge}
          <span style="margin-left:auto;display:inline-flex;align-items:center;gap:10px;">
            #{size_badge}
            #{loupe_btn}
          </span>
        </div>
        #{preview_block}
      </div>
    STEP
  end.join('<div class="evo-connector">&darr;</div>')

  %(<div class="evo-chain-wrap">#{steps_html}</div>)
end

fleet_lineage = analyze_fleet_lineage(afl_dir)

def render_crash_lineage_table(pathways, total_crashes, color_by_name, id_prefix:, title:, subtitle:, filter_controls: false)
  return "" if pathways.nil? || pathways.empty?

  max_count = [pathways.map { |p| p[:count] }.max.to_i, 1].max
  rows_html = pathways.each_with_index.map do |p, idx|
    drawer_id = "#{id_prefix}-drawer-#{idx}"
    top_root, top_root_cnt = p[:roots].max_by { |_, c| c } || ["-", 0]
    pct_of_total = total_crashes > 0 ? (p[:count] * 100.0 / total_crashes) : 0.0
    bar_w = (p[:count] * 100.0 / max_count).round(1)
    bar_color = p[:root_origin] == "grammar" ? "#34d399" : "#fb7185"
    row_tags = []
    row_tags << "grammar" if p[:root_origin] == "grammar"
    row_tags << "multihop" if p[:fuzzer_hop_count] >= 2
    row_tags << "singlehop" if p[:fuzzer_hop_count] < 2
    crash_step = (p[:sample_chain] || []).last || {}
    loupe_cell = if crash_step[:loupe_url]
                   %(<a class="cov-link" href="#{CGI.escapeHTML(crash_step[:loupe_url])}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="Animate representative crash in Prism Loupe">Prism Loupe &nearr;</a>)
                 else
                   "<span class=\"muted\">&mdash;</span>"
                 end

    <<~ROW
      <tr class="clickable-row lineage-row" data-lineage-prefix="#{id_prefix}" data-lineage-tags="#{row_tags.join(' ')}" onclick="toggleHunkDrawer('#{drawer_id}')">
        <td>
          <span id="caret-#{drawer_id}" class="muted" style="display:inline-block;width:14px;">&#9656;</span>
          #{render_pathway_pills(p[:hops], color_by_name)}
        </td>
        <td class="num">
          <div style="display:flex;align-items:center;justify-content:flex-end;gap:8px;">
            <div style="width:70px;height:7px;background:#0b0f19;border:1px solid #1f2937;border-radius:4px;overflow:hidden;">
              <div style="width:#{bar_w}%;height:100%;background:#{bar_color};"></div>
            </div>
            <strong>#{format_int(p[:count])}</strong>
            <span class="muted" style="min-width:44px;text-align:right;">(#{format("%.1f%%", pct_of_total)})</span>
          </div>
        </td>
        <td class="num">#{format_int(p[:parents].size)}</td>
        <td class="num">#{format_int(p[:roots].size)}</td>
        <td class="num">#{p[:max_steps]} steps</td>
        <td><code>#{CGI.escapeHTML(top_root.to_s)}</code> <span class="muted">(#{format_int(top_root_cnt)})</span></td>
        <td class="num">#{loupe_cell}</td>
      </tr>
      <tr id="#{drawer_id}" class="hunk-drawer-row" style="display:none;">
        <td colspan="7" class="hunk-drawer-cell">
          <div class="origin-hunk-title">
            <span>Representative Testcase Evolution: #{render_pathway_pills(p[:hops], color_by_name)}</span>
            <span class="muted">#{format_int(p[:count])} crashes from #{format_int(p[:parents].size)} parent queue items (#{format_int(p[:roots].size)} root seeds)</span>
          </div>
          #{render_evolution_chain_steps(p[:sample_chain], color_by_name)}
        </td>
      </tr>
    ROW
  end.join("\n")

  controls_html = if filter_controls
                    <<~CTRL
                      <div style="display:flex;gap:6px;flex-wrap:wrap;">
                        <button class="cov-btn" onclick="filterLineageRows('#{id_prefix}', 'all', this)">All Pathways (#{pathways.size})</button>
                        <button class="cov-btn cov-btn-secondary" onclick="filterLineageRows('#{id_prefix}', 'grammar', this)">&#9733; Grammar Rooted</button>
                        <button class="cov-btn cov-btn-secondary" onclick="filterLineageRows('#{id_prefix}', 'multihop', this)">Multi-Fuzzer Hops (&ge;2)</button>
                        <button class="cov-btn cov-btn-secondary" data-expand-label="Expand All Evolution Chains" data-collapse-label="Collapse All Evolution Chains" onclick="toggleAllHunks(this, '#{id_prefix}-drawer-')">Expand All Evolution Chains</button>
                      </div>
                    CTRL
                  else
                    <<~CTRL
                      <div>
                        <button class="cov-btn cov-btn-secondary" data-expand-label="Expand All Evolution Chains" data-collapse-label="Collapse All Evolution Chains" onclick="toggleAllHunks(this, '#{id_prefix}-drawer-')">Expand All Evolution Chains</button>
                      </div>
                    CTRL
                  end

  <<~HTML
    <div class="table-card" style="margin-top: 18px;">
      <div class="table-card-header">
        <div>
          <h3>#{title}</h3>
          <p class="chart-sub">#{subtitle}</p>
        </div>
        #{controls_html}
      </div>
      <table>
        <thead>
          <tr>
            <th>Lineage Pathway (Origin &rarr; Worker Hops &rarr; Crash Discoverer)</th>
            <th class="num">Crashes</th>
            <th class="num">Queue Parents</th>
            <th class="num">Root Seeds</th>
            <th class="num">Max Depth</th>
            <th>Top Root Seed (Crashes)</th>
            <th class="num">Parse Animator</th>
          </tr>
        </thead>
        <tbody id="#{id_prefix}-tbody">
          #{rows_html}
        </tbody>
      </table>
    </div>
  HTML
end

def render_grammar_lineage_section(fleet_lineage, color_by_name)
  q_paths = fleet_lineage[:grammar_queue_pathways] || []
  g_crashes = fleet_lineage[:grammar_seed_crashes] || []
  return "" if q_paths.empty? && g_crashes.empty?

  q_pills_html = q_paths.map do |qp|
    hops = qp.is_a?(Hash) ? qp[:hops] : qp[0]
    cnt = qp.is_a?(Hash) ? qp[:count] : qp[1]
    sample_last = qp.is_a?(Hash) ? (qp[:sample_chain] || []).last : nil
    loupe_a = if sample_last && sample_last[:loupe_url]
                %(<a class="cov-link" style="margin-left:8px;font-size:0.74rem;" href="#{CGI.escapeHTML(sample_last[:loupe_url])}" target="_blank" rel="noopener" title="Animate sample queue testcase from this pathway in Prism Loupe">Prism Loupe &nearr;</a>)
              else
                ""
              end
    <<~PILL
      <div class="excl-pill" style="padding:4px 10px;">
        #{render_pathway_pills(hops, color_by_name)}
        <strong style="margin-left:6px;color:#34d399;">#{format_int(cnt)}</strong>
        #{loupe_a}
      </div>
    PILL
  end.join("\n")

  seed_rows_html = g_crashes.each_with_index.map do |g, idx|
    drawer_id = "gram-seed-crash-#{idx}"
    first_step = g[:sample_chain].first || {}
    last_step = g[:sample_chain].last || {}
    loupe_links = []
    if first_step[:loupe_url]
      loupe_links << %(<a class="cov-link" href="#{CGI.escapeHTML(first_step[:loupe_url])}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="Animate original grammar seed in Prism Loupe">Prism Loupe (Seed) &nearr;</a>)
    end
    if last_step[:loupe_url]
      loupe_links << %(<a class="cov-link" href="#{CGI.escapeHTML(last_step[:loupe_url])}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="Animate mutated crash input in Prism Loupe">Prism Loupe (Crash) &nearr;</a>)
    end
    sample_crash_short = last_step[:id] ? "#{last_step[:worker]} id:#{last_step[:id]}" : last_step[:base].to_s
    <<~ROW
      <tr class="clickable-row" onclick="toggleHunkDrawer('#{drawer_id}')">
        <td>
          <span id="caret-#{drawer_id}" class="muted" style="display:inline-block;width:14px;">&#9656;</span>
          <code>#{CGI.escapeHTML(g[:seed])}</code>
        </td>
        <td>#{render_pathway_pills(g[:hops], color_by_name)}</td>
        <td class="num"><strong class="text-danger">#{format_int(g[:count])}</strong></td>
        <td class="num">#{format_int(g[:parents].size)}</td>
        <td class="num">#{g[:sample_chain].size} steps</td>
        <td><code title="#{CGI.escapeHTML(last_step[:base].to_s)}">#{CGI.escapeHTML(sample_crash_short)}</code></td>
        <td class="num" style="white-space:nowrap;">#{loupe_links.join(" &bull; ")}</td>
      </tr>
      <tr id="#{drawer_id}" class="hunk-drawer-row" style="display:none;">
        <td colspan="7" class="hunk-drawer-cell">
          <div class="origin-hunk-title">
            <span>Grammar Seed <code>#{CGI.escapeHTML(g[:seed])}</code> &rarr; Crash Evolution</span>
            <span class="muted">#{format_int(g[:count])} crashes</span>
          </div>
          #{render_evolution_chain_steps(g[:sample_chain], color_by_name)}
        </td>
      </tr>
    ROW
  end.join("\n")

  crashes_table = if g_crashes.any?
                    <<~TBL
                      <table>
                        <thead>
                          <tr>
                            <th>Grammar Seed ID</th>
                            <th>Deepest Pathway</th>
                            <th class="num">Crashes</th>
                            <th class="num">Queue Intermediates</th>
                            <th class="num">Max Depth</th>
                            <th>Sample Crash</th>
                            <th class="num">Parse Animator</th>
                          </tr>
                        </thead>
                        <tbody>
                          #{seed_rows_html}
                        </tbody>
                      </table>
                    TBL
                  else
                    %(<div style="padding:12px 16px;" class="muted">No crashes traced to grammar seeds yet.</div>)
                  end

  grammar_paths = (fleet_lineage[:pathways] || []).select { |p| p[:hops].include?("grammar") }
  grammar_pathway_table = if grammar_paths.any?
                            render_crash_lineage_table(
                              grammar_paths,
                              grammar_paths.sum { |p| p[:count] },
                              color_by_name,
                              id_prefix: "w-lineage-grammar",
                              title: "Crash Lineage Involving <code>grammar</code> (#{format_int(fleet_lineage[:total_grammar_crashes])} Crashes from #{format_int(fleet_lineage[:unique_grammar_crash_seeds])} Seeds across #{grammar_paths.size} Pathways)",
                              subtitle: "Pathways where grammar-generated seeds were imported via -F foreign sync and mutated into crashes across the fuzzer fleet."
                            )
                          else
                            ""
                          end

  <<~HTML
    #{grammar_pathway_table}
    <div class="table-card" style="margin-top: 18px;">
      <div class="table-card-header">
        <div>
          <h3><span class="legend-dot" style="background:#{color_by_name['grammar'] || '#34d399'}"></span> Grammar Seed Fleet Propagation &amp; Per-Seed Crash Breakdown</h3>
          <p class="chart-sub">
            <strong>#{format_int(fleet_lineage[:total_grammar_queue_items])}</strong> queue testcases across the fleet and
            <strong class="#{fleet_lineage[:total_grammar_crashes] > 0 ? 'text-danger' : ''}">#{format_int(fleet_lineage[:total_grammar_crashes])} crashes</strong>
            (from <strong>#{format_int(fleet_lineage[:unique_grammar_crash_seeds])}</strong> generated seeds) trace their ancestry back to <code>grammar</code>.
            Click any seed row below to inspect the generated Ruby code and the mutation steps that triggered the crash, or open directly in Prism Loupe.
          </p>
        </div>
        <div>
          <button class="cov-btn cov-btn-secondary" data-expand-label="Expand All Seed Crash Chains" data-collapse-label="Collapse All Seed Crash Chains" onclick="toggleAllHunks(this, 'gram-seed-crash-')">Expand All Seed Crash Chains</button>
        </div>
      </div>
      <div style="padding: 12px 16px; border-bottom: 1px solid var(--panel-border);">
        <div class="kpi-label" style="margin-bottom:8px;">Queue Propagation Pathways Across Fleet (#{format_int(fleet_lineage[:total_grammar_queue_items])} queue entries rooted in grammar)</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;">
          #{q_pills_html}
        </div>
      </div>
      #{crashes_table}
    </div>
  HTML
end

overview_crash_lineage_html = if fleet_lineage[:total_crashes] > 0
  multi_pct = (fleet_lineage[:total_multi_worker_crashes] * 100.0 / fleet_lineage[:total_crashes]).round(1)
  render_crash_lineage_table(
    fleet_lineage[:pathways],
    fleet_lineage[:total_crashes],
    color_by_name,
    id_prefix: "ov-lineage",
    title: "Crash Lineage &amp; Multi-Worker Evolution (#{format_int(fleet_lineage[:total_crashes])} Crashes across #{fleet_lineage[:pathways].size} Pathways)",
    subtitle: "Backwards walk from every crash file through local mutations (src:) and peer syncs (sync:) to its root origin: " \
              "#{format_int(fleet_lineage[:total_grammar_crashes])} crashes from #{fleet_lineage[:unique_grammar_crash_seeds]} grammar seeds (#{format_int(fleet_lineage[:total_grammar_queue_items])} grammar-rooted queue items fleet-wide) &bull; " \
              "#{format_int(fleet_lineage[:total_corpus_crashes])} crashes from #{fleet_lineage[:unique_corpus_crash_seeds]} initial corpus seeds &bull; " \
              "#{format_int(fleet_lineage[:total_multi_worker_crashes])} (#{multi_pct}%) involved &ge;2 fuzzers. Click any pathway to view step-by-step testcase evolution.",
    filter_controls: true
  )
else
  ""
end

# Overview comparison charts
overview_chart_list = [
  render_svg_chart(
    title: "Edge Coverage (%)",
    subtitle: "Percentage of instrumented CFG edges reached over time (map_size)",
    y_format: :percent,
    zero_base: false,
    chart_id: "ov-cvg",
    series: afl_fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:map_size]] } } }
  ),
  render_svg_chart(
    title: "Edges Discovered",
    subtitle: "Absolute number of edges hit in each worker's coverage map (edges_found)",
    y_format: :int,
    zero_base: false,
    chart_id: "ov-edges",
    series: afl_fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:edges_found]] } } }
  ),
  render_svg_chart(
    title: "Corpus Size Growth",
    subtitle: "Total interesting inputs in queue per worker (corpus_count)",
    y_format: :compact,
    zero_base: true,
    chart_id: "ov-corpus",
    series: afl_fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:corpus_count]] } } }
  ),
  render_svg_chart(
    title: "Execution Throughput (execs/sec)",
    subtitle: "Instantaneous execution speed across workers",
    y_format: :rate,
    zero_base: true,
    chart_id: "ov-speed",
    series: afl_fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:execs_per_sec]] } } }
  ),
  render_svg_chart(
    title: "Cumulative Executions",
    subtitle: "Total target executions completed per worker (total_execs)",
    y_format: :compact,
    zero_base: true,
    chart_id: "ov-execs",
    series: afl_fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:total_execs]] } } }
  ),
  render_svg_chart(
    title: "Pending Favored Queue",
    subtitle: "Unfuzzed favored entries remaining per worker (pending_favs)",
    y_format: :compact,
    zero_base: true,
    chart_id: "ov-favs",
    series: afl_fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:pending_favs]] } } }
  ),
  render_svg_chart(
    title: "Synced Queue Items (Foreign Imports)",
    subtitle: "Cumulative queue entries imported from other fuzzers over time (sync:<source>)",
    y_format: :compact,
    zero_base: true,
    chart_id: "ov-synced",
    series: afl_fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:synced_count]] } } }
  ),
  render_svg_chart(
    title: "Locally Discovered Queue Items",
    subtitle: "Cumulative queue entries discovered by each worker's own mutations (excluding initial seeds & syncs)",
    y_format: :compact,
    zero_base: true,
    chart_id: "ov-local",
    series: afl_fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:local_count]] } } }
  )
]

if gen_fuzzers.any?
  overview_chart_list << render_svg_chart(
    title: "Grammar Seeds Imported (-F)",
    subtitle: "Cumulative grammar-generated seeds imported into the fuzzer queue via foreign sync",
    y_format: :int,
    fill_area: true,
    zero_base: true,
    chart_id: "ov-gen-imports",
    series: gen_fuzzers.map do |gf|
      ps = peer_sync_by_name[gf[:name]]
      intake = ps ? ps[:intake_fuzzer] : main_fuzzer
      imp_prefix = intake[:origins][:by_source][gf[:name]] || []
      {
        name: "#{gf[:name]} -> #{intake[:name]}",
        color: "#34d399",
        points: intake[:samples].map { |r| [r[:relative_time], lookup_prefix(imp_prefix, r[:corpus_count])] }
      }
    end
  )
  overview_chart_list << render_svg_chart(
    title: "Grammar File Creation Rate (files/sec)",
    subtitle: "Seed file creation rate over time (rolling and cumulative average)",
    y_format: :file_rate,
    zero_base: true,
    chart_id: "ov-gen-rate",
    series: gen_fuzzers.flat_map do |gf|
      [
        { name: "#{gf[:name]} (files/s)", color: gf[:color], points: gf[:samples].map { |r| [r[:relative_time], r[:files_per_sec]] } },
        { name: "#{gf[:name]} (avg)", color: "#38bdf8", points: gf[:samples].map { |r| [r[:relative_time], r[:avg_files_per_sec]] } }
      ]
    end
  )
end

overview_charts = overview_chart_list.join("\n")

cov_by_origin = {}
combined_cov = nil
corpus_cov = nil
if coverage_data
  combined_cov = coverage_data["combined"]
  (coverage_data["origins"] || []).each do |o|
    cov_by_origin[o["name"]] = o
  end
  corpus_cov = cov_by_origin["corpus"]
end

def highlight_branch_spans(code_str, branches)
  return CGI.escapeHTML(code_str) if branches.nil? || branches.empty?

  spans = branches.map do |b|
    c1 = b["col_start"].to_i
    c2 = b["col_end"].to_i
    next nil unless c1 > 0 && c2 > c1 && (c1 - 1) < code_str.length
    [c1 - 1, [c2 - 1, code_str.length].min, b["taken"].to_s]
  end.compact.uniq.sort_by { |s, e, _| [s, -e] }

  return CGI.escapeHTML(code_str) if spans.empty?

  # Merge or drop overlapping spans
  merged = []
  spans.each do |s, e, taken|
    if merged.empty? || s >= merged.last[1]
      merged << [s, e, taken]
    end
  end

  out = +""
  cursor = 0
  merged.each do |s, e, taken|
    out << CGI.escapeHTML(code_str[cursor...s]) if s > cursor
    cls = taken == "False" ? "hunk-br-span hunk-br-false" : "hunk-br-span hunk-br-true"
    out << %(<mark class="#{cls}">#{CGI.escapeHTML(code_str[s...e])}</mark>)
    cursor = e
  end
  out << CGI.escapeHTML(code_str[cursor..]) if cursor < code_str.length
  out
end

def render_exclusive_hunks_block(origin_name, origin_color, fname, hunks, show_origin_header: false, tab_link: false)
  return "" if hunks.nil? || hunks.empty?

  file_base_href = "../coverage/workers/#{origin_name}/report/coverage/#{fname}.html"
  hunks_html = hunks.map do |h|
    s_ln = h["start_line"]
    e_ln = h["end_line"]
    anchor_ln = h["anchor_line"] || s_ln
    fn_label = h["function"] ? "in <code>#{CGI.escapeHTML(h['function'])}()</code>" : ""
    deep_href = "#{file_base_href}#L#{anchor_ln}"

    lines_html = (h["lines"] || []).map do |row|
      ln = row["line"]
      kind = row["kind"]
      row_cls = case kind
                when "both", "line" then "hunk-line-excl"
                when "branch"       then "hunk-branch-excl"
                else                     "hunk-context"
                end
      tags = []
      tags << %(<span class="hunk-tag hunk-tag-line">LINE #{format_int(row["line_count"].to_i)}x</span>) if row["line_count"]
      br_list = row["branches"] || []
      if br_list.any?
        br_list.each do |b|
          taken = b["taken"].to_s
          cnt = format_int(b["count"].to_i)
          other_lbl = taken == "True" ? "False" : "True"
          other_info = b["other_count"] ? " (#{other_lbl} branch taken #{format_int(b['other_count'].to_i)}x across fleet)" : ""
          expr = b["expr"].to_s
          mdef = b["macro_def"].to_s
          tag_cls = taken == "False" ? "hunk-tag hunk-tag-branch-false" : "hunk-tag hunk-tag-branch"

          label_prefix = if b["macro"] && !mdef.empty? && mdef != expr
                           "#{mdef} &rarr; "
                         elsif br_list.size > 1 && !expr.empty?
                           "#{expr} &rarr; "
                         else
                           "BR &rarr; "
                         end
          tip = if b["macro"] && !mdef.empty?
                  "Macro #{expr} expanded to: #{mdef} -> #{taken} (#{cnt}x)#{other_info}"
                elsif !expr.empty?
                  "Condition: #{expr} -> #{taken} (#{cnt}x)#{other_info}"
                else
                  "Branch #{taken} taken #{cnt}x#{other_info}"
                end
          tags << %(<span class="#{tag_cls}" title="#{CGI.escapeHTML(tip)}">#{label_prefix}#{CGI.escapeHTML(taken)} (#{cnt}x)</span>)
        end
      elsif row["branch_hits"].to_i > 0
        tags << %(<span class="hunk-tag hunk-tag-branch">+#{row["branch_hits"]} BR (#{format_int(row["branch_count"].to_i)}x)</span>)
      end
      code_html = highlight_branch_spans(row["code"].to_s, br_list)
      <<~LINE
        <div class="hunk-code-row #{row_cls}">
          <a class="hunk-ln" href="#{CGI.escapeHTML("#{file_base_href}#L#{ln}")}" target="_blank" rel="noopener">#{ln}</a>
          <span class="hunk-badges">#{tags.join}</span>
          <pre class="hunk-src">#{code_html}</pre>
        </div>
      LINE
    end.join

    <<~HUNK
      <div class="hunk-box">
        <div class="hunk-head">
          <span>Lines #{s_ln}&ndash;#{e_ln} #{fn_label}</span>
          <a class="cov-link" href="#{CGI.escapeHTML(deep_href)}" target="_blank" rel="noopener">Open in llvm-cov (#L#{anchor_ln}) &nearr;</a>
        </div>
        <div class="hunk-body">
          #{lines_html}
        </div>
      </div>
    HUNK
  end.join("\n")

  if show_origin_header
    tab_btn = tab_link ? %(<button class="hunk-tab-btn" onclick="selectTab('#{CGI.escapeHTML(origin_name)}')">View #{CGI.escapeHTML(origin_name)} Telemetry &rarr;</button>) : ""
    <<~WRAP
      <div class="origin-hunk-group" data-origin="#{CGI.escapeHTML(origin_name)}">
        <div class="origin-hunk-title">
          <span><span class="legend-dot" style="background:#{origin_color}"></span> <strong>#{CGI.escapeHTML(origin_name)}</strong> exclusive coverage in <code>#{CGI.escapeHTML(fname)}</code></span>
          <div style="display:flex;gap:10px;align-items:center;">
            #{tab_btn}
            <a class="cov-link" href="#{CGI.escapeHTML(file_base_href)}" target="_blank" rel="noopener">Full File HTML &nearr;</a>
          </div>
        </div>
        #{hunks_html}
      </div>
    WRAP
  else
    hunks_html
  end
end

def render_worker_cov_files_table(origin_cov, color)
  return "" unless origin_cov && origin_cov["has_coverage"]

  files = origin_cov["files"] || []
  return "" if files.empty?
  origin_name = origin_cov["name"].to_s
  safe_origin_id = origin_name.gsub(/[^a-zA-Z0-9_-]/, "_")

  # Sort files with exclusive coverage first, then by gain vs corpus, then by filename
  sorted_files = files.sort_by do |f|
    ex_l = f.dig("exclusive", "lines", "covered").to_i
    ex_b = f.dig("exclusive", "branches", "covered").to_i
    vc_l = f.dig("vs_corpus", "lines", "covered").to_i
    [-(ex_l * 100 + ex_b), -vc_l, f["filename"].to_s]
  end

  has_any_hunks = false
  rows_html = sorted_files.each_with_index.map do |f, idx|
    fname = f["filename"].to_s
    sum = f["summary"] || {}
    l = sum["lines"] || {}
    b = sum["branches"] || {}
    r = sum["regions"] || {}
    fn = sum["functions"] || {}
    next if l["count"].to_i.zero? && fn["count"].to_i.zero?

    vc_l = f.dig("vs_corpus", "lines", "covered").to_i
    vc_b = f.dig("vs_corpus", "branches", "covered").to_i
    ex_l = f.dig("exclusive", "lines", "covered").to_i
    ex_b = f.dig("exclusive", "branches", "covered").to_i
    ex_r = f.dig("exclusive", "regions", "covered").to_i
    hunks = f["exclusive_hunks"] || []
    drawer_id = "w-hunk-#{safe_origin_id}-#{idx}"

    vc_str = if vc_l > 0 || vc_b > 0
               "<span class=\"cov-gain\">+#{format_int(vc_l)}L / +#{format_int(vc_b)}B</span>"
             else
               "<span class=\"muted\">&mdash;</span>"
             end

    ex_str = if hunks.any?
               has_any_hunks = true
               "<button class=\"badge badge-success clickable-pill\" onclick=\"toggleHunkDrawer('#{drawer_id}')\" title=\"Click to view exclusive lines &amp; branches\">&#9662; +#{format_int(ex_l)}L / +#{format_int(ex_b)}B</button>"
             elsif ex_l > 0 || ex_b > 0 || ex_r > 0
               "<span class=\"badge badge-success\">+#{format_int(ex_l)}L / +#{format_int(ex_b)}B</span>"
             else
               "<span class=\"muted\">0</span>"
             end

    l_pct = l["percent"].to_f
    b_pct = b["percent"].to_f
    first_anchor = hunks.first ? "#L#{hunks.first['anchor_line']}" : ""
    file_html_href = "../coverage/workers/#{origin_name}/report/coverage/#{fname}.html#{first_anchor}"

    drawer_row = if hunks.any?
                   <<~DRAWER
                     <tr id="#{drawer_id}" class="hunk-drawer-row" data-worker-hunks="#{CGI.escapeHTML(origin_name)}" style="display:table-row;">
                       <td colspan="7" class="hunk-drawer-cell">
                         #{render_exclusive_hunks_block(origin_name, color, fname, hunks)}
                       </td>
                     </tr>
                   DRAWER
                 else
                   ""
                 end

    <<~ROW
      <tr>
        <td><a class="cov-link" href="#{CGI.escapeHTML(file_html_href)}" target="_blank" rel="noopener"><code>#{CGI.escapeHTML(fname)}</code> &nearr;</a></td>
        <td class="num">
          <strong>#{format("%.2f%%", l_pct)}</strong>
          <span class="muted">(#{format_int(l["covered"].to_i)}/#{format_int(l["count"].to_i)})</span>
        </td>
        <td class="num">
          #{b["count"].to_i > 0 ? "#{format('%.2f%%', b_pct)} <span class=\"muted\">(#{format_int(b['covered'].to_i)}/#{format_int(b['count'].to_i)})</span>" : "<span class=\"muted\">&mdash;</span>"}
        </td>
        <td class="num">#{format("%.2f%%", r["percent"].to_f)}</td>
        <td class="num">#{format("%.2f%%", fn["percent"].to_f)}</td>
        <td class="num">#{vc_str}</td>
        <td class="num">#{ex_str}</td>
      </tr>
      #{drawer_row}
    ROW
  end.compact.join("\n")

  toggle_all_btn = has_any_hunks ? %(<button class="cov-btn cov-btn-secondary" data-expand-label="Expand Exclusive Code Hunks" data-collapse-label="Collapse Exclusive Code Hunks" onclick="toggleAllHunks(this, 'w-hunk-#{safe_origin_id}-')">Collapse Exclusive Code Hunks</button>) : ""
  report_link = origin_cov["report_rel_path"] ? %(<a class="cov-btn" href="#{CGI.escapeHTML(origin_cov['report_rel_path'])}" target="_blank" rel="noopener">Open #{CGI.escapeHTML(origin_name)} llvm-cov HTML &nearr;</a>) : ""

  <<~HTML
    <div class="table-card" style="margin-top: 18px;">
      <div class="table-card-header">
        <div>
          <h3><span class="legend-dot" style="background:#{color}"></span> Source Coverage by File (Originated by <code>#{CGI.escapeHTML(origin_name)}</code>)</h3>
          <p class="chart-sub">Standalone coverage from <strong>#{format_int(origin_cov["input_count"].to_i)}</strong> originated inputs. Exclusive source lines (emerald) and branches (sky blue) are shown inline below each file.</p>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">#{toggle_all_btn} #{report_link}</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>File</th>
            <th class="num">Line Coverage</th>
            <th class="num">Branch Coverage</th>
            <th class="num">Region %</th>
            <th class="num">Function %</th>
            <th class="num">Gain vs. Corpus</th>
            <th class="num">Exclusive to #{CGI.escapeHTML(origin_cov["name"])}</th>
          </tr>
        </thead>
        <tbody>
          #{rows_html}
        </tbody>
      </table>
    </div>
  HTML
end

# Fleet summary table rows (AFL++ fuzzers only; generators rendered in their own table below)
summary_rows_html = afl_fuzzers.map do |f|
  ps = peer_sync_by_name[f[:name]]
  oc = cov_by_origin[f[:name]]
  edges_str = f[:total_edges] > 0 ? "#{format_int(f[:edges_found])} / #{format_int(f[:total_edges])}" : format_int(f[:edges_found])
  crash_cls = f[:saved_crashes] > 0 ? "badge-danger" : "badge-muted"
  hang_cls = f[:saved_hangs] > 0 ? "badge-warn" : "badge-muted"
  if ps
    main_sync_cell = "#{format_int(ps[:cursor])} / #{format_int(ps[:peer_total])} <span class=\"muted\">(#{format('%.0f%%', ps[:sync_pct])})</span>"
    main_yield_cell = "<strong>+#{format_int(ps[:imported_by_main])}</strong> / #{format_int(ps[:tested_by_main])} <span class=\"muted\">(#{format('%.1f%%', ps[:yield_pct])})</span>"
  else
    main_sync_cell = "<span class=\"muted\">hub</span>"
    main_yield_cell = "<span class=\"muted\">&mdash;</span>"
  end
  if oc && oc["has_coverage"]
    l_pct = oc.dig("totals", "lines", "percent").to_f
    b_pct = oc.dig("totals", "branches", "percent").to_f
    ex_l = oc.dig("exclusive", "lines", "covered").to_i
    ex_b = oc.dig("exclusive", "branches", "covered").to_i
    src_cov_cell = "<strong>#{format('%.2f%%', l_pct)}</strong> <span class=\"muted\">(#{format('%.1f%%', b_pct)} B)</span>"
    excl_cell = (ex_l > 0 || ex_b > 0) ? "<span class=\"badge badge-success\">+#{ex_l}L / +#{ex_b}B</span>" : "<span class=\"muted\">0</span>"
    rep_cell = oc["report_rel_path"] ? %(<a class="cov-link" href="#{CGI.escapeHTML(oc['report_rel_path'])}" target="_blank" rel="noopener" onclick="event.stopPropagation()">HTML &nearr;</a>) : "<span class=\"muted\">&mdash;</span>"
  else
    src_cov_cell = "<span class=\"muted\">&mdash;</span>"
    excl_cell = "<span class=\"muted\">&mdash;</span>"
    rep_cell = "<span class=\"muted\">&mdash;</span>"
  end
  <<~HTML
    <tr class="clickable-row" onclick="selectTab('#{CGI.escapeHTML(f[:name])}')">
      <td>
        <span class="legend-dot" style="background:#{f[:color]}"></span>
        <strong>#{CGI.escapeHTML(f[:name])}</strong>
      </td>
      <td><code>#{CGI.escapeHTML(File.basename(f[:banner]))}</code></td>
      <td><span class="sched-pill">#{CGI.escapeHTML(f[:sched])}</span></td>
      <td class="num">#{format_int(f[:execs_per_sec].round)}/s</td>
      <td class="num">#{format_compact(f[:execs_done])}</td>
      <td class="num"><strong>#{format("%.2f%%", f[:bitmap_cvg])}</strong></td>
      <td class="num">#{edges_str}</td>
      <td class="num">#{src_cov_cell}</td>
      <td class="num">#{excl_cell}</td>
      <td class="num">#{format_int(f[:corpus_count])}</td>
      <td class="num">#{format_int(f[:corpus_found])}</td>
      <td class="num">#{format_int(f[:corpus_imported])}</td>
      <td class="num">#{main_sync_cell}</td>
      <td class="num">#{main_yield_cell}</td>
      <td class="num">#{format_int(f[:pending_favs])} / #{format_int(f[:pending_total])}</td>
      <td class="num"><span class="badge #{crash_cls}">#{f[:saved_crashes]}</span></td>
      <td class="num"><span class="badge #{hang_cls}">#{f[:saved_hangs]}</span></td>
      <td class="num">#{rep_cell}</td>
    </tr>
  HTML
end.join("\n")

generator_table_html = if gen_fuzzers.any?
  gen_rows = gen_fuzzers.map do |gf|
    ps = peer_sync_by_name[gf[:name]]
    oc = cov_by_origin[gf[:name]]
    yield_cell = if ps
                   "<strong>+#{format_int(ps[:imported_by_main])}</strong> / #{format_int(ps[:tested_by_main])} <span class=\"muted\">(#{format('%.1f%%', ps[:yield_pct])} into #{CGI.escapeHTML(ps[:intake_name])})</span>"
                 else
                   "<span class=\"muted\">&mdash;</span>"
                 end
    if oc && oc["has_coverage"]
      l_pct = oc.dig("totals", "lines", "percent").to_f
      vc_l = oc.dig("vs_corpus", "lines", "covered").to_i
      ex_l = oc.dig("exclusive", "lines", "covered").to_i
      ex_b = oc.dig("exclusive", "branches", "covered").to_i
      src_cov_cell = "<strong>#{format('%.2f%%', l_pct)}</strong> <span class=\"muted\">(+#{format_int(vc_l)}L vs corpus)</span>"
      excl_cell = (ex_l > 0 || ex_b > 0) ? "<span class=\"badge badge-success\">+#{ex_l}L / +#{ex_b}B</span>" : "<span class=\"muted\">0</span>"
      rep_cell = oc["report_rel_path"] ? %(<a class="cov-link" href="#{CGI.escapeHTML(oc['report_rel_path'])}" target="_blank" rel="noopener" onclick="event.stopPropagation()">HTML &nearr;</a>) : "<span class=\"muted\">&mdash;</span>"
    else
      src_cov_cell = "<span class=\"muted\">&mdash;</span>"
      excl_cell = "<span class=\"muted\">&mdash;</span>"
      rep_cell = "<span class=\"muted\">&mdash;</span>"
    end
    <<~ROW
      <tr class="clickable-row" onclick="selectTab('#{CGI.escapeHTML(gf[:name])}')">
        <td>
          <span class="legend-dot" style="background:#{gf[:color]}"></span>
          <strong>#{CGI.escapeHTML(gf[:name])}</strong>
        </td>
        <td><code>#{CGI.escapeHTML(File.basename(gf[:banner]))}</code></td>
        <td><span class="sched-pill">#{CGI.escapeHTML(gf[:sched])}</span></td>
        <td class="num">#{format_compact(gf[:files_per_sec])} files/s</td>
        <td class="num">#{format_compact(gf[:avg_files_per_sec])} files/s</td>
        <td class="num">#{format_int(gf[:pending_files])} <span class="muted">/ #{format_int(gf[:max_pending_files])}</span></td>
        <td class="num">#{format_int(gf[:files_created])}</td>
        <td class="num">#{format_int(gf[:files_pruned])}</td>
        <td class="num">#{format_int(gf[:duplicates_skipped])}</td>
        <td class="num">#{yield_cell}</td>
        <td class="num">#{src_cov_cell}</td>
        <td class="num">#{excl_cell}</td>
        <td class="num">#{rep_cell}</td>
      </tr>
    ROW
  end.join("\n")

  <<~GEN_TABLE
    <div class="table-card" style="margin-top: 18px;">
      <table>
        <thead>
          <tr>
            <th>Seed Generator</th>
            <th>Engine</th>
            <th>Mode</th>
            <th class="num">Rate</th>
            <th class="num">Avg Rate</th>
            <th class="num">Pending</th>
            <th class="num">Created</th>
            <th class="num">Pruned</th>
            <th class="num">Duplicates</th>
            <th class="num">Foreign Sync Yield (-F)</th>
            <th class="num">Src Line %</th>
            <th class="num">Exclusive</th>
            <th class="num">Report</th>
          </tr>
        </thead>
        <tbody>
          #{gen_rows}
        </tbody>
      </table>
    </div>
  GEN_TABLE
else
  ""
end

# Per-fuzzer tab buttons and panels
tab_buttons_html = +%(<button class="tab-btn active" data-tab="overview" onclick="selectTab('overview')">Fleet Overview (#{fuzzers.size})</button>\n)
if combined_cov
  comb_line_pct = combined_cov.dig("totals", "lines", "percent").to_f
  tab_buttons_html << <<~HTML
    <button class="tab-btn" data-tab="coverage" onclick="selectTab('coverage')">
      <span class="legend-dot" style="background:#34d399"></span>
      Source Coverage (#{format("%.2f%%", comb_line_pct)})
    </button>
  HTML
end
tab_panels_html = +""

if combined_cov
  ct = combined_cov["totals"] || {}
  cl = ct["lines"] || {}
  cb = ct["branches"] || {}
  cr = ct["regions"] || {}
  cf = ct["functions"] || {}

  corp_lines = corpus_cov&.dig("totals", "lines", "covered").to_i
  corp_branches = corpus_cov&.dig("totals", "branches", "covered").to_i
  gain_lines_over_corpus = corp_lines > 0 ? [cl["covered"].to_i - corp_lines, 0].max : 0
  gain_branches_over_corpus = corp_branches > 0 ? [cb["covered"].to_i - corp_branches, 0].max : 0

  origins_list = coverage_data["origins"] || []
  total_excl_lines = origins_list.sum { |o| o.dig("exclusive", "lines", "covered").to_i }
  total_excl_branches = origins_list.sum { |o| o.dig("exclusive", "branches", "covered").to_i }

  # Build visual comparison bars for combined + each origin
  bar_entries = [
    {
      name: "combined (all origins)",
      tab: nil,
      color: "#34d399",
      role_label: "Combined Campaign",
      has_cov: true,
      inputs: combined_cov["input_count"].to_i,
      lines_pct: cl["percent"].to_f,
      lines_cov: cl["covered"].to_i,
      lines_tot: cl["count"].to_i,
      branches_pct: cb["percent"].to_f,
      branches_cov: cb["covered"].to_i,
      branches_tot: cb["count"].to_i,
      regions_pct: cr["percent"].to_f,
      functions_pct: cf["percent"].to_f,
      vs_corpus_l: gain_lines_over_corpus,
      vs_corpus_b: gain_branches_over_corpus,
      excl_l: nil,
      excl_b: nil,
      excl_r: nil,
      report_path: combined_cov["report_rel_path"],
      summary_path: combined_cov["summary_rel_path"]
    }
  ]

  origins_list.each do |o|
    oname = o["name"]
    ot = o["totals"] || {}
    ol = ot["lines"] || {}
    ob = ot["branches"] || {}
    or_ = ot["regions"] || {}
    of = ot["functions"] || {}
    role_lbl = case o["kind"]
               when "corpus" then "Initial Seed Corpus"
               when "generator" then "Grammar Seed Generator"
               else "AFL++ Fuzzer Worker"
               end
    bar_entries << {
      name: oname,
      tab: color_by_name.key?(oname) ? oname : nil,
      color: color_by_name[oname] || (oname == "corpus" ? "#fbbf24" : "#9ca3af"),
      role_label: role_lbl,
      has_cov: o["has_coverage"] != false,
      inputs: o["input_count"].to_i,
      lines_pct: ol["percent"].to_f,
      lines_cov: ol["covered"].to_i,
      lines_tot: ol["count"].to_i,
      branches_pct: ob["percent"].to_f,
      branches_cov: ob["covered"].to_i,
      branches_tot: ob["count"].to_i,
      regions_pct: or_["percent"].to_f,
      functions_pct: of["percent"].to_f,
      vs_corpus_l: o.dig("vs_corpus", "lines", "covered"),
      vs_corpus_b: o.dig("vs_corpus", "branches", "covered"),
      excl_l: o.dig("exclusive", "lines", "covered").to_i,
      excl_b: o.dig("exclusive", "branches", "covered").to_i,
      excl_r: o.dig("exclusive", "regions", "covered").to_i,
      report_path: o["report_rel_path"],
      summary_path: o["summary_rel_path"]
    }
  end

  cov_origins_table_rows = bar_entries.map do |e|
    row_click = e[:tab] ? %(class="clickable-row" onclick="selectTab('#{CGI.escapeHTML(e[:tab])}')") : ""
    vc_cell = if e[:name] == "corpus"
                "<span class=\"muted\">baseline</span>"
              elsif e[:vs_corpus_l].to_i > 0 || e[:vs_corpus_b].to_i > 0
                "<span class=\"cov-gain\">+#{format_int(e[:vs_corpus_l].to_i)}L / +#{format_int(e[:vs_corpus_b].to_i)}B</span>"
              else
                "<span class=\"muted\">&mdash;</span>"
              end
    ex_cell = if e[:excl_l].nil?
                "<span class=\"muted\">union</span>"
              elsif e[:excl_l] > 0 || e[:excl_b] > 0 || e[:excl_r].to_i > 0
                "<span class=\"badge badge-success\">+#{format_int(e[:excl_l])}L / +#{format_int(e[:excl_b])}B / +#{format_int(e[:excl_r].to_i)}R</span>"
              else
                "<span class=\"muted\">0</span>"
              end
    links = []
    links << %(<a class="cov-link" href="#{CGI.escapeHTML(e[:report_path])}" target="_blank" rel="noopener" onclick="event.stopPropagation()">HTML &nearr;</a>) if e[:report_path]
    links << %(<a class="cov-link muted" href="#{CGI.escapeHTML(e[:summary_path])}" target="_blank" rel="noopener" onclick="event.stopPropagation()">Txt &nearr;</a>) if e[:summary_path]
    lines_cell = if e[:has_cov]
                   <<~CELL
                     <div><strong>#{format("%.2f%%", e[:lines_pct])}</strong> <span class="muted">(#{format_int(e[:lines_cov])} / #{format_int(e[:lines_tot])})</span></div>
                     <div class="sync-bar" style="height: 6px; margin-top: 4px;">
                       <div class="sync-seg" style="width:#{e[:lines_pct].round(2)}%;background:#{e[:color]}"></div>
                     </div>
                   CELL
                 else
                   "<span class=\"muted\">&mdash;</span>"
                 end
    branches_cell = if e[:has_cov]
                      <<~CELL
                        <div><strong>#{format("%.2f%%", e[:branches_pct])}</strong> <span class="muted">(#{format_int(e[:branches_cov])} / #{format_int(e[:branches_tot])})</span></div>
                        <div class="sync-bar" style="height: 6px; margin-top: 4px;">
                          <div class="sync-seg" style="width:#{e[:branches_pct].round(2)}%;background:#38bdf8"></div>
                        </div>
                      CELL
                    else
                      "<span class=\"muted\">&mdash;</span>"
                    end
    regions_cell = e[:has_cov] ? format("%.2f%%", e[:regions_pct]) : "<span class=\"muted\">&mdash;</span>"
    functions_cell = e[:has_cov] ? format("%.2f%%", e[:functions_pct]) : "<span class=\"muted\">&mdash;</span>"
    ex_cell = "<span class=\"muted\">&mdash;</span>" unless e[:has_cov]
    <<~ROW
      <tr #{row_click}>
        <td>
          <span class="legend-dot" style="background:#{e[:color]}"></span>
          <strong>#{CGI.escapeHTML(e[:name])}</strong>
        </td>
        <td><span class="sched-pill">#{CGI.escapeHTML(e[:role_label])}</span></td>
        <td class="num">#{format_int(e[:inputs])}</td>
        <td class="num" style="min-width: 210px;">#{lines_cell}</td>
        <td class="num" style="min-width: 210px;">#{branches_cell}</td>
        <td class="num">#{regions_cell}</td>
        <td class="num">#{functions_cell}</td>
        <td class="num">#{vc_cell}</td>
        <td class="num">#{ex_cell}</td>
        <td class="num">#{links.join(" &bull; ")}</td>
      </tr>
    ROW
  end.join("\n")

  # Per-file coverage matrix across combined, corpus, grammar, and exclusive contributors
  corpus_file_map = (corpus_cov&.dig("files") || []).to_h { |f| [f["filename"], f] }
  grammar_file_map = (cov_by_origin.dig("grammar", "files") || []).to_h { |f| [f["filename"], f] }

  excl_by_file = Hash.new { |h, k| h[k] = [] }
  origins_list.each do |o|
    oname = o["name"]
    (o["files"] || []).each do |f|
      el = f.dig("exclusive", "lines", "covered").to_i
      eb = f.dig("exclusive", "branches", "covered").to_i
      hunks = f["exclusive_hunks"] || []
      if el > 0 || eb > 0 || hunks.any?
        excl_by_file[f["filename"]] << {
          name: oname,
          lines: el,
          branches: eb,
          hunks: hunks,
          color: color_by_name[oname] || "#fbbf24"
        }
      end
    end
  end

  file_matrix_rows = (combined_cov["files"] || []).each_with_index.map do |cf_entry, f_idx|
    fname = cf_entry["filename"].to_s
    cs = cf_entry["summary"] || {}
    fl = cs["lines"] || {}
    fb = cs["branches"] || {}
    ff = cs["functions"] || {}
    next if fl["count"].to_i.zero? && ff["count"].to_i.zero?

    corp_f = corpus_file_map[fname]
    corp_l_cov = corp_f&.dig("summary", "lines", "covered").to_i
    corp_l_pct = corp_f&.dig("summary", "lines", "percent").to_f
    camp_gain_l = corp_f ? [fl["covered"].to_i - corp_l_cov, 0].max : 0

    gram_f = grammar_file_map[fname]
    gram_l_pct = gram_f&.dig("summary", "lines", "percent").to_f
    gram_vc_l = gram_f&.dig("vs_corpus", "lines", "covered").to_i

    missed_l = fl["count"].to_i - fl["covered"].to_i
    missed_b = fb["count"].to_i - fb["covered"].to_i
    sorted_excl = excl_by_file[fname].sort_by { |x| -(x[:lines] * 100 + x[:branches]) }
    drawer_id = "cov-file-hunks-#{f_idx}"

    excl_badges = sorted_excl.map do |x|
      parts = []
      parts << "+#{x[:lines]}L" if x[:lines] > 0
      parts << "+#{x[:branches]}B" if x[:branches] > 0
      first_anchor = x[:hunks].first ? "#L#{x[:hunks].first['anchor_line']}" : ""
      worker_file_href = "../coverage/workers/#{x[:name]}/report/coverage/#{fname}.html#{first_anchor}"
      toggle_js = x[:hunks].any? ? %(onclick="toggleFileOriginHunks('#{drawer_id}', '#{CGI.escapeHTML(x[:name])}')") : (color_by_name.key?(x[:name]) ? %(onclick="selectTab('#{CGI.escapeHTML(x[:name])}')") : "")
      caret = x[:hunks].any? ? "&#9662; " : ""
      %(<span class="excl-pill clickable-pill" #{toggle_js} title="Click to inspect exclusive code lines/branches from #{CGI.escapeHTML(x[:name])}"><span class="legend-dot" style="background:#{x[:color]}"></span>#{caret}#{CGI.escapeHTML(x[:name])}: #{parts.join('/')} <a class="cov-link" href="#{CGI.escapeHTML(worker_file_href)}" target="_blank" rel="noopener" title="Open #{CGI.escapeHTML(fname)} in #{CGI.escapeHTML(x[:name])} llvm-cov report" onclick="event.stopPropagation()">&nearr;</a></span>)
    end.join(" ")

    hunk_groups_html = sorted_excl.select { |x| x[:hunks].any? }.map do |x|
      render_exclusive_hunks_block(
        x[:name],
        x[:color],
        fname,
        x[:hunks],
        show_origin_header: true,
        tab_link: color_by_name.key?(x[:name])
      )
    end.join("\n")

    drawer_row = if !hunk_groups_html.empty?
                   <<~DRAWER
                     <tr id="#{drawer_id}" class="hunk-drawer-row" data-worker-hunks="__matrix__" style="display:none;">
                       <td colspan="8" class="hunk-drawer-cell">
                         #{hunk_groups_html}
                       </td>
                     </tr>
                   DRAWER
                 else
                   ""
                 end

    comb_file_href = "../coverage/report/coverage/#{fname}.html"
    <<~ROW
      <tr>
        <td><a class="cov-link" href="#{CGI.escapeHTML(comb_file_href)}" target="_blank" rel="noopener"><code>#{CGI.escapeHTML(fname)}</code> &nearr;</a></td>
        <td class="num">
          <strong>#{format("%.2f%%", fl["percent"].to_f)}</strong>
          <span class="muted">(#{format_int(fl["covered"].to_i)}/#{format_int(fl["count"].to_i)})</span>
        </td>
        <td class="num">#{missed_l > 0 ? "<span class=\"text-warn\">#{format_int(missed_l)}</span>" : "<span class=\"muted\">0</span>"}</td>
        <td class="num">
          #{fb["count"].to_i > 0 ? "<strong>#{format('%.2f%%', fb['percent'].to_f)}</strong> <span class=\"muted\">(#{format_int(fb['covered'].to_i)}/#{format_int(fb['count'].to_i)})</span>" : "<span class=\"muted\">&mdash;</span>"}
        </td>
        <td class="num">#{missed_b > 0 ? "<span class=\"text-warn\">#{format_int(missed_b)}</span>" : "<span class=\"muted\">0</span>"}</td>
        <td class="num">
          #{corp_f ? "#{format('%.2f%%', corp_l_pct)} #{camp_gain_l > 0 ? "<span class=\"cov-gain\">(+#{format_int(camp_gain_l)}L)</span>" : ''}" : "<span class=\"muted\">&mdash;</span>"}
        </td>
        <td class="num">
          #{gram_f ? "#{format('%.2f%%', gram_l_pct)} #{gram_vc_l > 0 ? "<span class=\"cov-gain\">(+#{format_int(gram_vc_l)}L)</span>" : ''}" : "<span class=\"muted\">&mdash;</span>"}
        </td>
        <td>#{excl_badges.empty? ? "<span class=\"muted\">&mdash;</span>" : excl_badges}</td>
      </tr>
      #{drawer_row}
    ROW
  end.compact.join("\n")

  tab_panels_html << <<~HTML
    <section id="tab-coverage" class="tab-panel">
      <div class="fuzzer-banner">
        <div>
          <h2><span class="legend-dot" style="background:#34d399"></span> Source Coverage Breakdown (By Worker &amp; Combined)</h2>
          <p class="cmd-line">Partitioned across <strong>#{origins_list.size}</strong> origins (<strong>#{format_int(combined_cov["input_count"].to_i)}</strong> unique inputs) and merged via <code>llvm-profdata</code> &bull; Collected: #{CGI.escapeHTML(coverage_data["generated_at"].to_s)}</p>
        </div>
        <div class="fuzzer-meta">
          <a class="cov-btn" href="#{CGI.escapeHTML(combined_cov["report_rel_path"].to_s)}" target="_blank" rel="noopener">Open Combined llvm-cov HTML Report &nearr;</a>
          <a class="cov-btn cov-btn-secondary" href="#{CGI.escapeHTML(combined_cov["summary_rel_path"].to_s)}" target="_blank" rel="noopener">Text Summary &nearr;</a>
          <a class="cov-btn cov-btn-secondary" href="#{CGI.escapeHTML(combined_cov["lcov_rel_path"].to_s)}" target="_blank" rel="noopener">LCOV (IDE Gutters) &nearr;</a>
        </div>
      </div>

      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-label">Combined Line Coverage</div>
          <div class="kpi-value">#{format("%.2f%%", cl["percent"].to_f)}</div>
          <div class="kpi-sub">#{format_int(cl["covered"].to_i)} / #{format_int(cl["count"].to_i)} lines (+#{format_int(gain_lines_over_corpus)} vs corpus)</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Combined Branch Coverage</div>
          <div class="kpi-value">#{format("%.2f%%", cb["percent"].to_f)}</div>
          <div class="kpi-sub">#{format_int(cb["covered"].to_i)} / #{format_int(cb["count"].to_i)} branches (+#{format_int(gain_branches_over_corpus)} vs corpus)</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Combined Region Coverage</div>
          <div class="kpi-value">#{format("%.2f%%", cr["percent"].to_f)}</div>
          <div class="kpi-sub">#{format_int(cr["covered"].to_i)} / #{format_int(cr["count"].to_i)} regions (#{format_int(cr["count"].to_i - cr["covered"].to_i)} missed)</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Combined Function Coverage</div>
          <div class="kpi-value">#{format("%.2f%%", cf["percent"].to_f)}</div>
          <div class="kpi-sub">#{format_int(cf["covered"].to_i)} / #{format_int(cf["count"].to_i)} functions (#{format_int(cf["count"].to_i - cf["covered"].to_i)} missed)</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Exclusive Worker Coverage</div>
          <div class="kpi-value">+#{format_int(total_excl_lines)}L / +#{format_int(total_excl_branches)}B</div>
          <div class="kpi-sub">lines &amp; branches uniquely held by a single origin</div>
        </div>
      </div>

      <div class="table-card" style="margin-bottom: 22px;">
        <div class="table-card-header">
          <div>
            <h3>Coverage by Origin (Self-Originated Inputs vs. Combined Union)</h3>
            <p class="chart-sub">Each worker is evaluated on the inputs it originated before merging into the combined profile. <strong>Gain vs. Corpus</strong> measures <code>merge(corpus, worker) - corpus</code>; <strong>Exclusive</strong> measures <code>combined - merge(all_other_origins)</code>. Click any worker row to open its telemetry tab.</p>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Origin</th>
              <th>Role</th>
              <th class="num">Originated Inputs</th>
              <th class="num">Lines Covered</th>
              <th class="num">Branches Covered</th>
              <th class="num">Regions %</th>
              <th class="num">Functions %</th>
              <th class="num">Gain vs. Corpus</th>
              <th class="num">Exclusive (Lines / Branches / Regions)</th>
              <th class="num">llvm-cov Report</th>
            </tr>
          </thead>
          <tbody>
            #{cov_origins_table_rows}
          </tbody>
        </table>
      </div>

      <div class="table-card">
        <div class="table-card-header">
          <div>
            <h3>Per-File Coverage &amp; Exclusive Worker Contributions</h3>
            <p class="chart-sub">Combined coverage per source file alongside initial corpus baseline, grammar generator coverage, and workers holding exclusive lines/branches (click any exclusive pill or row to inspect exact C source code)</p>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="cov-btn" data-expand-label="Expand All Exclusive Hunks" data-collapse-label="Collapse All Exclusive Hunks" onclick="toggleAllHunks(this, 'cov-file-hunks-')">Expand All Exclusive Hunks</button>
            <a class="cov-btn" href="#{CGI.escapeHTML(combined_cov["report_rel_path"].to_s)}" target="_blank" rel="noopener">Browse Annotated Source (HTML) &nearr;</a>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Source File</th>
              <th class="num">Combined Lines</th>
              <th class="num">Missed L</th>
              <th class="num">Combined Branches</th>
              <th class="num">Missed B</th>
              <th class="num">Initial Corpus (+Campaign Gain)</th>
              <th class="num">Grammar (+vs Corpus)</th>
              <th>Origins with Exclusive Coverage in File</th>
            </tr>
          </thead>
          <tbody>
            #{file_matrix_rows}
          </tbody>
        </table>
      </div>
    </section>
  HTML
end

fuzzers.each do |f|
  name = f[:name]
  safe_name = CGI.escapeHTML(name)
  crash_dot = f[:saved_crashes] > 0 ? %(<span class="tab-crash">#{f[:saved_crashes]}</span>) : ""
  tab_buttons_html << <<~HTML
    <button class="tab-btn" data-tab="#{safe_name}" onclick="selectTab('#{safe_name}')">
      <span class="legend-dot" style="background:#{f[:color]}"></span>
      #{safe_name}
      #{crash_dot}
    </button>
  HTML

  s = f[:samples]
  cmd_line = f[:stats]["command_line"] || ""

  if f[:role] == :generator
    ps = peer_sync_by_name[name]
    intake = ps ? ps[:intake_fuzzer] : main_fuzzer
    intake_name = intake[:name]
    imp_prefix = intake[:origins][:by_source][name] || []
    unique_pct = f[:attempts_done] > 0 ? (f[:files_created] * 100.0 / f[:attempts_done]) : 100.0
    gen_charts = [
      render_svg_chart(
        title: "Cumulative Files Created",
        subtitle: "Unique seed files written to disk vs. total generation attempts",
        y_format: :compact,
        fill_area: true,
        zero_base: true,
        chart_id: "#{name}-files",
        series: [
          { name: "files_created", color: f[:color], points: s.map { |r| [r[:relative_time], r[:files_created]] } },
          { name: "attempts_done", color: "#9ca3af", points: s.map { |r| [r[:relative_time], r[:attempts_done]] } }
        ]
      ),
      render_svg_chart(
        title: "File Creation Rate (files/sec)",
        subtitle: "Seed file creation rate over time (rolling interval and cumulative average)",
        y_format: :file_rate,
        fill_area: true,
        zero_base: true,
        chart_id: "#{name}-rate",
        series: [
          { name: "files_per_sec", color: "#a78bfa", points: s.map { |r| [r[:relative_time], r[:files_per_sec]] } },
          { name: "avg_files_per_sec", color: "#38bdf8", points: s.map { |r| [r[:relative_time], r[:avg_files_per_sec]] } }
        ]
      ),
      render_svg_chart(
        title: "Valid vs. Invalid Generated Files",
        subtitle: "Breakdown of syntactically valid vs. error-injected Ruby seeds created",
        y_format: :compact,
        fill_area: false,
        zero_base: true,
        chart_id: "#{name}-validity",
        series: [
          { name: "files_valid", color: "#34d399", points: s.map { |r| [r[:relative_time], r[:files_valid]] } },
          { name: "files_invalid", color: "#fbbf24", points: s.map { |r| [r[:relative_time], r[:files_invalid]] } }
        ]
      ),
      render_svg_chart(
        title: "Imports into #{intake_name} Queue",
        subtitle: "Cumulative #{name} seed files imported by #{intake_name} via -F foreign sync",
        y_format: :compact,
        fill_area: true,
        zero_base: true,
        chart_id: "#{name}-imports",
        series: [
          {
            name: "imported_by_#{intake_name}",
            color: "#34d399",
            points: intake[:samples].map { |r| [r[:relative_time], lookup_prefix(imp_prefix, r[:corpus_count])] }
          }
        ]
      )
    ].join("\n")

    oc = cov_by_origin[name]
    gen_cov_btn = (oc && oc["report_rel_path"]) ? %(<a class="cov-btn" href="#{CGI.escapeHTML(oc['report_rel_path'])}" target="_blank" rel="noopener">Worker llvm-cov HTML &nearr;</a>) : ""
    gen_cov_kpis = if oc && oc["has_coverage"]
                     ol = oc.dig("totals", "lines") || {}
                     ob = oc.dig("totals", "branches") || {}
                     vc_l = oc.dig("vs_corpus", "lines", "covered").to_i
                     vc_b = oc.dig("vs_corpus", "branches", "covered").to_i
                     ex_l = oc.dig("exclusive", "lines", "covered").to_i
                     ex_b = oc.dig("exclusive", "branches", "covered").to_i
                     <<~COV_KPI
                       <div class="kpi-card">
                         <div class="kpi-label">Source Coverage (Seeds)</div>
                         <div class="kpi-value">#{format("%.2f%%", ol["percent"].to_f)}</div>
                         <div class="kpi-sub">#{format_int(ol["covered"].to_i)} lines &bull; #{format("%.2f%%", ob["percent"].to_f)} branches (+#{format_int(vc_l)}L / +#{format_int(vc_b)}B vs corpus)</div>
                       </div>
                       <div class="kpi-card">
                         <div class="kpi-label">Exclusive to #{safe_name}</div>
                         <div class="kpi-value">+#{format_int(ex_l)}L / +#{format_int(ex_b)}B</div>
                         <div class="kpi-sub">lines &amp; branches not hit by any other origin</div>
                       </div>
                     COV_KPI
                   else
                     ""
                   end

    tab_panels_html << <<~HTML
      <section id="tab-#{safe_name}" class="tab-panel">
        <div class="fuzzer-banner">
          <div>
            <h2><span class="legend-dot" style="background:#{f[:color]}"></span> #{safe_name}</h2>
            <p class="cmd-line"><code>#{CGI.escapeHTML(cmd_line)}</code></p>
          </div>
          <div class="fuzzer-meta">
            <span class="sched-pill">Role: Seed Generator (#{CGI.escapeHTML(f[:sched])})</span>
            <span class="sched-pill">Runtime: #{format_duration(f[:run_time])}</span>
            <span class="sched-pill">Samples: #{format_int(f[:sample_count])}</span>
            #{gen_cov_btn}
          </div>
        </div>

        <div class="kpi-grid">
          <div class="kpi-card">
            <div class="kpi-label">Files Created</div>
            <div class="kpi-value">#{format_int(f[:files_created])}</div>
            <div class="kpi-sub">#{format("%.1f%%", unique_pct)} unique of #{format_int(f[:attempts_done])} generated (#{format_int(f[:duplicates_skipped])} dup)</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">File Creation Rate</div>
            <div class="kpi-value">#{format_compact(f[:files_per_sec])} files/s</div>
            <div class="kpi-sub">avg #{format_compact(f[:avg_files_per_sec])} files/s over #{format_duration(f[:run_time])}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Valid / Invalid Split</div>
            <div class="kpi-value">#{format_int(f[:files_valid])} / #{format_int(f[:files_invalid])}</div>
            <div class="kpi-sub">valid vs. mutated/invalid Ruby seeds</div>
          </div>
          #{if ps
              <<~SYNC_KPI
                <div class="kpi-card">
                  <div class="kpi-label">Imported by #{CGI.escapeHTML(intake_name)}</div>
                  <div class="kpi-value">+#{format_int(ps[:imported_by_main])} <span class="muted">(#{format("%.1f%%", ps[:yield_pct])})</span></div>
                  <div class="kpi-sub">#{format_int(fleet_lineage[:total_grammar_queue_items])} fleet queue items &bull; #{format_int(fleet_lineage[:total_grammar_crashes])} crashes (#{fleet_lineage[:unique_grammar_crash_seeds]} seeds)</div>
                </div>
              SYNC_KPI
            else
              ""
            end}
          #{gen_cov_kpis}
        </div>

        <div class="charts-grid">
          #{gen_charts}
        </div>

        #{render_grammar_lineage_section(fleet_lineage, color_by_name)}
        #{render_worker_cov_files_table(oc, f[:color])}
      </section>
    HTML
    next
  end
  fuzzer_charts = [
    render_svg_chart(
      title: "Coverage & Edges Discovered",
      subtitle: "Instrumented edges reached (#{f[:total_edges] > 0 ? "out of #{format_int(f[:total_edges])} total" : 'edges_found'})",
      y_format: :int,
      fill_area: true,
      zero_base: false,
      chart_id: "#{name}-edges",
      series: [{ name: "edges_found", color: f[:color], points: s.map { |r| [r[:relative_time], r[:edges_found]] } }]
    ),
    render_svg_chart(
      title: "Map Density (%)",
      subtitle: "Bitmap coverage percentage over time (map_size)",
      y_format: :percent,
      fill_area: true,
      zero_base: false,
      chart_id: "#{name}-map",
      series: [{ name: "map_size", color: "#38bdf8", points: s.map { |r| [r[:relative_time], r[:map_size]] } }]
    ),
    render_svg_chart(
      title: "Queue & Pending Corpus",
      subtitle: "Total queue size vs. pending unfuzzed and pending favored items",
      y_format: :compact,
      fill_area: false,
      zero_base: true,
      chart_id: "#{name}-corpus",
      series: [
        { name: "corpus_count", color: "#34d399", points: s.map { |r| [r[:relative_time], r[:corpus_count]] } },
        { name: "pending_total", color: "#fbbf24", points: s.map { |r| [r[:relative_time], r[:pending_total]] } },
        { name: "pending_favs", color: "#f472b6", points: s.map { |r| [r[:relative_time], r[:pending_favs]] } }
      ]
    ),
    render_svg_chart(
      title: "Queue Origin Breakdown (Local vs. Synced)",
      subtitle: "Total queue split into locally mutated finds, foreign synced imports, and initial seeds",
      y_format: :compact,
      fill_area: false,
      zero_base: true,
      chart_id: "#{name}-origins",
      series: [
        { name: "corpus_count", color: "#9ca3af", points: s.map { |r| [r[:relative_time], r[:corpus_count]] } },
        { name: "local_finds", color: "#34d399", points: s.map { |r| [r[:relative_time], r[:local_count]] } },
        { name: "synced_imports", color: "#60a5fa", points: s.map { |r| [r[:relative_time], r[:synced_count]] } },
        { name: "initial_seeds", color: "#fbbf24", points: s.map { |r| [r[:relative_time], r[:seed_count]] } }
      ]
    ),
    render_svg_chart(
      title: "Synced Imports by Source Fuzzer",
      subtitle: "Which foreign fuzzers contributed synced queue entries to #{name} over time",
      y_format: :compact,
      fill_area: false,
      zero_base: true,
      chart_id: "#{name}-sync-src",
      series: sort_fuzzer_names(f[:origins][:by_source].keys).each_with_index.map do |src, s_idx|
        prefix_arr = f[:origins][:by_source][src]
        {
          name: "from #{src}",
          color: color_by_name[src] || PALETTE[s_idx % PALETTE.size],
          points: s.map { |r| [r[:relative_time], lookup_prefix(prefix_arr, r[:corpus_count])] }
        }
      end
    ),
    render_svg_chart(
      title: "Execution Speed (execs/sec)",
      subtitle: "Target executions per second over time",
      y_format: :rate,
      fill_area: true,
      zero_base: true,
      chart_id: "#{name}-speed",
      series: [{ name: "execs_per_sec", color: "#a78bfa", points: s.map { |r| [r[:relative_time], r[:execs_per_sec]] } }]
    ),
    render_svg_chart(
      title: "Cumulative Executions",
      subtitle: "Total executions completed by #{name}",
      y_format: :compact,
      fill_area: true,
      zero_base: true,
      chart_id: "#{name}-execs",
      series: [{ name: "total_execs", color: "#60a5fa", points: s.map { |r| [r[:relative_time], r[:total_execs]] } }]
    ),
    render_svg_chart(
      title: "Crashes, Hangs & Queue Depth",
      subtitle: "Saved crashes, saved hangs, cycles done, and max mutation depth",
      y_format: :int,
      fill_area: false,
      zero_base: true,
      chart_id: "#{name}-findings",
      series: [
        { name: "saved_crashes", color: "#fb7185", points: s.map { |r| [r[:relative_time], r[:saved_crashes]] } },
        { name: "saved_hangs", color: "#fbbf24", points: s.map { |r| [r[:relative_time], r[:saved_hangs]] } },
        { name: "max_depth", color: "#38bdf8", points: s.map { |r| [r[:relative_time], r[:max_depth]] } },
        { name: "cycles_done", color: "#4ade80", points: s.map { |r| [r[:relative_time], r[:cycles_done]] } }
      ]
    )
  ].join("\n")

  cmd_line = f[:stats]["command_line"] || ""
  oc = cov_by_origin[name]
  worker_cov_btn = (oc && oc["report_rel_path"]) ? %(<a class="cov-btn" href="#{CGI.escapeHTML(oc['report_rel_path'])}" target="_blank" rel="noopener">Worker llvm-cov HTML &nearr;</a>) : ""
  worker_cov_kpis = if oc && oc["has_coverage"]
                      ol = oc.dig("totals", "lines") || {}
                      ob = oc.dig("totals", "branches") || {}
                      vc_l = oc.dig("vs_corpus", "lines", "covered").to_i
                      vc_b = oc.dig("vs_corpus", "branches", "covered").to_i
                      ex_l = oc.dig("exclusive", "lines", "covered").to_i
                      ex_b = oc.dig("exclusive", "branches", "covered").to_i
                      <<~COV_KPI
                        <div class="kpi-card">
                          <div class="kpi-label">Source Coverage (Originated)</div>
                          <div class="kpi-value">#{format("%.2f%%", ol["percent"].to_f)}</div>
                          <div class="kpi-sub">#{format_int(ol["covered"].to_i)} lines &bull; #{format("%.2f%%", ob["percent"].to_f)} branches (+#{format_int(vc_l)}L / +#{format_int(vc_b)}B vs corpus)</div>
                        </div>
                        <div class="kpi-card">
                          <div class="kpi-label">Exclusive to #{safe_name}</div>
                          <div class="kpi-value">+#{format_int(ex_l)}L / +#{format_int(ex_b)}B</div>
                          <div class="kpi-sub">lines &amp; branches not hit by any other origin</div>
                        </div>
                      COV_KPI
                    else
                      ""
                    end

  tab_panels_html << <<~HTML
    <section id="tab-#{safe_name}" class="tab-panel">
      <div class="fuzzer-banner">
        <div>
          <h2><span class="legend-dot" style="background:#{f[:color]}"></span> #{safe_name}</h2>
          <p class="cmd-line"><code>#{CGI.escapeHTML(cmd_line)}</code></p>
        </div>
        <div class="fuzzer-meta">
          <span class="sched-pill">Schedule: #{CGI.escapeHTML(f[:sched])}</span>
          <span class="sched-pill">Stability: #{CGI.escapeHTML(f[:stability])}</span>
          <span class="sched-pill">Samples: #{format_int(f[:sample_count])}</span>
          #{worker_cov_btn}
        </div>
      </div>

      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-label">AFL++ Map Coverage</div>
          <div class="kpi-value">#{format("%.2f%%", f[:bitmap_cvg])}</div>
          <div class="kpi-sub">#{format_int(f[:edges_found])}#{f[:total_edges] > 0 ? " / #{format_int(f[:total_edges])}" : ""} edges</div>
        </div>
        #{worker_cov_kpis}
        <div class="kpi-card">
          <div class="kpi-label">Throughput</div>
          <div class="kpi-value">#{format_int(f[:execs_per_sec].round)}/s</div>
          <div class="kpi-sub">#{format_compact(f[:execs_done])} total execs</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Corpus Queue</div>
          <div class="kpi-value">#{format_int(f[:corpus_count])}</div>
          <div class="kpi-sub">+#{format_int(f[:corpus_found])} local, #{format_int(f[:corpus_imported])} synced</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Pending (Fav / Total)</div>
          <div class="kpi-value">#{format_int(f[:pending_favs])}</div>
          <div class="kpi-sub">of #{format_int(f[:pending_total])} unfuzzed</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Cycles / Max Depth</div>
          <div class="kpi-value">#{f[:cycles_done]}</div>
          <div class="kpi-sub">max depth #{f[:max_depth]}</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Crashes / Hangs</div>
          <div class="kpi-value #{f[:saved_crashes] > 0 ? 'text-danger' : ''}">#{f[:saved_crashes]} / #{f[:saved_hangs]}</div>
          <div class="kpi-sub"> Peak RSS: #{f[:stats]['peak_rss_mb'] || '-'} MB</div>
        </div>
        #{if (ps = peer_sync_by_name[f[:name]])
            if ps[:sync_mode] == :foreign_queue || ps[:sync_mode] == :shadow_peer
              upstream_gen_entry = peer_sync_by_name.find { |_gn, gps| gps[:is_generator] && gps[:consumer_name] == f[:name] }
              intake_kpi = if upstream_gen_entry
                             gen_name, gen_ps = upstream_gen_entry
                             <<~INTAKE_KPI
                               <div class="kpi-card">
                                 <div class="kpi-label">Intake from #{CGI.escapeHTML(gen_name)} (-F)</div>
                                 <div class="kpi-value">+#{format_int(gen_ps[:imported_by_main])} <span class="muted">(#{format("%.1f%%", gen_ps[:yield_pct])})</span></div>
                                 <div class="kpi-sub">#{format_int(gen_ps[:tested_by_main])} seeds tested &bull; standalone master (-M)</div>
                               </div>
                             INTAKE_KPI
                           else
                             <<~INTAKE_KPI
                               <div class="kpi-card">
                                 <div class="kpi-label">Sync Role</div>
                                 <div class="kpi-value">Master (-M)</div>
                                 <div class="kpi-sub">isolated sync root (no sync from #{CGI.escapeHTML(main_name)})</div>
                               </div>
                             INTAKE_KPI
                           end
              sync_to_label = ps[:sync_mode] == :shadow_peer ? "Sync to #{CGI.escapeHTML(main_name)}" : "Foreign Sync to #{CGI.escapeHTML(main_name)} (-F)"
              cursor_word = ps[:sync_mode] == :shadow_peer ? "cursor" : "scanned"
              <<~SYNC_KPI
                <div class="kpi-card">
                  <div class="kpi-label">#{sync_to_label}</div>
                  <div class="kpi-value">+#{format_int(ps[:imported_by_main])} <span class="muted">(#{format("%.1f%%", ps[:yield_pct])})</span></div>
                  <div class="kpi-sub">#{format_int(ps[:tested_by_main])} tested &bull; #{cursor_word} #{format_int(ps[:cursor])}/#{format_int(ps[:peer_total])} (#{format("%.0f%%", ps[:sync_pct])})</div>
                </div>
                #{intake_kpi}
              SYNC_KPI
            else
              <<~SYNC_KPI
                <div class="kpi-card">
                  <div class="kpi-label">Sync to #{CGI.escapeHTML(main_name)}</div>
                  <div class="kpi-value">+#{format_int(ps[:imported_by_main])} <span class="muted">(#{format("%.1f%%", ps[:yield_pct])})</span></div>
                  <div class="kpi-sub">#{format_int(ps[:tested_by_main])} tested &bull; cursor #{format_int(ps[:cursor])}/#{format_int(ps[:peer_total])} (#{format("%.0f%%", ps[:sync_pct])})</div>
                </div>
                <div class="kpi-card">
                  <div class="kpi-label">Sync from #{CGI.escapeHTML(main_name)}</div>
                  <div class="kpi-value">#{format("%.0f%%", ps[:peer_from_main_pct])}</div>
                  <div class="kpi-sub">cursor #{format_int(ps[:peer_from_main_cursor])} / #{format_int(main_fuzzer[:corpus_count])} in #{CGI.escapeHTML(main_name)}</div>
                </div>
              SYNC_KPI
            end
          else
            ""
          end}
      </div>

      <div class="charts-grid">
        #{fuzzer_charts}
      </div>

      #{
        worker_paths = (fleet_lineage[:pathways] || []).select { |p| p[:hops].include?(name) }
        if worker_paths.any?
          direct_cnt = worker_paths.select { |p| p[:crash_worker] == name }.sum { |p| p[:count] }
          assist_cnt = worker_paths.reject { |p| p[:crash_worker] == name }.sum { |p| p[:count] }
          render_crash_lineage_table(
            worker_paths,
            worker_paths.sum { |p| p[:count] },
            color_by_name,
            id_prefix: "w-lineage-#{name.gsub(/[^a-zA-Z0-9_-]/, '_')}",
            title: "Crash Lineage Involving <code>#{safe_name}</code> (#{format_int(direct_cnt)} Direct Crashes &bull; #{format_int(assist_cnt)} Forwarded to Peers)",
            subtitle: "Pathways where #{safe_name} either discovered the crash directly or mutated/forwarded an ancestor queue item that later crashed in another worker."
          )
        else
          ""
        end
      }
      #{render_worker_cov_files_table(oc, f[:color])}
    </section>
  HTML
end

html = <<~HTML
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Prism AFL++ Fuzzing Plots</title>
    <style>
      :root {
        --bg: #0b0f19;
        --panel: #111827;
        --panel-border: #1f2937;
        --text: #f3f4f6;
        --muted: #9ca3af;
        --accent: #60a5fa;
        --danger: #fb7185;
        --warn: #fbbf24;
        --success: #34d399;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
        background: var(--bg);
        color: var(--text);
        line-height: 1.45;
      }
      header {
        background: #0f172a;
        border-bottom: 1px solid var(--panel-border);
        padding: 18px 28px 0 28px;
        position: sticky;
        top: 0;
        z-index: 20;
      }
      .header-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 12px;
        margin-bottom: 14px;
      }
      .header-title {
        display: flex;
        align-items: baseline;
        gap: 12px;
      }
      .header-title h1 {
        margin: 0;
        font-size: 1.3rem;
        font-weight: 700;
        letter-spacing: -0.02em;
      }
      .header-sub {
        color: var(--muted);
        font-size: 0.85rem;
      }
      .tabs-bar {
        display: flex;
        gap: 6px;
        overflow-x: auto;
        padding-bottom: 1px;
      }
      .tab-btn {
        background: transparent;
        color: var(--muted);
        border: 1px solid transparent;
        border-bottom: 2px solid transparent;
        padding: 8px 14px;
        font-size: 0.86rem;
        font-weight: 600;
        cursor: pointer;
        border-radius: 6px 6px 0 0;
        display: inline-flex;
        align-items: center;
        gap: 7px;
        white-space: nowrap;
        transition: all 0.15s ease;
      }
      .tab-btn:hover {
        color: var(--text);
        background: rgba(255, 255, 255, 0.04);
      }
      .tab-btn.active {
        color: var(--accent);
        background: var(--bg);
        border-color: var(--panel-border);
        border-bottom-color: var(--accent);
      }
      .tab-crash {
        background: rgba(251, 113, 133, 0.2);
        color: var(--danger);
        font-size: 0.72rem;
        padding: 1px 6px;
        border-radius: 999px;
      }
      main {
        max-width: 1440px;
        margin: 0 auto;
        padding: 24px 28px 48px 28px;
      }
      .tab-panel { display: none; }
      .tab-panel.active { display: block; }
      .kpi-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        gap: 14px;
        margin-bottom: 22px;
      }
      .kpi-card {
        background: var(--panel);
        border: 1px solid var(--panel-border);
        border-radius: 10px;
        padding: 14px 16px;
      }
      .kpi-label {
        color: var(--muted);
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.04em;
      }
      .kpi-value {
        font-size: 1.55rem;
        font-weight: 700;
        margin: 4px 0 2px 0;
        font-variant-numeric: tabular-nums;
      }
      .kpi-sub {
        color: var(--muted);
        font-size: 0.8rem;
        font-variant-numeric: tabular-nums;
      }
      .text-danger { color: var(--danger); }
      .charts-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(540px, 1fr));
        gap: 18px;
        margin-bottom: 26px;
      }
      .chart-card {
        background: var(--panel);
        border: 1px solid var(--panel-border);
        border-radius: 10px;
        padding: 16px 18px 12px 18px;
        display: flex;
        flex-direction: column;
      }
      .chart-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 12px;
        flex-wrap: wrap;
        margin-bottom: 8px;
      }
      .chart-header h3 {
        margin: 0;
        font-size: 0.98rem;
        font-weight: 600;
      }
      .chart-sub {
        margin: 2px 0 0 0;
        color: var(--muted);
        font-size: 0.78rem;
      }
      .chart-legend {
        display: flex;
        flex-wrap: wrap;
        gap: 8px 12px;
        font-size: 0.76rem;
        max-width: 100%;
      }
      .legend-item {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 2px 6px;
        border-radius: 5px;
        cursor: pointer;
        transition: all 0.12s ease;
      }
      .legend-item:hover, .legend-item.active {
        background: rgba(255, 255, 255, 0.1);
        outline: 1px solid rgba(255, 255, 255, 0.22);
      }
      .legend-item.dimmed {
        opacity: 0.3;
      }
      .legend-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        display: inline-block;
        flex-shrink: 0;
      }
      .legend-name { color: var(--muted); }
      .legend-item.active .legend-name { color: var(--text); font-weight: 600; }
      .legend-val {
        font-weight: 600;
        font-variant-numeric: tabular-nums;
      }
      .svg-wrap {
        position: relative;
        width: 100%;
      }
      .plot-svg {
        width: 100%;
        height: auto;
        display: block;
        overflow: visible;
      }
      .series-group {
        transition: opacity 0.12s ease;
      }
      .series-group.dimmed {
        opacity: 0.16;
      }
      .series-group.active .series-line {
        stroke-width: 3.5px !important;
        filter: drop-shadow(0 0 5px rgba(255, 255, 255, 0.35));
      }
      .series-group.active .series-dot {
        r: 5px;
      }
      .series-hit {
        cursor: pointer;
      }
      .grid-line {
        stroke: #1f2937;
        stroke-dasharray: 3 3;
        stroke-width: 1;
      }
      .axis-tick {
        stroke: #374151;
        stroke-width: 1;
      }
      .axis-label {
        fill: #9ca3af;
        font-size: 11px;
        font-variant-numeric: tabular-nums;
      }
      .hover-line {
        stroke: #9ca3af;
        stroke-width: 1;
        stroke-dasharray: 2 2;
        pointer-events: none;
      }
      .hover-dot {
        stroke: #0b0f19;
        stroke-width: 2;
        pointer-events: none;
      }
      .line-badge {
        position: absolute;
        background: rgba(15, 23, 42, 0.96);
        border: 1px solid #475569;
        color: var(--text);
        font-size: 0.78rem;
        font-weight: 600;
        padding: 4px 9px;
        border-radius: 6px;
        pointer-events: none;
        z-index: 15;
        white-space: nowrap;
        box-shadow: 0 6px 16px rgba(0, 0, 0, 0.5);
        transform: translate(-50%, -130%);
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .chart-tooltip {
        position: absolute;
        top: 8px;
        right: 12px;
        background: rgba(15, 23, 42, 0.95);
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 8px 10px;
        font-size: 0.75rem;
        pointer-events: none;
        z-index: 10;
        box-shadow: 0 8px 20px rgba(0, 0, 0, 0.45);
        min-width: 150px;
      }
      .tt-time {
        font-weight: 600;
        color: var(--text);
        margin-bottom: 4px;
        border-bottom: 1px solid #1e293b;
        padding-bottom: 3px;
      }
      .tt-row {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        font-variant-numeric: tabular-nums;
        padding: 1px 4px;
        border-radius: 4px;
      }
      .tt-row.active {
        background: rgba(255, 255, 255, 0.14);
        font-weight: 700;
      }
      .empty-chart {
        height: 220px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: var(--muted);
        font-size: 0.85rem;
      }
      .table-card {
        background: var(--panel);
        border: 1px solid var(--panel-border);
        border-radius: 10px;
        overflow-x: auto;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.85rem;
      }
      th, td {
        padding: 10px 14px;
        text-align: left;
        border-bottom: 1px solid var(--panel-border);
      }
      th {
        color: var(--muted);
        font-weight: 600;
        font-size: 0.76rem;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        background: rgba(255, 255, 255, 0.02);
      }
      td.num, th.num {
        text-align: right;
        font-variant-numeric: tabular-nums;
      }
      .clickable-row { cursor: pointer; }
      .clickable-row:hover { background: rgba(255, 255, 255, 0.03); }
      .muted { color: var(--muted); font-size: 0.78rem; }
      .sched-pill {
        background: #1e293b;
        color: #cbd5e1;
        padding: 3px 8px;
        border-radius: 999px;
        font-size: 0.76rem;
      }
      .badge {
        padding: 2px 8px;
        border-radius: 999px;
        font-weight: 600;
        font-size: 0.76rem;
      }
      .badge-muted { background: #1f2937; color: #9ca3af; }
      .badge-danger { background: rgba(251, 113, 133, 0.2); color: var(--danger); }
      .badge-warn { background: rgba(251, 191, 36, 0.2); color: var(--warn); }
      .badge-success { background: rgba(52, 211, 153, 0.18); color: var(--success); }
      .text-warn { color: var(--warn); font-weight: 600; }
      .cov-gain { color: var(--success); font-weight: 600; font-size: 0.8rem; }
      .cov-link {
        color: var(--accent);
        text-decoration: none;
        font-weight: 600;
        font-size: 0.78rem;
      }
      .cov-link:hover { text-decoration: underline; }
      .cov-btn {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(96, 165, 250, 0.16);
        border: 1px solid rgba(96, 165, 250, 0.4);
        color: var(--accent);
        padding: 5px 12px;
        border-radius: 7px;
        font-size: 0.8rem;
        font-weight: 600;
        text-decoration: none;
        transition: all 0.15s ease;
      }
      .cov-btn:hover {
        background: rgba(96, 165, 250, 0.28);
        color: #fff;
      }
      .cov-btn-secondary {
        background: rgba(255, 255, 255, 0.05);
        border-color: var(--panel-border);
        color: var(--text);
      }
      .cov-btn-secondary:hover {
        background: rgba(255, 255, 255, 0.12);
      }
      .table-card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 12px;
        padding: 14px 16px 10px 16px;
        border-bottom: 1px solid var(--panel-border);
      }
      .table-card-header h3 {
        margin: 0;
        font-size: 0.98rem;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .cov-bars-head {
        display: grid;
        grid-template-columns: 220px 1fr 150px 150px 90px;
        gap: 14px;
        padding: 6px 8px;
        color: var(--muted);
        font-size: 0.74rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        border-bottom: 1px solid var(--panel-border);
      }
      .cov-bar-row {
        display: grid;
        grid-template-columns: 220px 1fr 150px 150px 90px;
        gap: 14px;
        align-items: center;
        padding: 8px;
        border-bottom: 1px solid rgba(31, 41, 55, 0.6);
        font-size: 0.82rem;
        border-radius: 6px;
      }
      .cov-bar-row:last-child { border-bottom: none; }
      .cov-dual-bars {
        display: flex;
        flex-direction: column;
        gap: 5px;
      }
      .cov-bar-line {
        display: grid;
        grid-template-columns: 62px 1fr 155px;
        gap: 10px;
        align-items: center;
      }
      .cov-bar-tag {
        color: var(--muted);
        font-size: 0.74rem;
      }
      .cov-bar-pct {
        text-align: right;
        font-variant-numeric: tabular-nums;
        font-size: 0.78rem;
      }
      .excl-pill {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid var(--panel-border);
        border-radius: 999px;
        padding: 2px 8px;
        font-size: 0.74rem;
        margin: 1px 2px;
        font-variant-numeric: tabular-nums;
      }
      .clickable-pill { cursor: pointer; }
      .clickable-pill:hover {
        background: rgba(255, 255, 255, 0.12);
        border-color: var(--accent);
      }
      .fuzzer-banner {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        flex-wrap: wrap;
        gap: 12px;
        margin-bottom: 16px;
        background: var(--panel);
        border: 1px solid var(--panel-border);
        border-radius: 10px;
        padding: 14px 18px;
      }
      .fuzzer-banner h2 {
        margin: 0 0 4px 0;
        font-size: 1.15rem;
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .cmd-line {
        margin: 0;
        color: var(--muted);
        font-size: 0.78rem;
        word-break: break-all;
      }
      .fuzzer-meta {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
      }
      .sync-overview-card {
        margin-bottom: 22px;
      }
      .sync-rows-head {
        display: grid;
        grid-template-columns: 210px 1fr 160px 210px;
        gap: 14px;
        padding: 6px 8px;
        color: var(--muted);
        font-size: 0.74rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        border-bottom: 1px solid var(--panel-border);
      }
      .sync-rows {
        display: flex;
        flex-direction: column;
      }
      .sync-row {
        display: grid;
        grid-template-columns: 210px 1fr 160px 210px;
        gap: 14px;
        align-items: center;
        padding: 7px 8px;
        border-bottom: 1px solid rgba(31, 41, 55, 0.6);
        font-size: 0.82rem;
        cursor: pointer;
        border-radius: 6px;
      }
      .sync-row:hover {
        background: rgba(255, 255, 255, 0.035);
      }
      .sync-row:last-child {
        border-bottom: none;
      }
      .sync-peer {
        display: flex;
        align-items: center;
        gap: 8px;
        white-space: nowrap;
      }
      .sync-bar-wrap {
        width: 100%;
      }
      .sync-bar {
        display: flex;
        width: 100%;
        height: 12px;
        background: #0b0f19;
        border: 1px solid #1f2937;
        border-radius: 6px;
        overflow: hidden;
      }
      .sync-seg {
        height: 100%;
      }
      .sync-seg-imported { background: #34d399; }
      .sync-seg-rejected { background: #3b82f6; }
      .sync-seg-skipped { background: #475569; }
      .sync-seg-unsynced { background: #1e293b; }
      .sync-stat {
        text-align: right;
        font-variant-numeric: tabular-nums;
        white-space: nowrap;
      }
      .sync-primary { font-weight: 600; color: var(--text); }
      .sync-pct { color: var(--muted); font-size: 0.76rem; margin-left: 4px; }
      .sync-imported { font-weight: 700; color: #34d399; }
      .sync-secondary { color: var(--muted); font-size: 0.78rem; margin-left: 3px; }
      .hunk-drawer-row {
        background: #080d16;
      }
      .hunk-drawer-cell {
        padding: 12px 16px 16px 26px !important;
        border-bottom: 1px solid var(--panel-border);
      }
      .origin-hunk-group {
        margin-bottom: 14px;
      }
      .origin-hunk-group:last-child {
        margin-bottom: 0;
      }
      .origin-hunk-title {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 0.8rem;
        margin-bottom: 6px;
        padding-bottom: 4px;
        border-bottom: 1px dashed rgba(255, 255, 255, 0.1);
      }
      .hunk-tab-btn {
        background: rgba(255, 255, 255, 0.06);
        border: 1px solid var(--panel-border);
        color: var(--text);
        border-radius: 5px;
        padding: 2px 8px;
        font-size: 0.72rem;
        cursor: pointer;
        margin-left: auto;
      }
      .hunk-tab-btn:hover {
        border-color: var(--accent);
        background: rgba(56, 189, 248, 0.12);
      }
      .hunk-box {
        background: #0b0f19;
        border: 1px solid #1f2937;
        border-radius: 7px;
        margin-bottom: 10px;
        overflow: hidden;
      }
      .hunk-box:last-child {
        margin-bottom: 0;
      }
      .hunk-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 8px;
        padding: 6px 10px;
        background: #131c2e;
        border-bottom: 1px solid #1f2937;
        font-size: 0.76rem;
      }
      .hunk-fn {
        color: #f8fafc;
        font-family: "SFMono-Regular", Menlo, Monaco, Consolas, monospace;
      }
      .hunk-range {
        color: var(--muted);
        margin-left: 8px;
        font-variant-numeric: tabular-nums;
      }
      .hunk-jump {
        color: var(--accent);
        text-decoration: none;
        font-weight: 600;
        font-size: 0.74rem;
      }
      .hunk-jump:hover {
        text-decoration: underline;
      }
      .hunk-body {
        display: flex;
        flex-direction: column;
        font-family: "SFMono-Regular", Menlo, Monaco, Consolas, monospace;
        font-size: 0.75rem;
        line-height: 1.45;
        overflow-x: auto;
      }
      .hunk-code-row {
        display: grid;
        grid-template-columns: 54px auto 1fr;
        gap: 8px;
        align-items: baseline;
        padding: 1px 10px;
        white-space: pre;
      }
      .hunk-context {
        color: #64748b;
      }
      .hunk-line-excl {
        background: rgba(16, 185, 129, 0.14);
        border-left: 3px solid #10b981;
        padding-left: 7px;
        color: #ecfdf5;
      }
      .hunk-branch-excl {
        background: rgba(56, 189, 248, 0.12);
        border-left: 3px solid #38bdf8;
        padding-left: 7px;
        color: #f0f9ff;
      }
      .hunk-ln {
        text-align: right;
        color: #64748b;
        text-decoration: none;
        user-select: none;
        font-variant-numeric: tabular-nums;
      }
      .hunk-ln:hover {
        color: var(--accent);
        text-decoration: underline;
      }
      .hunk-badges {
        display: inline-flex;
        gap: 4px;
        align-items: center;
      }
      .hunk-tag {
        display: inline-block;
        padding: 0 5px;
        border-radius: 3px;
        font-size: 0.66rem;
        font-weight: 700;
        letter-spacing: 0.02em;
      }
      .hunk-tag-line {
        background: #065f46;
        color: #a7f3d0;
        border: 1px solid #10b981;
      }
      .hunk-tag-branch {
        background: #075985;
        color: #bae6fd;
        border: 1px solid #38bdf8;
      }
      .hunk-tag-branch-false {
        background: #78350f;
        color: #fde68a;
        border: 1px solid #f59e0b;
      }
      .hunk-br-span {
        background: rgba(56, 189, 248, 0.25);
        color: #fff;
        border-bottom: 2px solid #38bdf8;
        border-radius: 2px;
        padding: 0 2px;
      }
      .hunk-br-false {
        background: rgba(245, 158, 11, 0.22);
        border-bottom-color: #f59e0b;
      }
      .hunk-src {
        overflow-x: visible;
      }
      .hop-pill {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid var(--panel-border);
        border-radius: 6px;
        padding: 2px 8px;
        font-size: 0.75rem;
        font-weight: 600;
      }
      .hop-arrow {
        color: var(--muted);
        margin: 0 5px;
        font-size: 0.78rem;
      }
      .evo-chain-wrap {
        display: flex;
        flex-direction: column;
        gap: 4px;
      }
      .evo-step {
        background: #0b0f19;
        border: 1px solid #1f2937;
        border-left: 3px solid #38bdf8;
        border-radius: 7px;
        padding: 8px 12px;
      }
      .evo-step-root {
        border-left-color: #34d399;
      }
      .evo-step-crash {
        border-left-color: #fb7185;
        background: rgba(251, 113, 133, 0.05);
      }
      .evo-step-head {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 8px;
        font-size: 0.76rem;
      }
      .evo-step-num {
        font-weight: 700;
        color: var(--muted);
        text-transform: uppercase;
        font-size: 0.68rem;
        letter-spacing: 0.04em;
      }
      .evo-fname {
        color: #e2e8f0;
        font-size: 0.74rem;
      }
      .evo-op {
        color: #93c5fd;
        font-size: 0.74rem;
      }
      .evo-size {
        margin-left: auto;
        color: var(--muted);
        font-variant-numeric: tabular-nums;
        font-size: 0.73rem;
      }
      .evo-preview {
        margin: 6px 0 0 0;
        padding: 6px 10px;
        background: #060911;
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 5px;
        font-family: "SFMono-Regular", Menlo, Monaco, Consolas, monospace;
        font-size: 0.73rem;
        line-height: 1.4;
        color: #d1d5db;
        white-space: pre-wrap;
        word-break: break-all;
        max-height: 160px;
        overflow-y: auto;
      }
      .evo-connector {
        text-align: left;
        padding-left: 24px;
        color: var(--muted);
        font-size: 0.75rem;
        line-height: 1;
      }
    </style>
  </head>
  <body>
    <header>
      <div class="header-top">
        <div class="header-title">
          <h1>Prism AFL++ Fuzzing Telemetry</h1>
          <span class="header-sub">Source: <code>#{CGI.escapeHTML(afl_dir)}</code> &bull; Runtime: #{format_duration(fleet_max_runtime)} &bull; Generated: #{Time.now.strftime("%Y-%m-%d %H:%M:%S")}</span>
        </div>
        #{if combined_cov && combined_cov["report_rel_path"]
            %(<div class="fuzzer-meta"><a class="cov-btn" href="#{CGI.escapeHTML(combined_cov['report_rel_path'])}" target="_blank" rel="noopener">Combined llvm-cov HTML &nearr;</a></div>)
          else
            ""
          end}
      </div>
      <nav class="tabs-bar">
        #{tab_buttons_html}
      </nav>
    </header>

    <main>
      <section id="tab-overview" class="tab-panel active">
        <div class="kpi-grid">
          <div class="kpi-card">
            <div class="kpi-label">Fuzzer Workers</div>
            <div class="kpi-value">#{afl_fuzzers.size}</div>
            <div class="kpi-sub">Uptime #{format_duration(fleet_max_runtime)}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Fleet Speed</div>
            <div class="kpi-value">#{format_int(fleet_speed.round)}/s</div>
            <div class="kpi-sub">#{format_compact(fleet_execs)} total execs</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Main Coverage</div>
            <div class="kpi-value">#{format("%.2f%%", main_fuzzer[:bitmap_cvg])}</div>
            <div class="kpi-sub">#{format_int(main_fuzzer[:edges_found])} / #{format_int(main_fuzzer[:total_edges])} edges</div>
          </div>
          #{if combined_cov
              cl_tot = combined_cov.dig("totals", "lines") || {}
              cb_tot = combined_cov.dig("totals", "branches") || {}
              <<~COV_KPI
                <div class="kpi-card clickable-row" onclick="selectTab('coverage')">
                  <div class="kpi-label">Source Coverage (LLVM)</div>
                  <div class="kpi-value">#{format("%.2f%%", cl_tot["percent"].to_f)}</div>
                  <div class="kpi-sub">#{format_int(cl_tot["covered"].to_i)} lines &bull; #{format("%.2f%%", cb_tot["percent"].to_f)} branches</div>
                </div>
              COV_KPI
            else
              ""
            end}
          <div class="kpi-card">
            <div class="kpi-label">Max Queue Size</div>
            <div class="kpi-value">#{format_int(fleet_max_corpus)}</div>
            <div class="kpi-sub">across AFL++ workers</div>
          </div>
          #{if gen_fuzzers.any?
              gen_total_files = gen_fuzzers.sum { |gf| gf[:files_created] }
              gen_total_rate = gen_fuzzers.sum { |gf| gf[:files_per_sec] }
              <<~GEN_KPI
                <div class="kpi-card">
                  <div class="kpi-label">Grammar Seeds</div>
                  <div class="kpi-value">#{format_int(gen_total_files)}</div>
                  <div class="kpi-sub">#{format_compact(gen_total_rate)} files/s</div>
                </div>
              GEN_KPI
            else
              ""
            end}
          <div class="kpi-card">
            <div class="kpi-label">Saved Crashes</div>
            <div class="kpi-value #{fleet_crashes > 0 ? 'text-danger' : ''}">#{fleet_crashes}</div>
            <div class="kpi-sub">#{fleet_lineage[:total_grammar_crashes]} grammar &bull; #{fleet_lineage[:total_corpus_crashes]} corpus &bull; #{fleet_hangs} hangs</div>
          </div>
        </div>

        <div class="charts-grid">
          #{overview_charts}
        </div>

        #{peer_sync_card_html}

        <div class="table-card">
          <table>
            <thead>
              <tr>
                <th>Fuzzer</th>
                <th>Binary</th>
                <th>Schedule</th>
                <th class="num">Speed</th>
                <th class="num">Total Execs</th>
                <th class="num">Map %</th>
                <th class="num">Edges</th>
                <th class="num">Src Line %</th>
                <th class="num">Exclusive</th>
                <th class="num">Corpus</th>
                <th class="num">Local Finds</th>
                <th class="num">Synced</th>
                <th class="num">Main Sync</th>
                <th class="num">Main Yield (Imp / Tested)</th>
                <th class="num">Pending (Fav/All)</th>
                <th class="num">Crashes</th>
                <th class="num">Hangs</th>
                <th class="num">Report</th>
              </tr>
            </thead>
            <tbody>
              #{summary_rows_html}
            </tbody>
          </table>
        </div>

        #{generator_table_html}
        #{overview_crash_lineage_html}
      </section>

      #{tab_panels_html}
    </main>

    <script>
      function selectTab(name, push = true) {
        if (!document.getElementById('tab-' + name)) return;
        document.querySelectorAll('.tab-btn').forEach(btn => {
          btn.classList.toggle('active', btn.dataset.tab === name);
        });
        document.querySelectorAll('.tab-panel').forEach(panel => {
          panel.classList.toggle('active', panel.id === 'tab-' + name);
        });
        const targetHash = '#' + encodeURIComponent(name);
        if (push && window.location.hash !== targetHash && history.pushState) {
          history.pushState({ tab: name }, '', targetHash);
          window.scrollTo({ top: 0, behavior: 'instant' });
        }
      }

      function formatDuration(sec) {
        sec = Math.max(0, Math.round(sec));
        const h = Math.floor(sec / 3600);
        const m = Math.floor((sec % 3600) / 60);
        const s = sec % 60;
        if (h > 0) return h + 'h ' + String(m).padStart(2, '0') + 'm';
        if (m > 0) return m + 'm ' + String(s).padStart(2, '0') + 's';
        return s + 's';
      }

      document.querySelectorAll('.chart-card[data-series]').forEach(card => {
        const series = JSON.parse(card.dataset.series || '[]');
        const minX = parseFloat(card.dataset.minX);
        const maxX = parseFloat(card.dataset.maxX);
        const padL = parseFloat(card.dataset.padL);
        const plotW = parseFloat(card.dataset.plotW);
        const svg = card.querySelector('.plot-svg');
        const hoverLine = card.querySelector('.hover-line');
        const hoverDot = card.querySelector('.hover-dot');
        const lineBadge = card.querySelector('.line-badge');
        const tooltip = card.querySelector('.chart-tooltip');
        const groups = Array.from(card.querySelectorAll('.series-group'));
        const legendItems = Array.from(card.querySelectorAll('.legend-item'));
        if (!svg || !series.length) return;

        let pinnedSeries = null;

        function highlightSeries(activeName) {
          if (groups.length <= 1) return;
          groups.forEach(g => {
            const match = g.dataset.seriesName === activeName;
            g.classList.toggle('active', !!activeName && match);
            g.classList.toggle('dimmed', !!activeName && !match);
            if (match && activeName && g.parentNode) {
              g.parentNode.appendChild(g);
              if (hoverLine) g.parentNode.appendChild(hoverLine);
              if (hoverDot) g.parentNode.appendChild(hoverDot);
            }
          });
          legendItems.forEach(item => {
            const match = item.dataset.seriesName === activeName;
            item.classList.toggle('active', !!activeName && match);
            item.classList.toggle('dimmed', !!activeName && !match);
          });
        }

        legendItems.forEach(item => {
          const sName = item.dataset.seriesName;
          item.addEventListener('mouseenter', () => highlightSeries(sName));
          item.addEventListener('mouseleave', () => highlightSeries(pinnedSeries));
          item.addEventListener('click', () => {
            pinnedSeries = (pinnedSeries === sName) ? null : sName;
            highlightSeries(pinnedSeries);
          });
        });

        svg.addEventListener('mousemove', e => {
          const rect = svg.getBoundingClientRect();
          const scaleX = 580 / rect.width;
          const scaleY = 270 / rect.height;
          const svgX = (e.clientX - rect.left) * scaleX;
          const svgY = (e.clientY - rect.top) * scaleY;
          if (svgX < padL || svgX > padL + plotW) {
            hoverLine.style.display = 'none';
            hoverDot.style.display = 'none';
            lineBadge.style.display = 'none';
            tooltip.style.display = 'none';
            highlightSeries(pinnedSeries);
            return;
          }
          const ratio = (svgX - padL) / plotW;
          const targetT = minX + ratio * (maxX - minX);

          hoverLine.setAttribute('x1', svgX.toFixed(1));
          hoverLine.setAttribute('x2', svgX.toFixed(1));
          hoverLine.style.display = '';

          // Determine closest series at this time slice (or directly hovered path)
          const directHit = e.target.closest('.series-hit');
          let hoveredSeriesName = directHit ? directHit.dataset.seriesName : null;
          let closestPointBySeries = {};
          let minVerticalDist = Infinity;
          let nearestSeries = null;

          series.forEach(s => {
            if (!s.points.length) return;
            let best = s.points[0];
            let bestDist = Math.abs(best[0] - targetT);
            for (let i = 1; i < s.points.length; i++) {
              const d = Math.abs(s.points[i][0] - targetT);
              if (d < bestDist) { bestDist = d; best = s.points[i]; }
            }
            closestPointBySeries[s.name] = { series: s, point: best };
            const vDist = Math.abs(best[3] - svgY);
            if (vDist < minVerticalDist) {
              minVerticalDist = vDist;
              nearestSeries = s.name;
            }
          });

          if (!hoveredSeriesName && minVerticalDist <= 28) {
            hoveredSeriesName = nearestSeries;
          }
          const activeName = pinnedSeries || hoveredSeriesName || (series.length === 1 ? series[0].name : null);
          highlightSeries(activeName);

          if (activeName && closestPointBySeries[activeName]) {
            const activeInfo = closestPointBySeries[activeName];
            const pt = activeInfo.point;
            const ptSvgX = padL + ((pt[0] - minX) / (maxX - minX)) * plotW;
            const ptSvgY = pt[3];
            hoverDot.setAttribute('cx', ptSvgX.toFixed(1));
            hoverDot.setAttribute('cy', ptSvgY.toFixed(1));
            hoverDot.setAttribute('fill', activeInfo.series.color);
            hoverDot.style.display = '';

            const badgeLeft = (ptSvgX / 580) * rect.width;
            const badgeTop = (ptSvgY / 270) * rect.height;
            lineBadge.style.left = Math.min(Math.max(badgeLeft, 50), rect.width - 60) + 'px';
            lineBadge.style.top = Math.max(badgeTop, 28) + 'px';
            lineBadge.innerHTML = '<span class="legend-dot" style="background:' + activeInfo.series.color + '"></span>' +
              '<span>' + activeInfo.series.name + ': <strong>' + pt[2] + '</strong></span>';
            lineBadge.style.display = 'flex';
          } else {
            hoverDot.style.display = 'none';
            lineBadge.style.display = 'none';
          }

          let html = '<div class="tt-time">t = ' + formatDuration(targetT) + '</div>';
          const sortedSeries = series
            .filter(s => closestPointBySeries[s.name])
            .slice()
            .sort((a, b) => {
              const va = closestPointBySeries[a.name].point[1];
              const vb = closestPointBySeries[b.name].point[1];
              return vb - va;
            });
          sortedSeries.forEach(s => {
            const info = closestPointBySeries[s.name];
            const isAct = s.name === activeName;
            html += '<div class="tt-row' + (isAct ? ' active' : '') + '">' +
              '<span><span class="legend-dot" style="background:' + s.color + '"></span> ' + s.name + '</span>' +
              '<strong>' + info.point[2] + '</strong></div>';
          });
          tooltip.innerHTML = html;
          tooltip.style.display = 'block';
        });

        svg.addEventListener('mouseleave', () => {
          hoverLine.style.display = 'none';
          hoverDot.style.display = 'none';
          lineBadge.style.display = 'none';
          tooltip.style.display = 'none';
          highlightSeries(pinnedSeries);
        });
      });

      function applyHashTab() {
        const hash = decodeURIComponent(window.location.hash.replace(/^#/, '')) || 'overview';
        if (document.getElementById('tab-' + hash)) {
          selectTab(hash, false);
        }
      }

      function toggleHunkDrawer(id) {
        const row = document.getElementById(id);
        if (!row) return;
        const isHidden = row.style.display === 'none' || !row.style.display;
        row.style.display = isHidden ? 'table-row' : 'none';
        if (isHidden) {
          row.querySelectorAll('.origin-hunk-group').forEach(g => { g.style.display = 'block'; });
        }
        const caret = document.getElementById('caret-' + id);
        if (caret) caret.innerHTML = isHidden ? '&#9662;' : '&#9656;';
      }

      function toggleAllHunks(btn, prefix) {
        const rows = Array.from(document.querySelectorAll('.hunk-drawer-row')).filter(r => r.id && r.id.startsWith(prefix));
        const anyHidden = rows.some(r => r.style.display === 'none' || !r.style.display);
        rows.forEach(row => {
          row.style.display = anyHidden ? 'table-row' : 'none';
          if (anyHidden) {
            row.querySelectorAll('.origin-hunk-group').forEach(g => { g.style.display = 'block'; });
          }
          const caret = document.getElementById('caret-' + row.id);
          if (caret) caret.innerHTML = anyHidden ? '&#9662;' : '&#9656;';
        });
        if (btn) {
          const collapseLabel = (btn.dataset && btn.dataset.collapseLabel) || 'Collapse All Exclusive Hunks';
          const expandLabel = (btn.dataset && btn.dataset.expandLabel) || 'Expand All Exclusive Hunks';
          btn.textContent = anyHidden ? collapseLabel : expandLabel;
        }
      }

      function toggleFileOriginHunks(drawerId, originName) {
        const row = document.getElementById(drawerId);
        if (!row) return;
        const groups = Array.from(row.querySelectorAll('.origin-hunk-group'));
        const isRowHidden = row.style.display === 'none' || !row.style.display;
        const targetGroup = groups.find(g => g.dataset.origin === originName);
        const onlyTargetShown = !isRowHidden && groups.every(g => (g.dataset.origin === originName) ? (g.style.display !== 'none') : (g.style.display === 'none'));
        if (onlyTargetShown) {
          row.style.display = 'none';
          const caret = document.getElementById('caret-' + drawerId);
          if (caret) caret.innerHTML = '&#9656;';
        } else {
          row.style.display = 'table-row';
          groups.forEach(g => {
            g.style.display = (g.dataset.origin === originName) ? 'block' : 'none';
          });
          const caret = document.getElementById('caret-' + drawerId);
          if (caret) caret.innerHTML = '&#9662;';
        }
      }

      function filterLineageRows(prefix, tag, btn) {
        const tbody = document.getElementById(prefix + '-tbody');
        if (!tbody) return;
        if (btn && btn.parentElement) {
          Array.from(btn.parentElement.querySelectorAll('button')).forEach(b => {
            if (b.textContent.includes('Expand') || b.textContent.includes('Collapse')) return;
            b.classList.toggle('cov-btn-secondary', b !== btn);
          });
        }
        const rows = Array.from(tbody.querySelectorAll('tr.lineage-row'));
        rows.forEach((r, idx) => {
          const tags = (r.dataset.lineageTags || '').split(/\s+/);
          const show = (tag === 'all') || tags.includes(tag);
          r.style.display = show ? 'table-row' : 'none';
          const drawer = document.getElementById(prefix + '-drawer-' + idx);
          if (drawer && !show) {
            drawer.style.display = 'none';
            const caret = document.getElementById('caret-' + prefix + '-drawer-' + idx);
            if (caret) caret.innerHTML = '&#9656;';
          }
        });
      }

      window.addEventListener('popstate', applyHashTab);
      window.addEventListener('hashchange', applyHashTab);
      window.addEventListener('DOMContentLoaded', applyHashTab);
    </script>
  </body>
  </html>
HTML

FileUtils.mkdir_p(File.dirname(out_path))
File.write(out_path, html)
puts "Wrote AFL++ plots report (#{fuzzers.size} fuzzers) to #{out_path}"
