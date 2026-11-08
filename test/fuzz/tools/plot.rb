#!/usr/bin/env ruby
# frozen_string_literal: true

require "cgi"
require "fileutils"
require "json"
require "time"

afl_dir = ARGV[0] || "./tmp/fuzz/afl"
out_path = ARGV[1] || "./tmp/fuzz/plots/index.html"

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
  return { prefix_sync: [0], prefix_local: [0], prefix_seed: [0], by_source: {} } unless Dir.exist?(queue_dir)

  max_id = -1
  item_kind = {}
  item_source = {}

  Dir.children(queue_dir).each do |fname|
    next unless fname.start_with?("id:")

    id = fname[3, 6].to_i
    max_id = id if id > max_id
    if fname =~ /,sync:([^,]+)/
      item_kind[id] = :sync
      item_source[id] = Regexp.last_match(1)
    elsif fname.include?(",orig:")
      item_kind[id] = :seed
    else
      item_kind[id] = :local
    end
  end

  return { prefix_sync: [0], prefix_local: [0], prefix_seed: [0], by_source: {} } if max_id < 0

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

  { prefix_sync: prefix_sync, prefix_local: prefix_local, prefix_seed: prefix_seed, by_source: by_source }
rescue StandardError
  { prefix_sync: [0], prefix_local: [0], prefix_seed: [0], by_source: {} }
end

def lookup_prefix(prefix_arr, count)
  return 0 if prefix_arr.empty? || count <= 0

  idx = [count, prefix_arr.size - 1].min
  prefix_arr[idx]
end

def sort_fuzzer_names(names)
  priority = { "main" => 0, "grammar" => 1, "msan" => 2, "ldet" => 3 }
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

fuzzer_dirs = Dir.glob(File.join(afl_dir, "*")).select do |d|
  File.directory?(d) && !File.basename(d).start_with?(".") &&
    (File.exist?(File.join(d, "fuzzer_stats")) || File.exist?(File.join(d, "plot_data")))
end

fuzzer_names = sort_fuzzer_names(fuzzer_dirs.map { |d| File.basename(d) })
if fuzzer_names.empty?
  warn "No fuzzer directories with fuzzer_stats or plot_data found in #{afl_dir}"
  exit 1
end

fuzzers = fuzzer_names.each_with_index.map do |name, idx|
  dir = File.join(afl_dir, name)
  stats = parse_fuzzer_stats(File.join(dir, "fuzzer_stats"))
  raw_plot = parse_plot_data(File.join(dir, "plot_data"))
  origins = parse_queue_origins(File.join(dir, "queue"))
  sampled = downsample(raw_plot).map do |r|
    cc = r[:corpus_count]
    r.merge(
      synced_count: lookup_prefix(origins[:prefix_sync], cc),
      local_count: lookup_prefix(origins[:prefix_local], cc),
      seed_count: lookup_prefix(origins[:prefix_seed], cc)
    )
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
  run_time = stats["run_time"]&.to_i || sampled.last&.dig(:relative_time) || 0
  stability = stats["stability"] || "100.00%"
  banner = stats["afl_banner"] || "./build/fuzz"

  {
    name: name,
    color: PALETTE[idx % PALETTE.size],
    sched: sched,
    banner: banner,
    stats: stats,
    origins: origins,
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
    stability: stability
  }
end

color_by_name = fuzzers.to_h { |f| [f[:name], f[:color]] }

# Compute Fleet Overview KPIs
fleet_execs = fuzzers.sum { |f| f[:execs_done] }
fleet_speed = fuzzers.sum { |f| f[:execs_per_sec] }
fleet_crashes = fuzzers.sum { |f| f[:saved_crashes] }
fleet_hangs = fuzzers.sum { |f| f[:saved_hangs] }
fleet_max_corpus = fuzzers.map { |f| f[:corpus_count] }.max || 0
fleet_max_runtime = fuzzers.map { |f| f[:run_time] }.max || 0
main_fuzzer = fuzzers.find { |f| f[:name] == "main" } || fuzzers.first

# Overview comparison charts
overview_charts = [
  render_svg_chart(
    title: "Edge Coverage (%)",
    subtitle: "Percentage of instrumented CFG edges reached over time (map_size)",
    y_format: :percent,
    zero_base: false,
    chart_id: "ov-cvg",
    series: fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:map_size]] } } }
  ),
  render_svg_chart(
    title: "Edges Discovered",
    subtitle: "Absolute number of edges hit in each worker's coverage map (edges_found)",
    y_format: :int,
    zero_base: false,
    chart_id: "ov-edges",
    series: fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:edges_found]] } } }
  ),
  render_svg_chart(
    title: "Corpus Size Growth",
    subtitle: "Total interesting inputs in queue per worker (corpus_count)",
    y_format: :compact,
    zero_base: true,
    chart_id: "ov-corpus",
    series: fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:corpus_count]] } } }
  ),
  render_svg_chart(
    title: "Execution Throughput (execs/sec)",
    subtitle: "Instantaneous execution speed across workers",
    y_format: :rate,
    zero_base: true,
    chart_id: "ov-speed",
    series: fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:execs_per_sec]] } } }
  ),
  render_svg_chart(
    title: "Cumulative Executions",
    subtitle: "Total target executions completed per worker (total_execs)",
    y_format: :compact,
    zero_base: true,
    chart_id: "ov-execs",
    series: fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:total_execs]] } } }
  ),
  render_svg_chart(
    title: "Pending Favored Queue",
    subtitle: "Unfuzzed favored entries remaining per worker (pending_favs)",
    y_format: :compact,
    zero_base: true,
    chart_id: "ov-favs",
    series: fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:pending_favs]] } } }
  ),
  render_svg_chart(
    title: "Synced Queue Items (Foreign Imports)",
    subtitle: "Cumulative queue entries imported from other fuzzers over time (sync:<source>)",
    y_format: :compact,
    zero_base: true,
    chart_id: "ov-synced",
    series: fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:synced_count]] } } }
  ),
  render_svg_chart(
    title: "Locally Discovered Queue Items",
    subtitle: "Cumulative queue entries discovered by each worker's own mutations (excluding initial seeds & syncs)",
    y_format: :compact,
    zero_base: true,
    chart_id: "ov-local",
    series: fuzzers.map { |f| { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[:local_count]] } } }
  )
].join("\n")

# Fleet summary table rows
summary_rows_html = fuzzers.map do |f|
  edges_str = f[:total_edges] > 0 ? "#{format_int(f[:edges_found])} / #{format_int(f[:total_edges])}" : format_int(f[:edges_found])
  crash_cls = f[:saved_crashes] > 0 ? "badge-danger" : "badge-muted"
  hang_cls = f[:saved_hangs] > 0 ? "badge-warn" : "badge-muted"
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
      <td class="num">#{format_int(f[:corpus_count])}</td>
      <td class="num">#{format_int(f[:corpus_found])}</td>
      <td class="num">#{format_int(f[:corpus_imported])}</td>
      <td class="num">#{format_int(f[:pending_favs])} / #{format_int(f[:pending_total])}</td>
      <td class="num"><span class="badge #{crash_cls}">#{f[:saved_crashes]}</span></td>
      <td class="num"><span class="badge #{hang_cls}">#{f[:saved_hangs]}</span></td>
    </tr>
  HTML
end.join("\n")

# Per-fuzzer tab buttons and panels
tab_buttons_html = +%(<button class="tab-btn active" data-tab="overview" onclick="selectTab('overview')">Fleet Overview (#{fuzzers.size})</button>\n)
tab_panels_html = +""

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
        </div>
      </div>

      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-label">Coverage</div>
          <div class="kpi-value">#{format("%.2f%%", f[:bitmap_cvg])}</div>
          <div class="kpi-sub">#{format_int(f[:edges_found])}#{f[:total_edges] > 0 ? " / #{format_int(f[:total_edges])}" : ""} edges</div>
        </div>
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
      </div>

      <div class="charts-grid">
        #{fuzzer_charts}
      </div>
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
    </style>
  </head>
  <body>
    <header>
      <div class="header-top">
        <div class="header-title">
          <h1>Prism AFL++ Fuzzing Telemetry</h1>
          <span class="header-sub">Source: <code>#{CGI.escapeHTML(afl_dir)}</code> &bull; Runtime: #{format_duration(fleet_max_runtime)} &bull; Generated: #{Time.now.strftime("%Y-%m-%d %H:%M:%S")}</span>
        </div>
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
            <div class="kpi-value">#{fuzzers.size}</div>
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
          <div class="kpi-card">
            <div class="kpi-label">Max Queue Size</div>
            <div class="kpi-value">#{format_int(fleet_max_corpus)}</div>
            <div class="kpi-sub">across all workers</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Saved Crashes</div>
            <div class="kpi-value #{fleet_crashes > 0 ? 'text-danger' : ''}">#{fleet_crashes}</div>
            <div class="kpi-sub">Saved hangs: #{fleet_hangs}</div>
          </div>
        </div>

        <div class="charts-grid">
          #{overview_charts}
        </div>

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
                <th class="num">Corpus</th>
                <th class="num">Local Finds</th>
                <th class="num">Synced</th>
                <th class="num">Pending (Fav/All)</th>
                <th class="num">Crashes</th>
                <th class="num">Hangs</th>
              </tr>
            </thead>
            <tbody>
              #{summary_rows_html}
            </tbody>
          </table>
        </div>
      </section>

      #{tab_panels_html}
    </main>

    <script>
      function selectTab(name) {
        document.querySelectorAll('.tab-btn').forEach(btn => {
          btn.classList.toggle('active', btn.dataset.tab === name);
        });
        document.querySelectorAll('.tab-panel').forEach(panel => {
          panel.classList.toggle('active', panel.id === 'tab-' + name);
        });
        if (history.replaceState) {
          history.replaceState(null, null, '#' + encodeURIComponent(name));
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

      window.addEventListener('DOMContentLoaded', () => {
        const hash = decodeURIComponent(window.location.hash.replace(/^#/, ''));
        if (hash && document.getElementById('tab-' + hash)) {
          selectTab(hash);
        }
      });
    </script>
  </body>
  </html>
HTML

FileUtils.mkdir_p(File.dirname(out_path))
File.write(out_path, html)
puts "Wrote AFL++ plots report (#{fuzzers.size} fuzzers) to #{out_path}"
