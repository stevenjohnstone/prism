#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"
require "optparse"
require "time"

require_relative "cluster"

def locate_repo_root
  dir = File.expand_path(Dir.pwd)
  loop do
    return dir if File.file?(File.join(dir, "include/prism.h")) && File.directory?(File.join(dir, "src"))

    parent = File.dirname(dir)
    break if parent == dir

    dir = parent
  end
  File.expand_path("../../..", __dir__)
end

def discover_buckets(triage_dir)
  return [] unless File.directory?(triage_dir)

  Dir.glob(File.join(triage_dir, "*", "*")).select do |dir|
    next false unless File.directory?(dir)

    reason = File.basename(File.dirname(dir))
    sig = File.basename(dir)
    next false if reason.start_with?(".") || sig.start_with?(".")

    File.file?(File.join(dir, "input.min")) ||
      File.file?(File.join(dir, "meta.json")) ||
      File.file?(File.join(dir, "inputs.tar.gz"))
  end.sort
end

def infer_bucket_profile(bucket_dir, meta)
  if meta.is_a?(Hash) && meta["verify_profile"] && !meta["verify_profile"].empty?
    return meta["verify_profile"]
  end

  reason = meta&.dig("reason") || File.basename(File.dirname(bucket_dir))
  reproduced_by = meta&.dig("reproduced_by").to_s
  return "diff_parse_y" if reproduced_by.end_with?("diff")
  return "msan_slow" if reproduced_by.end_with?("msan") || reason == "use-of-uninitialized-value"
  return "lsan_slow" if reproduced_by.end_with?("lsan") || reason == "memory-leak"
  return "xallocator" if reason == "allocation-size-too-big" || reproduced_by.end_with?("ijon", "native")
  return "asan_ubsan_slow" if reproduced_by.end_with?("slow")

  verify_sh = File.join(bucket_dir, "verify.sh")
  if File.file?(verify_sh)
    m = File.read(verify_sh).match(/--profile\s+"?([a-z_]+)"?/)
    return m[1] if m
  end

  build_sh = File.join(bucket_dir, "build.sh")
  if File.file?(build_sh)
    text = File.read(build_sh)
    return "msan_slow" if text.include?("-fsanitize=memory")
    return "lsan_slow" if text.include?("-fsanitize=leak")
    return "diff_parse_y" if text.include?("build_diff.sh")
    return "asan_ubsan_slow" if text.include?("-DSLOW")
  end

  "asan_ubsan"
end

def matches_bucket_filter?(bucket_id, patterns)
  return true if patterns.empty?

  sig = bucket_id.split("/", 2).last.to_s
  patterns.any? do |pat|
    bucket_id == pat ||
      sig == pat ||
      File.fnmatch?(pat, bucket_id, File::FNM_PATHNAME) ||
      bucket_id.include?(pat)
  end
end

def parse_csv_env(name)
  ENV.fetch(name, "").split(",").map(&:strip).reject(&:empty?)
end

def load_clusters_report(triage_dir, clusters_file: nil, include_unreproducible: false)
  metadata_path = File.join(triage_dir, "metadata.json")
  if clusters_file
    abort "Missing clusters file: #{clusters_file}" unless File.file?(clusters_file)

    report = JSON.parse(File.read(clusters_file))
    abort "Invalid clusters file (missing clusters array): #{clusters_file}" unless report.is_a?(Hash) && report["clusters"].is_a?(Array)
    return [report, clusters_file]
  end

  default_clusters = File.join(triage_dir, "clusters.json")
  has_metadata = File.file?(metadata_path)

  # Default clusters.json excludes unreproducible/; recompute in memory when requested.
  if include_unreproducible && has_metadata
    metadata = JSON.parse(File.read(metadata_path))
    report = FuzzClustering.cluster_metadata(metadata, include_unreproducible: true, metadata_path: metadata_path)
    return [report, metadata_path]
  end

  clusters_fresh = File.file?(default_clusters) && (!has_metadata || File.mtime(default_clusters) >= File.mtime(metadata_path))
  if clusters_fresh
    report = JSON.parse(File.read(default_clusters))
    return [report, default_clusters] if report.is_a?(Hash) && report["clusters"].is_a?(Array)
  end

  return [nil, nil] unless has_metadata

  metadata = JSON.parse(File.read(metadata_path))
  report = FuzzClustering.cluster_metadata(metadata, metadata_path: metadata_path)
  begin
    FuzzClustering.write_json_atomic(default_clusters, report)
  rescue SystemCallError
    # Proceed even if triage_dir is mounted read-only.
  end
  [report, default_clusters]
end

def matches_cluster_filter?(cluster, patterns)
  return true if patterns.empty?

  cid = cluster["cluster_id"].to_s
  cid_num = cid[/\d+\z/]&.to_i
  members = cluster["buckets"] || []

  patterns.any? do |raw_pat|
    pat = raw_pat.strip
    next false if pat.empty?

    # Short purely-decimal inputs act as cluster index shorthand (e.g. "1" -> "cluster-01"),
    # while keeping 16-digit signatures unambiguous.
    if pat.match?(/\A\d{1,15}\z/) && !cid_num.nil? && cid_num == pat.to_i
      true
    elsif cid.casecmp?(pat) || File.fnmatch?(pat.downcase, cid.downcase, File::FNM_PATHNAME)
      true
    else
      allow_glob = pat.include?("/") || pat.match?(/[*?\[]/)
      members.any? do |b|
        bid = b["bucket_id"].to_s
        bid == pat || b["signature"].to_s == pat || (allow_glob && File.fnmatch?(pat, bid, File::FNM_PATHNAME))
      end
    end
  end
end

def ordered_cluster_bucket_ids(cluster)
  rep_id = cluster.dig("representative", "bucket_id")
  member_ids = (cluster["buckets"] || []).map { |b| b["bucket_id"] }.compact
  ([rep_id].compact + member_ids).uniq
end

def build_bucket_entry(dir, reason, bucket_id, cluster_id: nil, cluster_info: nil, cluster_representative: false)
  meta_path = File.join(dir, "meta.json")
  meta = File.file?(meta_path) ? (JSON.parse(File.read(meta_path)) rescue nil) : nil
  profile = infer_bucket_profile(dir, meta)
  {
    dir: dir,
    bucket_id: bucket_id,
    reason: reason,
    meta: meta,
    profile: profile,
    cluster_id: cluster_id,
    cluster_info: cluster_info,
    cluster_representative: cluster_representative
  }
end

def filter_bucket_decision(bucket_id, reason, options, explicit_cluster_target: false)
  return :filtered if !options[:reasons].empty? && !options[:reasons].include?(reason)
  return :filtered unless matches_bucket_filter?(bucket_id, options[:buckets])

  explicitly_unrepro = explicit_cluster_target || !options[:buckets].empty? || options[:reasons].include?("unreproducible")
  return :skipped_unrepro if reason == "unreproducible" && !options[:include_unreproducible] && !explicitly_unrepro

  :include
end

def select_buckets(all_dirs, options, cluster_report, matched_clusters, cluster_mode:)
  entries_by_id = {}
  ordered_ids = []
  all_dirs.each do |dir|
    reason = File.basename(File.dirname(dir))
    sig = File.basename(dir)
    bucket_id = "#{reason}/#{sig}"
    entries_by_id[bucket_id] = { dir: dir, reason: reason, bucket_id: bucket_id }
    ordered_ids << bucket_id
  end

  selected = []
  skipped_unrepro = 0

  unless cluster_mode
    ordered_ids.each do |bid|
      info = entries_by_id.fetch(bid)
      decision = filter_bucket_decision(bid, info[:reason], options)
      skipped_unrepro += 1 if decision == :skipped_unrepro
      next unless decision == :include

      selected << build_bucket_entry(info[:dir], info[:reason], bid)
    end
    return [selected, skipped_unrepro]
  end

  seen_ids = {}
  explicit_cluster_target = !options[:clusters].empty?

  (matched_clusters || []).each do |cluster|
    cid = cluster["cluster_id"]
    rep_id = cluster.dig("representative", "bucket_id")

    ordered_cluster_bucket_ids(cluster).each do |bid|
      info = entries_by_id[bid]
      next unless info

      seen_ids[bid] = true
      decision = filter_bucket_decision(bid, info[:reason], options, explicit_cluster_target: explicit_cluster_target)
      skipped_unrepro += 1 if decision == :skipped_unrepro
      next unless decision == :include

      selected << build_bucket_entry(
        info[:dir],
        info[:reason],
        bid,
        cluster_id: cid,
        cluster_info: cluster,
        cluster_representative: bid == rep_id
      )
    end
  end

  # In --by-cluster sweeps without --cluster, include any unclustered on-disk buckets at the end.
  unless explicit_cluster_target
    ordered_ids.each do |bid|
      next if seen_ids[bid]

      info = entries_by_id.fetch(bid)
      decision = filter_bucket_decision(bid, info[:reason], options)
      skipped_unrepro += 1 if decision == :skipped_unrepro
      next unless decision == :include

      selected << build_bucket_entry(info[:dir], info[:reason], bid)
    end
  end

  [selected, skipped_unrepro]
end

def aggregate_cluster_status(bucket_results)
  counts = { "PASS" => 0, "PARTIAL" => 0, "FAIL" => 0, "EMPTY" => 0 }
  checked = 0
  failed = 0
  bucket_results.each do |res|
    counts[res["status"]] += 1
    checked += res["checked"].to_i
    failed += res["failed"].to_i
  end

  non_empty = counts["PASS"] + counts["PARTIAL"] + counts["FAIL"]
  status = if non_empty == 0
             "EMPTY"
           elsif counts["PARTIAL"] == 0 && counts["FAIL"] == 0
             "PASS"
           elsif counts["PASS"] > 0 || counts["PARTIAL"] > 0
             "PARTIAL"
           else
             "FAIL"
           end

  [status, counts, checked, failed]
end

def print_bucket_result(result, options)
  bucket_status = result["status"]
  bucket_id = result["bucket_id"]
  profile = result["profile"]
  checked = result["checked"]
  failed = result["failed"]
  has_min = result["has_input_min"]
  failures = result["failures"]
  profile_tag = result["cluster_representative"] ? "#{profile}, rep" : profile

  if bucket_status == "PASS"
    puts format("%-7s %-36s (%s, %d inputs)", "PASS", bucket_id, profile_tag, checked)
  elsif bucket_status == "EMPTY"
    puts format("%-7s %-36s (%s, 0 inputs)", "EMPTY", bucket_id, profile_tag)
  elsif bucket_status == "PARTIAL"
    archived_checked = has_min ? checked - 1 : checked
    puts format("%-7s %-36s (%s, input.min PASSED, %d/%d archived STILL FAIL!)", "PARTIAL", bucket_id, profile_tag, failed, archived_checked)
    failures.first(options[:verbose] ? failures.size : 5).each do |f|
      puts "          - #{f["name"]} (#{f["size_bytes"]} B): #{f["headline"]}"
    end
    puts "          ... (#{failures.size - 5} more)" if !options[:verbose] && failures.size > 5
  else
    puts format("%-7s %-36s (%s, %d/%d failed)", "FAIL", bucket_id, profile_tag, failed, checked)
    if options[:verbose]
      failures.each do |f|
        puts "          - #{f["name"]} (#{f["size_bytes"]} B): #{f["headline"]}"
      end
    elsif !failures.empty?
      first = failures.first
      puts "          - #{first["name"]}: #{first["headline"]}"
    end
  end
end

options = {
  triage_dir: ENV.fetch("TRIAGE_DIR", "tmp/fuzz/triage"),
  target: (ENV["VERIFY_TARGET"] || ENV["PRISM_TARGET"])&.strip,
  buckets: parse_csv_env("BUCKET"),
  reasons: parse_csv_env("REASON"),
  clusters: parse_csv_env("CLUSTER"),
  clusters_file: ENV["CLUSTERS_FILE"]&.strip,
  by_cluster: ENV["BY_CLUSTER"] == "1",
  list_clusters: false,
  timeout: Integer(ENV.fetch("VERIFY_TIMEOUT", "5")),
  max_failures: Integer(ENV.fetch("VERIFY_MAX_FAILURES", "0")),
  extract_dir: ENV["VERIFY_EXTRACT_SURVIVORS"]&.strip,
  input_min_only: ENV["VERIFY_INPUT_MIN_ONLY"] == "1",
  skip_min: ENV["VERIFY_SKIP_MIN"] == "1",
  include_unreproducible: ENV["VERIFY_UNREPRODUCIBLE"] == "1",
  rebuild: ENV["VERIFY_REBUILD"] == "1",
  symbolize: ENV["VERIFY_SYMBOLIZE"] == "1",
  fail_fast: ENV["VERIFY_FAIL_FAST"] == "1",
  invert: ENV["VERIFY_INVERT"] == "1",
  bisect: ENV["VERIFY_BISECT"] == "1",
  verbose: ENV["VERIFY_VERBOSE"] == "1",
  quiet: ENV["VERIFY_QUIET"] == "1",
  json_stdout: false,
  json_path: nil
}

def die_config(message, options, code: 2)
  warn message
  exit(options[:bisect] ? 128 : code)
end

begin
  OptionParser.new do |opts|
    opts.banner = "Usage: verify.rb [OPTIONS]"
    opts.on("--triage-dir DIR", "Triage directory (default: tmp/fuzz/triage)") { |v| options[:triage_dir] = v }
    opts.on("--target DIR", "Target Prism source directory to verify against (default: current repo)") { |v| options[:target] = v }
    opts.on("--bucket PATTERN", "Verify only buckets matching pattern/id/signature (repeatable)") { |v| options[:buckets] << v }
    opts.on("--reason REASON", "Verify only buckets in reason directory") { |v| options[:reasons] << v }
    opts.on("--cluster PATTERN", "Verify all buckets in matching cluster(s) (id, number, or member bucket; repeatable)") { |v| options[:clusters] << v }
    opts.on("--clusters-file PATH", "Path to clusters.json (default: <triage-dir>/clusters.json)") { |v| options[:clusters_file] = v }
    opts.on("--by-cluster", "Group output and summary rollups by root-cause cluster") { options[:by_cluster] = true }
    opts.on("--list-clusters", "Print available clusters for the triage directory and exit") { options[:list_clusters] = true }
    opts.on("--timeout SEC", Integer, "Per-input timeout in seconds (default: 5)") { |v| options[:timeout] = v }
    opts.on("--max-failures N", Integer, "Stop each bucket after N failures (default: 0 = all)") { |v| options[:max_failures] = v }
    opts.on("--extract-survivors DIR", "Write still-failing inputs into DIR/<bucket_id>/") { |v| options[:extract_dir] = v }
    opts.on("--input-min-only", "Check only each bucket's minimized input.min (skip archived inputs)") { options[:input_min_only] = true }
    opts.on("--skip-min", "Skip each bucket's input.min (check archived inputs only)") { options[:skip_min] = true }
    opts.on("--include-unreproducible", "Include unreproducible/ buckets") { options[:include_unreproducible] = true }
    opts.on("--rebuild", "Force rebuild of verify_runner binaries") { options[:rebuild] = true }
    opts.on("--symbolize", "Enable external llvm-symbolizer (slower when many inputs crash)") { options[:symbolize] = true }
    opts.on("--fail-fast", "Stop checking further buckets after the first failing/partial bucket") { options[:fail_fast] = true }
    opts.on("--invert", "Invert verdict exit status (exit 0 on FAIL/PARTIAL, 1 on PASS; useful when bisecting fixes)") { options[:invert] = true }
    opts.on("--bisect", "git bisect run mode (exit 125 to skip unbuildable commits, 128 on config errors)") { options[:bisect] = true }
    opts.on("--verbose", "Show stderr details on failures") { options[:verbose] = true }
    opts.on("--quiet", "Only print final summary") { options[:quiet] = true }
    opts.on("--json [PATH]", "Emit JSON report (to PATH or stdout)") do |v|
      if v && !v.empty?
        options[:json_path] = v
      else
        options[:json_stdout] = true
      end
    end
  end.parse!
rescue OptionParser::ParseError => e
  die_config("verify.rb: #{e.message}", options)
end

options[:extract_dir] = nil if options[:extract_dir]&.empty?
options[:clusters_file] = nil if options[:clusters_file]&.empty?
options[:target] = nil if options[:target]&.empty?
if options[:input_min_only] && options[:skip_min]
  die_config("verify.rb: --input-min-only and --skip-min cannot be used together", options)
end
cluster_mode = options[:by_cluster] || !options[:clusters].empty?

fuzz_root = File.expand_path("../../..", __dir__)
target_root = File.expand_path(options[:target] || locate_repo_root)
verify_bucket_sh = File.join(fuzz_root, "test/fuzz/triage/verify_bucket.sh")
die_config("Missing verify_bucket.sh at #{verify_bucket_sh}", options) unless File.executable?(verify_bucket_sh)
if !File.file?(File.join(target_root, "include/prism.h")) || !File.directory?(File.join(target_root, "src"))
  die_config("Invalid Prism target root: #{target_root} (missing include/prism.h or src/)", options)
end

cluster_report = nil
clusters_source = nil
if cluster_mode || options[:list_clusters]
  cluster_report, clusters_source = load_clusters_report(
    options[:triage_dir],
    clusters_file: options[:clusters_file],
    include_unreproducible: options[:include_unreproducible]
  )
end

if options[:list_clusters]
  if cluster_report.nil?
    die_config("No clusters or metadata.json found under #{options[:triage_dir]} (run make fuzz-triage or cluster.rb first)", options)
  end
  if options[:json_stdout]
    puts JSON.pretty_generate(cluster_report)
  else
    puts FuzzClustering.format_summary_table(cluster_report)
  end
  exit 0
end

matched_clusters = nil
if cluster_mode
  if !options[:clusters].empty?
    if cluster_report.nil?
      expected = options[:clusters_file] || File.join(options[:triage_dir], "clusters.json")
      die_config("Cannot resolve --cluster filter: neither #{expected} nor #{File.join(options[:triage_dir], 'metadata.json')} exists", options)
    end

    matched_clusters = cluster_report["clusters"].select { |c| matches_cluster_filter?(c, options[:clusters]) }
    if matched_clusters.empty?
      warn "No clusters match #{options[:clusters].join(', ')}."
      unless options[:json_stdout]
        warn ""
        warn FuzzClustering.format_summary_table(cluster_report)
      end
      die_config("", options, code: 1)
    end
  elsif cluster_report
    matched_clusters = cluster_report["clusters"]
  end
end

all_dirs = discover_buckets(options[:triage_dir])
if all_dirs.empty?
  die_config("No triage buckets found under #{options[:triage_dir]}", options, code: options[:bisect] ? 128 : 0)
end

selected, skipped_unrepro = select_buckets(all_dirs, options, cluster_report, matched_clusters, cluster_mode: cluster_mode)

if selected.empty?
  if !options[:clusters].empty?
    matched_ids = matched_clusters.map { |c| c["cluster_id"] }.join(", ")
    msg = "Matched cluster(s) (#{matched_ids}), but no matching bucket directories remain on disk under #{options[:triage_dir]}"
  else
    msg = "No matching buckets to verify (skipped #{skipped_unrepro} unreproducible buckets)"
  end
  die_config(msg, options, code: options[:bisect] ? 128 : 0)
end

if target_root != fuzz_root && !options[:json_stdout] && !options[:quiet]
  puts "Target: #{target_root}"
end

runners = {}
selected.map { |b| b[:profile] }.uniq.each do |profile|
  cmd = [
    verify_bucket_sh,
    "--repo-root", target_root,
    "--fuzz-root", fuzz_root,
    "--profile", profile,
    "--build-only"
  ]
  cmd << "--rebuild" if options[:rebuild]
  stdout, stderr, status = Open3.capture3(*cmd)
  unless status.success?
    warn stderr unless stderr.empty?
    if status.exitstatus == 125
      warn "Skipping commit: verify_runner (#{profile}) could not be built for #{target_root}"
      exit 125
    end
    die_config("Failed to build verify_runner (#{profile})", options, code: 1)
  end
  runners[profile] = stdout.strip
end

counts = { "PASS" => 0, "PARTIAL" => 0, "FAIL" => 0, "EMPTY" => 0 }
cluster_counts = { "PASS" => 0, "PARTIAL" => 0, "FAIL" => 0, "EMPTY" => 0 }
total_inputs_checked = 0
total_inputs_failed = 0
unclustered_count = 0
bucket_results = []
cluster_results = []
started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

selected.slice_when { |a, b| a[:cluster_id] != b[:cluster_id] }.each_with_index do |group_items, group_idx|
  cid = group_items.first[:cluster_id]
  if cluster_mode && !options[:json_stdout] && !options[:quiet]
    puts "" if group_idx > 0
    if cid
      info = group_items.first[:cluster_info] || {}
      rep_id = info.dig("representative", "bucket_id")
      occ = info["occurrences"].to_i
      bucket_word = group_items.size == 1 ? "bucket" : "buckets"
      rep_suffix = rep_id ? "; rep: #{rep_id}" : ""
      puts "== #{cid} (#{group_items.size} #{bucket_word}, #{occ} occurrences#{rep_suffix}) =="
    else
      bucket_word = group_items.size == 1 ? "bucket" : "buckets"
      puts "== unclustered (#{group_items.size} #{bucket_word}) =="
    end
  end

  group_results = []
  fail_fast_hit = false
  group_items.each do |b|
    bucket_dir = b[:dir]
    bucket_id = b[:bucket_id]
    profile = b[:profile]
    runner = runners.fetch(profile)

    cmd = [
      verify_bucket_sh,
      "--repo-root", target_root,
      "--fuzz-root", fuzz_root,
      "--bucket-dir", bucket_dir,
      "--profile", profile,
      "--runner", runner,
      "--timeout", options[:timeout].to_s,
      "--max-failures", options[:max_failures].to_s,
      "--json"
    ]
    cmd << "--input-min-only" if options[:input_min_only]
    cmd << "--skip-min" if options[:skip_min]
    cmd << "--symbolize" if options[:symbolize]
    if options[:extract_dir]
      surv_dir = File.join(options[:extract_dir], bucket_id)
      cmd.push("--extract-survivors", surv_dir)
    end

    stdout, stderr, status = Open3.capture3(*cmd)
    res = begin
            JSON.parse(stdout)
          rescue JSON::ParserError
            exit 125 if status.exitstatus == 125
            die_config("Malformed verifier output for #{bucket_id} (rc=#{status.exitstatus}): #{stdout}#{stderr}", options, code: 1)
          end

    has_min = File.file?(File.join(bucket_dir, "input.min"))
    min_checked = has_min && !options[:skip_min]
    failures = res["failures"] || []
    min_failed = failures.any? { |f| f["name"] == "input.min" }
    checked = res["checked"].to_i
    failed = res["failed"].to_i
    total_inputs_checked += checked
    total_inputs_failed += failed

    bucket_status = if res["total"].to_i == 0
                      "EMPTY"
                    elsif failed == 0
                      "PASS"
                    elsif min_checked && !min_failed
                      "PARTIAL"
                    else
                      "FAIL"
                    end
    counts[bucket_status] += 1

    # Remove empty survivor directories if this bucket had zero failures.
    if options[:extract_dir] && failed == 0
      surv_dir = File.join(options[:extract_dir], bucket_id)
      FileUtils.rm_rf(surv_dir) if File.directory?(surv_dir) && Dir.empty?(surv_dir)
    end

    bucket_entry = {
      "bucket_id" => bucket_id,
      "profile" => profile,
      "status" => bucket_status,
      "has_input_min" => has_min,
      "min_passed" => min_checked ? !min_failed : nil,
      "total" => res["total"],
      "checked" => checked,
      "passed" => res["passed"],
      "failed" => failed,
      "timed_out" => res["timed_out"],
      "failures" => failures
    }
    if cluster_mode
      bucket_entry["cluster_id"] = cid
      bucket_entry["cluster_representative"] = b[:cluster_representative]
    end
    bucket_results << bucket_entry
    group_results << bucket_entry

    if !options[:json_stdout] && !(options[:quiet] && bucket_status == "PASS")
      print_bucket_result(bucket_entry, options)
    end

    if options[:fail_fast] && %w[FAIL PARTIAL].include?(bucket_status)
      fail_fast_hit = true
      break
    end
  end

  if cluster_mode
    c_status, c_counts, c_checked, c_failed = aggregate_cluster_status(group_results)
    if !options[:json_stdout] && !options[:quiet]
      label = cid || "unclustered"
      puts "-> #{label}: #{c_status} (#{c_counts['PASS']}/#{group_results.size} PASS, #{c_counts['PARTIAL']} PARTIAL, #{c_counts['FAIL']} FAIL; #{c_failed}/#{c_checked} inputs failed)"
    end

    if cid
      info = group_items.first[:cluster_info] || {}
      cluster_counts[c_status] += 1
      cluster_results << {
        "cluster_id" => cid,
        "status" => c_status,
        "representative" => info.dig("representative", "bucket_id"),
        "buckets_checked" => group_results.size,
        "buckets_in_cluster" => info["bucket_count"] || group_results.size,
        "occurrences" => info["occurrences"],
        "pass" => c_counts["PASS"],
        "partial" => c_counts["PARTIAL"],
        "fail" => c_counts["FAIL"],
        "empty" => c_counts["EMPTY"],
        "inputs_checked" => c_checked,
        "inputs_failed" => c_failed,
        "buckets" => group_results.map { |r| r["bucket_id"] }
      }
    else
      unclustered_count += group_results.size
    end
  end

  break if fail_fast_hit
end

elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
summary = {
  "buckets_checked" => bucket_results.size,
  "buckets_skipped_unreproducible" => skipped_unrepro,
  "pass" => counts["PASS"],
  "partial" => counts["PARTIAL"],
  "fail" => counts["FAIL"],
  "empty" => counts["EMPTY"],
  "inputs_checked" => total_inputs_checked,
  "inputs_failed" => total_inputs_failed
}
if cluster_mode
  summary["clusters_checked"] = cluster_results.size
  summary["cluster_pass"] = cluster_counts["PASS"]
  summary["cluster_partial"] = cluster_counts["PARTIAL"]
  summary["cluster_fail"] = cluster_counts["FAIL"]
  summary["cluster_empty"] = cluster_counts["EMPTY"]
  summary["buckets_unclustered"] = unclustered_count
end

report = {
  "generated_at" => Time.now.utc.iso8601,
  "triage_dir" => options[:triage_dir],
  "elapsed_seconds" => elapsed.round(3),
  "summary" => summary,
  "buckets" => bucket_results
}
report["target_root"] = target_root if target_root != fuzz_root
if cluster_mode
  report["clusters_file"] = clusters_source if clusters_source
  report["clusters"] = cluster_results
end

if options[:json_path]
  FileUtils.mkdir_p(File.dirname(options[:json_path]))
  File.write(options[:json_path], "#{JSON.pretty_generate(report)}\n")
end

if options[:json_stdout]
  puts JSON.pretty_generate(report)
else
  puts ""
  if cluster_mode && !options[:quiet] && cluster_results.size > 1
    puts "Clusters:"
    cluster_results.each do |c|
      rep_note = c["representative"] ? "; rep: #{c["representative"]}" : ""
      puts format(
        "  %-7s %-11s %d/%d PASS (%d PARTIAL, %d FAIL; %d/%d inputs failed%s)",
        c["status"],
        c["cluster_id"],
        c["pass"],
        c["buckets_checked"],
        c["partial"],
        c["fail"],
        c["inputs_failed"],
        c["inputs_checked"],
        rep_note
      )
    end
    puts ""
  end

  cluster_prefix = if cluster_mode
                     c_word = cluster_results.size == 1 ? "cluster" : "clusters"
                     format(
                       "%d %s (%d PASS, %d PARTIAL, %d FAIL, %d EMPTY), ",
                       cluster_results.size,
                       c_word,
                       cluster_counts["PASS"],
                       cluster_counts["PARTIAL"],
                       cluster_counts["FAIL"],
                       cluster_counts["EMPTY"]
                     )
                   else
                     ""
                   end

  puts format(
    "Summary: %s%d buckets checked (%d PASS, %d PARTIAL, %d FAIL, %d EMPTY; %d unreproducible skipped), %d/%d inputs failed in %.2fs",
    cluster_prefix,
    bucket_results.size,
    counts["PASS"],
    counts["PARTIAL"],
    counts["FAIL"],
    counts["EMPTY"],
    skipped_unrepro,
    total_inputs_failed,
    total_inputs_checked,
    elapsed
  )
end

failed_buckets = counts["PARTIAL"] + counts["FAIL"]
if (options[:invert] || options[:bisect]) && (counts["PASS"] + failed_buckets) == 0
  exit 125
end
verdict_ok = failed_buckets == 0
verdict_ok = !verdict_ok if options[:invert]
exit(verdict_ok ? 0 : 1)

