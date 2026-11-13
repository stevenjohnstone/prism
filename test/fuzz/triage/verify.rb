#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"
require "optparse"
require "time"

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
  return "msan_slow" if reproduced_by.end_with?("msan") || reason == "use-of-uninitialized-value"
  return "lsan_slow" if reproduced_by.end_with?("lsan") || reason == "memory-leak"
  return "xallocator" if reason == "allocation-size-too-big" || reproduced_by.end_with?("ijon", "native")

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

options = {
  triage_dir: ENV.fetch("TRIAGE_DIR", "tmp/fuzz/triage"),
  buckets: ENV.fetch("BUCKET", "").split(",").map(&:strip).reject(&:empty?),
  reasons: ENV.fetch("REASON", "").split(",").map(&:strip).reject(&:empty?),
  timeout: Integer(ENV.fetch("VERIFY_TIMEOUT", "5")),
  max_failures: Integer(ENV.fetch("VERIFY_MAX_FAILURES", "0")),
  extract_dir: ENV["VERIFY_EXTRACT_SURVIVORS"]&.strip,
  include_unreproducible: ENV["VERIFY_UNREPRODUCIBLE"] == "1",
  rebuild: ENV["VERIFY_REBUILD"] == "1",
  symbolize: ENV["VERIFY_SYMBOLIZE"] == "1",
  verbose: ENV["VERIFY_VERBOSE"] == "1",
  quiet: ENV["VERIFY_QUIET"] == "1",
  json_stdout: false,
  json_path: nil
}

OptionParser.new do |opts|
  opts.banner = "Usage: verify.rb [OPTIONS]"
  opts.on("--triage-dir DIR", "Triage directory (default: tmp/fuzz/triage)") { |v| options[:triage_dir] = v }
  opts.on("--bucket PATTERN", "Verify only buckets matching pattern/id/signature (repeatable)") { |v| options[:buckets] << v }
  opts.on("--reason REASON", "Verify only buckets in reason directory") { |v| options[:reasons] << v }
  opts.on("--timeout SEC", Integer, "Per-input timeout in seconds (default: 5)") { |v| options[:timeout] = v }
  opts.on("--max-failures N", Integer, "Stop each bucket after N failures (default: 0 = all)") { |v| options[:max_failures] = v }
  opts.on("--extract-survivors DIR", "Write still-failing inputs into DIR/<bucket_id>/") { |v| options[:extract_dir] = v }
  opts.on("--include-unreproducible", "Include unreproducible/ buckets") { options[:include_unreproducible] = true }
  opts.on("--rebuild", "Force rebuild of verify_runner binaries") { options[:rebuild] = true }
  opts.on("--symbolize", "Enable external llvm-symbolizer (slower when many inputs crash)") { options[:symbolize] = true }
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

options[:extract_dir] = nil if options[:extract_dir]&.empty?

repo_root = locate_repo_root
verify_bucket_sh = File.join(repo_root, "test/fuzz/triage/verify_bucket.sh")
abort "Missing verify_bucket.sh at #{verify_bucket_sh}" unless File.executable?(verify_bucket_sh)

all_dirs = discover_buckets(options[:triage_dir])
if all_dirs.empty?
  warn "No triage buckets found under #{options[:triage_dir]}"
  exit 0
end

selected = []
skipped_unrepro = 0

all_dirs.each do |dir|
  reason = File.basename(File.dirname(dir))
  sig = File.basename(dir)
  bucket_id = "#{reason}/#{sig}"

  next if !options[:reasons].empty? && !options[:reasons].include?(reason)
  next unless matches_bucket_filter?(bucket_id, options[:buckets])

  explicitly_unrepro = !options[:buckets].empty? || options[:reasons].include?("unreproducible")
  if reason == "unreproducible" && !options[:include_unreproducible] && !explicitly_unrepro
    skipped_unrepro += 1
    next
  end

  meta_path = File.join(dir, "meta.json")
  meta = File.file?(meta_path) ? (JSON.parse(File.read(meta_path)) rescue nil) : nil
  profile = infer_bucket_profile(dir, meta)
  selected << { dir: dir, bucket_id: bucket_id, reason: reason, meta: meta, profile: profile }
end

if selected.empty?
  warn "No matching buckets to verify (skipped #{skipped_unrepro} unreproducible buckets)"
  exit 0
end

runners = {}
selected.map { |b| b[:profile] }.uniq.each do |profile|
  cmd = [
    verify_bucket_sh,
    "--repo-root", repo_root,
    "--profile", profile,
    "--build-only"
  ]
  cmd << "--rebuild" if options[:rebuild]
  stdout, stderr, status = Open3.capture3(*cmd)
  unless status.success?
    warn stderr unless stderr.empty?
    abort "Failed to build verify_runner (#{profile})"
  end
  runners[profile] = stdout.strip
end

counts = { "PASS" => 0, "PARTIAL" => 0, "FAIL" => 0, "EMPTY" => 0 }
total_inputs_checked = 0
total_inputs_failed = 0
bucket_results = []
started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

selected.each do |b|
  bucket_dir = b[:dir]
  bucket_id = b[:bucket_id]
  profile = b[:profile]
  runner = runners.fetch(profile)

  cmd = [
    verify_bucket_sh,
    "--repo-root", repo_root,
    "--bucket-dir", bucket_dir,
    "--profile", profile,
    "--runner", runner,
    "--timeout", options[:timeout].to_s,
    "--max-failures", options[:max_failures].to_s,
    "--json"
  ]
  cmd << "--symbolize" if options[:symbolize]
  if options[:extract_dir]
    surv_dir = File.join(options[:extract_dir], bucket_id)
    cmd.push("--extract-survivors", surv_dir)
  end

  stdout, stderr, status = Open3.capture3(*cmd)
  res = begin
          JSON.parse(stdout)
        rescue JSON::ParserError
          abort "Malformed verifier output for #{bucket_id} (rc=#{status.exitstatus}): #{stdout}#{stderr}"
        end

  has_min = File.file?(File.join(bucket_dir, "input.min"))
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
                  elsif has_min && !min_failed
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

  bucket_results << {
    "bucket_id" => bucket_id,
    "profile" => profile,
    "status" => bucket_status,
    "has_input_min" => has_min,
    "min_passed" => has_min ? !min_failed : nil,
    "total" => res["total"],
    "checked" => checked,
    "passed" => res["passed"],
    "failed" => failed,
    "timed_out" => res["timed_out"],
    "failures" => failures
  }

  next if options[:json_stdout] || (options[:quiet] && bucket_status == "PASS")

  if bucket_status == "PASS"
    puts format("%-7s %-36s (%s, %d inputs)", "PASS", bucket_id, profile, checked)
  elsif bucket_status == "EMPTY"
    puts format("%-7s %-36s (%s, 0 inputs)", "EMPTY", bucket_id, profile)
  elsif bucket_status == "PARTIAL"
    archived_checked = has_min ? checked - 1 : checked
    puts format("%-7s %-36s (%s, input.min PASSED, %d/%d archived STILL FAIL!)", "PARTIAL", bucket_id, profile, failed, archived_checked)
    failures.first(options[:verbose] ? failures.size : 5).each do |f|
      puts "          - #{f["name"]} (#{f["size_bytes"]} B): #{f["headline"]}"
    end
    puts "          ... (#{failures.size - 5} more)" if !options[:verbose] && failures.size > 5
  else
    puts format("%-7s %-36s (%s, %d/%d failed)", "FAIL", bucket_id, profile, failed, checked)
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

elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
report = {
  "generated_at" => Time.now.utc.iso8601,
  "triage_dir" => options[:triage_dir],
  "elapsed_seconds" => elapsed.round(3),
  "summary" => {
    "buckets_checked" => selected.size,
    "buckets_skipped_unreproducible" => skipped_unrepro,
    "pass" => counts["PASS"],
    "partial" => counts["PARTIAL"],
    "fail" => counts["FAIL"],
    "empty" => counts["EMPTY"],
    "inputs_checked" => total_inputs_checked,
    "inputs_failed" => total_inputs_failed
  },
  "buckets" => bucket_results
}

if options[:json_path]
  FileUtils.mkdir_p(File.dirname(options[:json_path]))
  File.write(options[:json_path], "#{JSON.pretty_generate(report)}\n")
end

if options[:json_stdout]
  puts JSON.pretty_generate(report)
else
  puts ""
  puts format(
    "Summary: %d buckets checked (%d PASS, %d PARTIAL, %d FAIL, %d EMPTY; %d unreproducible skipped), %d/%d inputs failed in %.2fs",
    selected.size,
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

exit((counts["PARTIAL"] + counts["FAIL"]) == 0 ? 0 : 1)

