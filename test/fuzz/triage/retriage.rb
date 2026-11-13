#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "optparse"
require "rbconfig"
require "set"
require "tmpdir"

ENV["TRIAGE_LIB_ONLY"] = "1"
require_relative "triage"

def parse_csv_env(name)
  ENV.fetch(name, "").split(",").map(&:strip).reject(&:empty?)
end

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

# Collect all unique raw input SHA-256 hashes and their latest occurrence metadata
# from a bucket directory before removing it from disk.
def collect_bucket_provenance(bucket_dir)
  hashes = Set.new
  occ_by_sha = {}

  occ_path = File.join(bucket_dir, "occurrences.jsonl")
  if File.file?(occ_path)
    File.foreach(occ_path) do |line|
      rec = JSON.parse(line)
      sha = rec["sha256"]
      next unless sha && !sha.empty?

      hashes.add(sha)
      occ_by_sha[sha] ||= rec
    rescue JSON::ParserError
      next
    end
  end

  meta_path = File.join(bucket_dir, "meta.json")
  meta = File.file?(meta_path) ? (JSON.parse(File.read(meta_path)) rescue nil) : nil
  if meta.is_a?(Hash)
    raw_sha = meta.dig("input", "raw_sha256")
    hashes.add(raw_sha) if raw_sha && !raw_sha.empty?
  end

  archive_path = File.join(bucket_dir, INPUTS_ARCHIVE_FILE)
  if File.file?(archive_path)
    read_tar_gz_entries(archive_path, include_bytes: false)[:entries].each_key { |sha| hashes.add(sha) }
  end

  read_pending_inputs(bucket_dir).each { |sha, _| hashes.add(sha) }

  Dir.glob(File.join(bucket_dir, "id*")).each do |id_path|
    next unless File.file?(id_path)

    hashes.add(Digest::SHA256.file(id_path).hexdigest)
  end

  { meta: meta, hashes: hashes, occ_by_sha: occ_by_sha }
end

def resolve_reclassify_executable(meta, profile)
  reproduced_by = meta&.dig("reproduced_by").to_s
  unless reproduced_by.empty?
    return "./build/fuzz" if %w[./build/fuzz.sand ./build/fuzz.cmplog].include?(reproduced_by)
    # Raw archived bytes already have IJON stream-mode bit cleared; classify via fuzz.native
    # when built so we avoid redundant normalization while keeping the same replay chain.
    return "./build/fuzz.native" if reproduced_by.end_with?("ijon") && File.executable?("./build/fuzz.native")

    return reproduced_by
  end

  case profile
  when "asan_ubsan_slow"
    "./build/fuzz.slow"
  when "msan_slow"
    "./build/fuzz.msan"
  when "lsan_slow"
    "./build/fuzz.lsan"
  when "xallocator"
    File.executable?("./build/fuzz.native") ? "./build/fuzz.native" : "./build/fuzz"
  else
    "./build/fuzz"
  end
end

def collect_survivor_files(bucket_survivor_dir)
  return [] unless File.directory?(bucket_survivor_dir)

  files = Dir.children(bucket_survivor_dir)
    .map { |name| File.join(bucket_survivor_dir, name) }
    .select { |path| File.file?(path) }
    .sort

  archived = files.reject { |path| File.basename(path) == "input.min" }
  archived.empty? ? files : archived
end

def build_verify_command(verify_rb, options, survivors_dir, verify_json_path)
  cmd = [
    RbConfig.ruby,
    verify_rb,
    "--triage-dir", options[:triage_dir],
    "--timeout", options[:timeout].to_s,
    "--max-failures", "0",
    "--extract-survivors", survivors_dir,
    "--json", verify_json_path
  ]
  cmd.push("--clusters-file", options[:clusters_file]) if options[:clusters_file]
  options[:clusters].each { |pat| cmd.push("--cluster", pat) }
  options[:buckets].each { |pat| cmd.push("--bucket", pat) }
  options[:reasons].each { |pat| cmd.push("--reason", pat) }
  cmd << "--include-unreproducible" if options[:include_unreproducible]
  cmd << "--rebuild" if options[:rebuild]
  cmd << "--quiet" if options[:quiet]
  cmd
end

def prune_empty_reason_dirs(triage_dir, bucket_ids)
  bucket_ids.map { |bid| bid.split("/", 2).first }.uniq.each do |reason|
    next if reason.nil? || reason.empty? || reason.start_with?(".")

    reason_dir = File.join(triage_dir, reason)
    Dir.rmdir(reason_dir) if File.directory?(reason_dir) && Dir.empty?(reason_dir)
  end
end

options = {
  triage_dir: ENV.fetch("TRIAGE_DIR", "tmp/fuzz/triage"),
  clusters: parse_csv_env("CLUSTER"),
  clusters_file: ENV["CLUSTERS_FILE"]&.strip,
  buckets: parse_csv_env("BUCKET"),
  reasons: parse_csv_env("REASON"),
  include_unreproducible: ENV["VERIFY_UNREPRODUCIBLE"] == "1",
  timeout: Integer(ENV.fetch("VERIFY_TIMEOUT", "5")),
  rebuild: ENV["VERIFY_REBUILD"] == "1",
  build: ENV.fetch("RETRIAGE_BUILD", "1") != "0",
  dry_run: ENV["RETRIAGE_DRY_RUN"] == "1",
  verbose: ENV["VERIFY_VERBOSE"] == "1",
  quiet: ENV["VERIFY_QUIET"] == "1"
}

OptionParser.new do |opts|
  opts.banner = "Usage: retriage.rb [OPTIONS]"
  opts.on("--triage-dir DIR", "Triage directory (default: tmp/fuzz/triage)") { |v| options[:triage_dir] = v }
  opts.on("--cluster PATTERN", "Only retriage buckets in matching cluster(s) (repeatable)") { |v| options[:clusters] << v }
  opts.on("--clusters-file PATH", "Path to clusters.json (default: <triage-dir>/clusters.json)") { |v| options[:clusters_file] = v }
  opts.on("--bucket PATTERN", "Only retriage buckets matching pattern (repeatable)") { |v| options[:buckets] << v }
  opts.on("--reason REASON", "Only retriage buckets in reason directory (repeatable)") { |v| options[:reasons] << v }
  opts.on("--include-unreproducible", "Include unreproducible/ buckets in verification") { options[:include_unreproducible] = true }
  opts.on("--timeout SEC", Integer, "Per-input verify timeout in seconds (default: 5)") { |v| options[:timeout] = v }
  opts.on("--rebuild", "Force rebuild of verify_runner binaries") { options[:rebuild] = true }
  opts.on("--no-build", "Skip `make fuzz-build` before re-triaging survivors") { options[:build] = false }
  opts.on("--dry-run", "Verify and report what would be removed/re-triaged without modifying disk") { options[:dry_run] = true }
  opts.on("--verbose", "Print detailed progress") { options[:verbose] = true }
  opts.on("--quiet", "Suppress detailed verification lines") { options[:quiet] = true }
end.parse!

options[:clusters_file] = nil if options[:clusters_file]&.empty?

repo_root = locate_repo_root
verify_rb = File.join(__dir__, "verify.rb")
abort "Missing verify.rb at #{verify_rb}" unless File.file?(verify_rb)

triage_dir = options[:triage_dir]
unless File.directory?(triage_dir)
  warn "Triage directory not found: #{triage_dir}"
  exit 0
end

Dir.mktmpdir("prism-retriage-") do |workdir|
  survivors_dir = File.join(workdir, "survivors")
  verify_json_path = File.join(workdir, "verify.json")
  verify_cmd = build_verify_command(verify_rb, options, survivors_dir, verify_json_path)

  system(*verify_cmd)
  verify_rc = $?.exitstatus

  if verify_rc == 0 && !File.file?(verify_json_path)
    puts "Nothing to retriage under #{triage_dir}."
    exit 0
  end

  unless [0, 1].include?(verify_rc) && File.file?(verify_json_path)
    abort "Verification failed (exit=#{verify_rc}); leaving #{triage_dir} unmodified."
  end

  verify_report = JSON.parse(File.read(verify_json_path))
  checked_buckets = verify_report.fetch("buckets")
  if checked_buckets.empty?
    puts "No matching buckets checked; leaving #{triage_dir} unmodified."
    exit 0
  end

  cured_buckets = []
  failing_buckets = []
  buckets_to_remove = []
  cured_hashes = Set.new
  survivors_by_sha = {}
  surviving_all_shas = Set.new
  occ_overrides = {}

  checked_buckets.each do |b|
    bucket_id = b["bucket_id"]
    bucket_dir = File.join(triage_dir, bucket_id)
    provenance = collect_bucket_provenance(bucket_dir)

    buckets_to_remove << bucket_id
    cured_hashes.merge(provenance[:hashes])

    if %w[PASS EMPTY].include?(b["status"])
      cured_buckets << bucket_id
      next
    end

    failing_buckets << bucket_id
    bucket_survivor_dir = File.join(survivors_dir, bucket_id)
    files = collect_survivor_files(bucket_survivor_dir)
    if b["failed"].to_i > 0 && files.empty?
      abort "Bucket #{bucket_id} reported #{b["failed"]} failures, but no survivors were extracted; leaving #{triage_dir} unmodified."
    end

    executable = resolve_reclassify_executable(provenance[:meta], b["profile"])
    default_queue = provenance[:meta]&.dig("reason") == "hang" ? "hangs" : "crashes"

    files.each do |file_path|
      bname = File.basename(file_path)
      content_sha = Digest::SHA256.file(file_path).hexdigest
      # Archived tar entries use the pre-normalized raw crash SHA-256 (differs from content_sha for IJON inputs).
      orig_sha = bname.match?(/\A[0-9a-f]{64}\z/i) ? bname : content_sha
      occ = provenance[:occ_by_sha][orig_sha] || provenance[:occ_by_sha][content_sha]
      if occ
        occ_overrides[content_sha] ||= occ.merge("sha256" => content_sha)
      end

      surviving_all_shas.add(orig_sha)
      surviving_all_shas.add(content_sha)

      survivors_by_sha[content_sha] ||= {
        sha: content_sha,
        path: file_path,
        executable: executable,
        queue: occ&.dig("queue") == "hangs" ? "hangs" : default_queue
      }
    end
  end

  cured_hashes.subtract(surviving_all_shas)

  unless options[:quiet]
    puts ""
    puts format(
      "Retriage plan for %s: %d bucket(s) cured/empty (to remove, %d unique input hashes skipped), %d failing/partial bucket(s) (%d surviving inputs to re-triage)",
      triage_dir,
      cured_buckets.size,
      cured_hashes.size,
      failing_buckets.size,
      survivors_by_sha.size
    )
  end

  if options[:dry_run]
    puts "Dry run (--dry-run): no changes made to #{triage_dir}."
    exit 0
  end

  # Rebuild classifying fuzzer binaries before modifying triage_dir so a compile failure
  # never discards existing triage buckets or archived survivors.
  if !survivors_by_sha.empty? && options[:build]
    puts "Rebuilding fuzzer binaries against current working tree (make fuzz-build)..." unless options[:quiet]
    build_ok = Dir.chdir(repo_root) { system("make", "fuzz-build") }
    abort "make fuzz-build failed; leaving #{triage_dir} unmodified." unless build_ok
  end

  buckets_to_remove.each do |bucket_id|
    FileUtils.rm_rf(File.join(triage_dir, bucket_id))
  end
  prune_empty_reason_dirs(triage_dir, buckets_to_remove)

  processed_dir = File.join(triage_dir, ".processed")
  FileUtils.mkdir_p(processed_dir)
  cured_hashes.each do |sha|
    File.write(File.join(processed_dir, sha), "#skip\n")
  end
  surviving_all_shas.each do |sha|
    FileUtils.rm_f(File.join(processed_dir, sha))
  end

  if survivors_by_sha.empty?
    finalize_triage_metadata(triage_dir)
  else
    staged_root = File.join(workdir, "staged")
    survivors_by_sha.values.group_by { |s| [s[:executable], s[:queue]] }.each_with_index do |((executable, queue), items), group_idx|
      worker_dir = File.join(staged_root, "retriage_#{group_idx}")
      crash_dir = File.join(worker_dir, queue)
      FileUtils.mkdir_p(crash_dir)
      File.write(File.join(worker_dir, "cmdline"), "#{executable}\n")

      items.each_with_index do |item, idx|
        dst = File.join(crash_dir, format("id:%06d,%s", idx, item[:sha][0, 12]))
        FileUtils.cp(item[:path], dst)
      end
    end

    run_triage_pipeline(
      output_dirs: [staged_root],
      testcases_dir: triage_dir,
      occurrence_overrides: occ_overrides
    )
  end

  clusters_path = File.join(triage_dir, "clusters.json")
  unless options[:quiet]
    puts ""
    if File.file?(clusters_path)
      updated = JSON.parse(File.read(clusters_path))
      puts FuzzClustering.format_summary_table(updated)
    end
    puts format(
      "Retriage complete: removed %d cured bucket(s), replaced %d failing bucket(s) (%d surviving input(s)) under %s",
      cured_buckets.size,
      failing_buckets.size,
      survivors_by_sha.size,
      triage_dir
    )
  end
end
