#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"
require "optparse"
require "shellwords"

def env_list(name)
  ENV.fetch(name, "").split(",").map(&:strip).reject(&:empty?)
end

def container_path(host_path, host_root, container_root, label)
  return host_path unless host_path.start_with?("/")

  expanded = File.expand_path(host_path)
  root_prefix = host_root.end_with?("/") ? host_root : "#{host_root}/"
  if expanded == host_root
    return container_root
  elsif expanded.start_with?(root_prefix)
    return File.join(container_root, expanded.delete_prefix(root_prefix))
  end

  abort "#{label} path '#{host_path}' is outside #{host_root} and is not mounted in the prism/fuzz container"
end

def run_git(repo_dir, *args, capture: false)
  cmd = ["git", "-C", repo_dir, *args]
  if capture
    out, err, st = Open3.capture3(*cmd)
    return [out, err, st]
  end

  system(*cmd)
  $?.exitstatus
end

def resolve_commit!(repo_dir, rev, label)
  out, err, st = run_git(repo_dir, "rev-parse", "--verify", "#{rev}^{commit}", capture: true)
  unless st.success?
    abort "bisect.rb: invalid #{label} revision '#{rev}': #{err.strip}"
  end
  out.strip
end

def checkout_worktree_commit!(worktree_dir, sha)
  rc = run_git(worktree_dir, "checkout", "--detach", "--force", sha)
  abort "bisect.rb: failed to checkout #{sha} in #{worktree_dir}" unless rc == 0

  run_git(worktree_dir, "clean", "-fdq")
end

def print_commit_header(worktree_dir)
  out, _, st = run_git(worktree_dir, "log", "-n", "1", "--oneline", "HEAD", capture: true)
  $stderr.puts "[bisect] #{st.success? ? out.strip : File.basename(worktree_dir)}"
end

def build_verify_args(opts, fuzz_root:, target_path:, fail_fast: true, json_path: nil, force_quiet: nil, suppress_invert: false)
  triage_dir = opts[:local] ? opts[:triage_dir] : container_path(opts[:triage_dir], fuzz_root, "/prism", "TRIAGE_DIR")
  args = [
    "--target", target_path,
    "--triage-dir", triage_dir,
    "--bisect",
    "--timeout", opts[:timeout].to_s,
    "--max-failures", opts[:max_failures].to_s
  ]
  args << "--fail-fast" if fail_fast
  args << "--invert" if opts[:invert] && !suppress_invert
  quiet = force_quiet.nil? ? !opts[:verbose] : force_quiet
  args << "--quiet" if quiet
  args << "--verbose" if opts[:verbose] && !quiet
  args << "--input-min-only" if opts[:input_min_only]
  args << "--skip-min" if opts[:skip_min]
  args << "--symbolize" if opts[:symbolize]
  args << "--include-unreproducible" if opts[:include_unreproducible]
  if json_path
    jp = opts[:local] ? json_path : container_path(json_path, fuzz_root, "/prism", "JSON_REPORT")
    args.push("--json", jp)
  end
  if opts[:clusters_file] && !opts[:clusters_file].empty?
    cf = opts[:local] ? opts[:clusters_file] : container_path(opts[:clusters_file], fuzz_root, "/prism", "CLUSTERS_FILE")
    args.push("--clusters-file", cf)
  end
  opts[:buckets].each { |b| args.push("--bucket", b) }
  opts[:clusters].each { |c| args.push("--cluster", c) }
  opts[:reasons].each { |r| args.push("--reason", r) }
  args
end

def build_verify_command(worktree_dir, fuzz_root:, opts:, fail_fast: true, json_path: nil, force_quiet: nil, suppress_invert: false)
  if opts[:local]
    verify_rb = File.join(fuzz_root, "test/fuzz/triage/verify.rb")
    verify_args = build_verify_args(
      opts,
      fuzz_root: fuzz_root,
      target_path: worktree_dir,
      fail_fast: fail_fast,
      json_path: json_path,
      force_quiet: force_quiet,
      suppress_invert: suppress_invert
    )
    ["ruby", verify_rb, *verify_args]
  else
    tmpfs_flags = Shellwords.split(ENV.fetch("FUZZ_TMPFS_FLAGS", "--tmpfs /tmp:rw,exec,mode=1777"))
    max_input = ENV.fetch("FUZZ_MAX_INPUT_SIZE", "1024")
    max_alloc = ENV.fetch("FUZZ_MAX_ALLOCATED", "128")
    verify_args = build_verify_args(
      opts,
      fuzz_root: fuzz_root,
      target_path: "/target",
      fail_fast: fail_fast,
      json_path: json_path,
      force_quiet: force_quiet,
      suppress_invert: suppress_invert
    )
    [
      "docker", "run", "--rm",
      *tmpfs_flags,
      "-e", "FUZZ_MAX_INPUT_SIZE=#{max_input}",
      "-e", "FUZZ_MAX_ALLOCATED=#{max_alloc}",
      "-v", "#{fuzz_root}:/prism",
      "-v", "#{worktree_dir}:/target",
      "prism/fuzz",
      "ruby", "./test/fuzz/triage/verify.rb", *verify_args
    ]
  end
end

def clean_worktree!(worktree_dir)
  run_git(worktree_dir, "checkout", "--force", "HEAD", "--", ".")
  run_git(worktree_dir, "clean", "-fdq")
end

def run_verify_step(worktree_dir, fuzz_root:, opts:)
  clean_worktree!(worktree_dir)
  print_commit_header(worktree_dir)

  cmd = build_verify_command(worktree_dir, fuzz_root: fuzz_root, opts: opts)
  _, _, st = Open3.capture3(*cmd)
  rc = st.exitstatus
  # Template generation on historical commits can modify tracked repo files (e.g. rbi/);
  # restore a clean tree so git bisect's next checkout cannot abort.
  clean_worktree!(worktree_dir)
  return rc if [0, 1, 125].include?(rc)

  warn "[bisect] unexpected verifier failure (exit=#{rc.inspect}); aborting bisection"
  128
end

# Run non-fail-fast, all-failure-count verification on one commit for post-bisect attribution.
def run_attribution_report(worktree_dir, sha, fuzz_root:, opts:, report_path:, full_corpus: false)
  checkout_worktree_commit!(worktree_dir, sha)
  clean_worktree!(worktree_dir)

  attr_opts = opts.merge(max_failures: 0)
  attr_opts = attr_opts.merge(input_min_only: false, skip_min: false) if full_corpus
  cmd = build_verify_command(
    worktree_dir,
    fuzz_root: fuzz_root,
    opts: attr_opts,
    fail_fast: false,
    json_path: report_path,
    force_quiet: true,
    suppress_invert: true
  )
  _, _, st = Open3.capture3(*cmd)
  rc = st.exitstatus
  clean_worktree!(worktree_dir)
  return [nil, :skipped] if rc == 125
  return [nil, :error] unless [0, 1].include?(rc) && File.file?(report_path)

  [JSON.parse(File.read(report_path)), :ok]
rescue JSON::ParserError
  [nil, :error]
end

def format_bucket_attribution(bucket)
  status = bucket["status"]
  failures = bucket["failures"] || []
  first = failures.first
  headline = first ? first["headline"] : status

  if status == "PARTIAL"
    sample = first ? "#{first["name"]}: #{headline}" : headline
    "PARTIAL (input.min PASSED; #{failures.size} archived failed — #{sample})"
  elsif status == "FAIL"
    has_min_fail = failures.any? { |f| f["name"] == "input.min" }
    arch_failed = failures.count { |f| f["name"] != "input.min" }
    if has_min_fail
      suffix = arch_failed > 0 ? " + #{arch_failed} archived" : ""
      "FAIL (input.min#{suffix}: #{headline})"
    else
      sample = first ? "#{first["name"]}: #{headline}" : headline
      "FAIL (#{failures.size} failed — #{sample})"
    end
  else
    status
  end
end

def print_attribution_group(label, buckets, limit:, &formatter)
  return if buckets.empty?

  puts "  #{label} (#{buckets.size}):"
  shown = limit ? buckets.first(limit) : buckets
  shown.each do |b|
    detail = block_given? ? formatter.call(b) : b["status"]
    puts "    - #{b["bucket_id"]}: #{detail}"
  end
  puts "    ... (#{buckets.size - shown.size} more; rerun with --verbose to list all)" if limit && buckets.size > shown.size
end

def print_regression_attribution(found_sha, found_buckets, parent_sha, parent_by_id, parent_state, limit:, bad_sha: nil, bad_by_id: nil)
  failing = found_buckets.select { |b| %w[FAIL PARTIAL].include?(b["status"]) }
  passing = found_buckets.select { |b| b["status"] == "PASS" }
  short_sha = found_sha[0, 12]
  pass_detail = proc do |b|
    if bad_by_id && (bad_b = bad_by_id[b["bucket_id"]])
      "PASS (at #{bad_sha[0, 12]} BAD: #{format_bucket_attribution(bad_b)})"
    else
      "PASS"
    end
  end

  if parent_by_id
    parent_short = parent_sha[0, 12]
    newly_failing = failing.select { |b| !%w[FAIL PARTIAL].include?(parent_by_id.dig(b["bucket_id"], "status")) }
    worsened = failing.select { |b| parent_by_id.dig(b["bucket_id"], "status") == "PARTIAL" && b["status"] == "FAIL" }
    already_failing = failing - newly_failing - worsened

    if passing.empty? && already_failing.empty? && worsened.empty?
      puts "All #{failing.size}/#{found_buckets.size} selected buckets transitioned from PASS at #{parent_short} to failing at #{short_sha}."
    else
      puts "Warning: only #{newly_failing.size + worsened.size}/#{found_buckets.size} selected buckets transitioned at #{short_sha} " \
           "(#{already_failing.size} already failing/partial at #{parent_short}, #{passing.size} still PASS at #{short_sha}) — " \
           "cluster/selection may combine multiple causes or pre-existing archived crashes:"
      print_attribution_group("Newly failing at #{short_sha}", newly_failing, limit: limit) { |b| format_bucket_attribution(b) }
      print_attribution_group("Changed PARTIAL -> FAIL at #{short_sha}", worsened, limit: limit) { |b| format_bucket_attribution(b) }
      print_attribution_group("Already failing at #{parent_short}", already_failing, limit: limit) { |b| format_bucket_attribution(b) }
      print_attribution_group("Still PASS at #{short_sha} (introduced after #{short_sha})", passing, limit: limit, &pass_detail)
    end
  else
    parent_note = parent_state == :skipped ? " (parent #{parent_sha[0, 12]} skipped as unbuildable)" : ""
    if passing.empty?
      puts "All #{failing.size}/#{found_buckets.size} selected buckets fail at #{short_sha}#{parent_note}."
    else
      puts "Warning: #{failing.size}/#{found_buckets.size} selected buckets fail at #{short_sha} and #{passing.size} still PASS#{parent_note} — " \
           "cluster/selection may combine causes from multiple commits:"
      print_attribution_group("Failing at #{short_sha}", failing, limit: limit) { |b| format_bucket_attribution(b) }
      print_attribution_group("Still PASS at #{short_sha} (introduced after #{short_sha})", passing, limit: limit, &pass_detail)
    end
  end
end

def print_fix_attribution(found_sha, found_buckets, parent_sha, parent_by_id, parent_state, limit:, broken_sha: nil, broken_by_id: nil)
  short_sha = found_sha[0, 12]
  if parent_by_id
    parent_short = parent_sha[0, 12]
    fixed_here = found_buckets.select { |b| b["status"] == "PASS" && %w[FAIL PARTIAL].include?(parent_by_id.dig(b["bucket_id"], "status")) }
    already_passing = found_buckets.select { |b| b["status"] == "PASS" && !%w[FAIL PARTIAL].include?(parent_by_id.dig(b["bucket_id"], "status")) }

    if already_passing.empty? && fixed_here.size == found_buckets.size
      puts "All #{fixed_here.size}/#{found_buckets.size} selected buckets were fixed together at #{short_sha} (all failed at #{parent_short})."
    else
      puts "Warning: #{short_sha} fixed only #{fixed_here.size}/#{found_buckets.size} selected buckets " \
           "(#{already_passing.size} already PASSED at #{parent_short}) — cluster/selection was fixed across multiple commits:"
      print_attribution_group("Fixed at #{short_sha} (failed at #{parent_short})", fixed_here, limit: limit) do |b|
        format_bucket_attribution(parent_by_id.fetch(b["bucket_id"]))
      end
      print_attribution_group("Already PASS at #{parent_short}", already_passing, limit: limit) do |b|
        if broken_by_id && (broken_b = broken_by_id[b["bucket_id"]])
          if %w[FAIL PARTIAL].include?(broken_b["status"])
            "PASS (failed at #{broken_sha[0, 12]} BROKEN: #{format_bucket_attribution(broken_b)})"
          else
            "PASS (already PASS at #{broken_sha[0, 12]} BROKEN too)"
          end
        else
          "PASS"
        end
      end
    end
  else
    parent_note = parent_state == :skipped ? " (parent #{parent_sha[0, 12]} skipped as unbuildable)" : ""
    puts "All #{found_buckets.size}/#{found_buckets.size} selected buckets PASS at #{short_sha}#{parent_note}."
  end
end

def summarize_multi_bucket_attribution(git_repo:, worktree_dir:, found_sha:, old_sha:, new_sha:, mode:, fuzz_root:, step_opts:, report_dir:)
  FileUtils.mkdir_p(report_dir)
  found_path = File.join(report_dir, "found.json")
  found_report, found_state = run_attribution_report(worktree_dir, found_sha, fuzz_root: fuzz_root, opts: step_opts, report_path: found_path)
  return unless found_state == :ok && found_report

  found_buckets = found_report["buckets"] || []
  return if found_buckets.size <= 1

  parents_out, _, p_st = run_git(git_repo, "rev-list", "--parents", "-n", "1", found_sha, capture: true)
  parent_sha = p_st.success? ? parents_out.strip.split[1] : nil

  parent_by_id = nil
  parent_state = :none
  if parent_sha
    parent_path = File.join(report_dir, "parent.json")
    parent_report, parent_state = run_attribution_report(worktree_dir, parent_sha, fuzz_root: fuzz_root, opts: step_opts, report_path: parent_path)
    if parent_state == :ok && parent_report
      parent_by_id = (parent_report["buckets"] || []).each_with_object({}) { |b, h| h[b["bucket_id"]] = b }
    end
  end

  bad_by_id = nil
  broken_by_id = nil
  if mode == :regression && new_sha && found_sha != new_sha && found_buckets.any? { |b| b["status"] == "PASS" }
    bad_path = File.join(report_dir, "bad.json")
    bad_report, bad_state = run_attribution_report(
      worktree_dir,
      new_sha,
      fuzz_root: fuzz_root,
      opts: step_opts,
      report_path: bad_path,
      full_corpus: !step_opts[:skip_min]
    )
    if bad_state == :ok && bad_report
      bad_by_id = (bad_report["buckets"] || []).each_with_object({}) { |b, h| h[b["bucket_id"]] = b }
    end
  elsif mode == :fix && old_sha && found_sha != old_sha && parent_by_id &&
        found_buckets.any? { |b| b["status"] == "PASS" && !%w[FAIL PARTIAL].include?(parent_by_id.dig(b["bucket_id"], "status")) }
    broken_path = File.join(report_dir, "broken.json")
    broken_report, broken_state = run_attribution_report(worktree_dir, old_sha, fuzz_root: fuzz_root, opts: step_opts, report_path: broken_path)
    if broken_state == :ok && broken_report
      broken_by_id = (broken_report["buckets"] || []).each_with_object({}) { |b, h| h[b["bucket_id"]] = b }
    end
  end

  mode_note = if step_opts[:input_min_only]
                "; input.min only"
              elsif step_opts[:skip_min]
                "; archived inputs only"
              else
                ""
              end
  limit = step_opts[:verbose] ? nil : 10
  puts ""
  puts "== Cluster attribution (#{found_buckets.size} buckets at #{found_sha[0, 12]}#{mode_note}) =="
  if mode == :fix
    print_fix_attribution(found_sha, found_buckets, parent_sha, parent_by_id, parent_state, limit: limit, broken_sha: old_sha, broken_by_id: broken_by_id)
  else
    print_regression_attribution(found_sha, found_buckets, parent_sha, parent_by_id, parent_state, limit: limit, bad_sha: new_sha, bad_by_id: bad_by_id)
  end
end

def run_step_mode(step_worktree)
  step_opts = {
    fuzz_root: ENV.fetch("BISECT_FUZZ_ROOT"),
    triage_dir: ENV.fetch("BISECT_TRIAGE_DIR", "tmp/fuzz/triage"),
    clusters_file: ENV["BISECT_CLUSTERS_FILE"],
    buckets: env_list("BISECT_BUCKET"),
    clusters: env_list("BISECT_CLUSTER"),
    reasons: env_list("BISECT_REASON"),
    timeout: Integer(ENV.fetch("BISECT_VERIFY_TIMEOUT", "5")),
    max_failures: Integer(ENV.fetch("BISECT_VERIFY_MAX_FAILURES", "1")),
    include_unreproducible: ENV["BISECT_VERIFY_UNREPRODUCIBLE"] == "1",
    input_min_only: ENV["BISECT_INPUT_MIN_ONLY"] == "1",
    skip_min: ENV["BISECT_SKIP_MIN"] == "1",
    symbolize: ENV["BISECT_VERIFY_SYMBOLIZE"] == "1",
    invert: ENV["BISECT_INVERT"] == "1",
    verbose: ENV["BISECT_VERBOSE"] == "1",
    local: ENV["BISECT_LOCAL"] == "1"
  }

  exit run_verify_step(step_worktree, fuzz_root: step_opts[:fuzz_root], opts: step_opts)
end

if ARGV.include?("--step")
  run_step_mode(Dir.pwd)
end

fuzz_root = File.expand_path("../../..", __dir__)
options = {
  git_repo: fuzz_root,
  good: ENV["GOOD"]&.strip,
  bad: ENV["BAD"]&.strip,
  broken: ENV["BROKEN"]&.strip,
  fixed: ENV["FIXED"]&.strip,
  triage_dir: ENV.fetch("TRIAGE_DIR", "tmp/fuzz/triage"),
  clusters_file: ENV["CLUSTERS_FILE"]&.strip,
  buckets: env_list("BUCKET"),
  clusters: env_list("CLUSTER"),
  reasons: env_list("REASON"),
  timeout: Integer(ENV.fetch("VERIFY_TIMEOUT", "5")),
  max_failures: Integer(ENV.fetch("VERIFY_MAX_FAILURES", "1")),
  include_unreproducible: ENV["VERIFY_UNREPRODUCIBLE"] == "1",
  input_min_only: ENV["VERIFY_INPUT_MIN_ONLY"] == "1",
  skip_min: ENV["VERIFY_SKIP_MIN"] == "1",
  symbolize: ENV["VERIFY_SYMBOLIZE"] == "1",
  verbose: ENV["BISECT_VERBOSE"] == "1" || ENV["VERIFY_VERBOSE"] == "1",
  check_endpoints: ENV["BISECT_NO_CHECK_ENDPOINTS"] != "1",
  keep_worktree: ENV["BISECT_KEEP_WORKTREE"] == "1",
  worktree: ENV["BISECT_WORKTREE"]&.strip,
  local: ENV["BISECT_LOCAL"] == "1" || File.exist?("/.dockerenv")
}

OptionParser.new do |opts|
  opts.banner = <<~BANNER
    Usage:
      bisect.rb --good REV --bad REV [OPTIONS]       # Find commit that introduced failure
      bisect.rb --broken REV --fixed REV [OPTIONS]   # Find commit that fixed failure
  BANNER
  opts.on("--git-repo DIR", "Git repository to bisect (default: current repo)") { |v| options[:git_repo] = File.expand_path(v) }
  opts.on("--good REV", "Older passing commit when bisecting a regression (env: GOOD)") { |v| options[:good] = v }
  opts.on("--bad REV", "Newer failing commit when bisecting a regression (env: BAD)") { |v| options[:bad] = v }
  opts.on("--broken REV", "Older failing commit when bisecting a fix (env: BROKEN)") { |v| options[:broken] = v }
  opts.on("--fixed REV", "Newer passing commit when bisecting a fix (env: FIXED)") { |v| options[:fixed] = v }
  opts.on("--triage-dir DIR", "Triage directory (default: tmp/fuzz/triage)") { |v| options[:triage_dir] = v }
  opts.on("--bucket PATTERN", "Bucket filter (repeatable; env: BUCKET)") { |v| options[:buckets] << v }
  opts.on("--cluster PATTERN", "Cluster filter (repeatable; env: CLUSTER)") { |v| options[:clusters] << v }
  opts.on("--reason REASON", "Reason filter (repeatable; env: REASON)") { |v| options[:reasons] << v }
  opts.on("--clusters-file PATH", "Path to clusters.json") { |v| options[:clusters_file] = v }
  opts.on("--timeout SEC", Integer, "Per-input timeout in seconds (default: 5)") { |v| options[:timeout] = v }
  opts.on("--max-failures N", Integer, "Stop each bucket after N failures (default: 1)") { |v| options[:max_failures] = v }
  opts.on("--input-min-only", "Only test each bucket's minimized input.min (skip archived inputs; env: VERIFY_INPUT_MIN_ONLY=1)") { options[:input_min_only] = true }
  opts.on("--skip-min", "Skip each bucket's input.min (test archived inputs only; env: VERIFY_SKIP_MIN=1)") { options[:skip_min] = true }
  opts.on("--include-unreproducible", "Include unreproducible/ buckets") { options[:include_unreproducible] = true }
  opts.on("--symbolize", "Enable external llvm-symbolizer during steps") { options[:symbolize] = true }
  opts.on("--no-check-endpoints", "Skip pre-flight verification of endpoint commits") { options[:check_endpoints] = false }
  opts.on("--keep-worktree", "Keep temporary bisect worktree after finishing") { options[:keep_worktree] = true }
  opts.on("--worktree DIR", "Explicit temporary worktree directory") { |v| options[:worktree] = v }
  opts.on("--local", "Run verify.rb directly on host without Docker") { options[:local] = true }
  opts.on("--verbose", "Print verifier details at each bisect step") { options[:verbose] = true }
  opts.on("--step", "Internal git bisect run step entrypoint") {}
end.parse!

options[:good] = nil if options[:good]&.empty?
options[:bad] = nil if options[:bad]&.empty?
options[:broken] = nil if options[:broken]&.empty?
options[:fixed] = nil if options[:fixed]&.empty?
options[:worktree] = nil if options[:worktree]&.empty?
if options[:input_min_only] && options[:skip_min]
  abort "bisect.rb: --input-min-only and --skip-min cannot be used together"
end

has_reg = options[:good] || options[:bad]
has_fix = options[:broken] || options[:fixed]

if has_reg && has_fix
  abort "bisect.rb: specify either GOOD/BAD or BROKEN/FIXED, not both"
elsif has_reg
  abort "bisect.rb: both GOOD and BAD revisions are required" unless options[:good] && options[:bad]
  mode = :regression
elsif has_fix
  abort "bisect.rb: both BROKEN and FIXED revisions are required" unless options[:broken] && options[:fixed]
  mode = :fix
else
  abort "bisect.rb: specify GOOD=... BAD=... (regression) or BROKEN=... FIXED=... (fix)"
end

git_repo = options[:git_repo]
if mode == :regression
  old_rev = options[:good]
  new_rev = options[:bad]
  old_sha = resolve_commit!(git_repo, old_rev, "GOOD")
  new_sha = resolve_commit!(git_repo, new_rev, "BAD")
  old_term = "good"
  new_term = "bad"
  expected_old_rc = 0
  expected_new_rc = 1
else
  old_rev = options[:broken]
  new_rev = options[:fixed]
  old_sha = resolve_commit!(git_repo, old_rev, "BROKEN")
  new_sha = resolve_commit!(git_repo, new_rev, "FIXED")
  old_term = "broken"
  new_term = "fixed"
  expected_old_rc = 1
  expected_new_rc = 0
end

worktree_dir = File.expand_path(options[:worktree] || File.join(fuzz_root, "build/.fuzz-bisect-worktree.#{Process.pid}"))
report_dir = File.join(fuzz_root, "build/.fuzz-bisect-reports.#{Process.pid}")
worktree_created = false

cleanup_worktree = proc do
  FileUtils.rm_rf(report_dir) if File.exist?(report_dir)
  if worktree_created && !options[:keep_worktree] && File.exist?(worktree_dir)
    run_git(worktree_dir, "bisect", "reset") if File.exist?(File.join(git_repo, ".git"))
    run_git(git_repo, "worktree", "remove", "--force", worktree_dir)
    FileUtils.rm_rf(worktree_dir) if File.exist?(worktree_dir)
    run_git(git_repo, "worktree", "prune")
  end
end

Signal.trap("INT") do
  cleanup_worktree.call
  exit 130
end
Signal.trap("TERM") do
  cleanup_worktree.call
  exit 143
end

begin
  run_git(git_repo, "worktree", "prune")
  if File.exist?(worktree_dir)
    abort "bisect.rb: worktree directory already exists: #{worktree_dir}"
  end
  FileUtils.mkdir_p(File.dirname(worktree_dir))
  rc = run_git(git_repo, "worktree", "add", "--detach", worktree_dir, new_sha)
  abort "bisect.rb: failed to create temporary worktree at #{worktree_dir}" unless rc == 0
  worktree_created = true

  step_opts = {
    triage_dir: options[:triage_dir],
    clusters_file: options[:clusters_file],
    buckets: options[:buckets],
    clusters: options[:clusters],
    reasons: options[:reasons],
    timeout: options[:timeout],
    max_failures: options[:max_failures],
    input_min_only: options[:input_min_only],
    skip_min: options[:skip_min],
    include_unreproducible: options[:include_unreproducible],
    symbolize: options[:symbolize],
    invert: false,
    verbose: options[:verbose],
    local: options[:local]
  }

  if options[:check_endpoints]
    puts "== Checking #{new_term.upcase} endpoint (#{new_rev} -> #{new_sha[0, 12]}) =="
    checkout_worktree_commit!(worktree_dir, new_sha)
    got_new = run_verify_step(worktree_dir, fuzz_root: fuzz_root, opts: step_opts)
    unless got_new == expected_new_rc
      hint = if mode == :regression && got_new == 0
               " (if bisecting for a fix, use BROKEN=<old> FIXED=<new>)"
             elsif mode == :fix && got_new == 1
               " (selected buckets still fail on FIXED revision)"
             else
               ""
             end
      abort "bisect.rb: #{new_term.upcase} commit #{new_sha[0, 12]} returned #{got_new}, expected #{expected_new_rc}#{hint}"
    end

    puts "== Checking #{old_term.upcase} endpoint (#{old_rev} -> #{old_sha[0, 12]}) =="
    checkout_worktree_commit!(worktree_dir, old_sha)
    got_old = run_verify_step(worktree_dir, fuzz_root: fuzz_root, opts: step_opts)
    unless got_old == expected_old_rc
      hint = if mode == :regression && got_old == 1
               " (if bisecting for a fix, use BROKEN=<old> FIXED=<new>)"
             elsif mode == :fix && got_old == 0
               " (selected buckets already pass on BROKEN revision)"
             else
               ""
             end
      abort "bisect.rb: #{old_term.upcase} commit #{old_sha[0, 12]} returned #{got_old}, expected #{expected_old_rc}#{hint}"
    end
  end

  puts "== Running git bisect (#{old_term}=#{old_sha[0, 12]} .. #{new_term}=#{new_sha[0, 12]}) =="
  if mode == :fix
    rc = run_git(worktree_dir, "bisect", "start", "--term-old=broken", "--term-new=fixed", new_sha, old_sha)
  else
    rc = run_git(worktree_dir, "bisect", "start", new_sha, old_sha)
  end
  abort "bisect.rb: git bisect start failed (rc=#{rc})" unless rc == 0

  step_env = {
    "BISECT_FUZZ_ROOT" => fuzz_root,
    "BISECT_TRIAGE_DIR" => options[:triage_dir],
    "BISECT_CLUSTERS_FILE" => options[:clusters_file].to_s,
    "BISECT_BUCKET" => options[:buckets].join(","),
    "BISECT_CLUSTER" => options[:clusters].join(","),
    "BISECT_REASON" => options[:reasons].join(","),
    "BISECT_VERIFY_TIMEOUT" => options[:timeout].to_s,
    "BISECT_VERIFY_MAX_FAILURES" => options[:max_failures].to_s,
    "BISECT_INPUT_MIN_ONLY" => options[:input_min_only] ? "1" : "0",
    "BISECT_SKIP_MIN" => options[:skip_min] ? "1" : "0",
    "BISECT_VERIFY_UNREPRODUCIBLE" => options[:include_unreproducible] ? "1" : "0",
    "BISECT_VERIFY_SYMBOLIZE" => options[:symbolize] ? "1" : "0",
    "BISECT_INVERT" => mode == :fix ? "1" : "0",
    "BISECT_VERBOSE" => options[:verbose] ? "1" : "0",
    "BISECT_LOCAL" => options[:local] ? "1" : "0"
  }

  system(step_env, "git", "-C", worktree_dir, "bisect", "run", "ruby", File.expand_path(__FILE__), "--step")
  bisect_rc = $?.exitstatus

  result_ref = mode == :fix ? "refs/bisect/fixed" : "refs/bisect/bad"
  out, _, st = run_git(worktree_dir, "rev-parse", "--verify", result_ref, capture: true)
  if bisect_rc == 0 && st.success?
    found_sha = out.strip
    puts ""
    puts "== First #{new_term} commit =="
    run_git(git_repo, "show", "--stat", found_sha)

    single_exact_bucket = options[:clusters].empty? &&
                          options[:reasons].empty? &&
                          options[:buckets].size == 1 &&
                          options[:buckets].first.include?("/") &&
                          !options[:buckets].first.match?(/[*?\[]/)
    unless single_exact_bucket
      summarize_multi_bucket_attribution(
        git_repo: git_repo,
        worktree_dir: worktree_dir,
        found_sha: found_sha,
        old_sha: old_sha,
        new_sha: new_sha,
        mode: mode,
        fuzz_root: fuzz_root,
        step_opts: step_opts,
        report_dir: report_dir
      )
    end
  end

  exit bisect_rc
ensure
  cleanup_worktree.call
end

