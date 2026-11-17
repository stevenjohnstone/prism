#!/usr/bin/env ruby
# frozen_string_literal: true

ENV["TRIAGE_LIB_ONLY"] ||= "1"

require "digest"
require "fileutils"
require "json"
require "optparse"
require "shellwords"
require "tempfile"
require "time"
require "tmpdir"

require_relative "triage"

module FuzzMatcher
  DEFAULT_FUZZER_ORDER = %w[fuzz.diff fuzz fuzz.msan fuzz.lsan fuzz.slow].freeze
  RAW_BASENAMES = %w[input.min input.raw].freeze
  RAW_EXTENSIONS = %w[.bin .fuzz .raw].freeze

  class ConfigError < StandardError; end

  module_function

  def parse_csv_env(key)
    ENV.fetch(key, "").split(",").map(&:strip).reject(&:empty?)
  end

  def parse_bool_arg(val, flag_name)
    return true if val.nil?

    case val.to_s.strip.downcase
    when "1", "true", "yes", "on"
      true
    when "0", "false", "no", "off"
      false
    else
      raise ConfigError, "Invalid boolean value '#{val}' for #{flag_name}"
    end
  end

  def default_options
    {
      triage_dir: ENV.fetch("TRIAGE_DIR", TESTCASES_DIR),
      metadata_path: nil,
      clusters_file: ENV["CLUSTERS_FILE"]&.strip,
      coverage_bin: ENV.key?("TRIAGE_COVERAGE_BIN") ? ENV["TRIAGE_COVERAGE_BIN"].strip : nil,
      diff_coverage_bin: ENV.key?("TRIAGE_DIFF_COVERAGE_BIN") ? ENV["TRIAGE_DIFF_COVERAGE_BIN"].strip : nil,
      bins: [],
      all_fuzzers: false,
      raw: false,
      snippet: false,
      header_hex: nil,
      header_explicit: false,
      header_opts: {
        ruby_version: "4.1",
        encoding: nil,
        frozen_string_literal: nil,
        partial_script: false,
        freeze: false,
        attach_comments: false,
        encoding_locked: false,
        stream_mode: false,
        main_script: false,
        command_line: nil,
        scopes_count: 0,
        forwarding: nil,
        start_line: 1
      },
      include_unreproducible: false,
      threshold: nil,
      diff_threshold: nil,
      reason_weight: nil,
      top: 5,
      expect_clusters: parse_csv_env("CLUSTER"),
      json_stdout: false,
      json_path: nil,
      quiet: false,
      verbose: false,
      inline_codes: [],
      stdin: false,
      inputs: []
    }
  end

  # Parses CLI flags and ordered input specs (-e, -, file paths).
  def parse_options(argv)
    options = default_options
    ordered_specs = []
    positional = []

    mark_header_opt = lambda do |key, val|
      options[:header_explicit] = true
      options[:header_opts][key] = val
    end

    parser = OptionParser.new do |opts|
      opts.banner = "Usage: match.rb [OPTIONS] [INPUT ...]"
      opts.separator ""
      opts.separator "Run Ruby snippet(s) or fuzzer input(s) through fuzzers (starting with fuzz.diff)"
      opts.separator "and match crashes/divergences against triage clusters."
      opts.separator ""
      opts.separator "Inputs:"
      opts.on("-e", "--code CODE", "Inline Ruby snippet (repeatable)") do |v|
        ordered_specs << { kind: :inline, label: "<inline:#{ordered_specs.count { |s| s[:kind] == :inline } + 1}>", content: v }
      end
      opts.on("--stdin", "Read Ruby snippet (or --raw bytes) from standard input") do
        options[:stdin] = true
        ordered_specs << { kind: :stdin, label: "<stdin>" }
      end
      opts.on("--raw", "Treat inputs as raw fuzzer testcases (already containing the 4-byte header)") do
        options[:raw] = true
      end
      opts.on("--snippet", "Force treating input files as Ruby source and prepend the 4-byte fuzzer header") do
        options[:snippet] = true
      end

      opts.separator ""
      opts.separator "Fuzzer header options (when encoding a Ruby snippet):"
      opts.on("--header HEX", "Explicit 4-byte hex header (e.g. 00000301)") { |v| options[:header_hex] = v.strip }
      opts.on("--ruby-version VER", "Target Ruby version (#{VERSIONS.join(', ')}; default: 4.1)") { |v| mark_header_opt.call(:ruby_version, v) }
      opts.on("--encoding ENC", "Encoding (#{ENCODINGS.join(', ')})") { |v| mark_header_opt.call(:encoding, v) }
      opts.on("--frozen-string-literal [BOOL]", "Set frozen_string_literal option (default: true)") do |v|
        mark_header_opt.call(:frozen_string_literal, parse_bool_arg(v, "--frozen-string-literal"))
      end
      opts.on("--partial-script", "Set partial_script=true") { mark_header_opt.call(:partial_script, true) }
      opts.on("--freeze", "Set freeze=true") { mark_header_opt.call(:freeze, true) }
      opts.on("--attach-comments", "Set attach_comments=true") { mark_header_opt.call(:attach_comments, true) }
      opts.on("--encoding-locked", "Set encoding_locked=true") { mark_header_opt.call(:encoding_locked, true) }
      opts.on("--stream", "Parse via pm_parse_stream_init") { mark_header_opt.call(:stream_mode, true) }
      opts.on("--main-script", "Set main_script=true") { mark_header_opt.call(:main_script, true) }
      opts.on("--command-line FLAGS", "Set command_line flags subset of #{COMMAND_LINE_CHARS.map(&:last).join}") { |v| mark_header_opt.call(:command_line, v) }
      opts.on("--forwarding FLAGS", "Set forwarding flags subset of #{FORWARDING_CHARS.map(&:last).join}") { |v| mark_header_opt.call(:forwarding, v) }
      opts.on("--scopes-count N", Integer, "Number of enclosing local scopes (0..3)") { |v| mark_header_opt.call(:scopes_count, v) }
      opts.on("--start-line N", Integer, "Parser start_line (-128..127; mutually exclusive with --encoding)") do |v|
        mark_header_opt.call(:start_line, v)
      end

      opts.separator ""
      opts.separator "Fuzzers & triage matching:"
      opts.on("--bin PATH", "Fuzzer binary to probe (repeatable; overrides default fuzz.diff -> fuzz -> ... order)") do |v|
        options[:bins] << v
      end
      opts.on("--all-fuzzers", "Probe all configured fuzzers instead of stopping at the first crash") do
        options[:all_fuzzers] = true
      end
      opts.on("--triage-dir DIR", "Triage directory (default: #{TESTCASES_DIR})") { |v| options[:triage_dir] = v }
      opts.on("--metadata PATH", "Path to metadata.json (default: <triage-dir>/metadata.json)") { |v| options[:metadata_path] = v }
      opts.on("--clusters-file PATH", "Path to clusters.json (default: <triage-dir>/clusters.json)") { |v| options[:clusters_file] = v }
      opts.on("--coverage-bin PATH", "Reference fuzz binary for prism edge coverage") { |v| options[:coverage_bin] = v }
      opts.on("--diff-coverage-bin PATH", "Reference fuzz.diff binary for dual-parser edge coverage") { |v| options[:diff_coverage_bin] = v }
      opts.on("--include-unreproducible", "Include unreproducible buckets when building clusters") { options[:include_unreproducible] = true }
      opts.on("--threshold FLOAT", Float, "Override prism cluster similarity threshold (0.0..1.0)") { |v| options[:threshold] = v }
      opts.on("--diff-threshold FLOAT", Float, "Override diff_parse_y cluster similarity threshold (0.0..1.0)") { |v| options[:diff_threshold] = v }
      opts.on("--reason-weight FLOAT", Float, "Override crash reason bonus weight (0.0..1.0)") { |v| options[:reason_weight] = v }
      opts.on("--top N", Integer, "Number of candidate clusters to show (default: 5, 0 = all)") { |v| options[:top] = v }

      opts.separator ""
      opts.separator "Workflows & output:"
      opts.on("-c", "--expect-cluster PATTERN", "--cluster PATTERN", "Assert each input matches cluster/bucket pattern (repeatable)") do |v|
        v.split(",").each do |part|
          stripped = part.strip
          options[:expect_clusters] << stripped unless stripped.empty?
        end
      end
      opts.on("--json", "Emit structured JSON report to stdout") do
        options[:json_stdout] = true
      end
      opts.on("-o", "--json-file PATH", "Write structured JSON report to PATH") do |v|
        raise OptionParser::InvalidArgument, "PATH cannot be empty" if v.strip.empty?

        options[:json_path] = v
      end
      opts.on("-q", "--quiet", "Print compact one-line verdicts per input") { options[:quiet] = true }
      opts.on("-v", "--verbose", "Show decoded fuzzer options, stderr snippets, and full candidate details") { options[:verbose] = true }
      opts.on("-h", "--help", "Show this help message") do
        puts opts
        exit 0
      end
    end

    begin
      positional = parser.parse(argv)
    rescue OptionParser::ParseError => e
      raise ConfigError, e.message
    end

    options[:clusters_file] = nil if options[:clusters_file]&.empty?
    options[:metadata_path] = nil if options[:metadata_path]&.empty?

    if options[:raw] && options[:snippet]
      raise ConfigError, "--raw and --snippet cannot be used together"
    end
    if options[:raw] && (options[:header_hex] || options[:header_explicit])
      raise ConfigError, "--raw cannot be combined with fuzzer header options (--header, --ruby-version, etc.)"
    end
    if options[:header_hex] && options[:header_explicit]
      raise ConfigError, "--header HEX cannot be combined with individual header options"
    end
    if options[:quiet] && options[:verbose]
      raise ConfigError, "--quiet and --verbose cannot be used together"
    end
    if options[:top].negative?
      raise ConfigError, "--top must be >= 0"
    end

    positional.each do |arg|
      if arg == "-"
        ordered_specs << { kind: :stdin, label: "<stdin>" }
      else
        ordered_specs << { kind: :file, label: arg, path: arg }
      end
    end

    raise ConfigError, "No input specified. Pass a file path, --code/-e CODE, or --stdin (-).\n\n#{parser}" if ordered_specs.empty?

    options[:inputs] = ordered_specs
    options
  end

  def repo_root_dir
    FuzzProvenance.locate_repo_root(__dir__) || File.expand_path("../../..", __dir__)
  end

  def resolve_repo_path(path, root = repo_root_dir)
    return nil if path.nil? || path.to_s.empty?

    str = path.to_s
    return str if File.exist?(str) || str.start_with?("/")

    cand = File.expand_path(str, root)
    File.exist?(cand) ? cand : str
  end

  def build_probe_header(options)
    if options[:header_hex]
      hex = options[:header_hex]
      raise ConfigError, "Invalid --header '#{hex}' (expected 8 hex characters, e.g. 00000301)" unless hex.match?(/\A[0-9a-fA-F]{8}\z/)

      return [hex].pack("H*")
    end

    encode_fuzz_header(**options[:header_opts])
  rescue ArgumentError => e
    raise ConfigError, e.message
  end

  # Heuristic for distinguishing existing raw fuzzer inputs (input.min, id:...)
  # from plain Ruby source files when neither --raw nor --snippet is passed.
  def treat_as_raw_file?(path, bytes, options)
    return true if options[:raw]
    return false if options[:snippet] || options[:header_hex] || options[:header_explicit]

    ext = File.extname(path.to_s)
    return false if ext.casecmp?(".rb")

    base = File.basename(path.to_s)
    return true if RAW_BASENAMES.include?(base) || RAW_EXTENSIONS.include?(ext.downcase) || base.start_with?("id:")

    bytes.byteslice(0, 4).to_s.bytes.any? { |b| b < 0x20 && b != 0x09 && b != 0x0a && b != 0x0d }
  end

  def read_input_bytes(spec, stdin_cache)
    case spec[:kind]
    when :inline
      spec[:content].to_s.b
    when :stdin
      stdin_cache[:data] ||= $stdin.binmode.read.b
    when :file
      path = spec[:path]
      raise ConfigError, "Input file not found: #{path}" unless File.file?(path)

      File.binread(path)
    end
  end

  def prepare_probe_input(spec, index, options, tmp_dir, header_bytes, stdin_cache)
    source_bytes = read_input_bytes(spec, stdin_cache)
    is_raw = if spec[:kind] == :file
               treat_as_raw_file?(spec[:path], source_bytes, options)
             else
               options[:raw]
             end

    wire_bytes = is_raw ? source_bytes : (header_bytes + source_bytes).b
    probe_path = File.join(tmp_dir, "probe_#{index}.bin")
    File.binwrite(probe_path, wire_bytes)

    decoded = decode_fuzz_header(wire_bytes)
    {
      index: index,
      label: spec[:label],
      kind: spec[:kind].to_s,
      mode: is_raw ? "raw" : "snippet",
      source_size_bytes: source_bytes.bytesize,
      wire_size_bytes: wire_bytes.bytesize,
      raw_sha256: Digest::SHA256.hexdigest(wire_bytes),
      probe_path: probe_path,
      decoded_header: decoded
    }
  end

  def resolve_fuzzers(options)
    root = repo_root_dir
    unless options[:bins].empty?
      resolved = options[:bins].map do |p|
        cand = resolve_repo_path(p, root)
        raise ConfigError, "Fuzzer binary not executable: #{p}" unless cand && File.file?(cand) && File.executable?(cand)

        { name: File.basename(cand), path: cand }
      end
      return resolved.uniq { |entry| File.realpath(entry[:path]) }
    end

    snap_bin_dir = File.join(File.dirname(options[:triage_dir]), "bin")
    build_dir = File.join(root, "build")
    snap_has_bins = DEFAULT_FUZZER_ORDER.any? do |name|
      p = File.join(snap_bin_dir, name)
      File.file?(p) && File.executable?(p)
    end
    search_dirs = snap_has_bins ? [snap_bin_dir] : [build_dir]
    seen_real = {}
    resolved = []

    DEFAULT_FUZZER_ORDER.each do |name|
      cand = search_dirs.map { |d| File.join(d, name) }.find do |p|
        File.file?(p) && File.executable?(p)
      end
      next unless cand

      real = File.realpath(cand)
      next if seen_real[real]

      seen_real[real] = true
      resolved << { name: name, path: cand }
    end

    if resolved.empty?
      raise ConfigError, "No executable fuzzer binaries found under #{snap_bin_dir} or #{build_dir} (run make fuzz-build or pass --bin)"
    end

    resolved
  end

  def resolve_reference_binary(role:, override_bin:, metadata_ref:, fallback_proc:, root:, warnings:, triage_dir:)
    expected_build_id = metadata_ref.is_a?(Hash) ? metadata_ref["build_id"] : nil

    if !override_bin.nil?
      return { bin: nil, build_id: nil, source: "disabled", reason: "disabled by override" } if override_bin.empty?

      cand = resolve_repo_path(override_bin, root)
      unless cand && File.file?(cand) && File.executable?(cand)
        raise ConfigError, "#{role} binary is not executable: #{override_bin}"
      end

      actual_id = binary_build_id(cand)
      if expected_build_id && actual_id && expected_build_id != actual_id
        warnings << "#{role} binary #{normalize_repo_path(cand)} build_id differs from metadata.json (#{actual_id[0, 12]} != #{expected_build_id[0, 12]}); edge IDs may not match"
      end
      return { bin: cand, build_id: actual_id, source: "override" }
    end

    meta_path = metadata_ref.is_a?(Hash) ? metadata_ref["path"] : nil
    if meta_path && !meta_path.to_s.empty? && metadata_ref["available"] != false
      cand = resolve_repo_path(meta_path, root)
      if cand && File.file?(cand) && File.executable?(cand)
        actual_id = binary_build_id(cand)
        if expected_build_id && actual_id && expected_build_id != actual_id
          warnings << "#{role} binary #{meta_path} on disk has build_id #{actual_id[0, 12]} (metadata.json recorded #{expected_build_id[0, 12]}); edge IDs may not align"
        end
        return { bin: cand, build_id: actual_id, source: "metadata" }
      end
      warnings << "#{role} binary from metadata.json (#{meta_path}) is missing/not executable; falling back to local discovery"
    end

    fallback_bin, = fallback_proc.call
    if fallback_bin && !fallback_bin.empty? && File.file?(fallback_bin) && File.executable?(fallback_bin)
      actual_id = binary_build_id(fallback_bin)
      if expected_build_id && actual_id && expected_build_id != actual_id
        warnings << "Fallback #{role} binary #{normalize_repo_path(fallback_bin)} build_id differs from metadata.json (#{actual_id[0, 12]} != #{expected_build_id[0, 12]})"
      end
      return { bin: fallback_bin, build_id: actual_id, source: "fallback" }
    end

    { bin: nil, build_id: nil, source: "unavailable", reason: "reference binary not found under #{File.join(File.dirname(triage_dir), 'bin')} or ./build" }
  end

  def clusters_report_compatible?(report, metadata_path, options)
    return false unless report.is_a?(Hash) && report["clusters"].is_a?(Array) && report["algorithm"].is_a?(Hash)

    algo = report["algorithm"]
    tol = FuzzClustering::TIE_EPSILON

    return false if options[:threshold] && (algo["threshold"].to_f - options[:threshold]).abs > tol
    return false if options[:diff_threshold] && (algo["diff_threshold"].to_f - options[:diff_threshold]).abs > tol
    return false if options[:reason_weight] && (algo["reason_weight"].to_f - options[:reason_weight]).abs > tol

    if options[:include_unreproducible] && report.dig("summary", "excluded_unreproducible").to_i.positive?
      return false
    end

    true
  end

  def load_triage_state(options)
    triage_dir = options[:triage_dir]
    metadata_path = options[:metadata_path] || File.join(triage_dir, "metadata.json")
    unless File.file?(metadata_path)
      raise ConfigError, "Metadata file not found: #{metadata_path} (run make fuzz-triage or pass --triage-dir/--metadata)"
    end

    begin
      metadata = JSON.parse(File.read(metadata_path))
    rescue JSON::ParserError => e
      raise ConfigError, "Invalid JSON in #{metadata_path}: #{e.message}"
    end
    raise ConfigError, "Invalid metadata.json structure in #{metadata_path}" unless metadata.is_a?(Hash) && metadata["buckets"].is_a?(Array)

    clusters_path = options[:clusters_file] || File.join(triage_dir, "clusters.json")
    if options[:clusters_file] && !File.file?(clusters_path)
      raise ConfigError, "Specified --clusters-file not found: #{clusters_path}"
    end

    report = nil
    clusters_source = nil
    if File.file?(clusters_path) && (options[:clusters_file] || File.mtime(clusters_path) >= File.mtime(metadata_path))
      begin
        parsed = JSON.parse(File.read(clusters_path))
        if clusters_report_compatible?(parsed, metadata_path, options)
          report = parsed
          clusters_source = clusters_path
        end
      rescue JSON::ParserError => e
        raise ConfigError, "Invalid JSON in #{clusters_path}: #{e.message}" if options[:clusters_file]
      end
    end

    if report
      algo = report["algorithm"]
      threshold = options[:threshold] || algo["threshold"] || FuzzClustering::DEFAULT_THRESHOLD
      diff_threshold = options[:diff_threshold] || algo["diff_threshold"]
      reason_weight = options[:reason_weight] || algo["reason_weight"] || FuzzClustering::DEFAULT_REASON_WEIGHT
      ctx_opts = {
        idf_smoothing: algo["idf_smoothing"] || FuzzClustering::IDF_SMOOTHING,
        frame_decay: algo["frame_decay"] || FuzzClustering::FRAME_DECAY,
        frame_blend: algo["frame_blend_weight"] || FuzzClustering::FRAME_BLEND_WEIGHT,
        mismatch_penalty: algo["frame_mismatch_penalty"] || FuzzClustering::FRAME_MISMATCH_PENALTY,
        setup_weight: algo["setup_function_weight"] || FuzzClustering::SETUP_FUNCTION_WEIGHT,
        encoding_weight: algo["encoding_helper_weight"] || FuzzClustering::ENCODING_HELPER_WEIGHT,
        recovery_weight: algo["recovery_function_weight"] || FuzzClustering::RECOVERY_FUNCTION_WEIGHT,
        dispatcher_weight: algo["dispatcher_weight"] || FuzzClustering::DISPATCHER_WEIGHT,
        function_edge_cap: algo["function_edge_cap"] || FuzzClustering::FUNCTION_EDGE_CAP,
        diff_conflict_scale: algo["diff_conflict_scale"] || FuzzClustering::DIFF_CONFLICT_SCALE,
        diff_match_boost: algo["diff_match_boost"] || FuzzClustering::DIFF_MATCH_BOOST
      }
    else
      threshold = options[:threshold] || FuzzClustering::DEFAULT_THRESHOLD
      diff_threshold = options[:diff_threshold]
      reason_weight = options[:reason_weight] || FuzzClustering::DEFAULT_REASON_WEIGHT
      ctx_opts = {}
      report = FuzzClustering.cluster_metadata(
        metadata,
        threshold: threshold,
        diff_threshold: diff_threshold,
        reason_weight: reason_weight,
        include_unreproducible: options[:include_unreproducible],
        metadata_path: metadata_path
      )
      clusters_source = "computed-in-memory"
    end

    placement_ctx = FuzzClustering.prepare_placement_context(
      metadata,
      report: report,
      threshold: threshold,
      diff_threshold: diff_threshold,
      reason_weight: reason_weight,
      include_unreproducible: options[:include_unreproducible],
      metadata_path: metadata_path,
      **ctx_opts
    )

    warnings = []
    root = repo_root_dir
    ref_cov = resolve_reference_binary(
      role: "coverage",
      override_bin: options[:coverage_bin],
      metadata_ref: metadata["reference_binary"],
      fallback_proc: -> { resolve_coverage_target(triage_dir: triage_dir, coverage_bin: options[:coverage_bin]) },
      root: root,
      warnings: warnings,
      triage_dir: triage_dir
    )
    ref_diff_cov = resolve_reference_binary(
      role: "diff_coverage",
      override_bin: options[:diff_coverage_bin],
      metadata_ref: metadata["diff_reference_binary"],
      fallback_proc: -> { resolve_diff_coverage_target(triage_dir: triage_dir, diff_coverage_bin: options[:diff_coverage_bin], coverage_bin: options[:coverage_bin]) },
      root: root,
      warnings: warnings,
      triage_dir: triage_dir
    )

    {
      metadata_path: metadata_path,
      metadata: metadata,
      clusters_source: clusters_source,
      report: report,
      placement_ctx: placement_ctx,
      ref_cov: ref_cov,
      ref_diff_cov: ref_diff_cov,
      warnings: warnings
    }
  rescue ArgumentError => e
    raise ConfigError, e.message
  end

  def execute_fuzzer_once(fuzzer, probe_path)
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    Thread.current[:last_testcase_signal] = nil
    raw_output, crashed, timed_out = run_testcase(fuzzer[:path], probe_path)
    duration_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000.0).round(2)

    clean_output = utf8_safe(raw_output)
    if clean_output.include?("Exec format error") || clean_output.include?("cannot execute binary file")
      raise ConfigError, "Cannot execute #{fuzzer[:path]} on this host architecture (run via `make fuzz-match` inside the prism/fuzz container)"
    end

    sig_name = crashed ? Thread.current[:last_testcase_signal] : nil
    reason = if crashed
               infer_crash_reason(clean_output, sig_name, default_reason: "unknown")
             elsif timed_out
               "hang"
             end
    parsed = (crashed || timed_out) ? parse_crash_output(clean_output) : nil
    headline = parsed&.dig("symptom", "headline")

    {
      name: fuzzer[:name],
      path: fuzzer[:path],
      status: crashed ? "crash" : (timed_out ? "timeout" : "pass"),
      crashed: crashed,
      timed_out: timed_out,
      reason: reason,
      headline: headline,
      clean_output: clean_output,
      duration_ms: duration_ms
    }
  rescue Errno::ENOEXEC => e
    raise ConfigError, "Cannot execute #{fuzzer[:path]} (#{e.message}; run via `make fuzz-match` inside the prism/fuzz container)"
  rescue Errno::ENOENT => e
    raise ConfigError, "Failed to invoke fuzzer #{fuzzer[:path]} (#{e.message})"
  end

  # Probes fuzzers in priority order for a single prepared input.
  # Mirrors triage.rb's classify_crash_execution promotion rule: when fuzz.diff
  # crashes without INVARIANT[diff_parse_y] (e.g. a signal in Prism before or
  # alongside parse.y), probe fast `fuzz` so Prism crashes deduplicate cleanly.
  def probe_fuzzers_for_input(probe, fuzzers, all_fuzzers:, explicit_bins:)
    attempts = []
    attempted_paths = {}
    findings = []
    fuzz_entry = fuzzers.find { |f| f[:name] == "fuzz" }

    run_and_record = lambda do |f|
      real = File.realpath(f[:path])
      return attempted_paths[real] if attempted_paths.key?(real)

      res = execute_fuzzer_once(f, probe[:probe_path])
      attempted_paths[real] = res
      attempts << res
      res
    end

    fuzzers.each do |fuzzer|
      res = run_and_record.call(fuzzer)
      next unless res[:crashed] || res[:timed_out]

      effective = res
      if !explicit_bins && fuzzer[:name] == "fuzz.diff" && res[:crashed] && !res[:clean_output].include?("INVARIANT[diff_parse_y]") && fuzz_entry
        fast_res = run_and_record.call(fuzz_entry)
        effective = fast_res if fast_res[:crashed] || fast_res[:timed_out]
      end

      findings << effective unless findings.any? { |seen| seen.equal?(effective) }
      break unless all_fuzzers
    end

    { attempts: attempts, findings: findings }
  end

  def sig_lines_for_reason(reason)
    case reason
    when "undefined-behavior" then 3
    when "ABRT" then 15
    when "use-of-uninitialized-value" then 5
    when "heap-use-after-free" then 7
    when "stack-use-after-return" then 50
    else 10
    end
  end

  def build_probe_bucket_stub(probe, finding, finding_index)
    reason = finding[:reason] || "unknown"
    sig = testcase_output_signature(finding[:clean_output], sig_lines_for_reason(reason))
    bucket_id = finding_index.zero? ? "probe:#{probe[:index] + 1}:#{probe[:label]}" : "probe:#{probe[:index] + 1}.#{finding_index + 1}:#{probe[:label]}"

    build_bucket_metadata(
      bucket_id: bucket_id,
      reason: reason,
      signature: sig,
      reproducible: true,
      timed_out: finding[:timed_out],
      executable: finding[:path],
      crash_output: finding[:clean_output],
      minimized_input: probe[:probe_path],
      raw_size_bytes: probe[:wire_size_bytes],
      raw_sha256: probe[:raw_sha256],
      minimized_matches_signature: true,
      occurrences: { "count" => 1 },
      coverage: nil
    )
  end

  def attach_batch_coverage(finding_entries, ref_binary, showmap_path, field_key:, warnings:)
    return if finding_entries.empty?

    if ref_binary[:bin].nil?
      reason = ref_binary[:reason] || "reference binary unavailable"
      finding_entries.each { |e| e[:bucket][field_key] = { "available" => false, "reason" => reason } }
      return
    end

    if showmap_path.nil?
      reason = "#{AFL_SHOWMAP_BIN} not found in PATH"
      warnings << "#{reason}; falling back to stack-frame / symptom similarity" unless warnings.include?("#{reason}; falling back to stack-frame / symptom similarity")
      finding_entries.each { |e| e[:bucket][field_key] = { "available" => false, "reason" => reason } }
      return
    end

    # Unique input path per probe index so afl-showmap runs once per unique input
    by_probe_path = {}
    finding_entries.each { |e| by_probe_path[e[:probe][:probe_path]] ||= e[:probe][:probe_path] }

    batch = collect_showmap_batch(by_probe_path, ref_binary[:bin], showmap_path)
    norm_bin = normalize_repo_path(ref_binary[:bin])
    if batch[:ok]
      finding_entries.each do |e|
        edges = batch[:maps][e[:probe][:probe_path]]
        e[:bucket][field_key] = if edges
                                  {
                                    "available" => true,
                                    "binary" => norm_bin,
                                    "build_id" => ref_binary[:build_id],
                                    "edge_count" => edges.size,
                                    "edges" => edges
                                  }
                                else
                                  {
                                    "available" => false,
                                    "binary" => norm_bin,
                                    "build_id" => ref_binary[:build_id],
                                    "reason" => "no coverage map produced"
                                  }
                                end
      end
    else
      warnings << "#{field_key} collection failed (#{batch[:reason]}); falling back to stack-frame similarity"
      finding_entries.each do |e|
        e[:bucket][field_key] = {
          "available" => false,
          "binary" => norm_bin,
          "build_id" => ref_binary[:build_id],
          "reason" => batch[:reason]
        }
      end
    end
  end

  def excerpt_lines(text, limit: 12)
    lines = text.to_s.lines.map(&:rstrip).reject(&:empty?)
    return [] if lines.empty?

    lines.first(limit)
  end

  def run(argv)
    options = parse_options(argv)
    triage_state = load_triage_state(options)
    fuzzers = resolve_fuzzers(options)
    header_bytes = build_probe_header(options)
    showmap_path = find_executable_in_path(AFL_SHOWMAP_BIN)
    warnings = triage_state[:warnings].dup

    stdin_cache = {}
    probe_records = []

    Dir.mktmpdir("fuzz-match-") do |tmp_dir|
      options[:inputs].each_with_index do |spec, idx|
        probe = prepare_probe_input(spec, idx, options, tmp_dir, header_bytes, stdin_cache)
        exec_res = probe_fuzzers_for_input(
          probe,
          fuzzers,
          all_fuzzers: options[:all_fuzzers],
          explicit_bins: !options[:bins].empty?
        )
        finding_entries = exec_res[:findings].each_with_index.map do |finding, f_idx|
          {
            probe: probe,
            finding: finding,
            bucket: build_probe_bucket_stub(probe, finding, f_idx)
          }
        end
        probe_records << { probe: probe, attempts: exec_res[:attempts], finding_entries: finding_entries }
      end

      all_entries = probe_records.flat_map { |r| r[:finding_entries] }
      diff_entries = all_entries.select { |e| diff_parse_y_invariant_meta?(e[:bucket]) }

      attach_batch_coverage(all_entries, triage_state[:ref_cov], showmap_path, field_key: "coverage", warnings: warnings)
      attach_batch_coverage(diff_entries, triage_state[:ref_diff_cov], showmap_path, field_key: "diff_coverage", warnings: warnings)
    end

    expect_patterns = options[:expect_clusters]
    expect_active = !expect_patterns.empty?
    clusters_by_id = if expect_active
                       triage_state[:report]["clusters"].each_with_object({}) { |c, h| h[c["cluster_id"]] = c }
                     else
                       {}
                     end

    results = probe_records.map do |rec|
      probe = rec[:probe]
      attempts_json = rec[:attempts].map do |a|
        {
          "binary" => normalize_repo_path(a[:path]),
          "name" => a[:name],
          "status" => a[:status],
          "reason" => a[:reason],
          "headline" => a[:headline],
          "duration_ms" => a[:duration_ms]
        }
      end

      evaluated_findings = rec[:finding_entries].map do |entry|
        bucket = entry[:bucket]
        finding = entry[:finding]
        placement = FuzzClustering.place_probe(
          triage_state[:metadata],
          bucket,
          placement_ctx: triage_state[:placement_ctx],
          top_n: options[:top]
        )

        matched_expected = if expect_active
                             placement["matched_clusters"].any? do |cl|
                               full_cl = clusters_by_id[cl["cluster_id"]] || cl
                               FuzzClustering.cluster_matches_pattern?(full_cl, expect_patterns)
                             end
                           end

        {
          "binary" => normalize_repo_path(finding[:path]),
          "name" => finding[:name],
          "status" => finding[:status],
          "reason" => bucket["reason"],
          "signature" => bucket["signature"],
          "verify_profile" => bucket["verify_profile"],
          "headline" => bucket.dig("symptom", "headline"),
          "loupe_url" => bucket.dig("input", "loupe_url"),
          "coverage_available" => bucket.dig("coverage", "available") == true,
          "diff_coverage_available" => bucket.dig("diff_coverage", "available") == true,
          "placement" => placement,
          "matched_expected" => matched_expected,
          "output_excerpt" => excerpt_lines(finding[:clean_output], limit: options[:verbose] ? 30 : 8)
        }
      end

      input_status = if evaluated_findings.empty?
                       "pass"
                     elsif evaluated_findings.any? { |f| f.dig("placement", "status") == "matched" }
                       "matched"
                     else
                       "unmatched"
                     end
      input_expected_match = expect_active ? evaluated_findings.any? { |f| f["matched_expected"] } : nil

      dec = probe[:decoded_header]
      header_hex = Array(dec[:header_bytes]).map { |b| format("%02x", b) }.join
      {
        "label" => probe[:label],
        "kind" => probe[:kind],
        "mode" => probe[:mode],
        "source_size_bytes" => probe[:source_size_bytes],
        "wire_size_bytes" => probe[:wire_size_bytes],
        "sha256" => probe[:raw_sha256],
        "header" => {
          "hex" => header_hex,
          "valid" => dec[:valid_header],
          "ruby_version" => dec[:version],
          "encoding" => dec[:encoding],
          "start_line" => dec[:start_line],
          "frozen_string_literal" => dec[:has_frozen_string_literal] ? dec[:frozen_string_literal] : nil,
          "partial_script" => dec[:partial_script],
          "stream_mode" => dec[:stream_mode],
          "command_line_flags" => dec[:command_line_chars],
          "forwarding_flags" => dec[:forwarding_chars]
        },
        "status" => input_status,
        "suspected_duplicate" => input_status == "matched",
        "expected_match" => input_expected_match,
        "attempts" => attempts_json,
        "findings" => evaluated_findings
      }
    end

    passed_count = results.count { |r| r["status"] == "pass" }
    matched_count = results.count { |r| r["status"] == "matched" }
    unmatched_count = results.count { |r| r["status"] == "unmatched" }
    crashed_count = matched_count + unmatched_count
    expected_matched_count = expect_active ? results.count { |r| r["expected_match"] } : nil
    expected_passed = expect_active ? results.all? { |r| r["expected_match"] } : nil

    payload = {
      "schema_version" => 1,
      "generated_at" => Time.now.utc.iso8601,
      "triage_dir" => normalize_repo_path(options[:triage_dir]),
      "metadata_path" => normalize_repo_path(triage_state[:metadata_path]),
      "clusters_source" => triage_state[:clusters_source] == "computed-in-memory" ? "computed-in-memory" : normalize_repo_path(triage_state[:clusters_source]),
      "warnings" => warnings,
      "options" => {
        "all_fuzzers" => options[:all_fuzzers],
        "threshold" => triage_state[:placement_ctx][:threshold],
        "diff_threshold" => triage_state[:placement_ctx][:diff_threshold],
        "include_unreproducible" => options[:include_unreproducible],
        "top" => options[:top]
      },
      "reference_binaries" => {
        "coverage" => format_ref_meta(triage_state[:ref_cov], showmap_path),
        "diff_coverage" => format_ref_meta(triage_state[:ref_diff_cov], showmap_path)
      },
      "fuzzers" => fuzzers.map { |f| { "name" => f[:name], "path" => normalize_repo_path(f[:path]) } },
      "expected_clusters" => expect_patterns,
      "summary" => {
        "total_inputs" => results.size,
        "passed_inputs" => passed_count,
        "crashed_inputs" => crashed_count,
        "matched_inputs" => matched_count,
        "unmatched_inputs" => unmatched_count,
        "expected_matched_inputs" => expected_matched_count,
        "expected_passed" => expected_passed
      },
      "results" => results
    }

    if options[:json_path]
      write_json_atomic(options[:json_path], payload)
    end

    if options[:json_stdout]
      puts JSON.pretty_generate(payload)
    else
      render_text_report(payload, options)
    end

    exit_code = if expect_active
                  expected_passed ? 0 : 1
                else
                  0
                end
    [exit_code, payload]
  end

  def format_ref_meta(ref_binary, showmap_path)
    {
      "available" => !ref_binary[:bin].nil? && !showmap_path.nil?,
      "path" => ref_binary[:bin] ? normalize_repo_path(ref_binary[:bin]) : nil,
      "build_id" => ref_binary[:build_id],
      "source" => ref_binary[:source],
      "reason" => ref_binary[:reason] || (showmap_path.nil? ? "#{AFL_SHOWMAP_BIN} not found" : nil)
    }
  end

  def format_header_summary(header)
    parts = ["Ruby #{header['ruby_version'] || '?'}"]
    parts << (header["encoding"] || "start_line=#{header['start_line']}")
    parts << "fsl=#{header['frozen_string_literal']}" unless header["frozen_string_literal"].nil?
    parts << "partial" if header["partial_script"]
    parts << "stream" if header["stream_mode"]
    flags = Array(header["command_line_flags"])
    parts << "cmd=#{flags.join}" unless flags.empty?
    "#{parts.join(', ')}, header=#{header['hex']}"
  end

  def render_text_report(payload, options)
    warnings = payload["warnings"]
    unless warnings.empty?
      warnings.each { |w| warn "WARNING: #{w}" }
    end

    results = payload["results"]
    total = results.size
    expect_patterns = payload["expected_clusters"]
    expect_active = !expect_patterns.empty?

    if options[:quiet]
      results.each do |r|
        verdict = case r["status"]
                  when "pass"
                    "PASS"
                  when "matched"
                    best = r["findings"].filter_map { |f| f.dig("placement", "best_cluster") }.max_by { |c| c["avg_similarity"] }
                    format("MATCH %s (avg=%.3f, rep=%.3f)", best["cluster_id"], best["avg_similarity"], best["rep_similarity"])
                  else
                    top_cand = r["findings"].filter_map { |f| f.dig("placement", "candidates", 0) }.max_by { |c| c["avg_similarity"] }
                    top_cand ? format("NEW (nearest=%s avg=%.3f < %.3f)", top_cand["cluster_id"], top_cand["avg_similarity"], top_cand["threshold_used"]) : "NEW"
                  end
        expect_tag = if expect_active
                       r["expected_match"] ? " [expect: PASS]" : " [expect: FAIL]"
                     else
                       ""
                     end
        puts "#{r['label']}: #{verdict}#{expect_tag}"
      end
      return
    end

    cluster_total = payload["summary"]
    puts "Triage: #{payload['metadata_path']} (clusters: #{payload['clusters_source']})"
    fuzz_names = payload["fuzzers"].map { |f| f["name"] }.join(" -> ")
    puts "Fuzzers: #{fuzz_names}#{payload.dig('options', 'all_fuzzers') ? ' (all-fuzzers)' : ' (stop on first crash)'}"

    results.each_with_index do |r, idx|
      puts ""
      puts "[#{idx + 1}/#{total}] #{r['label']} (#{r['mode']}, #{r['wire_size_bytes']} B, #{format_header_summary(r['header'])})"

      attempt_str = r["attempts"].map do |a|
        tag = a["status"].upcase
        detail = a["reason"] ? "#{a['reason']}, #{a['duration_ms']}ms" : "#{a['duration_ms']}ms"
        "#{a['name']} #{tag} (#{detail})"
      end.join(" | ")
      puts "  fuzzers: #{attempt_str}"

      if r["findings"].empty?
        puts "  verdict: PASS (no crash or timeout)"
        puts "  expect:  FAIL (expected #{expect_patterns.join(', ')}, input did not crash)" if expect_active
        next
      end

      r["findings"].each do |f|
        placement = f["placement"]
        probe_info = placement["probe"]
        cov_tag = if probe_info["oracle"] == "diff_parse_y"
                    f["diff_coverage_available"] ? "dual-cov" : "fallback-cov"
                  else
                    f["coverage_available"] ? "prism-cov" : "no-cov"
                  end
        puts "  finding: [#{f['name']}] #{probe_info['group']}/#{probe_info['oracle']} reason=#{f['reason']} (#{cov_tag})"
        puts "  headline: #{f['headline']}" if f["headline"] && !f["headline"].empty?
        raw_diffs = probe_info["diff_fields"]
        diff_parts = if raw_diffs.is_a?(Hash)
                       raw_diffs.map { |k, v| "#{k}=#{v}" }
                     else
                       Array(raw_diffs)
                     end
        puts "  diff:    #{diff_parts.join(', ')}" unless diff_parts.empty?
        puts "  loupe:   #{f['loupe_url']}" if options[:verbose] && f["loupe_url"]

        if options[:verbose] && !f["output_excerpt"].empty?
          puts "  stderr:"
          f["output_excerpt"].each { |line| puts "    #{line}" }
        end

        if placement["status"] == "matched"
          best = placement["best_cluster"]
          rep_id = best.dig("representative", "bucket_id")
          puts format(
            "  MATCHED: %s (avg=%.3f >= %.3f, rep=%.3f, max=%.3f, buckets=%d, occ=%d, rep=%s)",
            best["cluster_id"],
            best["avg_similarity"],
            best["threshold_used"],
            best["rep_similarity"],
            best["max_similarity"],
            best["bucket_count"],
            best["occurrences"],
            rep_id || "-"
          )
          extra = placement["matched_clusters"].drop(1)
          unless extra.empty?
            extra_str = extra.map { |c| format("%s (avg=%.3f)", c["cluster_id"], c["avg_similarity"]) }.join(", ")
            puts "  also matched: #{extra_str}"
          end
        else
          puts format("  UNMATCHED: no existing %s cluster reached threshold %.3f (potential new issue)", probe_info["oracle"], probe_info["threshold_used"])
        end

        cands = placement["candidates"]
        if cands.empty?
          puts "  candidates: (none in oracle=#{probe_info['oracle']})"
        elsif options[:verbose] || placement["status"] == "unmatched" || cands.size > 1
          limit = options[:verbose] ? cands.size : [cands.size, [options[:top], 3].max].min
          puts "  candidates (top #{limit}):"
          cands.first(limit).each_with_index do |c, c_idx|
            rep_b = c["representative"] || {}
            mark = c["matched"] ? "*" : " "
            puts format(
              "   %s %d. %-10s avg=%.3f rep=%.3f max=%.3f (thresh=%.3f, buckets=%d, occ=%d) rep=%s",
              mark,
              c_idx + 1,
              c["cluster_id"],
              c["avg_similarity"],
              c["rep_similarity"],
              c["max_similarity"],
              c["threshold_used"],
              c["bucket_count"],
              c["occurrences"],
              rep_b["bucket_id"] || "-"
            )
            if options[:verbose] && rep_b["headline"] && !rep_b["headline"].empty?
              puts "         #{rep_b['headline']}"
            end
          end
        end
      end

      if expect_active
        got = r["findings"].flat_map { |f| f.dig("placement", "matched_clusters").map { |c| c["cluster_id"] } }.uniq
        if r["expected_match"]
          puts "  expect:  PASS (matched #{expect_patterns.join(', ')}; matched clusters: #{got.join(', ')})"
        else
          puts "  expect:  FAIL (expected #{expect_patterns.join(', ')}, got #{got.empty? ? 'UNMATCHED' : got.join(', ')})"
        end
      end
    end

    puts ""
    s = cluster_total
    summary_line = "Summary: #{s['total_inputs']} input(s) — #{s['matched_inputs']} matched, #{s['unmatched_inputs']} unmatched, #{s['passed_inputs']} passed"
    if expect_active
      summary_line += "; expect #{expect_patterns.join(',')}: #{s['expected_passed'] ? 'PASS' : 'FAIL'} (#{s['expected_matched_inputs']}/#{s['total_inputs']})"
    end
    puts summary_line
  end
end

if __FILE__ == $PROGRAM_NAME
  begin
    exit_code, = FuzzMatcher.run(ARGV)
    exit(exit_code)
  rescue FuzzMatcher::ConfigError => e
    warn "match.rb: #{e.message}"
    exit 2
  end
end
