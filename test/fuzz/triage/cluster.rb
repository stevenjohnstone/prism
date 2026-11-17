#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "json"
require "optparse"
require "time"

# Clusters crash triage buckets in metadata.json into root-cause groups without
# re-executing testcases or scraping raw bucket files.
#
# Similarity combines Weighted Jaccard edge coverage (linear in Laplace-smoothed
# corpus IDF), leaf-anchored Prism call frames, and soft crash-reason agreement
# via UPGMA (average-linkage) clustering cut at a calibrated fixed threshold.
# See test/fuzz/triage/clustering.md for the derivation and calibration.
module FuzzClustering
  SCHEMA_VERSION = 1
  DEFAULT_METADATA_PATH = "tmp/fuzz/triage/metadata.json"
  DEFAULT_OUTPUT_PATH = "tmp/fuzz/triage/clusters.json"

  DEFAULT_THRESHOLD = 0.225
  DEFAULT_REASON_WEIGHT = 0.10
  IDF_SMOOTHING = 5.0
  FRAME_DECAY = 0.5
  FRAME_BLEND_WEIGHT = 0.75
  FRAME_MISMATCH_PENALTY = 0.50
  SETUP_FUNCTION_WEIGHT = 0.0
  ENCODING_HELPER_WEIGHT = 0.25
  RECOVERY_FUNCTION_WEIGHT = 0.10
  DISPATCHER_WEIGHT = 0.5
  FUNCTION_EDGE_CAP = 150.0
  DIFF_CONFLICT_SCALE = 0.35
  DIFF_MATCH_BOOST = 0.15
  TIE_EPSILON = 1e-12

  # Algorithm 2 (differential parse.y divergences) uses dual-parser PCGUARD
  # coverage from fuzz.diff split into Prism and CRuby parse.y edge domains.
  DIFF_DEFAULT_THRESHOLD = 0.25
  DIFF_ENCODING_HELPER_WEIGHT = 0.25
  DIFF_IDENTIFIER_HELPER_WEIGHT = 0.15
  DIFF_LEXER_DISPATCHER_WEIGHT = 0.35
  DIFF_PRISM_DISPATCHER_WEIGHT = 0.50
  DIFF_FUNCTION_EDGE_CAP = 400.0
  DIFF_LOCALS_MISMATCH_PENALTY = 0.65
  DIFF_CRUBY_CLASS_MISMATCH_PENALTY = 0.50
  DIFF_DIAGNOSTIC_MATCH_BOOST = 0.10

  # Generated AST/diagnostic reflection tables and harness wrappers carry no
  # root-cause signal when comparing stack traces or edge vectors.
  VISITOR_FUNCTIONS = %w[
    pm_visit_node
    pm_visit_child_nodes
    pm_node_type
    pm_diagnostic_type
    pm_diagnostic_error_level
    pm_diagnostic_warning_level
  ].freeze

  BOILERPLATE_PREFIXES = %w[
    fuzz_
    check_
    pm_visit_
  ].freeze

  BOILERPLATE_FUNCTIONS = (%w[
    fuzz_invariant_fail
    fuzz_loc_in_bounds
    fuzz_span_violation_kind
    fuzz_heredoc_span_contains
    fuzz_line_offset_context
    fuzz_line_offset_visit
    fuzz_shebang_cb
    fuzz_stream_fgets
    fuzz_stream_feof
    check_node_location
    fuzz_check_sub_location
    fuzz_check_node_sub_locations
    check_diagnostic_locations
    check_comment_locations
    harness_parse
    harness
    LLVMFuzzerTestOneInput
    pm_token_str
    context_human
  ] + VISITOR_FUNCTIONS).freeze

  # Parser option initialization and encoding lookup execute identically for any
  # input with the same 4-byte fuzzer option header before parsing syntax.
  SETUP_FUNCTIONS = %w[
    pm_parser_init
    pm_parser_init_shebang
    pm_encoding_find
    pm_strncasecmp
  ].freeze

  # Encoding character-width helpers run across every lexed token under non-UTF-8
  # fuzz options; downweighting prevents unrelated bugs sharing e.g. ASCII-8BIT
  # from aliasing while keeping residual signal for encoding-specific parser paths.
  ENCODING_HELPER_FUNCTIONS = %w[
    pm_encoding_char_width
    pm_encoding_cesu_8_char_width
    pm_encoding_utf_8_char_width
    pm_encoding_property_char
  ].freeze

  # Generic parser syntax-error recovery/diagnostic helpers appear across
  # unrelated syntax bugs yet can be rare in afl-cmin corpora. Soft downweighting
  # suppresses cross-bug attraction while preserving signal if a bug lives inside them.
  RECOVERY_FUNCTIONS = %w[
    context_recoverable
    pm_error_recovery_node_new
    pm_error_recovery_node_create
    pm_error_recovery_node_create_unexpected
    pm_parse_err_is_fatal
    pm_diagnostic_list_append
  ].freeze

  # Monolithic parser/lexer dispatch loops account for a disproportionate share of
  # uncovered edges across distinct syntax bugs entering or exiting parsing.
  DISPATCHER_FUNCTIONS = %w[
    parser_lex
    parse_expression
    pm_parse
  ].freeze

  # Generic catch-all diagnostics shared by unrelated syntax discrepancies should
  # not boost similarity when comparing diff_parse_y symptoms.
  GENERIC_DIFF_ERRORS = %w[
    expect_eol_after_statement
    unexpected_token_ignore
    unexpected_token_close_context
    regexp_parse_error
    SyntaxError:other
  ].freeze

  # Boilerplate prefixes and functions excluded in Algorithm 2 (differential
  # fuzz.diff coverage): fuzzing runtime, diff comparator harness, Prism/CRuby
  # parser drivers, AST allocators/visitors, and Bison error-line formatters
  # that fire identically across unrelated diff_parse_y divergences.
  DIFF_BOILERPLATE_PREFIXES = %w[
    __sanitizer
    __afl
    asan.
    msan.
    ubsan.
    lsan.
    sancov.
    LLVMFuzzer
    diff_
    pm_arena_
    pm_buffer_
    pm_constant_
    pm_node_list_
    pm_list_
    pm_string_
  ].freeze

  DIFF_BOILERPLATE_FUNCTIONS = %w[
    LLVMFuzzerTestOneInput
    main
    pm_parser_init
    pm_parser_new
    pm_parser_free
    pm_parse
    pm_parse_stream
    pm_serialize_parse
    pm_parse_success_p
    pm_line_offset_list_init
    pm_line_offset_list_free
    pm_line_offset_list_append
    pm_options_new
    pm_options_free
    pm_options_version_set
    pm_options_version_parse
    pm_program_node_new
    pm_statements_node_new
    pm_statements_node_body_append
    pm_void_statement_check
    pm_void_statement_check_unwrap
    flush_block_exits
    pm_locals_order
    pm_parser_scope_push
    pm_diagnostic_type
    pm_diagnostic_list_append
    pm_diagnostic_list_append_format
    pm_parse_err_is_fatal
    pm_parser_errors_size
    pm_parser_errors_first
    pm_visit_child_nodes
    pm_node_destroy
    pm_node_type
    pm_token_type
    pm_token_str
    pm_parser_constant
    pm_parser_local_add
    pm_locals_find
    yycompile0
    rb_parser_compile_string
    rb_parser_parse_string
    rb_ruby_parser_new
    rb_parser_compile
    rb_ruby_parser_set_context
    rb_str_to_parser_string
    init_block_exit
    clear_block_exit
    nextline
    newtok
    nextc0
    pushback
    tokadd_mbchar
    local_push
    local_pop
    local_free
    lvar_defined
    dyna_push
    dyna_pop
    dyna_pop_1
    parser_add_delayed_token
    parser_dispatch_delayed_token
    parser_dispatch_scan_event
    void_stmts
    void_expr
    block_append
    rb_node_scope_new
    rb_node_scope_new2
    ruby_show_error_line
    rb_yytnamerr
    yysyntax_error
    parser_compile_error
    parser_yyerror
    parser_yyerror0
    yydestruct
    yy_symbol_value_print
    yy_symbol_print
    token_info_warn
  ].freeze

  DIFF_IDENTIFIER_FUNCTIONS = %w[
    parse_ident
    dvar_defined
    rb_parser_dvar_defined_ref
    dvar_curr
    local_id
    local_id_ref
  ].freeze

  DIFF_LEXER_DISPATCHERS = %w[
    parser_lex
    parser_yylex
  ].freeze

  DIFF_PRISM_DISPATCHERS = %w[
    parse_expression
    parse_statements
  ].freeze

  # Signal handlers, libc abort wrappers, and CRuby VM entry trampolines carry
  # no root-cause signal when comparing external CRuby parse.y crash traces.
  EXTERNAL_FRAME_BOILERPLATE = %w[
    rb_print_backtrace
    rb_vm_bugreport
    rb_bug_for_fatal_signal
    rb_bug
    sigsegv
    sigbus
    sigill
    sigfpe
    diff_fatal_signal_handler
    __kernel_rt_sigreturn
    __pthread_kill_implementation
    raise
    abort
    invoke_bf
    vm_invoke_builtin_delegate
    vm_exec_core
    rb_vm_exec
    vm_call0_cc
    rb_funcallv_scope
    rb_funcallv
    rb_funcall
    rb_protect
    __libc_start_main
    _start
  ].freeze

  module_function

  def write_json_atomic(path, payload)
    dir = File.dirname(path)
    FileUtils.mkdir_p(dir)
    tmp = File.join(dir, ".#{File.basename(path)}.tmp.#{Process.pid}.#{Thread.current.object_id}")
    File.write(tmp, "#{JSON.pretty_generate(payload)}\n")
    File.rename(tmp, path)
  ensure
    File.delete(tmp) if tmp && File.exist?(tmp)
  end

  def boilerplate_function?(func_name)
    name = func_name.to_s
    BOILERPLATE_FUNCTIONS.include?(name) ||
      BOILERPLATE_PREFIXES.any? { |prefix| name.start_with?(prefix) }
  end

  def prism_frame?(frame)
    frame.is_a?(Hash) &&
      frame["scope"] == "prism" &&
      !frame["func"].to_s.empty? &&
      !boilerplate_function?(frame["func"])
  end

  def external_crash_frame?(frame)
    frame.is_a?(Hash) &&
      frame["scope"] == "external" &&
      !frame["func"].to_s.empty? &&
      !boilerplate_function?(frame["func"]) &&
      !EXTERNAL_FRAME_BOILERPLATE.include?(frame["func"])
  end

  def function_weight_multiplier(
    func_name,
    setup_weight: SETUP_FUNCTION_WEIGHT,
    encoding_weight: ENCODING_HELPER_WEIGHT,
    recovery_weight: RECOVERY_FUNCTION_WEIGHT,
    dispatcher_weight: DISPATCHER_WEIGHT,
    fn_edge_count: 0,
    function_edge_cap: FUNCTION_EDGE_CAP
  )
    base =
      if boilerplate_function?(func_name)
        0.0
      elsif SETUP_FUNCTIONS.include?(func_name)
        setup_weight
      elsif ENCODING_HELPER_FUNCTIONS.include?(func_name)
        encoding_weight
      elsif RECOVERY_FUNCTIONS.include?(func_name)
        recovery_weight
      else
        1.0
      end
    return 0.0 if base <= 0.0

    mult = base
    mult *= dispatcher_weight if DISPATCHER_FUNCTIONS.include?(func_name)
    if function_edge_cap && function_edge_cap > 0.0 && fn_edge_count > function_edge_cap
      mult *= Math.sqrt(function_edge_cap / fn_edge_count.to_f)
    end
    mult
  end

  def diff_boilerplate_function?(func_name, domain: nil)
    return true if domain == "harness"

    name = func_name.to_s
    DIFF_BOILERPLATE_FUNCTIONS.include?(name) ||
      DIFF_BOILERPLATE_PREFIXES.any? { |prefix| name.start_with?(prefix) }
  end

  def diff_function_weight_multiplier(
    func_name,
    domain: nil,
    fn_edge_count: 0,
    function_edge_cap: DIFF_FUNCTION_EDGE_CAP
  )
    return 0.0 if diff_boilerplate_function?(func_name, domain: domain)

    name = func_name.to_s
    mult =
      if name.start_with?("pm_encoding_")
        DIFF_ENCODING_HELPER_WEIGHT
      elsif DIFF_IDENTIFIER_FUNCTIONS.include?(name)
        DIFF_IDENTIFIER_HELPER_WEIGHT
      elsif DIFF_LEXER_DISPATCHERS.include?(name)
        DIFF_LEXER_DISPATCHER_WEIGHT
      elsif DIFF_PRISM_DISPATCHERS.include?(name)
        DIFF_PRISM_DISPATCHER_WEIGHT
      else
        1.0
      end
    if function_edge_cap && function_edge_cap > 0.0 && fn_edge_count > function_edge_cap
      mult *= Math.sqrt(function_edge_cap / fn_edge_count.to_f)
    end
    mult
  end

  def build_diff_edge_idf(
    diff_corpus,
    smoothing: IDF_SMOOTHING,
    function_edge_cap: DIFF_FUNCTION_EDGE_CAP
  )
    unless diff_corpus.is_a?(Hash) && diff_corpus["available"] == true
      return { enabled: false, prism_idf: {}, parse_y_idf: {}, pooled_idf: {}, edge_domains: {}, edge_functions: {} }
    end

    corpus_count = diff_corpus["corpus_count"].to_f
    unless corpus_count > 0.0
      return { enabled: false, prism_idf: {}, parse_y_idf: {}, pooled_idf: {}, edge_domains: {}, edge_functions: {} }
    end

    edge_df = diff_corpus["edge_df"].is_a?(Hash) ? diff_corpus["edge_df"] : {}
    edge_functions = diff_corpus["edge_functions"].is_a?(Hash) ? diff_corpus["edge_functions"] : {}
    edge_domains = diff_corpus["edge_domains"].is_a?(Hash) ? diff_corpus["edge_domains"] : {}

    if edge_functions.empty?
      return {
        enabled: true,
        prism_idf: {},
        parse_y_idf: {},
        pooled_idf: {},
        edge_domains: edge_domains,
        edge_functions: edge_functions,
        unmapped_fallback: true,
        corpus_count: corpus_count,
        smoothing: smoothing
      }
    end

    fn_counts = Hash.new(0)
    edge_functions.each do |edge_id, fn|
      dom = edge_domains[edge_id]
      fn_counts[[dom, fn]] += 1
    end

    prism_idf = {}
    parse_y_idf = {}
    pooled_idf = {}
    has_domains = !edge_domains.empty?

    edge_functions.each do |edge_id, func_name|
      dom = edge_domains[edge_id]
      mult = diff_function_weight_multiplier(
        func_name,
        domain: dom,
        fn_edge_count: fn_counts[[dom, func_name]],
        function_edge_cap: function_edge_cap
      )
      next if mult <= 0.0

      df = edge_df[edge_id].to_f
      raw = Math.log((corpus_count + smoothing) / (df + smoothing))
      w = raw * mult
      next unless w > 0.0

      if has_domains
        if dom == "prism"
          prism_idf[edge_id] = w
        elsif dom == "parse_y"
          parse_y_idf[edge_id] = w
        end
      else
        pooled_idf[edge_id] = w
      end
    end

    {
      enabled: true,
      prism_idf: prism_idf,
      parse_y_idf: parse_y_idf,
      pooled_idf: pooled_idf,
      edge_domains: edge_domains,
      edge_functions: edge_functions,
      has_domains: has_domains,
      unmapped_fallback: false,
      corpus_count: corpus_count,
      smoothing: smoothing
    }
  end

  def build_edge_idf(
    corpus,
    smoothing: IDF_SMOOTHING,
    setup_weight: SETUP_FUNCTION_WEIGHT,
    encoding_weight: ENCODING_HELPER_WEIGHT,
    recovery_weight: RECOVERY_FUNCTION_WEIGHT,
    dispatcher_weight: DISPATCHER_WEIGHT,
    function_edge_cap: FUNCTION_EDGE_CAP
  )
    return { enabled: false, idf: {}, edge_functions: {} } unless corpus.is_a?(Hash) && corpus["available"] == true

    corpus_count = corpus["corpus_count"].to_f
    return { enabled: false, idf: {}, edge_functions: {} } unless corpus_count > 0.0

    edge_df = corpus["edge_df"].is_a?(Hash) ? corpus["edge_df"] : {}
    edge_functions = corpus["edge_functions"].is_a?(Hash) ? corpus["edge_functions"] : {}
    idf = {}

    if edge_functions.empty?
      return {
        enabled: true,
        idf: idf,
        edge_functions: edge_functions,
        unmapped_fallback: true,
        corpus_count: corpus_count,
        smoothing: smoothing
      }
    end

    fn_counts = Hash.new(0)
    edge_functions.each_value { |fn| fn_counts[fn] += 1 }

    edge_functions.each do |edge_id, func_name|
      mult = function_weight_multiplier(
        func_name,
        setup_weight: setup_weight,
        encoding_weight: encoding_weight,
        recovery_weight: recovery_weight,
        dispatcher_weight: dispatcher_weight,
        fn_edge_count: fn_counts[func_name],
        function_edge_cap: function_edge_cap
      )
      next if mult <= 0.0

      df = edge_df[edge_id].to_f
      raw = Math.log((corpus_count + smoothing) / (df + smoothing))
      idf[edge_id] = raw * mult if raw > 0.0
    end

    {
      enabled: true,
      idf: idf,
      edge_functions: edge_functions,
      unmapped_fallback: false,
      corpus_count: corpus_count,
      smoothing: smoothing
    }
  end

  def extract_frame_vector(frames, frame_decay: FRAME_DECAY, oracle: nil)
    raw_frames = Array(frames)
    prism_frames = raw_frames.select { |f| prism_frame?(f) }
    used_frames =
      if !prism_frames.empty?
        prism_frames
      elsif oracle == "cruby_crash"
        raw_frames.select { |f| external_crash_frame?(f) }
      else
        []
      end

    vec = {}
    used_frames.each_with_index do |frame, depth|
      file = frame["file"].to_s
      file = "" if file == "(null)"
      key = file.empty? ? frame["func"].to_s : "#{frame['func']}@#{file}"
      vec[key] ||= frame_decay**depth
    end

    top_frame = if prism_frames.empty?
      nil
    else
      top = prism_frames.first
      line_suffix = top["line"] ? ":#{top['line']}" : ""
      "#{top['func']}@#{top['file']}#{line_suffix}"
    end

    [vec, vec.values.sum { |w| w * w }, top_frame]
  end

  def extract_coverage_vector(bucket, cov_model, corpus_edge_df)
    cov = bucket["coverage"]
    available = cov_model[:enabled] && cov.is_a?(Hash) && cov["available"] == true && cov["edges"].is_a?(Hash)
    return [{}, 0.0, false] unless available

    edges = cov["edges"]
    vec = {}

    if cov_model[:unmapped_fallback]
      n = cov_model[:corpus_count]
      smoothing = cov_model[:smoothing] || IDF_SMOOTHING
      edges.each_key do |edge_id|
        df = corpus_edge_df[edge_id].to_f
        raw = Math.log((n + smoothing) / (df + smoothing))
        # Store sqrt(weight) so dot products and Tanimoto denominators stay linear in IDF weight.
        vec[edge_id] = Math.sqrt(raw) if raw > 0.0
      end
    else
      idf = cov_model[:idf]
      edges.each_key do |edge_id|
        w = idf[edge_id]
        vec[edge_id] = Math.sqrt(w) if w && w > 0.0
      end
    end

    [vec, vec.values.sum { |w| w * w }, true]
  end

  def extract_diff_coverage_vectors(bucket, diff_cov_model, diff_corpus_edge_df)
    empty = [{}, 0.0, 0.0, {}, 0.0, 0.0, {}, 0.0, 0.0, false]
    cov = bucket["diff_coverage"]
    available = diff_cov_model[:enabled] && cov.is_a?(Hash) && cov["available"] == true && cov["edges"].is_a?(Hash)
    return empty unless available

    edges = cov["edges"]
    prism_vec = {}
    parse_y_vec = {}
    pooled_vec = {}
    prism_sum = 0.0
    prism_norm2 = 0.0
    parse_y_sum = 0.0
    parse_y_norm2 = 0.0
    pooled_sum = 0.0
    pooled_norm2 = 0.0

    if diff_cov_model[:unmapped_fallback]
      n = diff_cov_model[:corpus_count]
      smoothing = diff_cov_model[:smoothing] || IDF_SMOOTHING
      edges.each_key do |edge_id|
        df = diff_corpus_edge_df[edge_id].to_f
        raw = Math.log((n + smoothing) / (df + smoothing))
        next unless raw > 0.0

        pooled_vec[edge_id] = raw
        pooled_sum += raw
        pooled_norm2 += raw * raw
      end
    elsif diff_cov_model[:has_domains]
      p_idf = diff_cov_model[:prism_idf]
      y_idf = diff_cov_model[:parse_y_idf]
      edges.each_key do |edge_id|
        if (pw = p_idf[edge_id]) && pw > 0.0
          prism_vec[edge_id] = pw
          prism_sum += pw
          prism_norm2 += pw * pw
        elsif (yw = y_idf[edge_id]) && yw > 0.0
          parse_y_vec[edge_id] = yw
          parse_y_sum += yw
          parse_y_norm2 += yw * yw
        end
      end
    else
      pool_idf = diff_cov_model[:pooled_idf]
      edges.each_key do |edge_id|
        w = pool_idf[edge_id]
        next unless w && w > 0.0

        pooled_vec[edge_id] = w
        pooled_sum += w
        pooled_norm2 += w * w
      end
    end

    [
      prism_vec, prism_sum, prism_norm2,
      parse_y_vec, parse_y_sum, parse_y_norm2,
      pooled_vec, pooled_sum, pooled_norm2,
      true
    ]
  end

  def oracle_family(bucket)
    ns = bucket.dig("symptom", "invariant", "namespace").to_s
    headline = bucket.dig("symptom", "headline").to_s
    if ns == "diff_parse_y" || headline.start_with?("INVARIANT[diff_parse_y]:")
      "diff_parse_y"
    elsif ns == "stream_diff" || headline.start_with?("INVARIANT[stream_diff]:")
      "stream_diff"
    elsif bucket["verify_profile"].to_s == "diff_parse_y" || headline.start_with?("CRASH[diff_parse_y]:")
      has_prism = Array(bucket["frames"]).any? { |f| prism_frame?(f) }
      has_prism ? "crash_or_inv" : "cruby_crash"
    else
      "crash_or_inv"
    end
  end

  def extract_diff_fields(bucket)
    inv = bucket.dig("symptom", "invariant")
    return nil unless inv.is_a?(Hash) && inv["namespace"] == "diff_parse_y"

    fields = inv["fields"]
    fields.is_a?(Hash) ? fields : nil
  end

  def parse_afl_time_ms(name_or_path)
    return nil if name_or_path.nil?

    m = File.basename(name_or_path.to_s).match(/(?:\A|,)time:(\d+)(?:,|\z)/)
    m ? m[1].to_i : nil
  end

  def timestamp_sort_key(iso_str)
    return [1, Float::INFINITY, ""] if iso_str.nil? || iso_str.empty?

    [0, Time.iso8601(iso_str).to_f, iso_str]
  rescue ArgumentError
    [0, Float::INFINITY, iso_str]
  end

  # Returns non-negative elapsed milliseconds between two ISO-8601 timestamps,
  # or nil when either timestamp is missing or unparseable.
  def elapsed_ms_between(first_seen, baseline_seen)
    return nil if first_seen.to_s.empty? || baseline_seen.to_s.empty?

    [((Time.iso8601(first_seen) - Time.iso8601(baseline_seen)) * 1000.0).round, 0].max
  rescue ArgumentError
    nil
  end

  # Populates first_elapsed_ms from first_seen - baseline_seen when ,time:<ms>
  # is absent (e.g. crashes imported via AFL++ sync:main).
  def with_fallback_elapsed_ms(entry, baseline_seen)
    return entry unless entry["first_elapsed_ms"].nil?

    fallback_ms = elapsed_ms_between(entry["first_seen"], baseline_seen)
    return entry if fallback_ms.nil?

    entry.merge("first_elapsed_ms" => fallback_ms)
  end

  def extract_bucket_timestamps(bucket)
    occ = bucket["occurrences"].is_a?(Hash) ? bucket["occurrences"] : {}
    first_seen_str = occ["first_seen"].to_s.strip
    first_seen = first_seen_str.empty? ? nil : first_seen_str
    last_seen_str = occ["last_seen"].to_s.strip
    last_seen = last_seen_str.empty? ? nil : last_seen_str

    raw_elapsed = occ["first_elapsed_ms"]
    first_elapsed_ms = raw_elapsed.nil? ? nil : raw_elapsed.to_i
    if first_elapsed_ms.nil? && occ["sample_crashes"].is_a?(Array)
      candidates = occ["sample_crashes"].filter_map do |sample|
        next unless sample.is_a?(Hash)

        t_ms = sample["time_ms"] || parse_afl_time_ms(sample["filename"] || sample["path"])
        next unless t_ms

        [timestamp_sort_key(sample["mtime"].to_s.strip), t_ms.to_i]
      end
      best = candidates.min_by { |ts_key, ms| [ts_key, ms] }
      if best && (first_seen.nil? || best[0][0] == 1 || (best[0] <=> timestamp_sort_key(first_seen)) <= 0)
        first_elapsed_ms = best[1]
      end
    end

    [first_seen, last_seen, first_elapsed_ms]
  end

  def build_bucket_feature(
    bucket,
    cov_model,
    corpus_edge_df,
    diff_cov_model = nil,
    diff_corpus_edge_df = {},
    frame_decay: FRAME_DECAY
  )
    oracle = oracle_family(bucket)
    cov_vec, cov_norm2, cov_available = extract_coverage_vector(bucket, cov_model, corpus_edge_df)
    diff_vecs = if oracle == "diff_parse_y" && diff_cov_model
                  extract_diff_coverage_vectors(bucket, diff_cov_model, diff_corpus_edge_df)
                else
                  [{}, 0.0, 0.0, {}, 0.0, 0.0, {}, 0.0, 0.0, false]
                end
    dp_vec, dp_sum, dp_norm2, dy_vec, dy_sum, dy_norm2, dpool_vec, dpool_sum, dpool_norm2, diff_cov_available = diff_vecs
    frame_vec, frame_norm2, top_frame = extract_frame_vector(
      bucket["frames"],
      frame_decay: frame_decay,
      oracle: oracle
    )
    occ = bucket.dig("occurrences", "count").to_i
    first_seen, last_seen, first_elapsed_ms = extract_bucket_timestamps(bucket)
    min_size = bucket.dig("input", "min_size_bytes")
    versions = bucket["versions"].is_a?(Hash) && !bucket["versions"].empty? ? bucket["versions"] : nil

    {
      id: bucket["bucket_id"].to_s,
      reason: bucket["reason"].to_s,
      signature: bucket["signature"].to_s,
      oracle: oracle,
      diff_fields: extract_diff_fields(bucket),
      occurrences: occ,
      first_seen: first_seen,
      first_elapsed_ms: first_elapsed_ms,
      last_seen: last_seen,
      min_size_bytes: min_size,
      versions: versions,
      headline: bucket.dig("symptom", "headline").to_s,
      cov_vec: cov_vec,
      cov_norm2: cov_norm2,
      cov_available: cov_available,
      diff_cov_available: diff_cov_available,
      diff_has_domains: !!(diff_cov_model && diff_cov_model[:has_domains]),
      diff_prism_vec: dp_vec,
      diff_prism_sum: dp_sum,
      diff_prism_norm2: dp_norm2,
      diff_parse_y_vec: dy_vec,
      diff_parse_y_sum: dy_sum,
      diff_parse_y_norm2: dy_norm2,
      diff_pooled_vec: dpool_vec,
      diff_pooled_sum: dpool_sum,
      diff_pooled_norm2: dpool_norm2,
      frame_vec: frame_vec,
      frame_norm2: frame_norm2,
      top_prism_frame: top_frame
    }
  end

  def sparse_dot(va, vb)
    return 0.0 if va.empty? || vb.empty?

    small, large = va.size <= vb.size ? [va, vb] : [vb, va]
    sum = 0.0
    small.each do |k, w|
      other = large[k]
      sum += w * other if other
    end
    sum
  end

  def coverage_similarity(a, b)
    return 0.0 unless a[:cov_available] && b[:cov_available]

    na2 = a[:cov_norm2]
    nb2 = b[:cov_norm2]
    return 0.0 if na2 <= 0.0 || nb2 <= 0.0

    dot = sparse_dot(a[:cov_vec], b[:cov_vec])
    return 0.0 if dot <= 0.0

    # Because entries are sqrt(w_e), Tanimoto reduces to Weighted Jaccard: sum(min/shared w_e) / sum(union w_e).
    denom = na2 + nb2 - dot
    return 0.0 if denom <= 0.0

    val = dot / denom
    val > 1.0 ? 1.0 : val
  end

  def frame_similarity(a, b)
    na2 = a[:frame_norm2]
    nb2 = b[:frame_norm2]
    return nil if na2 <= 0.0 || nb2 <= 0.0

    dot = sparse_dot(a[:frame_vec], b[:frame_vec])
    return 0.0 if dot <= 0.0

    val = dot / Math.sqrt(na2 * nb2)
    val > 1.0 ? 1.0 : val
  end

  def conflict_field?(val_a, val_b)
    sa = val_a.to_s
    sb = val_b.to_s
    !sa.empty? && !sb.empty? && sa != sb
  end

  def normalize_diff_field(key, value)
    return nil if value.nil?

    str = value.to_s
    return nil if str.empty?
    return nil if %w[prism cruby].include?(key) && str == "ok"

    str
  end

  def generic_diff_error?(key, value)
    %w[prism cruby].include?(key) && GENERIC_DIFF_ERRORS.include?(value)
  end

  def diff_symptom_similarity(
    evidence,
    fields_a,
    fields_b,
    conflict_scale: DIFF_CONFLICT_SCALE,
    match_boost: DIFF_MATCH_BOOST
  )
    return evidence unless fields_a.is_a?(Hash) && fields_b.is_a?(Hash)

    if conflict_field?(fields_a["sub"], fields_b["sub"]) ||
       conflict_field?(fields_a["kind"], fields_b["kind"])
      return evidence * conflict_scale
    end

    mismatch = false
    specific_match = false
    %w[prism cruby node scope].each do |key|
      va = normalize_diff_field(key, fields_a[key])
      vb = normalize_diff_field(key, fields_b[key])
      next unless va && vb

      if va != vb
        mismatch = true
      elsif !generic_diff_error?(key, va)
        specific_match = true
      end
    end

    if specific_match && !mismatch
      [1.0, (1.0 - match_boost) * evidence + match_boost].min
    elsif mismatch
      evidence * conflict_scale
    else
      evidence
    end
  end

  def weighted_jaccard_and_cosine(va, sa, na2, vb, sb, nb2)
    return [0.0, 0.0] if va.empty? || vb.empty? || sa <= 0.0 || sb <= 0.0

    small, large = va.size <= vb.size ? [va, vb] : [vb, va]
    inter_w = 0.0
    inter_w2 = 0.0
    small.each do |k, w|
      next unless large.key?(k)

      inter_w += w
      inter_w2 += w * w
    end
    return [0.0, 0.0] if inter_w <= 0.0

    j_denom = sa + sb - inter_w
    j = j_denom > 0.0 ? [1.0, inter_w / j_denom].min : 0.0
    c_denom = Math.sqrt(na2 * nb2)
    cos = c_denom > 0.0 ? [1.0, inter_w2 / c_denom].min : 0.0
    [j, cos]
  end

  def diff_mismatch_class(fields)
    return "ast" unless fields.is_a?(Hash)

    kind = fields["kind"].to_s
    if kind == "syntax_mismatch"
      "syntax_mismatch:#{fields['sub']}"
    else
      "ast"
    end
  end

  def cruby_error_exception_class(val)
    s = val.to_s
    return nil if s.empty? || s == "ok"

    s.split(":", 2).first
  end

  def diff_parse_y_dual_similarity(
    a,
    b,
    locals_penalty: DIFF_LOCALS_MISMATCH_PENALTY,
    cruby_class_penalty: DIFF_CRUBY_CLASS_MISMATCH_PENALTY,
    diag_boost: DIFF_DIAGNOSTIC_MATCH_BOOST
  )
    fa = a[:diff_fields]
    fb = b[:diff_fields]
    cls_a = diff_mismatch_class(fa)
    cls_b = diff_mismatch_class(fb)
    return 0.0 if cls_a != cls_b

    sim =
      if a[:diff_has_domains] && b[:diff_has_domains]
        jp, cp = weighted_jaccard_and_cosine(
          a[:diff_prism_vec], a[:diff_prism_sum], a[:diff_prism_norm2],
          b[:diff_prism_vec], b[:diff_prism_sum], b[:diff_prism_norm2]
        )
        jy, cy = weighted_jaccard_and_cosine(
          a[:diff_parse_y_vec], a[:diff_parse_y_sum], a[:diff_parse_y_norm2],
          b[:diff_parse_y_vec], b[:diff_parse_y_sum], b[:diff_parse_y_norm2]
        )
        0.5 * Math.sqrt(jp * jy) + 0.5 * Math.sqrt(cp * cy)
      else
        jpool, cpool = weighted_jaccard_and_cosine(
          a[:diff_pooled_vec], a[:diff_pooled_sum], a[:diff_pooled_norm2],
          b[:diff_pooled_vec], b[:diff_pooled_sum], b[:diff_pooled_norm2]
        )
        0.5 * jpool + 0.5 * cpool
      end

    if cls_a == "ast"
      loc_a = fa.is_a?(Hash) && fa["kind"] == "locals_count_mismatch"
      loc_b = fb.is_a?(Hash) && fb["kind"] == "locals_count_mismatch"
      sim *= locals_penalty if loc_a != loc_b
    elsif fa.is_a?(Hash) && fb.is_a?(Hash)
      if fa["sub"] == "prism_ok_cruby_err"
        va = normalize_diff_field("cruby", fa["cruby"])
        vb = normalize_diff_field("cruby", fb["cruby"])
        if va && vb
          ca = cruby_error_exception_class(va)
          cb = cruby_error_exception_class(vb)
          if ca != cb
            sim *= cruby_class_penalty
          elsif va == vb && !generic_diff_error?("cruby", va) && sim > 0.05
            sim = [1.0, (1.0 - diag_boost) * sim + diag_boost].min
          end
        end
      elsif fa["sub"] == "prism_err_cruby_ok"
        va = normalize_diff_field("prism", fa["prism"])
        vb = normalize_diff_field("prism", fb["prism"])
        if va && vb && va == vb && !generic_diff_error?("prism", va) && sim > 0.05
          sim = [1.0, (1.0 - diag_boost) * sim + diag_boost].min
        end
      end
    end

    sim
  end

  def pair_similarity(
    a,
    b,
    reason_weight: DEFAULT_REASON_WEIGHT,
    frame_blend: FRAME_BLEND_WEIGHT,
    mismatch_penalty: FRAME_MISMATCH_PENALTY,
    diff_conflict_scale: DIFF_CONFLICT_SCALE,
    diff_match_boost: DIFF_MATCH_BOOST
  )
    # Never mix buckets from distinct verification oracles (crash/invariant vs diff_parse_y vs stream_diff).
    return 0.0 if a[:oracle] && b[:oracle] && a[:oracle] != b[:oracle]

    if a[:oracle] == "diff_parse_y" && a[:diff_cov_available] && b[:diff_cov_available]
      return diff_parse_y_dual_similarity(a, b)
    end

    has_fa = a[:frame_norm2] > 0.0
    has_fb = b[:frame_norm2] > 0.0
    cov_both = a[:cov_available] && b[:cov_available]
    scov = cov_both ? coverage_similarity(a, b) : 0.0

    evidence =
      if has_fa && has_fb
        sfrm = frame_similarity(a, b)
        cov_both ? (frame_blend * sfrm + (1.0 - frame_blend) * scov) : sfrm
      elsif !has_fa && !has_fb
        diff_symptom_similarity(
          scov,
          a[:diff_fields],
          b[:diff_fields],
          conflict_scale: diff_conflict_scale,
          match_boost: diff_match_boost
        )
      else
        mismatch_penalty * scov
      end

    same_reason = !a[:reason].empty? && a[:reason] == b[:reason] ? 1.0 : 0.0
    ((1.0 - reason_weight) * evidence) + (reason_weight * same_reason)
  end

  def compute_similarity_matrix(features, **sim_opts)
    n = features.size
    mat = Array.new(n) { Array.new(n, 0.0) }
    (0...n).each do |i|
      mat[i][i] = 1.0
      (i + 1...n).each do |j|
        s = pair_similarity(features[i], features[j], **sim_opts)
        mat[i][j] = s
        mat[j][i] = s
      end
    end
    mat
  end

  def best_upgma_merge(active, pair_sum, features, threshold: DEFAULT_THRESHOLD, diff_threshold: DIFF_DEFAULT_THRESHOLD)
    best = nil

    (0...active.size).each do |i|
      ci = active[i]
      uid_i = ci[:uid]
      size_i = ci[:members].size
      row_i = pair_sum[uid_i]

      (i + 1...active.size).each do |j|
        cj = active[j]
        next if ci[:oracle] && cj[:oracle] && ci[:oracle] != cj[:oracle]

        avg_sim = row_i[cj[:uid]] / (size_i * cj[:members].size).to_f
        pair_thresh = (ci[:diff_dual] && cj[:diff_dual]) ? diff_threshold : threshold
        next if avg_sim < pair_thresh

        pair_key = ci[:canon] <= cj[:canon] ? [ci[:canon], cj[:canon]] : [cj[:canon], ci[:canon]]

        if best.nil? ||
           avg_sim > best[:sim] + TIE_EPSILON ||
           ((avg_sim - best[:sim]).abs <= TIE_EPSILON && (pair_key <=> best[:pair_key]) < 0)
          best = { i: i, j: j, sim: avg_sim, pair_key: pair_key }
        end
      end
    end

    best
  end

  def representative_sort_key(feature)
    [
      -feature[:occurrences],
      feature[:min_size_bytes].nil? ? Float::INFINITY : feature[:min_size_bytes],
      feature[:id]
    ]
  end

  def summarize_versions_entries(features)
    prism_seen = {}
    ruby_seen = {}
    container_seen = {}
    fuzz_seen = {}
    triage_seen = {}

    features.each do |f|
      v = f[:versions]
      next unless v.is_a?(Hash)

      pv = v["prism"]
      if pv.is_a?(Hash) && !pv.empty?
        key = [pv["version"], pv["target_ruby_version"], pv["git_commit"], pv["git_short"], pv["git_dirty"]]
        prism_seen[key] ||= pv
      end

      rv = v["ruby_parse_y"]
      if rv.is_a?(Hash) && !rv.empty?
        key = [rv["version"], rv["revision"], rv["release_date"], rv["description"], rv["oracle_dir"]]
        ruby_seen[key] ||= rv
      end

      cv = v["container"]
      if cv.is_a?(Hash) && !cv.empty?
        key = [cv["image_id"], cv["os"], cv["arch"], cv["clang"], cv["aflplusplus"], cv["ruby"]]
        container_seen[key] ||= cv
      end

      fv = v["fuzz"]
      if fv.is_a?(Hash) && !fv.empty?
        key = [fv["binary"], fv["build_id"], fv["snapshot_dir"], fv["prism"], fv["ruby_parse_y"]]
        fuzz_seen[key] ||= fv
      end

      tv = v["triage"]
      if tv.is_a?(Hash) && !tv.empty?
        key = [tv["binary"], tv["build_id"], tv["coverage_binary"], tv["prism"], tv["workspace_git"]]
        triage_seen[key] ||= tv
      end
    end

    out = {}
    out["prism"] = prism_seen.values.sort_by { |p| [p["version"].to_s, p["git_commit"].to_s, p["target_ruby_version"].to_s] } unless prism_seen.empty?
    out["ruby_parse_y"] = ruby_seen.values.sort_by { |r| [r["version"].to_s, r["revision"].to_s] } unless ruby_seen.empty?
    out["container"] = container_seen.values.sort_by { |c| [c["os"].to_s, c["arch"].to_s, c["image_id"].to_s] } unless container_seen.empty?
    out["fuzz"] = fuzz_seen.values.sort_by { |x| [x["binary"].to_s, x["build_id"].to_s] } unless fuzz_seen.empty?
    out["triage"] = triage_seen.values.sort_by { |x| [x["binary"].to_s, x["build_id"].to_s] } unless triage_seen.empty?
    out.empty? ? nil : out
  end

  def format_bucket_entry(feature)
    entry = {
      "bucket_id" => feature[:id],
      "reason" => feature[:reason],
      "signature" => feature[:signature],
      "occurrences" => feature[:occurrences],
      "first_seen" => feature[:first_seen],
      "first_elapsed_ms" => feature[:first_elapsed_ms],
      "last_seen" => feature[:last_seen],
      "min_size_bytes" => feature[:min_size_bytes],
      "headline" => feature[:headline],
      "top_prism_frame" => feature[:top_prism_frame]
    }
    entry["versions"] = feature[:versions] if feature[:versions]
    entry
  end

  def cluster_mean_similarity(members, sim_matrix)
    return 1.0 if members.size <= 1

    total = 0.0
    pairs = 0
    members.each_with_index do |a, i|
      ((i + 1)...members.size).each do |j|
        total += sim_matrix[a][members[j]]
        pairs += 1
      end
    end
    total / pairs.to_f
  end

  def cluster_group_for_oracle(oracle)
    case oracle
    when "diff_parse_y" then "diff_parse_y"
    when "cruby_crash" then "cruby_crash"
    else "prism_flaw"
    end
  end

  def summarize_group_counts(clusters_json)
    summary = {}
    [
      ["prism_flaws", "prism_flaw"],
      ["cruby_crashes", "cruby_crash"],
      ["diff_parse_y", "diff_parse_y"]
    ].each do |key, group_val|
      grp = clusters_json.select { |c| c["group"] == group_val }
      next if grp.empty? && key == "cruby_crashes"

      summary[key] = {
        "cluster_count" => grp.size,
        "bucket_count" => grp.sum { |c| c["bucket_count"].to_i },
        "occurrences" => grp.sum { |c| c["occurrences"].to_i },
        "singleton_clusters" => grp.count { |c| c["bucket_count"] == 1 }
      }
    end
    summary
  end

  def effective_thresholds(threshold: DEFAULT_THRESHOLD, diff_threshold: nil, reason_weight: DEFAULT_REASON_WEIGHT)
    raise ArgumentError, "threshold must be between 0.0 and 1.0" unless threshold >= 0.0 && threshold <= 1.0
    raise ArgumentError, "reason_weight must be between 0.0 and 1.0" unless reason_weight >= 0.0 && reason_weight <= 1.0

    effective_diff = if diff_threshold.nil?
                       (threshold - DEFAULT_THRESHOLD).abs <= TIE_EPSILON ? DIFF_DEFAULT_THRESHOLD : threshold
                     else
                       diff_threshold
                     end
    unless effective_diff >= 0.0 && effective_diff <= 1.0
      raise ArgumentError, "diff_threshold must be between 0.0 and 1.0"
    end

    [threshold, effective_diff]
  end

  def prepare_feature_context(
    metadata,
    idf_smoothing: IDF_SMOOTHING,
    frame_decay: FRAME_DECAY,
    setup_weight: SETUP_FUNCTION_WEIGHT,
    encoding_weight: ENCODING_HELPER_WEIGHT,
    recovery_weight: RECOVERY_FUNCTION_WEIGHT,
    dispatcher_weight: DISPATCHER_WEIGHT,
    function_edge_cap: FUNCTION_EDGE_CAP
  )
    corpus = metadata["corpus"].is_a?(Hash) ? metadata["corpus"] : {}
    corpus_edge_df = corpus["edge_df"].is_a?(Hash) ? corpus["edge_df"] : {}
    cov_model = build_edge_idf(
      corpus,
      smoothing: idf_smoothing,
      setup_weight: setup_weight,
      encoding_weight: encoding_weight,
      recovery_weight: recovery_weight,
      dispatcher_weight: dispatcher_weight,
      function_edge_cap: function_edge_cap
    )

    diff_corpus = metadata["diff_corpus"].is_a?(Hash) ? metadata["diff_corpus"] : {}
    diff_corpus_edge_df = diff_corpus["edge_df"].is_a?(Hash) ? diff_corpus["edge_df"] : {}
    diff_cov_model = build_diff_edge_idf(diff_corpus, smoothing: idf_smoothing)

    {
      corpus: corpus,
      corpus_edge_df: corpus_edge_df,
      cov_model: cov_model,
      diff_corpus: diff_corpus,
      diff_corpus_edge_df: diff_corpus_edge_df,
      diff_cov_model: diff_cov_model,
      frame_decay: frame_decay
    }
  end

  def feature_for_bucket(bucket, feature_ctx)
    build_bucket_feature(
      bucket,
      feature_ctx[:cov_model],
      feature_ctx[:corpus_edge_df],
      feature_ctx[:diff_cov_model],
      feature_ctx[:diff_corpus_edge_df],
      frame_decay: feature_ctx[:frame_decay]
    )
  end

  def cluster_matches_pattern?(cluster, patterns)
    pats = Array(patterns).map { |p| p.to_s.strip }.reject(&:empty?)
    return true if pats.empty?

    cid = cluster["cluster_id"].to_s
    cid_num = cid[/\d+\z/]&.to_i
    members = cluster["buckets"] || []

    pats.any? do |pat|
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

  def prepare_placement_context(
    metadata,
    report: nil,
    threshold: DEFAULT_THRESHOLD,
    diff_threshold: nil,
    reason_weight: DEFAULT_REASON_WEIGHT,
    idf_smoothing: IDF_SMOOTHING,
    frame_decay: FRAME_DECAY,
    frame_blend: FRAME_BLEND_WEIGHT,
    mismatch_penalty: FRAME_MISMATCH_PENALTY,
    setup_weight: SETUP_FUNCTION_WEIGHT,
    encoding_weight: ENCODING_HELPER_WEIGHT,
    recovery_weight: RECOVERY_FUNCTION_WEIGHT,
    dispatcher_weight: DISPATCHER_WEIGHT,
    function_edge_cap: FUNCTION_EDGE_CAP,
    diff_conflict_scale: DIFF_CONFLICT_SCALE,
    diff_match_boost: DIFF_MATCH_BOOST,
    include_unreproducible: false,
    metadata_path: DEFAULT_METADATA_PATH
  )
    eff_thresh, eff_diff_thresh = effective_thresholds(
      threshold: threshold,
      diff_threshold: diff_threshold,
      reason_weight: reason_weight
    )
    feature_ctx = prepare_feature_context(
      metadata,
      idf_smoothing: idf_smoothing,
      frame_decay: frame_decay,
      setup_weight: setup_weight,
      encoding_weight: encoding_weight,
      recovery_weight: recovery_weight,
      dispatcher_weight: dispatcher_weight,
      function_edge_cap: function_edge_cap
    )
    report ||= cluster_metadata(
      metadata,
      threshold: eff_thresh,
      diff_threshold: eff_diff_thresh,
      reason_weight: reason_weight,
      idf_smoothing: idf_smoothing,
      frame_decay: frame_decay,
      frame_blend: frame_blend,
      mismatch_penalty: mismatch_penalty,
      setup_weight: setup_weight,
      encoding_weight: encoding_weight,
      recovery_weight: recovery_weight,
      dispatcher_weight: dispatcher_weight,
      function_edge_cap: function_edge_cap,
      diff_conflict_scale: diff_conflict_scale,
      diff_match_boost: diff_match_boost,
      include_unreproducible: include_unreproducible,
      metadata_path: metadata_path
    )

    features_by_id = {}
    Array(metadata["buckets"]).each do |b|
      next unless b.is_a?(Hash) && b["bucket_id"]

      features_by_id[b["bucket_id"].to_s] = feature_for_bucket(b, feature_ctx)
    end

    {
      report: report,
      feature_ctx: feature_ctx,
      features_by_id: features_by_id,
      threshold: eff_thresh,
      diff_threshold: eff_diff_thresh,
      sim_opts: {
        reason_weight: reason_weight,
        frame_blend: frame_blend,
        mismatch_penalty: mismatch_penalty,
        diff_conflict_scale: diff_conflict_scale,
        diff_match_boost: diff_match_boost
      }
    }
  end

  def place_probe(
    metadata,
    probe_bucket,
    placement_ctx: nil,
    report: nil,
    threshold: DEFAULT_THRESHOLD,
    diff_threshold: nil,
    reason_weight: DEFAULT_REASON_WEIGHT,
    top_n: 5,
    **ctx_opts
  )
    ctx = placement_ctx || prepare_placement_context(
      metadata,
      report: report,
      threshold: threshold,
      diff_threshold: diff_threshold,
      reason_weight: reason_weight,
      **ctx_opts
    )
    probe_feat = feature_for_bucket(probe_bucket, ctx[:feature_ctx])
    features_by_id = ctx[:features_by_id]
    sim_opts = ctx[:sim_opts]

    candidates = []
    ctx[:report]["clusters"].each do |cl|
      m_feats = Array(cl["buckets"]).filter_map { |mb| features_by_id[mb["bucket_id"].to_s] }
      next if m_feats.empty?
      next if probe_feat[:oracle] && m_feats.first[:oracle] && probe_feat[:oracle] != m_feats.first[:oracle]

      cluster_diff_dual = m_feats.all? { |mf| mf[:oracle] == "diff_parse_y" && mf[:diff_cov_available] }
      probe_diff_dual = probe_feat[:oracle] == "diff_parse_y" && probe_feat[:diff_cov_available]
      pair_thresh = (probe_diff_dual && cluster_diff_dual) ? ctx[:diff_threshold] : ctx[:threshold]

      scored_members = m_feats.map { |mf| [pair_similarity(probe_feat, mf, **sim_opts), mf] }
      sims = scored_members.map(&:first)
      avg_sim = sims.sum / sims.size.to_f
      best_member_sim, best_member = scored_members.max_by { |s, mf| [s, -mf[:occurrences], mf[:id]] }
      min_sim = sims.min
      rep_id = cl.dig("representative", "bucket_id").to_s
      rep_feat = features_by_id[rep_id]
      rep_sim = rep_feat ? pair_similarity(probe_feat, rep_feat, **sim_opts) : best_member_sim
      matched = avg_sim >= pair_thresh

      candidates << {
        "cluster_id" => cl["cluster_id"],
        "group" => cl["group"] || cluster_group_for_oracle(probe_feat[:oracle]),
        "algorithm" => cl["algorithm"],
        "matched" => matched,
        "threshold_used" => pair_thresh.round(6),
        "avg_similarity" => avg_sim.round(6),
        "rep_similarity" => rep_sim.round(6),
        "max_similarity" => best_member_sim.round(6),
        "min_similarity" => min_sim.round(6),
        "bucket_count" => cl["bucket_count"],
        "occurrences" => cl["occurrences"],
        "closest_bucket_id" => best_member[:id],
        "representative" => cl["representative"]
      }
    end

    candidates.sort_by! do |c|
      [c["matched"] ? 0 : 1, -c["avg_similarity"], -c["max_similarity"], c["cluster_id"].to_s]
    end
    matched_clusters = candidates.select { |c| c["matched"] }
    shown = top_n && top_n > 0 ? candidates.first(top_n) : candidates

    {
      "status" => matched_clusters.empty? ? "unmatched" : "matched",
      "probe" => {
        "bucket_id" => probe_feat[:id],
        "oracle" => probe_feat[:oracle],
        "group" => cluster_group_for_oracle(probe_feat[:oracle]),
        "reason" => probe_feat[:reason],
        "headline" => probe_feat[:headline],
        "top_prism_frame" => probe_feat[:top_prism_frame],
        "diff_fields" => probe_feat[:diff_fields],
        "cov_available" => probe_feat[:cov_available],
        "diff_cov_available" => probe_feat[:diff_cov_available],
        "threshold_used" => ((probe_feat[:oracle] == "diff_parse_y" && probe_feat[:diff_cov_available]) ? ctx[:diff_threshold] : ctx[:threshold]).round(6)
      },
      "matched_clusters" => matched_clusters,
      "best_cluster" => matched_clusters.first,
      "candidates" => shown
    }
  end

  def cluster_metadata(
    metadata,
    threshold: DEFAULT_THRESHOLD,
    diff_threshold: nil,
    reason_weight: DEFAULT_REASON_WEIGHT,
    idf_smoothing: IDF_SMOOTHING,
    frame_decay: FRAME_DECAY,
    frame_blend: FRAME_BLEND_WEIGHT,
    mismatch_penalty: FRAME_MISMATCH_PENALTY,
    setup_weight: SETUP_FUNCTION_WEIGHT,
    encoding_weight: ENCODING_HELPER_WEIGHT,
    recovery_weight: RECOVERY_FUNCTION_WEIGHT,
    dispatcher_weight: DISPATCHER_WEIGHT,
    function_edge_cap: FUNCTION_EDGE_CAP,
    diff_conflict_scale: DIFF_CONFLICT_SCALE,
    diff_match_boost: DIFF_MATCH_BOOST,
    include_unreproducible: false,
    metadata_path: DEFAULT_METADATA_PATH
  )
    threshold, effective_diff_threshold = effective_thresholds(
      threshold: threshold,
      diff_threshold: diff_threshold,
      reason_weight: reason_weight
    )

    raw_buckets = Array(metadata["buckets"])
    excluded_unreproducible = 0
    filtered = []

    raw_buckets.each do |b|
      next unless b.is_a?(Hash)

      unrepro = b["reason"] == "unreproducible" || b["reproducible"] == false
      if unrepro && !include_unreproducible
        excluded_unreproducible += 1
        next
      end
      filtered << b
    end

    filtered.sort_by! { |b| b["bucket_id"].to_s }

    feature_ctx = prepare_feature_context(
      metadata,
      idf_smoothing: idf_smoothing,
      frame_decay: frame_decay,
      setup_weight: setup_weight,
      encoding_weight: encoding_weight,
      recovery_weight: recovery_weight,
      dispatcher_weight: dispatcher_weight,
      function_edge_cap: function_edge_cap
    )
    corpus = feature_ctx[:corpus]
    diff_corpus = feature_ctx[:diff_corpus]
    diff_cov_model = feature_ctx[:diff_cov_model]

    features = filtered.map { |b| feature_for_bucket(b, feature_ctx) }
    sim_matrix = compute_similarity_matrix(
      features,
      reason_weight: reason_weight,
      frame_blend: frame_blend,
      mismatch_penalty: mismatch_penalty,
      diff_conflict_scale: diff_conflict_scale,
      diff_match_boost: diff_match_boost
    )

    n = features.size
    active = Array.new(n) do |idx|
      f = features[idx]
      {
        uid: idx,
        members: [idx],
        min_merge_sim: 1.0,
        canon: f[:id],
        oracle: f[:oracle],
        diff_dual: f[:oracle] == "diff_parse_y" && f[:diff_cov_available]
      }
    end
    pair_sum = Array.new(n) { |i| sim_matrix[i].dup }

    merge_similarities = []
    while active.size > 1
      best = best_upgma_merge(
        active,
        pair_sum,
        features,
        threshold: threshold,
        diff_threshold: effective_diff_threshold
      )
      break if best.nil?

      merge_similarities << best[:sim]
      ci = active[best[:i]]
      cj = active[best[:j]]
      uid_i = ci[:uid]
      uid_j = cj[:uid]

      ci[:members].concat(cj[:members])
      ci[:min_merge_sim] = [ci[:min_merge_sim], best[:sim]].min
      ci[:canon] = cj[:canon] if cj[:canon] < ci[:canon]
      ci[:diff_dual] = ci[:diff_dual] && cj[:diff_dual]

      active.delete_at(best[:j])
      active.each do |ck|
        uid_k = ck[:uid]
        next if uid_k == uid_i

        combined = pair_sum[uid_i][uid_k] + pair_sum[uid_j][uid_k]
        pair_sum[uid_i][uid_k] = combined
        pair_sum[uid_k][uid_i] = combined
      end
    end

    # Sort finalized clusters deterministically before computing IDs and inter-cluster neighbors,
    # keeping Prism flaws & crashes separate and ahead of differential parse.y divergences.
    built_clusters = active.map do |c|
      member_feats = c[:members].map { |idx| features[idx] }
      rep = member_feats.min_by { |f| representative_sort_key(f) }
      occ = member_feats.sum { |f| f[:occurrences] }
      reasons = Hash.new(0)
      member_feats.each { |f| reasons[f[:reason]] += 1 }
      sorted_members = member_feats.sort_by { |f| [-f[:occurrences], f[:id]] }
      earliest = member_feats
        .select { |f| f[:first_seen] || f[:first_elapsed_ms] }
        .min_by { |f| [timestamp_sort_key(f[:first_seen]), f[:first_elapsed_ms] || Float::INFINITY, f[:id]] }
      latest = member_feats
        .select { |f| f[:last_seen] }
        .max_by { |f| [timestamp_sort_key(f[:last_seen]), f[:id]] }
      group = cluster_group_for_oracle(c[:oracle])
      cluster_algo = if c[:oracle] == "diff_parse_y"
                       c[:diff_dual] ? "diff_parse_y_dual_edge" : "diff_parse_y_legacy"
                     else
                       "prism_flaw"
                     end

      {
        raw_cluster: c,
        group: group,
        cluster_algo: cluster_algo,
        occurrences: occ,
        bucket_count: member_feats.size,
        reasons: reasons.sort.to_h,
        representative: rep,
        first_seen: earliest&.fetch(:first_seen),
        first_elapsed_ms: earliest&.fetch(:first_elapsed_ms),
        first_seen_bucket: earliest&.fetch(:id),
        last_seen: latest&.fetch(:last_seen),
        min_merge_similarity: c[:min_merge_sim],
        mean_pairwise_similarity: cluster_mean_similarity(c[:members], sim_matrix),
        versions: summarize_versions_entries(member_feats),
        buckets: sorted_members.map { |f| format_bucket_entry(f) }
      }
    end

    built_clusters.sort_by! do |entry|
      [entry[:group] == "diff_parse_y" ? 1 : 0, -entry[:occurrences], -entry[:bucket_count], entry[:representative][:id]]
    end

    campaign_first_seen = features
      .filter_map { |f| f[:first_seen] }
      .min_by { |ts| timestamp_sort_key(ts) }
    campaign_last_seen = features
      .filter_map { |f| f[:last_seen] }
      .max_by { |ts| timestamp_sort_key(ts) }

    id_width = [2, built_clusters.size.to_s.length].max
    clusters_json = built_clusters.each_with_index.map do |entry, idx|
      cid = format("cluster-%0*d", id_width, idx + 1)
      entry[:cluster_id] = cid
      buckets_out = entry[:buckets].map { |b| with_fallback_elapsed_ms(b, campaign_first_seen) }
      rep_out = with_fallback_elapsed_ms(format_bucket_entry(entry[:representative]), campaign_first_seen)
      cluster_elapsed_ms = entry[:first_elapsed_ms] || elapsed_ms_between(entry[:first_seen], campaign_first_seen)

      cluster_out = {
        "cluster_id" => cid,
        "group" => entry[:group],
        "algorithm" => entry[:cluster_algo],
        "bucket_count" => entry[:bucket_count],
        "occurrences" => entry[:occurrences],
        "first_seen" => entry[:first_seen],
        "first_elapsed_ms" => cluster_elapsed_ms,
        "first_seen_bucket" => entry[:first_seen_bucket],
        "last_seen" => entry[:last_seen],
        "reasons" => entry[:reasons],
        "representative" => rep_out,
        "min_merge_similarity" => entry[:min_merge_similarity].round(6),
        "mean_pairwise_similarity" => entry[:mean_pairwise_similarity].round(6)
      }
      cluster_out["versions"] = entry[:versions] if entry[:versions]
      cluster_out["buckets"] = buckets_out
      cluster_out
    end

    inter_pairs = []
    (0...built_clusters.size).each do |i|
      ci = built_clusters[i]
      uid_i = ci[:raw_cluster][:uid]
      size_i = ci[:bucket_count]
      ((i + 1)...built_clusters.size).each do |j|
        cj = built_clusters[j]
        avg_sim = pair_sum[uid_i][cj[:raw_cluster][:uid]] / (size_i * cj[:bucket_count]).to_f
        inter_pairs << {
          "cluster_a" => ci[:cluster_id],
          "cluster_b" => cj[:cluster_id],
          "similarity" => avg_sim.round(6)
        }
      end
    end
    inter_pairs.sort_by! { |p| [-p["similarity"], p["cluster_a"], p["cluster_b"]] }

    max_inter = inter_pairs.empty? ? nil : inter_pairs.first["similarity"]
    min_intra = merge_similarities.empty? ? nil : merge_similarities.min.round(6)
    total_occurrences = features.sum { |f| f[:occurrences] }
    diff_dual_buckets = features.count { |f| f[:oracle] == "diff_parse_y" && f[:diff_cov_available] }
    diff_legacy_buckets = features.count { |f| f[:oracle] == "diff_parse_y" && !f[:diff_cov_available] }

    out = {
      "schema_version" => SCHEMA_VERSION,
      "generated_at" => Time.now.utc.iso8601,
      "metadata_path" => metadata_path,
      "algorithm" => {
        "method" => "upgma",
        "coverage_metric" => "weighted_jaccard",
        "threshold" => threshold,
        "diff_threshold" => effective_diff_threshold,
        "reason_weight" => reason_weight,
        "idf_smoothing" => idf_smoothing,
        "frame_decay" => frame_decay,
        "frame_blend_weight" => frame_blend,
        "frame_mismatch_penalty" => mismatch_penalty,
        "setup_function_weight" => setup_weight,
        "encoding_helper_weight" => encoding_weight,
        "recovery_function_weight" => recovery_weight,
        "dispatcher_weight" => dispatcher_weight,
        "function_edge_cap" => function_edge_cap,
        "diff_conflict_scale" => diff_conflict_scale,
        "diff_match_boost" => diff_match_boost,
        "corpus_count" => corpus["corpus_count"].to_i,
        "filtered_boilerplate_functions" => BOILERPLATE_FUNCTIONS,
        "filtered_boilerplate_prefixes" => BOILERPLATE_PREFIXES,
        "filtered_external_frame_boilerplate" => EXTERNAL_FRAME_BOILERPLATE,
        "filtered_setup_functions" => SETUP_FUNCTIONS,
        "downweighted_encoding_functions" => ENCODING_HELPER_FUNCTIONS,
        "downweighted_recovery_functions" => RECOVERY_FUNCTIONS,
        "downweighted_dispatcher_functions" => DISPATCHER_FUNCTIONS,
        "diff_parse_y" => {
          "mode" => diff_dual_buckets > 0 ? "dual_edge_prism_and_parse_y" : "legacy_fallback",
          "edge_metric" => "dual_geom_weighted_jaccard_and_cosine",
          "threshold" => effective_diff_threshold,
          "dual_edge_buckets" => diff_dual_buckets,
          "legacy_fallback_buckets" => diff_legacy_buckets,
          "corpus_count" => diff_corpus["corpus_count"].to_i,
          "has_domains" => !!diff_cov_model[:has_domains],
          "function_edge_cap" => DIFF_FUNCTION_EDGE_CAP,
          "lexer_dispatcher_weight" => DIFF_LEXER_DISPATCHER_WEIGHT,
          "prism_dispatcher_weight" => DIFF_PRISM_DISPATCHER_WEIGHT,
          "identifier_helper_weight" => DIFF_IDENTIFIER_HELPER_WEIGHT,
          "encoding_helper_weight" => DIFF_ENCODING_HELPER_WEIGHT,
          "locals_mismatch_penalty" => DIFF_LOCALS_MISMATCH_PENALTY,
          "cruby_class_mismatch_penalty" => DIFF_CRUBY_CLASS_MISMATCH_PENALTY
        }
      },
      "summary" => {
        "bucket_count" => features.size,
        "excluded_unreproducible" => excluded_unreproducible,
        "cluster_count" => clusters_json.size,
        "total_occurrences" => total_occurrences,
        "singleton_clusters" => clusters_json.count { |c| c["bucket_count"] == 1 },
        "by_group" => summarize_group_counts(clusters_json),
        "first_seen" => campaign_first_seen,
        "last_seen" => campaign_last_seen,
        "min_intra_merge_similarity" => min_intra,
        "max_inter_cluster_similarity" => max_inter,
        "nearest_inter_cluster_pairs" => inter_pairs.first(5)
      },
      "clusters" => clusters_json
    }
    report_versions = metadata["versions"].is_a?(Hash) ? metadata["versions"].dup : {}
    observed_versions = summarize_versions_entries(features)
    report_versions["observed"] = observed_versions if observed_versions && !observed_versions.empty?
    out["versions"] = report_versions unless report_versions.empty?
    out
  end

  def format_first_seen_cell(cluster, campaign_first_seen = nil)
    ms = cluster["first_elapsed_ms"] || elapsed_ms_between(cluster["first_seen"], campaign_first_seen)

    unless ms.nil?
      sec = [(ms.to_f / 1000.0).round, 0].max
      return format("%2dh%02dm%02ds", sec / 3600, (sec % 3600) / 60, sec % 60)
    end

    fs = cluster["first_seen"].to_s
    return fs[/T(\d{2}:\d{2}:\d{2}Z)\z/, 1] || fs[0, 10] unless fs.empty?

    "-"
  end

  def cluster_diff_section?(cluster)
    group = cluster["group"].to_s
    return group == "diff_parse_y" unless group.empty?

    cluster.dig("representative", "headline").to_s.start_with?("INVARIANT[diff_parse_y]:")
  end

  def format_cluster_table_lines(section_clusters, campaign_first_seen, show_first)
    lines = []
    if show_first
      lines << format("%-12s %7s %8s  %-9s  %-26s  %s", "Cluster", "Buckets", "Occur", "First", "Reasons", "Representative")
      lines << ("-" * 111)
    else
      lines << format("%-12s %7s %8s  %-26s  %s", "Cluster", "Buckets", "Occur", "Reasons", "Representative")
      lines << ("-" * 100)
    end

    section_clusters.each do |c|
      reasons_str = c["reasons"].map { |r, n| "#{r}=#{n}" }.join(",")
      rep = c["representative"]
      headline = rep["headline"].to_s.tr("\n", " ")
      headline = "#{headline[0, 52]}..." if headline.length > 55
      lines << if show_first
        format(
          "%-12s %7d %8d  %-9s  %-26s  %s  %s",
          c["cluster_id"],
          c["bucket_count"],
          c["occurrences"],
          format_first_seen_cell(c, campaign_first_seen),
          reasons_str,
          rep["bucket_id"],
          headline
        )
      else
        format(
          "%-12s %7d %8d  %-26s  %s  %s",
          c["cluster_id"],
          c["bucket_count"],
          c["occurrences"],
          reasons_str,
          rep["bucket_id"],
          headline
        )
      end
    end
    lines
  end

  def format_summary_table(report)
    clusters = report["clusters"]
    summary = report["summary"]
    algo = report["algorithm"]
    lines = []

    if clusters.empty?
      lines << "No clusters (0 buckets)."
      return lines.join("\n")
    end

    campaign_first_seen = summary["first_seen"]
    show_first = clusters.any? { |c| c["first_seen"] || !c["first_elapsed_ms"].nil? }
    diff_clusters, flaw_clusters = clusters.partition { |c| cluster_diff_section?(c) }

    if !flaw_clusters.empty? && !diff_clusters.empty?
      flaw_bkts = flaw_clusters.sum { |c| c["bucket_count"].to_i }
      flaw_occ = flaw_clusters.sum { |c| c["occurrences"].to_i }
      lines << "Prism Flaws & Crashes (#{flaw_bkts} buckets, #{flaw_occ} occurrences -> #{flaw_clusters.size} clusters; algorithm=prism_flaw, threshold=#{algo['threshold']}):"
      lines.concat(format_cluster_table_lines(flaw_clusters, campaign_first_seen, show_first))
      lines << ""

      diff_bkts = diff_clusters.sum { |c| c["bucket_count"].to_i }
      diff_occ = diff_clusters.sum { |c| c["occurrences"].to_i }
      diff_algo = algo.dig("diff_parse_y", "mode") || "legacy_fallback"
      diff_dual_active = diff_algo == "dual_edge_prism_and_parse_y"
      diff_th = diff_dual_active ? (algo.dig("diff_parse_y", "threshold") || algo["diff_threshold"] || algo["threshold"]) : algo["threshold"]
      lines << "Differential parse.y Divergences (#{diff_bkts} buckets, #{diff_occ} occurrences -> #{diff_clusters.size} clusters; algorithm=#{diff_algo}, threshold=#{diff_th}):"
      lines.concat(format_cluster_table_lines(diff_clusters, campaign_first_seen, show_first))
    else
      lines.concat(format_cluster_table_lines(clusters, campaign_first_seen, show_first))
    end

    lines << ""
    margin_info = []
    margin_info << "min_merge=#{summary['min_intra_merge_similarity']}" if summary["min_intra_merge_similarity"]
    margin_info << "max_inter=#{summary['max_inter_cluster_similarity']}" if summary["max_inter_cluster_similarity"]
    margin_suffix = margin_info.empty? ? "" : ", #{margin_info.join(', ')}"
    excl_suffix = summary["excluded_unreproducible"].to_i > 0 ? ", excluded_unrepro=#{summary['excluded_unreproducible']}" : ""
    diff_dual_count = algo.dig("diff_parse_y", "dual_edge_buckets").to_i
    diff_th_suffix = diff_dual_count > 0 && algo["diff_threshold"] && algo["diff_threshold"] != algo["threshold"] ? ", diff_threshold=#{algo['diff_threshold']}" : ""
    lines << "Summary: #{summary['bucket_count']} buckets (#{summary['total_occurrences']} occurrences) -> " \
             "#{summary['cluster_count']} clusters (threshold=#{algo['threshold']}#{diff_th_suffix}, reason_weight=#{algo['reason_weight']}" \
             "#{margin_suffix}#{excl_suffix})"
    versions_line = format_versions_line(report["versions"])
    lines << versions_line if versions_line
    container_line = format_container_line(report["versions"])
    lines << container_line if container_line
    lines.join("\n")
  end

  def format_prism_version_tag(pv)
    return nil unless pv.is_a?(Hash) && !pv.empty?

    ver = pv["version"]
    rev = pv["git_short"] || pv["git_commit"]&.[](0, 9)
    dirty = pv["git_dirty"] ? "-dirty" : ""
    rev_str = rev ? "#{rev}#{dirty}" : nil

    main = ver || rev_str
    return nil unless main

    (rev_str && rev_str != main) ? "#{main} (#{rev_str})" : main.to_s
  end

  def format_ruby_version_tag(rv)
    return nil unless rv.is_a?(Hash) && !rv.empty?

    ver = rv["version"]
    rev = rv["revision"]&.[](0, 10)
    main = ver || rev
    return nil unless main

    (rev && rev != main) ? "#{main} (#{rev})" : main.to_s
  end

  def format_versions_line(versions)
    return nil unless versions.is_a?(Hash) && !versions.empty?

    obs = versions["observed"].is_a?(Hash) ? versions["observed"] : {}
    prism_tags = ([versions["prism"]] + Array(obs["prism"])).compact
                 .filter_map { |pv| format_prism_version_tag(pv) }.uniq
    ruby_tags = ([versions["ruby_parse_y"]] + Array(obs["ruby_parse_y"])).compact
                .filter_map { |rv| format_ruby_version_tag(rv) }.uniq

    triage_tags = ([versions.dig("triage", "prism")] + Array(obs["triage"]).map { |t| t.is_a?(Hash) ? t["prism"] : nil })
                  .compact.filter_map { |pv| format_prism_version_tag(pv) }.uniq
    extra_triage = triage_tags - prism_tags

    parts = []
    parts << "prism=#{prism_tags.join(' | ')}" unless prism_tags.empty?
    parts << "triage_prism=#{extra_triage.join(' | ')}" unless extra_triage.empty?
    parts << "ruby_parse_y=#{ruby_tags.join(' | ')}" unless ruby_tags.empty?
    parts.empty? ? nil : "Versions: #{parts.join(', ')}"
  end

  def format_container_tag(cv)
    return nil unless cv.is_a?(Hash) && !cv.empty?

    items = []
    if cv["os"] && !cv["os"].to_s.empty?
      items << (cv["arch"] ? "#{cv['os']} (#{cv['arch']})" : cv["os"].to_s)
    elsif cv["arch"]
      items << cv["arch"].to_s
    end
    if cv["clang"] && !cv["clang"].to_s.empty?
      c_ver = cv["clang"].to_s[/clang version ([0-9.]+)/, 1]
      items << (c_ver ? "clang #{c_ver}" : cv["clang"].to_s)
    end
    items << cv["aflplusplus"].to_s if cv["aflplusplus"] && !cv["aflplusplus"].to_s.empty?
    items << "lrama-fuzz #{cv['lrama_fuzz']}" if cv["lrama_fuzz"] && !cv["lrama_fuzz"].to_s.empty?
    items.empty? ? nil : items.join(", ")
  end

  def format_container_line(versions)
    return nil unless versions.is_a?(Hash) && !versions.empty?

    obs = versions["observed"].is_a?(Hash) ? versions["observed"] : {}
    c_tags = ([versions["container"], versions.dig("fuzz", "container"), versions.dig("triage", "container")] +
              Array(obs["container"]) +
              Array(obs["fuzz"]).map { |f| f.is_a?(Hash) ? f["container"] : nil } +
              Array(obs["triage"]).map { |t| t.is_a?(Hash) ? t["container"] : nil })
             .compact.filter_map { |cv| format_container_tag(cv) }.uniq
    c_tags.empty? ? nil : "Container: #{c_tags.join(' | ')}"
  end
end

if __FILE__ == $PROGRAM_NAME
  options = {
    metadata: ENV.fetch("TRIAGE_METADATA", FuzzClustering::DEFAULT_METADATA_PATH),
    output: ENV.fetch("CLUSTER_OUTPUT", FuzzClustering::DEFAULT_OUTPUT_PATH),
    threshold: Float(ENV.fetch("CLUSTER_THRESHOLD", FuzzClustering::DEFAULT_THRESHOLD.to_s)),
    diff_threshold: ENV["CLUSTER_DIFF_THRESHOLD"] && !ENV["CLUSTER_DIFF_THRESHOLD"].empty? ? Float(ENV["CLUSTER_DIFF_THRESHOLD"]) : nil,
    reason_weight: Float(ENV.fetch("CLUSTER_REASON_WEIGHT", FuzzClustering::DEFAULT_REASON_WEIGHT.to_s)),
    include_unreproducible: false,
    quiet: false
  }

  OptionParser.new do |opts|
    opts.banner = "Usage: cluster.rb [OPTIONS]"
    opts.on("--metadata PATH", "Input metadata.json path (default: #{FuzzClustering::DEFAULT_METADATA_PATH})") do |v|
      options[:metadata] = v
    end
    opts.on("-o", "--output PATH", "Output clusters.json path, or '-' for stdout (default: #{FuzzClustering::DEFAULT_OUTPUT_PATH})") do |v|
      options[:output] = v
    end
    opts.on("--threshold FLOAT", Float, "UPGMA merge threshold in [0, 1] (default: #{FuzzClustering::DEFAULT_THRESHOLD})") do |v|
      options[:threshold] = v
    end
    opts.on("--diff-threshold FLOAT", Float, "UPGMA merge threshold for differential parse.y dual-edge clustering (default: #{FuzzClustering::DIFF_DEFAULT_THRESHOLD})") do |v|
      options[:diff_threshold] = v
    end
    opts.on("--reason-weight FLOAT", Float, "Crash-reason prior weight in [0, 1] (default: #{FuzzClustering::DEFAULT_REASON_WEIGHT})") do |v|
      options[:reason_weight] = v
    end
    opts.on("--include-unreproducible", "Include unreproducible buckets") do
      options[:include_unreproducible] = true
    end
    opts.on("--quiet", "Suppress terminal summary table") do
      options[:quiet] = true
    end
  end.parse!

  unless File.file?(options[:metadata])
    abort "Missing metadata file: #{options[:metadata]}"
  end

  metadata = JSON.parse(File.read(options[:metadata]))
  report = FuzzClustering.cluster_metadata(
    metadata,
    threshold: options[:threshold],
    diff_threshold: options[:diff_threshold],
    reason_weight: options[:reason_weight],
    include_unreproducible: options[:include_unreproducible],
    metadata_path: options[:metadata]
  )

  if options[:output] == "-"
    puts JSON.pretty_generate(report)
    warn FuzzClustering.format_summary_table(report) unless options[:quiet]
  else
    FuzzClustering.write_json_atomic(options[:output], report)
    unless options[:quiet]
      puts FuzzClustering.format_summary_table(report)
      puts "Wrote #{options[:output]}"
    end
  end
end

