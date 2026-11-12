#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "open3"
require "optparse"
require "tmpdir"
require_relative "grammar"

# Quantitative test & benchmark suite for test/fuzz/runtime/grammar.rb.
# Measures regexp/literal/terminal validity, heredoc rewriter stability,
# comment/encoding variant validity, multi-epoch throughput/bloat/uniqueness,
# lrama-fuzz rule coverage, avoided-rule leakage, in_flight syscall overhead,
# 4-byte pm_options_t header coverage, and optional AFL++ bitmap edge coverage.
module GrammarBench
  HEADER_FEATURE_NAMES = %w[
    freeze
    partial_script
    attach_comments
    encoding_locked
    has_frozen_string_literal
    frozen_string_literal
    stream_mode
    has_encoding_opts
    cmd_flags_nonzero
    main_script
    has_limit_opts
    non_default_version
    scopes_nonzero
    forwarding_nonzero
    non_one_start_line
  ].freeze

  module_function

  def parse_options(argv)
    opts = {
      epochs: 2,
      gens: 50,
      seed: 42,
      max_input_size: Integer(ENV.fetch("FUZZ_MAX_INPUT_SIZE", "1024")),
      variant_trials: 200,
      max_seconds: 60.0,
      record_result: false,
      no_breadcrumb: false,
      showmap_bin: nil,
      showmap_limit: 1000,
      json_path: nil,
      compare_path: nil,
      strict: false,
      quiet: false
    }

    OptionParser.new do |p|
      p.banner = "Usage: ruby #{File.basename($PROGRAM_NAME)} [options]"
      p.on("--epochs N", Integer, "Number of build_evolvers epochs (default: #{opts[:epochs]})") { |v| opts[:epochs] = v }
      p.on("--gens N", Integer, "Generations per epoch (default: #{opts[:gens]})") { |v| opts[:gens] = v }
      p.on("--seed N", Integer, "Deterministic PRNG seed (default: #{opts[:seed]})") { |v| opts[:seed] = v }
      p.on("--max-input-size N", Integer, "AFL++ max_length (-G) in bytes (default: #{opts[:max_input_size]})") { |v| opts[:max_input_size] = v }
      p.on("--variant-trials N", Integer, "Trials for standalone heredoc/variant audits (default: #{opts[:variant_trials]})") { |v| opts[:variant_trials] = v }
      p.on("--max-seconds F", Float, "Wall-clock cap for simulation loop (default: #{opts[:max_seconds]}s)") { |v| opts[:max_seconds] = v }
      p.on("--record-result", "Ablation: call Generator#record_result(valid:) during simulation") { opts[:record_result] = true }
      p.on("--no-breadcrumb", "Ablation: evaluate Prism.parse without writing in_flight breadcrumbs") { opts[:no_breadcrumb] = true }
      p.on("--showmap-bin PATH", String, "Measure real AFL++ edge coverage on sampled emitted seeds") { |v| opts[:showmap_bin] = v }
      p.on("--showmap-limit N", Integer, "Max unique seeds fed to afl-showmap (default: #{opts[:showmap_limit]})") { |v| opts[:showmap_limit] = v }
      p.on("--json PATH", String, "Write full structured metrics report to JSON") { |v| opts[:json_path] = v }
      p.on("--compare PATH", String, "Compare current metrics against a baseline JSON report") { |v| opts[:compare_path] = v }
      p.on("--strict", "Exit non-zero if target quality/compliance thresholds are not met") { opts[:strict] = true }
      p.on("--quiet", "Suppress detailed human tables (useful with --json)") { opts[:quiet] = true }
    end.parse!(argv)

    opts
  end

  def pct(num, den)
    return 0.0 if den.nil? || den <= 0

    (num * 100.0 / den).round(2)
  end

  def percentile(sorted_vals, p)
    return 0.0 if sorted_vals.empty?

    idx = [(p * (sorted_vals.size - 1)).round, sorted_vals.size - 1].min
    sorted_vals[idx].to_f
  end

  def find_generator(evolver)
    evolver.instance_variables.each do |iv|
      val = evolver.instance_variable_get(iv)
      return val if val.respond_to?(:coverage)
    end
    nil
  end

  def load_ruby_grammar
    ruby_src_dir = ENV.fetch("RUBY_SRC_DIR", "/opt/ruby")
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    grammar = Lrama::Fuzz.parse_ruby(
      parse_y_path: File.join(ruby_src_dir, "parse.y"),
      id_def_path: File.join(ruby_src_dir, "defs", "id.def")
    )
    [grammar, (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0).round(4)]
  end

  def decode_header_features(header)
    b0, b1, b2, b3 = header.b.unpack("C4")
    return {} unless b0

    {
      "freeze" => (b0 & 0x01) != 0,
      "partial_script" => (b0 & 0x02) != 0,
      "attach_comments" => (b0 & 0x04) != 0,
      "encoding_locked" => (b0 & 0x08) != 0,
      "has_frozen_string_literal" => (b0 & 0x10) != 0,
      "frozen_string_literal" => (b0 & 0x20) != 0,
      "stream_mode" => (b0 & 0x40) != 0,
      "has_encoding_opts" => (b0 & 0x80) != 0,
      "cmd_flags_nonzero" => (b1 & 0x3f) != 0,
      "main_script" => (b1 & 0x40) != 0,
      "has_limit_opts" => (b1 & 0x80) != 0,
      "non_default_version" => (b2 & 0x03) != 3,
      "scopes_nonzero" => ((b2 >> 2) & 0x03) != 0,
      "forwarding_nonzero" => ((b2 >> 4) & 0x0f) != 0,
      "non_one_start_line" => b3 != 1
    }
  end

  # Audit 1: Every REGEXP_VALID_FRAGMENTS entry across /, %r", %r{} and REGEXP_SAFE_MODIFIERS.
  def audit_regexp_fragments
    delimiters = [
      ["slash", "/", "/"],
      ["pct_dquote", '%r"', '"'],
      ["pct_brace", "%r{", "}"]
    ]
    prism_fail = 0
    ruby_vm_fail = 0
    total = 0
    prism_fail_by_frag = Hash.new { |h, k| h[k] = { count: 0, delimiters: [], error: nil } }
    ruby_vm_fail_indices = []
    has_ruby_vm = defined?(RubyVM::AbstractSyntaxTree)

    REGEXP_VALID_FRAGMENTS.each_with_index do |frag, idx|
      REGEXP_SAFE_MODIFIERS.each do |mod|
        delimiters.each do |kind, open_d, close_d|
          total += 1
          src = "#{open_d}#{frag}#{close_d}#{mod}"
          res = Prism.parse(src)
          unless res.success?
            prism_fail += 1
            entry = prism_fail_by_frag[idx]
            entry[:count] += 1
            entry[:delimiters] << kind unless entry[:delimiters].include?(kind)
            entry[:error] ||= res.errors.first&.message
          end

          next unless has_ruby_vm

          # RubyVM::AbstractSyntaxTree.parse emits C-level warnings for invalid
          # Unicode properties (e.g. `\pa`); silence only around the parser check.
          prev_verbose = $VERBOSE
          $VERBOSE = nil
          begin
            RubyVM::AbstractSyntaxTree.parse(src)
          rescue SyntaxError
            ruby_vm_fail += 1
            ruby_vm_fail_indices << idx unless ruby_vm_fail_indices.include?(idx)
          ensure
            $VERBOSE = prev_verbose
          end
        end
      end
    end

    {
      "fragments_count" => REGEXP_VALID_FRAGMENTS.size,
      "modifiers_count" => REGEXP_SAFE_MODIFIERS.size,
      "total_combos" => total,
      "prism_valid" => total - prism_fail,
      "prism_fail" => prism_fail,
      "prism_valid_pct" => pct(total - prism_fail, total),
      "ruby_vm_fail" => ruby_vm_fail,
      "ruby_vm_fail_indices" => ruby_vm_fail_indices,
      "prism_failures" => prism_fail_by_frag.map do |idx, info|
        {
          "index" => idx,
          "fragment" => REGEXP_VALID_FRAGMENTS[idx],
          "fail_combos" => info[:count],
          "delimiters" => info[:delimiters],
          "error" => info[:error]
        }
      end
    }
  end

  # Audit 2: Literal byte sizes vs max payload and grammar terminal coverage.
  def audit_literals_and_terminals(grammar, max_payload_bytes)
    oversized_bignums = LARGE_BIGNUM_LITERALS.each_with_index.filter_map do |lit, i|
      { "index" => i, "bytes" => lit.bytesize } if lit.bytesize > max_payload_bytes
    end

    numeric_groups = {
      "compact_integers" => COMPACT_INTEGERS,
      "rational_literals" => RATIONAL_LITERALS,
      "imaginary_literals" => IMAGINARY_LITERALS,
      "float_literals" => FLOAT_LITERALS,
      "large_bignums" => LARGE_BIGNUM_LITERALS,
      "long_float" => [LONG_FLOAT_LITERAL]
    }
    group_stats = numeric_groups.transform_values do |list|
      valid = list.count { |lit| Prism.parse_success?(lit) }
      {
        "count" => list.size,
        "valid" => valid,
        "max_bytes" => list.map(&:bytesize).max || 0,
        "oversized_count" => list.count { |lit| lit.bytesize > max_payload_bytes }
      }
    end

    terms, = build_ruby_terminals(Random.new(1), allow_invalid: false)
    term_keys = terms.keys.map(&:to_s)
    grammar_terms = grammar.terms.map { |t| t.id.s_value }
    meta_terms = %w[$end error $undefined END_OF_INPUT YYerror YYUNDEF]
    missing = (grammar_terms - term_keys - meta_terms).reject { |s| s.start_with?("'") && s.end_with?("'") }
    extra = term_keys - grammar_terms

    {
      "max_payload_bytes" => max_payload_bytes,
      "literal_groups" => group_stats,
      "oversized_bignums" => oversized_bignums,
      "grammar_terms_count" => grammar_terms.size,
      "terminal_table_keys" => term_keys.size,
      "missing_non_single_char_terms" => missing,
      "extra_unused_keys" => extra
    }
  end

  # Audit 3: Isolate Pass-1 vs Pass-2 heredoc rewriter stability and edge fixtures.
  def audit_heredocs(grammar, rng, parse_fn, validator, trials:)
    comp_rng = Random.new(rng.rand(2**32))
    terminals, reset_delims = build_ruby_terminals(comp_rng, allow_invalid: false)
    avoid = Lrama::Fuzz::Ruby::AVOID_SYMBOLS + Set["dsym", "END_OF_INPUT"]
    gen = Lrama::Fuzz::Generator.new(
      grammar,
      terminals: terminals,
      classifier: Lrama::Fuzz::Ruby.method(:classifier),
      avoid_symbols: avoid,
      max_depth: 10,
      random: comp_rng
    )
    gen.singleton_class.prepend(Module.new do
      define_method(:generate) { |**kw| reset_delims.call; super(**kw) }
      define_method(:generate_from) { |*a| reset_delims.call; super(*a) }
      define_method(:generate_targeted) { reset_delims.call; super() }
      define_method(:pick_rule) { |rules| super(filter_avoided(rules)) }
    end)
    composer = PrismComposer.new(gen, random: Random.new(rng.rand(2**32)), validator: validator)

    p1_tot = 0; p1_ok = 0
    p2_tot = 0; p2_ok = 0
    inj_tot = 0; inj_ok = 0

    (trials * 5).times do
      break if p1_tot >= trials

      src = composer.generate
      next unless src.include?('"') && validator.call(src)

      p1 = rewrite_heredocs_pass(src, rng, parse_fn, 0)
      if p1
        p1_tot += 1
        p1_ok += 1 if validator.call(p1)
        p2 = rewrite_heredocs_pass(p1, rng, parse_fn, 10)
        if p2
          p2_tot += 1
          p2_ok += 1 if validator.call(p2)
        end
      end

      hd = inject_heredocs(src, rng, parse_fn)
      if hd
        inj_tot += 1
        inj_ok += 1 if validator.call(hd)
      end
    end

    label_res = rewrite_heredocs_pass('{ "foo": 1 }', Random.new(1), parse_fn, 0)
    wide = "# before wide array\nqux = [" + (0...33).map { |i| i.even? ? i.to_s : "\"w#{i}\"" }.join(", ") + "]\n"
    wide_ok = 20.times.count { |i| out = inject_heredocs(wide, Random.new(i), parse_fn); out && validator.call(out) }
    hc_line = "x = <<~HC + \"\"\n  1\nHC\n"
    hc_res = rewrite_heredocs_pass(hc_line, Random.new(1), parse_fn, 0)

    {
      "pass1_total" => p1_tot,
      "pass1_valid" => p1_ok,
      "pass1_valid_pct" => pct(p1_ok, p1_tot),
      "pass2_total" => p2_tot,
      "pass2_valid" => p2_ok,
      "pass2_valid_pct" => pct(p2_ok, p2_tot),
      "inject_total" => inj_tot,
      "inject_valid" => inj_ok,
      "inject_valid_pct" => pct(inj_ok, inj_tot),
      "fixtures" => {
        "wide_array_20_trials_valid" => wide_ok,
        "hash_label_key_valid" => label_res ? validator.call(label_res) : nil,
        "same_line_existing_heredoc_valid" => hc_res ? validator.call(hc_res) : nil
      }
    }
  end

  # Audit 4: Standalone comment & encoding variant valid/error distributions.
  def audit_variants(rng, validator, trials:)
    cmt_ok = 0; cmt_main = 0; cmt_errs = Hash.new(0)
    enc_ok = 0; enc_errs = Hash.new(0)
    base = "x = 1\ny = \"hello\"\n"

    trials.times do
      c_code, is_main = inject_comments_variant(base, rng)
      cmt_main += 1 if is_main
      res = Prism.parse(c_code)
      if res.success?
        cmt_ok += 1
      else
        cmt_errs[res.errors.first&.message || "unknown"] += 1
      end

      e_code = inject_encoding_variant(base, rng)
      res_e = Prism.parse(e_code)
      if res_e.success?
        enc_ok += 1
      else
        enc_errs[res_e.errors.first&.message || "unknown"] += 1
      end
    end

    {
      "trials" => trials,
      "comments_valid" => cmt_ok,
      "comments_valid_pct" => pct(cmt_ok, trials),
      "comments_main_script_pct" => pct(cmt_main, trials),
      "comments_top_errors" => cmt_errs.sort_by { |_, v| -v }.first(5).to_h,
      "encoding_valid" => enc_ok,
      "encoding_valid_pct" => pct(enc_ok, trials),
      "encoding_top_errors" => enc_errs.sort_by { |_, v| -v }.first(5).to_h
    }
  end

  def make_evaluators(in_flight_io, no_breadcrumb:)
    writes = { count: 0 }
    if no_breadcrumb
      parse_fn = lambda do |code|
        ::Prism.parse(code)
      rescue StandardError, SystemStackError, NoMemoryError
        nil
      end
      validator = lambda do |code|
        ::Prism.parse_success?(code)
      rescue StandardError, SystemStackError, NoMemoryError
        false
      end
      fitness = lambda do |code|
        res = parse_fn.call(code)
        next 0.0 unless res
        res.success? ? (1.0 + Math.log(count_prism_nodes(res.value) + 1) * 0.1) : [0.0, 0.5 - res.errors.size * 0.05].max
      end
    else
      in_flight_io.singleton_class.prepend(Module.new do
        define_method(:write) { |*a| writes[:count] += 1; super(*a) }
      end)
      fitness, validator, parse_fn = build_guarded_evaluators(in_flight_io)
    end
    [fitness, validator, parse_fn, writes]
  end

  def measure_afl_showmap(showmap_bin, seeds_dir, total_written)
    out_map = File.join(File.dirname(seeds_dir), "showmap.out")
    cmd = ["afl-showmap", "-q", "-C", "-t", "250", "-i", seeds_dir, "-o", out_map, "--", showmap_bin]
    _, err, st = Open3.capture3(*cmd)
    return { "error" => err.lines.first&.strip || "exit #{st.exitstatus}" } unless st.success? && File.exist?(out_map)

    edges = File.foreach(out_map).count { |line| !line.strip.empty? }
    { "seeds_tested" => total_written, "edges_covered" => edges }
  rescue Errno::ENOENT => e
    { "error" => e.message }
  end

  # Audit 5: Multi-epoch evolution simulation mirroring run_worker().
  def run_simulation(grammar, opts, in_flight_io, showmap_dir: nil)
    avoid = Lrama::Fuzz::Ruby::AVOID_SYMBOLS + Set["dsym", "END_OF_INPUT"]
    avoided_rule_ids = Set.new(grammar.rules.select { |r| ([r.lhs] + r.rhs).any? { |s| avoid.include?(s.id.s_value) } }.map(&:id))
    # Avoided rules where `lhs` also has at least one non-avoided alternative rule.
    avoidable_rule_ids = Set.new(grammar.rules.select do |r|
      next false unless r.rhs.any? { |s| avoid.include?(s.id.s_value) }

      (grammar.find_rules_by_symbol(r.lhs) || []).any? { |sr| sr.rhs.none? { |s| avoid.include?(s.id.s_value) } }
    end.map(&:id))
    reachable_rules = Lrama::Fuzz::Coverage.new(grammar).total_count

    rng = Random.new(opts[:seed])
    fitness, validator, parse_fn, write_counter = make_evaluators(in_flight_io, no_breadcrumb: opts[:no_breadcrumb])

    seen_digests = {}
    attempts = 0; unique_emitted = 0; valid_unique = 0
    oversized_total = 0; oversized_unique = 0
    oversized_by_kind = Hash.new(0)
    raw_stats = { comp_tot: 0, comp_ok: 0, gram_tot: 0, gram_ok: 0 }
    raw_sizes = { comp: [], gram: [] }
    in_pop_uniq = { comp: [], gram: [] }
    variant_stats = Hash.new { |h, k| h[k] = { total: 0, valid: 0 } }
    distinct_headers = Set.new
    header_features = HEADER_FEATURE_NAMES.to_h { |k| [k, false] }
    gen_latencies = []
    init_writes = 0; comp_writes = 0; gram_writes = 0
    build_time = 0.0
    peak_cov = { comp_used: 0, comp_valid: 0, gram_seed_used: 0, gram_seed_valid: 0, combined_used: 0 }
    last_cov = peak_cov.dup
    comp_avoided_hits = 0; gram_avoided_hits = 0
    comp_avoidable_hits = 0; gram_avoidable_hits = 0
    showmap_written = 0
    gens_completed = 0
    timed_out = false

    t_sim0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    opts[:epochs].times do
      break if (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t_sim0) >= opts[:max_seconds]

      w0 = write_counter[:count]
      tb0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      comp, gram = build_evolvers(grammar, rng, fitness, validator)
      build_time += Process.clock_gettime(Process::CLOCK_MONOTONIC) - tb0
      init_writes += write_counter[:count] - w0
      comp_gen = find_generator(comp)
      gram_gen = find_generator(gram)

      opts[:gens].times do
        if (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t_sim0) >= opts[:max_seconds]
          timed_out = true
          break
        end

        tg0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        wc0 = write_counter[:count]
        c_batch = comp.evolve
        comp_writes += write_counter[:count] - wc0
        c_batch.each { |_, sc| comp_gen&.record_result(valid: sc >= 1.0) } if opts[:record_result]

        wg0 = write_counter[:count]
        g_batch = gram.evolve
        gram_writes += write_counter[:count] - wg0
        g_batch.each { |_, sc| gram_gen&.record_result(valid: sc >= 1.0) } if opts[:record_result]

        in_pop_uniq[:comp] << c_batch.map(&:first).uniq.size.to_f / [c_batch.size, 1].max
        in_pop_uniq[:gram] << g_batch.map(&:first).uniq.size.to_f / [g_batch.size, 1].max

        [[:comp, c_batch], [:gram, g_batch]].each do |source, batch|
          batch.each do |code, fitness_score|
            is_valid = fitness_score >= 1.0
            if source == :comp
              raw_stats[:comp_tot] += 1
              raw_stats[:comp_ok] += 1 if is_valid
              raw_sizes[:comp] << code.bytesize
            else
              raw_stats[:gram_tot] += 1
              raw_stats[:gram_ok] += 1 if is_valid
              raw_sizes[:gram] << code.bytesize
            end

            payload_cap = [opts[:max_input_size] - 4, 1].max
            expand_candidate_variants(code, is_valid, rng, validator, parse_fn, max_payload_bytes: payload_cap).each do |hdr, payload, valid, kind|
              payload_b = payload.b
              attempts += 1
              distinct_headers << hdr
              decode_header_features(hdr).each { |feat, active| header_features[feat] ||= active }

              if kind != :raw
                variant_stats[kind][:total] += 1
                variant_stats[kind][:valid] += 1 if valid
              end

              over = (hdr.bytesize + payload_b.bytesize) > opts[:max_input_size]
              if over
                oversized_total += 1
                oversized_by_kind[kind == :raw ? source : kind] += 1
              end

              digest = Digest::SHA1.digest("#{hdr}#{payload_b}")
              seen_digests.clear if seen_digests.size >= MAX_SEEN_DIGESTS
              next if seen_digests.key?(digest)

              seen_digests[digest] = true
              unique_emitted += 1
              valid_unique += 1 if valid
              oversized_unique += 1 if over

              if showmap_dir && showmap_written < opts[:showmap_limit]
                File.binwrite(File.join(showmap_dir, format("seed_%06d", showmap_written)), hdr + payload_b)
                showmap_written += 1
              end
            end
          end
        end

        gen_latencies << (Process.clock_gettime(Process::CLOCK_MONOTONIC) - tg0) * 1000.0
        gens_completed += 1
      end

      c_used = comp_gen.coverage.used_rule_ids
      g_used = gram_gen.coverage.used_rule_ids
      last_cov = {
        comp_used: c_used.size,
        comp_valid: comp_gen.coverage.valid_rule_ids.size,
        gram_seed_used: g_used.size,
        gram_seed_valid: gram_gen.coverage.valid_rule_ids.size,
        combined_used: (c_used | g_used).size
      }
      last_cov.each { |k, v| peak_cov[k] = [peak_cov[k], v].max }
      comp_avoided_hits = [comp_avoided_hits, (c_used & avoided_rule_ids).size].max
      gram_avoided_hits = [gram_avoided_hits, (g_used & avoided_rule_ids).size].max
      comp_avoidable_hits = [comp_avoidable_hits, (c_used & avoidable_rule_ids).size].max
      gram_avoidable_hits = [gram_avoidable_hits, (g_used & avoidable_rule_ids).size].max
      break if timed_out
    end

    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t_sim0
    sorted_lat = gen_latencies.sort
    sorted_comp_sz = raw_sizes[:comp].sort
    sorted_gram_sz = raw_sizes[:gram].sort

    showmap_result = if opts[:showmap_bin] && showmap_dir && showmap_written > 0
                       measure_afl_showmap(opts[:showmap_bin], showmap_dir, showmap_written)
                     end

    {
      "epochs_requested" => opts[:epochs],
      "gens_per_epoch" => opts[:gens],
      "generations_completed" => gens_completed,
      "timed_out" => timed_out,
      "elapsed_sec" => elapsed.round(3),
      "build_evolvers_sec" => build_time.round(3),
      "gen_latency_ms" => {
        "mean" => sorted_lat.empty? ? 0.0 : (sorted_lat.sum / sorted_lat.size).round(2),
        "p50" => percentile(sorted_lat, 0.50).round(2),
        "p95" => percentile(sorted_lat, 0.95).round(2),
        "max" => (sorted_lat.last || 0.0).round(2)
      },
      "throughput" => {
        "attempts" => attempts,
        "unique_emitted" => unique_emitted,
        "valid_unique" => valid_unique,
        "unique_pct" => pct(unique_emitted, attempts),
        "attempts_per_sec" => (attempts / [elapsed, 0.001].max).round(1),
        "unique_per_sec" => (unique_emitted / [elapsed, 0.001].max).round(1),
        "valid_unique_per_sec" => (valid_unique / [elapsed, 0.001].max).round(1)
      },
      "evolvers" => {
        "composed_valid_pct" => pct(raw_stats[:comp_ok], raw_stats[:comp_tot]),
        "composed_in_pop_uniq_pct" => in_pop_uniq[:comp].empty? ? 0.0 : (in_pop_uniq[:comp].sum * 100.0 / in_pop_uniq[:comp].size).round(2),
        "composed_bytes_avg" => sorted_comp_sz.empty? ? 0 : (sorted_comp_sz.sum.to_f / sorted_comp_sz.size).round(1),
        "composed_bytes_p95" => percentile(sorted_comp_sz, 0.95).round(0).to_i,
        "composed_bytes_max" => sorted_comp_sz.last || 0,
        "grammar_valid_pct" => pct(raw_stats[:gram_ok], raw_stats[:gram_tot]),
        "grammar_in_pop_uniq_pct" => in_pop_uniq[:gram].empty? ? 0.0 : (in_pop_uniq[:gram].sum * 100.0 / in_pop_uniq[:gram].size).round(2),
        "grammar_bytes_avg" => sorted_gram_sz.empty? ? 0 : (sorted_gram_sz.sum.to_f / sorted_gram_sz.size).round(1),
        "grammar_bytes_p95" => percentile(sorted_gram_sz, 0.95).round(0).to_i,
        "grammar_bytes_max" => sorted_gram_sz.last || 0
      },
      "oversized" => {
        "limit_bytes" => opts[:max_input_size],
        "total" => oversized_total,
        "total_pct" => pct(oversized_total, attempts),
        "unique" => oversized_unique,
        "unique_pct" => pct(oversized_unique, unique_emitted),
        "by_source" => oversized_by_kind.transform_keys(&:to_s)
      },
      "variants_in_run" => variant_stats.each_with_object({}) do |(k, v), out|
        out[k.to_s] = { "valid" => v[:valid], "total" => v[:total], "valid_pct" => pct(v[:valid], v[:total]) }
      end,
      "in_flight_writes" => {
        "init_total" => init_writes,
        "comp_per_gen" => (comp_writes.to_f / [gens_completed, 1].max).round(1),
        "gram_per_gen" => (gram_writes.to_f / [gens_completed, 1].max).round(1),
        "total" => write_counter[:count]
      },
      "coverage" => {
        "total_rules" => grammar.rules.size,
        "reachable_rules" => reachable_rules,
        "peak_comp_used" => peak_cov[:comp_used],
        "peak_comp_valid" => peak_cov[:comp_valid],
        "peak_gram_seed_used" => peak_cov[:gram_seed_used],
        "peak_gram_seed_valid" => peak_cov[:gram_seed_valid],
        "peak_combined_used" => peak_cov[:combined_used],
        "last_comp_used" => last_cov[:comp_used],
        "comp_avoided_hits" => comp_avoided_hits,
        "gram_seed_avoided_hits" => gram_avoided_hits,
        "comp_avoidable_hits" => comp_avoidable_hits,
        "gram_seed_avoidable_hits" => gram_avoidable_hits
      },
      "headers" => {
        "distinct_count" => distinct_headers.size,
        "features_covered_count" => header_features.values.count(true),
        "features_total" => HEADER_FEATURE_NAMES.size,
        "features" => header_features
      },
      "afl_showmap" => showmap_result
    }
  end

  def strict_failures(report)
    sim = report["simulation"]
    failures = []
    failures << "regexp prism_fail=#{report["regexp_audit"]["prism_fail"]} (expected 0)" if report["regexp_audit"]["prism_fail"] > 0
    if report["heredoc_audit"]["pass2_total"].to_i > 0 && report["heredoc_audit"]["pass2_valid_pct"] < 90.0
      failures << "heredoc pass2_valid_pct=#{report["heredoc_audit"]["pass2_valid_pct"]} (expected >=90%)"
    end
    failures << "heredoc pass1_valid_pct=#{report["heredoc_audit"]["pass1_valid_pct"]} (expected >=98%)" if report["heredoc_audit"]["pass1_valid_pct"] < 98.0
    failures << "oversized_pct=#{sim["oversized"]["total_pct"]} (expected 0%)" if sim["oversized"]["total_pct"] > 0.0
    failures << "comp_avoidable_hits=#{sim["coverage"]["comp_avoidable_hits"]} (expected 0)" if sim["coverage"]["comp_avoidable_hits"] > 0
    failures << "gram_seed_avoidable_hits=#{sim["coverage"]["gram_seed_avoidable_hits"]} (expected 0)" if sim["coverage"]["gram_seed_avoidable_hits"] > 0
    failures << "comp_valid=#{sim["coverage"]["peak_comp_valid"]} (expected >0)" if sim["coverage"]["peak_comp_valid"] <= 0
    failures << "gram_seed_valid=#{sim["coverage"]["peak_gram_seed_valid"]} (expected >0)" if sim["coverage"]["peak_gram_seed_valid"] <= 0
    failures << "header features=#{sim["headers"]["features_covered_count"]}/#{sim["headers"]["features_total"]} (expected >=6)" if sim["headers"]["features_covered_count"] < 6
    failures
  end

  def print_report(report)
    puts "=== Environment ==="
    puts "ruby=#{report["env"]["ruby"]} | prism=#{report["env"]["prism_version"]} (#{report["env"]["prism_backend"]}) | parse.y=#{report["env"]["parse_y_parse_sec"]}s"

    re = report["regexp_audit"]
    puts "\n=== 1. Regexp Valid Fragments (#{re["total_combos"]} combos) ==="
    puts format("Prism valid: %d/%d (%.1f%%) | RubyVM AST fail: %d (indices: %s)",
      re["prism_valid"], re["total_combos"], re["prism_valid_pct"], re["ruby_vm_fail"], re["ruby_vm_fail_indices"].inspect)
    re["prism_failures"].each do |f|
      puts format("  FAIL [%d] %s (%d combos, delims=%s): %s", f["index"], f["fragment"].inspect, f["fail_combos"], f["delimiters"].join(","), f["error"])
    end

    lit = report["literals_and_terminals"]
    puts "\n=== 2. Literals & Terminals (payload cap=#{lit["max_payload_bytes"]}B) ==="
    lit["literal_groups"].each do |name, g|
      puts format("  %-18s count=%2d valid=%2d maxB=%4d >cap=%d", name, g["count"], g["valid"], g["max_bytes"], g["oversized_count"])
    end
    puts "  missing_non_single_char_terms=#{lit["missing_non_single_char_terms"].inspect} | extra_unused_keys=#{lit["extra_unused_keys"].inspect}"

    hd = report["heredoc_audit"]
    puts "\n=== 3. Heredoc Rewriter Audit ==="
    puts format("  Pass 1: %d/%d (%.1f%%) | Pass 2: %d/%d (%.1f%%) | inject_heredocs: %d/%d (%.1f%%)",
      hd["pass1_valid"], hd["pass1_total"], hd["pass1_valid_pct"],
      hd["pass2_valid"], hd["pass2_total"], hd["pass2_valid_pct"],
      hd["inject_valid"], hd["inject_total"], hd["inject_valid_pct"])
    puts "  Fixtures: #{hd["fixtures"].inspect}"

    vr = report["variants_audit"]
    puts "\n=== 4. Variant Generators (#{vr["trials"]} trials) ==="
    puts format("  comments: %d/%d (%.1f%%, main_script=%.1f%%) top_errs=%s",
      vr["comments_valid"], vr["trials"], vr["comments_valid_pct"], vr["comments_main_script_pct"], vr["comments_top_errors"].inspect)
    puts format("  encoding: %d/%d (%.1f%%) top_errs=%s",
      vr["encoding_valid"], vr["trials"], vr["encoding_valid_pct"], vr["encoding_top_errors"].inspect)

    sim = report["simulation"]
    tp = sim["throughput"]
    ev = sim["evolvers"]
    cov = sim["coverage"]
    hdr = sim["headers"]
    puts "\n=== 5. Simulation (#{sim["generations_completed"]}/#{sim["epochs_requested"] * sim["gens_per_epoch"]} gens, #{sim["elapsed_sec"]}s, build=#{sim["build_evolvers_sec"]}s#{sim["timed_out"] ? " TIMED OUT" : ""}) ==="
    puts format("  Throughput: %.1f uniq/s, %.1f valid_uniq/s, %.1f attempts/s | unique=%d/%d (%.1f%%)",
      tp["unique_per_sec"], tp["valid_unique_per_sec"], tp["attempts_per_sec"],
      tp["unique_emitted"], tp["attempts"], tp["unique_pct"])
    puts format("  Gen latency (ms): mean=%.1f p50=%.1f p95=%.1f max=%.1f",
      sim["gen_latency_ms"]["mean"], sim["gen_latency_ms"]["p50"], sim["gen_latency_ms"]["p95"], sim["gen_latency_ms"]["max"])
    puts format("  Composed: valid=%.1f%% pop_uniq=%.1f%% bytes avg=%.0f p95=%d max=%d",
      ev["composed_valid_pct"], ev["composed_in_pop_uniq_pct"], ev["composed_bytes_avg"], ev["composed_bytes_p95"], ev["composed_bytes_max"])
    puts format("  Grammar:  valid=%.1f%% pop_uniq=%.1f%% bytes avg=%.0f p95=%d max=%d",
      ev["grammar_valid_pct"], ev["grammar_in_pop_uniq_pct"], ev["grammar_bytes_avg"], ev["grammar_bytes_p95"], ev["grammar_bytes_max"])
    puts format("  Oversized (>%dB): %d/%d (%.1f%%), unique=%d (%.1f%%), by_source=%s",
      sim["oversized"]["limit_bytes"], sim["oversized"]["total"], tp["attempts"], sim["oversized"]["total_pct"],
      sim["oversized"]["unique"], sim["oversized"]["unique_pct"], sim["oversized"]["by_source"].inspect)
    puts format("  in_flight writes: init=%d comp/gen=%.1f gram/gen=%.1f total=%d",
      sim["in_flight_writes"]["init_total"], sim["in_flight_writes"]["comp_per_gen"], sim["in_flight_writes"]["gram_per_gen"], sim["in_flight_writes"]["total"])
    puts format("  Coverage (%d reachable/%d total): peak comp=%d (valid=%d) gram_seed=%d (valid=%d) combined=%d | avoided comp=%d (avoidable=%d) gram_seed=%d (avoidable=%d)",
      cov["reachable_rules"], cov["total_rules"], cov["peak_comp_used"], cov["peak_comp_valid"],
      cov["peak_gram_seed_used"], cov["peak_gram_seed_valid"], cov["peak_combined_used"],
      cov["comp_avoided_hits"], cov["comp_avoidable_hits"], cov["gram_seed_avoided_hits"], cov["gram_seed_avoidable_hits"])
    puts format("  Headers: %d distinct | %d/%d option features active (%s)",
      hdr["distinct_count"], hdr["features_covered_count"], hdr["features_total"],
      hdr["features"].select { |_, v| v }.keys.join(", "))
    if sim["afl_showmap"]
      puts "  AFL++ showmap: #{sim["afl_showmap"].inspect}"
    end
  end

  def print_comparison(current, baseline)
    rows = [
      ["unique_per_sec", baseline.dig("simulation", "throughput", "unique_per_sec"), current.dig("simulation", "throughput", "unique_per_sec")],
      ["valid_unique_per_sec", baseline.dig("simulation", "throughput", "valid_unique_per_sec"), current.dig("simulation", "throughput", "valid_unique_per_sec")],
      ["unique_pct", baseline.dig("simulation", "throughput", "unique_pct"), current.dig("simulation", "throughput", "unique_pct")],
      ["composed_valid_pct", baseline.dig("simulation", "evolvers", "composed_valid_pct"), current.dig("simulation", "evolvers", "composed_valid_pct")],
      ["grammar_valid_pct", baseline.dig("simulation", "evolvers", "grammar_valid_pct"), current.dig("simulation", "evolvers", "grammar_valid_pct")],
      ["oversized_pct", baseline.dig("simulation", "oversized", "total_pct"), current.dig("simulation", "oversized", "total_pct")],
      ["heredoc_pass2_valid_pct", baseline.dig("heredoc_audit", "pass2_valid_pct"), current.dig("heredoc_audit", "pass2_valid_pct")],
      ["regexp_prism_fail", baseline.dig("regexp_audit", "prism_fail"), current.dig("regexp_audit", "prism_fail")],
      ["peak_comp_valid_rules", baseline.dig("simulation", "coverage", "peak_comp_valid"), current.dig("simulation", "coverage", "peak_comp_valid")],
      ["comp_avoided_hits", baseline.dig("simulation", "coverage", "comp_avoided_hits"), current.dig("simulation", "coverage", "comp_avoided_hits")],
      ["gram_seed_avoided_hits", baseline.dig("simulation", "coverage", "gram_seed_avoided_hits"), current.dig("simulation", "coverage", "gram_seed_avoided_hits")],
      ["in_flight_writes_total", baseline.dig("simulation", "in_flight_writes", "total"), current.dig("simulation", "in_flight_writes", "total")],
      ["header_features_covered", baseline.dig("simulation", "headers", "features_covered_count"), current.dig("simulation", "headers", "features_covered_count")]
    ]
    puts "\n=== Baseline Comparison ==="
    rows.each do |name, b_val, c_val|
      next if b_val.nil? || c_val.nil?
      diff = c_val - b_val
      sign = diff > 0 ? "+" : ""
      puts format("  %-26s %10s -> %-10s (%s%s)", name, b_val.to_s, c_val.to_s, sign, diff.is_a?(Float) ? format("%.2f", diff) : diff.to_s)
    end
  end

  def run(argv = ARGV)
    $stdout.sync = true
    opts = parse_options(argv)
    grammar, parse_sec = load_ruby_grammar

    report = Dir.mktmpdir("grammar-bench-") do |tmpdir|
      in_flight_io = File.open(File.join(tmpdir, "in_flight"), File::RDWR | File::CREAT | File::BINARY, 0o600)
      in_flight_io.sync = true
      showmap_dir = opts[:showmap_bin] ? File.join(tmpdir, "seeds") : nil
      FileUtils.mkdir_p(showmap_dir) if showmap_dir

      _, validator, parse_fn = build_guarded_evaluators(in_flight_io)
      audit_rng = Random.new(opts[:seed])

      {
        "schema_version" => 1,
        "config" => opts.transform_keys(&:to_s),
        "env" => {
          "ruby" => RUBY_DESCRIPTION,
          "prism_version" => Prism::VERSION,
          "prism_backend" => defined?(Prism::BACKEND) ? Prism::BACKEND.to_s : "unknown",
          "parse_y_parse_sec" => parse_sec
        },
        "regexp_audit" => audit_regexp_fragments,
        "literals_and_terminals" => audit_literals_and_terminals(grammar, [opts[:max_input_size] - 4, 1].max),
        "heredoc_audit" => audit_heredocs(grammar, audit_rng, parse_fn, validator, trials: opts[:variant_trials]),
        "variants_audit" => audit_variants(audit_rng, validator, trials: opts[:variant_trials]),
        "simulation" => run_simulation(grammar, opts, in_flight_io, showmap_dir: showmap_dir)
      }
    ensure
      in_flight_io&.close rescue nil
    end

    print_report(report) unless opts[:quiet]

    if opts[:compare_path]
      baseline = JSON.parse(File.read(opts[:compare_path]))
      print_comparison(report, baseline) unless opts[:quiet]
    end

    if opts[:json_path]
      FileUtils.mkdir_p(File.dirname(opts[:json_path]))
      File.write(opts[:json_path], "#{JSON.pretty_generate(report)}\n")
      puts "\nWrote benchmark JSON to #{opts[:json_path]}" unless opts[:quiet]
    end

    if opts[:strict]
      failures = strict_failures(report)
      if failures.any?
        warn "\nSTRICT CHECK FAILED:\n  - #{failures.join("\n  - ")}"
        exit(1)
      end
    end
  end
end

GrammarBench.run(ARGV) if __FILE__ == $PROGRAM_NAME
