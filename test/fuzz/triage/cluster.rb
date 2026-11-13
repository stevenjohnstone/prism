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
  TIE_EPSILON = 1e-12

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

  def function_weight_multiplier(
    func_name,
    setup_weight: SETUP_FUNCTION_WEIGHT,
    encoding_weight: ENCODING_HELPER_WEIGHT,
    recovery_weight: RECOVERY_FUNCTION_WEIGHT
  )
    if BOILERPLATE_FUNCTIONS.include?(func_name)
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
  end

  def build_edge_idf(
    corpus,
    smoothing: IDF_SMOOTHING,
    setup_weight: SETUP_FUNCTION_WEIGHT,
    encoding_weight: ENCODING_HELPER_WEIGHT,
    recovery_weight: RECOVERY_FUNCTION_WEIGHT
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

    edge_functions.each do |edge_id, func_name|
      mult = function_weight_multiplier(
        func_name,
        setup_weight: setup_weight,
        encoding_weight: encoding_weight,
        recovery_weight: recovery_weight
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

  def extract_frame_vector(frames, frame_decay: FRAME_DECAY)
    vec = {}
    prism_frames = Array(frames).select do |f|
      f.is_a?(Hash) &&
        f["scope"] == "prism" &&
        !f["func"].to_s.empty? &&
        !VISITOR_FUNCTIONS.include?(f["func"])
    end

    prism_frames.each_with_index do |frame, depth|
      file = frame["file"].to_s
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

  def build_bucket_feature(bucket, cov_model, corpus_edge_df, frame_decay: FRAME_DECAY)
    cov_vec, cov_norm2, cov_available = extract_coverage_vector(bucket, cov_model, corpus_edge_df)
    frame_vec, frame_norm2, top_frame = extract_frame_vector(bucket["frames"], frame_decay: frame_decay)
    occ = bucket.dig("occurrences", "count").to_i
    min_size = bucket.dig("input", "min_size_bytes")

    {
      id: bucket["bucket_id"].to_s,
      reason: bucket["reason"].to_s,
      signature: bucket["signature"].to_s,
      occurrences: occ,
      min_size_bytes: min_size,
      headline: bucket.dig("symptom", "headline").to_s,
      cov_vec: cov_vec,
      cov_norm2: cov_norm2,
      cov_available: cov_available,
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

  def pair_similarity(
    a,
    b,
    reason_weight: DEFAULT_REASON_WEIGHT,
    frame_blend: FRAME_BLEND_WEIGHT,
    mismatch_penalty: FRAME_MISMATCH_PENALTY
  )
    has_fa = a[:frame_norm2] > 0.0
    has_fb = b[:frame_norm2] > 0.0
    cov_both = a[:cov_available] && b[:cov_available]
    scov = cov_both ? coverage_similarity(a, b) : 0.0

    evidence =
      if has_fa && has_fb
        sfrm = frame_similarity(a, b)
        cov_both ? (frame_blend * sfrm + (1.0 - frame_blend) * scov) : sfrm
      elsif !has_fa && !has_fb
        scov
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

  def best_upgma_merge(active, pair_sum, features)
    best = nil

    (0...active.size).each do |i|
      ci = active[i]
      uid_i = ci[:uid]
      size_i = ci[:members].size
      row_i = pair_sum[uid_i]

      (i + 1...active.size).each do |j|
        cj = active[j]
        avg_sim = row_i[cj[:uid]] / (size_i * cj[:members].size).to_f
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

  def format_bucket_entry(feature)
    {
      "bucket_id" => feature[:id],
      "reason" => feature[:reason],
      "signature" => feature[:signature],
      "occurrences" => feature[:occurrences],
      "min_size_bytes" => feature[:min_size_bytes],
      "headline" => feature[:headline],
      "top_prism_frame" => feature[:top_prism_frame]
    }
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

  def cluster_metadata(
    metadata,
    threshold: DEFAULT_THRESHOLD,
    reason_weight: DEFAULT_REASON_WEIGHT,
    idf_smoothing: IDF_SMOOTHING,
    frame_decay: FRAME_DECAY,
    frame_blend: FRAME_BLEND_WEIGHT,
    mismatch_penalty: FRAME_MISMATCH_PENALTY,
    setup_weight: SETUP_FUNCTION_WEIGHT,
    encoding_weight: ENCODING_HELPER_WEIGHT,
    recovery_weight: RECOVERY_FUNCTION_WEIGHT,
    include_unreproducible: false,
    metadata_path: DEFAULT_METADATA_PATH
  )
    raise ArgumentError, "threshold must be between 0.0 and 1.0" unless threshold >= 0.0 && threshold <= 1.0
    raise ArgumentError, "reason_weight must be between 0.0 and 1.0" unless reason_weight >= 0.0 && reason_weight <= 1.0

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

    corpus = metadata["corpus"].is_a?(Hash) ? metadata["corpus"] : {}
    corpus_edge_df = corpus["edge_df"].is_a?(Hash) ? corpus["edge_df"] : {}
    cov_model = build_edge_idf(
      corpus,
      smoothing: idf_smoothing,
      setup_weight: setup_weight,
      encoding_weight: encoding_weight,
      recovery_weight: recovery_weight
    )

    features = filtered.map { |b| build_bucket_feature(b, cov_model, corpus_edge_df, frame_decay: frame_decay) }
    sim_matrix = compute_similarity_matrix(
      features,
      reason_weight: reason_weight,
      frame_blend: frame_blend,
      mismatch_penalty: mismatch_penalty
    )

    n = features.size
    active = Array.new(n) do |idx|
      { uid: idx, members: [idx], min_merge_sim: 1.0, canon: features[idx][:id] }
    end
    pair_sum = Array.new(n) { |i| sim_matrix[i].dup }

    merge_similarities = []
    while active.size > 1
      best = best_upgma_merge(active, pair_sum, features)
      break if best.nil? || best[:sim] < threshold

      merge_similarities << best[:sim]
      ci = active[best[:i]]
      cj = active[best[:j]]
      uid_i = ci[:uid]
      uid_j = cj[:uid]

      ci[:members].concat(cj[:members])
      ci[:min_merge_sim] = [ci[:min_merge_sim], best[:sim]].min
      ci[:canon] = cj[:canon] if cj[:canon] < ci[:canon]

      active.delete_at(best[:j])
      active.each do |ck|
        uid_k = ck[:uid]
        next if uid_k == uid_i

        combined = pair_sum[uid_i][uid_k] + pair_sum[uid_j][uid_k]
        pair_sum[uid_i][uid_k] = combined
        pair_sum[uid_k][uid_i] = combined
      end
    end

    # Sort finalized clusters deterministically before computing IDs and inter-cluster neighbors.
    built_clusters = active.map do |c|
      member_feats = c[:members].map { |idx| features[idx] }
      rep = member_feats.min_by { |f| representative_sort_key(f) }
      occ = member_feats.sum { |f| f[:occurrences] }
      reasons = Hash.new(0)
      member_feats.each { |f| reasons[f[:reason]] += 1 }
      sorted_members = member_feats.sort_by { |f| [-f[:occurrences], f[:id]] }

      {
        raw_cluster: c,
        occurrences: occ,
        bucket_count: member_feats.size,
        reasons: reasons.sort.to_h,
        representative: rep,
        min_merge_similarity: c[:min_merge_sim],
        mean_pairwise_similarity: cluster_mean_similarity(c[:members], sim_matrix),
        buckets: sorted_members.map { |f| format_bucket_entry(f) }
      }
    end

    built_clusters.sort_by! do |entry|
      [-entry[:occurrences], -entry[:bucket_count], entry[:representative][:id]]
    end

    id_width = [2, built_clusters.size.to_s.length].max
    clusters_json = built_clusters.each_with_index.map do |entry, idx|
      cid = format("cluster-%0*d", id_width, idx + 1)
      entry[:cluster_id] = cid
      {
        "cluster_id" => cid,
        "bucket_count" => entry[:bucket_count],
        "occurrences" => entry[:occurrences],
        "reasons" => entry[:reasons],
        "representative" => format_bucket_entry(entry[:representative]),
        "min_merge_similarity" => entry[:min_merge_similarity].round(6),
        "mean_pairwise_similarity" => entry[:mean_pairwise_similarity].round(6),
        "buckets" => entry[:buckets]
      }
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

    {
      "schema_version" => SCHEMA_VERSION,
      "generated_at" => Time.now.utc.iso8601,
      "metadata_path" => metadata_path,
      "algorithm" => {
        "method" => "upgma",
        "coverage_metric" => "weighted_jaccard",
        "threshold" => threshold,
        "reason_weight" => reason_weight,
        "idf_smoothing" => idf_smoothing,
        "frame_decay" => frame_decay,
        "frame_blend_weight" => frame_blend,
        "frame_mismatch_penalty" => mismatch_penalty,
        "setup_function_weight" => setup_weight,
        "encoding_helper_weight" => encoding_weight,
        "recovery_function_weight" => recovery_weight,
        "corpus_count" => corpus["corpus_count"].to_i,
        "filtered_boilerplate_functions" => BOILERPLATE_FUNCTIONS,
        "filtered_setup_functions" => SETUP_FUNCTIONS,
        "downweighted_encoding_functions" => ENCODING_HELPER_FUNCTIONS,
        "downweighted_recovery_functions" => RECOVERY_FUNCTIONS
      },
      "summary" => {
        "bucket_count" => features.size,
        "excluded_unreproducible" => excluded_unreproducible,
        "cluster_count" => clusters_json.size,
        "total_occurrences" => total_occurrences,
        "singleton_clusters" => clusters_json.count { |c| c["bucket_count"] == 1 },
        "min_intra_merge_similarity" => min_intra,
        "max_inter_cluster_similarity" => max_inter,
        "nearest_inter_cluster_pairs" => inter_pairs.first(5)
      },
      "clusters" => clusters_json
    }
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

    lines << format("%-12s %7s %8s  %-26s  %s", "Cluster", "Buckets", "Occur", "Reasons", "Representative")
    lines << ("-" * 100)
    clusters.each do |c|
      reasons_str = c["reasons"].map { |r, n| "#{r}=#{n}" }.join(",")
      rep = c["representative"]
      headline = rep["headline"].to_s.tr("\n", " ")
      headline = "#{headline[0, 52]}..." if headline.length > 55
      lines << format(
        "%-12s %7d %8d  %-26s  %s  %s",
        c["cluster_id"],
        c["bucket_count"],
        c["occurrences"],
        reasons_str,
        rep["bucket_id"],
        headline
      )
    end

    lines << ""
    margin_info = []
    margin_info << "min_merge=#{summary['min_intra_merge_similarity']}" if summary["min_intra_merge_similarity"]
    margin_info << "max_inter=#{summary['max_inter_cluster_similarity']}" if summary["max_inter_cluster_similarity"]
    margin_suffix = margin_info.empty? ? "" : ", #{margin_info.join(', ')}"
    excl_suffix = summary["excluded_unreproducible"].to_i > 0 ? ", excluded_unrepro=#{summary['excluded_unreproducible']}" : ""
    lines << "Summary: #{summary['bucket_count']} buckets (#{summary['total_occurrences']} occurrences) -> " \
             "#{summary['cluster_count']} clusters (threshold=#{algo['threshold']}, reason_weight=#{algo['reason_weight']}" \
             "#{margin_suffix}#{excl_suffix})"
    lines.join("\n")
  end
end

if __FILE__ == $PROGRAM_NAME
  options = {
    metadata: ENV.fetch("TRIAGE_METADATA", FuzzClustering::DEFAULT_METADATA_PATH),
    output: ENV.fetch("CLUSTER_OUTPUT", FuzzClustering::DEFAULT_OUTPUT_PATH),
    threshold: Float(ENV.fetch("CLUSTER_THRESHOLD", FuzzClustering::DEFAULT_THRESHOLD.to_s)),
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

