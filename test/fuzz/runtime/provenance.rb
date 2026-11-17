#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "time"

module FuzzProvenance
  BINARIES = %w[
    fuzz
    fuzz.cmplog
    fuzz.msan
    fuzz.lsan
    fuzz.ijon
    fuzz.native
    fuzz.slow
    fuzz.sand
    fuzz.diff
  ].freeze

  AUX_FILES = %w[fuzz.ids].freeze
  REPRO_DIR_ENTRIES = %w[fuzz-ruby-ext].freeze
  GIT_DIRTY_PATHS = %w[src include templates test/fuzz/harness].freeze
  MARKER_REGEX = /@\(#\)PRISM_FUZZ_PROVENANCE\t([^\n\0]+)/

  CACHE_MUTEX = Mutex.new
  EMBEDDED_CACHE = {}
  DIFF_VERSION_CACHE = {}
  GIT_STATE_CACHE = {}
  SHA256_CACHE = {}
  MANIFEST_CACHE = {}
  CONTAINER_CACHE = {}

  module_function

  def locate_repo_root(start_dir = nil)
    candidates = [
      start_dir,
      Dir.pwd,
      (__dir__ ? File.expand_path("../../..", __dir__) : nil)
    ].compact.uniq

    candidates.each do |dir|
      cur = File.expand_path(dir)
      loop do
        return cur if File.file?(File.join(cur, "include/prism/version.h"))

        parent = File.dirname(cur)
        break if parent == cur

        cur = parent
      end
    end
    nil
  end

  def normalize_path(path, repo_root = locate_repo_root)
    return nil if path.nil? || path.to_s.empty?

    str = path.to_s
    return str unless repo_root

    expanded = File.expand_path(str)
    prefix = "#{File.expand_path(repo_root)}/"
    expanded.start_with?(prefix) ? expanded.delete_prefix(prefix) : str
  rescue StandardError
    path.to_s
  end

  def utf8_safe(text)
    text.to_s.encode("UTF-8", invalid: :replace, undef: :replace, replace: "\uFFFD")
  end

  def stat_cache_key(path)
    st = File.stat(path)
    [File.expand_path(path), st.size, st.mtime.to_i, st.mtime.nsec]
  end

  def binary_sha256(path)
    return nil if path.nil? || path.empty? || !File.file?(path)

    key = stat_cache_key(path)
    cached = CACHE_MUTEX.synchronize { SHA256_CACHE[key] }
    return cached if cached

    digest = Digest::SHA256.file(path).hexdigest
    CACHE_MUTEX.synchronize { SHA256_CACHE[key] = digest }
  rescue StandardError
    nil
  end

  def native_executable_magic?(path)
    File.open(path, "rb") do |f|
      magic = f.read(4)
      return false unless magic && magic.bytesize == 4

      bytes = magic.bytes
      magic == "\x7fELF".b ||
        bytes == [0xfe, 0xed, 0xfa, 0xce] ||
        bytes == [0xce, 0xfa, 0xed, 0xfe] ||
        bytes == [0xfe, 0xed, 0xfa, 0xcf] ||
        bytes == [0xcf, 0xfa, 0xed, 0xfe] ||
        bytes == [0xca, 0xfe, 0xba, 0xbe]
    end
  rescue StandardError
    false
  end

  def read_prism_header_version(repo_root = locate_repo_root)
    return nil unless repo_root

    header = File.join(repo_root, "include/prism/version.h")
    return nil unless File.file?(header)

    File.read(header, encoding: "BINARY")[/^\s*#\s*define\s+PRISM_VERSION\s+"([^"]+)"/, 1]
  rescue StandardError
    nil
  end

  def detect_git_state(repo_root = locate_repo_root, paths: GIT_DIRTY_PATHS)
    return nil unless repo_root

    cache_key = [File.expand_path(repo_root), paths]
    CACHE_MUTEX.synchronize do
      return GIT_STATE_CACHE[cache_key] if GIT_STATE_CACHE.key?(cache_key)

      commit_out, commit_st = Open3.capture2e("git", "-C", repo_root, "rev-parse", "HEAD")
      unless commit_st.success? && commit_out.strip =~ /\A[0-9a-f]{40}\z/i
        GIT_STATE_CACHE[cache_key] = nil
        return nil
      end

      commit = commit_out.strip
      status_cmd = ["git", "-C", repo_root, "status", "--porcelain", "--", *paths]
      status_out, status_st = Open3.capture2e(*status_cmd)
      dirty = status_st.success? ? !status_out.strip.empty? : nil

      GIT_STATE_CACHE[cache_key] = {
        "git_commit" => commit,
        "git_short" => commit[0, 9],
        "git_dirty" => dirty
      }.compact
    end
  rescue StandardError
    nil
  end

  def parse_bool_token(val)
    case val
    when "1", "true" then true
    when "0", "false" then false
    end
  end

  def read_embedded_binary_provenance(bin_path)
    return nil if bin_path.nil? || bin_path.empty? || !File.file?(bin_path)

    key = stat_cache_key(bin_path)
    cached = CACHE_MUTEX.synchronize { EMBEDDED_CACHE.fetch(key, :miss) }
    return cached unless cached == :miss

    raw = File.binread(bin_path)
    matches = raw.scan(MARKER_REGEX)
    parsed = nil
    unless matches.empty?
      kv = {}
      matches.last.first.split("\t").each do |entry|
        k, v = entry.split("=", 2)
        next unless k && v && !v.empty? && v != "unknown"

        kv[k] = v
      end

      commit = kv["git_commit"]
      dirty = parse_bool_token(kv["git_dirty"])
      prism_info = {
        "version" => kv["prism"],
        "git_commit" => commit,
        "git_short" => commit && !commit.empty? ? commit[0, 9] : nil,
        "git_dirty" => dirty,
        "source" => "embedded"
      }.compact
      prism_info.delete("source") if prism_info.size == 1

      ruby_info = {
        "version" => kv["ruby_version"],
        "revision" => kv["ruby_revision"],
        "release_date" => kv["ruby_release_date"]
      }.compact

      result = {}
      result["prism"] = prism_info unless prism_info.empty?
      result["ruby_parse_y"] = ruby_info unless ruby_info.empty?
      parsed = result unless result.empty?
    end

    CACHE_MUTEX.synchronize { EMBEDDED_CACHE[key] = parsed }
  rescue StandardError
    nil
  end

  def probe_diff_binary_versions(bin_path)
    return nil if bin_path.nil? || bin_path.empty?
    return nil unless File.file?(bin_path) && File.executable?(bin_path) && native_executable_magic?(bin_path)

    key = stat_cache_key(bin_path)
    cached = CACHE_MUTEX.synchronize { DIFF_VERSION_CACHE.fetch(key, :miss) }
    return cached unless cached == :miss

    out, status = Open3.capture2e(bin_path, "--version")
    parsed = nil
    if status.success?
      kv = {}
      utf8_safe(out).each_line do |line|
        k, v = line.strip.split("=", 2)
        kv[k] = v if k && v && !v.empty? && v != "unknown"
      end
      parsed = kv if kv["prism"] && kv["ruby_version"]
    end
    CACHE_MUTEX.synchronize { DIFF_VERSION_CACHE[key] = parsed }
  rescue StandardError
    nil
  end

  def detect_oracle_dir_versions(oracle_dir = ENV["RUBY_ORACLE_DIR"])
    dir = (oracle_dir && !oracle_dir.strip.empty?) ? oracle_dir.strip : "/opt/ruby"
    return nil unless File.directory?(dir)

    inc_ver_path = File.join(dir, "include/ruby/version.h")
    top_ver_path = File.join(dir, "version.h")
    rev_path = File.join(dir, "revision.h")

    version = nil
    release_date = nil
    revision = nil

    if File.file?(inc_ver_path) && File.file?(top_ver_path)
      inc_ver = File.read(inc_ver_path, encoding: "BINARY")
      top_ver = File.read(top_ver_path, encoding: "BINARY")
      maj = inc_ver[/^\s*#\s*define\s+RUBY_API_VERSION_MAJOR\s+(\d+)/, 1]
      min = inc_ver[/^\s*#\s*define\s+RUBY_API_VERSION_MINOR\s+(\d+)/, 1]
      teeny = top_ver[/^\s*#\s*define\s+RUBY_VERSION_TEENY\s+(\d+)/, 1] ||
              inc_ver[/^\s*#\s*define\s+RUBY_API_VERSION_TEENY\s+(\d+)/, 1]
      version = "#{maj}.#{min}.#{teeny}" if maj && min && teeny
    end

    if File.file?(rev_path)
      rev_src = File.read(rev_path, encoding: "BINARY")
      revision = rev_src[/^\s*#\s*define\s+RUBY_FULL_REVISION\s+"([^"]+)"/, 1] ||
                 rev_src[/^\s*#\s*define\s+RUBY_REVISION\s+"([^"]+)"/, 1]
      y = rev_src[/^\s*#\s*define\s+RUBY_RELEASE_YEAR\s+(\d+)/, 1]
      m = rev_src[/^\s*#\s*define\s+RUBY_RELEASE_MONTH\s+(\d+)/, 1]
      d = rev_src[/^\s*#\s*define\s+RUBY_RELEASE_DAY\s+(\d+)/, 1]
      release_date = format("%04d-%02d-%02d", y.to_i, m.to_i, d.to_i) if y && m && d
    end

    {
      "oracle_dir" => dir,
      "version" => version,
      "revision" => revision,
      "release_date" => release_date
    }.compact
  rescue StandardError
    nil
  end

  def find_in_path(cmd)
    ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |dir|
      next if dir.empty?

      cand = File.join(dir, cmd)
      return cand if File.file?(cand) && File.executable?(cand)
    end
    nil
  end

  def collect_container_provenance(repo_root: locate_repo_root)
    image_id = ENV["FUZZ_IMAGE_ID"].to_s.strip
    cache_key = [repo_root ? File.expand_path(repo_root) : nil, image_id, ENV["LLVM_VERSION"].to_s]

    cached = CACHE_MUTEX.synchronize { CONTAINER_CACHE.fetch(cache_key, :miss) }
    return cached unless cached == :miss

    os_name = nil
    if File.file?("/etc/os-release")
      os_rel = utf8_safe(File.read("/etc/os-release"))
      os_name = os_rel[/^PRETTY_NAME="([^"]+)"/, 1] ||
                os_rel[/^PRETTY_NAME=([^\s#]+)/, 1]
    end
    os_name ||= RbConfig::CONFIG["host_os"]

    clang_ver = nil
    if find_in_path("clang")
      out, st = Open3.capture2e("clang", "--version")
      clang_ver = utf8_safe(out).gsub(/\e\[[0-9;]*m/, "").lines.first&.strip if st.success?
    end

    afl_ver = nil
    if find_in_path("afl-fuzz")
      out, = Open3.capture2e("afl-fuzz", "-h")
      first = utf8_safe(out).gsub(/\e\[[0-9;]*m/, "").lines.find { |l| !l.strip.empty? }&.strip
      afl_ver = first if first && !first.empty?
    end

    afl_patch_sha256 = nil
    if repo_root
      patch_path = File.join(repo_root, "test/fuzz/patches/aflplusplus.patch")
      afl_patch_sha256 = binary_sha256(patch_path) if File.file?(patch_path)
    end

    lrama_ver = begin
      Gem::Specification.find_by_name("lrama-fuzz").version.to_s
    rescue StandardError
      nil
    end

    llvm_ver = ENV["LLVM_VERSION"].to_s.strip
    info = {
      "image_id" => image_id.empty? ? nil : image_id,
      "os" => os_name,
      "arch" => RbConfig::CONFIG["host_cpu"],
      "clang" => clang_ver,
      "llvm_version" => llvm_ver.empty? ? nil : llvm_ver,
      "aflplusplus" => afl_ver,
      "afl_patch_sha256" => afl_patch_sha256,
      "ruby" => defined?(RUBY_DESCRIPTION) ? RUBY_DESCRIPTION : nil,
      "lrama_fuzz" => lrama_ver
    }.compact

    result = info.empty? ? nil : info
    CACHE_MUTEX.synchronize { CONTAINER_CACHE[cache_key] = result }
  rescue StandardError
    nil
  end

  def read_manifest(manifest_path)
    return nil if manifest_path.nil? || manifest_path.empty? || !File.file?(manifest_path)

    key = stat_cache_key(manifest_path)
    cached = CACHE_MUTEX.synchronize { MANIFEST_CACHE.fetch(key, :miss) }
    return cached unless cached == :miss

    data = JSON.parse(File.read(manifest_path))
    data = nil unless data.is_a?(Hash)
    CACHE_MUTEX.synchronize { MANIFEST_CACHE[key] = data }
  rescue StandardError
    nil
  end

  def find_manifest_for_bin_dir(bin_dir)
    return nil if bin_dir.nil? || bin_dir.empty? || !File.directory?(bin_dir)

    [
      File.join(bin_dir, "versions.json"),
      File.join(bin_dir, "fuzz.versions.json")
    ].each do |cand|
      m = read_manifest(cand)
      return m if m
    end
    nil
  end

  def write_json_atomic(path, data)
    dir = File.dirname(path)
    FileUtils.mkdir_p(dir)
    tmp_path = File.join(dir, ".#{File.basename(path)}.tmp.#{Process.pid}.#{Thread.current.object_id}")
    File.write(tmp_path, "#{JSON.pretty_generate(data)}\n")
    File.chmod(0o666 & ~File.umask, tmp_path)
    File.rename(tmp_path, path)
  ensure
    FileUtils.rm_f(tmp_path) if tmp_path && File.exist?(tmp_path)
  end

  def summarize_dir_binaries(bin_dir)
    out = {}
    (BINARIES + AUX_FILES).each do |name|
      p = File.join(bin_dir, name)
      next unless File.file?(p)

      entry = {
        "sha256" => binary_sha256(p),
        "size_bytes" => File.size(p)
      }
      if BINARIES.include?(name)
        emb = read_embedded_binary_provenance(p)
        entry["embedded"] = emb if emb
      end
      out[name] = entry
    end
    out
  end

  def resolve_dir_provenance(bin_dir, repo_root: locate_repo_root, fallback_live_git: true, fallback_live_container: true, use_manifest: true)
    manifest = use_manifest ? find_manifest_for_bin_dir(bin_dir) : nil
    bins = summarize_dir_binaries(bin_dir)
    diff_bin = File.join(bin_dir, "fuzz.diff")

    manifest_matches = manifest && !bins.empty? && bins.all? do |name, info|
      m_sha = manifest.dig("binaries", name, "sha256")
      m_sha && m_sha == info["sha256"]
    end

    embedded_prism = nil
    embedded_ruby = nil
    bins.each_value do |info|
      emb = info["embedded"]
      next unless emb.is_a?(Hash)

      embedded_prism ||= emb["prism"] if emb["prism"].is_a?(Hash)
      embedded_ruby ||= emb["ruby_parse_y"] if emb["ruby_parse_y"].is_a?(Hash)
    end

    prism_info = if embedded_prism
                   embedded_prism.dup
                 elsif manifest_matches && manifest["prism"].is_a?(Hash)
                   manifest["prism"].merge("source" => "manifest")
                 else
                   ver = read_prism_header_version(repo_root)
                   git_info = fallback_live_git ? detect_git_state(repo_root) : nil
                   p_hash = {
                     "version" => ver,
                     "git_commit" => git_info&.dig("git_commit"),
                     "git_short" => git_info&.dig("git_short"),
                     "git_dirty" => git_info&.dig("git_dirty"),
                     "source" => "live_git"
                   }.compact
                   p_hash.delete("source") if p_hash.size == 1
                   p_hash
                 end

    probe = File.file?(diff_bin) ? probe_diff_binary_versions(diff_bin) : nil
    oracle_info = nil
    if probe || embedded_ruby || (manifest_matches && manifest["ruby_parse_y"].is_a?(Hash))
      oracle_info = detect_oracle_dir_versions
    end

    if probe && prism_info["git_commit"].nil? && probe["git_commit"]
      prism_info["git_commit"] = probe["git_commit"]
      prism_info["git_short"] = probe["git_commit"][0, 9]
      dirty = parse_bool_token(probe["git_dirty"])
      prism_info["git_dirty"] = dirty unless dirty.nil?
      prism_info["version"] ||= probe["prism"]
      prism_info["source"] = "binary_version"
    end

    manifest_ruby = (manifest_matches && manifest["ruby_parse_y"].is_a?(Hash)) ? manifest["ruby_parse_y"] : {}
    ruby_info = {
      "version" => probe&.dig("ruby_version") || embedded_ruby&.dig("version") || manifest_ruby["version"] || oracle_info&.dig("version"),
      "revision" => probe&.dig("ruby_description")&.[](/\brevision ([0-9a-f]+)\b/, 1) ||
                    embedded_ruby&.dig("revision") || manifest_ruby["revision"] || oracle_info&.dig("revision"),
      "release_date" => probe&.dig("ruby_release_date") || embedded_ruby&.dig("release_date") || manifest_ruby["release_date"] || oracle_info&.dig("release_date"),
      "description" => probe&.dig("ruby_description") || manifest_ruby["description"],
      "oracle_dir" => manifest_ruby["oracle_dir"] || oracle_info&.dig("oracle_dir")
    }.compact

    container_info = if manifest_matches && manifest["container"].is_a?(Hash) && !manifest["container"].empty?
                       manifest["container"]
                     elsif fallback_live_container
                       collect_container_provenance(repo_root: repo_root)
                     end

    payload = {
      "schema_version" => 1,
      "prism" => prism_info.empty? ? nil : prism_info,
      "ruby_parse_y" => ruby_info.empty? ? nil : ruby_info,
      "container" => container_info,
      "binaries" => bins.empty? ? nil : bins
    }.compact
    payload
  end

  def write_build_manifest(build_dir, repo_root: locate_repo_root)
    payload = resolve_dir_provenance(build_dir, repo_root: repo_root, use_manifest: false)
    payload["built_at"] = Time.now.utc.iso8601
    if payload["ruby_parse_y"].nil?
      oracle = detect_oracle_dir_versions
      payload["ruby_parse_y"] = oracle if oracle && !oracle.empty?
    end
    out_path = File.join(build_dir, "fuzz.versions.json")
    write_json_atomic(out_path, payload)
    out_path
  end

  def snapshot_build_to_bin(src_build_dir, dst_bin_dir, repo_root: locate_repo_root)
    FileUtils.mkdir_p(File.dirname(dst_bin_dir))
    staging_dir = File.join(File.dirname(dst_bin_dir), ".bin.staging.#{Process.pid}")
    old_dir = File.join(File.dirname(dst_bin_dir), ".bin.old.#{Process.pid}")
    FileUtils.rm_rf(staging_dir)
    FileUtils.rm_rf(old_dir)
    FileUtils.mkdir_p(staging_dir)

    copied = []
    (BINARIES + AUX_FILES).each do |name|
      src = File.join(src_build_dir, name)
      next unless File.file?(src)

      FileUtils.cp(src, File.join(staging_dir, name), preserve: true)
      copied << name
    end

    REPRO_DIR_ENTRIES.each do |dir_name|
      src_sub = File.join(src_build_dir, dir_name)
      next unless File.directory?(src_sub)

      FileUtils.cp_r(src_sub, File.join(staging_dir, dir_name), preserve: true)
    end

    src_manifest = File.join(src_build_dir, "fuzz.versions.json")
    src_m_data = read_manifest(src_manifest)
    bins = summarize_dir_binaries(staging_dir)

    manifest_matches = src_m_data && !bins.empty? && bins.all? do |name, info|
      m_sha = src_m_data.dig("binaries", name, "sha256")
      m_sha && m_sha == info["sha256"]
    end

    provenance = if manifest_matches
                   src_m_data.dup
                 else
                   resolve_dir_provenance(staging_dir, repo_root: repo_root)
                 end

    provenance["started_at"] = Time.now.utc.iso8601
    provenance["source_build_dir"] = normalize_path(src_build_dir, repo_root)
    provenance["snapshot_bin_dir"] = normalize_path(dst_bin_dir, repo_root)
    provenance["fuzz_workers"] = ENV["FUZZ_WORKERS"] if ENV["FUZZ_WORKERS"] && !ENV["FUZZ_WORKERS"].empty?
    provenance["max_input_size"] = ENV["FUZZ_MAX_INPUT_SIZE"] if ENV["FUZZ_MAX_INPUT_SIZE"] && !ENV["FUZZ_MAX_INPUT_SIZE"].empty?

    write_json_atomic(File.join(staging_dir, "versions.json"), provenance)

    File.rename(dst_bin_dir, old_dir) if File.exist?(dst_bin_dir)
    File.rename(staging_dir, dst_bin_dir)
    FileUtils.rm_rf(old_dir) if File.exist?(old_dir)

    File.join(dst_bin_dir, "versions.json")
  ensure
    FileUtils.rm_rf(staging_dir) if staging_dir && File.exist?(staging_dir)
    FileUtils.rm_rf(old_dir) if old_dir && File.exist?(old_dir) && !File.exist?(dst_bin_dir)
  end

  def resolve_binary_provenance(bin_path, is_diff: false, target_ruby_version: nil, include_ruby_oracle: is_diff, repo_root: locate_repo_root)
    exe_str = bin_path.to_s
    exe_exists = !exe_str.empty? && File.file?(exe_str)
    bin_dir = exe_exists ? File.dirname(exe_str) : nil
    bin_name = exe_exists ? File.basename(exe_str) : nil
    manifest = find_manifest_for_bin_dir(bin_dir)
    build_id = exe_exists ? binary_sha256(exe_str) : nil
    manifest_matches = manifest && build_id && manifest.dig("binaries", bin_name, "sha256") == build_id

    embedded = exe_exists ? read_embedded_binary_provenance(exe_str) : nil

    diff_probe_bin = if (is_diff || exe_str.end_with?("diff") || bin_name == "fuzz.diff") && exe_exists
                       exe_str
                     elsif include_ruby_oracle && bin_dir && File.file?(File.join(bin_dir, "fuzz.diff"))
                       File.join(bin_dir, "fuzz.diff")
                     elsif include_ruby_oracle && File.file?("./tmp/fuzz/bin/fuzz.diff")
                       "./tmp/fuzz/bin/fuzz.diff"
                     elsif include_ruby_oracle && File.file?("./build/fuzz.diff")
                       "./build/fuzz.diff"
                     elsif include_ruby_oracle && repo_root && File.file?(File.join(repo_root, "build/fuzz.diff"))
                       File.join(repo_root, "build/fuzz.diff")
                     end
    probe = diff_probe_bin ? probe_diff_binary_versions(diff_probe_bin) : nil
    diff_embedded = diff_probe_bin ? read_embedded_binary_provenance(diff_probe_bin) : nil

    prism_info = nil
    if embedded && embedded["prism"]
      prism_info = embedded["prism"].dup
      if manifest_matches && manifest.dig("prism", "git_commit") && prism_info["git_commit"].nil?
        prism_info["git_commit"] = manifest.dig("prism", "git_commit")
        prism_info["git_short"] = manifest.dig("prism", "git_short")
        prism_info["git_dirty"] = manifest.dig("prism", "git_dirty") unless manifest.dig("prism", "git_dirty").nil?
      end
    elsif manifest_matches && manifest["prism"].is_a?(Hash)
      prism_info = manifest["prism"].dup
      prism_info["source"] = "manifest"
    elsif probe && probe["git_commit"]
      dirty = parse_bool_token(probe["git_dirty"])
      prism_info = {
        "version" => probe["prism"] || read_prism_header_version(repo_root),
        "git_commit" => probe["git_commit"],
        "git_short" => probe["git_commit"][0, 9],
        "git_dirty" => dirty,
        "source" => "binary_version"
      }.compact
    else
      git_info = detect_git_state(repo_root)
      prism_info = {
        "version" => probe&.dig("prism") || read_prism_header_version(repo_root),
        "git_commit" => git_info&.dig("git_commit"),
        "git_short" => git_info&.dig("git_short"),
        "git_dirty" => git_info&.dig("git_dirty"),
        "source" => git_info ? "live_git" : nil
      }.compact
    end
    prism_info["target_ruby_version"] = target_ruby_version if target_ruby_version && !target_ruby_version.to_s.empty?
    prism_info = nil if prism_info.empty?

    ruby_info = nil
    if include_ruby_oracle || is_diff
      manifest_ruby = (manifest_matches && manifest["ruby_parse_y"].is_a?(Hash)) ? manifest["ruby_parse_y"] : {}
      emb_ruby = embedded&.dig("ruby_parse_y") || diff_embedded&.dig("ruby_parse_y") || {}
      oracle_info = detect_oracle_dir_versions
      desc = probe&.dig("ruby_description") || manifest_ruby["description"]
      rev = desc&.[](/\brevision ([0-9a-f]+)\b/, 1) || emb_ruby["revision"] || manifest_ruby["revision"] || oracle_info&.dig("revision")

      ruby_info = {
        "version" => probe&.dig("ruby_version") || emb_ruby["version"] || manifest_ruby["version"] || oracle_info&.dig("version"),
        "revision" => rev,
        "release_date" => probe&.dig("ruby_release_date") || emb_ruby["release_date"] || manifest_ruby["release_date"] || oracle_info&.dig("release_date"),
        "description" => desc,
        "oracle_dir" => manifest_ruby["oracle_dir"] || oracle_info&.dig("oracle_dir")
      }.compact
      ruby_info = nil if ruby_info.empty?
    end

    container_info = if manifest_matches && manifest["container"].is_a?(Hash) && !manifest["container"].empty?
                       manifest["container"]
                     else
                       collect_container_provenance(repo_root: repo_root)
                     end

    out = {
      "binary" => exe_str.empty? ? nil : normalize_path(exe_str, repo_root),
      "build_id" => build_id,
      "prism" => prism_info,
      "ruby_parse_y" => ruby_info,
      "container" => container_info
    }.compact
    out.empty? ? nil : out
  end
end

if __FILE__ == $PROGRAM_NAME
  cmd = ARGV.shift
  case cmd
  when "write-build"
    build_dir = ARGV[0] || "./build"
    puts FuzzProvenance.write_build_manifest(build_dir)
  when "snapshot"
    src_dir = ARGV[0] || "./build"
    dst_dir = ARGV[1] || "./tmp/fuzz/bin"
    puts FuzzProvenance.snapshot_build_to_bin(src_dir, dst_dir)
  when "show-container"
    puts JSON.pretty_generate(FuzzProvenance.collect_container_provenance || {})
  else
    warn "Usage: #{$PROGRAM_NAME} {write-build [DIR]|snapshot [SRC DST]|show-container}"
    exit 2
  end
end
