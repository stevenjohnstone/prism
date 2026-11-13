# frozen_string_literal: true

require "base64"
require "cgi"
require "concurrent"
require "digest"
require "fileutils"
require "json"
require "open3"
require "rubygems/package"
require "set"
require "tempfile"
require "time"
require "tmpdir"
require "zlib"

cluster_lib = [(__dir__ && File.join(__dir__, "cluster.rb")), File.expand_path("test/fuzz/triage/cluster.rb")].compact.find { |p| File.file?(p) }
require cluster_lib if cluster_lib

PRISM_LOUPE_BASE_URL = "https://stevenjohnstone.github.io/prism-loupe/"

OUTPUT_DIRS = ["tmp/fuzz/afl", "tmp/fuzz/afl-ijon"].freeze
TESTCASES_DIR = "tmp/fuzz/triage"
TESTCASES_PROCESSED_DIR = File.join(TESTCASES_DIR, ".processed")
MAX_ALLOCATED_MB = Integer(ENV.fetch("FUZZ_MAX_ALLOCATED", "128"))
HARD_RSS_LIMIT_MB = MAX_ALLOCATED_MB * 16
HALFEMPTY_THREADS = Integer(ENV.fetch("HALFEMPTY_THREADS", "2"))
TRIAGE_THREADS = Integer(ENV.fetch("TRIAGE_THREADS", [Concurrent.processor_count / 2, 1].max.to_s))
COVERAGE_BIN = ENV.fetch("TRIAGE_COVERAGE_BIN", "./build/fuzz")
COVERAGE_IDS_PATH = ENV.fetch("TRIAGE_COVERAGE_IDS", COVERAGE_BIN.empty? ? "" : "#{COVERAGE_BIN}.ids")
CORPUS_DIR = ENV.fetch("TRIAGE_CORPUS_DIR", "tmp/fuzz/corpus")
AFL_SHOWMAP_BIN = ENV.fetch("AFL_SHOWMAP", "afl-showmap")
SHOWMAP_TIMEOUT_MS = Integer(ENV.fetch("TRIAGE_SHOWMAP_TIMEOUT_MS", "1000"))
TRIAGE_RECOUNT = ENV["TRIAGE_RECOUNT"] == "1"
INPUTS_ARCHIVE_FILE = "inputs.tar.gz"
PENDING_INPUTS_FILE = ".inputs.pending"
META_SCHEMA_VERSION = 1

SANITIZER_ENV = {
  "ASAN_OPTIONS" => "abort_on_error=1:handle_abort=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}",
  "UBSAN_OPTIONS" => "abort_on_error=1:print_stacktrace=1",
  "MSAN_OPTIONS" => "abort_on_error=1:handle_abort=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}",
  "LSAN_OPTIONS" => "handle_abort=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}"
}.freeze

FileUtils.mkdir_p(TESTCASES_PROCESSED_DIR) unless ENV["TRIAGE_LIB_ONLY"] == "1"

VERSIONS = ["3.3", "3.4", "3.5", "4.1"].freeze
ENCODINGS = ["UTF-8", "ASCII-8BIT", "US-ASCII", "Windows-31J", "EUC-JP", "UTF-8-MAC", "ISO-8859-1", "Shift_JIS"].freeze
EXTREME_LINES = [2_147_483_647, 2_147_483_643, -2_147_483_648, 0].freeze
EXTREME_LINES_C = ["INT32_MAX", "INT32_MAX - 4", "INT32_MIN", "0"].freeze
STACK_BUDGETS = ["SIZE_MAX", "0", "512", "4096"].freeze
SCOPE_BASE_LOCALS = [["a", "foo"], ["b", "it"], ["c", "_1"]].freeze
DEFAULT_HEADER_BYTES = [0x00, 0x00, 0x03, 0x01].freeze

COMMAND_LINE_FLAGS = [
  [0x01, "PM_OPTIONS_COMMAND_LINE_A"],
  [0x02, "PM_OPTIONS_COMMAND_LINE_E"],
  [0x04, "PM_OPTIONS_COMMAND_LINE_L"],
  [0x08, "PM_OPTIONS_COMMAND_LINE_N"],
  [0x10, "PM_OPTIONS_COMMAND_LINE_P"],
  [0x20, "PM_OPTIONS_COMMAND_LINE_X"]
].freeze

COMMAND_LINE_CHARS = [
  [0x01, "a"],
  [0x02, "e"],
  [0x04, "l"],
  [0x08, "n"],
  [0x10, "p"],
  [0x20, "x"]
].freeze

FORWARDING_FLAGS = [
  [0x01, "PM_OPTIONS_SCOPE_FORWARDING_POSITIONALS"],
  [0x02, "PM_OPTIONS_SCOPE_FORWARDING_KEYWORDS"],
  [0x04, "PM_OPTIONS_SCOPE_FORWARDING_BLOCK"],
  [0x08, "PM_OPTIONS_SCOPE_FORWARDING_ALL"]
].freeze

FORWARDING_CHARS = [
  [0x01, "p"],
  [0x02, "k"],
  [0x04, "b"],
  [0x08, "a"]
].freeze

def escape_c_comment(text)
  text.gsub("*/", "* /")
end

def format_uint8_bitmask(value, flags)
  selected = flags.filter_map { |bit, name| name if (value & bit) != 0 }
  return "0" if selected.empty?
  return selected.first if selected.size == 1

  "(uint8_t)(#{selected.join(' | ')})"
end

def encode_loupe_scope_local(bytes)
  if bytes.match?(/\A[A-Za-z0-9_]+\z/n)
    bytes
  else
    "~#{Base64.urlsafe_encode64(bytes, padding: false)}"
  end
end

def sanitizer_loupe_crash?(reason, crash_output)
  return false if crash_output.include?("INVARIANT[") || crash_output.include?("Assertion `")
  return true if reason == "undefined-behavior"
  return true if crash_output.match?(/SUMMARY: (?:Address|UndefinedBehavior)Sanitizer:/)
  return true if crash_output.match?(/:\d+:\d+: runtime error: |fuzz_(?:free|realloc)_sized/)

  %w[
    heap-buffer-overflow stack-buffer-overflow global-buffer-overflow
    heap-use-after-free stack-use-after-return stack-use-after-scope
    attempting-double-free bad-free alloc-dealloc-mismatch SEGV
  ].include?(reason)
end

# Decodes the 4-byte fuzzer option header consumed by harness() in
# test/fuzz/harness/parse.c into structured fields shared by C reproducers,
# Loupe URLs, and bucket metadata JSON.
def decode_fuzz_header(raw)
  raw = raw.b
  valid_header = raw.bytesize >= 4
  padded_raw = valid_header ? raw : (raw + ("\x00".b * (4 - raw.bytesize)))
  b0, b1, b2, b3 = padded_raw.bytes[0, 4]
  source = raw.bytesize > 4 ? raw.byteslice(4..) : "".b

  freeze = (b0 & 0x01) != 0
  partial_script = (b0 & 0x02) != 0
  attach_comments = (b0 & 0x04) != 0
  encoding_locked = (b0 & 0x08) != 0
  has_frozen_string_literal = (b0 & 0x10) != 0
  frozen_string_literal = (b0 & 0x20) != 0
  stream_mode = (b0 & 0x40) != 0
  has_encoding_opts = (b0 & 0x80) != 0

  cmd_flags = b1 & 0x3f
  main_script = (b1 & 0x40) != 0
  has_limit_opts = (b1 & 0x80) != 0

  version = VERSIONS[b2 & 0x03]
  scopes_count = (b2 >> 2) & 0x03
  forwarding_bits = (b2 >> 4) & 0x0f

  extreme_idx = has_limit_opts ? ((b3 >> 4) & 0x03) : nil
  start_line = has_limit_opts ? EXTREME_LINES[extreme_idx] : [b3].pack("C").unpack1("c")
  start_line_c = has_limit_opts ? EXTREME_LINES_C[extreme_idx] : start_line.to_s
  need_limits = has_limit_opts && extreme_idx != 3
  stack_budget = has_limit_opts ? STACK_BUDGETS[(b3 >> 6) & 0x03] : "SIZE_MAX"

  encoding = has_encoding_opts ? ENCODINGS[b3 & 0x07] : nil
  filepath = has_encoding_opts ? "fuzz.rb" : nil
  shebang_callback = has_encoding_opts && (b3 & 0x08) != 0

  forwarding_scope = scopes_count > 0 ? (has_encoding_opts ? (b3 % scopes_count) : (scopes_count - 1)) : nil
  cmd_chars = COMMAND_LINE_CHARS.filter_map { |bit, ch| ch if (cmd_flags & bit) != 0 }
  fwd_chars = FORWARDING_CHARS.filter_map { |bit, ch| ch if (forwarding_bits & bit) != 0 }
  has_shebang_prefix = source.start_with?("#!".b) || source.start_with?("\xef\xbb\xbf#!".b)

  {
    raw: raw,
    valid_header: valid_header,
    padded_raw: padded_raw,
    header_bytes: [b0, b1, b2, b3],
    b3: b3,
    source: source,
    freeze: freeze,
    partial_script: partial_script,
    attach_comments: attach_comments,
    encoding_locked: encoding_locked,
    has_frozen_string_literal: has_frozen_string_literal,
    frozen_string_literal: frozen_string_literal,
    stream_mode: stream_mode,
    has_encoding_opts: has_encoding_opts,
    cmd_flags: cmd_flags,
    command_line_chars: cmd_chars,
    main_script: main_script,
    has_limit_opts: has_limit_opts,
    extreme_idx: extreme_idx,
    need_limits: need_limits,
    start_line: start_line,
    start_line_c: start_line_c,
    stack_budget: stack_budget,
    version: version,
    scopes_count: scopes_count,
    forwarding_bits: forwarding_bits,
    forwarding_chars: fwd_chars,
    forwarding_scope: forwarding_scope,
    encoding: encoding,
    filepath: filepath,
    shebang_callback: shebang_callback,
    has_shebang_prefix: has_shebang_prefix
  }
end

def build_prism_loupe_url(raw, sanitize: false)
  return nil if raw.nil? || raw.empty?
  if raw.bytesize < 4
    san_part = sanitize ? "&san=1" : ""
    return "#{PRISM_LOUPE_BASE_URL}?code=#{CGI.escape(Base64.strict_encode64(raw))}#{san_part}"
  end

  h = decode_fuzz_header(raw)
  source = h[:source]

  params = [["code", Base64.strict_encode64(source)]]
  params << ["san", "1"] if sanitize
  params << ["enc", h[:encoding]] if h[:has_encoding_opts]
  params << ["ruby_ver", h[:version]]
  params << ["line", h[:start_line].to_s] if h[:start_line] != 1

  cmd = h[:command_line_chars].join
  params << ["cmd", cmd] unless cmd.empty?

  params << ["main", "1"] if h[:main_script]
  params << ["partial", "1"] if h[:partial_script]
  params << ["freeze", "1"] if h[:freeze]
  params << ["comments", "1"] if h[:attach_comments]
  params << ["enc_lock", "1"] if h[:encoding_locked]
  params << ["frozen_lit", h[:frozen_string_literal] ? "1" : "0"] if h[:has_frozen_string_literal]
  params << ["stream", "1"] if h[:stream_mode]

  if h[:has_encoding_opts]
    params << ["filepath", h[:filepath]]
    params << ["shebang_cb", "1"] if h[:shebang_callback]
  end

  params << ["budget", h[:stack_budget]] unless h[:stack_budget] == "SIZE_MAX"

  scopes_count = h[:scopes_count]
  if scopes_count > 0
    fwd_chars = h[:forwarding_chars].join
    forwarding_scope = h[:forwarding_scope]

    scope_segments = (0...scopes_count).map do |i|
      locals_count = (i == 0 && source.bytesize > 0) ? 3 : 2
      locals_count = 0 if i == 0 && h[:has_encoding_opts] && (h[:b3] & 0x10) != 0
      locals = (0...[2, locals_count].min).map { |j| SCOPE_BASE_LOCALS[i][j].b }
      locals << source.byteslice(0, [source.bytesize, 4].min) if locals_count == 3
      encoded_locals = locals.map { |loc| encode_loupe_scope_local(loc) }
      fwd = (i == forwarding_scope) ? fwd_chars : ""
      if encoded_locals.empty?
        fwd.empty? ? ":" : "#{fwd}:"
      else
        fwd.empty? ? encoded_locals.join(",") : "#{fwd}:#{encoded_locals.join(",")}"
      end
    end
    params << ["scopes", scope_segments.join(";")]
  end

  query = params.map { |k, v| "#{k}=#{CGI.escape(v)}" }.join("&")
  "#{PRISM_LOUPE_BASE_URL}?#{query}"
end

def c_array(source, loupe_url)
  comment = <<~C.chomp
    /*
    #{escape_c_comment(source.dump)}
    Prism Loupe: #{escape_c_comment(loupe_url)}
    */
  C
  if source.empty?
    "#{comment}\nstatic const size_t input_size = 0;"
  else
    bytes = source.bytes.map { |c| format("0x%02x", c) }.join(", ")
    "#{comment}\nstatic const uint8_t input[] = {#{bytes}};\nstatic const size_t input_size = #{source.bytesize};"
  end
end

def slow_consumer_lines(stream_mode, source_ptr)
  lines = [
    "pm_buffer_t *serialize_buf = pm_buffer_new();",
    "pm_serialize(parser, node, serialize_buf);",
    "pm_buffer_free(serialize_buf);"
  ]
  if stream_mode
    lines.concat([
      "pm_buffer_t *stream_buf = pm_buffer_new();",
      "mem_stream_t stream_state2 = {.data = #{source_ptr}, .size = input_size, .pos = 0, .eof = false};",
      "pm_source_t *stream_src2 = pm_source_stream_new(&stream_state2, mem_stream_fgets, mem_stream_feof);",
      "pm_serialize_parse_stream(stream_buf, stream_src2, NULL);",
      "pm_source_free(stream_src2);",
      "pm_buffer_free(stream_buf);"
    ])
  end
  lines.concat([
    "if (pm_parser_errors_size(parser) > 0) {",
    "  pm_buffer_t *plain_buf = pm_buffer_new();",
    "  (void)pm_errors_format(parser, plain_buf, PM_ERRORS_FORMAT_PLAIN);",
    "  pm_buffer_free(plain_buf);",
    "  pm_buffer_t *color_buf = pm_buffer_new();",
    "  (void)pm_errors_format(parser, color_buf, PM_ERRORS_FORMAT_COLOR);",
    "  pm_buffer_free(color_buf);",
    "}",
    "pm_buffer_t *pretty_buf = pm_buffer_new();",
    "pm_prettyprint(pretty_buf, parser, node);",
    "pm_buffer_free(pretty_buf);",
    "pm_buffer_t *json_buf = pm_buffer_new();",
    "pm_dump_json(json_buf, parser, node);",
    "pm_buffer_free(json_buf);"
  ])
  lines
end

def post_parse_plan(crash_output, executable, stream_mode, source_ptr)
  size_var = stream_mode ? "parsed_size" : "input_size"
  plan = {
    need_node: false,
    need_parsed_size: false,
    need_check_node_helper: false,
    need_check_node_relation_helper: false,
    need_check_recursion_depth_helper: false,
    need_stream_helpers: stream_mode,
    need_assert: false,
    need_stdbool: stream_mode,
    need_string: false,
    lines: []
  }

  if crash_output.include?("INVARIANT[stream]:")
    plan[:need_parsed_size] = true
    plan[:need_assert] = true
    plan[:lines] = ["assert(#{size_var} <= input_size);"]
  elsif crash_output.include?("INVARIANT[line_offsets]:")
    plan[:need_parsed_size] = stream_mode
    plan[:need_assert] = true
    plan[:lines] = [
      "const pm_line_offset_list_t *line_offsets = pm_parser_line_offsets(parser);",
      "assert(line_offsets->size > 0);",
      "assert(line_offsets->offsets[0] == 0);",
      "for (size_t i = 1; i < line_offsets->size; i++) {",
      "  assert(line_offsets->offsets[i] > line_offsets->offsets[i - 1]);",
      "  assert((size_t)line_offsets->offsets[i] <= #{size_var});",
      "}"
    ]
  elsif crash_output.include?("INVARIANT[node_location]:")
    plan[:need_node] = true
    plan[:need_parsed_size] = true
    plan[:need_check_node_helper] = true
    plan[:need_assert] = true
    plan[:lines] = ["pm_visit_node(node, check_node_location, &parsed_size);"]
  elsif crash_output.include?("INVARIANT[node_relation]:")
    plan[:need_node] = true
    plan[:need_parsed_size] = true
    plan[:need_check_node_relation_helper] = true
    plan[:need_assert] = true
    plan[:need_stdbool] = true
    plan[:lines] = [
      "node_relation_ctx_t rel_ctx = {.source = #{source_ptr}, .parsed_size = parsed_size};",
      "pm_visit_node(node, check_node_relation, &rel_ctx);"
    ]
  elsif crash_output.include?("INVARIANT[recursion_depth]:")
    plan[:need_node] = true
    plan[:need_check_recursion_depth_helper] = true
    plan[:need_assert] = true
    plan[:need_stdbool] = true
    plan[:need_string] = true
    plan[:lines] = [
      "bool has_depth_error = false;",
      "for (const pm_diagnostic_t *d = pm_parser_errors_first(parser); d != NULL; d = pm_diagnostic_next(d)) {",
      "  const char *diag_type = pm_diagnostic_type(d);",
      "  if (strcmp(diag_type, \"nesting_too_deep\") == 0 || strcmp(diag_type, \"stack_exhausted\") == 0) {",
      "    has_depth_error = true;",
      "    break;",
      "  }",
      "}",
      "if (!has_depth_error) {",
      "  rec_depth_ctx_t depth_ctx = {.parent_type = 0, .depth = 0};",
      "  pm_visit_node(node, check_recursion_depth, &depth_ctx);",
      "}"
    ]
  elsif crash_output.include?("INVARIANT[diagnostic_semantic]:")
    plan[:need_parsed_size] = true
    plan[:need_assert] = true
    plan[:need_stdbool] = true
    plan[:need_string] = true
    plan[:lines] = [
      "for (const pm_diagnostic_t *d = pm_parser_errors_first(parser); d != NULL; d = pm_diagnostic_next(d)) {",
      "  const char *diag_type = pm_diagnostic_type(d);",
      "  pm_location_t loc = pm_diagnostic_location(d);",
      "  assert((size_t)loc.start <= parsed_size && (size_t)loc.length <= parsed_size - (size_t)loc.start);",
      "  if (strcmp(diag_type, \"mixed_encoding\") == 0) {",
      "    assert(loc.length > 0);",
      "    bool has_non_ascii_or_escape = false;",
      "    for (uint32_t i = 0; i < loc.length; i++) {",
      "      uint8_t byte = #{source_ptr}[loc.start + i];",
      "      if (byte >= 0x80 || byte == '\\\\') {",
      "        has_non_ascii_or_escape = true;",
      "        break;",
      "      }",
      "    }",
      "    assert(has_non_ascii_or_escape);",
      "  } else if (strcmp(diag_type, \"escape_invalid_unicode_literal\") == 0) {",
      "    assert(loc.length > 0);",
      "  }",
      "}"
    ]
  elsif crash_output.include?("INVARIANT[diagnostic]: list=error")
    plan[:need_parsed_size] = stream_mode
    plan[:need_assert] = true
    plan[:lines] = [
      "for (const pm_diagnostic_t *d = pm_parser_errors_first(parser); d != NULL; d = pm_diagnostic_next(d)) {",
      "  pm_location_t loc = pm_diagnostic_location(d);",
      "  assert((size_t)loc.start <= #{size_var} && (size_t)loc.length <= #{size_var} - (size_t)loc.start);",
      "}"
    ]
  elsif crash_output.include?("INVARIANT[diagnostic]: list=warning")
    plan[:need_parsed_size] = stream_mode
    plan[:need_assert] = true
    plan[:lines] = [
      "for (const pm_diagnostic_t *d = pm_parser_warnings_first(parser); d != NULL; d = pm_diagnostic_next(d)) {",
      "  pm_location_t loc = pm_diagnostic_location(d);",
      "  assert((size_t)loc.start <= #{size_var} && (size_t)loc.length <= #{size_var} - (size_t)loc.start);",
      "}"
    ]
  elsif crash_output.include?("INVARIANT[comment]:")
    plan[:need_assert] = true
    if crash_output.include?("kind=unsorted")
      plan[:need_stdbool] = true
      plan[:lines] = [
        "uint32_t prev_comment_start = 0;",
        "bool first_comment = true;",
        "for (const pm_comment_t *c = pm_parser_comments_first(parser); c != NULL; c = pm_comment_next(c)) {",
        "  pm_location_t loc = pm_comment_location(c);",
        "  assert(first_comment || loc.start >= prev_comment_start);",
        "  prev_comment_start = loc.start;",
        "  first_comment = false;",
        "}"
      ]
    else
      plan[:need_parsed_size] = stream_mode
      plan[:lines] = [
        "for (const pm_comment_t *c = pm_parser_comments_first(parser); c != NULL; c = pm_comment_next(c)) {",
        "  pm_location_t loc = pm_comment_location(c);",
        "  assert((size_t)loc.start <= #{size_var} && (size_t)loc.length <= #{size_var} - (size_t)loc.start);",
        "}"
      ]
    end
  elsif crash_output.include?("INVARIANT[magic_comment]:")
    plan[:need_parsed_size] = stream_mode
    plan[:need_assert] = true
    plan[:lines] = [
      "for (const pm_magic_comment_t *mc = pm_parser_magic_comments_first(parser); mc != NULL; mc = pm_magic_comment_next(mc)) {",
      "  pm_location_t key = pm_magic_comment_key(mc);",
      "  pm_location_t val = pm_magic_comment_value(mc);",
      "  assert((size_t)key.start <= #{size_var} && (size_t)key.length <= #{size_var} - (size_t)key.start);",
      "  assert((size_t)val.start <= #{size_var} && (size_t)val.length <= #{size_var} - (size_t)val.start);",
      "}"
    ]
  elsif crash_output.match?(/\bpm_serialize_parse_stream\b/)
    plan[:need_stream_helpers] = true
    plan[:need_stdbool] = true
    plan[:lines] = [
      "pm_buffer_t *buffer = pm_buffer_new();",
      "mem_stream_t stream_state2 = {.data = #{source_ptr}, .size = input_size, .pos = 0, .eof = false};",
      "pm_source_t *stream_src2 = pm_source_stream_new(&stream_state2, mem_stream_fgets, mem_stream_feof);",
      "pm_serialize_parse_stream(buffer, stream_src2, NULL);",
      "pm_source_free(stream_src2);",
      "pm_buffer_free(buffer);"
    ]
  elsif crash_output.match?(/\bpm_serialize\b/)
    plan[:need_node] = true
    plan[:lines] = [
      "pm_buffer_t *buffer = pm_buffer_new();",
      "pm_serialize(parser, node, buffer);",
      "pm_buffer_free(buffer);"
    ]
  elsif crash_output.match?(/\bpm_errors_format\b/)
    plan[:lines] = [
      "if (pm_parser_errors_size(parser) > 0) {",
      "  pm_buffer_t *plain = pm_buffer_new();",
      "  (void)pm_errors_format(parser, plain, PM_ERRORS_FORMAT_PLAIN);",
      "  pm_buffer_free(plain);",
      "  pm_buffer_t *color = pm_buffer_new();",
      "  (void)pm_errors_format(parser, color, PM_ERRORS_FORMAT_COLOR);",
      "  pm_buffer_free(color);",
      "}"
    ]
  elsif crash_output.match?(/\bpm_prettyprint\b/)
    plan[:need_node] = true
    plan[:lines] = [
      "pm_buffer_t *buffer = pm_buffer_new();",
      "pm_prettyprint(buffer, parser, node);",
      "pm_buffer_free(buffer);"
    ]
  elsif crash_output.match?(/\bpm_dump_json\b/)
    plan[:need_node] = true
    plan[:lines] = [
      "pm_buffer_t *buffer = pm_buffer_new();",
      "pm_dump_json(buffer, parser, node);",
      "pm_buffer_free(buffer);"
    ]
  elsif executable.end_with?("msan", "lsan", "slow") && !crash_output.match?(/\bpm_parse(_stream)?\b/)
    plan[:need_node] = true
    plan[:lines] = slow_consumer_lines(stream_mode, source_ptr)
  end

  plan
end

def c_program(input_file, crash_details, crash_output: "", reason: "unknown", executable: "")
  h = decode_fuzz_header(File.binread(input_file))
  source = h[:source]
  stream_mode = h[:stream_mode]
  loupe_url = build_prism_loupe_url(h[:padded_raw], sanitize: sanitizer_loupe_crash?(reason, crash_output))

  source_ptr = source.empty? ? "source_buf" : "source"
  plan = post_parse_plan(crash_output, executable, stream_mode, source_ptr)

  need_limits = h[:need_limits]
  need_stdbool = plan[:need_stdbool]
  need_shebang_cb = false
  option_lines = []

  if h[:has_limit_opts]
    option_lines << "pm_options_line_set(options, #{h[:start_line_c]});"
  elsif h[:start_line] != 1
    option_lines << "pm_options_line_set(options, #{h[:start_line_c]});"
  end

  option_lines << "pm_options_command_line_set(options, #{format_uint8_bitmask(h[:cmd_flags], COMMAND_LINE_FLAGS)});" if h[:cmd_flags] != 0
  if h[:main_script]
    need_stdbool = true
    option_lines << "pm_options_main_script_set(options, true);"
  end
  if h[:freeze]
    need_stdbool = true
    option_lines << "pm_options_freeze_set(options, true);"
  end
  if h[:partial_script]
    need_stdbool = true
    option_lines << "pm_options_partial_script_set(options, true);"
  end
  if h[:attach_comments]
    need_stdbool = true
    option_lines << "pm_options_attach_comments_set(options, true);"
  end
  if h[:encoding_locked]
    need_stdbool = true
    option_lines << "pm_options_encoding_locked_set(options, true);"
  end
  option_lines << "pm_options_version_set(options, #{h[:version].dump}, #{h[:version].bytesize});" if h[:version] != "4.1"
  if h[:has_frozen_string_literal]
    need_stdbool = true
    option_lines << "pm_options_frozen_string_literal_set(options, #{h[:frozen_string_literal]});"
  end

  if h[:has_encoding_opts]
    option_lines << "pm_options_encoding_set(options, #{h[:encoding].dump});"
    option_lines << 'pm_options_filepath_set(options, "fuzz.rb");'
    if h[:shebang_callback]
      need_shebang_cb = true
      option_lines << "pm_options_shebang_callback_set(options, shebang_cb, NULL);"
    end
  end

  option_lines << "pm_options_stack_budget_set(options, #{h[:stack_budget]});" unless h[:stack_budget] == "SIZE_MAX"

  scopes_count = h[:scopes_count]
  if scopes_count > 0
    forwarding_scope = h[:forwarding_scope]
    forwarding_bits = h[:forwarding_bits]
    option_lines << "if (pm_options_scopes_init(options, #{scopes_count})) {"
    scopes_count.times do |i|
      locals_count = (i == 0 && !source.empty?) ? 3 : 2
      locals_count = 0 if i == 0 && h[:has_encoding_opts] && (h[:b3] & 0x10) != 0
      scope_var = "scope#{i}"
      option_lines << "  pm_options_scope_t *#{scope_var} = pm_options_scope_mut(options, #{i});"
      option_lines << "  pm_options_scope_init(#{scope_var}, #{locals_count});"
      if i == forwarding_scope && forwarding_bits != 0
        option_lines << "  pm_options_scope_forwarding_set(#{scope_var}, #{format_uint8_bitmask(forwarding_bits, FORWARDING_FLAGS)});"
      end
      [2, locals_count].min.times do |j|
        name = SCOPE_BASE_LOCALS[i][j]
        option_lines << "  pm_string_init(pm_options_scope_local_mut(#{scope_var}, #{j}), (const uint8_t *)#{name.dump}, #{name.bytesize});"
      end
      if locals_count == 3
        local_len = [source.bytesize, 4].min
        option_lines << "  pm_string_init(pm_options_scope_local_mut(#{scope_var}, 2), #{source_ptr}, #{local_len});"
      end
    end
    option_lines << "}"
  end

  # Note: pm_parser_init treats options == NULL as main_script == true for carriage-return
  # warnings on leading `#!...ruby...` lines, whereas pm_options_new() defaults main_script to false.
  use_options = !option_lines.empty? || h[:has_shebang_prefix]
  options_arg = use_options ? "options" : "NULL"

  need_assert = !source.empty? || plan[:need_assert]
  need_string = !source.empty? || plan[:need_string]

  includes = []
  includes << "#include <assert.h>" if need_assert
  includes << "#include <limits.h>" if need_limits
  includes << "#include <prism.h>"
  includes << "#include <stdbool.h>" if need_stdbool
  includes << "#include <stdint.h>"
  includes << "#include <stdlib.h>"
  includes << "#include <string.h>" if need_string

  helpers = []
  if reason == "allocation-size-too-big"
    helpers << <<~C.chomp
      const char *__asan_default_options(void) {
        return "max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}";
      }
    C
  end

  if plan[:need_stream_helpers]
    helpers << <<~C.chomp
      typedef struct {
        const uint8_t *data;
        size_t size;
        size_t pos;
        bool eof;
      } mem_stream_t;

      static char *mem_stream_fgets(char *buf, int n, void *vp) {
        mem_stream_t *s = (mem_stream_t *)vp;
        if (n <= 0) return NULL;
        if (s->pos >= s->size) {
          s->eof = true;
          return NULL;
        }
        size_t count = 0;
        size_t limit = (size_t)(n - 1);
        while (count < limit && s->pos < s->size) {
          uint8_t ch = s->data[s->pos++];
          buf[count++] = (char)ch;
          if (ch == '\\n') break;
        }
        if (count < limit && (count == 0 || buf[count - 1] != '\\n') && s->pos >= s->size) {
          s->eof = true;
        }
        buf[count] = '\\0';
        return buf;
      }

      static int mem_stream_feof(void *vp) {
        return ((const mem_stream_t *)vp)->eof ? 1 : 0;
      }
    C
  end

  if need_shebang_cb
    helpers << <<~C.chomp
      static void shebang_cb(pm_options_t *options, const uint8_t *source, size_t length, void *data) {
        (void)options;
        (void)source;
        (void)length;
        (void)data;
      }
    C
  end

  if plan[:need_check_node_helper]
    helpers << <<~C.chomp
      static pm_visit_result_t check_node_location(const pm_node_t *node, void *data) {
        size_t parsed_size = *(const size_t *)data;
        assert((size_t)node->location.start <= parsed_size);
        assert((size_t)node->location.length <= parsed_size - (size_t)node->location.start);
        return PM_VISIT_DESCEND;
      }
    C
  end

  if plan[:need_check_node_relation_helper]
    helpers << <<~C.chomp
      typedef struct {
        const uint8_t *source;
        size_t parsed_size;
      } node_relation_ctx_t;

      static void check_node_list_relations(
          const pm_node_t *parent,
          pm_location_t opening_loc,
          pm_location_t closing_loc,
          const pm_node_list_t *list,
          const node_relation_ctx_t *ctx) {
        bool opening_valid = opening_loc.length > 0 &&
            (size_t)opening_loc.start <= ctx->parsed_size &&
            (size_t)opening_loc.length <= ctx->parsed_size - (size_t)opening_loc.start;
        bool closing_valid = closing_loc.length > 0 &&
            (size_t)closing_loc.start <= ctx->parsed_size &&
            (size_t)closing_loc.length <= ctx->parsed_size - (size_t)closing_loc.start;
        bool is_heredoc = opening_valid && opening_loc.length >= 2 &&
            ctx->source[opening_loc.start] == '<' && ctx->source[opening_loc.start + 1] == '<';
        uint64_t pend = (uint64_t)parent->location.start + (uint64_t)parent->location.length;
        uint64_t opening_end = (uint64_t)opening_loc.start + (uint64_t)opening_loc.length;
        uint64_t prev_end = 0;

        for (size_t i = 0; i < list->size; i++) {
          const pm_node_t *child = list->nodes[i];
          uint64_t cstart = (uint64_t)child->location.start;
          uint64_t cend = cstart + (uint64_t)child->location.length;
          assert(i == 0 || cstart >= prev_end);
          if (!is_heredoc) {
            assert(child->location.start >= parent->location.start);
            assert(cend <= pend);
            assert(!opening_valid || cstart >= opening_end);
            assert(!closing_valid || cend <= (uint64_t)closing_loc.start);
          }
          prev_end = cend;
        }
      }

      static pm_visit_result_t check_node_relation(const pm_node_t *node, void *data) {
        const node_relation_ctx_t *ctx = (const node_relation_ctx_t *)data;
        switch (node->type) {
          case PM_ARRAY_NODE: {
            const pm_array_node_t *arr = (const pm_array_node_t *)node;
            check_node_list_relations(node, arr->opening_loc, arr->closing_loc, &arr->elements, ctx);
            break;
          }
          case PM_INTERPOLATED_SYMBOL_NODE: {
            const pm_interpolated_symbol_node_t *sym = (const pm_interpolated_symbol_node_t *)node;
            check_node_list_relations(node, sym->opening_loc, sym->closing_loc, &sym->parts, ctx);
            break;
          }
          case PM_INTERPOLATED_STRING_NODE: {
            const pm_interpolated_string_node_t *str = (const pm_interpolated_string_node_t *)node;
            check_node_list_relations(node, str->opening_loc, str->closing_loc, &str->parts, ctx);
            break;
          }
          case PM_INTERPOLATED_X_STRING_NODE: {
            const pm_interpolated_x_string_node_t *xstr = (const pm_interpolated_x_string_node_t *)node;
            check_node_list_relations(node, xstr->opening_loc, xstr->closing_loc, &xstr->parts, ctx);
            break;
          }
          case PM_INTERPOLATED_REGULAR_EXPRESSION_NODE: {
            const pm_interpolated_regular_expression_node_t *re =
                (const pm_interpolated_regular_expression_node_t *)node;
            check_node_list_relations(node, re->opening_loc, re->closing_loc, &re->parts, ctx);
            break;
          }
          default:
            break;
        }
        return PM_VISIT_DESCEND;
      }
    C
  end

  if plan[:need_check_recursion_depth_helper]
    helpers << <<~C.chomp
      typedef struct {
        pm_node_type_t parent_type;
        size_t depth;
      } rec_depth_ctx_t;

      static bool is_iterative_chain_node(pm_node_type_t parent, pm_node_type_t child) {
        if (parent != child) return false;
        switch (child) {
          case PM_CALL_NODE:
          case PM_AND_NODE:
          case PM_OR_NODE:
          case PM_CONSTANT_PATH_NODE:
          case PM_IF_NODE:
          case PM_RESCUE_NODE:
            return true;
          default:
            return false;
        }
      }

      static pm_visit_result_t check_recursion_depth(const pm_node_t *node, void *data) {
        const rec_depth_ctx_t *ctx = (const rec_depth_ctx_t *)data;
        size_t cur_depth = ctx->depth + (is_iterative_chain_node(ctx->parent_type, node->type) ? 0u : 1u);
        assert(cur_depth <= (size_t)128 * 2u + 64u);
        rec_depth_ctx_t child_ctx = {.parent_type = node->type, .depth = cur_depth};
        pm_visit_child_nodes(node, check_recursion_depth, &child_ctx);
        return PM_VISIT_SKIP;
      }
    C
  end

  main_lines = []
  if source.empty?
    main_lines << "uint8_t *source = malloc(input_size);"
    main_lines << 'const uint8_t *source_buf = source != NULL ? source : (const uint8_t *)"";'
  else
    main_lines << "uint8_t *source = malloc(input_size);"
    main_lines << "assert(source != NULL);"
    main_lines << "memcpy(source, input, input_size);"
  end
  main_lines << ""

  if use_options
    main_lines << "pm_options_t *options = pm_options_new();"
    main_lines.concat(option_lines)
    main_lines << ""
  end

  main_lines << "pm_arena_t *arena = pm_arena_new();"
  if stream_mode
    main_lines << "mem_stream_t stream_state = {.data = #{source_ptr}, .size = input_size, .pos = 0, .eof = false};"
    main_lines << "pm_source_t *stream_src = pm_source_stream_new(&stream_state, mem_stream_fgets, mem_stream_feof);"
    main_lines << "pm_parser_t *parser = NULL;"
    if plan[:need_node]
      main_lines << "pm_node_t *node = pm_parse_stream(&parser, arena, stream_src, #{options_arg});"
    else
      main_lines << "(void)pm_parse_stream(&parser, arena, stream_src, #{options_arg});"
    end
    main_lines << "size_t parsed_size = pm_source_length(stream_src);" if plan[:need_parsed_size]
  else
    main_lines << "pm_parser_t *parser = pm_parser_new(arena, #{source_ptr}, input_size, #{options_arg});"
    if plan[:need_node]
      main_lines << "pm_node_t *node = pm_parse(parser);"
    else
      main_lines << "(void)pm_parse(parser);"
    end
    main_lines << "size_t parsed_size = input_size;" if plan[:need_parsed_size]
  end

  unless plan[:lines].empty?
    main_lines << ""
    main_lines.concat(plan[:lines])
  end

  main_lines << ""
  main_lines << "pm_parser_free(parser);"
  main_lines << "pm_source_free(stream_src);" if stream_mode
  main_lines << "pm_arena_free(arena);"
  main_lines << "pm_options_free(options);" if use_options
  main_lines << "free(source);"
  main_lines << "return 0;"

  sections = [
    includes.join("\n"),
    "/*\n#{escape_c_comment(crash_details)}\n*/",
    *helpers,
    c_array(source, loupe_url),
    "int main(void) {\n#{main_lines.map { |l| l.empty? ? '' : "  #{l}" }.join("\n")}\n}"
  ]

  clang_format("#{sections.join("\n\n")}\n")
end

def repo_root_lookup_bash
  <<~'SH'.chomp
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    REPO_ROOT="${PRISM_ROOT:-}"
    if [ -z "$REPO_ROOT" ]; then
      dir="$SCRIPT_DIR"
      while [ "$dir" != "/" ]; do
        if [ -f "$dir/include/prism.h" ] && [ -d "$dir/src" ]; then
          REPO_ROOT="$dir"
          break
        fi
        dir="$(dirname "$dir")"
      done
    fi
    if [ -z "$REPO_ROOT" ]; then
      echo "Error: could not locate Prism root (set PRISM_ROOT=/path/to/prism)" >&2
      exit 1
    fi
  SH
end

def bucket_verify_profile(reason:, executable: "")
  exe = executable.to_s
  if exe.end_with?("msan") || reason == "use-of-uninitialized-value"
    "msan_slow"
  elsif exe.end_with?("lsan") || reason == "memory-leak"
    "lsan_slow"
  elsif reason == "allocation-size-too-big" || exe.end_with?("ijon", "native")
    "xallocator"
  elsif exe.end_with?("slow")
    "asan_ubsan_slow"
  else
    "asan_ubsan"
  end
end

def verify_script(reason:, executable: "")
  profile = bucket_verify_profile(reason: reason, executable: executable)
  <<~SH
    #!/usr/bin/env bash
    set -euo pipefail

    #{repo_root_lookup_bash}

    exec "$REPO_ROOT/test/fuzz/triage/verify_bucket.sh" \\
      --repo-root "$REPO_ROOT" \\
      --bucket-dir "$SCRIPT_DIR" \\
      --profile "#{profile}" \\
      "$@"
  SH
end

def build_script(input_file, crash_output: "", reason: "unknown", executable: "")
  raw = File.binread(input_file)
  source = raw.bytesize > 4 ? raw.byteslice(4..) : "".b

  is_native_only = executable.end_with?("ijon", "native")
  is_invariant = crash_output.include?("INVARIANT[")
  is_arith_ub = reason == "undefined-behavior" && !crash_output.include?("arena")
  has_long_decimal = source.scan(/[0-9][0-9_]*/n).any? { |s| s.delete("_").bytesize >= 73 }

  defines = []
  defines << "-DPM_ARENA_INITIAL_SIZE=0" unless is_native_only || is_invariant || is_arith_ub
  defines << "-DPM_INTEGER_DIVIDE_THRESHOLD=8" if has_long_decimal || crash_output.match?(/\b(?:pm_integer|pm_bignum)_|(?:integer|bignum)\.c\b/)
  defines << "-DPRISM_DEPTH_MAXIMUM=128" if source.bytesize >= 48 || reason == "hang" || crash_output.include?("nesting_too_deep") || crash_output.include?("INVARIANT[recursion_depth]")
  defines << "-DPRISM_BUILD_DEBUG" if crash_output.match?(/fuzz_(free|realloc)_sized/)
  defines << "-DSLOW" if executable.end_with?("slow")

  sanitizers = if executable.end_with?("msan") || reason == "use-of-uninitialized-value"
                 ["-fsanitize=memory", "-fsanitize-memory-track-origins", "-fno-sanitize-recover=all"]
               elsif executable.end_with?("lsan") || reason == "memory-leak"
                 ["-fsanitize=leak"]
               elsif reason == "undefined-behavior"
                 ["-fsanitize=undefined", "-fno-sanitize-recover=undefined"]
               else
                 ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
               end

  flag_lines = ['  -I"$REPO_ROOT/include" \\']
  flag_lines << "  #{defines.join(' ')} \\" unless defines.empty?
  flag_lines << "  #{sanitizers.join(' ')} \\"

  <<~SH
    #!/usr/bin/env bash
    set -euo pipefail

    #{repo_root_lookup_bash}

    shopt -s nullglob
    srcs=("$REPO_ROOT"/src/*.c "$REPO_ROOT"/src/*/*.c)

    exec "${CC:-clang}" -O1 -fno-omit-frame-pointer -ggdb3 -std=c99 \\
    #{flag_lines.join("\n")}
      "${srcs[@]}" \\
      "$SCRIPT_DIR/testcase.c" \\
      -o "$SCRIPT_DIR/testcase" \\
      "$@"
  SH
end

def testcase_output_signature(testcase_output, siglines = 10)
  o, = Open3.capture2({ "SIGLINES" => siglines.to_s }, "./test/fuzz/triage/signature.sh", stdin_data: testcase_output)
  o.strip
end

def run_testcase(executable, input_file)
  o, s = Open3.capture2e(SANITIZER_ENV, "timeout", "-k", "1", "5", executable, input_file)
  timed_out = s.exitstatus == 124 || s.exitstatus == 137
  crashed = !s.success? && !timed_out
  [o, crashed, timed_out]
end

def clang_format(c_code)
  o, = Open3.capture2('clang-format --style="{ReflowComments: false}"', stdin_data: c_code)
  o
end

def run_afl_tmin_hang(crash, minimized_input, executable)
  env = {
    "AFL_NO_IJON" => "1",
    "AFL_TMIN_EXACT" => "1",
    "ASAN_OPTIONS" => "abort_on_error=1:handle_abort=0:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}:symbolize=0",
    "UBSAN_OPTIONS" => "abort_on_error=1:symbolize=0",
    "MSAN_OPTIONS" => "exit_code=86:abort_on_error=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}:symbolize=0"
  }
  Open3.capture2e(env, "afl-tmin", "-H", "-t", "500", "-i", crash, "-o", minimized_input, "--", executable)
end

def minimize_options_header(minimized_input, executable, sig_lines)
  return unless File.exist?(minimized_input) && File.size(minimized_input) >= 4

  raw = File.binread(minimized_input)
  orig_hdr = raw.bytes[0, 4]
  hdr = orig_hdr.dup
  return if hdr == DEFAULT_HEADER_BYTES

  orig_out, orig_crashed, = run_testcase(executable, minimized_input)
  return unless orig_crashed

  orig_sig = testcase_output_signature(orig_out, sig_lines)
  body = raw.bytesize > 4 ? raw.byteslice(4..) : "".b
  tmp_file = "#{minimized_input}.hdrtmp"
  tested = Set.new([hdr.dup])

  try_hdr = lambda do |cand|
    return true if cand == hdr
    return false unless tested.add?(cand.dup)

    File.binwrite(tmp_file, cand.pack("C4") + body)
    out, crashed, = run_testcase(executable, tmp_file)
    if crashed && testcase_output_signature(out, sig_lines) == orig_sig
      hdr = cand.dup
      true
    else
      false
    end
  end

  begin
    unless try_hdr.call(DEFAULT_HEADER_BYTES)
      loop do
        prev_hdr = hdr.dup

        # b0: stream_mode, has_encoding_opts, frozen_string_literal, and boolean flags
        try_hdr.call([hdr[0] & ~0x40, hdr[1], hdr[2], hdr[3]]) if (hdr[0] & 0x40) != 0
        if (hdr[0] & 0x80) != 0
          unless try_hdr.call([hdr[0] & ~0x80, hdr[1], hdr[2], hdr[3]])
            try_hdr.call([hdr[0] & ~0x80, hdr[1], hdr[2], 0x01]) if (hdr[1] & 0x80) == 0 && hdr[3] != 0x01
          end
        end
        try_hdr.call([hdr[0] & ~0x30, hdr[1], hdr[2], hdr[3]]) if (hdr[0] & 0x30) != 0
        try_hdr.call([hdr[0] & ~0x20, hdr[1], hdr[2], hdr[3]]) if (hdr[0] & 0x10) == 0 && (hdr[0] & 0x20) != 0
        [0x08, 0x04, 0x02, 0x01].each do |bit|
          try_hdr.call([hdr[0] & ~bit, hdr[1], hdr[2], hdr[3]]) if (hdr[0] & bit) != 0
        end

        # b1: has_limit_opts, main_script, and command_line flags
        if (hdr[1] & 0x80) != 0
          alt_b3 = (hdr[0] & 0x80) != 0 ? (hdr[3] & 0x1f) : 0x01
          unless try_hdr.call([hdr[0], hdr[1] & ~0x80, hdr[2], alt_b3])
            try_hdr.call([hdr[0], hdr[1] & ~0x80, hdr[2], hdr[3]])
          end
        end
        try_hdr.call([hdr[0], hdr[1] & ~0x40, hdr[2], hdr[3]]) if (hdr[1] & 0x40) != 0
        if (hdr[1] & 0x3f) != 0 && !try_hdr.call([hdr[0], hdr[1] & ~0x3f, hdr[2], hdr[3]])
          [0x20, 0x10, 0x08, 0x04, 0x02, 0x01].each do |bit|
            try_hdr.call([hdr[0], hdr[1] & ~bit, hdr[2], hdr[3]]) if (hdr[1] & bit) != 0
          end
        end

        # b2: version (prefer latest "4.1" = 3), scopes_count, and forwarding
        try_hdr.call([hdr[0], hdr[1], (hdr[2] & ~0x03) | 0x03, hdr[3]]) if (hdr[2] & 0x03) != 0x03
        if (hdr[2] & 0xfc) != 0 && !try_hdr.call([hdr[0], hdr[1], hdr[2] & 0x03, hdr[3]])
          scopes = (hdr[2] >> 2) & 0x03
          if scopes > 1 && !try_hdr.call([hdr[0], hdr[1], (hdr[2] & ~0x0c) | 0x04, hdr[3]])
            try_hdr.call([hdr[0], hdr[1], (hdr[2] & ~0x0c) | 0x08, hdr[3]]) if scopes > 2
          end
          if ((hdr[2] >> 2) & 0x03) == 0
            try_hdr.call([hdr[0], hdr[1], hdr[2] & 0x03, hdr[3]])
          elsif (hdr[2] & 0xf0) != 0 && !try_hdr.call([hdr[0], hdr[1], hdr[2] & ~0xf0, hdr[3]])
            [0x80, 0x40, 0x20, 0x10].each do |bit|
              try_hdr.call([hdr[0], hdr[1], hdr[2] & ~bit, hdr[3]]) if (hdr[2] & bit) != 0
            end
          end
        end

        # b3: start_line (default 1) and aux_byte subfields
        if hdr[3] != 0x01 && !try_hdr.call([hdr[0], hdr[1], hdr[2], 0x01])
          if (hdr[0] & 0x80) != 0
            try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] & ~0x08]) if (hdr[3] & 0x08) != 0
            try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] & ~0x10]) if (hdr[1] & 0x80) == 0 && (hdr[3] & 0x10) != 0
            try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] & 0x1f]) if (hdr[1] & 0x80) == 0 && (hdr[3] & 0xe0) != 0
            try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] & ~0x07]) if (hdr[3] & 0x07) != 0
          end
          if (hdr[1] & 0x80) != 0
            try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] & ~0xc0]) if (hdr[3] & 0xc0) != 0
            try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] | 0x30]) if (hdr[3] & 0x30) != 0x30
            try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] & 0xf0]) if (hdr[0] & 0x80) == 0 && (hdr[3] & 0x0f) != 0
          end
        end

        break if hdr == prev_hdr
      end
    end

    File.binwrite(minimized_input, hdr.pack("C4") + body) if hdr != orig_hdr
  ensure
    FileUtils.rm_f(tmp_file)
  end
end

def minimize(crash, reason, minimized_input, executable, sig_lines)
  puts "minimizing #{crash}"
  pre_min_size = File.size(crash)
  if reason == "hang"
    run_afl_tmin_hang(crash, minimized_input, executable)
  else
    Open3.capture2e(
      SANITIZER_ENV.merge({
        "SIGLINES" => sig_lines.to_s,
        "HALFEMPTY_THREADS" => HALFEMPTY_THREADS.to_s
      }),
      "./test/fuzz/triage/halfempty.sh", executable, crash, minimized_input
    )
  end
  FileUtils.cp(crash, minimized_input) unless File.exist?(minimized_input) && File.size(minimized_input) >= 4
  minimize_options_header(minimized_input, executable, sig_lines) if reason != "hang"
  post_min_size = File.size(minimized_input)
  puts "#{crash} minimized #{pre_min_size} => #{post_min_size}"
end

def normalize_ijon_crash_bytes(raw)
  return nil unless raw.bytesize >= 4 && (raw.getbyte(0) & 0x40) != 0

  out = raw.b.dup
  out.setbyte(0, out.getbyte(0) & ~0x40)
  out
end

def utf8_safe(text)
  return "" if text.nil?

  text.to_s.encode("UTF-8", invalid: :replace, undef: :replace, replace: "?")
end

def normalize_repo_path(path)
  clean = utf8_safe(path).strip
  pwd_prefix = "#{Dir.pwd}/"
  clean = if clean.start_with?(pwd_prefix)
            clean.delete_prefix(pwd_prefix)
          elsif clean.start_with?("/prism/")
            clean.delete_prefix("/prism/")
          else
            clean
          end
  clean.start_with?("prism/src/", "prism/include/", "prism/templates/") ? clean.delete_prefix("prism/") : clean
end

def frame_scope(file)
  return "external" if file.nil? || file.empty?
  return "prism" if file.start_with?("src/", "include/", "templates/")
  return "harness" if file.start_with?("test/fuzz/harness/")

  "external"
end

def parse_kv_pairs(text)
  result = {}
  text.to_s.scan(/([A-Za-z0-9_]+)=([^\s\]]+)/) do |k, v|
    result[k] = v.match?(/\A-?\d+\z/) ? v.to_i : v
  end
  result
end

def parse_frame_location(loc)
  clean_loc = loc.sub(/\s+\(BuildId:[^)]*\)\z/, "").strip
  if clean_loc =~ /\A(.+?):(\d+):(\d+)\z/
    [normalize_repo_path(Regexp.last_match(1)), Regexp.last_match(2).to_i, Regexp.last_match(3).to_i, nil]
  elsif clean_loc =~ /\A(.+?):(\d+)\z/
    [normalize_repo_path(Regexp.last_match(1)), Regexp.last_match(2).to_i, nil, nil]
  elsif clean_loc =~ /\A\(([^)]+)\)\z/
    [nil, nil, nil, Regexp.last_match(1)]
  else
    [normalize_repo_path(clean_loc), nil, nil, nil]
  end
end

# Extracts structured symptom, invariant, sanitizer, assertion, and full stack
# frames from raw sanitizer/abort output so downstream clustering never needs
# to scrape testcase.c comments or re-run testcases.
def parse_crash_output(crash_output)
  clean = utf8_safe(crash_output)
  lines = clean.lines.map(&:chomp)

  summary = nil
  invariant = nil
  ubsan = nil
  sanitizer = nil
  assertion = nil
  frames = []
  preamble_lines = []
  seen_frames = false

  lines.each do |line|
    next if line.match?(/\AReading \d+ bytes from /) || line == "Execution successful."

    if line =~ /\A\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+((?:\/|\(|<|[^\s]+\/|[^\s]+:\d+)\S*(?:\s+\(BuildId:[^)]*\))?)\s*\z/ ||
       line =~ /\A\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(.+?)\s*\z/
      seen_frames = true
      next if frames.size >= 64

      depth = Regexp.last_match(1).to_i
      func = Regexp.last_match(2)
      file, line_no, col_no, mod = parse_frame_location(Regexp.last_match(3))
      frames << {
        "depth" => depth,
        "func" => func,
        "file" => file,
        "line" => line_no,
        "col" => col_no,
        "module" => mod,
        "scope" => frame_scope(file)
      }.compact
      next
    elsif line =~ /\A\s*#(\d+)\s+0x[0-9a-fA-F]+\s+\(([^)]+)\)(?:\s+\(BuildId:.*\))?\s*\z/
      seen_frames = true
      next if frames.size >= 64

      frames << {
        "depth" => Regexp.last_match(1).to_i,
        "module" => Regexp.last_match(2),
        "scope" => "external"
      }
      next
    end

    if line.start_with?("SUMMARY: ")
      summary ||= line.delete_prefix("SUMMARY: ").strip
    elsif !seen_frames && preamble_lines.size < 20 && !line.strip.empty?
      preamble_lines << line
    end

    if invariant.nil? && line =~ /\AINVARIANT\[([^\]]+)\]:\s*(.+)\z/
      ns = Regexp.last_match(1)
      rest = Regexp.last_match(2)
      before_detail, detail_body = rest.split(/\s*\[detail:\s*(.*?)\]\s*\z/, 2)
      invariant = {
        "namespace" => ns,
        "fields" => parse_kv_pairs(before_detail),
        "detail" => detail_body ? parse_kv_pairs(detail_body) : {}
      }
    end

    if ubsan.nil? && line =~ /\A(.+?):(\d+):(\d+): runtime error: (.+?)\z/
      msg = Regexp.last_match(4).strip
      check, detail = msg.split(": ", 2)
      ubsan = {
        "file" => normalize_repo_path(Regexp.last_match(1)),
        "line" => Regexp.last_match(2).to_i,
        "col" => Regexp.last_match(3).to_i,
        "check" => check,
        "message" => detail
      }.compact
    end

    if line =~ /ERROR: (AddressSanitizer|MemorySanitizer|LeakSanitizer): (detected memory leaks|\S+)(.*)\z/
      sanitizer ||= {
        "tool" => Regexp.last_match(1),
        "kind" => Regexp.last_match(2).tr(" ", "-")
      }
    end

    if line =~ /\A(READ|WRITE) of size (\d+)\b/
      sanitizer ||= { "tool" => "AddressSanitizer" }
      sanitizer["access"] ||= {
        "op" => Regexp.last_match(1),
        "size" => Regexp.last_match(2).to_i
      }
    end

    if assertion.nil? && line =~ /(?:([^:\s]+):(\d+): (?:([^:]+): )?)?Assertion `(.+?)' failed\.\z/
      assertion = {
        "file" => Regexp.last_match(1) ? normalize_repo_path(Regexp.last_match(1)) : nil,
        "line" => Regexp.last_match(2)&.to_i,
        "func" => Regexp.last_match(3),
        "expr" => Regexp.last_match(4)
      }.compact
    end
  end

  headline = preamble_lines.find { |l| !l.start_with?("====") && l != "AddressSanitizer:DEADLYSIGNAL" } || summary || preamble_lines.first

  {
    "symptom" => {
      "headline" => headline,
      "summary" => summary,
      "preamble_lines" => preamble_lines,
      "invariant" => invariant,
      "ubsan" => ubsan,
      "sanitizer" => sanitizer,
      "assertion" => assertion
    },
    "frames" => frames
  }
end

def input_and_options_metadata(minimized_input, reason:, crash_output:, raw_size_bytes: nil, raw_sha256: nil, minimized_matches_signature: nil)
  raw_min = File.binread(minimized_input)
  h = decode_fuzz_header(raw_min)
  loupe_url = build_prism_loupe_url(h[:padded_raw], sanitize: sanitizer_loupe_crash?(reason, crash_output))
  min_sha256 = Digest::SHA256.hexdigest(raw_min)

  {
    "input" => {
      "raw_size_bytes" => raw_size_bytes,
      "raw_sha256" => raw_sha256,
      "min_size_bytes" => raw_min.bytesize,
      "min_sha256" => min_sha256,
      "payload_size_bytes" => h[:source].bytesize,
      "header_bytes" => h[:header_bytes],
      "header_hex" => h[:header_bytes].map { |b| format("%02x", b) }.join,
      "valid_header" => h[:valid_header],
      "has_shebang_prefix" => h[:has_shebang_prefix],
      "minimized_matches_signature" => minimized_matches_signature,
      "loupe_url" => loupe_url
    },
    "options" => {
      "ruby_version" => h[:version],
      "start_line" => h[:start_line],
      "start_line_expr" => h[:has_limit_opts] ? h[:start_line_c] : nil,
      "encoding" => h[:encoding],
      "encoding_locked" => h[:encoding_locked],
      "freeze" => h[:freeze],
      "partial_script" => h[:partial_script],
      "attach_comments" => h[:attach_comments],
      "main_script" => h[:main_script],
      "stream_mode" => h[:stream_mode],
      "frozen_string_literal" => h[:has_frozen_string_literal] ? h[:frozen_string_literal] : nil,
      "command_line_flags" => h[:command_line_chars],
      "filepath" => h[:filepath],
      "shebang_callback" => h[:shebang_callback],
      "stack_budget" => h[:stack_budget],
      "scopes_count" => h[:scopes_count],
      "forwarding_scope" => h[:forwarding_scope],
      "forwarding_flags" => h[:forwarding_chars]
    }
  }
end

def build_occurrence_record(crash_dir, crash, crash_hash)
  worker_dir = File.dirname(crash_dir)
  {
    "sha256" => crash_hash,
    "path" => utf8_safe(crash),
    "filename" => utf8_safe(File.basename(crash)),
    "fuzzer" => utf8_safe(File.basename(File.dirname(worker_dir))),
    "worker" => utf8_safe(File.basename(worker_dir)),
    "queue" => utf8_safe(File.basename(crash_dir)),
    "size_bytes" => File.size(crash),
    "mtime" => File.mtime(crash).utc.iso8601
  }
end

def append_occurrences(bucket_dir, records)
  return if records.nil? || records.empty?

  occ_path = File.join(bucket_dir, "occurrences.jsonl")
  File.open(occ_path, "a") do |f|
    records.each { |rec| f.puts(JSON.generate(rec)) }
    f.flush
  end
end

def read_occurrences(bucket_dir)
  occ_path = File.join(bucket_dir, "occurrences.jsonl")
  return [] unless File.file?(occ_path)

  by_sha = {}
  File.foreach(occ_path) do |line|
    line = line.strip
    next if line.empty?

    rec = JSON.parse(line)
    sha = rec["sha256"]
    next if sha.nil? || sha.empty?

    by_sha[sha] ||= rec
  rescue JSON::ParserError
    next
  end

  by_sha.values.sort_by { |r| [r["mtime"].to_s, r["sha256"].to_s] }
end

def summarize_occurrences(bucket_dir)
  records = read_occurrences(bucket_dir)
  by_fuzzer = Hash.new(0)
  by_worker = Hash.new(0)
  by_queue = Hash.new(0)
  mtimes = []

  records.each do |rec|
    by_fuzzer[rec["fuzzer"] || "unknown"] += 1
    by_worker[rec["worker"] || "unknown"] += 1
    by_queue[rec["queue"] || "unknown"] += 1
    mtimes << rec["mtime"] if rec["mtime"]
  end

  {
    "count" => records.size,
    "by_fuzzer" => by_fuzzer.sort.to_h,
    "by_worker" => by_worker.sort.to_h,
    "by_queue" => by_queue.sort.to_h,
    "first_seen" => mtimes.min,
    "last_seen" => mtimes.max,
    "sample_crashes" => records.first(5).map do |r|
      {
        "sha256" => r["sha256"],
        "fuzzer" => r["fuzzer"],
        "worker" => r["worker"],
        "path" => r["path"],
        "mtime" => r["mtime"]
      }
    end
  }
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

def build_bucket_metadata(bucket_id:, reason:, signature:, reproducible:, timed_out:, executable:, crash_output:, minimized_input:, raw_size_bytes:, raw_sha256:, minimized_matches_signature:, occurrences:, coverage: nil, archive: nil, verify_profile: nil)
  parsed = parse_crash_output(crash_output)
  io_meta = input_and_options_metadata(
    minimized_input,
    reason: reason,
    crash_output: crash_output,
    raw_size_bytes: raw_size_bytes,
    raw_sha256: raw_sha256,
    minimized_matches_signature: minimized_matches_signature
  )

  {
    "schema_version" => META_SCHEMA_VERSION,
    "bucket_id" => bucket_id,
    "reason" => reason,
    "signature" => signature,
    "reproducible" => reproducible,
    "timed_out" => timed_out,
    "reproduced_by" => File.basename(executable.to_s),
    "verify_profile" => verify_profile || bucket_verify_profile(reason: reason, executable: executable),
    "occurrences" => occurrences,
    "archive" => archive,
    "input" => io_meta["input"],
    "options" => io_meta["options"],
    "symptom" => parsed["symptom"],
    "frames" => parsed["frames"],
    "coverage" => coverage
  }
end

def classify_crash_execution(crash_dir, crash_input, executable)
  reason = File.basename(crash_dir) == "hangs" ? "hang" : "unknown"
  timed_out = false

  if reason == "hang"
    testcase_output, crashed, timed_out = run_testcase(executable, crash_input)
    return { transient_timeout: true } if !crashed && !timed_out
  elsif executable.end_with?("ijon", "native")
    # fuzz.ijon and fuzz.native are built without sanitizers (and SAND workers
    # record fuzz.native in cmdline while running fuzz.sand under -w), so try
    # ./build/fuzz (ASAN/UBSAN) first for sanitizer crashes and assertions so
    # they deduplicate with main; next try ./build/fuzz.lsan for memory leaks;
    # finally fall back to executable for cumulative allocation limit assertions
    # in PRISM_XALLOCATOR.
    testcase_output, crashed, timed_out = run_testcase("./build/fuzz", crash_input)
    if crashed
      executable = "./build/fuzz"
    else
      testcase_output, crashed, timed_out = run_testcase("./build/fuzz.lsan", crash_input)
      if crashed
        executable = "./build/fuzz.lsan"
      else
        testcase_output, crashed, timed_out = run_testcase(executable, crash_input)
      end
    end
  elsif executable.end_with?("msan", "slow")
    # Try the fast ASAN/UBSAN binary first: if it crashes (e.g. on an illegal write,
    # UBSAN check, assertion failure, SEGV, or fast invariant), prefer it for deterministic
    # classification, minimization, and deduplication against main/grammar;
    # otherwise fall back to msan/slow for read issues (MSAN) or -DSLOW consumer /
    # differential checks.
    testcase_output, crashed, timed_out = run_testcase("./build/fuzz", crash_input)
    if crashed
      executable = "./build/fuzz"
    else
      testcase_output, crashed, timed_out = run_testcase(executable, crash_input)
    end
  else
    testcase_output, crashed, timed_out = run_testcase(executable, crash_input)
  end

  unreproducible = !crashed && !(reason == "hang" && timed_out)

  if crashed
    reason = "unknown" if reason == "hang"
    testcase_output.match(/SUMMARY: (Memory|UndefinedBehavior|Address|Leak)Sanitizer: ([[:alpha:]-]*) .*/) do |m|
      reason = m.captures[1]
    end
    if reason == "unknown"
      if testcase_output.match?(/ERROR: LeakSanitizer: detected memory leaks/) || testcase_output.include?("Assertion `allocated == 0' failed")
        reason = "memory-leak"
      elsif testcase_output.include?("FUZZ_MAX_ALLOCATED_BYTES")
        reason = "allocation-size-too-big"
      elsif testcase_output.include?("Assertion `") || testcase_output.include?("INVARIANT[")
        reason = "ABRT"
      end
    end
  end

  sig_lines = case reason
              when "undefined-behavior"
                3
              when "ABRT"
                15
              when "use-of-uninitialized-value"
                5
              when "heap-use-after-free"
                7
              when "stack-use-after-return"
                50
              else
                10
              end

  {
    transient_timeout: false,
    reason: reason,
    executable: executable,
    testcase_output: testcase_output,
    crashed: crashed,
    timed_out: timed_out,
    unreproducible: unreproducible,
    sig_lines: sig_lines
  }
end

def find_executable_in_path(cmd)
  return nil if cmd.nil? || cmd.empty?
  return cmd if cmd.include?("/") && File.executable?(cmd) && !File.directory?(cmd)

  ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |dir|
    cand = File.join(dir, cmd)
    return cand if File.executable?(cand) && !File.directory?(cand)
  end
  nil
end

def showmap_env
  SANITIZER_ENV.merge(
    "AFL_NO_IJON" => "1",
    "AFL_CMIN_ALLOW_ANY" => "1",
    "ASAN_OPTIONS" => "abort_on_error=1:handle_abort=1:symbolize=0:detect_leaks=0:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}",
    "UBSAN_OPTIONS" => "abort_on_error=1:symbolize=0",
    "MSAN_OPTIONS" => "abort_on_error=1:handle_abort=1:symbolize=0:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}"
  )
end

def parse_showmap_file(path)
  edges = {}
  return edges unless File.file?(path)

  File.foreach(path) do |line|
    next unless line =~ /\A\s*(\d+):(\d+)\s*\z/

    edges[Regexp.last_match(1).to_i] = Regexp.last_match(2).to_i
  end
  edges.sort.to_h { |k, v| [k.to_s, v] }
end

# Runs afl-showmap in a single persistent forkserver batch across inputs_by_key
# (mapping caller key -> input file path), using numeric symlink filenames so
# arbitrary source paths cannot collide or trigger shell/filename issues.
def collect_showmap_batch(inputs_by_key, bin_path, showmap_path)
  return { ok: true, maps: {} } if inputs_by_key.empty?

  Dir.mktmpdir("showmap-") do |tmpdir|
    in_dir = File.join(tmpdir, "in")
    out_dir = File.join(tmpdir, "out")
    FileUtils.mkdir_p(in_dir)
    FileUtils.mkdir_p(out_dir)

    key_by_id = {}
    inputs_by_key.each_with_index do |(key, input_path), idx|
      sym_name = format("%06d", idx)
      File.symlink(File.expand_path(input_path), File.join(in_dir, sym_name))
      key_by_id[sym_name] = key
    end

    out, status = Open3.capture2e(
      showmap_env,
      showmap_path, "-q", "-t", SHOWMAP_TIMEOUT_MS.to_s,
      "-i", in_dir, "-o", out_dir, "--", bin_path, "@@"
    )

    if out.include?("Fork server handshake failed") || out.include?("PROGRAM ABORT")
      return { ok: false, reason: "afl-showmap forkserver handshake failed for #{bin_path}: #{out.lines.last&.strip}" }
    end

    maps = {}
    key_by_id.each do |sym_name, key|
      map_file = File.join(out_dir, sym_name)
      maps[key] = parse_showmap_file(map_file) if File.file?(map_file)
    end

    if maps.empty? && !status.success?
      return { ok: false, reason: "afl-showmap exited with #{status.exitstatus} and produced no maps" }
    end

    { ok: true, maps: maps }
  end
end

def load_coverage_ids(ids_path)
  return { available: false, path: nil, sha256: nil, edge_count_total: nil, edge_functions: {} } if ids_path.nil? || ids_path.empty? || !File.file?(ids_path)

  edge_functions = {}
  File.foreach(ids_path) do |line|
    next unless line =~ /\bFunction=(\S+)\s+edgeID=(\d+)\s*\z/

    edge_functions[Regexp.last_match(2).to_i] = Regexp.last_match(1)
  end

  sorted = edge_functions.sort.to_h { |k, v| [k.to_s, v] }
  {
    available: true,
    path: ids_path,
    sha256: Digest::SHA256.file(ids_path).hexdigest,
    edge_count_total: sorted.size,
    edge_functions: sorted
  }
end

def corpus_dir_fingerprint(corpus_dir)
  return nil, [] unless !corpus_dir.nil? && !corpus_dir.empty? && File.directory?(corpus_dir)

  files = Dir.glob(File.join(corpus_dir, "**", "*")).select { |p| File.file?(p) }.sort
  digest = Digest::SHA256.new
  files.each do |path|
    st = File.stat(path)
    rel = path.delete_prefix("#{corpus_dir}/")
    digest.update("#{rel}\0#{st.size}\0#{st.mtime.to_i}:#{st.mtime.nsec}\n")
  end
  [digest.hexdigest, files]
end

def load_or_build_corpus_coverage(bin_path, build_id, ids_info, corpus_dir, showmap_path, cache_path)
  fingerprint, corpus_files = corpus_dir_fingerprint(corpus_dir)
  if fingerprint.nil?
    return {
      "available" => false,
      "reason" => "corpus directory not found: #{corpus_dir}",
      "dir" => corpus_dir
    }
  end

  if File.file?(cache_path)
    begin
      cached = JSON.parse(File.read(cache_path))
      if cached["available"] &&
         cached["build_id"] == build_id &&
         cached["corpus_fingerprint"] == fingerprint &&
         cached["ids_sha256"] == ids_info[:sha256]
        return cached
      end
    rescue JSON::ParserError
      # Rebuild stale or corrupt cache.
    end
  end

  puts "Collecting afl-showmap corpus baseline (#{corpus_files.size} files)..."
  inputs = {}
  corpus_files.each_with_index { |p, i| inputs[i.to_s] = p }
  batch = collect_showmap_batch(inputs, bin_path, showmap_path)
  unless batch[:ok]
    return {
      "available" => false,
      "reason" => batch[:reason],
      "dir" => corpus_dir,
      "build_id" => build_id
    }
  end

  df = Hash.new(0)
  batch[:maps].each_value do |edges|
    edges.each_key { |edge_id| df[edge_id.to_i] += 1 }
  end

  result = {
    "available" => true,
    "dir" => corpus_dir,
    "binary" => normalize_repo_path(bin_path),
    "build_id" => build_id,
    "ids_sha256" => ids_info[:sha256],
    "corpus_fingerprint" => fingerprint,
    "corpus_count" => corpus_files.size,
    "edge_df" => df.sort.to_h { |k, v| [k.to_s, v] },
    "edge_functions" => ids_info[:edge_functions]
  }
  write_json_atomic(cache_path, result)
  result
end

def discover_bucket_dirs(triage_dir)
  return [] unless File.directory?(triage_dir)

  Dir.glob(File.join(triage_dir, "*", "*")).select do |d|
    next false unless File.directory?(d)

    reason_name = File.basename(File.dirname(d))
    sig_name = File.basename(d)
    !reason_name.start_with?(".") && !sig_name.start_with?(".") &&
      (File.file?(File.join(d, "input.min")) || File.file?(File.join(d, "meta.json")))
  end.sort
end

def load_all_recorded_occurrence_hashes(triage_dir)
  hashes = Set.new
  discover_bucket_dirs(triage_dir).each do |bucket_dir|
    read_occurrences(bucket_dir).each { |rec| hashes.add(rec["sha256"]) if rec["sha256"] }
  end
  hashes
end

def read_sentinel_state(sentinel_path, triage_dir)
  return { status: :absent } unless File.exist?(sentinel_path)

  raw = File.read(sentinel_path).strip
  return { status: :skip } if raw == "#skip"
  return { status: :empty } if raw.empty?

  if raw.match?(%r{\A[^/\n]+/[^/\n]+\z}) && File.directory?(File.join(triage_dir, raw))
    return { status: :bucket, bucket_id: raw }
  end

  { status: :empty }
rescue SystemCallError
  { status: :empty }
end

def write_processed_sentinel(sentinel_path, content = "")
  File.write(sentinel_path, content.empty? ? "" : "#{content.chomp}\n")
end

def append_pending_inputs(bucket_dir, items)
  return if items.nil? || items.empty?

  pending_path = File.join(bucket_dir, PENDING_INPUTS_FILE)
  File.open(pending_path, "ab") do |f|
    items.each do |sha, bytes|
      next if sha.nil? || sha.empty? || bytes.nil?

      b = bytes.b
      f.write("#{sha}\t#{b.bytesize}\n")
      f.write(b)
      f.write("\n")
    end
    f.flush
  end
end

def read_pending_inputs(bucket_dir)
  pending_path = File.join(bucket_dir, PENDING_INPUTS_FILE)
  entries = {}
  return entries unless File.file?(pending_path)

  File.open(pending_path, "rb") do |f|
    while (header = f.gets("\n"))
      header = header.chomp
      next if header.empty?

      sha, len_str = header.split("\t", 2)
      break if sha.nil? || len_str.nil? || !len_str.match?(/\A\d+\z/)

      sz = Integer(len_str)
      data = sz > 0 ? f.read(sz) : "".b
      break if data.nil? || data.bytesize < sz

      nl = f.read(1)
      f.seek(-1, IO::SEEK_CUR) if nl && nl != "\n"
      entries[sha] ||= data.b
    end
  end
  entries
end

def read_tar_gz_entries(archive_path, include_bytes: true)
  entries = {}
  total_bytes = 0
  return { entries: entries, total_bytes: 0 } unless File.file?(archive_path)

  Zlib::GzipReader.open(archive_path) do |gz|
    Gem::Package::TarReader.new(gz) do |tar|
      tar.each do |entry|
        next unless entry.file?

        name = File.basename(entry.full_name.to_s)
        next if name.empty?

        sz = entry.header.size.to_i
        if include_bytes
          entries[name] ||= (entry.read || "".b).b
        else
          entries[name] = true
        end
        total_bytes += sz
      end
    end
  end
  { entries: entries, total_bytes: total_bytes }
rescue Zlib::Error, Gem::Package::TarInvalidError
  { entries: {}, total_bytes: 0 }
end

def load_all_archived_input_hashes(triage_dir)
  hashes = Set.new
  discover_bucket_dirs(triage_dir).each do |bucket_dir|
    tar_path = File.join(bucket_dir, INPUTS_ARCHIVE_FILE)
    if File.file?(tar_path)
      read_tar_gz_entries(tar_path, include_bytes: false)[:entries].each_key { |sha| hashes.add(sha) }
    end
    read_pending_inputs(bucket_dir).each_key { |sha| hashes.add(sha) }
  end
  hashes
end

def legacy_bucket_ijon?(bucket_dir)
  tc_path = File.join(bucket_dir, "testcase.c")
  return false unless File.file?(tc_path)

  head = File.read(tc_path, 4096)
  crash_line = head[/^(?:Crash|Unreproducible crash):\s*(.+)$/, 1]
  !crash_line.nil? && crash_line.include?("/afl-ijon/")
end

def sync_bucket_archive(bucket_dir, existing_archive = nil)
  tar_path = File.join(bucket_dir, INPUTS_ARCHIVE_FILE)
  pending_path = File.join(bucket_dir, PENDING_INPUTS_FILE)
  has_pending = File.file?(pending_path) && File.size(pending_path) > 0

  if !has_pending && File.file?(tar_path) &&
     existing_archive.is_a?(Hash) &&
     existing_archive["file"] == INPUTS_ARCHIVE_FILE &&
     existing_archive["archive_bytes"] == File.size(tar_path) &&
     existing_archive["count"].is_a?(Integer)
    return existing_archive
  end

  if !has_pending && File.file?(tar_path)
    stats = read_tar_gz_entries(tar_path, include_bytes: false)
    return {
      "file" => INPUTS_ARCHIVE_FILE,
      "count" => stats[:entries].size,
      "total_bytes" => stats[:total_bytes],
      "archive_bytes" => File.size(tar_path)
    }
  end

  merged = File.file?(tar_path) ? read_tar_gz_entries(tar_path, include_bytes: true)[:entries] : {}
  if !File.file?(tar_path)
    from_ijon = legacy_bucket_ijon?(bucket_dir)
    Dir.glob(File.join(bucket_dir, "id*")).select { |p| File.file?(p) }.sort.each do |raw_path|
      raw = File.binread(raw_path)
      sha = Digest::SHA256.hexdigest(raw)
      next if merged.key?(sha)

      effective = from_ijon ? (normalize_ijon_crash_bytes(raw) || raw) : raw
      merged[sha] = effective.b
    end
  end

  read_pending_inputs(bucket_dir).each do |sha, bytes|
    merged[sha] ||= bytes.b
  end

  return nil if merged.empty?

  dir = File.dirname(tar_path)
  tmp_path = File.join(dir, ".#{INPUTS_ARCHIVE_FILE}.tmp.#{Process.pid}.#{Thread.current.object_id}")
  total_bytes = 0
  Zlib::GzipWriter.open(tmp_path) do |gz|
    Gem::Package::TarWriter.new(gz) do |tar|
      merged.keys.sort.each do |sha|
        data = merged[sha]
        total_bytes += data.bytesize
        tar.add_file_simple(sha, 0o644, data.bytesize) { |io| io.write(data) }
      end
    end
  end
  File.chmod(0o666 & ~File.umask, tmp_path)
  File.rename(tmp_path, tar_path)
  FileUtils.rm_f(pending_path) if File.exist?(pending_path)

  {
    "file" => INPUTS_ARCHIVE_FILE,
    "count" => merged.size,
    "total_bytes" => total_bytes,
    "archive_bytes" => File.size(tar_path)
  }
ensure
  FileUtils.rm_f(tmp_path) if tmp_path && File.exist?(tmp_path)
end

def ensure_bucket_verify_script(bucket_dir, reason:, executable:)
  verify_path = File.join(bucket_dir, "verify.sh")
  content = verify_script(reason: reason, executable: executable)
  return if File.file?(verify_path) && File.read(verify_path) == content

  File.write(verify_path, content)
  File.chmod(0o755, verify_path)
end

# Populates occurrences.jsonl for buckets created before metadata tracking existed.
def seed_legacy_occurrences(bucket_dir)
  occ_path = File.join(bucket_dir, "occurrences.jsonl")
  return if File.file?(occ_path)

  tc_path = File.join(bucket_dir, "testcase.c")
  recorded_crash_path = nil
  if File.file?(tc_path)
    head = File.read(tc_path, 4096)
    recorded_crash_path = head[/^(?:Crash|Unreproducible crash):\s*(.+)$/, 1]&.strip
  end

  raw_files = Dir.glob(File.join(bucket_dir, "id*")).select { |p| File.file?(p) }.sort
  records = raw_files.each_with_index.map do |raw_path, idx|
    sha = Digest::SHA256.hexdigest(File.binread(raw_path))
    crash_path = (idx == 0 && recorded_crash_path) ? recorded_crash_path : raw_path
    parts = crash_path.split(File::SEPARATOR)
    queue_name = parts[-2] || "crashes"
    worker_name = parts[-3] || "unknown"
    fuzzer_name = parts[-4] || "afl"
    if idx > 0 || recorded_crash_path.nil?
      fuzzer_name = "triage"
      worker_name = "legacy"
      queue_name = "crashes"
    end
    {
      "sha256" => sha,
      "path" => utf8_safe(crash_path),
      "filename" => utf8_safe(File.basename(raw_path)),
      "fuzzer" => utf8_safe(fuzzer_name),
      "worker" => utf8_safe(worker_name),
      "queue" => utf8_safe(queue_name),
      "size_bytes" => File.size(raw_path),
      "mtime" => File.mtime(raw_path).utc.iso8601
    }
  end

  append_occurrences(bucket_dir, records)
end

def backfill_bucket_meta(bucket_dir)
  sig = File.basename(bucket_dir)
  reason = File.basename(File.dirname(bucket_dir))
  bucket_id = "#{reason}/#{sig}"
  min_path = File.join(bucket_dir, "input.min")
  occurrences = summarize_occurrences(bucket_dir)
  first_occ = occurrences["sample_crashes"]&.first
  raw_file = Dir.glob(File.join(bucket_dir, "id*")).select { |p| File.file?(p) }.min
  raw_size_bytes = raw_file ? File.size(raw_file) : (File.file?(min_path) ? File.size(min_path) : nil)
  raw_sha256 = first_occ ? first_occ["sha256"] : (raw_file ? Digest::SHA256.hexdigest(File.binread(raw_file)) : nil)

  crash_output = ""
  reproducible = reason != "unreproducible"
  timed_out = false
  used_exec = "unknown"

  if reproducible && File.file?(min_path)
    build_sh = File.join(bucket_dir, "build.sh")
    build_text = File.file?(build_sh) ? File.read(build_sh) : ""
    candidates = []
    candidates << "./build/fuzz.msan" if build_text.include?("-fsanitize=memory")
    candidates << "./build/fuzz.lsan" if build_text.include?("-fsanitize=leak")
    candidates << "./build/fuzz.slow" if build_text.include?("-DSLOW")
    candidates << COVERAGE_BIN unless COVERAGE_BIN.empty?
    candidates.concat(["./build/fuzz", "./build/fuzz.slow", "./build/fuzz.msan", "./build/fuzz.lsan", "./build/fuzz.native"])
    candidates.uniq!

    candidates.each do |cand|
      next unless File.executable?(cand)

      out, crashed, t_out = run_testcase(cand, min_path)
      if crashed || (reason == "hang" && t_out)
        crash_output = out
        timed_out = t_out
        used_exec = cand
        break
      end
    end
    reproducible = (used_exec != "unknown")
  end

  build_bucket_metadata(
    bucket_id: bucket_id,
    reason: reason,
    signature: sig,
    reproducible: reproducible,
    timed_out: timed_out,
    executable: used_exec,
    crash_output: crash_output,
    minimized_input: min_path,
    raw_size_bytes: raw_size_bytes,
    raw_sha256: raw_sha256,
    minimized_matches_signature: nil,
    occurrences: occurrences,
    coverage: nil
  )
end

def finalize_triage_metadata(triage_dir)
  bucket_dirs = discover_bucket_dirs(triage_dir)

  metas_by_dir = {}
  dirty_dirs = Set.new
  bucket_dirs.each do |bucket_dir|
    seed_legacy_occurrences(bucket_dir)
    occ_summary = summarize_occurrences(bucket_dir)
    meta_path = File.join(bucket_dir, "meta.json")
    meta = nil
    if File.file?(meta_path)
      begin
        meta = JSON.parse(File.read(meta_path))
      rescue JSON::ParserError
        meta = nil
      end
    end

    if meta.nil? || meta["schema_version"] != META_SCHEMA_VERSION
      meta = backfill_bucket_meta(bucket_dir)
      dirty_dirs.add(bucket_dir)
    elsif meta["occurrences"] != occ_summary
      meta["occurrences"] = occ_summary
      dirty_dirs.add(bucket_dir)
    end

    archive_info = sync_bucket_archive(bucket_dir, meta["archive"])
    if meta["archive"] != archive_info
      meta["archive"] = archive_info
      dirty_dirs.add(bucket_dir)
    end

    expected_profile = bucket_verify_profile(
      reason: meta["reason"].to_s,
      executable: meta["reproduced_by"].to_s
    )
    if meta["verify_profile"] != expected_profile
      meta["verify_profile"] = expected_profile
      dirty_dirs.add(bucket_dir)
    end

    ensure_bucket_verify_script(
      bucket_dir,
      reason: meta["reason"].to_s,
      executable: meta["reproduced_by"].to_s
    )
    metas_by_dir[bucket_dir] = meta
  end

  showmap_path = find_executable_in_path(AFL_SHOWMAP_BIN)
  cov_disabled_reason = if COVERAGE_BIN.empty?
                          "TRIAGE_COVERAGE_BIN is empty"
                        elsif !File.executable?(COVERAGE_BIN)
                          "reference binary not found or not executable: #{COVERAGE_BIN}"
                        elsif showmap_path.nil?
                          "afl-showmap not found in PATH"
                        end

  ref_binary_meta = {
    "available" => false,
    "path" => COVERAGE_BIN.empty? ? nil : normalize_repo_path(COVERAGE_BIN),
    "build_id" => nil,
    "ids_path" => nil,
    "ids_available" => false,
    "edge_count_total" => nil
  }

  if cov_disabled_reason
    corpus_info = { "available" => false, "reason" => cov_disabled_reason, "dir" => CORPUS_DIR }
    metas_by_dir.each do |dir, meta|
      next if meta["coverage"] && meta["coverage"]["available"] == false && meta["coverage"]["reason"] == cov_disabled_reason

      meta["coverage"] = { "available" => false, "reason" => cov_disabled_reason }
      dirty_dirs.add(dir)
    end
  else
    build_id = binary_build_id(COVERAGE_BIN)
    ids_info = load_coverage_ids(COVERAGE_IDS_PATH)
    ref_binary_meta = {
      "available" => true,
      "path" => normalize_repo_path(COVERAGE_BIN),
      "build_id" => build_id,
      "ids_path" => ids_info[:path] ? normalize_repo_path(ids_info[:path]) : nil,
      "ids_available" => ids_info[:available],
      "edge_count_total" => ids_info[:edge_count_total]
    }

    corpus_info = load_or_build_corpus_coverage(
      COVERAGE_BIN,
      build_id,
      ids_info,
      CORPUS_DIR,
      showmap_path,
      File.join(triage_dir, ".corpus-coverage.json")
    )

    stale_inputs = {}
    metas_by_dir.each do |dir, meta|
      min_path = File.join(dir, "input.min")
      next unless File.file?(min_path)

      cov = meta["coverage"]
      next if cov && cov["available"] == true && cov["build_id"] == build_id

      stale_inputs[dir] = min_path
    end

    unless stale_inputs.empty?
      puts "Collecting afl-showmap bucket coverage (#{stale_inputs.size} buckets)..."
      batch = collect_showmap_batch(stale_inputs, COVERAGE_BIN, showmap_path)
      if batch[:ok]
        stale_inputs.each_key do |dir|
          edges = batch[:maps][dir]
          metas_by_dir[dir]["coverage"] = if edges
                                            {
                                              "available" => true,
                                              "binary" => normalize_repo_path(COVERAGE_BIN),
                                              "build_id" => build_id,
                                              "edge_count" => edges.size,
                                              "edges" => edges
                                            }
                                          else
                                            {
                                              "available" => false,
                                              "binary" => normalize_repo_path(COVERAGE_BIN),
                                              "build_id" => build_id,
                                              "reason" => "no coverage map produced"
                                            }
                                          end
          dirty_dirs.add(dir)
        end
      else
        ref_binary_meta["available"] = false
        ref_binary_meta["reason"] = batch[:reason]
        stale_inputs.each_key do |dir|
          metas_by_dir[dir]["coverage"] = { "available" => false, "reason" => batch[:reason] }
          dirty_dirs.add(dir)
        end
      end
    end
  end

  dirty_dirs.each do |dir|
    write_json_atomic(File.join(dir, "meta.json"), metas_by_dir[dir])
  end

  buckets = metas_by_dir.values.sort_by { |m| [-(m.dig("occurrences", "count") || 0), m["bucket_id"].to_s] }
  by_reason = Hash.new(0)
  by_worker = Hash.new(0)
  total_occurrences = 0
  buckets.each do |b|
    occ_count = b.dig("occurrences", "count") || 0
    total_occurrences += occ_count
    by_reason[b["reason"]] += 1
    (b.dig("occurrences", "by_worker") || {}).each { |w, c| by_worker[w] += c }
  end

  corpus_payload = corpus_info.reject { |k, _| %w[corpus_fingerprint ids_sha256].include?(k) }
  index_data = {
    "schema_version" => META_SCHEMA_VERSION,
    "generated_at" => Time.now.utc.iso8601,
    "triage_dir" => normalize_repo_path(triage_dir),
    "reference_binary" => ref_binary_meta,
    "corpus" => corpus_payload,
    "summary" => {
      "bucket_count" => buckets.size,
      "total_occurrences" => total_occurrences,
      "by_reason" => by_reason.sort.to_h,
      "by_worker" => by_worker.sort.to_h
    },
    "buckets" => buckets
  }

  metadata_path = File.join(triage_dir, "metadata.json")
  write_json_atomic(metadata_path, index_data)
  if defined?(FuzzClustering)
    clusters_report = FuzzClustering.cluster_metadata(index_data, metadata_path: normalize_repo_path(metadata_path))
    write_json_atomic(File.join(triage_dir, "clusters.json"), clusters_report)
  end
end

def binary_build_id(bin_path)
  Digest::SHA256.file(bin_path).hexdigest
end

def process_crash(crash_dir, crash, executable, semaphore, in_progress, pending_sentinels, pending_occurrences, pending_inputs, recorded_hashes = Set.new, archived_hashes = Set.new, testcases_dir: TESTCASES_DIR, occurrence_overrides: nil)
  raw_crash = File.binread(crash)
  crash_hash = Digest::SHA2.hexdigest(raw_crash)
  sentinel = File.join(testcases_dir, ".processed", crash_hash)

  recount_only = false
  cached_bucket_id = nil
  claimed = semaphore.synchronize do
    state = read_sentinel_state(sentinel, testcases_dir)
    if state[:status] != :absent
      if TRIAGE_RECOUNT && state[:status] != :skip &&
         (!recorded_hashes.include?(crash_hash) || !archived_hashes.include?(crash_hash)) &&
         !in_progress.include?(crash_hash)
        recount_only = true
        cached_bucket_id = state[:bucket_id]
        in_progress.add(crash_hash)
        true
      else
        false
      end
    else
      !in_progress.add?(crash_hash).nil?
    end
  end
  return unless claimed

  normalized_crash_file = nil
  begin
    normalized_bytes = executable.end_with?("ijon") ? normalize_ijon_crash_bytes(raw_crash) : nil
    effective_raw_bytes = normalized_bytes || raw_crash
    occ_record = occurrence_overrides&.dig(crash_hash) || build_occurrence_record(crash_dir, crash, crash_hash)

    if recount_only && cached_bucket_id
      target_directory = File.join(testcases_dir, cached_bucket_id)
      semaphore.synchronize do
        unless recorded_hashes.include?(crash_hash)
          append_occurrences(target_directory, [occ_record])
          recorded_hashes.add(crash_hash)
        end
        unless archived_hashes.include?(crash_hash)
          append_pending_inputs(target_directory, [[crash_hash, effective_raw_bytes]])
          archived_hashes.add(crash_hash)
        end
      end
      return
    end

    crash_input = crash
    if normalized_bytes
      normalized_crash_file = Tempfile.new(["ijon-crash-", ".bin"])
      normalized_crash_file.binmode
      normalized_crash_file.write(normalized_bytes)
      normalized_crash_file.close
      crash_input = normalized_crash_file.path
    end

    info = classify_crash_execution(crash_dir, crash_input, executable)
    if info[:transient_timeout]
      puts "Skipping #{crash} (transient timeout)"
      semaphore.synchronize { write_processed_sentinel(sentinel, "#skip") }
      return
    end

    reason = info[:reason]
    executable = info[:executable]
    testcase_output = info[:testcase_output]
    timed_out = info[:timed_out]
    unreproducible = info[:unreproducible]
    sig_lines = info[:sig_lines]

    if unreproducible && File.basename(crash).include?("sig:09")
      puts "Skipping #{crash} (external SIGKILL / OOM)"
      semaphore.synchronize { write_processed_sentinel(sentinel, "#skip") }
      return
    end

    signature = unreproducible ? crash_hash[0, 16] : testcase_output_signature(testcase_output, sig_lines)
    bucket_dir_name = unreproducible ? "unreproducible" : reason
    bucket_id = "#{bucket_dir_name}/#{signature}"
    target_directory = File.join(testcases_dir, bucket_dir_name, signature)

    skip_duplicate = semaphore.synchronize do
      if File.directory?(target_directory) && !Dir.empty?(target_directory)
        puts "#{crash} is a duplicate of #{target_directory}"
        unless recorded_hashes.include?(crash_hash)
          append_occurrences(target_directory, [occ_record])
          recorded_hashes.add(crash_hash)
        end
        unless archived_hashes.include?(crash_hash)
          append_pending_inputs(target_directory, [[crash_hash, effective_raw_bytes]])
          archived_hashes.add(crash_hash)
        end
        write_processed_sentinel(sentinel, bucket_id)
        true
      elsif pending_sentinels.key?(target_directory)
        puts "#{crash} is a duplicate of in-progress #{target_directory}"
        pending_sentinels[target_directory] << sentinel
        pending_occurrences[target_directory] ||= []
        pending_occurrences[target_directory] << occ_record unless recorded_hashes.include?(crash_hash)
        pending_inputs[target_directory] ||= []
        pending_inputs[target_directory] << [crash_hash, effective_raw_bytes] unless archived_hashes.include?(crash_hash)
        true
      else
        puts "#{crash} is new"
        pending_sentinels[target_directory] = [sentinel]
        pending_occurrences[target_directory] = []
        pending_inputs[target_directory] = []
        false
      end
    end
    return if skip_duplicate

    parent_dir = File.dirname(target_directory)
    semaphore.synchronize { FileUtils.mkdir_p(parent_dir) }
    staging_dir = Dir.mktmpdir(".tmp-", parent_dir)
    published = false
    begin
      minimized_input = File.join(staging_dir, "input.min")
      minimized_matches_sig = nil

      if ENV["TRIAGE_MINIMIZE"] == "0" || unreproducible
        FileUtils.cp(crash_input, minimized_input)
      else
        minimize(crash_input, reason, minimized_input, executable, sig_lines)
        if reason != "hang"
          min_output, min_crashed, = run_testcase(executable, minimized_input)
          if min_crashed
            minimized_matches_sig = testcase_output_signature(min_output, sig_lines) == signature
            testcase_output = min_output
          else
            minimized_matches_sig = false
          end
        end
      end

      details = if unreproducible
                  "Unreproducible crash: #{crash}"
                else
                  "Crash: #{crash}\n#{testcase_output}"
                end
      effective_output = unreproducible ? "" : testcase_output
      c_testcase = c_program(
        minimized_input,
        details,
        crash_output: effective_output,
        reason: bucket_dir_name,
        executable: executable
      )
      c_build = build_script(
        minimized_input,
        crash_output: effective_output,
        reason: bucket_dir_name,
        executable: executable
      )
      c_verify = verify_script(
        reason: bucket_dir_name,
        executable: executable
      )

      File.write(File.join(staging_dir, "testcase.c"), c_testcase)
      build_path = File.join(staging_dir, "build.sh")
      File.write(build_path, c_build)
      File.chmod(0o755, build_path)
      verify_path = File.join(staging_dir, "verify.sh")
      File.write(verify_path, c_verify)
      File.chmod(0o755, verify_path)
      FileUtils.cp(crash, File.join(staging_dir, File.basename(crash)))
      append_occurrences(staging_dir, [occ_record])
      append_pending_inputs(staging_dir, [[crash_hash, effective_raw_bytes]])
      initial_meta = build_bucket_metadata(
        bucket_id: bucket_id,
        reason: bucket_dir_name,
        signature: signature,
        reproducible: !unreproducible,
        timed_out: timed_out,
        executable: executable,
        crash_output: effective_output,
        minimized_input: minimized_input,
        raw_size_bytes: occ_record["size_bytes"],
        raw_sha256: crash_hash,
        minimized_matches_signature: minimized_matches_sig,
        occurrences: summarize_occurrences(staging_dir),
        coverage: nil
      )
      write_json_atomic(File.join(staging_dir, "meta.json"), initial_meta)
      File.chmod(0o777 & ~File.umask, staging_dir)

      semaphore.synchronize do
        Dir.rmdir(target_directory) if File.directory?(target_directory) && Dir.empty?(target_directory)
        unless File.directory?(target_directory)
          File.rename(staging_dir, target_directory)
          published = true
        end
        extra_occurrences = pending_occurrences.delete(target_directory) || []
        extra_inputs = pending_inputs.delete(target_directory) || []
        if published
          append_occurrences(target_directory, extra_occurrences)
          append_pending_inputs(target_directory, extra_inputs)
        else
          append_occurrences(target_directory, [occ_record] + extra_occurrences) unless recorded_hashes.include?(crash_hash)
          new_items = archived_hashes.include?(crash_hash) ? extra_inputs : [[crash_hash, effective_raw_bytes]] + extra_inputs
          append_pending_inputs(target_directory, new_items)
        end
        recorded_hashes.add(crash_hash)
        extra_occurrences.each { |r| recorded_hashes.add(r["sha256"]) if r["sha256"] }
        archived_hashes.add(crash_hash)
        extra_inputs.each { |sha, _| archived_hashes.add(sha) if sha }
        sentinels = pending_sentinels.delete(target_directory) || [sentinel]
        sentinels.uniq.each { |s| write_processed_sentinel(s, bucket_id) }
      end
    ensure
      FileUtils.rm_rf(staging_dir) if !published && staging_dir && File.exist?(staging_dir)
      unless published
        semaphore.synchronize do
          pending_sentinels.delete(target_directory)
          pending_occurrences.delete(target_directory)
          pending_inputs.delete(target_directory)
        end
      end
    end
    puts "#{crash} complete => #{target_directory}"
  ensure
    normalized_crash_file&.close!
    semaphore.synchronize { in_progress.delete(crash_hash) }
  end
end

def run_triage_pipeline(output_dirs: OUTPUT_DIRS, testcases_dir: TESTCASES_DIR, occurrence_overrides: nil)
  FileUtils.mkdir_p(File.join(testcases_dir, ".processed"))
  pool = Concurrent::FixedThreadPool.new(TRIAGE_THREADS)
  semaphore = Mutex.new
  in_progress = Set.new
  pending_sentinels = {}
  pending_occurrences = {}
  pending_inputs = {}
  recorded_hashes = load_all_recorded_occurrence_hashes(testcases_dir)
  archived_hashes = load_all_archived_input_hashes(testcases_dir)
  output_dirs.flat_map { |d| Dir.glob(File.join(d, "**/{crashes*,hangs*}")) }.each do |crash_dir|
    cmdline_file = File.join(crash_dir, "../cmdline")
    next unless File.exist?(cmdline_file)

    executable = File.read(cmdline_file).strip
    Dir.glob(File.join(crash_dir, "/id*")) do |crash|
      pool.post do
        process_crash(
          crash_dir,
          crash,
          executable,
          semaphore,
          in_progress,
          pending_sentinels,
          pending_occurrences,
          pending_inputs,
          recorded_hashes,
          archived_hashes,
          testcases_dir: testcases_dir,
          occurrence_overrides: occurrence_overrides
        )
      rescue StandardError => e
        warn "Error processing #{crash}: #{e.class}: #{e.message}\n#{e.backtrace.join("\n")}"
      end
    end
  end
  pool.shutdown
  pool.wait_for_termination
  finalize_triage_metadata(testcases_dir)
end

pool = unless ENV["TRIAGE_LIB_ONLY"] == "1"
         run_triage_pipeline(output_dirs: OUTPUT_DIRS, testcases_dir: TESTCASES_DIR)
         nil
       end
