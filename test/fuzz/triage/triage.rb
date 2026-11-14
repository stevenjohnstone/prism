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

OUTPUT_DIRS = ["tmp/fuzz/afl", "tmp/fuzz/afl-ijon", "tmp/fuzz/afl-diff"].freeze
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

def diff_bucket?(executable: "", crash_output: "")
  co = crash_output.to_s
  executable.to_s.end_with?("diff") || co.include?("INVARIANT[diff_parse_y]") || co.include?("CRASH[diff_parse_y]")
end

def build_diff_loupe_url(source)
  "#{PRISM_LOUPE_BASE_URL}?code=#{CGI.escape(Base64.strict_encode64(source.b))}&ruby_ver=4.0"
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
    need_stream_diff_helper: false,
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
  elsif crash_output.include?("INVARIANT[stream_diff]:")
    plan[:need_node] = true
    plan[:need_parsed_size] = true
    plan[:need_stream_diff_helper] = true
    plan[:need_assert] = true
    plan[:need_stdbool] = true
    plan[:need_string] = true
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

def diff_c_program(source, crash_details, crash_output, loupe_url)
  need_ast = crash_output.include?("kind=locals_") || crash_output.include?("kind=ast_")
  source_ptr = source.empty? ? "source_buf" : "source"

  includes = [
    "#include <assert.h>",
    "#include <limits.h>",
    "#include <prism.h>",
    "#include <signal.h>",
    "#include <stdarg.h>",
    "#include <stdbool.h>",
    "#include <stddef.h>",
    "#include <stdint.h>",
    "#include <stdio.h>",
    "#include <stdlib.h>",
    "#include <string.h>",
    "#include <ruby.h>"
  ]

  helpers = []
  helpers << <<~'C'.chomp
    static void diff_invariant_fail(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
    static void diff_invariant_fail(const char *fmt, ...) {
      va_list args;
      va_start(args, fmt);
      vfprintf(stderr, fmt, args);
      va_end(args);
      fflush(stderr);
      signal(SIGABRT, SIG_DFL);
      abort();
    }

    static VALUE diff_warning_warn(int argc, VALUE *argv, VALUE self) {
      return Qnil;
    }

    static VALUE diff_ast_parse_cb(VALUE src_str) {
      VALUE rb_cRubyVM = rb_const_get(rb_cObject, rb_intern("RubyVM"));
      VALUE rb_mAST = rb_const_get(rb_cRubyVM, rb_intern("AbstractSyntaxTree"));
      return rb_funcall(rb_mAST, rb_intern("parse"), 1, src_str);
    }

    static bool diff_is_valid_utf8(const uint8_t *s, size_t len) {
      size_t i = 0;
      while (i < len) {
        uint8_t b0 = s[i];
        if (b0 <= 0x7F) {
          i += 1;
        } else if (b0 >= 0xC2 && b0 <= 0xDF) {
          if (i + 2 > len || (s[i + 1] & 0xC0) != 0x80) return false;
          i += 2;
        } else if (b0 == 0xE0) {
          if (i + 3 > len || s[i + 1] < 0xA0 || s[i + 1] > 0xBF || (s[i + 2] & 0xC0) != 0x80) return false;
          i += 3;
        } else if ((b0 >= 0xE1 && b0 <= 0xEC) || (b0 >= 0xEE && b0 <= 0xEF)) {
          if (i + 3 > len || (s[i + 1] & 0xC0) != 0x80 || (s[i + 2] & 0xC0) != 0x80) return false;
          i += 3;
        } else if (b0 == 0xED) {
          if (i + 3 > len || s[i + 1] < 0x80 || s[i + 1] > 0x9F || (s[i + 2] & 0xC0) != 0x80) return false;
          i += 3;
        } else if (b0 == 0xF0) {
          if (i + 4 > len || s[i + 1] < 0x90 || s[i + 1] > 0xBF || (s[i + 2] & 0xC0) != 0x80 || (s[i + 3] & 0xC0) != 0x80) return false;
          i += 4;
        } else if (b0 >= 0xF1 && b0 <= 0xF3) {
          if (i + 4 > len || (s[i + 1] & 0xC0) != 0x80 || (s[i + 2] & 0xC0) != 0x80 || (s[i + 3] & 0xC0) != 0x80) return false;
          i += 4;
        } else if (b0 == 0xF4) {
          if (i + 4 > len || s[i + 1] < 0x80 || s[i + 1] > 0x8F || (s[i + 2] & 0xC0) != 0x80 || (s[i + 3] & 0xC0) != 0x80) return false;
          i += 4;
        } else {
          return false;
        }
      }
      return true;
    }

    static bool diff_has_nul(const uint8_t *s, size_t len) {
      return len > 0 && memchr(s, '\0', len) != NULL;
    }

    static bool diff_starts_with(const char *s, const char *prefix) {
      return strncmp(s, prefix, strlen(prefix)) == 0;
    }

    static void diff_sanitize_ident(const char *src, char *dst, size_t cap, const char *fallback) {
      if (cap == 0) return;
      size_t out = 0;
      if (src != NULL) {
        for (size_t i = 0; src[i] != '\0' && out + 1 < cap; i++) {
          char c = src[i];
          if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
            dst[out++] = c;
          }
        }
      }
      if (out == 0) {
        snprintf(dst, cap, "%s", fallback);
      } else {
        dst[out] = '\0';
      }
    }

    static void diff_classify_cruby_msg(const char *cls, const char *line, char *tag_buf, size_t tag_cap) {
      static const struct {
        const char *prefix;
        const char *tag;
      } prefix_tags[] = {
        { "unknown encoding name:",                        "unknown_encoding" },
        { "invalid multibyte char (UTF-8)",                "invalid_multibyte_utf8" },
        { "invalid multibyte char (US-ASCII)",             "invalid_multibyte_us_ascii" },
        { "invalid multibyte char",                        "invalid_multibyte" },
        { "string literal encodings differ",               "string_encodings_differ" },
        { "invalid symbol",                                "invalid_symbol" },
        { "premature end of char-class:",                  "regexp_char_class" },
        { "invalid character property name",               "regexp_property" },
        { "invalid backref number/name:",                  "regexp_backref" },
        { "too short escape sequence:",                    "regexp_escape" },
        { "invalid escape:",                               "regexp_escape" },
        { "end pattern",                                   "regexp_pattern" },
        { "empty char-class:",                             "regexp_char_class" },
        { "target of repeat-operator",                     "regexp_repeat" },
        { "invalid pattern in look-behind",                "regexp_lookbehind" },
        { "unterminated string meets end of file",         "unterminated_string" },
        { "unterminated regexp meets end of file",         "unterminated_regexp" },
        { "can't find string \"",                          "unterminated_heredoc" },
        { "embedded document meets end of file",           "unterminated_embdoc" },
        { "dynamic constant assignment",                   "dynamic_constant_assign" },
        { "formal argument cannot be",                     "invalid_formal_arg" },
        { "duplicated argument name",                      "duplicate_arg_name" },
        { "circular argument reference",                   "circular_arg_ref" },
        { "Invalid break",                                 "invalid_break" },
        { "Invalid next",                                  "invalid_next" },
        { "Invalid redo",                                  "invalid_redo" },
        { "Invalid retry",                                 "invalid_retry" },
        { "Invalid yield",                                 "invalid_yield" },
        { "numbered parameter",                            "numbered_param" },
        { "ordinary parameter is defined",                 "ordinary_param_conflict" },
        { "no .<digit> floating literal anymore",          "float_literal_method" },
        { "syntax error, unexpected 'do' for block",       "unexpected_do_block" },
        { "syntax error, unexpected '\\n'",                "unexpected_newline" }
      };

      for (size_t i = 0; i < sizeof(prefix_tags) / sizeof(prefix_tags[0]); i++) {
        if (diff_starts_with(line, prefix_tags[i].prefix)) {
          snprintf(tag_buf, tag_cap, "%s:%s", cls, prefix_tags[i].tag);
          return;
        }
      }
      if (diff_starts_with(line, "identifier ")) {
        if (strstr(line, " is not valid to get") != NULL) {
          snprintf(tag_buf, tag_cap, "%s:invalid_identifier_get", cls);
          return;
        }
        if (strstr(line, " is not valid to set") != NULL) {
          snprintf(tag_buf, tag_cap, "%s:invalid_identifier_set", cls);
          return;
        }
      }
      static const char unexpected_pfx[] = "syntax error, unexpected ";
      if (diff_starts_with(line, unexpected_pfx)) {
        const char *p = line + sizeof(unexpected_pfx) - 1;
        char tok[48];
        size_t len = 0;
        bool has_alnum = false;
        while (*p != '\0' && *p != ',' && len + 1 < sizeof(tok)) {
          unsigned char ch = (unsigned char)*p++;
          if (ch >= 'A' && ch <= 'Z') {
            tok[len++] = (char)(ch + ('a' - 'A'));
            has_alnum = true;
          } else if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) {
            tok[len++] = (char)ch;
            has_alnum = true;
          } else if ((ch == ' ' || ch == '-' || ch == '_') && len > 0 && tok[len - 1] != '_') {
            tok[len++] = '_';
          }
        }
        while (len > 0 && tok[len - 1] == '_') len--;
        tok[len] = '\0';
        snprintf(tag_buf, tag_cap, "%s:unexpected_%s", cls, has_alnum ? tok : "punct");
        return;
      }
      if (strcmp(cls, "RegexpError") == 0 || strstr(line, ": /") != NULL) {
        snprintf(tag_buf, tag_cap, "%s:regexp_other", cls);
        return;
      }
      snprintf(tag_buf, tag_cap, "%s:other", cls);
    }

    static void diff_format_exception(VALUE err, char *exc_buf, size_t exc_cap, char *tag_buf, size_t tag_cap) {
      if (NIL_P(err)) {
        if (exc_cap > 0) snprintf(exc_buf, exc_cap, "nil");
        if (tag_cap > 0) snprintf(tag_buf, tag_cap, "nil");
        return;
      }
      char cls_buf[48];
      diff_sanitize_ident(rb_obj_classname(err), cls_buf, sizeof(cls_buf), "Exception");
      VALUE msg = rb_funcall(err, rb_intern("message"), 0);
      const char *mptr = (RB_TYPE_P(msg, T_STRING) && RSTRING_LEN(msg) > 0) ? RSTRING_PTR(msg) : "";
      long mlen = RB_TYPE_P(msg, T_STRING) ? RSTRING_LEN(msg) : 0;
      char line[128];
      long line_len = 0;
      while (line_len < mlen && line_len < (long)(sizeof(line) - 1) && mptr[line_len] != '\n' && mptr[line_len] != '\r') {
        line[line_len] = (mptr[line_len] != '\0') ? mptr[line_len] : ' ';
        line_len++;
      }
      line[line_len] = '\0';
      if (exc_cap > 0) {
        int detail_len = (int)(line_len > 96 ? 96 : line_len);
        snprintf(exc_buf, exc_cap, "%s: %.*s", cls_buf, detail_len, line);
      }
      if (tag_cap > 0) {
        diff_classify_cruby_msg(cls_buf, line, tag_buf, tag_cap);
      }
      RB_GC_GUARD(msg);
    }
  C

  if need_ast
    helpers << <<~'C'.chomp
      #define DIFF_MAX_AST_DEPTH 4096

      typedef enum {
        DIFF_SCOPE_PROGRAM = 0,
        DIFF_SCOPE_DEF,
        DIFF_SCOPE_CLASS,
        DIFF_SCOPE_MODULE,
        DIFF_SCOPE_SCLASS,
        DIFF_SCOPE_BLOCK,
        DIFF_SCOPE_LAMBDA
      } diff_scope_kind_t;

      typedef enum {
        DIFF_CNT_CLASS = 0,
        DIFF_CNT_MODULE,
        DIFF_CNT_SCLASS,
        DIFF_CNT_FOR,
        DIFF_CNT_IF,
        DIFF_CNT_UNLESS,
        DIFF_CNT_WHILE,
        DIFF_CNT_UNTIL,
        DIFF_CNT_YIELD,
        DIFF_CNT_RETURN,
        DIFF_CNT_SUPER,
        DIFF_CNT_DEFINED,
        DIFF_CNT_ALIAS,
        DIFF_CNT_UNDEF,
        DIFF_CNT_CASE,
        DIFF_CNT_LEN
      } diff_count_kind_t;

      typedef struct {
        uint32_t offset;
        uint32_t length;
      } diff_span_t;

      typedef struct {
        char *data;
        size_t used;
        size_t cap;
      } diff_strbuf_t;

      typedef struct {
        diff_span_t *items;
        size_t count;
        size_t cap;
      } diff_span_vec_t;

      typedef struct {
        uint8_t kind;
        uint32_t local_start;
        uint32_t local_count;
      } diff_scope_t;

      typedef struct {
        diff_scope_t *items;
        size_t count;
        size_t cap;
      } diff_scope_vec_t;

      typedef struct {
        diff_strbuf_t strbuf;
        diff_scope_vec_t scopes;
        diff_span_vec_t locals;
        diff_span_vec_t defs;
        diff_span_vec_t block_owners;
        size_t counts[DIFF_CNT_LEN];
      } diff_summary_t;

      typedef struct {
        VALUE ast_node_cls;
        ID id_type;
        ID id_children;
        ID scope, defn, defs, cls, mod, scls, iter, lambda, for_n, postexe;
        ID if_n, unless_n, while_n, until_n, yield_n, return_n, break_n, next_n;
        ID super_n, zsuper_n, defined_n, alias_n, valias_n, undef_n, case_n, case2_n;
        ID fcall, vcall, call, qcall, opcall;
      } diff_cruby_env_t;

      static const char *diff_scope_kind_name(diff_scope_kind_t kind) {
        static const char *const names[] = {"program", "def", "class", "module", "sclass", "block", "lambda"};
        size_t idx = (size_t)kind;
        return idx < (sizeof(names) / sizeof(names[0])) ? names[idx] : "unknown";
      }

      static const char *diff_count_kind_name(diff_count_kind_t kind) {
        static const char *const names[] = {
          "class", "module", "sclass", "for", "if", "unless", "while", "until",
          "yield", "return", "super", "defined", "alias", "undef", "case"
        };
        size_t idx = (size_t)kind;
        return idx < (sizeof(names) / sizeof(names[0])) ? names[idx] : "unknown";
      }

      static void diff_summary_init(diff_summary_t *s) {
        memset(s, 0, sizeof(*s));
      }

      static void diff_summary_free(diff_summary_t *s) {
        free(s->strbuf.data);
        free(s->scopes.items);
        free(s->locals.items);
        free(s->defs.items);
        free(s->block_owners.items);
        memset(s, 0, sizeof(*s));
      }

      static void diff_grow_heap(void **buf, size_t *cap, size_t elem_size, size_t needed) {
        if (needed <= *cap) return;
        size_t new_cap = *cap > 0 ? *cap : 16;
        while (new_cap < needed) {
          assert(new_cap <= SIZE_MAX / 2);
          new_cap *= 2;
        }
        assert(new_cap <= SIZE_MAX / elem_size);
        void *next = realloc(*buf, new_cap * elem_size);
        assert(next != NULL);
        *buf = next;
        *cap = new_cap;
      }

      static diff_span_t diff_strbuf_add(diff_strbuf_t *b, const char *ptr, size_t len) {
        assert(len <= UINT32_MAX && b->used <= (size_t)UINT32_MAX - len);
        void *p = b->data;
        diff_grow_heap(&p, &b->cap, 1, b->used + len);
        b->data = (char *)p;
        diff_span_t span = {.offset = (uint32_t)b->used, .length = (uint32_t)len};
        if (len > 0) {
          memcpy(b->data + b->used, ptr, len);
          b->used += len;
        }
        return span;
      }

      static void diff_span_vec_push(diff_span_vec_t *v, diff_span_t span) {
        void *p = v->items;
        diff_grow_heap(&p, &v->cap, sizeof(diff_span_t), v->count + 1);
        v->items = (diff_span_t *)p;
        v->items[v->count++] = span;
      }

      static void diff_scope_vec_push(diff_scope_vec_t *v, diff_scope_t sc) {
        void *p = v->items;
        diff_grow_heap(&p, &v->cap, sizeof(diff_scope_t), v->count + 1);
        v->items = (diff_scope_t *)p;
        v->items[v->count++] = sc;
      }

      static int diff_span_cmp(diff_span_t a, diff_span_t b, const char *buf) {
        size_t min_len = a.length < b.length ? a.length : b.length;
        int cmp = min_len > 0 ? memcmp(buf + a.offset, buf + b.offset, min_len) : 0;
        if (cmp != 0) return cmp;
        return (a.length > b.length) - (a.length < b.length);
      }

      static void diff_sift_down(diff_span_t *arr, size_t start, size_t end, const char *buf) {
        size_t root = start;
        while (root * 2 + 1 <= end) {
          size_t child = root * 2 + 1;
          size_t swap_idx = root;
          if (diff_span_cmp(arr[swap_idx], arr[child], buf) < 0) swap_idx = child;
          if (child + 1 <= end && diff_span_cmp(arr[swap_idx], arr[child + 1], buf) < 0) swap_idx = child + 1;
          if (swap_idx == root) return;
          diff_span_t tmp = arr[root];
          arr[root] = arr[swap_idx];
          arr[swap_idx] = tmp;
          root = swap_idx;
        }
      }

      static void diff_sort_spans(diff_span_t *arr, size_t n, const char *buf) {
        if (n < 2) return;
        for (size_t start = n / 2; start > 0; start--) diff_sift_down(arr, start - 1, n - 1, buf);
        for (size_t end = n - 1; end > 0; end--) {
          diff_span_t tmp = arr[0];
          arr[0] = arr[end];
          arr[end] = tmp;
          diff_sift_down(arr, 0, end - 1, buf);
        }
      }

      static void diff_finalize_summary(diff_summary_t *s) {
        for (size_t i = 0; i < s->scopes.count; i++) {
          diff_scope_t *sc = &s->scopes.items[i];
          size_t n = sc->local_count;
          if (n < 2) continue;
          diff_span_t *slice = &s->locals.items[sc->local_start];
          diff_sort_spans(slice, n, s->strbuf.data);
          size_t unique = 1;
          for (size_t j = 1; j < n; j++) {
            if (diff_span_cmp(slice[j], slice[unique - 1], s->strbuf.data) != 0) slice[unique++] = slice[j];
          }
          sc->local_count = (uint32_t)unique;
        }
        diff_sort_spans(s->block_owners.items, s->block_owners.count, s->strbuf.data);
      }

      static bool diff_is_synthetic_local(const char *s, size_t len) {
        switch (len) {
          case 1: return s[0] == '*' || s[0] == '&';
          case 2: return memcmp(s, "**", 2) == 0;
          case 3: return memcmp(s, "...", 3) == 0;
          case 4: return memcmp(s, "<it>", 4) == 0;
          default: return false;
        }
      }

      typedef struct {
        const pm_parser_t *parser;
        diff_summary_t *out;
        size_t depth;
      } diff_prism_ctx_t;

      static void diff_prism_push_scope(const pm_parser_t *parser, diff_summary_t *out, diff_scope_kind_t kind, const pm_constant_id_list_t *list) {
        assert(out->locals.count <= UINT32_MAX);
        diff_scope_t sc = {.kind = (uint8_t)kind, .local_start = (uint32_t)out->locals.count, .local_count = 0};
        for (size_t i = 0; i < list->size; i++) {
          const pm_constant_t *c = pm_parser_constant(parser, list->ids[i]);
          const char *ptr = (const char *)pm_constant_start(c);
          size_t len = pm_constant_length(c);
          if (diff_is_synthetic_local(ptr, len)) continue;
          diff_span_vec_push(&out->locals, diff_strbuf_add(&out->strbuf, ptr, len));
          sc.local_count++;
        }
        diff_scope_vec_push(&out->scopes, sc);
      }

      static void diff_prism_add_const(const pm_parser_t *parser, diff_summary_t *out, pm_constant_id_t id, diff_span_vec_t *vec) {
        const pm_constant_t *c = pm_parser_constant(parser, id);
        diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, (const char *)pm_constant_start(c), pm_constant_length(c)));
      }

      static pm_visit_result_t diff_prism_visit_cb(const pm_node_t *node, void *data);

      static void diff_prism_visit_child(const pm_node_t *child, diff_prism_ctx_t *ctx) {
        if (child != NULL && ctx->depth < DIFF_MAX_AST_DEPTH) pm_visit_node(child, diff_prism_visit_cb, ctx);
      }

      static pm_visit_result_t diff_prism_visit_cb(const pm_node_t *node, void *data) {
        diff_prism_ctx_t *ctx = (diff_prism_ctx_t *)data;
        if (ctx->depth >= DIFF_MAX_AST_DEPTH) return PM_VISIT_SKIP;
        ctx->depth++;
        switch (PM_NODE_TYPE(node)) {
          case PM_PROGRAM_NODE: {
            const pm_program_node_t *prog = (const pm_program_node_t *)node;
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_PROGRAM, &prog->locals);
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
          }
          case PM_DEF_NODE: {
            const pm_def_node_t *def_n = (const pm_def_node_t *)node;
            diff_prism_visit_child(def_n->receiver, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_DEF, &def_n->locals);
            diff_prism_add_const(ctx->parser, ctx->out, def_n->name, &ctx->out->defs);
            if (def_n->parameters != NULL) diff_prism_visit_child(&def_n->parameters->base, ctx);
            diff_prism_visit_child(def_n->body, ctx);
            break;
          }
          case PM_CLASS_NODE: {
            const pm_class_node_t *cls = (const pm_class_node_t *)node;
            ctx->out->counts[DIFF_CNT_CLASS]++;
            diff_prism_visit_child(cls->constant_path, ctx);
            diff_prism_visit_child(cls->superclass, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_CLASS, &cls->locals);
            diff_prism_visit_child(cls->body, ctx);
            break;
          }
          case PM_MODULE_NODE: {
            const pm_module_node_t *mod = (const pm_module_node_t *)node;
            ctx->out->counts[DIFF_CNT_MODULE]++;
            diff_prism_visit_child(mod->constant_path, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_MODULE, &mod->locals);
            diff_prism_visit_child(mod->body, ctx);
            break;
          }
          case PM_SINGLETON_CLASS_NODE: {
            const pm_singleton_class_node_t *scls = (const pm_singleton_class_node_t *)node;
            ctx->out->counts[DIFF_CNT_SCLASS]++;
            diff_prism_visit_child(scls->expression, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_SCLASS, &scls->locals);
            diff_prism_visit_child(scls->body, ctx);
            break;
          }
          case PM_FOR_NODE: {
            const pm_for_node_t *for_n = (const pm_for_node_t *)node;
            ctx->out->counts[DIFF_CNT_FOR]++;
            diff_prism_visit_child(for_n->collection, ctx);
            diff_prism_visit_child(for_n->index, ctx);
            if (for_n->statements != NULL) diff_prism_visit_child(&for_n->statements->base, ctx);
            break;
          }
          case PM_BLOCK_NODE: {
            const pm_block_node_t *blk = (const pm_block_node_t *)node;
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_BLOCK, &blk->locals);
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
          }
          case PM_LAMBDA_NODE: {
            const pm_lambda_node_t *lam = (const pm_lambda_node_t *)node;
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_LAMBDA, &lam->locals);
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
          }
          case PM_CALL_NODE: {
            const pm_call_node_t *call = (const pm_call_node_t *)node;
            if (call->block != NULL && PM_NODE_TYPE_P(call->block, PM_BLOCK_NODE)) {
              diff_prism_add_const(ctx->parser, ctx->out, call->name, &ctx->out->block_owners);
            }
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
          }
          case PM_SUPER_NODE: {
            const pm_super_node_t *sup = (const pm_super_node_t *)node;
            ctx->out->counts[DIFF_CNT_SUPER]++;
            if (sup->block != NULL && PM_NODE_TYPE_P(sup->block, PM_BLOCK_NODE)) {
              diff_span_vec_push(&ctx->out->block_owners, diff_strbuf_add(&ctx->out->strbuf, "super", 5));
            }
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
          }
          case PM_FORWARDING_SUPER_NODE: {
            const pm_forwarding_super_node_t *fsup = (const pm_forwarding_super_node_t *)node;
            ctx->out->counts[DIFF_CNT_SUPER]++;
            if (fsup->block != NULL && PM_NODE_TYPE_P(&fsup->block->base, PM_BLOCK_NODE)) {
              diff_span_vec_push(&ctx->out->block_owners, diff_strbuf_add(&ctx->out->strbuf, "super", 5));
            }
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
          }
          case PM_IF_NODE:      ctx->out->counts[DIFF_CNT_IF]++;      pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
          case PM_UNLESS_NODE:  ctx->out->counts[DIFF_CNT_UNLESS]++;  pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
          case PM_WHILE_NODE:   ctx->out->counts[DIFF_CNT_WHILE]++;   pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
          case PM_UNTIL_NODE:   ctx->out->counts[DIFF_CNT_UNTIL]++;   pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
          case PM_YIELD_NODE:   ctx->out->counts[DIFF_CNT_YIELD]++;   pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
          case PM_RETURN_NODE:  ctx->out->counts[DIFF_CNT_RETURN]++;  pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
          case PM_DEFINED_NODE: ctx->out->counts[DIFF_CNT_DEFINED]++; pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
          case PM_ALIAS_METHOD_NODE:
          case PM_ALIAS_GLOBAL_VARIABLE_NODE:
            ctx->out->counts[DIFF_CNT_ALIAS]++;
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
          case PM_UNDEF_NODE:   ctx->out->counts[DIFF_CNT_UNDEF]++;   pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
          case PM_CASE_NODE:    ctx->out->counts[DIFF_CNT_CASE]++;    pm_visit_child_nodes(node, diff_prism_visit_cb, ctx); break;
          default:
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
        }
        ctx->depth--;
        return PM_VISIT_SKIP;
      }

      static void diff_collect_prism_summary(const pm_parser_t *parser, const pm_node_t *root, diff_summary_t *out) {
        if (root == NULL) return;
        diff_prism_ctx_t ctx = {.parser = parser, .out = out, .depth = 0};
        pm_visit_node(root, diff_prism_visit_cb, &ctx);
        diff_finalize_summary(out);
      }

      static void diff_init_cruby_env(diff_cruby_env_t *env) {
        VALUE rb_cRubyVM = rb_const_get(rb_cObject, rb_intern("RubyVM"));
        VALUE rb_mAST = rb_const_get(rb_cRubyVM, rb_intern("AbstractSyntaxTree"));
        env->ast_node_cls = rb_const_get(rb_mAST, rb_intern("Node"));
        env->id_type = rb_intern("type");
        env->id_children = rb_intern("children");
        static const struct {
          size_t off;
          const char *name;
        } map[] = {
          {offsetof(diff_cruby_env_t, scope), "SCOPE"},     {offsetof(diff_cruby_env_t, defn), "DEFN"},
          {offsetof(diff_cruby_env_t, defs), "DEFS"},       {offsetof(diff_cruby_env_t, cls), "CLASS"},
          {offsetof(diff_cruby_env_t, mod), "MODULE"},      {offsetof(diff_cruby_env_t, scls), "SCLASS"},
          {offsetof(diff_cruby_env_t, iter), "ITER"},       {offsetof(diff_cruby_env_t, lambda), "LAMBDA"},
          {offsetof(diff_cruby_env_t, for_n), "FOR"},       {offsetof(diff_cruby_env_t, postexe), "POSTEXE"},
          {offsetof(diff_cruby_env_t, if_n), "IF"},         {offsetof(diff_cruby_env_t, unless_n), "UNLESS"},
          {offsetof(diff_cruby_env_t, while_n), "WHILE"},   {offsetof(diff_cruby_env_t, until_n), "UNTIL"},
          {offsetof(diff_cruby_env_t, yield_n), "YIELD"},   {offsetof(diff_cruby_env_t, return_n), "RETURN"},
          {offsetof(diff_cruby_env_t, break_n), "BREAK"},   {offsetof(diff_cruby_env_t, next_n), "NEXT"},
          {offsetof(diff_cruby_env_t, super_n), "SUPER"},   {offsetof(diff_cruby_env_t, zsuper_n), "ZSUPER"},
          {offsetof(diff_cruby_env_t, defined_n), "DEFINED"}, {offsetof(diff_cruby_env_t, alias_n), "ALIAS"},
          {offsetof(diff_cruby_env_t, valias_n), "VALIAS"}, {offsetof(diff_cruby_env_t, undef_n), "UNDEF"},
          {offsetof(diff_cruby_env_t, case_n), "CASE"},     {offsetof(diff_cruby_env_t, case2_n), "CASE2"},
          {offsetof(diff_cruby_env_t, fcall), "FCALL"},     {offsetof(diff_cruby_env_t, vcall), "VCALL"},
          {offsetof(diff_cruby_env_t, call), "CALL"},       {offsetof(diff_cruby_env_t, qcall), "QCALL"},
          {offsetof(diff_cruby_env_t, opcall), "OPCALL"}
        };
        char *base = (char *)env;
        for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
          ID id_val = rb_intern(map[i].name);
          memcpy(base + map[i].off, &id_val, sizeof(id_val));
        }
      }

      static bool diff_cruby_is_ast_node(const diff_cruby_env_t *env, VALUE v) {
        return RB_TYPE_P(v, T_DATA) && rb_obj_is_kind_of(v, env->ast_node_cls);
      }

      static void diff_cruby_add_sym(VALUE sym, diff_summary_t *out, diff_span_vec_t *vec) {
        if (!SYMBOL_P(sym)) {
          diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, "<nil>", 5));
          return;
        }
        volatile VALUE sym_str = rb_sym2str(sym);
        if (RB_TYPE_P(sym_str, T_STRING)) {
          diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, RSTRING_PTR(sym_str), (size_t)RSTRING_LEN(sym_str)));
        } else {
          diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, "<sym>", 5));
        }
        RB_GC_GUARD(sym_str);
      }

      static void diff_cruby_record_block_owner(const diff_cruby_env_t *env, VALUE target, diff_summary_t *out) {
        volatile VALUE cur = target;
        for (int hop = 0; hop < 32 && diff_cruby_is_ast_node(env, cur); hop++) {
          volatile VALUE type_sym = rb_funcall(cur, env->id_type, 0);
          ID tid = SYMBOL_P(type_sym) ? SYM2ID(type_sym) : 0;
          volatile VALUE ch = rb_funcall(cur, env->id_children, 0);
          if (!RB_TYPE_P(ch, T_ARRAY)) {
            RB_GC_GUARD(ch);
            RB_GC_GUARD(type_sym);
            break;
          }
          long len = RARRAY_LEN(ch);
          if ((tid == env->return_n || tid == env->break_n || tid == env->next_n) && len >= 1) {
            cur = RARRAY_AREF(ch, 0);
            RB_GC_GUARD(ch);
            RB_GC_GUARD(type_sym);
            continue;
          }
          if ((tid == env->fcall || tid == env->vcall) && len >= 1) {
            diff_cruby_add_sym(RARRAY_AREF(ch, 0), out, &out->block_owners);
          } else if ((tid == env->call || tid == env->qcall || tid == env->opcall) && len >= 2) {
            diff_cruby_add_sym(RARRAY_AREF(ch, 1), out, &out->block_owners);
          } else if (tid == env->super_n || tid == env->zsuper_n) {
            diff_span_vec_push(&out->block_owners, diff_strbuf_add(&out->strbuf, "super", 5));
          } else {
            const char *tname = SYMBOL_P(type_sym) ? rb_id2name(tid) : "unknown";
            diff_span_vec_push(&out->block_owners, diff_strbuf_add(&out->strbuf, tname ? tname : "unknown", tname ? strlen(tname) : 7));
          }
          RB_GC_GUARD(ch);
          RB_GC_GUARD(type_sym);
          RB_GC_GUARD(cur);
          return;
        }
        diff_span_vec_push(&out->block_owners, diff_strbuf_add(&out->strbuf, "<unknown>", 9));
        RB_GC_GUARD(cur);
      }

      static void diff_cruby_extract_scope_locals(VALUE tbl, diff_scope_kind_t kind, diff_summary_t *out) {
        if (!RB_TYPE_P(tbl, T_ARRAY)) {
          int t = (int)TYPE(tbl);
          diff_summary_free(out);
          diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_tbl_type [detail: type=%d]\n", t);
        }
        assert(out->locals.count <= UINT32_MAX);
        diff_scope_t sc = {.kind = (uint8_t)kind, .local_start = (uint32_t)out->locals.count, .local_count = 0};
        long tbl_len = RARRAY_LEN(tbl);
        for (long i = 0; i < tbl_len; i++) {
          VALUE sym = RARRAY_AREF(tbl, i);
          if (!SYMBOL_P(sym)) continue;
          volatile VALUE sym_str = rb_sym2str(sym);
          if (!RB_TYPE_P(sym_str, T_STRING)) {
            RB_GC_GUARD(sym_str);
            continue;
          }
          const char *ptr = RSTRING_PTR(sym_str);
          size_t len = (size_t)RSTRING_LEN(sym_str);
          if (!diff_is_synthetic_local(ptr, len)) {
            diff_span_vec_push(&out->locals, diff_strbuf_add(&out->strbuf, ptr, len));
            sc.local_count++;
          }
          RB_GC_GUARD(sym_str);
        }
        diff_scope_vec_push(&out->scopes, sc);
      }

      static void diff_cruby_visit_val(const diff_cruby_env_t *env, VALUE val, diff_summary_t *out, int depth);

      static void diff_cruby_visit_scope_child(const diff_cruby_env_t *env, VALUE sc, int scope_kind, diff_summary_t *out, int depth) {
        if (depth >= DIFF_MAX_AST_DEPTH) return;
        if (!diff_cruby_is_ast_node(env, sc)) {
          diff_cruby_visit_val(env, sc, out, depth);
          return;
        }
        volatile VALUE type_sym = rb_funcall(sc, env->id_type, 0);
        ID tid = SYMBOL_P(type_sym) ? SYM2ID(type_sym) : 0;
        if (tid != env->scope) {
          RB_GC_GUARD(type_sym);
          diff_cruby_visit_val(env, sc, out, depth);
          return;
        }
        volatile VALUE ch = rb_funcall(sc, env->id_children, 0);
        if (!RB_TYPE_P(ch, T_ARRAY) || RARRAY_LEN(ch) < 1) {
          long clen = RB_TYPE_P(ch, T_ARRAY) ? RARRAY_LEN(ch) : -1L;
          RB_GC_GUARD(ch);
          RB_GC_GUARD(type_sym);
          diff_summary_free(out);
          diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_shape [detail: node=SCOPE children_len=%ld]\n", clen);
        }
        if (scope_kind >= 0) diff_cruby_extract_scope_locals(RARRAY_AREF(ch, 0), (diff_scope_kind_t)scope_kind, out);
        long clen = RARRAY_LEN(ch);
        for (long i = 1; i < clen; i++) diff_cruby_visit_val(env, RARRAY_AREF(ch, i), out, depth + 1);
        RB_GC_GUARD(ch);
        RB_GC_GUARD(type_sym);
      }

      static void diff_cruby_count_if_matched(const diff_cruby_env_t *env, ID tid, diff_summary_t *out) {
        if      (tid == env->if_n)      out->counts[DIFF_CNT_IF]++;
        else if (tid == env->unless_n)  out->counts[DIFF_CNT_UNLESS]++;
        else if (tid == env->while_n)   out->counts[DIFF_CNT_WHILE]++;
        else if (tid == env->until_n)   out->counts[DIFF_CNT_UNTIL]++;
        else if (tid == env->yield_n)   out->counts[DIFF_CNT_YIELD]++;
        else if (tid == env->return_n)  out->counts[DIFF_CNT_RETURN]++;
        else if (tid == env->super_n || tid == env->zsuper_n) out->counts[DIFF_CNT_SUPER]++;
        else if (tid == env->defined_n) out->counts[DIFF_CNT_DEFINED]++;
        else if (tid == env->alias_n || tid == env->valias_n) out->counts[DIFF_CNT_ALIAS]++;
        else if (tid == env->undef_n)   out->counts[DIFF_CNT_UNDEF]++;
        else if (tid == env->case_n || tid == env->case2_n)   out->counts[DIFF_CNT_CASE]++;
      }

      static void diff_cruby_visit_node(const diff_cruby_env_t *env, VALUE node, diff_summary_t *out, int depth) {
        if (depth >= DIFF_MAX_AST_DEPTH) return;
        volatile VALUE type_sym = rb_funcall(node, env->id_type, 0);
        ID tid = SYMBOL_P(type_sym) ? SYM2ID(type_sym) : 0;
        volatile VALUE ch = rb_funcall(node, env->id_children, 0);
        if (!RB_TYPE_P(ch, T_ARRAY)) {
          const char *tname = SYMBOL_P(type_sym) ? rb_id2name(tid) : "unknown";
          RB_GC_GUARD(ch);
          RB_GC_GUARD(type_sym);
          diff_summary_free(out);
          diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_shape [detail: node=%s children_len=-1]\n", tname ? tname : "unknown");
        }
        long len = RARRAY_LEN(ch);
        if (tid == env->scope) {
          diff_cruby_visit_scope_child(env, node, depth == 0 ? (int)DIFF_SCOPE_PROGRAM : -1, out, depth);
        } else if (tid == env->defn && len >= 2) {
          diff_cruby_add_sym(RARRAY_AREF(ch, 0), out, &out->defs);
          diff_cruby_visit_scope_child(env, RARRAY_AREF(ch, 1), DIFF_SCOPE_DEF, out, depth + 1);
        } else if (tid == env->defs && len >= 3) {
          diff_cruby_visit_val(env, RARRAY_AREF(ch, 0), out, depth + 1);
          diff_cruby_add_sym(RARRAY_AREF(ch, 1), out, &out->defs);
          diff_cruby_visit_scope_child(env, RARRAY_AREF(ch, 2), DIFF_SCOPE_DEF, out, depth + 1);
        } else if (tid == env->cls && len >= 3) {
          out->counts[DIFF_CNT_CLASS]++;
          diff_cruby_visit_val(env, RARRAY_AREF(ch, 0), out, depth + 1);
          diff_cruby_visit_val(env, RARRAY_AREF(ch, 1), out, depth + 1);
          diff_cruby_visit_scope_child(env, RARRAY_AREF(ch, 2), DIFF_SCOPE_CLASS, out, depth + 1);
        } else if (tid == env->mod && len >= 2) {
          out->counts[DIFF_CNT_MODULE]++;
          diff_cruby_visit_val(env, RARRAY_AREF(ch, 0), out, depth + 1);
          diff_cruby_visit_scope_child(env, RARRAY_AREF(ch, 1), DIFF_SCOPE_MODULE, out, depth + 1);
        } else if (tid == env->scls && len >= 2) {
          out->counts[DIFF_CNT_SCLASS]++;
          diff_cruby_visit_val(env, RARRAY_AREF(ch, 0), out, depth + 1);
          diff_cruby_visit_scope_child(env, RARRAY_AREF(ch, 1), DIFF_SCOPE_SCLASS, out, depth + 1);
        } else if (tid == env->iter && len >= 2) {
          diff_cruby_record_block_owner(env, RARRAY_AREF(ch, 0), out);
          diff_cruby_visit_val(env, RARRAY_AREF(ch, 0), out, depth + 1);
          diff_cruby_visit_scope_child(env, RARRAY_AREF(ch, 1), DIFF_SCOPE_BLOCK, out, depth + 1);
        } else if (tid == env->lambda && len >= 1) {
          diff_cruby_visit_scope_child(env, RARRAY_AREF(ch, 0), DIFF_SCOPE_LAMBDA, out, depth + 1);
        } else if (tid == env->for_n && len >= 2) {
          out->counts[DIFF_CNT_FOR]++;
          diff_cruby_visit_val(env, RARRAY_AREF(ch, 0), out, depth + 1);
          diff_cruby_visit_scope_child(env, RARRAY_AREF(ch, 1), -1, out, depth + 1);
        } else if (tid == env->postexe && len >= 1) {
          diff_cruby_visit_scope_child(env, RARRAY_AREF(ch, 0), -1, out, depth + 1);
        } else {
          diff_cruby_count_if_matched(env, tid, out);
          for (long i = 0; i < len; i++) diff_cruby_visit_val(env, RARRAY_AREF(ch, i), out, depth + 1);
        }
        RB_GC_GUARD(ch);
        RB_GC_GUARD(type_sym);
      }

      static void diff_cruby_visit_val(const diff_cruby_env_t *env, VALUE val, diff_summary_t *out, int depth) {
        if (depth >= DIFF_MAX_AST_DEPTH) return;
        if (diff_cruby_is_ast_node(env, val)) {
          diff_cruby_visit_node(env, val, out, depth);
        } else if (RB_TYPE_P(val, T_ARRAY)) {
          long len = RARRAY_LEN(val);
          for (long i = 0; i < len; i++) diff_cruby_visit_val(env, RARRAY_AREF(val, i), out, depth + 1);
        }
      }

      static void diff_collect_cruby_summary(VALUE ast_node, diff_summary_t *out) {
        if (NIL_P(ast_node)) return;
        diff_cruby_env_t env;
        diff_init_cruby_env(&env);
        RB_GC_GUARD(env.ast_node_cls);
        diff_cruby_visit_val(&env, ast_node, out, 0);
        diff_finalize_summary(out);
      }

      static const char *diff_block_mismatch_sub(const char *p_ptr, size_t p_len, const char *c_ptr, size_t c_len) {
        if ((p_len == 5 && memcmp(p_ptr, "super", 5) == 0) || (c_len == 5 && memcmp(c_ptr, "super", 5) == 0)) return "super";
        if (p_len > 0) {
          char p0 = p_ptr[0];
          if (!((p0 >= 'a' && p0 <= 'z') || (p0 >= 'A' && p0 <= 'Z') || p0 == '_')) return "operator";
        }
        if (c_len > 0) {
          char c0 = c_ptr[0];
          if (!((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') || c0 == '_')) return "operator";
        }
        return "method";
      }

      static bool diff_span_equal(const char *pbuf, diff_span_t pspan, const char *cbuf, diff_span_t cspan) {
        return pspan.length == cspan.length &&
               (pspan.length == 0 || memcmp(pbuf + pspan.offset, cbuf + cspan.offset, pspan.length) == 0);
      }

      static size_t diff_copy_span(const char *buf, diff_span_t span, char dst[97]) {
        size_t len = span.length > 96 ? 96 : (size_t)span.length;
        if (len > 0) memcpy(dst, buf + span.offset, len);
        dst[len] = '\0';
        return len;
      }

      static void diff_compare_locals(diff_summary_t *prism, diff_summary_t *cruby) {
        for (size_t s = 0; s < prism->scopes.count; s++) {
          const diff_scope_t *ps = &prism->scopes.items[s];
          const diff_scope_t *cs = &cruby->scopes.items[s];
          const char *sname = diff_scope_kind_name((diff_scope_kind_t)ps->kind);
          if (ps->local_count != cs->local_count) {
            size_t pc = ps->local_count;
            size_t cc = cs->local_count;
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail("INVARIANT[diff_parse_y]: kind=locals_count_mismatch scope=%s [detail: scope_idx=%zu prism=%zu cruby=%zu]\n", sname, s, pc, cc);
          }
          for (uint32_t j = 0; j < ps->local_count; j++) {
            diff_span_t pspan = prism->locals.items[ps->local_start + j];
            diff_span_t cspan = cruby->locals.items[cs->local_start + j];
            if (!diff_span_equal(prism->strbuf.data, pspan, cruby->strbuf.data, cspan)) {
              char pcopy[97];
              char ccopy[97];
              diff_copy_span(prism->strbuf.data, pspan, pcopy);
              diff_copy_span(cruby->strbuf.data, cspan, ccopy);
              diff_summary_free(prism);
              diff_summary_free(cruby);
              diff_invariant_fail("INVARIANT[diff_parse_y]: kind=locals_name_mismatch scope=%s [detail: scope_idx=%zu idx=%zu prism=%s cruby=%s]\n", sname, s, (size_t)j, pcopy, ccopy);
            }
          }
        }
      }

      static void diff_compare_asts(diff_summary_t *prism, diff_summary_t *cruby) {
        size_t common_scopes = prism->scopes.count < cruby->scopes.count ? prism->scopes.count : cruby->scopes.count;
        for (size_t i = 0; i < common_scopes; i++) {
          if (prism->scopes.items[i].kind != cruby->scopes.items[i].kind) {
            const char *pk = diff_scope_kind_name((diff_scope_kind_t)prism->scopes.items[i].kind);
            const char *ck = diff_scope_kind_name((diff_scope_kind_t)cruby->scopes.items[i].kind);
            size_t pc = prism->scopes.count;
            size_t cc = cruby->scopes.count;
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_scope_kind_mismatch prism=%s cruby=%s [detail: scope_idx=%zu prism_scopes=%zu cruby_scopes=%zu]\n", pk, ck, i, pc, cc);
          }
        }
        if (prism->scopes.count != cruby->scopes.count) {
          size_t pc = prism->scopes.count;
          size_t cc = cruby->scopes.count;
          diff_summary_free(prism);
          diff_summary_free(cruby);
          diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_scope_count_mismatch [detail: prism=%zu cruby=%zu]\n", pc, cc);
        }
        diff_compare_locals(prism, cruby);
        for (size_t k = 0; k < DIFF_CNT_LEN; k++) {
          if (prism->counts[k] != cruby->counts[k]) {
            size_t pc = prism->counts[k];
            size_t cc = cruby->counts[k];
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_node_count_mismatch node=%s [detail: prism=%zu cruby=%zu]\n", diff_count_kind_name((diff_count_kind_t)k), pc, cc);
          }
        }
        size_t common_defs = prism->defs.count < cruby->defs.count ? prism->defs.count : cruby->defs.count;
        for (size_t i = 0; i < common_defs; i++) {
          diff_span_t ps = prism->defs.items[i];
          diff_span_t cs = cruby->defs.items[i];
          if (!diff_span_equal(prism->strbuf.data, ps, cruby->strbuf.data, cs)) {
            char pcopy[97];
            char ccopy[97];
            diff_copy_span(prism->strbuf.data, ps, pcopy);
            diff_copy_span(cruby->strbuf.data, cs, ccopy);
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_def_name_mismatch [detail: idx=%zu prism=%s cruby=%s]\n", i, pcopy, ccopy);
          }
        }
        if (prism->defs.count != cruby->defs.count) {
          size_t pc = prism->defs.count;
          size_t cc = cruby->defs.count;
          diff_summary_free(prism);
          diff_summary_free(cruby);
          diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_node_count_mismatch node=def [detail: prism=%zu cruby=%zu]\n", pc, cc);
        }
        if (prism->block_owners.count != cruby->block_owners.count) {
          size_t pc = prism->block_owners.count;
          size_t cc = cruby->block_owners.count;
          diff_summary_free(prism);
          diff_summary_free(cruby);
          diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_block_owner_mismatch sub=count [detail: prism=%zu cruby=%zu]\n", pc, cc);
        }
        for (size_t i = 0; i < prism->block_owners.count; i++) {
          diff_span_t ps = prism->block_owners.items[i];
          diff_span_t cs = cruby->block_owners.items[i];
          if (!diff_span_equal(prism->strbuf.data, ps, cruby->strbuf.data, cs)) {
            char pcopy[97];
            char ccopy[97];
            size_t plen = diff_copy_span(prism->strbuf.data, ps, pcopy);
            size_t clen = diff_copy_span(cruby->strbuf.data, cs, ccopy);
            const char *sub = diff_block_mismatch_sub(pcopy, plen, ccopy, clen);
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_block_owner_mismatch sub=%s [detail: idx=%zu prism=%s cruby=%s]\n", sub, i, pcopy, ccopy);
          }
        }
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
  main_lines << "pm_options_t *options = pm_options_new();"
  main_lines << 'pm_options_version_set(options, "4.0", 3);'
  main_lines << ""
  main_lines << "pm_arena_t *arena = pm_arena_new();"
  main_lines << "pm_parser_t *parser = pm_parser_new(arena, #{source_ptr}, input_size, options);"
  if need_ast
    main_lines << "pm_node_t *root = pm_parse(parser);"
  else
    main_lines << "(void)pm_parse(parser);"
  end
  main_lines << "size_t prism_errs = pm_parser_errors_size(parser);"
  main_lines << "bool prism_ok = (prism_errs == 0);"
  main_lines << 'const char *prism_diag = "ok";'
  main_lines << "if (!prism_ok) {"
  main_lines << "  const pm_diagnostic_t *first_err = pm_parser_errors_first(parser);"
  main_lines << '  prism_diag = (first_err != NULL) ? pm_diagnostic_type(first_err) : "error";'
  main_lines << "}"
  if need_ast
    main_lines << "diff_summary_t prism_ast;"
    main_lines << "diff_summary_init(&prism_ast);"
    main_lines << "if (prism_ok && root != NULL && PM_NODE_TYPE_P(root, PM_PROGRAM_NODE)) {"
    main_lines << "  diff_collect_prism_summary(parser, root, &prism_ast);"
    main_lines << "}"
  end
  main_lines << "pm_parser_free(parser);"
  main_lines << "pm_arena_free(arena);"
  main_lines << "pm_options_free(options);"
  main_lines << ""
  main_lines << "int has_nul = diff_has_nul((const uint8_t *)#{source_ptr}, input_size) ? 1 : 0;"
  main_lines << "int valid_utf8 = diff_is_valid_utf8((const uint8_t *)#{source_ptr}, input_size) ? 1 : 0;"
  main_lines << ""
  main_lines << "RUBY_INIT_STACK;"
  main_lines << "if (ruby_setup() != 0) {"
  main_lines << '  fprintf(stderr, "ruby_setup() failed\n");'
  main_lines << "  free(source);"
  main_lines << "  diff_summary_free(&prism_ast);" if need_ast
  main_lines << "  signal(SIGABRT, SIG_DFL);"
  main_lines << "  abort();"
  main_lines << "}"
  main_lines << 'char *opts[] = {(char *)"ruby", (char *)"--disable=gems", (char *)"--parser=parse.y", (char *)"-e", (char *)""};'
  main_lines << "(void)ruby_options(5, opts);"
  main_lines << 'rb_define_singleton_method(rb_const_get(rb_cObject, rb_intern("Warning")), "warn", diff_warning_warn, -1);'
  main_lines << ""
  main_lines << "assert(input_size <= (size_t)LONG_MAX);"
  main_lines << "volatile VALUE src_str = rb_utf8_str_new((const char *)#{source_ptr}, (long)input_size);"
  main_lines << "free(source);"
  main_lines << "int state = 0;"
  main_lines << "volatile VALUE ast_node = rb_protect(diff_ast_parse_cb, src_str, &state);"
  main_lines << "bool cruby_ok = (state == 0);"
  main_lines << 'char exc_buf[160] = "";'
  main_lines << 'char cruby_tag[128] = "ok";'
  main_lines << "if (!cruby_ok) {"
  main_lines << "  VALUE err = rb_errinfo();"
  main_lines << "  rb_set_errinfo(Qnil);"
  main_lines << "  diff_format_exception(err, exc_buf, sizeof(exc_buf), cruby_tag, sizeof(cruby_tag));"
  main_lines << "}"
  main_lines << "RB_GC_GUARD(src_str);"
  main_lines << ""
  main_lines << "if (prism_ok != cruby_ok) {"
  main_lines << '  const char *sub = prism_ok ? "prism_ok_cruby_err" : "prism_err_cruby_ok";'
  main_lines << "  diff_summary_free(&prism_ast);" if need_ast
  main_lines << '  diff_invariant_fail("INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=%s nul=%d utf8=%d prism=%s cruby=%s [detail: prism_errs=%zu cruby=%s]\n", sub, has_nul, valid_utf8, prism_diag, cruby_ok ? "ok" : cruby_tag, prism_errs, cruby_ok ? "ok" : exc_buf);'
  main_lines << "}"
  if need_ast
    main_lines << "if (prism_ok && cruby_ok) {"
    main_lines << "  diff_summary_t cruby_ast;"
    main_lines << "  diff_summary_init(&cruby_ast);"
    main_lines << "  diff_collect_cruby_summary(ast_node, &cruby_ast);"
    main_lines << "  diff_compare_asts(&prism_ast, &cruby_ast);"
    main_lines << "  diff_summary_free(&cruby_ast);"
    main_lines << "}"
    main_lines << "diff_summary_free(&prism_ast);"
  end
  main_lines << "RB_GC_GUARD(ast_node);"
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

def c_program(input_file, crash_details, crash_output: "", reason: "unknown", executable: "")
  h = decode_fuzz_header(File.binread(input_file))
  source = h[:source]
  is_diff = diff_bucket?(executable: executable, crash_output: crash_output)
  return diff_c_program(source, crash_details, crash_output, build_diff_loupe_url(source)) if is_diff

  stream_mode = h[:stream_mode]
  loupe_url = build_prism_loupe_url(h[:padded_raw], sanitize: sanitizer_loupe_crash?(reason, crash_output))

  source_ptr = source.empty? ? "source_buf" : "source"
  plan = post_parse_plan(crash_output, executable, stream_mode, source_ptr)

  need_limits = false
  need_stdbool = plan[:need_stdbool]
  need_shebang_cb = false
  option_lines = []

  if is_diff
    option_lines << 'pm_options_version_set(options, "4.0", 3);'
  else
    need_limits = h[:need_limits]

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
  end

  # Note: pm_parser_init treats options == NULL as main_script == true for carriage-return
  # warnings on leading `#!...ruby...` lines, whereas pm_options_new() defaults main_script to false.
  use_options = is_diff || !option_lines.empty? || h[:has_shebang_prefix]
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

  if plan[:need_stream_diff_helper]
    helpers << <<~C.chomp
      static void check_stream_diff(pm_parser_t *parser, pm_node_t *node, const uint8_t *source_buf, size_t size, size_t parsed_size, const pm_options_t *options) {
        pm_arena_t *ref_arena = pm_arena_new();
        pm_parser_t *ref_parser = pm_parser_new(ref_arena, source_buf, size, options);
        pm_node_t *ref_node = pm_parse(ref_parser);
        assert((node == NULL) == (ref_node == NULL));

        if (parsed_size == size) {
          if (node != NULL) {
            pm_buffer_t *stream_buf = pm_buffer_new();
            pm_buffer_t *ref_buf = pm_buffer_new();
            pm_serialize(parser, node, stream_buf);
            pm_serialize(ref_parser, ref_node, ref_buf);
            assert(pm_buffer_length(stream_buf) == pm_buffer_length(ref_buf));
            assert(memcmp(pm_buffer_value(stream_buf), pm_buffer_value(ref_buf), pm_buffer_length(stream_buf)) == 0);
            pm_buffer_free(ref_buf);
            pm_buffer_free(stream_buf);
          }
        } else {
          const pm_location_t *stream_data = pm_parser_data_loc(parser);
          const pm_location_t *full_data = pm_parser_data_loc(ref_parser);
          assert(stream_data->length != 0);
          assert(full_data->length != 0 && stream_data->start == full_data->start);
          assert(pm_parser_errors_size(parser) == pm_parser_errors_size(ref_parser));
          assert(pm_parser_warnings_size(parser) == pm_parser_warnings_size(ref_parser));
          if (node != NULL) {
            pm_buffer_t *stream_pp = pm_buffer_new();
            pm_buffer_t *ref_pp = pm_buffer_new();
            pm_prettyprint(stream_pp, parser, node);
            pm_prettyprint(ref_pp, ref_parser, ref_node);
            assert(pm_buffer_length(stream_pp) == pm_buffer_length(ref_pp));
            assert(memcmp(pm_buffer_value(stream_pp), pm_buffer_value(ref_pp), pm_buffer_length(stream_pp)) == 0);
            pm_buffer_free(ref_pp);
            pm_buffer_free(stream_pp);

            pm_arena_t *prefix_arena = pm_arena_new();
            pm_parser_t *prefix_parser = pm_parser_new(prefix_arena, source_buf, parsed_size, options);
            pm_node_t *prefix_node = pm_parse(prefix_parser);
            pm_buffer_t *stream_ser = pm_buffer_new();
            pm_buffer_t *prefix_ser = pm_buffer_new();
            pm_serialize(parser, node, stream_ser);
            pm_serialize(prefix_parser, prefix_node, prefix_ser);
            assert(pm_buffer_length(stream_ser) == pm_buffer_length(prefix_ser));
            assert(memcmp(pm_buffer_value(stream_ser), pm_buffer_value(prefix_ser), pm_buffer_length(stream_ser)) == 0);
            pm_buffer_free(prefix_ser);
            pm_buffer_free(stream_ser);
            pm_parser_free(prefix_parser);
            pm_arena_free(prefix_arena);
          }
        }

        pm_parser_free(ref_parser);
        pm_arena_free(ref_arena);
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
  if plan[:need_stream_diff_helper]
    main_lines << "" if plan[:lines].empty?
    main_lines << "check_stream_diff(parser, node, #{source_ptr}, input_size, parsed_size, #{options_arg});"
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

def bucket_verify_profile(reason:, executable: "", crash_output: "")
  exe = executable.to_s
  if diff_bucket?(executable: exe, crash_output: crash_output)
    "diff_parse_y"
  elsif exe.end_with?("msan") || reason == "use-of-uninitialized-value"
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

def verify_script(reason:, executable: "", crash_output: "")
  profile = bucket_verify_profile(reason: reason, executable: executable, crash_output: crash_output)
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
  is_diff = diff_bucket?(executable: executable, crash_output: crash_output)
  if is_diff
    return <<~SH
      #!/usr/bin/env bash
      set -euo pipefail

      #{repo_root_lookup_bash}

      ORACLE_DIR="${DIFF_ORACLE_DIR:-}"
      if [ -z "$ORACLE_DIR" ]; then
        if mkdir -p "$REPO_ROOT/build" 2>/dev/null && [ -w "$REPO_ROOT/build" ]; then
          ORACLE_DIR="$REPO_ROOT/build/diff-testcase-oracle"
        else
          ORACLE_DIR="$SCRIPT_DIR/.diff-oracle"
        fi
      fi

      args=(
        --mode testcase
        --prism-root "$REPO_ROOT"
        --fuzz-root "$REPO_ROOT"
        --oracle-dir "$ORACLE_DIR"
        --source "$SCRIPT_DIR/testcase.c"
        --output "$SCRIPT_DIR/testcase"
      )
      for flag in "$@"; do
        args+=(--cflag "$flag")
      done

      exec "$REPO_ROOT/test/fuzz/harness/build_diff.sh" "${args[@]}"
    SH
  end

  raw = File.binread(input_file)
  source = raw.bytesize > 4 ? raw.byteslice(4..) : "".b

  is_native_only = executable.end_with?("ijon", "native")
  is_invariant = crash_output.include?("INVARIANT[")
  is_arith_ub = reason == "undefined-behavior" && !crash_output.include?("arena")
  has_long_decimal = source.scan(/[0-9][0-9_]*/n).any? { |s| s.delete("_").bytesize >= 73 }

  defines = []
  defines << "-DPM_ARENA_INITIAL_SIZE=0" unless is_native_only || is_invariant || is_arith_ub
  defines << "-DPM_INTEGER_DIVIDE_THRESHOLD=8" if has_long_decimal || crash_output.match?(/\b(?:pm_integer|pm_bignum)_|(?:integer|bignum)\.c\b/)
  defines << "-DPRISM_DEPTH_MAXIMUM=128" if !is_diff && (source.bytesize >= 48 || reason == "hang" || crash_output.include?("nesting_too_deep") || crash_output.include?("INVARIANT[recursion_depth]"))
  defines << "-DPRISM_BUILD_DEBUG" if crash_output.match?(/fuzz_(free|realloc)_sized/)
  defines << "-DSLOW" if executable.end_with?("slow") || crash_output.include?("INVARIANT[stream_diff]")

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
  Thread.current[:last_testcase_signal] = nil
  o, s = Open3.capture2e(SANITIZER_ENV, "timeout", "-k", "1", "5", executable, input_file)
  timed_out = s.exitstatus == 124 || s.exitstatus == 137
  crashed = !s.success? && !timed_out
  sig = if crashed
          s.termsig || (s.exitstatus && s.exitstatus > 128 ? s.exitstatus - 128 : nil)
        end
  Thread.current[:last_testcase_signal] = sig && (1..64).include?(sig) ? Signal.signame(sig) : nil
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
    elsif line =~ /\A\s*([^\s(]+)?\(([^)]*)\)\s+\[0x[0-9a-fA-F]+\](?:\s+(.+?))?\s*\z/ ||
          line =~ /\A\s*([^\s(]+)\(([^)\s]+)\)\s+((?:\/|[^\s]+:\d+)\S*)\s*\z/
      seen_frames = true
      next if frames.size >= 64

      mod_path = Regexp.last_match(1)
      sym_part = Regexp.last_match(2).to_s
      loc_part = Regexp.last_match(3)
      func = sym_part.sub(/\+0x[0-9a-fA-F]+\z/, "")
      func = nil if func.empty?
      file, line_no, col_no, loc_mod = loc_part && !loc_part.empty? ? parse_frame_location(loc_part) : [nil, nil, nil, nil]
      mod = file ? loc_mod : (mod_path && !mod_path.empty? ? "#{mod_path}(#{sym_part})" : loc_mod)
      frames << {
        "depth" => frames.size,
        "func" => func,
        "file" => file,
        "line" => line_no,
        "col" => col_no,
        "module" => mod,
        "scope" => frame_scope(file)
      }.compact
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

def input_and_options_metadata(minimized_input, reason:, crash_output:, raw_size_bytes: nil, raw_sha256: nil, minimized_matches_signature: nil, executable: "")
  raw_min = File.binread(minimized_input)
  h = decode_fuzz_header(raw_min)
  is_diff = diff_bucket?(executable: executable, crash_output: crash_output)
  loupe_url = is_diff ? build_diff_loupe_url(h[:source]) : build_prism_loupe_url(h[:padded_raw], sanitize: sanitizer_loupe_crash?(reason, crash_output))
  min_sha256 = Digest::SHA256.hexdigest(raw_min)

  options_meta = if is_diff
                   {
                     "ruby_version" => "4.0",
                     "start_line" => 1,
                     "start_line_expr" => nil,
                     "encoding" => nil,
                     "encoding_locked" => false,
                     "freeze" => false,
                     "partial_script" => false,
                     "attach_comments" => false,
                     "main_script" => false,
                     "stream_mode" => false,
                     "frozen_string_literal" => nil,
                     "command_line_flags" => [],
                     "filepath" => nil,
                     "shebang_callback" => false,
                     "stack_budget" => "SIZE_MAX",
                     "scopes_count" => 0,
                     "forwarding_scope" => nil,
                     "forwarding_flags" => []
                   }
                 else
                   {
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
                 end

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
    "options" => options_meta
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
    minimized_matches_signature: minimized_matches_signature,
    executable: executable
  )

  {
    "schema_version" => META_SCHEMA_VERSION,
    "bucket_id" => bucket_id,
    "reason" => reason,
    "signature" => signature,
    "reproducible" => reproducible,
    "timed_out" => timed_out,
    "reproduced_by" => File.basename(executable.to_s),
    "verify_profile" => verify_profile || bucket_verify_profile(reason: reason, executable: executable, crash_output: crash_output),
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
  Thread.current[:last_testcase_signal] = nil

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
      Thread.current[:last_testcase_signal] = nil
      testcase_output, crashed, timed_out = run_testcase("./build/fuzz.lsan", crash_input)
      if crashed
        executable = "./build/fuzz.lsan"
      else
        Thread.current[:last_testcase_signal] = nil
        testcase_output, crashed, timed_out = run_testcase(executable, crash_input)
      end
    end
  elsif executable.end_with?("msan", "slow", "diff")
    # Try the fast ASAN/UBSAN binary first: if it crashes (e.g. on an illegal write,
    # UBSAN check, assertion failure, SEGV, or fast invariant), prefer it for deterministic
    # classification, minimization, and deduplication against main/grammar;
    # otherwise fall back to msan/slow/diff for read issues (MSAN), -DSLOW consumer /
    # differential checks, or CRuby parse.y differential invariants / crashes.
    testcase_output, crashed, timed_out = run_testcase("./build/fuzz", crash_input)
    if crashed
      executable = "./build/fuzz"
    else
      Thread.current[:last_testcase_signal] = nil
      testcase_output, crashed, timed_out = run_testcase(executable, crash_input)
    end
  else
    testcase_output, crashed, timed_out = run_testcase(executable, crash_input)
  end

  sig_name = crashed ? Thread.current[:last_testcase_signal] : nil
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
      elsif testcase_output =~ /^CRASH\[[^\]]+\]:\s*signal=SIG([A-Z0-9_]+)/
        reason = Regexp.last_match(1)
      elsif sig_name && !sig_name.empty?
        reason = sig_name
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

def ensure_bucket_verify_script(bucket_dir, reason:, executable:, crash_output: "")
  verify_path = File.join(bucket_dir, "verify.sh")
  content = verify_script(reason: reason, executable: executable, crash_output: crash_output)
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
    verify_sh = File.join(bucket_dir, "verify.sh")
    verify_text = File.file?(verify_sh) ? File.read(verify_sh) : ""
    candidates = []
    candidates << "./build/fuzz.diff" if verify_text.include?("diff_parse_y")
    candidates << "./build/fuzz.msan" if build_text.include?("-fsanitize=memory")
    candidates << "./build/fuzz.lsan" if build_text.include?("-fsanitize=leak")
    candidates << "./build/fuzz.slow" if build_text.include?("-DSLOW")
    candidates << COVERAGE_BIN unless COVERAGE_BIN.empty?
    candidates.concat(["./build/fuzz", "./build/fuzz.slow", "./build/fuzz.msan", "./build/fuzz.lsan", "./build/fuzz.native", "./build/fuzz.diff"])
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
        executable: executable,
        crash_output: effective_output
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
