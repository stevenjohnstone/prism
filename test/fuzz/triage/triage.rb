# frozen_string_literal: true

require "base64"
require "cgi"
require "concurrent"
require "digest"
require "fileutils"
require "open3"
require "set"
require "tmpdir"

PRISM_LOUPE_BASE_URL = "https://stevenjohnstone.github.io/prism-loupe/"

OUTPUT_DIRS = ["tmp/fuzz/afl", "tmp/fuzz/afl-ijon"].freeze
TESTCASES_DIR = "tmp/fuzz/triage"
TESTCASES_PROCESSED_DIR = File.join(TESTCASES_DIR, ".processed")
MAX_ALLOCATED_MB = Integer(ENV.fetch("FUZZ_MAX_ALLOCATED", "128"))
HARD_RSS_LIMIT_MB = MAX_ALLOCATED_MB * 16
HALFEMPTY_THREADS = Integer(ENV.fetch("HALFEMPTY_THREADS", "2"))

SANITIZER_ENV = {
  "ASAN_OPTIONS" => "abort_on_error=1:handle_abort=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}",
  "UBSAN_OPTIONS" => "abort_on_error=1:print_stacktrace=1",
  "MSAN_OPTIONS" => "abort_on_error=1:handle_abort=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}",
  "LSAN_OPTIONS" => "handle_abort=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}"
}.freeze

FileUtils.mkdir_p(TESTCASES_PROCESSED_DIR)

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

def build_prism_loupe_url(raw)
  return nil if raw.nil? || raw.empty?
  if raw.bytesize < 4
    return "#{PRISM_LOUPE_BASE_URL}?code=#{CGI.escape(Base64.strict_encode64(raw))}"
  end

  b0, b1, b2, b3 = raw.bytes[0, 4]
  source = raw.bytesize > 4 ? raw.byteslice(4..) : "".b
  has_encoding_opts = (b0 & 0x80) != 0
  has_limit_opts = (b1 & 0x80) != 0

  params = [["code", Base64.strict_encode64(source)]]
  params << ["enc", ENCODINGS[b3 & 0x07]] if has_encoding_opts
  params << ["ruby_ver", VERSIONS[b2 & 0x03]]

  start_line = has_limit_opts ? EXTREME_LINES[(b3 >> 4) & 0x03] : [b3].pack("C").unpack1("c")
  params << ["line", start_line.to_s] if start_line != 1

  cmd = COMMAND_LINE_CHARS.filter_map { |bit, ch| ch if (b1 & bit) != 0 }.join
  params << ["cmd", cmd] unless cmd.empty?

  params << ["main", "1"] if (b1 & 0x40) != 0
  params << ["partial", "1"] if (b0 & 0x02) != 0
  params << ["freeze", "1"] if (b0 & 0x01) != 0
  params << ["comments", "1"] if (b0 & 0x04) != 0
  params << ["enc_lock", "1"] if (b0 & 0x08) != 0
  params << ["frozen_lit", (b0 & 0x20) != 0 ? "1" : "0"] if (b0 & 0x10) != 0
  params << ["stream", "1"] if (b0 & 0x40) != 0

  if has_encoding_opts
    params << ["filepath", "fuzz.rb"]
    params << ["shebang_cb", "1"] if (b3 & 0x08) != 0
  end

  if has_limit_opts
    budget = STACK_BUDGETS[(b3 >> 6) & 0x03]
    params << ["budget", budget] unless budget == "SIZE_MAX"
  end

  scopes_count = (b2 >> 2) & 0x03
  if scopes_count > 0
    fwd_bits = (b2 >> 4) & 0x0f
    fwd_chars = FORWARDING_CHARS.filter_map { |bit, ch| ch if (fwd_bits & bit) != 0 }.join
    forwarding_scope = has_encoding_opts ? (b3 % scopes_count) : (scopes_count - 1)

    scope_segments = (0...scopes_count).map do |i|
      locals_count = (i == 0 && source.bytesize > 0) ? 3 : 2
      locals_count = 0 if i == 0 && has_encoding_opts && (b3 & 0x10) != 0
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
    need_stream_helpers: stream_mode,
    need_assert: false,
    need_stdbool: stream_mode,
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
  elsif executable.end_with?("msan", "lsan") && !crash_output.match?(/\bpm_parse(_stream)?\b/)
    plan[:need_node] = true
    plan[:lines] = slow_consumer_lines(stream_mode, source_ptr)
  end

  plan
end

def c_program(input_file, crash_details, crash_output: "", reason: "unknown", executable: "")
  raw = File.binread(input_file)
  padded_raw = raw.bytesize >= 4 ? raw : (raw + ("\x00".b * (4 - raw.bytesize)))
  b0, b1, b2, b3 = padded_raw.bytes[0, 4]
  source = raw.bytesize > 4 ? raw.byteslice(4..) : "".b
  loupe_url = build_prism_loupe_url(padded_raw)

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

  source_ptr = source.empty? ? "source_buf" : "source"
  plan = post_parse_plan(crash_output, executable, stream_mode, source_ptr)

  need_limits = false
  need_stdbool = plan[:need_stdbool]
  need_shebang_cb = false
  option_lines = []

  if has_limit_opts
    extreme_idx = (b3 >> 4) & 0x03
    need_limits = true if extreme_idx != 3
    option_lines << "pm_options_line_set(options, #{EXTREME_LINES_C[extreme_idx]});"
  else
    start_line = [b3].pack("C").unpack1("c")
    option_lines << "pm_options_line_set(options, #{start_line});" if start_line != 1
  end

  option_lines << "pm_options_command_line_set(options, #{format_uint8_bitmask(cmd_flags, COMMAND_LINE_FLAGS)});" if cmd_flags != 0
  if main_script
    need_stdbool = true
    option_lines << "pm_options_main_script_set(options, true);"
  end
  if freeze
    need_stdbool = true
    option_lines << "pm_options_freeze_set(options, true);"
  end
  if partial_script
    need_stdbool = true
    option_lines << "pm_options_partial_script_set(options, true);"
  end
  if attach_comments
    need_stdbool = true
    option_lines << "pm_options_attach_comments_set(options, true);"
  end
  if encoding_locked
    need_stdbool = true
    option_lines << "pm_options_encoding_locked_set(options, true);"
  end
  option_lines << "pm_options_version_set(options, #{version.dump}, #{version.bytesize});" if version != "4.1"
  if has_frozen_string_literal
    need_stdbool = true
    option_lines << "pm_options_frozen_string_literal_set(options, #{frozen_string_literal});"
  end

  if has_encoding_opts
    option_lines << "pm_options_encoding_set(options, #{ENCODINGS[b3 & 0x07].dump});"
    option_lines << 'pm_options_filepath_set(options, "fuzz.rb");'
    if (b3 & 0x08) != 0
      need_shebang_cb = true
      option_lines << "pm_options_shebang_callback_set(options, shebang_cb, NULL);"
    end
  end

  if has_limit_opts
    budget = STACK_BUDGETS[(b3 >> 6) & 0x03]
    option_lines << "pm_options_stack_budget_set(options, #{budget});" unless budget == "SIZE_MAX"
  end

  if scopes_count > 0
    forwarding_scope = has_encoding_opts ? (b3 % scopes_count) : (scopes_count - 1)
    option_lines << "if (pm_options_scopes_init(options, #{scopes_count})) {"
    scopes_count.times do |i|
      locals_count = (i == 0 && !source.empty?) ? 3 : 2
      locals_count = 0 if i == 0 && has_encoding_opts && (b3 & 0x10) != 0
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
  has_shebang_prefix = source.start_with?("#!".b) || source.start_with?("\xef\xbb\xbf#!".b)
  use_options = !option_lines.empty? || has_shebang_prefix
  options_arg = use_options ? "options" : "NULL"

  need_assert = !source.empty? || plan[:need_assert]
  need_string = !source.empty?

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

def process_crash(crash_dir, crash, executable, semaphore, in_progress, pending_sentinels)
  crash_hash = Digest::SHA2.hexdigest(File.binread(crash))
  sentinel = File.join(TESTCASES_PROCESSED_DIR, crash_hash)

  claimed = semaphore.synchronize do
    !File.exist?(sentinel) && !in_progress.add?(crash_hash).nil?
  end
  return unless claimed

  begin
    reason = File.basename(crash_dir) == "hangs" ? "hang" : "unknown"
    timed_out = false

    if reason == "hang"
      testcase_output, crashed, timed_out = run_testcase(executable, crash)
      if !crashed && !timed_out
        puts "Skipping #{crash} (transient timeout)"
        semaphore.synchronize { FileUtils.touch(sentinel) }
        return
      end
    elsif executable.end_with?("ijon", "native")
      # fuzz.ijon and fuzz.native are built without sanitizers (and SAND workers
      # record fuzz.native in cmdline while running fuzz.sand under -w), so try
      # ./build/fuzz (ASAN/UBSAN) first for sanitizer crashes and assertions so
      # they deduplicate with main; next try ./build/fuzz.lsan for memory leaks;
      # finally fall back to executable for cumulative allocation limit assertions
      # in PRISM_XALLOCATOR.
      testcase_output, crashed, timed_out = run_testcase("./build/fuzz", crash)
      if crashed
        executable = "./build/fuzz"
      else
        testcase_output, crashed, timed_out = run_testcase("./build/fuzz.lsan", crash)
        if crashed
          executable = "./build/fuzz.lsan"
        else
          testcase_output, crashed, timed_out = run_testcase(executable, crash)
        end
      end
    elsif executable.end_with?("msan")
      # Try the ASAN/UBSAN binary first: if it crashes (e.g. on an illegal write,
      # UBSAN check, assertion failure, or SEGV), prefer it for deterministic
      # classification, minimization, and deduplication against main/grammar;
      # otherwise fall back to MSAN for read issues (uninitialized or out-of-bounds
      # reads, since ./build/fuzz has ASAN read instrumentation disabled).
      testcase_output, crashed, timed_out = run_testcase("./build/fuzz", crash)
      if crashed
        executable = "./build/fuzz"
      else
        testcase_output, crashed, timed_out = run_testcase(executable, crash)
      end
    else
      testcase_output, crashed, timed_out = run_testcase(executable, crash)
    end

    unreproducible = !crashed && !(reason == "hang" && timed_out)
    if unreproducible && File.basename(crash).include?("sig:09")
      puts "Skipping #{crash} (external SIGKILL / OOM)"
      semaphore.synchronize { FileUtils.touch(sentinel) }
      return
    end

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

    target_directory = if unreproducible
                         File.join(TESTCASES_DIR, "unreproducible", crash_hash[0, 16])
                       else
                         File.join(TESTCASES_DIR, reason, testcase_output_signature(testcase_output, sig_lines))
                       end

    skip_duplicate = semaphore.synchronize do
      if File.directory?(target_directory) && !Dir.empty?(target_directory)
        puts "#{crash} is a duplicate of #{target_directory}"
        FileUtils.touch(sentinel)
        true
      elsif pending_sentinels.key?(target_directory)
        puts "#{crash} is a duplicate of in-progress #{target_directory}"
        pending_sentinels[target_directory] << sentinel
        true
      else
        puts "#{crash} is new"
        pending_sentinels[target_directory] = [sentinel]
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

      if ENV["TRIAGE_MINIMIZE"] == "0" || unreproducible
        FileUtils.cp(crash, minimized_input)
      else
        minimize(crash, reason, minimized_input, executable, sig_lines)
        if reason != "hang"
          min_output, min_crashed, = run_testcase(executable, minimized_input)
          testcase_output = min_output if min_crashed
        end
      end

      details = if unreproducible
                  "Unreproducible crash: #{crash}"
                else
                  "Crash: #{crash}\n#{testcase_output}"
                end
      c_testcase = c_program(
        minimized_input,
        details,
        crash_output: unreproducible ? "" : testcase_output,
        reason: reason,
        executable: executable
      )

      File.write(File.join(staging_dir, "testcase.c"), c_testcase)
      FileUtils.cp(crash, File.join(staging_dir, File.basename(crash)))
      File.chmod(0o777 & ~File.umask, staging_dir)

      semaphore.synchronize do
        Dir.rmdir(target_directory) if File.directory?(target_directory) && Dir.empty?(target_directory)
        unless File.directory?(target_directory)
          File.rename(staging_dir, target_directory)
          published = true
        end
        sentinels = pending_sentinels.delete(target_directory) || [sentinel]
        sentinels.uniq.each { |s| FileUtils.touch(s) }
      end
    ensure
      FileUtils.rm_rf(staging_dir) if !published && staging_dir && File.exist?(staging_dir)
      semaphore.synchronize { pending_sentinels.delete(target_directory) } unless published
    end
    puts "#{crash} complete => #{target_directory}"
  ensure
    semaphore.synchronize { in_progress.delete(crash_hash) }
  end
end

pool = Concurrent::FixedThreadPool.new([Concurrent.processor_count / 2, 1].max)
semaphore = Mutex.new
in_progress = Set.new
pending_sentinels = {}
OUTPUT_DIRS.flat_map { |d| Dir.glob(File.join(d, "**/{crashes*,hangs*}")) }.each do |crash_dir|
  cmdline_file = File.join(crash_dir, "../cmdline")
  next unless File.exist?(cmdline_file)

  executable = File.read(cmdline_file).strip
  Dir.glob(File.join(crash_dir, "/id*")) do |crash|
    pool.post do
      process_crash(crash_dir, crash, executable, semaphore, in_progress, pending_sentinels)
    rescue StandardError => e
      warn "Error processing #{crash}: #{e.class}: #{e.message}\n#{e.backtrace.join("\n")}"
    end
  end
end
pool.shutdown
pool.wait_for_termination
