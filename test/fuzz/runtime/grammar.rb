# frozen_string_literal: true

require "lrama/fuzz"
require "prism"
require "digest"
require "fileutils"
require "securerandom"

afl_dir = ARGV[0] || "./tmp/fuzz/afl"
queue_dir = ARGV[1] || "/tmp/afl-tmpdir/grammar/seeds"
work_dir = File.dirname(queue_dir)
staging_dir = File.join(work_dir, "staging")
in_flight_path = File.join(work_dir, "in_flight")

stats_dir = File.join(afl_dir, "grammar")
crashes_dir = File.join(stats_dir, "crashes")
cmdline_path = File.join(stats_dir, "cmdline")
stats_path = File.join(stats_dir, "fuzzer_stats")
stats_tmp_path = File.join(stats_dir, ".fuzzer_stats.tmp")
plot_path = File.join(stats_dir, "plot_data")

FileUtils.mkdir_p(queue_dir)
FileUtils.mkdir_p(staging_dir)
FileUtils.mkdir_p(crashes_dir)

# Allow `make fuzz-triage` to triage any crashes caught directly inside grammar.rb
File.write(cmdline_path, "./build/fuzz.native\n")

# 4-byte options header consumed by harness() in test/fuzz/harness/parse.c
DEFAULT_HEADER = "\x00\x00\x03\x01".b
MAX_PENDING_SEEDS = Integer(ENV.fetch("FUZZ_GRAMMAR_MAX_PENDING", "50000"))
MAX_SEEN_DIGESTS = 500_000
PRUNE_INTERVAL_SEC = 10.0
GENERATIONS_PER_EPOCH = 50
POPULATION_SIZE = 50
STRING_FRAGMENTS = [
  "hello", "world", "foo", "bar",
  'line1\nline2', 'tab\there', 'utf8_\u{61}', 'hex_\x41',
  'interp_#{["inner", "nested"].first}'
].freeze

WORD_LIST_FRAGMENTS = %w[alpha beta gamma delta foo_bar item_1].freeze

# Valid Onigmo / Prism regexp fragments (no unescaped `/` or `"` so they are valid
# inside both `/.../` and `%r"..."`, and compatible with `/`, `/i`, `/m`, `/x`, `/o`, `/u`).
REGEXP_VALID_FRAGMENTS = [
  # Named captures (<name> and 'name'), backrefs, and subexp calls
  '(?<foo>\w+)(?:\s+(?\'bar\'\d+))?\k<foo>',
  '(?<tok>[a-z]+)|\g<tok>',
  # Groups: non-capturing, lookahead, lookbehind, atomic, absence, conditional
  '(?:foo|bar)+(?=baz)(?!qux)',
  '(?<=^|\s)(?>\w+)(?<!_)(?~end)',
  '(a)(?(1)b|c)',
  '(?<k>x)(?(<k>)y|z)',
  # Inline group option toggles (both standalone `(?imx)`/`(?x-i)`/`(?i-x)` and scoped `(?imx:...)`)
  "(?x-i)foo # ext comment\n(?i-x)bar",
  "(?iix:foo # scoped ext\n)+(?imxdau-imx:bar)+",
  '(?-x:a b c)',
  # Inline comments (including escaped `\)` paren and UTF-8 multibyte text) and extended `#` comments
  '(?#simple comment)foo(?#escaped \) paren)bar',
  '(?#コメント)abc',
  "foo # comment with newline\nbar",
  'foo # trailing comment without newline',
  # Range quantifiers `{n}`, `{n,}`, `{n,m}`, `{,m}` (single & multi-digit) + backtracked `{...}` forms
  'a{12}b{10,}c{2,15}d{,12}',
  'a{foo}b{2x}c{,x}d{2,3x}e{2,',
  # POSIX bracket classes, negated POSIX classes, nested character set intersections, backtracked `[[:`
  '[[:alpha:]][[:digit:]][[:xdigit:]][[:^space:]][[:^cntrl:]]',
  '[a-z&&[^aeiou]][[a-f][0-9]]',
  '[[:unclosed_posix]',
  # All 3 Onigmo property escape tiers: POSIX, Script, and Unicode-only + non-brace `\p`
  '\p{Alpha}\p{ASCII}\p{Blank}\p{Cntrl}\p{Print}\p{Punct}\p{Upper}\p{Word}\p{XDigit}\P{Space}\p{^Digit}',
  '\p{Han}\p{Greek}\p{Latin}\p{Hiragana}\p{^Katakana}\p{Cyrillic}',
  '\p{Lu}\P{Nd}\p{^Assigned}\pa',
  # Unicode escapes (`\uNNNN` and `\u{...}` >= 0x80 with whitespace), valid UTF-8 `\x` groups, meta/control
  '\u3042\u00e9\u{ 3042 3044 0041 }',
  '\xE3\x81\x82a\xC3\xA9',
  '\M-a\C-b\cc\M-\C-d\C-\M-e\M-\cf\c\M-g',
  # Non-ASCII UTF-8 literals (both outside and inside character sets)
  '(?:あいう|λ)+[あ-ん]'
].freeze

# Intentionally malformed / encoding-conflict regexp fragments sampled by the raw
# grammar evolver and post-pass mutator to cover diagnostic & recovery paths in src/regexp.c.
REGEXP_ERROR_FRAGMENTS = [
  '(?<>empty_name)',
  '[]empty_char_class',
  '(?z:undef_opt)',
  '(?-d:non_removable_opt)',
  '(?-z:invalid_remove_opt)',
  '(?i-i+i:re_add_removed)',
  '(+repeat_target)',
  ')unmatched_at_start',
  'a)unmatched_close',
  '(unmatched_open',
  '(?#unclosed_comment',
  '(?<unclosed_group',
  '(?\'unclosed_sq_group',
  '(?(unclosed_cond',
  '(?i',
  '(?-x',
  '(?',
  '\Ma\Cb',
  '\uD800',
  '\u{110000}',
  '\u{1234567}',
  '\u{1234',
  '\u{}',
  '\u{xyz}',
  '\u12',
  '\u',
  '\xFF',
  '\u{3042}\x80',
  '\x80\u{3042}'
].freeze

REGEXP_SAFE_MODIFIERS = ["", "i", "m", "x", "o", "u", "imx", "iu", "mx"].freeze
REGEXP_ALL_MODIFIERS = (REGEXP_SAFE_MODIFIERS + ["n", "e", "s", "ne", "nu"]).freeze
MAGIC_ENCODINGS = %w[us-ascii ascii-8bit euc-jp windows-31j iso-8859-1 utf-8].freeze

def parse_kv_file(path)
  return {} unless File.exist?(path)

  out = {}
  File.foreach(path) do |line|
    k, v = line.split(":", 2)
    out[k.strip] = v.strip if k && v
  end
  out
rescue StandardError
  {}
end

def write_atomic_seed(queue_dir, staging_dir, header, payload, seen_digests)
  payload_bytes = payload.b
  sha1 = Digest::SHA1.new
  sha1.update(header)
  sha1.update(payload_bytes)
  raw_digest = sha1.digest

  return false if seen_digests&.key?(raw_digest)

  if seen_digests
    seen_digests.clear if seen_digests.size >= MAX_SEEN_DIGESTS
    seen_digests[raw_digest] = true
  end

  final_name = raw_digest.unpack1("H*")
  final_path = File.join(queue_dir, final_name)
  return false if File.exist?(final_path)

  tmp_path = File.join(staging_dir, ".tmp_#{Process.pid}_#{SecureRandom.hex(6)}")

  begin
    File.binwrite(tmp_path, header + payload_bytes)
    File.rename(tmp_path, final_path)
  rescue StandardError
    File.unlink(tmp_path) if File.exist?(tmp_path)
    raise
  end

  true
end

# On tmpfs (relatime), newly created seed files have st.atime == st.mtime until
# AFL++'s read_foreign_testcases() opens and mmaps them (setting st.atime > st.mtime)
# and advances foreign_syncs[0].mtime to the max st_mtime it scanned.
# Unlink files already read by the foreign-sync intake worker, as well as any
# older files behind its mtime watermark that it will never revisit.
def prune_synced_seeds(queue_dir)
  now = Time.now
  entries = []
  max_read_mtime = nil

  Dir.children(queue_dir).each do |fname|
    next if fname.start_with?(".")

    path = File.join(queue_dir, fname)
    st = File.stat(path) rescue next
    was_read = st.atime > st.mtime
    mtime_i = st.mtime.to_i
    if was_read && (max_read_mtime.nil? || mtime_i > max_read_mtime)
      max_read_mtime = mtime_i
    end
    entries << [path, was_read, st.mtime]
  end

  pruned = 0
  entries.each do |path, was_read, mtime|
    next if (now - mtime) < 2.0

    if was_read || (max_read_mtime && mtime.to_i < max_read_mtime - 1)
      begin
        File.unlink(path)
        pruned += 1
      rescue Errno::ENOENT
        # ignore
      end
    end
  end

  [entries.size - pruned, pruned]
rescue StandardError
  [0, 0]
end

# Nudge the isolated ijon master via SIGUSR2 (AFL++'s handle_syncreq -> sync_requested = 1)
# so it imports newly generated foreign seeds promptly without waiting for AFL_SYNC_TIME.
def notify_intake_sync(afl_dir)
  ijon_stats_path = File.join("#{afl_dir}-ijon", "ijon", "fuzzer_stats")
  return unless File.exist?(ijon_stats_path)

  pid = parse_kv_file(ijon_stats_path)["fuzzer_pid"].to_i
  Process.kill("USR2", pid) if pid > 0
rescue StandardError
  # ignore if ijon is not running yet or already exited
end

# Iterative AST node count to avoid SystemStackError on deeply nested trees.
def count_prism_nodes(root)
  count = 0
  stack = [root]
  while (node = stack.pop)
    count += 1
    node.child_nodes.each { |child| stack << child if child }
  end
  count
end

def build_guarded_evaluators(in_flight_io)
  with_breadcrumb = lambda do |code, &blk|
    payload = DEFAULT_HEADER + code.b
    in_flight_io.rewind
    in_flight_io.write(payload)
    in_flight_io.flush
    in_flight_io.truncate(payload.bytesize)
    begin
      blk.call
    ensure
      in_flight_io.truncate(0)
    end
  end

  parse_fn = lambda do |code|
    with_breadcrumb.call(code) { ::Prism.parse(code) }
  rescue StandardError, SystemStackError, NoMemoryError
    nil
  end

  validator = lambda do |code|
    with_breadcrumb.call(code) { ::Prism.parse_success?(code) }
  rescue StandardError, SystemStackError, NoMemoryError
    false
  end

  fitness = lambda do |code|
    result = parse_fn.call(code)
    next 0.0 unless result

    if result.success?
      node_count = count_prism_nodes(result.value)
      1.0 + Math.log(node_count + 1) * 0.1
    else
      error_count = result.errors.size
      [0.0, 0.5 - error_count * 0.05].max
    end
  rescue StandardError, SystemStackError, NoMemoryError
    0.0
  end

  [fitness, validator, parse_fn]
end

# Build terminal generators with matching string/regexp delimiters, unary +/-
# operators (`+` / `-` rather than method names `+@` / `-@`), and a delimiter stack
# so `tSTRING_CONTENT` emits regexp syntax inside regexps, clean words inside
# `%w`/`%i` word lists, and string fragments inside strings.
# Note: in CRuby's parse.y, tQWORDS_BEG/tQSYMBOLS_BEG are the non-interpolating
# %w/%i forms, while tWORDS_BEG/tSYMBOLS_BEG are the interpolating %W/%I forms.
def build_ruby_terminals(rng, allow_invalid: false)
  delim_stack = []
  reset_delims = -> { delim_stack.clear }

  terminals = Lrama::Fuzz::RubyTerminals.build(random: rng)
  terminals["tSTRING_BEG"] = -> { delim_stack << [:string, '"']; '"' }
  terminals["tXSTRING_BEG"] = -> { delim_stack << [:string, '"']; '%x"' }
  terminals["tWORDS_BEG"] = -> { delim_stack << [:words, '"']; '%W"' }
  terminals["tQWORDS_BEG"] = -> { delim_stack << [:words, '"']; '%w"' }
  terminals["tSYMBOLS_BEG"] = -> { delim_stack << [:words, '"']; '%I"' }
  terminals["tQSYMBOLS_BEG"] = -> { delim_stack << [:words, '"']; '%i"' }
  terminals["tSTRING_END"] = lambda do
    top_kind = delim_stack.last&.first
    delim_stack.pop if top_kind == :string || top_kind == :words
    '"'
  end
  terminals["tSTRING_DBEG"] = -> { delim_stack << [:interp, "}"]; '#{' }
  terminals["tSTRING_DEND"] = lambda do
    delim_stack.pop if delim_stack.last&.first == :interp
    "}"
  end
  terminals["tREGEXP_BEG"] = lambda do
    if rng.rand < 0.85
      delim_stack << [:regexp, "/"]
      "/"
    else
      delim_stack << [:regexp, '"']
      '%r"'
    end
  end
  terminals["tREGEXP_END"] = lambda do
    idx = delim_stack.rindex { |k, _| k == :regexp }
    close_delim = if idx
                    _, d = delim_stack[idx]
                    delim_stack.slice!(idx..-1)
                    d
                  else
                    "/"
                  end
    mods = (allow_invalid && rng.rand < 0.25) ? REGEXP_ALL_MODIFIERS : REGEXP_SAFE_MODIFIERS
    "#{close_delim}#{mods.sample(random: rng)}"
  end
  terminals["tUPLUS"] = "+"
  terminals["tUMINUS"] = "-"
  terminals["tSTRING_CONTENT"] = lambda do
    case delim_stack.last&.first
    when :regexp
      if allow_invalid && rng.rand < 0.18
        REGEXP_ERROR_FRAGMENTS.sample(random: rng)
      else
        REGEXP_VALID_FRAGMENTS.sample(random: rng)
      end
    when :words
      WORD_LIST_FRAGMENTS.sample(random: rng)
    else
      STRING_FRAGMENTS.sample(random: rng)
    end
  end
  [terminals, reset_delims]
end

# Extend lrama-fuzz's Ruby::Composer so composed programs also exercise regexp
# literals (including inside `case ... in /.../` and `case ... when /.../`),
# `=~` / `!~` calls, and LHS named-capture `MatchWriteNode` variable introduction
# (both plain `/(?<x>...)/ =~ str` and interpolated `/(?<x>...)#{v}/x =~ str`).
class PrismComposer < Lrama::Fuzz::Ruby::Composer
  PRISM_TEMPLATES = (Lrama::Fuzz::Ruby::Composer::TEMPLATES + %i[regexp_match]).freeze
  PRISM_NESTED_TEMPLATES = (Lrama::Fuzz::Ruby::Composer::NESTED_TEMPLATES + %i[regexp_match]).freeze

  private

  def pick_template(pool = PRISM_TEMPLATES)
    pool = PRISM_NESTED_TEMPLATES if pool.equal?(Lrama::Fuzz::Ruby::Composer::NESTED_TEMPLATES)
    super(pool)
  end

  def nested_fragment
    @nesting += 1
    send(PRISM_NESTED_TEMPLATES.sample(random: @random))
  ensure
    @nesting -= 1
  end

  def literal_expr
    return regexp_literal if @random.rand < 0.22
    super
  end

  def rich_expr
    r = @random.rand
    if r < 0.12
      regexp_match
    elsif r < 0.20
      op = @random.rand < 0.5 ? "=~" : "!~"
      "#{simple_expr} #{op} #{regexp_literal}"
    else
      super
    end
  end

  def regexp_literal
    body = REGEXP_VALID_FRAGMENTS.sample(random: @random)
    flags = REGEXP_SAFE_MODIFIERS.sample(random: @random)
    if @random.rand < 0.8
      "/#{body}/#{flags}"
    else
      "%r\"#{body}\"#{flags}"
    end
  end

  def regexp_match
    rhs = @defined_vars.empty? ? %("#{WORDS.sample(random: @random)}") : known_var
    if @random.rand < 0.55
      cap1 = define_var
      cap2 = define_var
      inner = REGEXP_VALID_FRAGMENTS.sample(random: @random)
      flags = REGEXP_SAFE_MODIFIERS.sample(random: @random)
      "/(?<#{cap1}>[[:alpha:]]+)(?'#{cap2}'\\d*)#{inner}/#{flags} =~ #{rhs}"
    else
      interp_expr = @defined_vars.empty? ? literal_expr : known_var
      cap1 = define_var
      cap2 = define_var
      flags = %w[x ix mx u].sample(random: @random)
      "/(?<#{cap1}>\\p{Alpha}+)\#{#{interp_expr}}(?'#{cap2}'[0-9]{1,3}) # ext\n/#{flags} =~ #{rhs}"
    end
  end
end

# Emit an encoding / multibyte regexp variant to exercise parser->encoding_changed
# paths in src/regexp.c (US-ASCII, ASCII-8BIT, EUC-JP, Windows-31J, ISO-8859-1, UTF-8).
def inject_encoding_variant(code, rng)
  enc = MAGIC_ENCODINGS.sample(random: rng)
  extra = case rng.rand(6)
          when 0
            # Valid EUC-JP / SJIS / UTF-8 / single-byte raw multibyte (with ASCII prefix) under /n, /e, /s, /u
            mod = %w[n e s u].sample(random: rng)
            raw_seq = ["abc\xA4\xA2".b, "abc\x82\xA0".b, "abc\xE3\x81\x82".b, "abc\xFF".b].sample(random: rng)
            "/#{raw_seq}/#{mod}".b
          when 1
            # Multibyte inline comment `(?#...)` slow path + invalid multibyte inside `[...]`
            raw_seq = ["\xA4\xA2\\)ok".b, "\xFF".b].sample(random: rng)
            "/(?##{raw_seq})[#{raw_seq}]/".b
          when 2
            # Property escape tier mismatches (/n rejects Script+Unicode; /e,/s reject Unicode-only)
            prop = %w[\p{Hiragana} \p{Lu} \p{Alpha} \p{^Katakana}].sample(random: rng)
            mod = %w[n e s u].sample(random: rng)
            "/#{prop}/#{mod}".b
          when 3
            # Unicode & hex escapes (mixed and standalone) across encoding modifiers
            seq = ['\u{3042}', '\u{3042}\x80', '\x80\u{3042}', '\xE3\x81\x82', '\x82\xA0', '\xFE'].sample(random: rng)
            mod = ["", "n", "e", "s", "u"].sample(random: rng)
            "/#{seq}/#{mod}".b
          when 4
            "/#{REGEXP_ERROR_FRAGMENTS.sample(random: rng)}/".b
          else
            "".b
          end
  prefix = "# encoding: #{enc}\n".b
  extra.empty? ? (prefix + code.b) : (prefix + code.b + "\n".b + extra + "\n".b)
end

# Collect double-quoted StringNode and InterpolatedStringNode spans from a Prism AST.
def collect_double_quoted_strings(root)
  candidates = []
  stack = [[root, false]]
  while (entry = stack.pop)
    node, in_concat = entry
    is_concat = node.is_a?(::Prism::InterpolatedStringNode) && node.opening_loc.nil?
    if !in_concat &&
       (node.is_a?(::Prism::StringNode) || node.is_a?(::Prism::InterpolatedStringNode)) &&
       node.opening_loc && node.closing_loc &&
       node.opening_loc.slice == '"' && node.closing_loc.slice == '"'
      candidates << node
    end
    node.child_nodes.each { |child| stack << [child, is_concat] if child }
  end
  candidates.sort_by { |n| n.location.start_offset }
end

# Rewrite 1..3 non-overlapping double-quoted string literals into heredocs on a
# single pass (`<<H`, `<<-H`, `<<~H`, `<<"H"`, `<<'H'`, or `<<\`H\``), splicing
# each heredoc body + terminator immediately after the physical line's `\n`.
# Running a second pass produces nested heredocs inside `#{...}` interpolations.
def rewrite_heredocs_pass(code, rng, parse_fn, id_offset = 0)
  src = code.b
  src = "#{src}\n".b unless src.end_with?("\n".b)
  result = parse_fn.call(src)
  return nil unless result&.value

  all_strings = collect_double_quoted_strings(result.value)
  return nil if all_strings.empty?

  # Pick up to 3 disjoint string spans (preferring shuffled variety, then sorted by offset)
  chosen = []
  all_strings.shuffle(random: rng).each do |node|
    s = node.location.start_offset
    e = node.location.end_offset
    next if chosen.any? { |c| s < c.location.end_offset && e > c.location.start_offset }

    chosen << node
    break if chosen.size >= 3
  end
  return nil if chosen.empty?

  chosen.sort_by! { |n| n.location.start_offset }

  inline_replacements = []
  line_insertions = Hash.new { |h, k| h[k] = +"".b }

  chosen.each_with_index do |node, idx|
    tag = "H#{id_offset + idx}"
    open_start = node.location.start_offset
    close_end = node.location.end_offset
    inner = src.byteslice(node.opening_loc.end_offset...node.closing_loc.start_offset)
    plain_string = node.is_a?(::Prism::StringNode) && !inner.include?("\\")

    opener, indent_body, indent_term =
      case rng.rand(plain_string ? 6 : 5)
      when 0 then ["<<#{tag}", "", ""]
      when 1 then ["<<-#{tag}", "  ", "  "]
      when 2 then ["<<~#{tag}", "  ", "  "]
      when 3 then ["<<\"#{tag}\"", "", ""]
      when 4 then ["<<`#{tag}`", "", ""]
      else        ["<<'#{tag}'", "", ""]
      end

    line_nl = src.byteindex("\n", close_end) || (src.bytesize - 1)
    body_line = inner.empty? ? "" : "#{indent_body}#{inner}\n"
    heredoc_block = "#{body_line}#{indent_term}#{tag}\n".b

    inline_replacements << [open_start, close_end, opener.b]
    line_insertions[line_nl + 1] << heredoc_block
  end

  # Apply inline string->opener replacements and after-newline body insertions
  # in a single left-to-right pass over byte offsets.
  out = +"".b
  cursor = 0
  events = []
  inline_replacements.each { |s, e, rep| events << [s, :replace, e, rep] }
  line_insertions.each { |pos, blk| events << [pos, :insert, pos, blk] }
  # Process replacements before insertions at the same offset
  events.sort_by! { |pos, kind, _, _| [pos, kind == :replace ? 0 : 1] }

  events.each do |pos, _kind, end_pos, text|
    out << src.byteslice(cursor...pos) if pos > cursor
    out << text
    cursor = end_pos
  end
  out << src.byteslice(cursor..(-1)) if cursor < src.bytesize
  out
rescue StandardError
  nil
end

def inject_heredocs(code, rng, parse_fn)
  pass1 = rewrite_heredocs_pass(code, rng, parse_fn, 0)
  return nil unless pass1

  if rng.rand < 0.4
    pass2 = rewrite_heredocs_pass(pass1, rng, parse_fn, 10)
    return pass2 if pass2
  end

  pass1
end

def build_evolvers(grammar, rng, fitness, validator)
  classifier = Lrama::Fuzz::Ruby.method(:classifier)
  # Also avoid dsym (tSYMBEG string_contents tSTRING_END emits `:..."` without an
  # opening quote because tSYMBEG is `:`) and END_OF_INPUT (string_dend -> END_OF_INPUT
  # omits the closing `}` on `#{...}`).
  avoid = Lrama::Fuzz::Ruby::AVOID_SYMBOLS + Set["dsym", "END_OF_INPUT"]

  comp_rng = Random.new(rng.rand(2**32))
  comp_terminals, comp_reset_delims = build_ruby_terminals(comp_rng, allow_invalid: false)
  comp_gen = Lrama::Fuzz::Generator.new(
    grammar,
    terminals: comp_terminals,
    classifier: classifier,
    avoid_symbols: avoid,
    max_depth: rng.rand(8..12),
    random: comp_rng
  )
  # Filter avoided rules upfront in pick_rule so once all non-avoided rules of a
  # non-terminal are covered, `uncovered` does not fall back to avoided rules,
  # and clear the delimiter stack at the start of every derivation.
  comp_gen.singleton_class.prepend(Module.new do
    define_method(:generate) do |**kwargs|
      comp_reset_delims.call
      super(**kwargs)
    end

    define_method(:generate_from) do |*args|
      comp_reset_delims.call
      super(*args)
    end

    define_method(:generate_targeted) do
      comp_reset_delims.call
      super()
    end

    def pick_rule(rules)
      super(filter_avoided(rules))
    end
  end)
  composed_evolver = Lrama::Fuzz::ComposedEvolver.new(
    comp_gen,
    fitness: fitness,
    composer_class: PrismComposer,
    validator: validator,
    population_size: POPULATION_SIZE,
    genome_length: 300,
    mutation_rate: 0.05 + rng.rand * 0.07,
    random: Random.new(rng.rand(2**32))
  )

  gram_rng = Random.new(rng.rand(2**32))
  gram_terminals, gram_reset_delims = build_ruby_terminals(gram_rng, allow_invalid: true)
  grammar_evolver = Lrama::Fuzz::Evolver.new(
    grammar,
    terminals: gram_terminals,
    fitness: fitness,
    classifier: classifier,
    avoid_symbols: avoid,
    max_depth: rng.rand(8..14),
    population_size: POPULATION_SIZE,
    genome_length: 220,
    mutation_rate: 0.05 + rng.rand * 0.10,
    random: gram_rng
  )
  grammar_evolver.singleton_class.prepend(Module.new do
    define_method(:generate_from_genome) do |genome|
      gram_reset_delims.call
      super(genome)
    end
  end)

  [composed_evolver, grammar_evolver]
end

def run_worker(grammar:, supervisor_pid:, start_time:, saved_crashes:, afl_dir:, queue_dir:, staging_dir:, in_flight_path:, stats_path:, stats_tmp_path:, plot_path:)
  prev_stats = parse_kv_file(stats_path)
  start_ts = start_time.to_i

  seen_digests = {}
  existing_files = Dir.children(queue_dir).reject { |f| f.start_with?(".") }
  existing_files.each do |fname|
    seen_digests[[fname].pack("H*")] = true if fname.length == 40
  end

  resumed = prev_stats["start_time"].to_i == start_ts
  files_created = resumed ? prev_stats["files_created"].to_i : existing_files.size
  files_pruned = resumed ? prev_stats["files_pruned"].to_i : 0
  files_valid = resumed ? prev_stats["files_valid"].to_i : 0
  files_invalid = resumed ? prev_stats["files_invalid"].to_i : 0
  duplicates_skipped = resumed ? prev_stats["duplicates_skipped"].to_i : 0
  attempts_done = resumed ? prev_stats["attempts_done"].to_i : existing_files.size
  last_find_ts = resumed ? prev_stats["last_find"].to_i : start_ts
  pending_files = existing_files.size

  now_f = Time.now.to_f
  last_stats_flush = now_f
  last_plot_flush = now_f
  last_prune_time = now_f
  prev_stats_files = files_created
  prev_plot_files = files_created
  inst_rate = 0.0

  in_flight_io = File.open(in_flight_path, File::RDWR | File::CREAT | File::BINARY, 0o600)
  in_flight_io.sync = true
  fitness, validator, parse_fn = build_guarded_evaluators(in_flight_io)

  flush_telemetry = lambda do |force_plot: false|
    now = Time.now.to_f
    now_i = now.to_i
    elapsed = [now - start_time, 0.001].max
    dt_stats = now - last_stats_flush
    if dt_stats >= 0.25
      inst_rate = (files_created - prev_stats_files) / dt_stats
      prev_stats_files = files_created
      last_stats_flush = now
    end
    avg_rate = files_created / elapsed

    stats_content = <<~STATS
      start_time        : #{start_ts}
      last_update       : #{now_i}
      run_time          : #{(now_i - start_ts)}
      fuzzer_pid        : #{supervisor_pid}
      fuzzer_role       : generator
      power_mode        : evolve
      afl_banner        : lrama-fuzz
      command_line      : ruby ./test/fuzz/runtime/grammar.rb #{afl_dir} #{queue_dir}
      corpus_count      : #{files_created}
      files_created     : #{files_created}
      pending_files     : #{pending_files}
      max_pending_files : #{MAX_PENDING_SEEDS}
      files_pruned      : #{files_pruned}
      files_valid       : #{files_valid}
      files_invalid     : #{files_invalid}
      duplicates_skipped: #{duplicates_skipped}
      attempts_done     : #{attempts_done}
      execs_done        : #{attempts_done}
      execs_per_sec     : #{format("%.2f", avg_rate)}
      files_per_sec     : #{format("%.2f", inst_rate > 0 ? inst_rate : avg_rate)}
      avg_files_per_sec : #{format("%.2f", avg_rate)}
      saved_crashes     : #{saved_crashes}
      saved_hangs       : 0
      last_find         : #{last_find_ts}
    STATS

    File.write(stats_tmp_path, stats_content)
    File.rename(stats_tmp_path, stats_path)

    dt_plot = now - last_plot_flush
    if force_plot || dt_plot >= 5.0
      plot_rate = dt_plot > 0 ? (files_created - prev_plot_files) / dt_plot : avg_rate
      rel_time = [now_i - start_ts, 0].max
      File.open(plot_path, "a") do |f|
        f.puts("#{rel_time}, #{files_created}, #{format('%.2f', plot_rate)}, #{format('%.2f', avg_rate)}, #{attempts_done}, #{files_valid}, #{files_invalid}")
      end
      prev_plot_files = files_created
      last_plot_flush = now
    end

    $stdout.write(
      format(
        "\r[lrama-fuzz] created: %d (valid: %d, invalid: %d, pending: %d, crashes: %d) | rate: %.1f/s (avg: %.1f/s)   ",
        files_created, files_valid, files_invalid, pending_files, saved_crashes,
        inst_rate > 0 ? inst_rate : avg_rate, avg_rate
      )
    )
    $stdout.flush
  rescue StandardError
    # ignore transient I/O errors during shutdown
  end

  Signal.trap("INT") do
    flush_telemetry.call(force_plot: true)
    exit!(0)
  end
  Signal.trap("TERM") do
    flush_telemetry.call(force_plot: true)
    exit!(0)
  end

  flush_telemetry.call(force_plot: !resumed)

  # Optional fault-injection hook for testing supervisor crash capture:
  if (fault_sig = ENV["FUZZ_GRAMMAR_TEST_CRASH_SIG"]) && !resumed
    in_flight_io.rewind
    in_flight_io.write(DEFAULT_HEADER + "def crash_test; end\n".b)
    in_flight_io.truncate(24)
    Process.kill(fault_sig, Process.pid)
  end

  master_rng = Random.new
  initial_sync_notified = false

  emit_candidate = lambda do |code, is_valid|
    while pending_files >= MAX_PENDING_SEEDS
      notify_intake_sync(afl_dir)
      pending_files, newly_pruned = prune_synced_seeds(queue_dir)
      files_pruned += newly_pruned
      last_prune_time = Time.now.to_f
      flush_telemetry.call
      break if pending_files < MAX_PENDING_SEEDS

      sleep(0.5)
    end

    attempts_done += 1
    if write_atomic_seed(queue_dir, staging_dir, DEFAULT_HEADER, code, seen_digests)
      files_created += 1
      pending_files += 1
      if is_valid
        files_valid += 1
      else
        files_invalid += 1
      end
      last_find_ts = Time.now.to_i
      if !initial_sync_notified && pending_files >= 200
        notify_intake_sync(afl_dir)
        initial_sync_notified = true
      end
    else
      duplicates_skipped += 1
    end

    now = Time.now.to_f
    if (now - last_prune_time) >= PRUNE_INTERVAL_SEC
      pending_files, newly_pruned = prune_synced_seeds(queue_dir)
      files_pruned += newly_pruned
      notify_intake_sync(afl_dir) if pending_files > 0
      last_prune_time = now
    end

    if (now - last_stats_flush) >= 1.0
      flush_telemetry.call
    end
  end

  record_batch = lambda do |batch|
    batch.each do |code, fitness_score|
      emit_candidate.call(code, fitness_score >= 1.0)

      # Rewrite double-quoted strings into heredocs (including multi-heredoc lines
      # and nested heredocs in interpolation) on ~35% of string-bearing candidates.
      if code.include?('"') && master_rng.rand < 0.35
        heredoc_code = inject_heredocs(code, master_rng, parse_fn)
        if heredoc_code
          emit_candidate.call(heredoc_code, validator.call(heredoc_code))
        end
      end

      # Emit magic `# encoding:` + multibyte/modifier regexp variants on ~18% of candidates.
      if master_rng.rand < 0.18
        enc_code = inject_encoding_variant(code, master_rng)
        emit_candidate.call(enc_code, validator.call(enc_code))
      end
    end
  end

  loop do
    composed_evolver, grammar_evolver = build_evolvers(grammar, master_rng, fitness, validator)
    GENERATIONS_PER_EPOCH.times do
      record_batch.call(composed_evolver.evolve)
      record_batch.call(grammar_evolver.evolve)
    end
  end
ensure
  in_flight_io&.close rescue nil
end

# Parse CRuby's parse.y once in the supervisor before forking so respawned
# workers inherit the prepared grammar via copy-on-write without re-parsing.
ruby_src_dir = ENV.fetch("RUBY_SRC_DIR", "/opt/ruby")
grammar = Lrama::Fuzz.parse_ruby(
  parse_y_path: File.join(ruby_src_dir, "parse.y"),
  id_def_path: File.join(ruby_src_dir, "defs", "id.def")
)

File.write(plot_path, "# relative_time, files_created, files_per_sec, avg_files_per_sec, attempts_done, files_valid, files_invalid\n")
File.unlink(in_flight_path) if File.exist?(in_flight_path)

supervisor_pid = Process.pid
start_time = Time.now.to_f
saved_crashes = Dir.glob(File.join(crashes_dir, "id:*")).size
stopping = false
child_pid = nil

stop_supervisor = lambda do |sig|
  stopping = true
  if child_pid
    begin
      Process.kill(sig, child_pid)
    rescue Errno::ESRCH
      # already exited
    end
  end
end

Signal.trap("INT") { stop_supervisor.call("INT") }
Signal.trap("TERM") { stop_supervisor.call("TERM") }

until stopping
  child_pid = Process.fork do
    run_worker(
      grammar: grammar,
      supervisor_pid: supervisor_pid,
      start_time: start_time,
      saved_crashes: saved_crashes,
      afl_dir: afl_dir,
      queue_dir: queue_dir,
      staging_dir: staging_dir,
      in_flight_path: in_flight_path,
      stats_path: stats_path,
      stats_tmp_path: stats_tmp_path,
      plot_path: plot_path
    )
  end

  _, status = Process.wait2(child_pid)
  child_pid = nil
  break if stopping

  if status.signaled? && ![Signal.list["INT"], Signal.list["TERM"]].include?(status.termsig)
    sig = status.termsig
    if File.exist?(in_flight_path) && File.size(in_flight_path) > 0
      raw = File.binread(in_flight_path)
      File.unlink(in_flight_path) rescue nil

      rel_ms = ((Time.now.to_f - start_time) * 1000).round
      crash_name = format("id:%06d,sig:%02d,src:lrama-fuzz,time:%d", saved_crashes, sig, rel_ms)
      crash_file = File.join(crashes_dir, crash_name)
      File.binwrite(crash_file, raw)
      saved_crashes += 1

      # Also drop into queue_dir so main tests it under ASAN/UBSAN as well
      if raw.bytesize >= 4
        write_atomic_seed(queue_dir, staging_dir, raw.byteslice(0, 4), raw.byteslice(4..), nil) rescue nil
      end

      warn "\n[lrama-fuzz] Caught worker signal #{sig}! Saved crashing input to #{crash_file} and restarting worker..."
    else
      warn "\n[lrama-fuzz] Worker exited on signal #{sig} (no in-flight input); restarting in 1s..."
      sleep(1.0)
    end
  elsif !status.success?
    warn "\n[lrama-fuzz] Worker exited with status #{status.exitstatus}; restarting in 1s..."
    sleep(1.0)
  else
    break
  end
end
