#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "optparse"
require "tmpdir"

minimize = true
OptionParser.new do |opts|
  opts.banner = "Usage: corpus.rb [options] [OUTPUT_DIR]"
  opts.on("--no-minimize", "Copy generated seed files without running afl-cmin") do
    minimize = false
  end
  opts.on("-h", "--help", "Show this help message") do
    puts opts
    exit 0
  end
end.parse!(ARGV)

MINIMIZE = minimize
OUTPUT_DIR = File.absolute_path(ARGV[0] || "./tmp/fuzz/corpus")
CORPUS_DIR = "./test/prism/fixtures"
MAX_INPUT_SIZE = Integer(ENV.fetch("FUZZ_MAX_INPUT_SIZE", "1024"))
MAX_PAYLOAD_SIZE = [MAX_INPUT_SIZE - 4, 1].max

# 4-byte options header consumed by harness() in test/fuzz/harness/parse.c:
#   byte 0 (0x00): default opt_flags (encoding_locked=false, freeze=false, etc.)
#   byte 1 (0x00): default cmd_flags=0, main_script=false
#   byte 2 (0x03): version_idx=3 ("4.1"), scopes_count=0, forwarding=0
#   byte 3 (0x01): start_line=1
DEFAULT_HEADER = "\x00\x00\x03\x01".b

OPTION_SEED_VARIANTS = [
  ["opt_ruby_3_3",      "\x00\x00\x00\x01".b, "def f(a = 1, &blk); it + a; end\n"],
  ["opt_ruby_3_4",      "\x00\x00\x01\x01".b, "[1, 2].map { it * 2 }\n"],
  ["opt_ruby_3_5",      "\x00\x00\x02\x01".b, "case x; in [Integer => a, *rest]; a; end\n"],
  ["opt_freeze",        "\x01\x00\x03\x01".b, "x = 'hello'; y = [1, :sym, /re/i]\n"],
  ["opt_partial",       "\x02\x00\x03\x01".b, "return 1 if retry_ok || break_ok\nyield 2\n"],
  ["opt_comments",      "\x04\x00\x03\x01".b, "# frozen_string_literal: true\n=begin\ndoc\n=end\nx = 1 # inline\n"],
  ["opt_enc_locked",    "\x08\x00\x03\x01".b, "# encoding: ASCII-8BIT\nx = \"\\x80\\xff\"\n"],
  ["opt_fsl_false",     "\x10\x00\x03\x01".b, "s = \"mutable \#{1 + 2}\"\n"],
  ["opt_fsl_true",      "\x30\x00\x03\x01".b, "s = \"frozen\" + 'lit'\n"],
  ["opt_cmd_nl_split",  "\x00\x1d\x03\x01".b, "puts $F.first if $. == 1\n"],
  ["opt_cmd_e",         "\x00\x02\x03\x01".b, "if /foo/ .. /bar/; print; end\n"],
  ["opt_cmd_x_main",    "\x04\x60\x03\x01".b, "junk before shebang\n#!ruby\nx = 1\n__END__\ndata\n"],
  ["opt_scope_fwd_all", "\x00\x00\xf7\x01".b, "bar(...); baz(*, **, &)\n"],
  ["opt_scope_depth2",  "\x00\x00\x7b\x01".b, "local_0 = 1; call(*, **)\n"],
  ["opt_neg_line",      "\x04\x00\x03\xff".b, "__LINE__ + 1\ndef m; __LINE__; end\n"],
  ["opt_stream_mode",   "\x40\x04\x03\x01".b, "def stream_fn(x)\n  x + 1\nend\n__END__\ntrailing\n"]
].freeze

def split_payload_chunks(bytes, max_len)
  return [bytes] if bytes.bytesize <= max_len

  chunks = []
  pos = 0
  total = bytes.bytesize
  while pos < total
    rem = total - pos
    if rem <= max_len
      chunks << bytes.byteslice(pos, rem)
      break
    end

    window = bytes.byteslice(pos, max_len)
    nl = window.rindex("\n".b)
    take = nl && nl >= max_len / 2 ? nl + 1 : max_len
    chunks << bytes.byteslice(pos, take)
    pos += take
  end
  chunks
end

FileUtils.mkdir_p(File.dirname(OUTPUT_DIR))
executable = File.absolute_path("./build/fuzz") if MINIMIZE

Dir.chdir(CORPUS_DIR)

puts "Generating corpus in directory: #{OUTPUT_DIR}"
puts "------------------------------------------------"

staging_dir = "#{OUTPUT_DIR}.tmp.#{Process.pid}"
FileUtils.rm_rf(staging_dir)

begin
  Dir.mktmpdir do |tmpdir|
    count = 0

    Dir.glob("**/*.txt") do |filename|
      next if File.directory?(filename)

      base = filename.gsub(/[^a-zA-Z0-9.-]/, "_")
      chunks = split_payload_chunks(File.binread(filename), MAX_PAYLOAD_SIZE)
      chunks.each_with_index do |chunk, idx|
        suffix = chunks.size > 1 ? ".part#{idx}.rb" : ".rb"
        target_filename = File.join(tmpdir, "#{base}#{suffix}")
        File.binwrite(target_filename, DEFAULT_HEADER + chunk)
        count += 1
      end
      puts "✅ Generated: #{base} (#{chunks.size} chunk#{'s' if chunks.size != 1})"
    end

    OPTION_SEED_VARIANTS.each do |name, hdr, snippet|
      payload = snippet.b.byteslice(0, MAX_PAYLOAD_SIZE)
      target_filename = File.join(tmpdir, "#{name}.rb")
      File.binwrite(target_filename, hdr + payload)
      puts "✅ Generated: #{target_filename}"
      count += 1
    end

    base_content = <<~RUBY
      # This acts as a standard variable assignment
      foo = "Standard: abc"

      # This tests Latin-1/Windows handling
      bar = "Accents: ü"
      baz = "Currency: €"

      # This tests multibyte/wide handling
      qux = "Japanese: あ"

      puts [foo, bar, baz, qux]
    RUBY

    Encoding.list.each do |target_enc|
      next if target_enc.dummy?

      encoded_body = base_content.encode(target_enc, "binary", invalid: :replace, undef: :replace, replace: "")
      magic_comment = "# encoding: #{target_enc.name}\n".encode(target_enc)
      full_script = (magic_comment + encoded_body).b.byteslice(0, MAX_PAYLOAD_SIZE)

      safe_name = target_enc.name.gsub(/[^a-zA-Z0-9.-]/, "_")
      filename = File.join(tmpdir, "corpus_#{safe_name}.rb")

      File.binwrite(filename, DEFAULT_HEADER + full_script)
      puts "✅ Generated: #{filename}"
      count += 1
    rescue Encoding::UndefinedConversionError
      puts "⚠️  Skipped:   #{target_enc.name} (cannot represent all characters)"
    rescue Encoding::ConverterNotFoundError
      puts "❌ Error:     #{target_enc.name} (converter not found)"
    end

    puts "------------------------------------------------"
    FileUtils.mkdir_p(staging_dir)
    if MINIMIZE
      puts "Total corpus size: #{count} files. Now minimizing"
      system("afl-cmin", "-o", staging_dir, "-i", tmpdir, "--", executable, "@@", exception: true)
    else
      puts "Total corpus size: #{count} files. Skipping minimization (--no-minimize)"
      FileUtils.cp_r(File.join(tmpdir, "."), staging_dir)
    end
    FileUtils.rm_rf(OUTPUT_DIR)
    File.rename(staging_dir, OUTPUT_DIR)
  end
ensure
  FileUtils.rm_rf(staging_dir)
end
