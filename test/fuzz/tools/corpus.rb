#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "tmpdir"

OUTPUT_DIR = File.absolute_path(ARGV[0] || "./tmp/fuzz/corpus")
CORPUS_DIR = "./test/fuzz/corpus/"
# 4-byte options header consumed by harness() in test/fuzz/parse.c:
#   byte 0 (0x00): default opt_flags (encoding_locked=false, dump_json)
#   byte 1 (0x00): default cmd_flags=0, main_script=false
#   byte 2 (0x03): version_idx=3 ("4.1"), scopes_count=0, forwarding=0
#   byte 3 (0x01): start_line=1
DEFAULT_HEADER = "\x00\x00\x03\x01".b

FileUtils.mkdir_p(File.dirname(OUTPUT_DIR))
executable = File.absolute_path("./build/fuzz")

Dir.chdir(CORPUS_DIR)

puts "Generating corpus in directory: #{OUTPUT_DIR}"
puts "------------------------------------------------"

staging_dir = "#{OUTPUT_DIR}.tmp.#{Process.pid}"
FileUtils.rm_rf(staging_dir)

begin
  Dir.mktmpdir do |tmpdir|
    count = 0

    Dir.glob("**{,/*/**}/*.txt") do |filename|
      next if File.directory?(filename)

      target_filename = File.join(tmpdir, "#{filename.gsub(/[^a-zA-Z0-9.-]/, "_")}.rb")

      File.binwrite(target_filename, DEFAULT_HEADER + File.binread(filename))
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
      full_script = magic_comment + encoded_body

      safe_name = target_enc.name.gsub(/[^a-zA-Z0-9.-]/, "_")
      filename = File.join(tmpdir, "corpus_#{safe_name}.rb")

      File.binwrite(filename, DEFAULT_HEADER + full_script.b)
      puts "✅ Generated: #{filename}"
      count += 1
    rescue Encoding::UndefinedConversionError
      puts "⚠️  Skipped:   #{target_enc.name} (cannot represent all characters)"
    rescue Encoding::ConverterNotFoundError
      puts "❌ Error:     #{target_enc.name} (converter not found)"
    end

    puts "------------------------------------------------"
    puts "Total corpus size: #{count} files. Now minimizing"

    FileUtils.mkdir_p(staging_dir)
    system("afl-cmin", "-o", staging_dir, "-i", tmpdir, "--", executable, "@@", exception: true)
    FileUtils.rm_rf(OUTPUT_DIR)
    File.rename(staging_dir, OUTPUT_DIR)
  end
ensure
  FileUtils.rm_rf(staging_dir)
end
