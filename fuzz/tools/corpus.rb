#!/usr/bin/env ruby
# frozen_string_literal: true

require 'fileutils'
require 'tmpdir'

OUTPUT_DIR = File.absolute_path('./fuzz/output/corpus')
CORPUS_DIR = './fuzz/corpus/'
FileUtils.mkdir_p(OUTPUT_DIR)
executable = File.absolute_path('./build/fuzz')
tmpdir = File.absolute_path('./fuzz/output/corpus.tmp')
FileUtils.mkdir_p(tmpdir)

Dir.chdir(CORPUS_DIR)

puts "Generating corpus in directory: ./#{OUTPUT_DIR}/"
puts '------------------------------------------------'

count = 0

Dir.glob('**{,/*/**}/*.txt') do |filename|
  next if File.directory?(filename)

  begin
    target_filename = File.join(tmpdir, "#{filename.gsub(/[^a-zA-Z0-9.-]/, '_')}.rb")

    FileUtils.cp(filename, target_filename)
    puts "✅ Generated: #{target_filename}"
    count += 1
  end
end

BASE_CONTENT = <<~RUBY
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

  begin
    encoded_body = BASE_CONTENT.encode(target_enc, 'binary', invalid: :replace, undef: :replace, replace: '')

    magic_comment = "# encoding: #{target_enc.name}\n".encode(target_enc)

    full_script = magic_comment + encoded_body

    safe_name = target_enc.name.gsub(/[^a-zA-Z0-9.-]/, '_')
    filename = File.join(tmpdir, "corpus_#{safe_name}.rb")

    File.binwrite(filename, full_script)
    puts "✅ Generated: #{filename}"
    count += 1
  rescue Encoding::UndefinedConversionError
    puts "⚠️  Skipped:   #{target_enc.name} (cannot represent all characters)"
  rescue Encoding::ConverterNotFoundError
    puts "❌ Error:     #{target_enc.name} (converter not found)"
  end
end

puts '------------------------------------------------'
puts "Total corpus size: #{count} files. Now minimizing"

`afl-cmin -o #{OUTPUT_DIR} -i #{tmpdir} -- #{executable} @@`
FileUtils.rm_r(tmpdir)
