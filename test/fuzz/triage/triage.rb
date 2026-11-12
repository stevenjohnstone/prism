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

COMMAND_LINE_FLAGS = [
  [0x01, "PM_OPTIONS_COMMAND_LINE_A"],
  [0x02, "PM_OPTIONS_COMMAND_LINE_E"],
  [0x04, "PM_OPTIONS_COMMAND_LINE_L"],
  [0x08, "PM_OPTIONS_COMMAND_LINE_N"],
  [0x10, "PM_OPTIONS_COMMAND_LINE_P"],
  [0x20, "PM_OPTIONS_COMMAND_LINE_X"]
].freeze

FORWARDING_FLAGS = [
  [0x01, "PM_OPTIONS_SCOPE_FORWARDING_POSITIONALS"],
  [0x02, "PM_OPTIONS_SCOPE_FORWARDING_KEYWORDS"],
  [0x04, "PM_OPTIONS_SCOPE_FORWARDING_BLOCK"],
  [0x08, "PM_OPTIONS_SCOPE_FORWARDING_ALL"]
].freeze

def escape_c_comment(text)
  text.gsub("*/", "* /")
end

def format_bitmask(value, flags, zero_default = "0")
  selected = flags.filter_map { |bit, name| name if (value & bit) != 0 }
  selected.empty? ? zero_default : selected.join(" | ")
end

def c_fuzz_options(input_file)
  raw = File.binread(input_file)
  b0, b1, b2, b3 = raw.bytes[0, 4].map { |b| b || 0 }
  opt_flags = b0
  cmd_flags = format_bitmask(b1 & 0x3f, COMMAND_LINE_FLAGS, "0")
  main_script = (b1 & 0x40) != 0
  has_limit_opts = (b1 & 0x80) != 0
  version = VERSIONS[b2 & 0x03]
  scopes_count = (b2 >> 2) & 0x03
  forwarding = format_bitmask((b2 >> 4) & 0x0f, FORWARDING_FLAGS, "PM_OPTIONS_SCOPE_FORWARDING_NONE")
  start_line = [b3].pack("C").unpack1("c")

  <<~C
    static const fuzz_options_t fuzz_options = {
      .start_line = #{start_line},
      .cmd_flags = #{cmd_flags},
      .main_script = #{main_script},
      .freeze = #{(opt_flags & 1) != 0},
      .partial_script = #{(opt_flags & 2) != 0},
      .attach_comments = #{(opt_flags & 4) != 0},
      .encoding_locked = #{(opt_flags & 8) != 0},
      .version = "#{version}",
      .has_frozen_string_literal = #{(opt_flags & 16) != 0},
      .frozen_string_literal = #{(opt_flags & 32) != 0},
      .scopes_count = #{scopes_count},
      .forwarding = #{forwarding},
      .stream_mode = #{(opt_flags & 0x40) != 0},
      .has_encoding_opts = #{(opt_flags & 0x80) != 0},
      .has_limit_opts = #{has_limit_opts},
      .aux_byte = #{format("0x%02x", b3)},
    };
  C
end

def c_array(input_file)
  raw = File.binread(input_file)
  source = raw.bytesize > 4 ? raw.byteslice(4..) : "".b
  loupe_url = "#{PRISM_LOUPE_BASE_URL}?code=#{CGI.escape(Base64.strict_encode64(source))}"
  bytes = source.bytes.map { |c| format("0x%02x", c) }.join(",")
  bytes = "0x00" if bytes.empty?
  <<~C.chomp
    /*
    #{escape_c_comment(source.dump)}
    Prism Loupe: #{escape_c_comment(loupe_url)}
    */
    static const uint8_t input[] = {#{bytes}};
    static const size_t input_size = #{source.bytesize};
  C
end

def c_program(input, harness_code, crash_details)
  program = <<~HEREDOC
    #{harness_code}
    #include <stdint.h>

    /*
    #{escape_c_comment(crash_details)}
    */

    // Cause ASAN and UBSAN to call abort on an error to make
    // debugging inside gdb easier
    const char *__asan_default_options(void) {
      return "abort_on_error=1:handle_abort=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}";
    }
    const char *__ubsan_default_options(void) {
      return "abort_on_error=1:print_stacktrace=1";
    }

    #{c_fuzz_options(input)}

    #{c_array(input)}

    int main(int argc, const char **argv) {
      (void)argc;
      (void)argv;
      harness_parse(input, input_size, &fuzz_options);
      return 0;
    }
  HEREDOC
  clang_format(program)
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
  post_min_size = File.size(minimized_input)
  puts "#{crash} minimized #{pre_min_size} => #{post_min_size}"
end

def process_crash(crash_dir, crash, executable, harness_code, semaphore, in_progress, pending_sentinels)
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
        elsif testcase_output.include?("Assertion `")
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
      end

      details = if unreproducible
                  "Unreproducible crash: #{crash}"
                else
                  "Crash: #{crash}\n#{testcase_output}"
                end
      c_testcase = c_program(minimized_input, harness_code, details)

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

harness_code = File.read("test/fuzz/harness/parse.c")
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
      process_crash(crash_dir, crash, executable, harness_code, semaphore, in_progress, pending_sentinels)
    rescue StandardError => e
      warn "Error processing #{crash}: #{e.class}: #{e.message}\n#{e.backtrace.join("\n")}"
    end
  end
end
pool.shutdown
pool.wait_for_termination
