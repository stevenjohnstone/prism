# frozen_string_literal: true

require "concurrent"
require "digest"
require "fileutils"
require "open3"
require "tmpdir"

OUTPUT_DIR = "tmp/fuzz/afl"
TESTCASES_DIR = "tmp/fuzz/triage"
TESTCASES_PROCESSED_DIR = File.join(TESTCASES_DIR, ".processed")
MAX_ALLOCATED_MB = Integer(ENV.fetch("FUZZ_MAX_ALLOCATED", "128"))
HARD_RSS_LIMIT_MB = MAX_ALLOCATED_MB * 16

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
    };
  C
end

def c_array(input_file)
  raw = File.binread(input_file)
  source = raw.bytesize > 4 ? raw.byteslice(4..) : "".b
  bytes = source.bytes.map { |c| format("0x%02x", c) }.join(",")
  bytes = "0x00" if bytes.empty?
  "/*\n#{escape_c_comment(source.dump)}\n*/\nstatic const uint8_t input[] = {#{bytes}};"
end

def c_program(input, harness_code, crash_details)
  program = <<~HEREDOC
    #include <assert.h>
    #include <stdlib.h>
    #include <stdint.h>
    #include <string.h>
    #{harness_code}

    /*
    #{escape_c_comment(crash_details)}
    */

    // Cause ASAN and UBSAN to call abort on an error to make
    // debugging inside gdb easier
    const char* __asan_default_options() {
      return "abort_on_error=1:handle_abort=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}";
    }
    const char* __ubsan_default_options() {
      return "abort_on_error=1:print_stacktrace=1";
    }

    #{c_fuzz_options(input)}

    #{c_array(input)}

    int main(int argc, const char **argv) {
      (void)argc;
      (void)argv;
      harness_parse(input, sizeof(input), &fuzz_options);
      return 0;
    }
  HEREDOC
  clang_format(program)
end

def c_program_heisenbug(input, harness_code, crash_details = "Heisenbug - input ran without error")
  c_program = <<~HEREDOC
    #include <assert.h>
    #include <stdlib.h>
    #include <stdint.h>
    #include <string.h>
    #{harness_code}

    /*
    #{escape_c_comment(crash_details)}
    */

    // Cause ASAN and UBSAN to call abort on an error to make
    // debugging inside gdb easier
    const char* __asan_default_options() {
      return "abort_on_error=1:handle_abort=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}";
    }
    const char* __ubsan_default_options() {
      return "abort_on_error=1:print_stacktrace=1";
    }

    #{c_fuzz_options(input)}

    #{c_array(input)}

    int main(int argc, const char **argv) {
      (void)argc;
      (void)argv;
      char *mutation_buffer = malloc(sizeof(input) + 1);
      assert(mutation_buffer);
      memcpy(mutation_buffer, input, sizeof(input));

      // try all possible trailing bytes to see if it triggers
      // the bug
      for (unsigned int i = 0; i <= UINT8_MAX; i++) {
          mutation_buffer[sizeof(input)] = (char) i;
          harness_parse((const uint8_t *) mutation_buffer, sizeof(input), &fuzz_options);
      }

      free(mutation_buffer);
      return 0;
    }
  HEREDOC
  clang_format(c_program)
end

def testcase_output_signature(testcase_output, siglines = 10)
  o, = Open3.capture2({ "SIGLINES" => siglines.to_s }, "./test/fuzz/triage/signature.sh", stdin_data: testcase_output)
  o.strip
end

def run_testcase(executable, input_file)
  o, s = Open3.capture2e(SANITIZER_ENV, executable, input_file)
  [o, s.exitstatus != 0]
end

def clang_format(c_code)
  o, = Open3.capture2('clang-format --style="{ReflowComments: false}"', stdin_data: c_code)
  o
end

def extract_harness_code(executable)
  o, = Open3.capture2("gdb -q -ex 'set listsize unlimited' -ex 'list harness' -ex 'quit' #{executable} | sed -n -r 's/^[[:digit:]]+\\s*//p' | clang-format")
  o
end

def run_afl_tmin(hang, crash, minimized_input, executable)
  flag = hang ? "-H" : "-e"
  env = {
    "AFL_NO_IJON" => "1",
    "AFL_TMIN_EXACT" => "1",
    "ASAN_OPTIONS" => "abort_on_error=1:handle_abort=0:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}:symbolize=0",
    "UBSAN_OPTIONS" => "abort_on_error=1:symbolize=0",
    "MSAN_OPTIONS" => "exit_code=86:abort_on_error=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}:symbolize=0"
  }
  Open3.capture2e(env, "afl-tmin", flag, "-t", "500", "-i", crash, "-o", minimized_input, "--", executable)
end

def minimize(crash, reason, minimized_input, executable, sig_lines)
  puts "minimizing #{crash}"
  pre_min_size = File.size(crash)
  if reason == "hang"
    run_afl_tmin(true, crash, minimized_input, executable)
  else
    Dir.mktmpdir do |tmpdir|
      tmpfile = File.join(tmpdir, "halfempty")
      Open3.capture2e(
        SANITIZER_ENV.merge({ "SIGLINES" => sig_lines.to_s }),
        "./test/fuzz/triage/halfempty.sh", executable, crash, tmpfile
      )
      tmin_input = File.exist?(tmpfile) ? tmpfile : crash
      # afl-tmin runs the target via the AFL++ forkserver, which exits via
      # _exit(0) without running LSAN's atexit leak check (and LSAN does not
      # raise a crash signal by default). Use fuzz.ldet for afl-tmin on memory
      # leaks so assert(allocated == 0) aborts directly inside
      # LLVMFuzzerTestOneInput.
      tmin_executable = reason == "memory-leak" ? "./build/fuzz.ldet" : executable
      run_afl_tmin(false, tmin_input, minimized_input, tmin_executable)
      FileUtils.cp(tmin_input, minimized_input) unless File.exist?(minimized_input)
    end
  end
  FileUtils.cp(crash, minimized_input) unless File.exist?(minimized_input)
  post_min_size = File.size(minimized_input)
  puts "#{crash} minimized #{pre_min_size} => #{post_min_size}"
end

def process_crash(crash_dir, crash, executable, harness_code, semaphore)
  crash_hash = Digest::SHA2.hexdigest(File.binread(crash))
  sentinel = File.join(TESTCASES_PROCESSED_DIR, crash_hash)

  semaphore.synchronize do
    return if File.exist?(sentinel)

    FileUtils.touch(sentinel)
  end

  reason = File.basename(crash_dir) == "hangs" ? "hang" : "unknown"
  if executable.end_with?("ldet", "native")
    # fuzz.ldet and fuzz.native are built without sanitizers (and SAND workers
    # record fuzz.native in cmdline while running fuzz.sand under -w), so try
    # ./build/fuzz (ASAN/UBSAN) first for sanitizer crashes and assertions so
    # they deduplicate with main; next try ./build/fuzz.lsan for memory leaks;
    # finally fall back to executable for cumulative allocation limit assertions
    # in PRISM_XALLOCATOR.
    testcase_output, crashed = run_testcase("./build/fuzz", crash)
    if crashed
      executable = "./build/fuzz"
    else
      testcase_output, crashed = run_testcase("./build/fuzz.lsan", crash)
      if crashed
        executable = "./build/fuzz.lsan"
      else
        testcase_output, crashed = run_testcase(executable, crash)
      end
    end
  elsif executable.end_with?("msan")
    # Try the ASAN/UBSAN binary first: if it crashes (e.g. on an illegal write,
    # UBSAN check, assertion failure, or SEGV), prefer it for deterministic
    # classification, minimization, and deduplication against main/grammar;
    # otherwise fall back to MSAN for read issues (uninitialized or out-of-bounds
    # reads, since ./build/fuzz has ASAN read instrumentation disabled).
    testcase_output, crashed = run_testcase("./build/fuzz", crash)
    if crashed
      executable = "./build/fuzz"
    else
      testcase_output, crashed = run_testcase(executable, crash)
    end
  else
    testcase_output, crashed = run_testcase(executable, crash)
  end
  heisenbug = !crashed
  if heisenbug && File.basename(crash).include?("sig:09")
    puts "Skipping #{crash} (external SIGKILL / OOM)"
    return
  end
  if heisenbug && reason == "hang"
    puts "Skipping #{crash} (transient timeout)"
    return
  end
  if crashed
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

  target_directory = if heisenbug
                       File.join(TESTCASES_DIR, "heisenbug", crash_hash[0, 16])
                     else
                       File.join(TESTCASES_DIR, reason, testcase_output_signature(testcase_output, sig_lines))
                     end

  semaphore.synchronize do
    puts "#{crash} is new"
    if File.directory?(target_directory)
      # don't do duplicate work for this signature
      puts "#{crash} is a duplicate of #{target_directory}"
      return
    end
    FileUtils.mkdir_p(target_directory)
  end

  Dir.mktmpdir do |testcase_subdir|
    minimized_input = File.join(testcase_subdir, "input.min")

    if ENV["TRIAGE_MINIMIZE"] == "0" || heisenbug
      # don't bother minimizing
      FileUtils.cp(crash, minimized_input)
    else
      minimize(crash, reason, minimized_input, executable, sig_lines)
    end

    c_testcase = if heisenbug
                   c_program_heisenbug(minimized_input, harness_code, "Heisenbug - #{crash} ran without error")
                 else
                   c_program(minimized_input, harness_code, "Crash: #{crash}\n#{testcase_output}")
                 end

    File.write(File.join(target_directory, "testcase.c"), c_testcase)
    FileUtils.cp(minimized_input, File.join(target_directory, "input.min"))
    FileUtils.cp(crash, File.join(target_directory, File.basename(crash)))
  end
  puts "#{crash} complete => #{target_directory}"
end

harness_code = extract_harness_code("./build/fuzz")
pool = Concurrent::FixedThreadPool.new([Concurrent.processor_count / 2, 1].max)
semaphore = Mutex.new
Dir.glob(File.join(OUTPUT_DIR, "**/{crashes*,hangs*}")) do |crash_dir|
  cmdline_file = File.join(crash_dir, "../cmdline")
  next unless File.exist?(cmdline_file)

  executable = File.read(cmdline_file).strip
  Dir.glob(File.join(crash_dir, "/id*")) do |crash|
    pool.post do
      process_crash(crash_dir, crash, executable, harness_code, semaphore)
    rescue StandardError => e
      warn "Error processing #{crash}: #{e.class}: #{e.message}\n#{e.backtrace.join("\n")}"
    end
  end
end
pool.shutdown
pool.wait_for_termination
