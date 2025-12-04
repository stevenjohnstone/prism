# frozen_string_literal: true

require 'concurrent'
require 'digest'
require 'fileutils'
require 'open3'
require 'tmpdir'

OUTPUT_DIR = 'fuzz/output'
TESTCASES_DIR = 'triage'

def c_array(input_file)
  input = File.read(input_file)
  comment = "/*\n%s\n*/\n" % input.dump
  array = 'static const uint8_t input[] = {%s};' % input.bytes.map { |c| '0x%02x' % c }.join(',')
  "#{comment}#{array}"
end

def c_program(input, harness_code, crash_details)
  program = <<~HEREDOC
    #include <assert.h>
    #include <stdlib.h>
    #include <stdint.h>
    #include <string.h>
    #{harness_code}

    /*
    #{crash_details}
    */

    // Cause ASAN to call abort on an error to make
    // debugging inside gdb easier
    const char* __asan_default_options() {
      return "abort_on_error=1:handle_abort=1";
    }

    #{c_array(input)}

    int main(int argc, const char **argv) {
      (void)argc;
      (void)argv;
      harness(input, sizeof(input));
      return 0;
    }
  HEREDOC
  clang_format(program)
end

def c_program_heisenbug(input, harness_code, crash_details = 'Heisenbug - input ran without error')
  c_program = <<~HEREDOC
    #include <assert.h>
    #include <stdlib.h>
    #include <stdint.h>
    #include <string.h>
    #{harness_code}

    /*
    #{crash_details}
    */

    // Cause ASAN to call abort on an error to make
    // debugging inside gdb easier
    const char* __asan_default_options() {
      return "abort_on_error=1:handle_abort=1";
    }

    #{c_array(input)}

      char *mutation_buffer = malloc(sizeof(input) + 1);
      assert(mutation_buffer);
      memcpy(mutation_buffer, input, sizeof(input));

      // try all possible trailing bytes to see if it triggers
      // the bug
      for (unsigned int i = 0; i < UINT8_MAX; i++) {
          mutation_buffer[sizeof(input)] = (char) i;
          harness((const uint8_t *) mutation_buffer, sizeof(input));
      }

      free(mutation_buffer);
      return 0;
    }
  HEREDOC
  clang_format(c_program)
end

def testcase_output_signature(testcase_output)
  o, = Open3.capture2('./fuzz/tools/signature.sh', stdin_data: testcase_output)
  o.strip
end

def run_testcase(executable, input_file)
  o, s = Open3.capture2e({ 'UBSAN_OPTIONS' => 'print_stacktrace=1' }, "#{executable} #{input_file}")
  [o, s.exitstatus != 0]
end

def clang_format(c_code)
  o, = Open3.capture2('clang-format --style="{ReflowComments: false}"', stdin_data: c_code)
  o
end

def run_afl_tmin(hang, crash, minimized_input, executable)
  flag = hang ? '-H' : '-e'
  cmd = "afl-tmin #{flag} -t 500 -i #{crash} -o #{minimized_input} -- #{executable}"
  Open3.capture2({ 'AFL_TMIN_EXACT' => '1' }, cmd)
end

def minimize(crash, reason, minimized_input, executable)
  puts "minimizing #{crash}"
  pre_min_size = File.size(crash)
  if reason != 'hang'
    tmpdir = Dir.mktmpdir
    tmpfile = File.join(tmpdir, 'halfempty')
    Open3.capture2({ 'UBSAN_OPTIONS' => 'print_stacktrace=1' },
                   "./fuzz/tools/halfempty.sh #{executable} #{crash} #{tmpfile}")
    run_afl_tmin(false, tmpfile, minimized_input, executable)
    FileUtils.rm_r(tmpdir)
  else
    run_afl_tmin(reason == 'hang', crash, minimized_input, executable)
  end
  post_min_size = File.size(minimized_input)
  puts "#{crash} minimized #{pre_min_size} => #{post_min_size}"
end

def process_crash(crash_dir, crash, executable, semaphore)
  puts crash
  harness_code, = Open3.capture2("gdb -q -ex 'set listsize unlimited' -ex 'list harness' -ex 'quit' #{executable} | sed -n -r 's/^[[:digit:]]+\\s*//p' | clang-format")
  reason = File.basename(crash_dir) == 'hangs' ? 'hang' : 'unknown'
  testcase_subdir = Dir.mktmpdir
  testcase_output, crashed = run_testcase(executable, crash)
  heisenbug = !crashed
  if crashed
    testcase_output.match(/SUMMARY: (UndefinedBehavior|Address)Sanitizer: ([[:alpha:]-]*) .*/) do |m|
      reason = m.captures[1]
    end
  end

  target_directory = if heisenbug
                       File.join(TESTCASES_DIR, 'heisenbug', Digest::SHA2.hexdigest(File.read(minimized_input))[0, 16])
                     else
                       File.join(TESTCASES_DIR, reason, testcase_output_signature(testcase_output))
                     end

  semaphore.synchronize do
    if File.directory?(target_directory)
      # don't do duplicate work for this signature
      puts "#{crash} has signature that's been seen before"
      return
    end
    FileUtils.mkdir_p(target_directory)
  end

  minimized_input = File.join(testcase_subdir, 'input.min')
  pre_min_size = File.size(crash)
  if ENV['TRIAGE_MINIMIZE'] == '0' || pre_min_size <= 16
    # don't bother minimizing
    FileUtils.cp(crash, minimized_input)
  else
    minimize(crash, reason, minimized_input, executable)
  end

  c_testcase = if heisenbug
                 c_program_heisenbug(minimized_input, harness_code)
               else
                 c_program(minimized_input, harness_code, testcase_output)
               end

  File.open(File.join(target_directory, 'testcase.c'), File::CREAT | File::TRUNC | File::RDWR) do |f|
    f.write(c_testcase)
  end
  FileUtils.cp(minimized_input, File.join(target_directory, 'input.min'))
  FileUtils.rm_r(testcase_subdir)
  puts "#{crash} complete => #{target_directory}"
end

pool = Concurrent::FixedThreadPool.new(Concurrent.processor_count / 2)
semaphore = Mutex.new
Dir.glob(File.join(OUTPUT_DIR, '**/{crashes*,hangs*}')) do |crash_dir|
  executable = File.read(File.join(crash_dir, '../cmdline')).strip
  Dir.glob(File.join(crash_dir, '/id*')) do |crash|
    pool.post do
      process_crash(crash_dir, crash, executable, semaphore)
    end
  end
end
pool.shutdown
pool.wait_for_termination
