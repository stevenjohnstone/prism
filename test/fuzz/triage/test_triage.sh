#!/usr/bin/env bash
# Verifies the fuzz crash triage and minimization pipeline:
# 1. signature.sh normalization (UBSAN operands, LSan counts, ASAN sizes,
#    binary prefixes) and SIGPIPE safety under set -o pipefail.
# 2. halfempty.sh + halfempty_compare.sh minimization, strict 4-byte options
#    header preservation, crash-signature drift rejection, empty-stderr SIGSEGV
#    safety, non-crashing input rejection, and 0-byte Ruby body handling.
# 3. triage.rb standalone <prism.h> C reproducer synthesis (no harness noise,
#    public headers only via -Iinclude, active options & targeted checks only)
#    compiled under strict C99 (-Wall -Wextra -Wconversion -Wstrict-prototypes -Werror)
#    with ASAN+UBSAN.
# 4. Concurrent triage.rb deduplication, 4-byte options header minimization,
#    in-flight minimization coalescing, transient hang / sig:09 filtering,
#    atomic staging + .processed sentinels, and per-bucket / index JSON metadata.
# 5. afl-showmap per-bucket edge coverage, corpus edge document frequencies,
#    AFL_LLVM_DOCUMENT_IDS function resolution, corpus cache hits, and recount.

set -euo pipefail

WORKDIR="$(mktemp -d /tmp/test-fuzz-triage.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "[1/5] Checking signature.sh normalization and SIGPIPE safety..."
s1=$(printf "src/prism.c:10:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int32_t'\n#0 0x1234 in foo\n" | SIGLINES=3 ./test/fuzz/triage/signature.sh)
s2=$(printf "src/prism.c:10:5: runtime error: signed integer overflow: 2147483600 + 99 cannot be represented in type 'int32_t'\n#0 0x9999 in foo\n" | SIGLINES=3 ./test/fuzz/triage/signature.sh)
s3=$(printf "src/prism.c:20:5: runtime error: signed integer overflow: 2147483600 + 99 cannot be represented in type 'int32_t'\n#0 0x9999 in foo\n" | SIGLINES=3 ./test/fuzz/triage/signature.sh)
[ "$s1" = "$s2" ] || fail "UBSAN signatures differed for distinct integer operands at same location ($s1 != $s2)"
[ "$s1" != "$s3" ] || fail "UBSAN signatures collided across distinct source lines ($s1 == $s3)"

l1=$(printf "Direct leak of 48 byte(s) in 3 object(s) allocated from:\n#0 0x11 in bar\n" | SIGLINES=5 ./test/fuzz/triage/signature.sh)
l2=$(printf "Direct leak of 16 byte(s) in 1 object(s) allocated from:\n#0 0x22 in bar\n" | SIGLINES=5 ./test/fuzz/triage/signature.sh)
[ "$l1" = "$l2" ] || fail "LeakSanitizer signatures differed across byte/object counts ($l1 != $l2)"

a1=$(printf "READ of size 4 at 0x602000000014 thread T0\n" | SIGLINES=5 ./test/fuzz/triage/signature.sh)
a2=$(printf "READ of size 19 at 0x602000009998 thread T2\n" | SIGLINES=5 ./test/fuzz/triage/signature.sh)
[ "$a1" = "$a2" ] || fail "ASAN READ size/address/thread normalization failed ($a1 != $a2)"

b1=$(printf "fuzz: src/prism.c:12: bar: Assertion \`0' failed.\n" | SIGLINES=5 ./test/fuzz/triage/signature.sh)
b2=$(printf "./build/fuzz.ijon: src/prism.c:12: bar: Assertion \`0' failed.\n" | SIGLINES=5 ./test/fuzz/triage/signature.sh)
b3=$(printf "/prism/build/fuzz.native: src/prism.c:12: bar: Assertion \`0' failed.\n" | SIGLINES=5 ./test/fuzz/triage/signature.sh)
[ "$b1" = "$b2" ] && [ "$b1" = "$b3" ] || fail "binary name normalization failed ($b1, $b2, $b3)"

i1=$(printf "INVARIANT[diagnostic]: list=error type=escape_invalid_meta kind=end_oob [detail: level=0 start=1 length=3 parsed_size=3]\nAddressSanitizer:DEADLYSIGNAL\n#0 0x1111 in abort\n" | SIGLINES=15 ./test/fuzz/triage/signature.sh)
i2=$(printf "Reading 487 bytes from /tmp/c\nINVARIANT[diagnostic]: list=error type=escape_invalid_meta kind=end_oob [detail: level=0 start=481 length=3 parsed_size=483]\n" | SIGLINES=15 ./test/fuzz/triage/signature.sh)
i3=$(printf "INVARIANT[diagnostic]: list=error type=regexp_term kind=end_oob [detail: level=0 start=1 length=3 parsed_size=3]\nAddressSanitizer:DEADLYSIGNAL\n#0 0x1111 in abort\n" | SIGLINES=15 ./test/fuzz/triage/signature.sh)
i4=$(printf "INVARIANT[diagnostic]: list=error type=escape_invalid_meta kind=length_underflow [detail: level=0 start=1 length=4294967295 parsed_size=3]\nAddressSanitizer:DEADLYSIGNAL\n#0 0x1111 in abort\n" | SIGLINES=15 ./test/fuzz/triage/signature.sh)
[ "$i1" = "$i2" ] || fail "INVARIANT[diagnostic] signature varied across offsets or sanitizer frames ($i1 != $i2)"
[ "$i1" != "$i3" ] || fail "INVARIANT[diagnostic] collided across distinct diagnostic types ($i1 == $i3)"
[ "$i1" != "$i4" ] || fail "INVARIANT[diagnostic] collided across distinct violation kinds ($i1 == $i4)"

n1=$(printf "INVARIANT[node_location]: type=PM_REGULAR_EXPRESSION_NODE kind=end_oob [detail: parent=PM_LOCAL_VARIABLE_WRITE_NODE start=8 length=4 parsed_size=11]\n#0 0x1 in check_node_location\n#1 0x2 in check_node_location\n#2 0x3 in check_node_location\n" | SIGLINES=15 ./test/fuzz/triage/signature.sh)
n2=$(printf "INVARIANT[node_location]: type=PM_REGULAR_EXPRESSION_NODE kind=end_oob [detail: parent=PM_STATEMENTS_NODE start=0 length=4 parsed_size=3]\n#0 0x9 in check_node_location\n" | SIGLINES=15 ./test/fuzz/triage/signature.sh)
n3=$(printf "INVARIANT[node_location]: type=PM_CALL_NODE kind=end_oob [detail: parent=PM_STATEMENTS_NODE start=0 length=4 parsed_size=3]\n#0 0x9 in check_node_location\n" | SIGLINES=15 ./test/fuzz/triage/signature.sh)
[ "$n1" = "$n2" ] || fail "INVARIANT[node_location] varied across parent wrapper or AST recursion depth ($n1 != $n2)"
[ "$n1" != "$n3" ] || fail "INVARIANT[node_location] collided across distinct node types ($n1 == $n3)"
[ "$i1" != "$n1" ] || fail "INVARIANT[diagnostic] collided with INVARIANT[node_location] ($i1 == $n1)"

ruby -e 'File.write(ARGV.fetch(0), "stack frame 0xdeadbeef in fn\n" * 5000)' "$WORKDIR/big_trace.txt"
SIGLINES=3 ./test/fuzz/triage/signature.sh < "$WORKDIR/big_trace.txt" >/dev/null
ruby -e 'File.write(ARGV.fetch(0), "INVARIANT[stream]: kind=parsed_size_oob [detail: parsed_size=9 size=4]\n" + ("stack frame 0xdeadbeef in fn\n" * 5000))' "$WORKDIR/big_inv_trace.txt"
SIGLINES=15 ./test/fuzz/triage/signature.sh < "$WORKDIR/big_inv_trace.txt" >/dev/null
echo "  signature.sh normalization and 5,000-line trace check passed"

echo "[2/5] Checking halfempty.sh minimization, header preservation, and drift protection..."
cat << 'EOF' > "$WORKDIR/synth_target.c"
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noreturn, noinline))
static void fail_invariant_at_shared_site(const char *diag_type, size_t start, size_t parsed_size) {
    fprintf(
        stderr,
        "INVARIANT[diagnostic]: list=error type=%s kind=end_oob [detail: level=0 start=%zu length=4 parsed_size=%zu]\n"
        "    #0 0x1000 in fail_invariant_at_shared_site /prism/test/fuzz/harness/parse.c:90:5\n"
        "    #1 0x1010 in harness_parse /prism/test/fuzz/harness/parse.c:550:13\n",
        diag_type,
        start,
        parsed_size
    );
    fflush(stderr);
    abort();
}

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long n = ftell(f);
    if (n < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }
    uint8_t *buf = malloc((size_t)(n > 0 ? n : 1));
    if (!buf) { fclose(f); return 0; }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return 0;
    }
    fclose(f);

    if (n < 4) {
        free(buf);
        return 0;
    }

    const uint8_t *body = buf + 4;
    size_t body_len = (size_t)(n - 4);

    if ((buf[0] & 0x08) && body_len == 0) {
        fprintf(stderr, "fuzz: src/prism.c:11: empty_body: Assertion `0' failed.\n");
        free(buf);
        abort();
    }
    if ((buf[0] & 0x02) && body_len >= 4 && memmem(body, body_len, "BOOM", 4) != NULL) {
        fprintf(stderr, "fuzz: src/prism.c:42: bug_a: Assertion `0' failed.\n");
        free(buf);
        abort();
    }
    if (body_len >= 9 && memmem(body, body_len, "ALT_CRASH", 9) != NULL) {
        fprintf(stderr, "fuzz: src/prism.c:84: bug_b: Assertion `0' failed.\n");
        free(buf);
        abort();
    }
    if ((buf[0] & 0x04) && body_len >= 4 && memmem(body, body_len, "SEGV", 4) != NULL) {
        free(buf);
        raise(SIGSEGV);
    }
    if (buf[0] & 0x10) {
        const uint8_t *target = body_len >= 10 ? (const uint8_t *)memmem(body, body_len, "INV_TARGET", 10) : NULL;
        if (target != NULL) {
            size_t off = (size_t)(target - body);
            free(buf);
            fail_invariant_at_shared_site("heredoc_term", off, body_len);
        }
        const uint8_t *decoy = body_len >= 9 ? (const uint8_t *)memmem(body, body_len, "INV_DECOY", 9) : NULL;
        if (decoy != NULL) {
            size_t off = (size_t)(decoy - body);
            free(buf);
            fail_invariant_at_shared_site("escape_invalid_meta", off, body_len);
        }
    }

    free(buf);
    return 0;
}
EOF
clang -O2 -std=c99 "$WORKDIR/synth_target.c" -o "$WORKDIR/synth_target"

# 2a. Non-crashing input must be rejected cleanly.
printf '\x00\x00\x03\x01hello world\n' > "$WORKDIR/noncrash.in"
if ./test/fuzz/triage/halfempty.sh "$WORKDIR/synth_target" "$WORKDIR/noncrash.in" "$WORKDIR/noncrash.min" >/dev/null 2>&1; then
    fail "halfempty.sh succeeded on a non-crashing input"
fi

# 2b. Noisy input containing both ALT_CRASH and BOOM with non-default header \x2a\x11\x22\x33:
#     must preserve exact 4-byte header, reject drifting to ALT_CRASH, and shrink around BOOM.
ruby -e '
  hdr = "\x2a\x11\x22\x33".b
  body = ("x = 1 + 2\n".b * 15) + "ALT_CRASH\n".b + ("m = 0\n".b * 15) + "BOOM\n".b + ("y = 3 + 4\n".b * 15)
  File.binwrite(ARGV.fetch(0), hdr + body)
' "$WORKDIR/boom.in"
./test/fuzz/triage/halfempty.sh "$WORKDIR/synth_target" "$WORKDIR/boom.in" "$WORKDIR/boom.min" >/dev/null 2>&1
ruby -e '
  orig = File.binread(ARGV.fetch(0))
  mini = File.binread(ARGV.fetch(1))
  raise "4-byte header mutated: #{mini.byteslice(0, 4).dump}" unless mini.byteslice(0, 4) == "\x2a\x11\x22\x33".b
  body = mini.byteslice(4..)
  raise "expected crash token BOOM missing: #{mini.dump}" unless body.include?("BOOM".b)
  raise "secondary token ALT_CRASH not minimized away: #{mini.dump}" if body.include?("ALT_CRASH".b)
  raise "expected <= 12 bytes from #{orig.bytesize} bytes, got #{mini.bytesize}: #{mini.dump}" unless mini.bytesize <= 12
' "$WORKDIR/boom.in" "$WORKDIR/boom.min"
orig_sig=$("$WORKDIR/synth_target" "$WORKDIR/boom.in" 2>&1 | ./test/fuzz/triage/signature.sh || true)
min_sig=$("$WORKDIR/synth_target" "$WORKDIR/boom.min" 2>&1 | ./test/fuzz/triage/signature.sh || true)
[ "$orig_sig" = "$min_sig" ] || fail "minimized crash signature drifted ($orig_sig != $min_sig)"

# 2c. Silent SIGSEGV (empty stderr) must not be minimized into a non-crashing 0-byte body.
ruby -e '
  hdr = "\x04\xaa\xbb\xcc".b
  body = ("a = 1\n".b * 12) + "SEGV".b + ("\nb = 2\n".b * 12)
  File.binwrite(ARGV.fetch(0), hdr + body)
' "$WORKDIR/segv.in"
./test/fuzz/triage/halfempty.sh "$WORKDIR/synth_target" "$WORKDIR/segv.in" "$WORKDIR/segv.min" >/dev/null 2>&1
ruby -e '
  mini = File.binread(ARGV.fetch(0))
  raise "4-byte header mutated on SIGSEGV: #{mini.byteslice(0, 4).dump}" unless mini.byteslice(0, 4) == "\x04\xaa\xbb\xcc".b
  raise "empty-stderr SIGSEGV wiped out crash token: #{mini.dump}" unless mini.byteslice(4..).include?("SEGV".b)
  raise "expected <= 12 bytes on SIGSEGV, got #{mini.bytesize}: #{mini.dump}" unless mini.bytesize <= 12
' "$WORKDIR/segv.min"
if sh -c '"$1" "$2"' _ "$WORKDIR/synth_target" "$WORKDIR/segv.min" >/dev/null 2>&1; then
    fail "segv.min no longer crashes"
fi

# 2d. Exact 4-byte crash (0-byte Ruby body) must preserve the 4-byte input cleanly.
printf '\x08\xde\xad\x01' > "$WORKDIR/empty_body.in"
./test/fuzz/triage/halfempty.sh "$WORKDIR/synth_target" "$WORKDIR/empty_body.in" "$WORKDIR/empty_body.min" >/dev/null 2>&1
cmp -s "$WORKDIR/empty_body.in" "$WORKDIR/empty_body.min" || fail "4-byte input was altered by halfempty.sh"

# 2e. Two INVARIANT[...] failures sharing the exact same C call stack and shifting offsets:
#     must preserve INV_TARGET (heredoc_term), delete INV_DECOY (escape_invalid_meta), and shrink prefix/suffix.
ruby -e '
  hdr = "\x10\x44\x55\x66".b
  body = ("p = 1\n".b * 15) + "INV_DECOY\n".b + ("q = 2\n".b * 15) + "INV_TARGET\n".b + ("r = 3\n".b * 15)
  File.binwrite(ARGV.fetch(0), hdr + body)
' "$WORKDIR/inv.in"
SIGLINES=15 ./test/fuzz/triage/halfempty.sh "$WORKDIR/synth_target" "$WORKDIR/inv.in" "$WORKDIR/inv.min" >/dev/null 2>&1
ruby -e '
  orig = File.binread(ARGV.fetch(0))
  mini = File.binread(ARGV.fetch(1))
  raise "4-byte header mutated on INVARIANT: #{mini.byteslice(0, 4).dump}" unless mini.byteslice(0, 4) == "\x10\x44\x55\x66".b
  body = mini.byteslice(4..)
  raise "target invariant token INV_TARGET missing: #{mini.dump}" unless body.include?("INV_TARGET".b)
  raise "decoy invariant token INV_DECOY not minimized away: #{mini.dump}" if body.include?("INV_DECOY".b)
  raise "expected <= 18 bytes from #{orig.bytesize} bytes, got #{mini.bytesize}: #{mini.dump}" unless mini.bytesize <= 18
' "$WORKDIR/inv.in" "$WORKDIR/inv.min"
echo "  halfempty.sh header preservation, drift protection, INVARIANT symmetry breaking, SIGSEGV, and 4-byte checks passed"

echo "[3/5] Checking triage.rb minimal <prism.h> C reproducer synthesis and strict C99 build..."
ruby - "$WORKDIR" << 'EOF'
workdir = ARGV.fetch(0)
code = File.read("test/fuzz/triage/triage.rb")
defs = code.split(/^pool = /).first
eval(defs)

nonempty_in = File.join(workdir, "repro_nonempty.bin")
empty_in = File.join(workdir, "repro_empty.bin")
enc_oob_in = File.join(workdir, "repro_enc_oob.bin")
min_oob_in = File.join(workdir, "repro_min_oob.bin")
stream_slow_in = File.join(workdir, "repro_stream_slow.bin")
node_loc_in = File.join(workdir, "repro_node_loc.bin")

File.binwrite(nonempty_in, "\x2a\x05\x1b\xff1 + 2\n".b)
File.binwrite(empty_in, "\x00\x00\x03\x01".b)
File.binwrite(enc_oob_in, "\xa3\xc5\x28\x31/\\M".b)
File.binwrite(min_oob_in, "\x80\x00\x03\x01/\\M".b)
File.binwrite(stream_slow_in, "\xc8\x80\x00\xa91 + 2\n".b)
File.binwrite(node_loc_in, "\x00\x00\x03\x011 + 2\n".b)

tc_nonempty_c = c_program(nonempty_in, "test */ nonempty")
tc_empty_c = c_program(empty_in, "test empty")
tc_enc_oob_c = c_program(enc_oob_in, "test enc oob")
tc_min_oob_c = c_program(
  min_oob_in,
  "test min oob",
  crash_output: "INVARIANT[diagnostic]: list=error type=escape_invalid_meta kind=end_oob [detail: level=0 start=1 length=3 parsed_size=3]\n"
)
tc_stream_slow_c = c_program(
  stream_slow_in,
  "test stream slow",
  crash_output: "    #0 0x1234 in pm_prettyprint /prism/src/prettyprint.c:10:5\n",
  executable: "./build/fuzz.msan"
)
tc_node_loc_c = c_program(
  node_loc_in,
  "test node loc",
  crash_output: "INVARIANT[node_location]: type=PM_CALL_NODE kind=end_oob\n"
)

expected_nonempty_url = "https://stevenjohnstone.github.io/prism-loupe/?code=MSArIDIK&ruby_ver=4.1&line=-1&cmd=al&partial=1&enc_lock=1&scopes=a%2Cfoo%2C~MSArIA%3Bp%3Ab%2Cit"
raise "unexpected Loupe URL in tc_nonempty.c:\n#{tc_nonempty_c}" unless tc_nonempty_c.include?("Prism Loupe: #{expected_nonempty_url}")

expected_empty_url = "https://stevenjohnstone.github.io/prism-loupe/?code=&ruby_ver=4.1"
raise "unexpected Loupe URL in tc_empty.c:\n#{tc_empty_c}" unless tc_empty_c.include?("Prism Loupe: #{expected_empty_url}")

expected_enc_oob_url = "https://stevenjohnstone.github.io/prism-loupe/?code=L1xN&enc=ASCII-8BIT&ruby_ver=3.3&line=0&cmd=al&main=1&partial=1&freeze=1&filepath=fuzz.rb&scopes=%3A%3Bk%3Ab%2Cit"
raise "unexpected Loupe URL in tc_enc_oob.c:\n#{tc_enc_oob_c}" unless tc_enc_oob_c.include?("Prism Loupe: #{expected_enc_oob_url}")

tc_ubsan_c = c_program(
  empty_in,
  "test ubsan",
  crash_output: "src/line_offset_list.c:85:58: runtime error: signed integer overflow\nSUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/line_offset_list.c:85:58\n",
  reason: "undefined-behavior"
)
expected_ubsan_url = "https://stevenjohnstone.github.io/prism-loupe/?code=&san=1&ruby_ver=4.1"
raise "expected san=1 in UBSAN Loupe URL:\n#{tc_ubsan_c}" unless tc_ubsan_c.include?("Prism Loupe: #{expected_ubsan_url}")

[tc_nonempty_c, tc_empty_c, tc_min_oob_c, tc_stream_slow_c, tc_node_loc_c].each do |src|
  %w[harness( harness_parse fuzz_options_t PRISM_FUZZ_IJON prism/internal/ #ifdef\ SLOW].each do |forbidden|
    raise "forbidden harness noise #{forbidden.inspect} found in:\n#{src}" if src.include?(forbidden)
  end
end

raise "expected NULL options in tc_empty.c:\n#{tc_empty_c}" unless tc_empty_c.include?("pm_parser_new(arena, source_buf, input_size, NULL)")
raise "expected <= 35 lines in tc_empty.c, got #{tc_empty_c.lines.size}:\n#{tc_empty_c}" unless tc_empty_c.lines.size <= 35
raise "expected error diagnostic loop only in tc_min_oob.c:\n#{tc_min_oob_c}" unless tc_min_oob_c.include?("pm_parser_errors_first(parser)") && !tc_min_oob_c.include?("pm_parser_warnings_first")
raise "expected INT32_MIN + stack_budget + shebang_cb + pm_prettyprint in tc_stream_slow.c:\n#{tc_stream_slow_c}" unless tc_stream_slow_c.include?("INT32_MIN") && tc_stream_slow_c.include?("pm_options_stack_budget_set(options, 512)") && tc_stream_slow_c.include?("shebang_cb") && tc_stream_slow_c.include?("pm_prettyprint") && !tc_stream_slow_c.include?("pm_dump_json")

File.write(File.join(workdir, "tc_nonempty.c"), tc_nonempty_c)
File.write(File.join(workdir, "tc_empty.c"), tc_empty_c)
File.write(File.join(workdir, "tc_min_oob.c"), tc_min_oob_c)
File.write(File.join(workdir, "tc_stream_slow.c"), tc_stream_slow_c)
File.write(File.join(workdir, "tc_node_loc.c"), tc_node_loc_c)

inv_build = build_script(
  min_oob_in,
  crash_output: "INVARIANT[diagnostic]: list=error type=escape_invalid_meta kind=end_oob\n",
  reason: "ABRT",
  executable: "./build/fuzz"
)
raise "INVARIANT build.sh should omit unnecessary -D flags:\n#{inv_build}" if inv_build.include?("-DPM_") || inv_build.include?("-DPRISM_")
raise "INVARIANT build.sh missing ASAN+UBSAN flags:\n#{inv_build}" unless inv_build.include?("-fsanitize=address,undefined -fno-sanitize-recover=all")

msan_build = build_script(
  stream_slow_in,
  crash_output: "    #0 0x1234 in pm_prettyprint\n",
  reason: "use-of-uninitialized-value",
  executable: "./build/fuzz.msan"
)
raise "MSAN build.sh missing MSAN/arena flags:\n#{msan_build}" unless msan_build.include?("-DPM_ARENA_INITIAL_SIZE=0") && msan_build.include?("-fsanitize=memory -fsanitize-memory-track-origins -fno-sanitize-recover=all")

ub_build = build_script(
  nonempty_in,
  crash_output: "src/line_offset_list.c:85: runtime error: signed integer overflow\n",
  reason: "undefined-behavior",
  executable: "./build/fuzz"
)
raise "UB build.sh unexpected flags:\n#{ub_build}" unless ub_build.include?("-fsanitize=undefined -fno-sanitize-recover=undefined") && !ub_build.include?("-DPM_") && !ub_build.include?("-DPRISM_")

bignum_in = File.join(workdir, "repro_bignum.bin")
File.binwrite(bignum_in, "\x00\x00\x03\x01".b + ("9" * 75).b)
bignum_build = build_script(
  bignum_in,
  crash_output: "fuzz_free_sized\n",
  reason: "ABRT",
  executable: "./build/fuzz.native"
)
raise "bignum/native build.sh unexpected flags:\n#{bignum_build}" unless bignum_build.include?("-DPM_INTEGER_DIVIDE_THRESHOLD=8") && bignum_build.include?("-DPRISM_DEPTH_MAXIMUM=128") && bignum_build.include?("-DPRISM_BUILD_DEBUG") && !bignum_build.include?("-DPM_ARENA_INITIAL_SIZE=0")

raise "expected nil when stream bit unset" unless normalize_ijon_crash_bytes("\x2a\x11\x22\x33abc".b).nil?
raise "expected stream bit cleared" unless normalize_ijon_crash_bytes("\x6a\x11\x22\x33abc".b) == "\x2a\x11\x22\x33abc".b

parsed_inv = parse_crash_output(
  "Reading 11 bytes from x\n" \
  "INVARIANT[node_location]: type=PM_WHILE_NODE kind=length_underflow [detail: parent=PM_STATEMENTS_NODE start=6 length=4294967294 parsed_size=12]\n" \
  "    #0 0xffff9c3374d8 in abort stdlib/abort.c:79:7\n" \
  "    #1 0xaaaa in fuzz_invariant_fail /prism/test/fuzz/harness/parse.c:94:5\n" \
  "    #2 0xaaab in pm_visit_node /prism/prism/templates/src/node.c.erb:409:32\n" \
  "    #3 0xaaac in parse_while /prism/src/prism.c:20046:5\n"
)
raise "unexpected invariant parse: #{parsed_inv.inspect}" unless parsed_inv.dig("symptom", "invariant", "namespace") == "node_location" &&
                                                                 parsed_inv.dig("symptom", "invariant", "fields", "type") == "PM_WHILE_NODE" &&
                                                                 parsed_inv.dig("symptom", "invariant", "detail", "length") == 4_294_967_294 &&
                                                                 parsed_inv["frames"].map { |f| f["scope"] } == %w[external harness prism prism] &&
                                                                 parsed_inv["frames"][2]["file"] == "templates/src/node.c.erb" &&
                                                                 parsed_inv["frames"][3]["file"] == "src/prism.c" &&
                                                                 parsed_inv["frames"][3]["line"] == 20_046

parsed_ub = parse_crash_output(
  "src/prism.c:15213:5: runtime error: signed integer overflow: 1 + 2147483647 cannot be represented in type 'int32_t'\n" \
  "    #0 0xaaaa in parser_warn_indentation_mismatch /prism/src/prism.c:15213:5\n" \
  "    #1 0xaaab in _start (/prism/build/fuzz+0x10d9ec) (BuildId: abc)\n" \
  "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/prism.c:15213:5\n"
)
raise "unexpected ubsan parse: #{parsed_ub.inspect}" unless parsed_ub.dig("symptom", "ubsan", "file") == "src/prism.c" &&
                                                             parsed_ub.dig("symptom", "ubsan", "line") == 15_213 &&
                                                             parsed_ub.dig("symptom", "ubsan", "check") == "signed integer overflow" &&
                                                             parsed_ub["frames"][1]["module"] == "/prism/build/fuzz+0x10d9ec"

repro_dir = File.join(workdir, "standalone_repro")
FileUtils.mkdir_p(repro_dir)
File.write(File.join(repro_dir, "testcase.c"), tc_min_oob_c)
build_sh_path = File.join(repro_dir, "build.sh")
File.write(build_sh_path, inv_build)
File.chmod(0o755, build_sh_path)
EOF

grep -q "static const size_t input_size = 6;" "$WORKDIR/tc_nonempty.c" || fail "missing input_size = 6 in tc_nonempty.c"
grep -q "static const size_t input_size = 0;" "$WORKDIR/tc_empty.c" || fail "missing input_size = 0 in tc_empty.c"

repo_root="$PWD"
mkdir -p "$WORKDIR/prism_objs"
(
    cd "$WORKDIR/prism_objs"
    clang -O1 -std=c99 -DPRISM_EXPORT_SYMBOLS -fsanitize=address,undefined \
        -I"$repo_root/include" -I"$repo_root/src" $(find "$repo_root/src" -name '*.c') -c
)
ar rcs "$WORKDIR/libprism_test.a" "$WORKDIR/prism_objs/"*.o

for name in tc_nonempty tc_empty tc_min_oob tc_stream_slow tc_node_loc; do
    clang -O1 -c -std=c99 -Wall -Wextra -Wpedantic -Wundef -Wconversion -Wstrict-prototypes -Werror \
        -fsanitize=address,undefined -Iinclude "$WORKDIR/$name.c" -o "$WORKDIR/$name.o"
    clang -fsanitize=address,undefined "$WORKDIR/$name.o" "$WORKDIR/libprism_test.a" -o "$WORKDIR/$name"
done

"$WORKDIR/tc_nonempty"
"$WORKDIR/tc_empty"
"$WORKDIR/tc_min_oob"
"$WORKDIR/tc_stream_slow"
"$WORKDIR/tc_node_loc"
PRISM_ROOT="$repo_root" "$WORKDIR/standalone_repro/build.sh"
"$WORKDIR/standalone_repro/testcase"
echo "  minimal <prism.h> testcase.c + build.sh compiled with -Iinclude only under -std=c99 -Werror and passed ASAN+UBSAN"

echo "[4/5] Checking concurrent triage.rb deduplication, header minimization, coalescing, sentinels, and JSON metadata..."
mkdir -p "$WORKDIR/afl/w1/crashes" "$WORKDIR/afl/w2/crashes" "$WORKDIR/afl/w1/hangs"
printf '%s\n' "$WORKDIR/synth_target" > "$WORKDIR/afl/w1/cmdline"
printf '%s\n' "$WORKDIR/synth_target" > "$WORKDIR/afl/w2/cmdline"

ruby - "$WORKDIR/afl" << 'EOF'
afl = ARGV.fetch(0)
hdr = "\x2a\x11\x22\x33".b
4.times do |i|
  body = ("x_#{i} = 123\n".b * 10) + "BOOM\n".b + ("y_#{i} = 456\n".b * 10)
  File.binwrite(File.join(afl, "w1/crashes/id:00000#{i},sig:06"), hdr + body)
end

# Byte-identical duplicate across workers
dup = File.binread(File.join(afl, "w1/crashes/id:000000,sig:06"))
File.binwrite(File.join(afl, "w2/crashes/id:000000,sig:06"), dup)

# Two distinct INVARIANT[...] crashes sharing an identical C call stack (plus a shifted-offset duplicate)
inv_hdr = "\x10\x44\x55\x66".b
File.binwrite(File.join(afl, "w1/crashes/id:000010,sig:06"), inv_hdr + ("a = 1\n".b * 8) + "INV_TARGET\n".b)
File.binwrite(File.join(afl, "w2/crashes/id:000011,sig:06"), inv_hdr + ("b = 222\n".b * 20) + "INV_TARGET\n".b)
File.binwrite(File.join(afl, "w1/crashes/id:000012,sig:06"), inv_hdr + ("c = 3\n".b * 8) + "INV_DECOY\n".b)

# Unreproducible crash (sig:06, exits 0 on replay)
File.binwrite(File.join(afl, "w1/crashes/id:000098,sig:06"), "\x00\x00\x03\x011 + 1\n".b)

# External OOM SIGKILL (sig:09, exits 0 on replay -> skipped)
File.binwrite(File.join(afl, "w1/crashes/id:000099,sig:09"), "\x00\x00\x03\x01ok\n".b)

# Transient timeout in hangs/ (exits 0 on replay -> skipped)
File.binwrite(File.join(afl, "w1/hangs/id:000000,src:000001"), "\x00\x00\x03\x01ok_hang\n".b)
EOF

ruby - "$WORKDIR/afl" "$WORKDIR/triage" << 'EOF' > "$WORKDIR/triage.log"
require "json"
afl_dir, triage_dir = ARGV
ENV["TRIAGE_COVERAGE_BIN"] = ""
src = File.read("test/fuzz/triage/triage.rb")
src.sub!('OUTPUT_DIRS = ["tmp/fuzz/afl", "tmp/fuzz/afl-ijon"].freeze', "OUTPUT_DIRS = [#{afl_dir.dump}].freeze")
src.sub!('TESTCASES_DIR = "tmp/fuzz/triage"', "TESTCASES_DIR = #{triage_dir.dump}")
eval(src)
EOF

ruby - "$WORKDIR/triage" "$WORKDIR/triage.log" << 'EOF'
require "json"
triage_dir, log_path = ARGV
log = File.read(log_path)

abrt_dirs = Dir.glob(File.join(triage_dir, "ABRT", "*")).sort
raise "expected 3 ABRT dirs (BOOM + heredoc_term + escape_invalid_meta), got #{abrt_dirs.inspect}\nlog:\n#{log}" unless abrt_dirs.size == 3

tokens_found = []
counts_by_token = {}
abrt_dirs.each do |abrt_dir|
  mode = File.stat(abrt_dir).mode & 0o777
  raise "expected world-readable/traversable dir mode, got #{format('%#o', mode)}" unless (mode & 0o755) == 0o755
  tc_path = File.join(abrt_dir, "testcase.c")
  build_path = File.join(abrt_dir, "build.sh")
  meta_path = File.join(abrt_dir, "meta.json")
  occ_path = File.join(abrt_dir, "occurrences.jsonl")
  raise "missing testcase.c in #{abrt_dir}" unless File.file?(tc_path)
  raise "missing executable build.sh in #{abrt_dir}" unless File.executable?(build_path)
  raise "missing meta.json in #{abrt_dir}" unless File.file?(meta_path)
  raise "missing occurrences.jsonl in #{abrt_dir}" unless File.file?(occ_path)
  tc = File.read(tc_path)
  meta = JSON.parse(File.read(meta_path))

  min_data = File.binread(File.join(abrt_dir, "input.min"))
  body = min_data.byteslice(4..)
  if body.include?("BOOM".b)
    raise "expected BOOM header minimized to \\x02\\x00\\x03\\x01, got #{min_data.byteslice(0, 4).dump}" unless min_data.byteslice(0, 4) == "\x02\x00\x03\x01".b
    raise "unexpected BOOM input.min size: #{min_data.dump}" unless min_data.bytesize <= 12
    raise "expected only partial_script option in BOOM testcase.c:\n#{tc}" unless tc.include?("pm_options_partial_script_set(options, true);") && !tc.include?("pm_options_command_line_set") && !tc.include?("pm_options_scopes_init") && !tc.include?("pm_parser_errors_first")
    raise "unexpected BOOM meta options: #{meta["options"].inspect}" unless meta.dig("options", "partial_script") == true && meta.dig("options", "ruby_version") == "4.1"
    raise "unexpected BOOM assertion meta: #{meta.dig("symptom", "assertion").inspect}" unless meta.dig("symptom", "assertion", "expr") == "0"
    tokens_found << "BOOM"
    counts_by_token["BOOM"] = meta.dig("occurrences", "count")
  elsif body.include?("INV_TARGET".b)
    raise "expected INV_TARGET header minimized to \\x10\\x00\\x03\\x01, got #{min_data.byteslice(0, 4).dump}" unless min_data.byteslice(0, 4) == "\x10\x00\x03\x01".b
    raise "unexpected INV_TARGET input.min size: #{min_data.dump}" unless min_data.bytesize <= 18
    raise "expected frozen_string_literal + error invariant in INV_TARGET testcase.c:\n#{tc}" unless tc.include?("pm_options_frozen_string_literal_set(options, false);") && tc.include?("pm_parser_errors_first(parser)")
    raise "unexpected INV_TARGET invariant meta: #{meta.dig("symptom", "invariant").inspect}" unless meta.dig("symptom", "invariant", "namespace") == "diagnostic" && meta.dig("symptom", "invariant", "fields", "type") == "heredoc_term"
    raise "unexpected INV_TARGET frames: #{meta["frames"].inspect}" unless meta["frames"].size == 2 && meta["frames"][0]["func"] == "fail_invariant_at_shared_site"
    raise "unexpected INV_TARGET by_worker: #{meta.dig("occurrences", "by_worker").inspect}" unless meta.dig("occurrences", "by_worker") == { "w1" => 1, "w2" => 1 }
    tokens_found << "INV_TARGET"
    counts_by_token["INV_TARGET"] = meta.dig("occurrences", "count")
  elsif body.include?("INV_DECOY".b)
    raise "expected INV_DECOY header minimized to \\x10\\x00\\x03\\x01, got #{min_data.byteslice(0, 4).dump}" unless min_data.byteslice(0, 4) == "\x10\x00\x03\x01".b
    raise "unexpected INV_DECOY input.min size: #{min_data.dump}" unless min_data.bytesize <= 18
    raise "unexpected INV_DECOY invariant meta: #{meta.dig("symptom", "invariant").inspect}" unless meta.dig("symptom", "invariant", "fields", "type") == "escape_invalid_meta"
    tokens_found << "INV_DECOY"
    counts_by_token["INV_DECOY"] = meta.dig("occurrences", "count")
  else
    raise "unexpected minimized body in #{abrt_dir}: #{min_data.dump}"
  end
  raise "expected coverage disabled in uninstrumented test, got #{meta["coverage"].inspect}" unless meta.dig("coverage", "available") == false
end
raise "expected all 3 distinct ABRT tokens, got #{tokens_found.inspect}" unless tokens_found.sort == %w[BOOM INV_DECOY INV_TARGET]
raise "expected counts {BOOM=>4, INV_TARGET=>2, INV_DECOY=>1}, got #{counts_by_token.inspect}" unless counts_by_token == { "BOOM" => 4, "INV_TARGET" => 2, "INV_DECOY" => 1 }

unrepro_dirs = Dir.glob(File.join(triage_dir, "unreproducible", "*"))
raise "expected 1 unreproducible dir, got #{unrepro_dirs.inspect}" unless unrepro_dirs.size == 1
raise "missing testcase.c in unreproducible dir" unless File.file?(File.join(unrepro_dirs.first, "testcase.c"))
raise "missing executable build.sh in unreproducible dir" unless File.executable?(File.join(unrepro_dirs.first, "build.sh"))
raise "missing meta.json in unreproducible dir" unless File.file?(File.join(unrepro_dirs.first, "meta.json"))

raise "transient hang should not create hang dir" if File.exist?(File.join(triage_dir, "hang"))
min_runs = log.scan(/^minimizing /).size
raise "expected exactly 3 minimization runs across duplicates, got #{min_runs}:\n#{log}" unless min_runs == 3

sentinels = Dir.glob(File.join(triage_dir, ".processed", "*"))
raise "expected 10 .processed sentinels (4 BOOM + 2 INV_TARGET + 1 INV_DECOY + 1 unrepro + 1 sig:09 + 1 hang), got #{sentinels.size}" unless sentinels.size == 10

index_path = File.join(triage_dir, "metadata.json")
raise "missing consolidated metadata.json" unless File.file?(index_path)
index = JSON.parse(File.read(index_path))
raise "unexpected metadata summary: #{index["summary"].inspect}" unless index.dig("summary", "bucket_count") == 4 && index.dig("summary", "total_occurrences") == 8
EOF
echo "  concurrent deduplication, header minimization, coalescing, sentinel, and JSON metadata checks passed"

if command -v afl-clang-lto >/dev/null 2>&1 && command -v afl-showmap >/dev/null 2>&1 && [ -d build/afl ]; then
    echo "[5/5] Checking afl-showmap bucket coverage, corpus edge DF, DOCUMENT_IDS, caching, and recount..."
    cat << 'EOF' > "$WORKDIR/cov_target.c"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) static void common_path(void) { asm volatile(""); }
__attribute__((noinline)) static void rare_corpus_path(void) { asm volatile(""); }
__attribute__((noinline)) static void bug_recovery_helper(void) {
    fprintf(stderr, "INVARIANT[node_location]: type=PM_CALL_NODE kind=length_underflow [detail: start=1 length=9 parsed_size=2]\n");
    abort();
}

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    uint8_t buf[64];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n < 5) return 0;
    uint8_t op = buf[4];
    common_path();
    if (op == 'R') rare_corpus_path();
    if (op == 'B') bug_recovery_helper();
    return 0;
}
EOF
    rm -f "$WORKDIR/cov_target.ids"
    AFL_PATH="$PWD/build/afl" AFL_LLVM_DOCUMENT_IDS="$WORKDIR/cov_target.ids" afl-clang-lto -O1 -g "$WORKDIR/cov_target.c" -o "$WORKDIR/cov_target" >/dev/null 2>&1

    mkdir -p "$WORKDIR/corpus" "$WORKDIR/afl_cov/m1/crashes" "$WORKDIR/afl_cov/m2/crashes"
    printf '\x00\x00\x03\x01cccc' > "$WORKDIR/corpus/c1.rb"
    printf '\x00\x00\x03\x01dddd' > "$WORKDIR/corpus/c2.rb"
    printf '\x00\x00\x03\x01Rrrr' > "$WORKDIR/corpus/r1.rb"

    printf '%s\n' "$WORKDIR/cov_target" > "$WORKDIR/afl_cov/m1/cmdline"
    printf '%s\n' "$WORKDIR/cov_target" > "$WORKDIR/afl_cov/m2/cmdline"
    printf '\x00\x00\x03\x01Bxyz' > "$WORKDIR/afl_cov/m1/crashes/id:000001,sig:06"
    printf '\x00\x00\x03\x01B123' > "$WORKDIR/afl_cov/m2/crashes/id:000002,sig:06"

    ruby - "$WORKDIR" << 'EOF' > "$WORKDIR/cov_triage1.log"
workdir = ARGV.fetch(0)
ENV["TRIAGE_COVERAGE_BIN"] = File.join(workdir, "cov_target")
ENV["TRIAGE_COVERAGE_IDS"] = File.join(workdir, "cov_target.ids")
ENV["TRIAGE_CORPUS_DIR"] = File.join(workdir, "corpus")
src = File.read("test/fuzz/triage/triage.rb")
src.sub!('OUTPUT_DIRS = ["tmp/fuzz/afl", "tmp/fuzz/afl-ijon"].freeze', "OUTPUT_DIRS = [#{File.join(workdir, "afl_cov").dump}].freeze")
src.sub!('TESTCASES_DIR = "tmp/fuzz/triage"', "TESTCASES_DIR = #{File.join(workdir, "triage_cov").dump}")
eval(src)
EOF

    ruby - "$WORKDIR" << 'EOF'
require "json"
workdir = ARGV.fetch(0)
triage_dir = File.join(workdir, "triage_cov")
index = JSON.parse(File.read(File.join(triage_dir, "metadata.json")))

raise "expected reference binary available" unless index.dig("reference_binary", "available") && index.dig("reference_binary", "ids_available")
raise "expected 3 corpus files, got #{index.dig("corpus", "corpus_count")}" unless index.dig("corpus", "corpus_count") == 3
edge_df = index.dig("corpus", "edge_df") || {}
edge_fns = index.dig("corpus", "edge_functions") || {}
raise "expected non-empty edge_df and edge_functions" if edge_df.empty? || edge_fns.empty?
raise "expected at least one df==3 edge and df==1 rare edge in corpus: #{edge_df.inspect}" unless edge_df.values.include?(3) && edge_df.values.include?(1)

raise "expected 1 bucket totaling 2 occurrences, got #{index["summary"].inspect}" unless index.dig("summary", "bucket_count") == 1 && index.dig("summary", "total_occurrences") == 2
bucket = index["buckets"].first
edges = bucket.dig("coverage", "edges") || {}
raise "expected available bucket coverage edges, got #{bucket["coverage"].inspect}" unless bucket.dig("coverage", "available") && !edges.empty?
unseen_edges = edges.keys.reject { |e| edge_df.key?(e) }
raise "expected bug-specific edge unseen in corpus (#{edges.keys.inspect} vs corpus #{edge_df.keys.inspect})" if unseen_edges.empty?
EOF

    # Second run with no changes must reuse the corpus cache, and a recount test on
    # a pre-existing processed sentinel without occurrences must add the missing count.
    ruby - "$WORKDIR" << 'EOF' > "$WORKDIR/cov_triage2.log"
workdir = ARGV.fetch(0)
triage_dir = File.join(workdir, "triage_cov")
require "digest"
late_crash = File.join(workdir, "afl_cov/m2/crashes/id:000003,sig:06")
File.binwrite(late_crash, "\x00\x00\x03\x01B999")
File.write(File.join(triage_dir, ".processed", Digest::SHA2.hexdigest(File.binread(late_crash))), "")

ENV["TRIAGE_COVERAGE_BIN"] = File.join(workdir, "cov_target")
ENV["TRIAGE_COVERAGE_IDS"] = File.join(workdir, "cov_target.ids")
ENV["TRIAGE_CORPUS_DIR"] = File.join(workdir, "corpus")
ENV["TRIAGE_RECOUNT"] = "1"
src = File.read("test/fuzz/triage/triage.rb")
src.sub!('OUTPUT_DIRS = ["tmp/fuzz/afl", "tmp/fuzz/afl-ijon"].freeze', "OUTPUT_DIRS = [#{File.join(workdir, "afl_cov").dump}].freeze")
src.sub!('TESTCASES_DIR = "tmp/fuzz/triage"', "TESTCASES_DIR = #{triage_dir.dump}")
eval(src)
EOF

    grep -q "Collecting afl-showmap corpus baseline" "$WORKDIR/cov_triage2.log" && fail "expected second run to hit corpus cache"
    ruby - "$WORKDIR/triage_cov/metadata.json" << 'EOF'
require "json"
index = JSON.parse(File.read(ARGV.fetch(0)))
raise "expected recount to raise count to 3, got #{index.dig("summary", "total_occurrences")}" unless index.dig("summary", "total_occurrences") == 3
EOF
    echo "  afl-showmap coverage, corpus DF, DOCUMENT_IDS, caching, and recount checks passed"
else
    echo "[5/5] SKIPPED: afl-clang-lto / afl-showmap / build/afl not available outside Docker"
fi

echo "PASS: Fuzz crash triage and minimization suite verified."
