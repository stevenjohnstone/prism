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
# 6. Per-bucket raw input archiving, verify.sh / verify.rb PARTIAL-fix detection,
#    survivor extraction, crash/timeout isolation, and LSan leak bisection.
# 7. Root-cause bucket clustering (cluster.rb): cross-reason frame merges,
#    frame-presence mismatch separation, single-bug short campaigns, boilerplate
#    & recovery damping, unreproducible filtering, fallbacks, and determinism.

set -euo pipefail

WORKDIR="$(mktemp -d /tmp/test-fuzz-triage.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "[1/7] Checking signature.sh normalization and SIGPIPE safety..."
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

echo "[2/7] Checking halfempty.sh minimization, header preservation, and drift protection..."
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

echo "[3/7] Checking triage.rb minimal <prism.h> C reproducer synthesis and strict C99 build..."
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

echo "[4/7] Checking concurrent triage.rb deduplication, header minimization, coalescing, sentinels, and JSON metadata..."
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
  verify_path = File.join(abrt_dir, "verify.sh")
  archive_path = File.join(abrt_dir, "inputs.tar.gz")
  pending_path = File.join(abrt_dir, ".inputs.pending")
  meta_path = File.join(abrt_dir, "meta.json")
  occ_path = File.join(abrt_dir, "occurrences.jsonl")
  raise "missing testcase.c in #{abrt_dir}" unless File.file?(tc_path)
  raise "missing executable build.sh in #{abrt_dir}" unless File.executable?(build_path)
  raise "missing executable verify.sh in #{abrt_dir}" unless File.executable?(verify_path)
  raise "missing inputs.tar.gz in #{abrt_dir}" unless File.file?(archive_path)
  raise "unexpected leftover .inputs.pending in #{abrt_dir}" if File.exist?(pending_path)
  raise "missing meta.json in #{abrt_dir}" unless File.file?(meta_path)
  raise "missing occurrences.jsonl in #{abrt_dir}" unless File.file?(occ_path)
  tc = File.read(tc_path)
  meta = JSON.parse(File.read(meta_path))
  raise "archive count #{meta.dig("archive", "count")} != occurrences #{meta.dig("occurrences", "count")}" unless meta.dig("archive", "count") == meta.dig("occurrences", "count")
  raise "unexpected verify_profile: #{meta["verify_profile"].inspect}" unless meta["verify_profile"] == "asan_ubsan"

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
    echo "[5/7] Checking afl-showmap bucket coverage, corpus edge DF, DOCUMENT_IDS, caching, and recount..."
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
b = index["buckets"].first
raise "expected recounted archive to contain all 3 inputs, got #{b["archive"].inspect}" unless b.dig("archive", "count") == 3
EOF
    echo "  afl-showmap coverage, corpus DF, DOCUMENT_IDS, caching, and recount checks passed"
else
    echo "[5/7] SKIPPED: afl-clang-lto / afl-showmap / build/afl not available outside Docker"
fi

echo "[6/7] Checking verify_runner crash/timeout/leak isolation and verify.sh / verify.rb PARTIAL-fix workflow..."
cat << 'EOF' > "$WORKDIR/mock_fuzz_target.c"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile uintptr_t leak_sink = 0;

__attribute__((noinline)) static void do_leak(void) {
    void *p = malloc(128);
    if (!p) abort();
    leak_sink = ((uintptr_t)p) ^ (uintptr_t)0x5555;
}

__attribute__((noinline)) static void scrub_stack(void) {
    volatile char buf[512];
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = 0;
}

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
    if (size >= 5 && memcmp(data, "CRASH", 5) == 0) {
        fprintf(stderr, "INVARIANT[mock]: kind=crash\n");
        abort();
    }
    if (size >= 4 && memcmp(data, "HANG", 4) == 0) {
        for (;;) {}
    }
    if (size >= 4 && memcmp(data, "LEAK", 4) == 0) {
        do_leak();
    }
    scrub_stack();
    return 0;
}
EOF

clang -O1 -g -std=c99 -fsanitize=address \
    test/fuzz/triage/verify_runner.c "$WORKDIR/mock_fuzz_target.c" \
    -o "$WORKDIR/mock_verify"

ruby - "$WORKDIR" << 'EOF'
require "rubygems/package"
require "zlib"
workdir = ARGV.fetch(0)
Zlib::GzipWriter.open(File.join(workdir, "mixed.tar.gz")) do |gz|
  Gem::Package::TarWriter.new(gz) do |tar|
    items = [
      ["ok_0", "ok_zero"],
      ["bad_crash", "CRASH_1"],
      ["ok_1", "ok_one"],
      ["bad_hang", "HANG_forever"],
      ["ok_2", "ok_two"],
      ["bad_crash2", "CRASH_2"],
      ["ok_3", "ok_three"]
    ]
    items.each do |name, body|
      tar.add_file_simple(name, 0o644, body.bytesize) { |io| io.write(body) }
    end
  end
end

Zlib::GzipWriter.open(File.join(workdir, "leak.tar.gz")) do |gz|
  Gem::Package::TarWriter.new(gz) do |tar|
    10.times do |i|
      body = (i == 6) ? "LEAK_here" : "clean_#{i}"
      tar.add_file_simple("item_#{i}", 0o644, body.bytesize) { |io| io.write(body) }
    end
  end
end
EOF

set +e
gzip -dc "$WORKDIR/mixed.tar.gz" | "$WORKDIR/mock_verify" --tar - --timeout 1 --json > "$WORKDIR/mixed.json"
mixed_rc=$?
set -e
[ "$mixed_rc" -eq 1 ] || fail "expected mixed verify_runner run to exit 1, got $mixed_rc"

ruby - "$WORKDIR/mixed.json" << 'EOF'
require "json"
res = JSON.parse(File.read(ARGV.fetch(0)))
raise "expected 7 checked inputs, got #{res.inspect}" unless res["checked"] == 7 && res["passed"] == 4 && res["failed"] == 3 && res["timed_out"] == 1
names = res["failures"].map { |f| f["name"] }
raise "expected exact failure isolation [bad_crash, bad_hang, bad_crash2], got #{names.inspect}" unless names == %w[bad_crash bad_hang bad_crash2]
EOF

if [ "$(uname -s)" != "Darwin" ]; then
    set +e
    gzip -dc "$WORKDIR/leak.tar.gz" | ASAN_OPTIONS=detect_leaks=1 "$WORKDIR/mock_verify" --tar - --timeout 5 --json > "$WORKDIR/leak.json"
    leak_rc=$?
    set -e
    [ "$leak_rc" -eq 1 ] || fail "expected LSan bisection run to exit 1, got $leak_rc"
    ruby - "$WORKDIR/leak.json" << 'EOF'
require "json"
res = JSON.parse(File.read(ARGV.fetch(0)))
raise "expected LSan bisect to isolate only item_6, got #{res.inspect}" unless res["checked"] == 10 && res["failed"] == 1 && res["failures"].first["name"] == "item_6"
EOF
fi

# 1) Compile verify_runner.c against the real Prism tree and verify valid inputs end-to-end.
real_triage="$WORKDIR/real_verify_triage"
real_pass_dir="$real_triage/ABRT/real_pass_sig"
mkdir -p "$real_pass_dir"
printf '\x00\x00\x03\x012 + 2\n' > "$real_pass_dir/input.min"
ruby - "$real_pass_dir" << 'EOF'
require "digest"
require "rubygems/package"
require "zlib"
pass_dir = ARGV.fetch(0)
ok_bytes_a = "\x00\x00\x03\x01puts 42\n".b
ok_bytes_b = "\x00\x00\x03\x01x = [1, 2]\n".b
Zlib::GzipWriter.open(File.join(pass_dir, "inputs.tar.gz")) do |gz|
  Gem::Package::TarWriter.new(gz) do |tar|
    [ok_bytes_a, ok_bytes_b].each do |data|
      sha = Digest::SHA256.hexdigest(data)
      tar.add_file_simple(sha, 0o644, data.bytesize) { |io| io.write(data) }
    end
  end
end
EOF
cat << EOF > "$real_pass_dir/verify.sh"
#!/usr/bin/env bash
set -euo pipefail
exec "$PWD/test/fuzz/triage/verify_bucket.sh" --repo-root "$PWD" --bucket-dir "$real_pass_dir" --profile "asan_ubsan" "\$@"
EOF
chmod +x "$real_pass_dir/verify.sh"
VERIFY_BUILD_DIR="$WORKDIR/real_verify_build" "$real_pass_dir/verify.sh" --quiet >/dev/null
VERIFY_BUILD_DIR="$WORKDIR/real_verify_build" ruby ./test/fuzz/triage/verify.rb --triage-dir "$real_triage" --quiet

# 2) Deterministic verify.sh + verify.rb PARTIAL-fix & survivor extraction check.
mock_triage="$WORKDIR/mock_verify_triage"
partial_dir="$mock_triage/ABRT/partial_sig"
pass_dir="$mock_triage/ABRT/pass_sig"
mkdir -p "$partial_dir" "$pass_dir" "$WORKDIR/mock_verify_build"
cp "$WORKDIR/mock_verify" "$WORKDIR/mock_verify_build/verify_runner.asan_ubsan"
touch "$WORKDIR/mock_verify_build/verify_runner.asan_ubsan"

printf 'fixed_representative' > "$partial_dir/input.min"
printf 'clean_representative' > "$pass_dir/input.min"

ruby - "$partial_dir" "$pass_dir" << 'EOF'
require "digest"
require "rubygems/package"
require "zlib"
partial_dir, pass_dir = ARGV

bad_bytes = "CRASH_rare_sibling".b
bad_sha = Digest::SHA256.hexdigest(bad_bytes)
File.write(File.join(partial_dir, ".expected_bad_sha"), bad_sha)
ok_bytes_a = "clean_a".b
ok_bytes_b = "clean_b".b

Zlib::GzipWriter.open(File.join(partial_dir, "inputs.tar.gz")) do |gz|
  Gem::Package::TarWriter.new(gz) do |tar|
    [[Digest::SHA256.hexdigest(ok_bytes_a), ok_bytes_a], [bad_sha, bad_bytes], [Digest::SHA256.hexdigest(ok_bytes_b), ok_bytes_b]].each do |sha, data|
      tar.add_file_simple(sha, 0o644, data.bytesize) { |io| io.write(data) }
    end
  end
end

Zlib::GzipWriter.open(File.join(pass_dir, "inputs.tar.gz")) do |gz|
  Gem::Package::TarWriter.new(gz) do |tar|
    tar.add_file_simple(Digest::SHA256.hexdigest(ok_bytes_a), 0o644, ok_bytes_a.bytesize) { |io| io.write(ok_bytes_a) }
  end
end
EOF

cat << EOF > "$partial_dir/verify.sh"
#!/usr/bin/env bash
set -euo pipefail
exec "$PWD/test/fuzz/triage/verify_bucket.sh" --repo-root "$PWD" --bucket-dir "$partial_dir" --profile "asan_ubsan" "\$@"
EOF
cat << EOF > "$pass_dir/verify.sh"
#!/usr/bin/env bash
set -euo pipefail
exec "$PWD/test/fuzz/triage/verify_bucket.sh" --repo-root "$PWD" --bucket-dir "$pass_dir" --profile "asan_ubsan" "\$@"
EOF
chmod +x "$partial_dir/verify.sh" "$pass_dir/verify.sh"

export VERIFY_BUILD_DIR="$WORKDIR/mock_verify_build"
"$pass_dir/verify.sh" --quiet >/dev/null
if "$partial_dir/verify.sh" --quiet >/dev/null 2>&1; then
    fail "expected verify.sh to catch surviving archived crasher when input.min passes"
fi

set +e
ruby ./test/fuzz/triage/verify.rb \
    --triage-dir "$mock_triage" \
    --extract-survivors "$WORKDIR/survivors" \
    --json "$WORKDIR/verify_report.json" >/dev/null
vrb_rc=$?
set -e
[ "$vrb_rc" -eq 1 ] || fail "expected verify.rb to exit 1 on PARTIAL bucket, got $vrb_rc"

ruby - "$WORKDIR/verify_report.json" "$WORKDIR/survivors" "$partial_dir/.expected_bad_sha" << 'EOF'
require "json"
report_path, surv_dir, sha_file = ARGV
report = JSON.parse(File.read(report_path))
bad_sha = File.read(sha_file).strip
summary = report["summary"]
raise "unexpected verify summary: #{summary.inspect}" unless summary["pass"] == 1 && summary["partial"] == 1 && summary["fail"] == 0 && summary["inputs_checked"] == 6 && summary["inputs_failed"] == 1

partial_bucket = report["buckets"].find { |b| b["bucket_id"] == "ABRT/partial_sig" }
raise "expected min_passed==true on PARTIAL bucket: #{partial_bucket.inspect}" unless partial_bucket && partial_bucket["min_passed"] == true
surv_file = File.join(surv_dir, "ABRT/partial_sig", bad_sha)
raise "missing extracted survivor at #{surv_file}" unless File.file?(surv_file)
raise "extracted survivor contents mismatch" unless File.binread(surv_file) == "CRASH_rare_sibling".b
raise "empty survivor dir should not exist for PASS bucket" if Dir.exist?(File.join(surv_dir, "ABRT/pass_sig"))
EOF
echo "  verify_runner isolation, real verify.sh build, and verify.rb PARTIAL-fix checks passed"

echo "[7/7] Checking cluster.rb root-cause clustering, cross-reason merges, single-bug stability, and CLI..."
ruby - "$WORKDIR" << 'EOF'
require "json"
require_relative "test/fuzz/triage/cluster"

workdir = ARGV.fetch(0)

# Build a synthetic multi-regime metadata fixture exercising:
# 1. Cross-reason same-bug (SEGV from ijon vs use-of-uninitialized-value from msan sharing leaf parser_lex)
# 2. Cross-reason 1-frame wrapper shift sharing rare coverage
# 3. Distinct leaf sharing only root parser callers (parse_case -> parse_expression -> pm_parse) stays separate
# 4. Two stackless ABRT buckets (minimal + verbose) sharing rare heredoc edges + boilerplate/recovery noise
# 5. Adversarial frame-presence mismatch: stackless ABRT parse_for + in-parse UB parse_for stays separate
# 6. Single unreproducible bucket excluded by default, included via --include-unreproducible
edge_functions = {
  "1" => "pm_parse",
  "2" => "fuzz_invariant_fail",
  "3" => "check_node_location",
  "4" => "pm_visit_node",
  "5" => "pm_error_recovery_node_create",
  "6" => "context_recoverable",
  "10" => "pm_parser_err_heredoc_term",
  "11" => "parse_heredoc",
  "12" => "parse_string_part",
  "13" => "parse_statements",
  "20" => "parse_for",
  "21" => "parse_for",
  "22" => "parse_for",
  "30" => "parser_lex",
  "31" => "pm_string_ensure",
  "40" => "parse_interpolated_symbol_array"
}
edge_df = {
  "1" => 100,
  "2" => 0,
  "3" => 0,
  "4" => 100,
  "5" => 0,
  "6" => 0,
  "10" => 0,
  "11" => 5,
  "12" => 1,
  "13" => 1,
  "20" => 0,
  "21" => 0,
  "22" => 1,
  "30" => 0,
  "31" => 1,
  "40" => 0
}
corpus = {
  "available" => true,
  "corpus_count" => 100,
  "edge_df" => edge_df,
  "edge_functions" => edge_functions
}

make_bucket = lambda do |id:, reason:, occ:, size: 10, frames: [], edges: {}, unrepro: false|
  {
    "bucket_id" => id,
    "reason" => reason,
    "signature" => id.split("/", 2).last,
    "reproducible" => !unrepro,
    "occurrences" => { "count" => occ },
    "input" => { "min_size_bytes" => size },
    "symptom" => { "headline" => "synthetic #{id}" },
    "frames" => frames,
    "coverage" => { "available" => true, "edges" => edges }
  }
end

f_segv = [
  { "scope" => "prism", "func" => "parser_lex", "file" => "src/prism.c", "line" => 300 },
  { "scope" => "prism", "func" => "parse_expression", "file" => "src/prism.c", "line" => 2000 },
  { "scope" => "prism", "func" => "pm_parse", "file" => "src/prism.c", "line" => 3000 }
]
f_msan = [
  { "scope" => "prism", "func" => "parser_lex", "file" => "src/prism.c", "line" => 305 },
  { "scope" => "prism", "func" => "parse_string_part", "file" => "src/prism.c", "line" => 900 },
  { "scope" => "prism", "func" => "pm_parse", "file" => "src/prism.c", "line" => 3000 }
]
f_shift = [
  { "scope" => "prism", "func" => "pm_helper_read", "file" => "src/prism.c", "line" => 50 },
  { "scope" => "prism", "func" => "parser_lex", "file" => "src/prism.c", "line" => 300 },
  { "scope" => "prism", "func" => "parse_expression", "file" => "src/prism.c", "line" => 2000 },
  { "scope" => "prism", "func" => "pm_parse", "file" => "src/prism.c", "line" => 3000 }
]
f_other_leaf = [
  { "scope" => "prism", "func" => "pm_line_offset_list_line_column", "file" => "src/line_offset_list.c", "line" => 96 },
  { "scope" => "prism", "func" => "parse_case", "file" => "src/prism.c", "line" => 1800 },
  { "scope" => "prism", "func" => "parse_expression", "file" => "src/prism.c", "line" => 2000 },
  { "scope" => "prism", "func" => "pm_parse", "file" => "src/prism.c", "line" => 3000 }
]
f_ub_for = [
  { "scope" => "prism", "func" => "parser_warn_indentation_mismatch", "file" => "src/prism.c", "line" => 15213 },
  { "scope" => "prism", "func" => "parse_for", "file" => "src/prism.c", "line" => 19744 },
  { "scope" => "prism", "func" => "pm_parse", "file" => "src/prism.c", "line" => 3000 }
]

buckets = [
  # Cross-reason leaf + 1-frame shift cluster (should merge across SEGV, msan, asan)
  make_bucket.call(id: "SEGV/lex_ijon", reason: "SEGV", occ: 40, frames: f_segv, edges: { "1" => 1, "30" => 1, "31" => 1 }),
  make_bucket.call(id: "use-of-uninitialized-value/lex_msan", reason: "use-of-uninitialized-value", occ: 12, frames: f_msan, edges: { "1" => 1, "30" => 1, "31" => 1 }),
  make_bucket.call(id: "heap-buffer-overflow/lex_shift", reason: "heap-buffer-overflow", occ: 5, frames: f_shift, edges: { "1" => 1, "30" => 1, "31" => 1 }),
  # Separate stack bug sharing root frames
  make_bucket.call(id: "use-of-uninitialized-value/line_col", reason: "use-of-uninitialized-value", occ: 9, frames: f_other_leaf, edges: { "1" => 1 }),
  # Stackless heredoc cluster (minimal + verbose + parse_for caller noise) + visitor wrapper stripped
  make_bucket.call(id: "ABRT/heredoc_min", reason: "ABRT", occ: 100, size: 9, frames: [{ "scope" => "prism", "func" => "pm_visit_node", "file" => "node.c", "line" => 1 }], edges: { "1" => 1, "2" => 1, "3" => 1, "4" => 1, "10" => 1, "11" => 1 }),
  make_bucket.call(id: "ABRT/heredoc_full", reason: "ABRT", occ: 25, size: 22, edges: { "1" => 1, "2" => 1, "3" => 1, "5" => 1, "6" => 1, "10" => 1, "11" => 1, "12" => 1, "13" => 1, "20" => 1, "21" => 1, "22" => 1 }),
  # Different stackless ABRT sharing recovery + boilerplate noise only (must NOT merge with heredoc_full)
  make_bucket.call(id: "ABRT/sym_array", reason: "ABRT", occ: 30, edges: { "1" => 1, "2" => 1, "3" => 1, "5" => 1, "6" => 1, "40" => 1 }),
  # Adversarial in-parse UB parse_for (must NOT merge with ABRT/heredoc_full despite shared parse_for edges)
  make_bucket.call(id: "undefined-behavior/indent_for", reason: "undefined-behavior", occ: 18, frames: f_ub_for, edges: { "1" => 1, "5" => 1, "6" => 1, "20" => 1, "21" => 1, "22" => 1 }),
  # Unreproducible bucket (skipped by default; common parse edge only)
  make_bucket.call(id: "unreproducible/transient_01", reason: "unreproducible", occ: 2, unrepro: true, edges: { "1" => 1 })
]

metadata = { "schema_version" => 1, "corpus" => corpus, "buckets" => buckets }
report = FuzzClustering.cluster_metadata(metadata)
groups = report["clusters"].map { |c| c["buckets"].map { |b| b["bucket_id"] }.sort }.sort
expected = [
  ["ABRT/heredoc_full", "ABRT/heredoc_min"],
  ["ABRT/sym_array"],
  ["SEGV/lex_ijon", "heap-buffer-overflow/lex_shift", "use-of-uninitialized-value/lex_msan"],
  ["undefined-behavior/indent_for"],
  ["use-of-uninitialized-value/line_col"]
].sort
raise "unexpected clusters:\n  got:      #{groups.inspect}\n  expected: #{expected.inspect}" unless groups == expected
raise "expected excluded_unreproducible=1" unless report.dig("summary", "excluded_unreproducible") == 1

# Shuffling bucket order must produce identical deterministic output
shuffled = { "schema_version" => 1, "corpus" => corpus, "buckets" => buckets.reverse }
report_rev = FuzzClustering.cluster_metadata(shuffled)
raise "cluster_metadata must be permutation-invariant" unless report_rev["clusters"] == report["clusters"]

# Include unreproducible option preserves unreproducible bucket as its own cluster
report_unrepro = FuzzClustering.cluster_metadata(metadata, include_unreproducible: true)
raise "expected 6 clusters with include_unreproducible=true, got #{report_unrepro.dig("summary", "cluster_count")}" unless report_unrepro.dig("summary", "cluster_count") == 6

# Single-bug short-campaign mode (only the 2 heredoc buckets, 1 reason, zero external contrast)
single_bug_meta = { "schema_version" => 1, "corpus" => corpus, "buckets" => buckets.select { |b| b["bucket_id"].start_with?("ABRT/heredoc") } }
single_rep = FuzzClustering.cluster_metadata(single_bug_meta)
raise "single-bug 2-bucket heredoc collapsed failed: #{single_rep["clusters"].inspect}" unless single_rep.dig("summary", "cluster_count") == 1

# Recovery-only bug must still cluster (recovery weight = 0.10 > 0 rather than zeroed)
rec_a = make_bucket.call(id: "ABRT/rec_a", reason: "ABRT", occ: 4, edges: { "1" => 1, "5" => 1, "6" => 1 })
rec_b = make_bucket.call(id: "ABRT/rec_b", reason: "ABRT", occ: 2, edges: { "1" => 1, "5" => 1, "6" => 1 })
rec_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => corpus, "buckets" => [rec_a, rec_b] })
raise "expected recovery-only bug buckets to merge via S_cov=1.0, got #{rec_rep["clusters"].inspect}" unless rec_rep.dig("summary", "cluster_count") == 1

# Setup/encoding-lookup functions (weight 0.0) must not alias unrelated syntax bugs sharing rare fuzz options
setup_ef = edge_functions.merge("50" => "pm_parser_init", "51" => "pm_encoding_find", "52" => "parse_heredoc", "53" => "parse_global_variable")
setup_df = edge_df.merge("50" => 0, "51" => 0, "52" => 0, "53" => 0)
setup_corpus = { "available" => true, "corpus_count" => 100, "edge_df" => setup_df, "edge_functions" => setup_ef }
setup_a = make_bucket.call(id: "ABRT/setup_a", reason: "ABRT", occ: 3, edges: { "1" => 1, "50" => 1, "51" => 1, "52" => 1 })
setup_b = make_bucket.call(id: "ABRT/setup_b", reason: "ABRT", occ: 3, edges: { "1" => 1, "50" => 1, "51" => 1, "53" => 1 })
setup_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => setup_corpus, "buckets" => [setup_a, setup_b] })
raise "expected SETUP_FUNCTIONS filtering to separate setup_a and setup_b, got #{setup_rep["clusters"].inspect}" unless setup_rep.dig("summary", "cluster_count") == 2

# Subset containment: short syntax bug whose rare edges also appear inside a much larger compound bug must not merge
sub_ef = edge_functions.dup
sub_df = edge_df.dup
%w[60 61].each { |k| sub_ef[k] = "parse_not"; sub_df[k] = 1 }
%w[70 71 72 73 74 75 76 77 78 79 80 81 82 83].each { |k| sub_ef[k] = "parse_heredoc"; sub_df[k] = 0 }
sub_corpus = { "available" => true, "corpus_count" => 100, "edge_df" => sub_df, "edge_functions" => sub_ef }
sub_small = make_bucket.call(id: "ABRT/sub_small", reason: "ABRT", occ: 5, edges: { "60" => 1, "61" => 1 })
sub_big_edges = { "60" => 1, "61" => 1 }.merge((70..83).each_with_object({}) { |k, h| h[k.to_s] = 1 })
sub_big = make_bucket.call(id: "ABRT/sub_big", reason: "ABRT", occ: 5, edges: sub_big_edges)
sub_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => sub_corpus, "buckets" => [sub_small, sub_big] })
raise "expected Weighted Jaccard to separate subset containment, got #{sub_rep["clusters"].inspect}" unless sub_rep.dig("summary", "cluster_count") == 2

# Empty, singleton, and coverage-unavailable fallbacks
empty_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => corpus, "buckets" => [] })
raise "expected 0 clusters on empty metadata" unless empty_rep.dig("summary", "cluster_count") == 0

one_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => corpus, "buckets" => [buckets.first] })
raise "expected 1 cluster on singleton metadata" unless one_rep.dig("summary", "cluster_count") == 1

no_cov_corpus = { "available" => false, "corpus_count" => 0 }
no_cov_buckets = [
  make_bucket.call(id: "SEGV/s1", reason: "SEGV", occ: 5, frames: f_segv, edges: {}).merge("coverage" => { "available" => false }),
  make_bucket.call(id: "use-of-uninitialized-value/s2", reason: "use-of-uninitialized-value", occ: 3, frames: f_msan, edges: {}).merge("coverage" => { "available" => false }),
  make_bucket.call(id: "ABRT/u1", reason: "ABRT", occ: 2, edges: {}).merge("coverage" => { "available" => false }),
  make_bucket.call(id: "ABRT/u2", reason: "ABRT", occ: 1, edges: {}).merge("coverage" => { "available" => false })
]
no_cov_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => no_cov_corpus, "buckets" => no_cov_buckets })
no_cov_groups = no_cov_rep["clusters"].map { |c| c["buckets"].map { |b| b["bucket_id"] }.sort }.sort
unless no_cov_groups == [["ABRT/u1"], ["ABRT/u2"], ["SEGV/s1", "use-of-uninitialized-value/s2"]]
  raise "unexpected no-coverage fallback clusters: #{no_cov_groups.inspect}"
end

# Exercise CLI file and stdout output paths
meta_path = File.join(workdir, "cluster_meta.json")
out_path = File.join(workdir, "clusters_out.json")
File.write(meta_path, JSON.generate(metadata))
cli_out = `ruby ./test/fuzz/triage/cluster.rb --metadata #{meta_path} --output #{out_path}`
raise "cluster.rb CLI failed" unless $?.success? && File.file?(out_path) && cli_out.include?("5 clusters")
stdout_json = JSON.parse(`ruby ./test/fuzz/triage/cluster.rb --metadata #{meta_path} --output - --quiet`)
raise "cluster.rb stdout JSON mismatch" unless stdout_json["clusters"] == JSON.parse(File.read(out_path))["clusters"]
EOF
echo "  cluster.rb cross-reason, single-bug, recovery-damping, fallback, and CLI checks passed"

echo "PASS: Fuzz crash triage and minimization suite verified."
