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
# 8. External target verification (--target / --fuzz-root), automatic template
#    regeneration, 2026 API capability shims, exit 125 on unbuildable/pre-opaque
#    commits, verify.rb --invert / --fail-fast, and git bisect (bisect.rb).

set -euo pipefail

WORKDIR="$(mktemp -d /tmp/test-fuzz-triage.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "[1/8] Checking signature.sh normalization and SIGPIPE safety..."
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

echo "[2/8] Checking halfempty.sh minimization, header preservation, and drift protection..."
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

echo "[3/8] Checking triage.rb minimal <prism.h> C reproducer synthesis and strict C99 build..."
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

echo "[4/8] Checking concurrent triage.rb deduplication, header minimization, coalescing, sentinels, and JSON metadata..."
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
clusters_path = File.join(triage_dir, "clusters.json")
raise "missing consolidated clusters.json" unless File.file?(clusters_path)
clusters = JSON.parse(File.read(clusters_path))
raise "expected schema_version 1 in clusters.json" unless clusters["schema_version"] == 1
EOF
echo "  concurrent deduplication, header minimization, coalescing, sentinel, and JSON metadata checks passed"

if command -v afl-clang-lto >/dev/null 2>&1 && command -v afl-showmap >/dev/null 2>&1 && [ -d build/afl ]; then
    echo "[5/8] Checking afl-showmap bucket coverage, corpus edge DF, DOCUMENT_IDS, caching, and recount..."
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
    echo "[5/8] SKIPPED: afl-clang-lto / afl-showmap / build/afl not available outside Docker"
fi

echo "[6/8] Checking verify_runner crash/timeout/leak isolation and verify.sh / verify.rb PARTIAL-fix workflow..."
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

echo "[7/8] Checking cluster.rb root-cause clustering, cross-reason merges, single-bug stability, and CLI..."
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

# Exercise verify.rb cluster-based verification workflows (--cluster, --by-cluster, --list-clusters, stale auto-refresh)
cluster_verify_triage="$WORKDIR/cluster_verify_triage"
mkdir -p \
    "$cluster_verify_triage/ABRT/c1_rep_pass" \
    "$cluster_verify_triage/ABRT/c1_sib_part" \
    "$cluster_verify_triage/ABRT/c2_only_pass"

ruby - "$cluster_verify_triage" << 'EOF'
require "digest"
require "fileutils"
require "json"
require "rubygems/package"
require "zlib"

triage_dir = ARGV.fetch(0)
write_archive = lambda do |dir, payloads|
  Zlib::GzipWriter.open(File.join(dir, "inputs.tar.gz")) do |gz|
    Gem::Package::TarWriter.new(gz) do |tar|
      payloads.each do |data|
        sha = Digest::SHA256.hexdigest(data)
        tar.add_file_simple(sha, 0o644, data.bytesize) { |io| io.write(data) }
      end
    end
  end
end

# cluster-01: representative (10 occ, PASS) + sibling (5 occ, PARTIAL -> cluster PARTIAL)
# Representative vs sibling names intentionally pick alphabetical order != rep-first order
# so tests verify representative runs first inside the cluster.
c1_rep_dir = File.join(triage_dir, "ABRT/c1_rep_pass")
c1_sib_dir = File.join(triage_dir, "ABRT/c1_sib_part")
c2_dir = File.join(triage_dir, "ABRT/c2_only_pass")

File.binwrite(File.join(c1_rep_dir, "input.min"), "clean_rep")
write_archive.call(c1_rep_dir, ["clean_rep_sib".b])

File.binwrite(File.join(c1_sib_dir, "input.min"), "clean_min")
write_archive.call(c1_sib_dir, ["clean_ok".b, "CRASH_cluster_sib".b])

File.binwrite(File.join(c2_dir, "input.min"), "clean_c2")
write_archive.call(c2_dir, ["clean_c2_arch".b])

edge_functions = {
  "10" => "parse_heredoc",
  "11" => "parse_heredoc",
  "20" => "parse_for"
}
metadata = {
  "schema_version" => 1,
  "corpus" => {
    "available" => true,
    "corpus_count" => 100,
    "edge_df" => { "10" => 0, "11" => 0, "20" => 0 },
    "edge_functions" => edge_functions
  },
  "buckets" => [
    {
      "bucket_id" => "ABRT/c1_rep_pass",
      "reason" => "ABRT",
      "signature" => "c1_rep_pass",
      "reproducible" => true,
      "verify_profile" => "asan_ubsan",
      "occurrences" => { "count" => 10 },
      "input" => { "min_size_bytes" => 9 },
      "symptom" => { "headline" => "Assertion heredoc failed" },
      "frames" => [{ "function" => "parse_heredoc", "scope" => "prism" }],
      "coverage" => { "available" => true, "edges" => { "10" => 1, "11" => 1 } }
    },
    {
      "bucket_id" => "ABRT/c1_sib_part",
      "reason" => "ABRT",
      "signature" => "c1_sib_part",
      "reproducible" => true,
      "verify_profile" => "asan_ubsan",
      "occurrences" => { "count" => 5 },
      "input" => { "min_size_bytes" => 9 },
      "symptom" => { "headline" => "Assertion heredoc failed" },
      "frames" => [{ "function" => "parse_heredoc", "scope" => "prism" }],
      "coverage" => { "available" => true, "edges" => { "10" => 1, "11" => 1 } }
    },
    {
      "bucket_id" => "ABRT/c2_only_pass",
      "reason" => "ABRT",
      "signature" => "c2_only_pass",
      "reproducible" => true,
      "verify_profile" => "asan_ubsan",
      "occurrences" => { "count" => 3 },
      "input" => { "min_size_bytes" => 8 },
      "symptom" => { "headline" => "Assertion parse_for failed" },
      "frames" => [{ "function" => "parse_for", "scope" => "prism" }],
      "coverage" => { "available" => true, "edges" => { "20" => 1 } }
    }
  ]
}
File.write(File.join(triage_dir, "metadata.json"), JSON.pretty_generate(metadata))
EOF

list_out=$(ruby ./test/fuzz/triage/verify.rb --triage-dir "$cluster_verify_triage" --list-clusters)
echo "$list_out" | grep -q "cluster-01" || fail "expected --list-clusters to auto-generate and list cluster-01"
echo "$list_out" | grep -q "cluster-02" || fail "expected --list-clusters to list cluster-02"
[ -f "$cluster_verify_triage/clusters.json" ] || fail "expected auto-generated clusters.json under $cluster_verify_triage"

# Verify stale clusters.json is automatically refreshed when older than metadata.json
ruby - "$cluster_verify_triage" << 'EOF'
require "json"
dir = ARGV.fetch(0)
meta_path = File.join(dir, "metadata.json")
clusters_path = File.join(dir, "clusters.json")
stale_time = File.mtime(meta_path) - 60
File.write(clusters_path, JSON.generate({ "schema_version" => 1, "clusters" => [{ "cluster_id" => "cluster-99", "bucket_count" => 0, "occurrences" => 0, "reasons" => {}, "representative" => {}, "buckets" => [] }] }))
File.utime(stale_time, stale_time, clusters_path)
EOF
refreshed_list=$(ruby ./test/fuzz/triage/verify.rb --triage-dir "$cluster_verify_triage" --list-clusters)
echo "$refreshed_list" | grep -q "cluster-01" || fail "expected stale clusters.json to refresh from metadata.json"
echo "$refreshed_list" | grep -q "cluster-99" && fail "stale cluster-99 should not persist after refresh"

export VERIFY_BUILD_DIR="$WORKDIR/mock_verify_build"
touch "$WORKDIR/mock_verify_build/verify_runner.asan_ubsan"

# Passing cluster (--cluster 2 numeric shorthand) exits 0 and runs only cluster-02
ruby ./test/fuzz/triage/verify.rb \
    --triage-dir "$cluster_verify_triage" \
    --cluster 2 \
    --json "$WORKDIR/verify_c2.json" > "$WORKDIR/verify_c2.out"

# Partial cluster (--cluster cluster-01, member-bucket expansion, --by-cluster sweep)
set +e
ruby ./test/fuzz/triage/verify.rb \
    --triage-dir "$cluster_verify_triage" \
    --cluster cluster-01 \
    --json "$WORKDIR/verify_c1.json" > "$WORKDIR/verify_c1.out"
c1_rc=$?
set -e
[ "$c1_rc" -eq 1 ] || fail "expected --cluster cluster-01 to exit 1 on PARTIAL sibling, got $c1_rc"

set +e
ruby ./test/fuzz/triage/verify.rb \
    --triage-dir "$cluster_verify_triage" \
    --cluster ABRT/c1_sib_part \
    --json "$WORKDIR/verify_member.json" >/dev/null
mem_rc=$?
set -e
[ "$mem_rc" -eq 1 ] || fail "expected member-bucket --cluster lookup to exit 1, got $mem_rc"

set +e
ruby ./test/fuzz/triage/verify.rb \
    --triage-dir "$cluster_verify_triage" \
    --by-cluster \
    --json "$WORKDIR/verify_all_clusters.json" > "$WORKDIR/verify_all_clusters.out"
all_rc=$?
set -e
[ "$all_rc" -eq 1 ] || fail "expected --by-cluster sweep to exit 1, got $all_rc"

if ruby ./test/fuzz/triage/verify.rb --triage-dir "$cluster_verify_triage" --cluster cluster-99 >/dev/null 2>&1; then
    fail "expected unknown --cluster filter to exit non-zero"
fi

ruby - "$WORKDIR" << 'EOF'
require "json"
workdir = ARGV.fetch(0)

c2 = JSON.parse(File.read(File.join(workdir, "verify_c2.json")))
raise "expected 1 cluster/1 PASS for --cluster 2: #{c2["summary"].inspect}" unless c2.dig("summary", "clusters_checked") == 1 && c2.dig("summary", "cluster_pass") == 1 && c2.dig("summary", "buckets_checked") == 1

c1 = JSON.parse(File.read(File.join(workdir, "verify_c1.json")))
raise "expected cluster-01 PARTIAL with 2 buckets: #{c1.inspect}" unless c1.dig("summary", "clusters_checked") == 1 && c1.dig("summary", "cluster_partial") == 1 && c1.dig("summary", "buckets_checked") == 2
raise "expected representative first in cluster-01: #{c1["buckets"].map { |b| b["bucket_id"] }.inspect}" unless c1["buckets"].map { |b| b["bucket_id"] } == %w[ABRT/c1_rep_pass ABRT/c1_sib_part]
raise "expected cluster_representative flags on cluster-01" unless c1["buckets"][0]["cluster_representative"] == true && c1["buckets"][1]["cluster_representative"] == false
raise "expected PARTIAL cluster status on cluster-01" unless c1["clusters"].first["status"] == "PARTIAL"

mem = JSON.parse(File.read(File.join(workdir, "verify_member.json")))
raise "member lookup must expand full cluster-01" unless mem["buckets"].map { |b| b["bucket_id"] } == c1["buckets"].map { |b| b["bucket_id"] }

all = JSON.parse(File.read(File.join(workdir, "verify_all_clusters.json")))
raise "expected 2 clusters (1 PARTIAL, 1 PASS) in --by-cluster sweep: #{all["summary"].inspect}" unless all.dig("summary", "clusters_checked") == 2 && all.dig("summary", "cluster_partial") == 1 && all.dig("summary", "cluster_pass") == 1

all_out = File.read(File.join(workdir, "verify_all_clusters.out"))
raise "expected cluster headers, rollup table, and cluster summary in terminal output:\n#{all_out}" unless all_out.include?("== cluster-01") && all_out.include?("-> cluster-01: PARTIAL") && all_out.include?("Clusters:") && all_out.include?("2 clusters (1 PASS, 1 PARTIAL, 0 FAIL, 0 EMPTY)")
EOF
echo "  cluster.rb cross-reason, single-bug, recovery-damping, fallback, CLI, and verify.rb cluster checks passed"

# Exercise retriage.rb post-fix lifecycle (--dry-run, scoped --cluster PARTIAL split, occurrence preservation, #skip sentinels, and full PASS cleanup)
cat << 'EOF' > "$WORKDIR/mock_retriage_target.c"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int contains_token(const uint8_t *data, size_t size, const char *tok) {
    size_t tlen = strlen(tok);
    if (size < tlen) return 0;
    for (size_t i = 0; i <= size - tlen; i++) {
        if (memcmp(data + i, tok, tlen) == 0) return 1;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (contains_token(data, size, "CRASH_ALPHA")) {
        fprintf(stderr, "INVARIANT[alpha]: kind=one\n");
        abort();
    }
    if (contains_token(data, size, "CRASH_BETA")) {
        fprintf(stderr, "INVARIANT[beta]: kind=two\n");
        abort();
    }
    return 0;
}

#ifdef STANDALONE_MAIN
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(f);
        return 0;
    }
    uint8_t *buf = (uint8_t *) malloc((size_t) sz);
    if (!buf) {
        fclose(f);
        return 0;
    }
    size_t n = fread(buf, 1, (size_t) sz, f);
    fclose(f);
    LLVMFuzzerTestOneInput(buf, n);
    free(buf);
    return 0;
}
#endif
EOF

mkdir -p "$WORKDIR/mock_retriage_build"
clang -O1 -g -std=c99 -fsanitize=address \
    test/fuzz/triage/verify_runner.c "$WORKDIR/mock_retriage_target.c" \
    -o "$WORKDIR/mock_retriage_build/verify_runner.asan_ubsan"
touch "$WORKDIR/mock_retriage_build/verify_runner.asan_ubsan"
clang -O1 -g -std=c99 -fsanitize=address -DSTANDALONE_MAIN \
    "$WORKDIR/mock_retriage_target.c" -o "$WORKDIR/mock_retriage_fuzz"

retriage_dir="$WORKDIR/retriage_work"
mkdir -p \
    "$retriage_dir/.processed" \
    "$retriage_dir/ABRT/old_c1_pass" \
    "$retriage_dir/ABRT/old_c1_part" \
    "$retriage_dir/ABRT/old_c2_keep"

ruby - "$retriage_dir" "$WORKDIR/mock_retriage_fuzz" << 'EOF'
require "digest"
require "json"
require "rubygems/package"
require "zlib"

triage_dir, mock_fuzz = ARGV

write_bucket = lambda do |sig, raw_inputs, meta_extra = {}|
  dir = File.join(triage_dir, "ABRT", sig)
  File.binwrite(File.join(dir, "input.min"), raw_inputs.first[:bytes])
  File.write(File.join(dir, "testcase.c"), "/* old #{sig} */\n")
  Zlib::GzipWriter.open(File.join(dir, "inputs.tar.gz")) do |gz|
    Gem::Package::TarWriter.new(gz) do |tar|
      raw_inputs.each do |item|
        tar.add_file_simple(item[:sha], 0o644, item[:bytes].bytesize) { |io| io.write(item[:bytes]) }
      end
    end
  end
  File.open(File.join(dir, "occurrences.jsonl"), "w") do |f|
    raw_inputs.each_with_index do |item, idx|
      rec = {
        "sha256" => item[:sha],
        "path" => "/orig/afl/fuzz01/crashes/id:#{format('%06d', idx)}",
        "filename" => "id:#{format('%06d', idx)},sig:06",
        "fuzzer" => "afl",
        "worker" => item[:worker] || "fuzz01",
        "queue" => "crashes",
        "size_bytes" => item[:bytes].bytesize,
        "mtime" => "2026-11-01T00:00:00Z"
      }
      f.puts(JSON.generate(rec))
      File.write(File.join(triage_dir, ".processed", item[:sha]), "ABRT/#{sig}\n")
    end
  end
  meta = {
    "schema_version" => 1,
    "bucket_id" => "ABRT/#{sig}",
    "reason" => "ABRT",
    "signature" => sig,
    "reproducible" => true,
    "reproduced_by" => mock_fuzz,
    "verify_profile" => "asan_ubsan",
    "occurrences" => { "count" => raw_inputs.size },
    "input" => { "min_size_bytes" => raw_inputs.first[:bytes].bytesize, "raw_sha256" => raw_inputs.first[:sha] },
    "symptom" => { "headline" => meta_extra[:headline] || "old assert" },
    "frames" => [{ "function" => meta_extra[:frame] || "parse_heredoc", "scope" => "prism" }],
    "coverage" => { "available" => true, "edges" => meta_extra[:edges] || { "10" => 1 } }
  }
  File.write(File.join(dir, "meta.json"), JSON.pretty_generate(meta))
  meta
end

mk = lambda do |bytes, worker = "fuzz01"|
  b = bytes.b
  { bytes: b, sha: Digest::SHA256.hexdigest(b), worker: worker }
end

c1_pass_inputs = [mk.call("\x00\x00\x03\x01cured_bucket_a\n"), mk.call("\x00\x00\x03\x01cured_bucket_b\n")]
c1_part_inputs = [
  mk.call("\x00\x00\x03\x01cured_in_partial\n", "fuzz02"),
  mk.call("\x00\x00\x03\x01padding_prefix CRASH_ALPHA padding_suffix\n", "fuzz03"),
  mk.call("\x00\x00\x03\x01padding_prefix CRASH_BETA padding_suffix\n", "fuzz04")
]
c2_keep_inputs = [mk.call("\x00\x00\x03\x01untouched CRASH_ALPHA\n", "fuzz09")]

File.write(File.join(triage_dir, ".hashes.json"), JSON.generate({
  "c1_pass" => c1_pass_inputs.map { |i| i[:sha] },
  "c1_part_cured" => c1_part_inputs[0][:sha],
  "c1_part_alpha" => c1_part_inputs[1][:sha],
  "c1_part_beta" => c1_part_inputs[2][:sha],
  "c2_keep" => c2_keep_inputs.map { |i| i[:sha] }
}))

m1 = write_bucket.call("old_c1_pass", c1_pass_inputs, edges: { "10" => 1, "11" => 1 }, frame: "parse_heredoc")
m2 = write_bucket.call("old_c1_part", c1_part_inputs, edges: { "10" => 1, "11" => 1 }, frame: "parse_heredoc")
m3 = write_bucket.call("old_c2_keep", c2_keep_inputs, edges: { "20" => 1 }, frame: "parse_for")

metadata = {
  "schema_version" => 1,
  "corpus" => {
    "available" => true,
    "corpus_count" => 100,
    "edge_df" => { "10" => 0, "11" => 0, "20" => 0 },
    "edge_functions" => { "10" => "parse_heredoc", "11" => "parse_heredoc", "20" => "parse_for" }
  },
  "buckets" => [m2, m1, m3]
}
File.write(File.join(triage_dir, "metadata.json"), JSON.pretty_generate(metadata))
EOF

# 1) --dry-run must inspect cluster-01 without deleting/modifying anything on disk
VERIFY_BUILD_DIR="$WORKDIR/mock_retriage_build" TRIAGE_COVERAGE_BIN="" \
    ruby ./test/fuzz/triage/retriage.rb \
    --triage-dir "$retriage_dir" \
    --cluster cluster-01 \
    --no-build \
    --dry-run > "$WORKDIR/retriage_dry.out"

grep -q "1 bucket(s) cured/empty" "$WORKDIR/retriage_dry.out" || fail "expected dry-run plan to identify 1 cured bucket"
grep -q "2 surviving inputs to re-triage" "$WORKDIR/retriage_dry.out" || fail "expected dry-run plan to identify 2 surviving inputs"
[ -d "$retriage_dir/ABRT/old_c1_pass" ] || fail "dry-run must not remove cured bucket"
[ -d "$retriage_dir/ABRT/old_c1_part" ] || fail "dry-run must not remove partial bucket"

# 2) Scoped retriage of cluster-01 removes cured old_c1_pass, splits old_c1_part into 2 fresh buckets, and preserves untouched cluster-02
VERIFY_BUILD_DIR="$WORKDIR/mock_retriage_build" TRIAGE_COVERAGE_BIN="" TRIAGE_MINIMIZE=0 \
    ruby ./test/fuzz/triage/retriage.rb \
    --triage-dir "$retriage_dir" \
    --cluster cluster-01 \
    --no-build > "$WORKDIR/retriage_run.out"

[ ! -e "$retriage_dir/ABRT/old_c1_pass" ] || fail "expected cured old_c1_pass bucket to be removed"
[ ! -e "$retriage_dir/ABRT/old_c1_part" ] || fail "expected stale old_c1_part bucket to be removed"
[ -d "$retriage_dir/ABRT/old_c2_keep" ] || fail "expected unscoped cluster-02 bucket old_c2_keep to remain untouched"

ruby - "$retriage_dir" << 'EOF'
require "json"
triage_dir = ARGV.fetch(0)
hashes = JSON.parse(File.read(File.join(triage_dir, ".hashes.json")))

# Cured hashes must now be marked #skip in .processed/
(hashes["c1_pass"] + [hashes["c1_part_cured"]]).each do |sha|
  sentinel = File.join(triage_dir, ".processed", sha)
  raise "expected #skip sentinel for cured input #{sha}" unless File.file?(sentinel) && File.read(sentinel).strip == "#skip"
end

# Both surviving hashes must be re-triaged into 2 distinct new ABRT/* buckets (1 alpha, 1 beta), keeping original worker names
alpha_bucket = File.read(File.join(triage_dir, ".processed", hashes["c1_part_alpha"])).strip
beta_bucket = File.read(File.join(triage_dir, ".processed", hashes["c1_part_beta"])).strip
raise "expected valid new bucket sentinels, got #{alpha_bucket.inspect} / #{beta_bucket.inspect}" if alpha_bucket.start_with?("#") || beta_bucket.start_with?("#")
raise "expected survivors from different bugs to split into separate buckets" if alpha_bucket == beta_bucket
raise "survivors must not reuse removed old_c1_part" if [alpha_bucket, beta_bucket].include?("ABRT/old_c1_part")

alpha_meta = JSON.parse(File.read(File.join(triage_dir, alpha_bucket, "meta.json")))
beta_meta = JSON.parse(File.read(File.join(triage_dir, beta_bucket, "meta.json")))
raise "expected preserved fuzz03 worker provenance on alpha bucket: #{alpha_meta["occurrences"].inspect}" unless alpha_meta.dig("occurrences", "by_worker", "fuzz03") == 1
raise "expected preserved fuzz04 worker provenance on beta bucket: #{beta_meta["occurrences"].inspect}" unless beta_meta.dig("occurrences", "by_worker", "fuzz04") == 1

idx = JSON.parse(File.read(File.join(triage_dir, "metadata.json")))
raise "expected 3 total buckets (2 new from cluster-01 + 1 kept old_c2_keep), got #{idx.dig("summary", "bucket_count")}" unless idx.dig("summary", "bucket_count") == 3
clusters = JSON.parse(File.read(File.join(triage_dir, "clusters.json")))
raise "expected clusters.json schema_version 1" unless clusters["schema_version"] == 1
EOF

# 3) All-PASS retriage cleans up 100% of cured buckets and prunes empty reason directories
all_pass_retriage="$WORKDIR/retriage_all_pass"
mkdir -p "$all_pass_retriage/.processed" "$all_pass_retriage/ABRT/only_cured"
printf '\x00\x00\x03\x01completely_fixed\n' > "$all_pass_retriage/ABRT/only_cured/input.min"
VERIFY_BUILD_DIR="$WORKDIR/mock_retriage_build" TRIAGE_COVERAGE_BIN="" \
    ruby ./test/fuzz/triage/retriage.rb \
    --triage-dir "$all_pass_retriage" \
    --no-build > "$WORKDIR/retriage_all_pass.out"

[ ! -e "$all_pass_retriage/ABRT" ] || fail "expected empty ABRT/ reason directory to be pruned when all buckets PASS"
ruby - "$all_pass_retriage" << 'EOF'
require "json"
dir = ARGV.fetch(0)
idx = JSON.parse(File.read(File.join(dir, "metadata.json")))
cl = JSON.parse(File.read(File.join(dir, "clusters.json")))
raise "expected 0 buckets remaining" unless idx.dig("summary", "bucket_count") == 0
raise "expected 0 clusters remaining" unless cl.dig("summary", "cluster_count") == 0
EOF
echo "  retriage.rb (--dry-run, scoped cluster survivor split, occurrence provenance, #skip sentinels, and full PASS cleanup) checks passed"

echo "[8/8] Checking external target verification, template regeneration, 2026 API shims, exit 125, --invert/--fail-fast, and bisect.rb..."

# 1) Verify parse.c compiles cleanly under all compatibility macro combinations (-DSLOW and fast modes).
${CC:-clang} -c -O1 -std=c99 -Iinclude -DSLOW \
    -DPRISM_FUZZ_NO_ATTACH_COMMENTS -DPRISM_FUZZ_NO_STACK_BUDGET \
    -DPRISM_FUZZ_NO_ERRORS_FORMAT -DPRISM_FUZZ_NO_STREAM -DPRISM_FUZZ_NO_JSON \
    test/fuzz/harness/parse.c -o "$WORKDIR/parse_compat_slow.o"

# 2) Verify external Prism target copy regenerates missing templates cleanly without touching host templates.
ext_prism_target="$WORKDIR/ext_prism_target"
mkdir -p "$ext_prism_target"
cp -R "$PWD/config.yml" "$PWD/templates" "$PWD/include" "$PWD/src" "$ext_prism_target/"
rm -f "$ext_prism_target/src/node.c" "$ext_prism_target/include/prism/ast.h"
ext_runner="$(VERIFY_BUILD_DIR="" "$PWD/test/fuzz/triage/verify_bucket.sh" --repo-root "$ext_prism_target" --fuzz-root "$PWD" --profile asan_ubsan --build-only)"
[ -x "$ext_runner" ] || fail "expected external verify_runner to build at $ext_runner"
[ -f "$ext_prism_target/src/node.c" ] && [ -f "$ext_prism_target/include/prism/ast.h" ] || fail "expected verify_bucket.sh to regenerate missing templates under $ext_prism_target"
[ -f "$ext_runner.fingerprint" ] || fail "expected build fingerprint at $ext_runner.fingerprint"

# 3) Build a synthetic 7-commit Prism mock git repo covering:
#    - c1: GOOD (all pass, current API)
#    - c2: pre-opaque API (no pm_arena_new -> verify_bucket.sh / verify.rb exits 125)
#    - c3: GOOD after opaque (pass, allows bisect to isolate c4 even after skipping c2)
#    - c4: BAD regression (older 2026 APIs: no stack_budget/attach_comments, pm_string_constant_init, pm_parser_*_each; triggers ABRT)
#    - c5: STILL BAD (current API, crashes on CRASH_TOK_INPUT)
#    - c6: FIRST FIXED (current API, all pass)
#    - c7: LATER FIXED (current API, all pass; catches missing --invert in fix bisect)
bisect_repo="$WORKDIR/bisect_mock_repo"
bisect_triage="$WORKDIR/bisect_triage"
mkdir -p "$bisect_repo/include/prism" "$bisect_repo/src" "$bisect_triage/ABRT/tok_bug" "$bisect_triage/ABRT/tok_other"
# Put tok_bug first (lexicographically or via input) and tok_other second to also verify --fail-fast.
printf '\x80\x80\xff\x01CRASH_TOK_INPUT' > "$bisect_triage/ABRT/tok_bug/input.min"
printf '\x00\x00\x03\x01PASS_INPUT' > "$bisect_triage/ABRT/tok_other/input.min"

git init -q "$bisect_repo"
git -C "$bisect_repo" config user.email "fuzz-test@example.com"
git -C "$bisect_repo" config user.name "Fuzz Test"

cat << 'EOF' > "$bisect_repo/write_commit.rb"
mode, crash_on = ARGV
h = File.join(__dir__, "include")
p = File.join(h, "prism")

if mode == "pre_opaque"
  File.write(File.join(h, "prism.h"), "#include \"prism/arena.h\"\n")
  File.write(File.join(p, "arena.h"), "typedef struct { int x; } pm_arena_t;\n")
  File.write(File.join(p, "options.h"), "")
  File.write(File.join(p, "stringy.h"), "")
  File.write(File.join(p, "parser.h"), "")
  File.write(File.join(p, "diagnostic.h"), "")
  File.write(File.join(__dir__, "src/stub.c"), "int stub_dummy = 0;\n")
  exit 0
end

legacy = (mode == "legacy2026")
File.write(File.join(h, "prism.h"), <<~H)
  #include <stddef.h>
  #include <stdint.h>
  #include <stdbool.h>
  #include "prism/arena.h"
  #include "prism/stringy.h"
  #include "prism/options.h"
  #include "prism/diagnostic.h"
  #include "prism/parser.h"
  #include "prism/source.h"
  #include "prism/stream.h"
H
File.write(File.join(p, "arena.h"), <<~H)
  typedef struct pm_arena_t pm_arena_t;
  pm_arena_t *pm_arena_new(void);
  void pm_arena_free(pm_arena_t *arena);
H
File.write(File.join(p, "stringy.h"), <<~H)
  typedef struct { const uint8_t *source; size_t length; } pm_string_t;
  #{legacy ? "void pm_string_constant_init(pm_string_t *s, const char *src, size_t len);" : "void pm_string_init(pm_string_t *s, const uint8_t *src, size_t len);"}
H
opts_extra = legacy ? "" : <<~H
  void pm_options_attach_comments_set(pm_options_t *o, bool v);
  void pm_options_stack_budget_set(pm_options_t *o, size_t b);
H
File.write(File.join(p, "options.h"), <<~H)
  typedef struct pm_options_t pm_options_t;
  typedef struct pm_options_scope_t pm_options_scope_t;
  typedef void (*pm_options_shebang_callback_t)(pm_options_t *, const uint8_t *, size_t, void *);
  #define PM_OPTIONS_COMMAND_LINE_X 0x20
  #define PM_OPTIONS_SCOPE_FORWARDING_NONE 0x0
  pm_options_t *pm_options_new(void);
  void pm_options_free(pm_options_t *o);
  void pm_options_line_set(pm_options_t *o, int32_t l);
  void pm_options_command_line_set(pm_options_t *o, uint8_t c);
  void pm_options_main_script_set(pm_options_t *o, bool m);
  void pm_options_freeze_set(pm_options_t *o, bool f);
  void pm_options_partial_script_set(pm_options_t *o, bool p);
  void pm_options_encoding_locked_set(pm_options_t *o, bool e);
  bool pm_options_version_set(pm_options_t *o, const char *v, size_t l);
  void pm_options_frozen_string_literal_set(pm_options_t *o, bool f);
  void pm_options_encoding_set(pm_options_t *o, const char *e);
  void pm_options_filepath_set(pm_options_t *o, const char *f);
  void pm_options_shebang_callback_set(pm_options_t *o, pm_options_shebang_callback_t cb, void *d);
  bool pm_options_scopes_init(pm_options_t *o, size_t c);
  pm_options_scope_t *pm_options_scope_mut(pm_options_t *o, size_t i);
  void pm_options_scope_init(pm_options_scope_t *s, size_t c);
  void pm_options_scope_forwarding_set(pm_options_scope_t *s, uint8_t f);
  pm_string_t *pm_options_scope_local_mut(pm_options_scope_t *s, size_t i);
  #{opts_extra}
H
File.write(File.join(p, "diagnostic.h"), <<~H)
  typedef struct { uint32_t start; uint32_t length; } pm_location_t;
  typedef struct pm_diagnostic_t pm_diagnostic_t;
  typedef struct pm_comment_t pm_comment_t;
  typedef struct pm_magic_comment_t pm_magic_comment_t;
  #define PM_COMMENT_EMBDOC 1
  pm_location_t pm_diagnostic_location(const pm_diagnostic_t *d);
  const char *pm_diagnostic_type(const pm_diagnostic_t *d);
  unsigned pm_diagnostic_error_level(const pm_diagnostic_t *d);
  unsigned pm_diagnostic_warning_level(const pm_diagnostic_t *d);
  pm_location_t pm_comment_location(const pm_comment_t *c);
  int pm_comment_type(const pm_comment_t *c);
  pm_location_t pm_magic_comment_key(const pm_magic_comment_t *mc);
  pm_location_t pm_magic_comment_value(const pm_magic_comment_t *mc);
  const pm_diagnostic_t *pm_diagnostic_next(const pm_diagnostic_t *d);
  const pm_comment_t *pm_comment_next(const pm_comment_t *c);
  const pm_magic_comment_t *pm_magic_comment_next(const pm_magic_comment_t *mc);
H
iter_decls = if legacy
  <<~H
    typedef void (*pm_comment_callback_t)(const pm_comment_t *, void *);
    typedef void (*pm_diagnostic_callback_t)(const pm_diagnostic_t *, void *);
    typedef void (*pm_magic_comment_callback_t)(const pm_magic_comment_t *, void *);
    void pm_parser_errors_each(const pm_parser_t *, pm_diagnostic_callback_t, void *);
    void pm_parser_warnings_each(const pm_parser_t *, pm_diagnostic_callback_t, void *);
    void pm_parser_comments_each(const pm_parser_t *, pm_comment_callback_t, void *);
    void pm_parser_magic_comments_each(const pm_parser_t *, pm_magic_comment_callback_t, void *);
  H
else
  <<~H
    const pm_diagnostic_t *pm_parser_errors_first(const pm_parser_t *);
    const pm_diagnostic_t *pm_parser_warnings_first(const pm_parser_t *);
    const pm_comment_t *pm_parser_comments_first(const pm_parser_t *);
    const pm_magic_comment_t *pm_parser_magic_comments_first(const pm_parser_t *);
  H
end
visit_decls = if legacy
  <<~H
    void pm_visit_node(const pm_node_t *n, bool (*cb)(const pm_node_t *, void *), void *d);
    void pm_visit_child_nodes(const pm_node_t *n, bool (*cb)(const pm_node_t *, void *), void *d);
  H
else
  <<~H
    typedef enum { PM_VISIT_DESCEND = 0, PM_VISIT_SKIP = 1 } pm_visit_result_t;
    void pm_visit_node(const pm_node_t *n, pm_visit_result_t (*cb)(const pm_node_t *, void *), void *d);
    void pm_visit_child_nodes(const pm_node_t *n, pm_visit_result_t (*cb)(const pm_node_t *, void *), void *d);
  H
end
File.write(File.join(p, "parser.h"), <<~H)
  typedef uint16_t pm_node_type_t;
  typedef struct { pm_node_type_t type; pm_location_t location; } pm_node_t;
  typedef struct { uint32_t start; uint32_t length; } pm_string_loc_dummy;
  typedef struct { pm_node_t base; pm_location_t opening_loc; pm_location_t closing_loc; } pm_string_node_t;
  typedef pm_string_node_t pm_interpolated_string_node_t;
  typedef pm_string_node_t pm_x_string_node_t;
  typedef pm_string_node_t pm_interpolated_x_string_node_t;
  typedef struct { pm_node_t base; pm_location_t opening_loc; } pm_array_node_t;
  enum { PM_STRING_NODE = 1, PM_INTERPOLATED_STRING_NODE, PM_X_STRING_NODE, PM_INTERPOLATED_X_STRING_NODE, PM_SYMBOL_NODE, PM_INTERPOLATED_SYMBOL_NODE, PM_REGULAR_EXPRESSION_NODE, PM_INTERPOLATED_REGULAR_EXPRESSION_NODE, PM_MATCH_LAST_LINE_NODE, PM_INTERPOLATED_MATCH_LAST_LINE_NODE, PM_ARRAY_NODE };
  #define PM_NODE_TYPE(n) ((n)->type)
  typedef struct { size_t size; size_t capacity; uint32_t *offsets; } pm_line_offset_list_t;
  typedef struct pm_parser_t pm_parser_t;
  pm_parser_t *pm_parser_new(pm_arena_t *a, const uint8_t *s, size_t n, const pm_options_t *o);
  void pm_parser_free(pm_parser_t *p);
  pm_node_t *pm_parse(pm_parser_t *p);
  const pm_line_offset_list_t *pm_parser_line_offsets(const pm_parser_t *p);
  const pm_location_t *pm_parser_data_loc(const pm_parser_t *p);
  #{visit_decls}
  const char *pm_node_type(pm_node_type_t t);
  #{iter_decls}
H
File.write(File.join(p, "source.h"), "typedef struct pm_source_t pm_source_t; typedef char *(pm_source_stream_fgets_t)(char *, int, void *); typedef int (pm_source_stream_feof_t)(void *); pm_source_t *pm_source_stream_new(void *, pm_source_stream_fgets_t *, pm_source_stream_feof_t *); size_t pm_source_length(const pm_source_t *); void pm_source_free(pm_source_t *);\n")
File.write(File.join(p, "stream.h"), "pm_node_t *pm_parse_stream(pm_parser_t **p, pm_arena_t *a, pm_source_t *s, const pm_options_t *o);\n")

crash_tokens = crash_on == "NONE" ? [] : crash_on.split(",")
crash_stmt = crash_tokens.map do |tok|
  <<~C
    for (size_t i = 0; i + #{tok.bytesize} <= len; i++) {
      if (memcmp(src + i, "#{tok}", #{tok.bytesize}) == 0) abort();
    }
  C
end.join("\n")

File.write(File.join(__dir__, "src/stub.c"), <<~C)
  #include "prism.h"
  #include <stdlib.h>
  #include <string.h>
  struct pm_arena_t { int unused; };
  struct pm_options_scope_t { pm_string_t locals[4]; };
  struct pm_options_t { pm_options_scope_t scopes[4]; };
  struct pm_diagnostic_t { int unused; };
  struct pm_comment_t { int unused; };
  struct pm_magic_comment_t { int unused; };
  struct pm_source_t { size_t len; const uint8_t *src; };
  struct pm_parser_t { const uint8_t *src; size_t len; uint32_t offs[1]; pm_line_offset_list_t lo; pm_location_t data_loc; pm_node_t root; };
  pm_arena_t *pm_arena_new(void) { return calloc(1, sizeof(pm_arena_t)); }
  void pm_arena_free(pm_arena_t *a) { free(a); }
  pm_options_t *pm_options_new(void) { return calloc(1, sizeof(pm_options_t)); }
  void pm_options_free(pm_options_t *o) { free(o); }
  void pm_options_line_set(pm_options_t *o, int32_t l) { (void)o; (void)l; }
  void pm_options_command_line_set(pm_options_t *o, uint8_t c) { (void)o; (void)c; }
  void pm_options_main_script_set(pm_options_t *o, bool m) { (void)o; (void)m; }
  void pm_options_freeze_set(pm_options_t *o, bool f) { (void)o; (void)f; }
  void pm_options_partial_script_set(pm_options_t *o, bool p) { (void)o; (void)p; }
  void pm_options_encoding_locked_set(pm_options_t *o, bool e) { (void)o; (void)e; }
  bool pm_options_version_set(pm_options_t *o, const char *v, size_t l) { (void)o; (void)v; (void)l; return true; }
  void pm_options_frozen_string_literal_set(pm_options_t *o, bool f) { (void)o; (void)f; }
  void pm_options_encoding_set(pm_options_t *o, const char *e) { (void)o; (void)e; }
  void pm_options_filepath_set(pm_options_t *o, const char *f) { (void)o; (void)f; }
  void pm_options_shebang_callback_set(pm_options_t *o, pm_options_shebang_callback_t cb, void *d) { (void)o; (void)cb; (void)d; }
  bool pm_options_scopes_init(pm_options_t *o, size_t c) { (void)o; return c <= 4; }
  pm_options_scope_t *pm_options_scope_mut(pm_options_t *o, size_t i) { return &o->scopes[i]; }
  void pm_options_scope_init(pm_options_scope_t *s, size_t c) { (void)s; (void)c; }
  void pm_options_scope_forwarding_set(pm_options_scope_t *s, uint8_t f) { (void)s; (void)f; }
  pm_string_t *pm_options_scope_local_mut(pm_options_scope_t *s, size_t i) { return &s->locals[i]; }
  void pm_string_init(pm_string_t *s, const uint8_t *src, size_t len) { s->source = src; s->length = len; }
  void pm_string_constant_init(pm_string_t *s, const char *src, size_t len) { s->source = (const uint8_t *)src; s->length = len; }
  void pm_options_attach_comments_set(pm_options_t *o, bool v) { (void)o; (void)v; }
  void pm_options_stack_budget_set(pm_options_t *o, size_t b) { (void)o; (void)b; }
  pm_parser_t *pm_parser_new(pm_arena_t *a, const uint8_t *s, size_t n, const pm_options_t *o) {
    (void)a; (void)o;
    pm_parser_t *p = calloc(1, sizeof(pm_parser_t));
    p->src = s; p->len = n; p->offs[0] = 0; p->lo.size = 1; p->lo.capacity = 1; p->lo.offsets = p->offs;
    p->root.type = 0; p->root.location.start = 0; p->root.location.length = (uint32_t)n;
    return p;
  }
  void pm_parser_free(pm_parser_t *p) { free(p); }
  pm_node_t *pm_parse(pm_parser_t *p) {
    const uint8_t *src = p->src; size_t len = p->len;
    #{crash_stmt}
    return &p->root;
  }
  const pm_line_offset_list_t *pm_parser_line_offsets(const pm_parser_t *p) { return &p->lo; }
  const pm_location_t *pm_parser_data_loc(const pm_parser_t *p) { return &p->data_loc; }
  pm_source_t *pm_source_stream_new(void *st, pm_source_stream_fgets_t *fg, pm_source_stream_feof_t *fe) { (void)st; (void)fg; (void)fe; return calloc(1, sizeof(pm_source_t)); }
  pm_node_t *pm_parse_stream(pm_parser_t **p, pm_arena_t *a, pm_source_t *s, const pm_options_t *o) { (void)s; *p = pm_parser_new(a, (const uint8_t *)"", 0, o); return pm_parse(*p); }
  size_t pm_source_length(const pm_source_t *s) { return s->len; }
  void pm_source_free(pm_source_t *s) { free(s); }
  void pm_visit_node(const pm_node_t *n, #{legacy ? "bool" : "pm_visit_result_t"} (*cb)(const pm_node_t *, void *), void *d) { if (n) cb(n, d); }
  void pm_visit_child_nodes(const pm_node_t *n, #{legacy ? "bool" : "pm_visit_result_t"} (*cb)(const pm_node_t *, void *), void *d) { (void)n; (void)cb; (void)d; }
  const char *pm_node_type(pm_node_type_t t) { (void)t; return "node"; }
  pm_location_t pm_diagnostic_location(const pm_diagnostic_t *d) { (void)d; return (pm_location_t){0, 0}; }
  const char *pm_diagnostic_type(const pm_diagnostic_t *d) { (void)d; return "err"; }
  unsigned pm_diagnostic_error_level(const pm_diagnostic_t *d) { (void)d; return 0; }
  unsigned pm_diagnostic_warning_level(const pm_diagnostic_t *d) { (void)d; return 0; }
  pm_location_t pm_comment_location(const pm_comment_t *c) { (void)c; return (pm_location_t){0, 0}; }
  int pm_comment_type(const pm_comment_t *c) { (void)c; return 0; }
  pm_location_t pm_magic_comment_key(const pm_magic_comment_t *mc) { (void)mc; return (pm_location_t){0, 0}; }
  pm_location_t pm_magic_comment_value(const pm_magic_comment_t *mc) { (void)mc; return (pm_location_t){0, 0}; }
  const pm_diagnostic_t *pm_diagnostic_next(const pm_diagnostic_t *d) { (void)d; return NULL; }
  const pm_comment_t *pm_comment_next(const pm_comment_t *c) { (void)c; return NULL; }
  const pm_magic_comment_t *pm_magic_comment_next(const pm_magic_comment_t *mc) { (void)mc; return NULL; }
  const pm_diagnostic_t *pm_parser_errors_first(const pm_parser_t *p) { (void)p; return NULL; }
  const pm_diagnostic_t *pm_parser_warnings_first(const pm_parser_t *p) { (void)p; return NULL; }
  const pm_comment_t *pm_parser_comments_first(const pm_parser_t *p) { (void)p; return NULL; }
  const pm_magic_comment_t *pm_parser_magic_comments_first(const pm_parser_t *p) { (void)p; return NULL; }
  void pm_parser_errors_each(const pm_parser_t *p, void (*cb)(const pm_diagnostic_t *, void *), void *d) { (void)p; (void)cb; (void)d; }
  void pm_parser_warnings_each(const pm_parser_t *p, void (*cb)(const pm_diagnostic_t *, void *), void *d) { (void)p; (void)cb; (void)d; }
  void pm_parser_comments_each(const pm_parser_t *p, void (*cb)(const pm_comment_t *, void *), void *d) { (void)p; (void)cb; (void)d; }
  void pm_parser_magic_comments_each(const pm_parser_t *p, void (*cb)(const pm_magic_comment_t *, void *), void *d) { (void)p; (void)cb; (void)d; }
C
EOF

make_commit() {
  local mode="$1" crash_on="$2" msg="$3"
  ruby "$bisect_repo/write_commit.rb" "$mode" "$crash_on"
  git -C "$bisect_repo" add include src
  git -C "$bisect_repo" commit -q --allow-empty -m "$msg"
}

make_commit current NONE "c1_good"
c1_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit pre_opaque NONE "c2_pre_opaque"
c2_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit current NONE "c3_good_after_opaque"
c3_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit legacy2026 CRASH_TOK_INPUT "c4_bad_legacy2026"
c4_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit current CRASH_TOK_INPUT "c5_still_bad"
c5_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit current NONE "c6_first_fixed"
c6_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit current NONE "c7_later_fixed"
c7_sha="$(git -C "$bisect_repo" rev-parse HEAD)"

# Check pre-opaque target returns exit 125 from verify.rb --target
git -C "$bisect_repo" checkout -q "$c2_sha"
set +e
VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/verify.rb --triage-dir "$bisect_triage" --target "$bisect_repo" --bisect --quiet >"$WORKDIR/pre_opaque.out" 2>"$WORKDIR/pre_opaque.err"
pre_rc=$?
set -e
[ "$pre_rc" -eq 125 ] || fail "expected exit 125 for pre-opaque commit, got $pre_rc"

# Check legacy2026 target compiles with probed shims, --invert returns 0 on FAIL, --fail-fast stops after tok_bug, and missing cluster returns 128 in --bisect mode.
git -C "$bisect_repo" checkout -q "$c4_sha"
VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/verify.rb \
    --triage-dir "$bisect_triage" --target "$bisect_repo" --invert --fail-fast \
    --json "$WORKDIR/bisect_inv.json" >/dev/null
ruby - "$WORKDIR/bisect_inv.json" << 'EOF'
require "json"
rep = JSON.parse(File.read(ARGV.fetch(0)))
raise "expected fail-fast to stop after 1 bucket, got #{rep.dig('summary', 'buckets_checked')}" unless rep.dig("summary", "buckets_checked") == 1
raise "expected fail == 1" unless rep.dig("summary", "fail") == 1
EOF

set +e
VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/verify.rb --triage-dir "$WORKDIR/no_such_dir" --target "$bisect_repo" --bisect --quiet >/dev/null 2>&1
bad_cfg_rc=$?
set -e
[ "$bad_cfg_rc" -eq 128 ] || fail "expected exit 128 for missing triage dir under --bisect, got $bad_cfg_rc"

git -C "$bisect_repo" checkout -q "$c7_sha"

# Bisect regression: c1 (good) .. c5 (bad), skipping c2 (125), identifying c4_bad_legacy2026!
if ! VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/bisect.rb \
    --local --git-repo "$bisect_repo" --triage-dir "$bisect_triage" \
    --good "$c1_sha" --bad "$c5_sha" --bucket ABRT/tok_bug \
    --worktree "$WORKDIR/bisect_wt_reg" > "$WORKDIR/bisect_reg.out" 2>&1; then
  fail "regression bisect failed: $(cat "$WORKDIR/bisect_reg.out")"
fi
grep -q "^${c4_sha} is the first bad commit$" "$WORKDIR/bisect_reg.out" || fail "expected regression bisect to identify $c4_sha, output: $(cat "$WORKDIR/bisect_reg.out")"
[ ! -e "$WORKDIR/bisect_wt_reg" ] || fail "expected temporary bisect worktree to be cleaned up"

# Bisect fix: c4 (broken) .. c7 (fixed), identifying c6_first_fixed (not c7_later_fixed)!
if ! VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/bisect.rb \
    --local --git-repo "$bisect_repo" --triage-dir "$bisect_triage" \
    --broken "$c4_sha" --fixed "$c7_sha" --bucket ABRT/tok_bug \
    --worktree "$WORKDIR/bisect_wt_fix" > "$WORKDIR/bisect_fix.out" 2>&1; then
  fail "fix bisect failed: $(cat "$WORKDIR/bisect_fix.out")"
fi
grep -q "^${c6_sha} is the first fixed commit$" "$WORKDIR/bisect_fix.out" || fail "expected fix bisect to identify $c6_sha, output: $(cat "$WORKDIR/bisect_fix.out")"

# Multi-bucket cluster attribution checks (regression split, fix split, PARTIAL archived failure, and --input-min-only/--skip-min)
bisect_cluster_triage="$WORKDIR/bisect_cluster_triage"
mkdir -p "$bisect_cluster_triage/ABRT/tok_bug" "$bisect_cluster_triage/ABRT/tok2_bug" "$WORKDIR/bisect_arch_src" "$WORKDIR/bisect_bc1_src"
printf '\x80\x80\xff\x01CRASH_TOK_INPUT' > "$bisect_cluster_triage/ABRT/tok_bug/input.min"
printf '\x80\x80\xff\x01CRASH_BC1_INPUT' > "$WORKDIR/bisect_bc1_src/bc1"
tar -czf "$bisect_cluster_triage/ABRT/tok_bug/inputs.tar.gz" -C "$WORKDIR/bisect_bc1_src" bc1
printf '\x80\x80\xff\x01CRASH_TOK2_INPUT' > "$bisect_cluster_triage/ABRT/tok2_bug/input.min"
printf '\x80\x80\xff\x01CRASH_ARCH_INPUT' > "$WORKDIR/bisect_arch_src/arch_extra"
tar -czf "$bisect_cluster_triage/ABRT/tok2_bug/inputs.tar.gz" -C "$WORKDIR/bisect_arch_src" arch_extra

ruby - "$bisect_cluster_triage" << 'EOF'
require "json"
dir = ARGV.fetch(0)
meta = {
  "schema_version" => 1,
  "buckets" => [
    { "bucket_id" => "ABRT/tok_bug", "reason" => "ABRT", "signature" => "tok_bug", "reproducible" => true, "occurrences" => { "count" => 5 } },
    { "bucket_id" => "ABRT/tok2_bug", "reason" => "ABRT", "signature" => "tok2_bug", "reproducible" => true, "occurrences" => { "count" => 3 } }
  ]
}
clusters = {
  "schema_version" => 1,
  "clusters" => [
    {
      "cluster_id" => "cluster-01",
      "bucket_count" => 2,
      "occurrences" => 8,
      "reasons" => { "ABRT" => 8 },
      "representative" => { "bucket_id" => "ABRT/tok_bug" },
      "buckets" => [{ "bucket_id" => "ABRT/tok_bug" }, { "bucket_id" => "ABRT/tok2_bug" }]
    }
  ]
}
File.write(File.join(dir, "metadata.json"), JSON.pretty_generate(meta))
File.write(File.join(dir, "clusters.json"), JSON.pretty_generate(clusters))
EOF

make_commit current CRASH_TOK_INPUT "c8_cluster_part1"
c8_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit current CRASH_TOK_INPUT,CRASH_TOK2_INPUT,CRASH_ARCH_INPUT "c9_cluster_both"
c9_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit current CRASH_TOK2_INPUT "c10_cluster_fix1"
c10_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit current NONE "c11_cluster_fix_all"
c11_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit current CRASH_ARCH_INPUT "c12_cluster_arch_only"
c12_sha="$(git -C "$bisect_repo" rev-parse HEAD)"

git -C "$bisect_repo" checkout -q "$c12_sha"

if ! VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/bisect.rb \
    --local --git-repo "$bisect_repo" --triage-dir "$bisect_cluster_triage" \
    --good "$c7_sha" --bad "$c9_sha" --cluster cluster-01 \
    --worktree "$WORKDIR/bisect_wt_cluster_reg" > "$WORKDIR/bisect_cluster_reg.out" 2>&1; then
  fail "split cluster regression bisect failed: $(cat "$WORKDIR/bisect_cluster_reg.out")"
fi
grep -q "^${c8_sha} is the first bad commit$" "$WORKDIR/bisect_cluster_reg.out" || fail "expected c8, got: $(cat "$WORKDIR/bisect_cluster_reg.out")"
grep -q "Warning: only 1/2 selected buckets transitioned at ${c8_sha:0:12}" "$WORKDIR/bisect_cluster_reg.out" || fail "expected split-cluster warning in regression output: $(cat "$WORKDIR/bisect_cluster_reg.out")"
grep -q "ABRT/tok_bug: FAIL (input.min:" "$WORKDIR/bisect_cluster_reg.out" || fail "expected tok_bug FAIL attribution: $(cat "$WORKDIR/bisect_cluster_reg.out")"
grep -q "ABRT/tok2_bug: PASS (at ${c9_sha:0:12} BAD: FAIL (input.min + 1 archived:" "$WORKDIR/bisect_cluster_reg.out" || fail "expected tok2_bug PASS + BAD FAIL attribution: $(cat "$WORKDIR/bisect_cluster_reg.out")"
[ ! -e "$WORKDIR/bisect_wt_cluster_reg" ] || fail "expected temporary cluster reg worktree to be cleaned up"

if ! VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/bisect.rb \
    --local --git-repo "$bisect_repo" --triage-dir "$bisect_cluster_triage" \
    --broken "$c9_sha" --fixed "$c11_sha" --cluster cluster-01 \
    --worktree "$WORKDIR/bisect_wt_cluster_fix" > "$WORKDIR/bisect_cluster_fix.out" 2>&1; then
  fail "split cluster fix bisect failed: $(cat "$WORKDIR/bisect_cluster_fix.out")"
fi
grep -q "^${c11_sha} is the first fixed commit$" "$WORKDIR/bisect_cluster_fix.out" || fail "expected c11, got: $(cat "$WORKDIR/bisect_cluster_fix.out")"
grep -q "Warning: ${c11_sha:0:12} fixed only 1/2 selected buckets (1 already PASSED at ${c10_sha:0:12})" "$WORKDIR/bisect_cluster_fix.out" || fail "expected split-cluster fix warning: $(cat "$WORKDIR/bisect_cluster_fix.out")"
grep -q "ABRT/tok2_bug: FAIL (input.min:" "$WORKDIR/bisect_cluster_fix.out" || fail "expected tok2_bug fixed-here attribution: $(cat "$WORKDIR/bisect_cluster_fix.out")"
grep -q "ABRT/tok_bug: PASS (failed at ${c9_sha:0:12} BROKEN: FAIL (input.min" "$WORKDIR/bisect_cluster_fix.out" || fail "expected tok_bug already-PASS + BROKEN detail: $(cat "$WORKDIR/bisect_cluster_fix.out")"
[ ! -e "$WORKDIR/bisect_wt_cluster_fix" ] || fail "expected temporary cluster fix worktree to be cleaned up"

if ! VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/bisect.rb \
    --local --git-repo "$bisect_repo" --triage-dir "$bisect_cluster_triage" \
    --good "$c11_sha" --bad "$c12_sha" --cluster cluster-01 \
    --worktree "$WORKDIR/bisect_wt_cluster_part" > "$WORKDIR/bisect_cluster_part.out" 2>&1; then
  fail "PARTIAL cluster regression bisect failed: $(cat "$WORKDIR/bisect_cluster_part.out")"
fi
grep -q "^${c12_sha} is the first bad commit$" "$WORKDIR/bisect_cluster_part.out" || fail "expected c12, got: $(cat "$WORKDIR/bisect_cluster_part.out")"
grep -q "ABRT/tok2_bug: PARTIAL (input.min PASSED; 1 archived failed" "$WORKDIR/bisect_cluster_part.out" || fail "expected PARTIAL attribution detail: $(cat "$WORKDIR/bisect_cluster_part.out")"
[ ! -e "$WORKDIR/bisect_wt_cluster_part" ] || fail "expected temporary cluster partial worktree to be cleaned up"

# Check verify.rb --input-min-only, --skip-min (must report FAIL, not PARTIAL, and min_passed=nil), and mutual exclusion on c12.
git -C "$bisect_repo" checkout -q "$c12_sha"
VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/verify.rb \
    --triage-dir "$bisect_cluster_triage" --target "$bisect_repo" --cluster cluster-01 \
    --input-min-only --json "$WORKDIR/verify_min_only.json" >/dev/null
set +e
VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/verify.rb \
    --triage-dir "$bisect_cluster_triage" --target "$bisect_repo" --bucket ABRT/tok2_bug \
    --skip-min --json "$WORKDIR/verify_skip_min.json" >/dev/null
skip_rc=$?
VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/verify.rb \
    --triage-dir "$bisect_cluster_triage" --target "$bisect_repo" --input-min-only --skip-min >/dev/null 2>&1
both_rc=$?
set -e
[ "$skip_rc" -eq 1 ] || fail "expected --skip-min on c12 tok2_bug to exit 1, got $skip_rc"
[ "$both_rc" -eq 2 ] || fail "expected --input-min-only --skip-min to exit 2, got $both_rc"
ruby - "$WORKDIR/verify_min_only.json" "$WORKDIR/verify_skip_min.json" << 'EOF'
require "json"
mo = JSON.parse(File.read(ARGV.fetch(0)))
raise "expected both buckets PASS under --input-min-only: #{mo['summary']}" unless mo.dig("summary", "pass") == 2 && mo.dig("summary", "inputs_checked") == 2
sm = JSON.parse(File.read(ARGV.fetch(1)))
b = sm.fetch("buckets").first
raise "expected FAIL (not PARTIAL) and min_passed=nil under --skip-min: #{b.inspect}" unless b["status"] == "FAIL" && b["min_passed"].nil? && b["failed"] == 1
EOF

# Model X -> Y -> Z with contaminated GOOD baseline (c13 has pre-existing archive crash on tok2_bug,
# c14 introduces B_1.min, c15 introduces BC_1 archive inside tok_bug, c16 leaves B_2.min passing).
make_commit current CRASH_ARCH_INPUT "c13_g_arch_noise"
c13_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit current CRASH_ARCH_INPUT,CRASH_TOK_INPUT "c14_x_b1_min"
c14_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit current CRASH_ARCH_INPUT,CRASH_TOK_INPUT,CRASH_BC1_INPUT "c15_y_bc1_arch"
c15_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
make_commit current CRASH_ARCH_INPUT,CRASH_TOK_INPUT,CRASH_BC1_INPUT "c16_z_b2_min_ok"
c16_sha="$(git -C "$bisect_repo" rev-parse HEAD)"
git -C "$bisect_repo" checkout -q "$c16_sha"

if ! VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/bisect.rb \
    --local --git-repo "$bisect_repo" --triage-dir "$bisect_cluster_triage" \
    --good "$c13_sha" --bad "$c16_sha" --cluster cluster-01 --input-min-only \
    --worktree "$WORKDIR/bisect_wt_xyz_min" > "$WORKDIR/bisect_xyz_min.out" 2>&1; then
  fail "--input-min-only X->Y->Z bisect failed: $(cat "$WORKDIR/bisect_xyz_min.out")"
fi
grep -q "^${c14_sha} is the first bad commit$" "$WORKDIR/bisect_xyz_min.out" || fail "expected c14 (X), got: $(cat "$WORKDIR/bisect_xyz_min.out")"
grep -q "^== Cluster attribution (2 buckets at ${c14_sha:0:12}; input.min only) ==$" "$WORKDIR/bisect_xyz_min.out" || fail "expected input.min-only attribution header: $(cat "$WORKDIR/bisect_xyz_min.out")"
grep -q "ABRT/tok2_bug: PASS (at ${c16_sha:0:12} BAD: PARTIAL (input.min PASSED; 1 archived failed — arch_extra" "$WORKDIR/bisect_xyz_min.out" || fail "expected tok2_bug BAD PARTIAL attribution: $(cat "$WORKDIR/bisect_xyz_min.out")"
[ ! -e "$WORKDIR/bisect_wt_xyz_min" ] || fail "expected temporary xyz_min worktree to be cleaned up"

if ! VERIFY_BUILD_DIR="" ruby ./test/fuzz/triage/bisect.rb \
    --local --git-repo "$bisect_repo" --triage-dir "$bisect_cluster_triage" \
    --good "$c14_sha" --bad "$c16_sha" --bucket ABRT/tok_bug --skip-min \
    --worktree "$WORKDIR/bisect_wt_xyz_skip" > "$WORKDIR/bisect_xyz_skip.out" 2>&1; then
  fail "--skip-min follow-up bisect failed: $(cat "$WORKDIR/bisect_xyz_skip.out")"
fi
grep -q "^${c15_sha} is the first bad commit$" "$WORKDIR/bisect_xyz_skip.out" || fail "expected c15 (Y) under --skip-min, got: $(cat "$WORKDIR/bisect_xyz_skip.out")"
[ ! -e "$WORKDIR/bisect_wt_xyz_skip" ] || fail "expected temporary xyz_skip worktree to be cleaned up"

echo "  external target verification, template regen, 2026 API shims, exit 125/128, --invert/--fail-fast, and bisect.rb checks passed"

echo "PASS: Fuzz crash triage and minimization suite verified."
