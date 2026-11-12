#!/usr/bin/env bash
# Verifies the fuzz crash triage and minimization pipeline:
# 1. signature.sh normalization (UBSAN operands, LSan counts, ASAN sizes,
#    binary prefixes) and SIGPIPE safety under set -o pipefail.
# 2. halfempty.sh + halfempty_compare.sh minimization, strict 4-byte options
#    header preservation, crash-signature drift rejection, empty-stderr SIGSEGV
#    safety, non-crashing input rejection, and 0-byte Ruby body handling.
# 3. triage.rb standalone C reproducer generation (#define _GNU_SOURCE ordering,
#    explicit input_size for non-empty and 4-byte inputs) compiled under strict
#    C99 (-Wall -Wextra -Wstrict-prototypes -Werror) with ASAN+UBSAN.
# 4. Concurrent triage.rb deduplication, in-flight minimization coalescing,
#    transient hang / sig:09 filtering, and atomic staging + .processed sentinels.

set -euo pipefail

WORKDIR="$(mktemp -d /tmp/test-fuzz-triage.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "[1/4] Checking signature.sh normalization and SIGPIPE safety..."
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

echo "[2/4] Checking halfempty.sh minimization, header preservation, and drift protection..."
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

echo "[3/4] Checking triage.rb standalone C reproducer generation and strict C99 build..."
ruby - "$WORKDIR" << 'EOF'
workdir = ARGV.fetch(0)
code = File.read("test/fuzz/triage/triage.rb")
defs = code.split(/^harness_code = /).first
eval(defs)
harness_code = File.read("test/fuzz/harness/parse.c")

nonempty_in = File.join(workdir, "repro_nonempty.bin")
empty_in = File.join(workdir, "repro_empty.bin")
enc_oob_in = File.join(workdir, "repro_enc_oob.bin")
File.binwrite(nonempty_in, "\x2a\x05\x1b\xff1 + 2\n".b)
File.binwrite(empty_in, "\x00\x00\x03\x01".b)
File.binwrite(enc_oob_in, "\xa3\xc5\x28\x31/\\M".b)

tc_nonempty_c = c_program(nonempty_in, harness_code, "test */ nonempty")
tc_empty_c = c_program(empty_in, harness_code, "test empty")
tc_enc_oob_c = c_program(enc_oob_in, harness_code, "test enc oob")

expected_nonempty_url = "https://stevenjohnstone.github.io/prism-loupe/?code=MSArIDIK&ruby_ver=4.1&line=-1&cmd=al&partial=1&enc_lock=1&scopes=a%2Cfoo%2C~MSArIA%3Bp%3Ab%2Cit"
raise "unexpected Loupe URL in tc_nonempty.c:\n#{tc_nonempty_c}" unless tc_nonempty_c.include?("Prism Loupe: #{expected_nonempty_url}")

expected_empty_url = "https://stevenjohnstone.github.io/prism-loupe/?code=&ruby_ver=4.1"
raise "unexpected Loupe URL in tc_empty.c:\n#{tc_empty_c}" unless tc_empty_c.include?("Prism Loupe: #{expected_empty_url}")

expected_enc_oob_url = "https://stevenjohnstone.github.io/prism-loupe/?code=L1xN&enc=ASCII-8BIT&ruby_ver=3.3&line=0&cmd=al&main=1&partial=1&freeze=1&filepath=fuzz.rb&scopes=%3A%3Bk%3Ab%2Cit"
raise "unexpected Loupe URL in tc_enc_oob.c:\n#{tc_enc_oob_c}" unless tc_enc_oob_c.include?("Prism Loupe: #{expected_enc_oob_url}")

File.write(File.join(workdir, "tc_nonempty.c"), tc_nonempty_c)
File.write(File.join(workdir, "tc_empty.c"), tc_empty_c)
EOF

awk '/#define _GNU_SOURCE/ { found=1; exit } /^#include/ { exit 1 } END { exit !found }' "$WORKDIR/tc_nonempty.c" \
    || fail "#define _GNU_SOURCE did not precede #include directives in generated testcase.c"
grep -q "static const size_t input_size = 6;" "$WORKDIR/tc_nonempty.c" || fail "missing input_size = 6 in tc_nonempty.c"
grep -q "static const size_t input_size = 0;" "$WORKDIR/tc_empty.c" || fail "missing input_size = 0 in tc_empty.c"

prism_srcs=$(find src -name '*.c')
clang -std=c99 -Wall -Wextra -Wpedantic -Wundef -Wconversion -Wstrict-prototypes -Werror -DPRISM_EXPORT_SYMBOLS \
    -fsanitize=address,undefined -Iinclude -Isrc "$WORKDIR/tc_nonempty.c" $prism_srcs -o "$WORKDIR/tc_nonempty"
clang -std=c99 -Wall -Wextra -Wpedantic -Wundef -Wconversion -Wstrict-prototypes -Werror -DPRISM_EXPORT_SYMBOLS \
    -fsanitize=address,undefined -Iinclude -Isrc "$WORKDIR/tc_empty.c" $prism_srcs -o "$WORKDIR/tc_empty"
"$WORKDIR/tc_nonempty"
"$WORKDIR/tc_empty"
echo "  standalone testcase.c compiled cleanly under -std=c99 -Werror and passed ASAN+UBSAN"

echo "[4/4] Checking concurrent triage.rb deduplication, coalescing, and sentinels..."
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
afl_dir, triage_dir = ARGV
src = File.read("test/fuzz/triage/triage.rb")
src.sub!('OUTPUT_DIRS = ["tmp/fuzz/afl", "tmp/fuzz/afl-ijon"].freeze', "OUTPUT_DIRS = [#{afl_dir.dump}].freeze")
src.sub!('TESTCASES_DIR = "tmp/fuzz/triage"', "TESTCASES_DIR = #{triage_dir.dump}")
eval(src)
EOF

ruby - "$WORKDIR/triage" "$WORKDIR/triage.log" << 'EOF'
triage_dir, log_path = ARGV
log = File.read(log_path)

abrt_dirs = Dir.glob(File.join(triage_dir, "ABRT", "*")).sort
raise "expected 3 ABRT dirs (BOOM + heredoc_term + escape_invalid_meta), got #{abrt_dirs.inspect}\nlog:\n#{log}" unless abrt_dirs.size == 3

tokens_found = []
abrt_dirs.each do |abrt_dir|
  mode = File.stat(abrt_dir).mode & 0o777
  raise "expected world-readable/traversable dir mode, got #{format('%#o', mode)}" unless (mode & 0o755) == 0o755
  raise "missing testcase.c in #{abrt_dir}" unless File.file?(File.join(abrt_dir, "testcase.c"))

  min_data = File.binread(File.join(abrt_dir, "input.min"))
  body = min_data.byteslice(4..)
  if body.include?("BOOM".b)
    raise "header mutated for BOOM: #{min_data.byteslice(0, 4).dump}" unless min_data.byteslice(0, 4) == "\x2a\x11\x22\x33".b
    raise "unexpected BOOM input.min size: #{min_data.dump}" unless min_data.bytesize <= 12
    tokens_found << "BOOM"
  elsif body.include?("INV_TARGET".b)
    raise "header mutated for INV_TARGET: #{min_data.byteslice(0, 4).dump}" unless min_data.byteslice(0, 4) == "\x10\x44\x55\x66".b
    raise "unexpected INV_TARGET input.min size: #{min_data.dump}" unless min_data.bytesize <= 18
    tokens_found << "INV_TARGET"
  elsif body.include?("INV_DECOY".b)
    raise "header mutated for INV_DECOY: #{min_data.byteslice(0, 4).dump}" unless min_data.byteslice(0, 4) == "\x10\x44\x55\x66".b
    raise "unexpected INV_DECOY input.min size: #{min_data.dump}" unless min_data.bytesize <= 18
    tokens_found << "INV_DECOY"
  else
    raise "unexpected minimized body in #{abrt_dir}: #{min_data.dump}"
  end
end
raise "expected all 3 distinct ABRT tokens, got #{tokens_found.inspect}" unless tokens_found.sort == %w[BOOM INV_DECOY INV_TARGET]

unrepro_dirs = Dir.glob(File.join(triage_dir, "unreproducible", "*"))
raise "expected 1 unreproducible dir, got #{unrepro_dirs.inspect}" unless unrepro_dirs.size == 1
raise "missing testcase.c in unreproducible dir" unless File.file?(File.join(unrepro_dirs.first, "testcase.c"))

raise "transient hang should not create hang dir" if File.exist?(File.join(triage_dir, "hang"))
min_runs = log.scan(/^minimizing /).size
raise "expected exactly 3 minimization runs across duplicates, got #{min_runs}:\n#{log}" unless min_runs == 3

sentinels = Dir.glob(File.join(triage_dir, ".processed", "*"))
raise "expected 10 .processed sentinels (4 BOOM + 2 INV_TARGET + 1 INV_DECOY + 1 unrepro + 1 sig:09 + 1 hang), got #{sentinels.size}" unless sentinels.size == 10
EOF
echo "  concurrent deduplication, coalescing, and sentinel checks passed"

echo "PASS: Fuzz crash triage and minimization suite verified."
