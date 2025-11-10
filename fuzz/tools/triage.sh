#!/bin/bash -e

OUTPUT_DIR="fuzz/output"
parallel=8

TESTCASES_DIR=${1:-"triage"}
mkdir -p "$TESTCASES_DIR"

crash_count=0
for f in "$OUTPUT_DIR"/*/*/{crashes,hangs}/id*; do
	[[ -f $f ]] && { crash_count=$((crash_count + 1)); }
done

START=""
END="\n"

[[ -t 1 ]] && {
	# attached to tty so don't fill the terminal
	START="\033[K"
	END="\r"
}

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

print_lock=$(mktemp)
exec 200<>"$print_lock"
progress=0
function print() {
	percent=$(((progress * 100) / crash_count))
	(
		flock 200
		printf "$START"
		printf "%-10s %4s %-14s " "$(date "-d@${SECONDS}" -u +%H:%M:%S)" "${percent}%" "(${progress}/${crash_count})"
		printf "$@"
		printf "$END"
	) 200>"$print_lock"
}

function process_crash() {
	crash_dir=$1
	crash=$2
	executable=$3

	reason=""
	[ "$(basename "$crash_dir")" = "hangs" ] && {
		reason="hang"
	}
	# make a report dir with a unique name (the hash of the input file contents)
	unique=($(xxh64sum "$crash"))
	testcase_subdir="${TESTCASES_DIR}/${unique}"
	mkdir -p "$testcase_subdir"
	minimized_input="${testcase_subdir}/input.min"
	c_file="${testcase_subdir}/testcase.c"
	touch "$minimized_input"
	pre_min_size=$(stat --format %s "$crash")
	if [[ "$pre_min_size" -gt 16 ]]; then
		print "Minimizing %s -- may take a long time" "$crash"
		if [ "$reason" = "hang" ]; then
			AFL_TMIN_EXACT=1 afl-tmin -e -H -t 500 -i "$crash" -o "$minimized_input" -- "$executable" &>/dev/null
		else
			AFL_TMIN_EXACT=1 afl-tmin -e -t 500 -i "$crash" -o "$minimized_input" -- "$executable" &>/dev/null
		fi
		post_min_size=$(stat --format %s "$minimized_input")
		if [[ "$reason" != "hang" && "$post_min_size" == "$pre_min_size" ]]; then
			print "Trying again with halfempty"
			./fuzz/tools/halfempty.sh "$executable" "$crash" "$minimized_input" &>/dev/null
			post_min_size=$(stat --format %s "$minimized_input")
		fi
		print "Minimized from %s bytes to %s bytes" "$pre_min_size" "$post_min_size"
	else
		print "too short to minimize (%s bytes)" "$pre_min_size"
		cp "$crash" "$minimized_input"
	fi

	# xxd generates a view of the minimized input which goes into a comment in the C file
	hex_input="$(xxd "$minimized_input")"
	# xxd can generate a C representation of the input. Needs to be massaged a little
	# to give the variables good names
	c_input="$(xxd -i /dev/stdin <"$minimized_input" | sed -r 's/_dev_stdin/input/g')"
	# the C file needs a main entry point: we simply call the harness code with our input
	cat <<EOF >>"$c_file"
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Fuzz case ${crash}

${harness_code}
/*
${hex_input}
*/

${c_input}

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char* __asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/* Crash output from fuzz run $executable input.min:

EOF

	# let's strip the backtrace of random stuff so we can hash the output and make a directory containing related
	# crashes
	heisenbug=0
	if [ -z "$reason" ]; then
		tmpfile=$(mktemp)
		set +e
		set -o pipefail
		signature=($("$executable" "$minimized_input" |& tee -a "$c_file" | sed -r 's/0x[0-9a-fA-F]*|==[[:digit:]]*==|[[:digit:]]* bytes|[[:digit:]]*-byte//g' | xxh64sum -))
		program_status="${PIPESTATUS[0]}"
		set +o pipefail
		set -e
		if [ "$program_status" -ne 0 ]; then
			reason="$(grep -aEo 'SUMMARY: AddressSanitizer: [[:alpha:]-]*' "$c_file" | sed -r 's/SUMMARY: AddressSanitizer: //g')"/"$signature"
		else
			heisenbug=1
			# there was no failure...maybe due to reading outside of bounds setting up very specific conditions
			reason="heisenbug/${signature}"
		fi
	else
		echo "Not available: hang" >>"$c_file"
	fi
	flags="-fsanitize=address"
	if [ "$heisenbug" -eq 0 ]; then
		cat <<EOF >>"$c_file"
*/

int main(int argc, const char **argv) {
    (void) argc;
    (void) argv;
    harness((const uint8_t *)input, (size_t) input_len);
    return 0;
}
EOF
	else
		flags=""
		cat <<EOF >>"$c_file"
*/

int main(int argc, const char **argv) {
    (void) argc;
    (void) argv;

    char *mutation_buffer = malloc(input_len + 1);
    assert(mutation_buffer);
    memcpy(mutation_buffer, input, input_len);

    // try all possible trailing bytes to see if it triggers
    // the bug
    for (unsigned int i = 0; i < UINT8_MAX; i++) {
        mutation_buffer[input_len] = (char) i;
        harness((const uint8_t *) mutation_buffer, input_len);
    }

    free(mutation_buffer);
    return 0;
}
EOF
	fi

	[ -z "$reason" ] && {
		print "%s %s has no crash reason" "$executable" "$crash"
		exit 1
	}

	mkdir -p "$TESTCASES_DIR/$reason"
	# a new hash for the minimized input is calulated and this is used as the sub-directory name
	# inside the directory which indicates the crash reason
	unique=($(xxh64sum "$minimized_input"))
	target_dir="${TESTCASES_DIR}/${reason}/${unique}"
	# create a convenience executable to build the reproducing case
	cat <<EOF >"${testcase_subdir}/build.sh"
#!/bin/bash
clang -Iinclude $flags -ggdb3 \$(find src -name '*.c') $target_dir/testcase.c -o testcase
EOF
	chmod +x "${testcase_subdir}/build.sh"
	if [ -d "$target_dir" ]; then
		# after minimisation, it's possible that we've seen a crash input before
		rm -rf "$testcase_subdir"
	else
		mv "$testcase_subdir" "$target_dir"
	fi
}

for crash_dir in "$OUTPUT_DIR"/*/*/{crashes,hangs}; do
	readme_path="$crash_dir/../crashes/README.txt"
	# It's entirely possible that there are no crashes in the directory
	# which is indicated by the absence of a README.txt file
	[ -f "$readme_path" ] || {
		continue
	}
	# the crash dir contains a README.txt with information about how the fuzz was run
	# scrape the executable path here
	command_line=$(grep '^afl-fuzz' "$readme_path")
	executable=${command_line##* }
	# the fuzz executable is built with '-ggdb' flag so it has the source code embedded in the debug info. Gdb
	# can extract this for us so we know exactly what the harness code was when the fuzzer was built
	harness_code=$(gdb -q -ex 'set listsize unlimited' -ex 'list harness' -ex 'quit' "$executable" | sed -n -r 's/^[[:digit:]]+\s*//p' | clang-format)

	while IFS= read -r -d '' crash; do
		progress=$((progress + 1))
		print "Processing %s %s" "$executable" "$crash"
		process_crash "$crash_dir" "$crash" "$executable" &
		if (($(jobs -r -p | wc -l) >= parallel)); then
			# 'wait -n' waits for the *next* job to finish,
			# freeing up a slot.
			wait -n
		fi
	done 2>/dev/null < <(find "$crash_dir" -type f ! -name "*.txt" -print0)
done
wait
