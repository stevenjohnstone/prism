# Fuzzing

We use fuzzing to test the various entrypoints to the library. The fuzzer we use is [AFL++](https://aflplus.plus). All files related to fuzzing live within the `fuzz` directory, which has the following structure:

```
fuzz
├── corpus
│   ├── parse                 fuzzing corpus for parsing (a symlink to our fixtures)
│   └── regexp                fuzzing corpus for regexp
├── dict                      a AFL++ dictionary containing various tokens
├── docker
│   └── Dockerfile            for building a container with the fuzzer toolchain
├── fuzz.c                    generic entrypoint for fuzzing
├── parse.c                   fuzz handler for parsing
├── parse.sh                  script to run parsing fuzzer
├── regexp.c                  fuzz handler for regular expression parsing
├── regexp.sh                 script to run regexp fuzzer
└── tools
    ├── halfempty.sh          script to use Google zero's halfempty minimizer
    ├── halfempty_compare.sh  identifies similar backtraces
    └── triage.sh             automagic triage of crashes
```

## Requirements


> Fuzzing runs inside a Docker container. If Docker is installed on the host platform, then fuzzing should work without installing any other dependencies. Everything required to fuzz and triage crashes is included in the container.

## Usage

There are currently two fuzzing targets:
* `pm_serialize_parse` (parse)
* `pm_regexp_parse` (regexp)

You can run them from the root of the prism repository.

* **To run the parse fuzzer:**
    ```bash
    # builds and runs fuzzing code in a container
    make fuzz-run-parse 
    ```
* **To run the regexp fuzzer:**
    ```bash
    # builds and runs fuzzing code in a container
    make fuzz-run-regexp
    ```

Either command will start a container with one or more fuzzer jobs. You can find an explanation of the status screen [here](https://aflplus.plus/docs/status_screen/).

Fuzzing output will be generated in the `fuzz/output` directory.

To end a fuzzing job, interrupt with **CTRL+C**. To leave the Docker container shell, type:
```bash
exit
```

## Usage

There are currently two fuzzing targets

- `pm_serialize_parse` (parse)
- `pm_regexp_parse` (regexp)

Respectively, fuzzing can be performed by executing

```bash
make fuzz-run-parse #builds and runs fuzzing code in a container
```
and
```bash
make fuzz-run-regexp #builds and runs fuzzing code in a container
```
in the root of the prism respository.

Either will start a container with one or more fuzzer jobs running. The status screen is explained [here](https://aflplus.plus/docs/status_screen/).

To end a fuzzing job, interrupt with CTRL+C. To leave the docker container shell, type
```bash
exit
```

There will be fuzz output in the directory
```
fuzz/output
```

## Triaging Crashes and Hangs

From the prism directory where fuzzing is running, run
```bash
make fuzz-triage
```


This will create a `triage/` directory with crashes organized by type. Each leaf directory contains:

1.  A C program (`testcase.c`)
2.  A build script (`build.sh`)
3.  The raw, malformed Ruby program that causes the crash (`input.min`)

For example, the `triage` directory may look like this:


```
triage
├── ABRT
│  	├── 14a9275da317ddd6
│  	│  	├── d0a90c13bfbe209b
│  	│  	│  	├── build.sh
│  	│  	│  	├── input.min
│  	│  	│  	└── testcase.c
│  	│  	└── e4ceb80a0511fe06
│  	│  	 	 ├── build.sh
│  	│  	 	 ├── input.min
│  	│  	 	 └── testcase.c

```
In this case, `ABRT` (abort signal) crashes were found, most likely from a failing program assert.

### Reproducing a Crash

To demonstrate a crash, you can build and run a specific test case:

```bash
# Build the test case
./triage/ABRT/d0a90c13bfbe209b/e4ceb80a0511fe06/build.sh

# Run the test case
./testcase
```

> **NOTE** if you do not have a compiler which support ASAN (clang, gcc) installed on the host, run `make fuzz-debug` to start a container with clang, fuzzing tools etc installed and follow the instructions as above


The output may be something like
```
testcase: src/util/pm_newline_list.c:51: _Bool pm_newline_list_append(pm_newline_list_t *, const uint8_t *): Assertion `list->size == 0 || newline_offset > list->offsets[list->size - 1]' failed.
AddressSanitizer:DEADLYSIGNAL
=================================================================
==143==ERROR: AddressSanitizer: ABRT on unknown address 0x03e80000008f (pc 0xffff91cf2008 bp 0xfffff8cce460 sp 0xfffff8cce3d0 T0)
    #0 0xffff91cf2008 in __pthread_kill_implementation nptl/pthread_kill.c:44:76
    #1 0xffff91caa838 in gsignal signal/../sysdeps/posix/raise.c:26:13
    #2 0xffff91c97130 in abort stdlib/abort.c:79:7
    #3 0xffff91ca4110 in __assert_fail_base assert/assert.c:94:3
    #4 0xffff91ca4188 in __assert_fail assert/assert.c:103:3
    #5 0xaaaad388572c in pm_newline_list_append /prism/src/util/pm_newline_list.c:51:5
    #6 0xaaaad38c5b1c in parser_lex /prism/src/prism.c:12248:25
    #7 0xaaaad38fece0 in accept1 /prism/src/prism.c:13229:9
    #8 0xaaaad3902cc0 in expect1 /prism/src/prism.c:13261:9
    #9 0xaaaad390fc3c in parse_string_part /prism/src/prism.c:16193:13
    #10 0xaaaad38f51e8 in parse_expression_prefix /prism/src/prism.c:20544:29
    #11 0xaaaad38e45f8 in parse_expression /prism/src/prism.c:22251:23
    #12 0xaaaad38fb858 in parse_expression_infix /prism/src/prism.c:21887:35
    #13 0xaaaad38e4b60 in parse_expression /prism/src/prism.c:22303:16
    #14 0xaaaad38cc880 in parse_statements /prism/src/prism.c:13985:27
    #15 0xaaaad38b31e4 in parse_program /prism/src/prism.c:22524:40
    #16 0xaaaad38b2ff8 in pm_parse /prism/src/prism.c:22957:12
    #17 0xaaaad38b3ff8 in pm_parse_success_p /prism/src/prism.c:23074:23
    #18 0xaaaad39bdc34 in harness /prism/triage/ABRT/14a9275da317ddd6/d0a90c13bfbe209b/testcase.c:11:3
    #19 0xaaaad39bdc84 in main /prism/triage/ABRT/14a9275da317ddd6/d0a90c13bfbe209b/testcase.c:80:5
    #20 0xffff91c973fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #21 0xffff91c974d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #22 0xaaaad3762eec in _start (/prism/testcase+0x52eec) (BuildId: 263757dc719fdaad53a70d21f0dcbcaf732902ec)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: ABRT nptl/pthread_kill.c:44:76 in __pthread_kill_implementation
==143==ABORTING
Aborted
```
You can then debug the crash using gdb:
```bash
gdb ./testcase
```
To run the test case on **the host plaform** (Linux, WSL and macOS supported)
exit the container
```bash
exit
```
and run
```bash
# Build the test case
./triage/ABRT/d0a90c13bfbe209b/e4ceb80a0511fe06/build.sh

# Run the test case
./testcase
```
just as in the container.



## Crash Similarity

Crashes are deemed to be **similar** if:

  * They are in the same category (e.g., `ABRT`, `SEGV`).
  * Their backtraces have the same hash signature after being stripped of random elements (like memory addresses).

Similar crashes are stored in the output directory under their category and backtrace signature. For example:

```
triage
├── ABRT  <------------------------type of crash
│   ├── 14a9275da317ddd6     <-----backtrace signature
│   │   ├── d0a90c13bfbe209b <-----instance 1
│   │   │   ├── build.sh
│   │   │   ├── input.min
│   │   │   └── testcase.c
│   │   └── e4ceb80a0511fe06 <-----instance 2
│   │       ├── build.sh
│   │       ├── input.min
│   │       └── testcase.c
```

Here, the `ABRT` with signature `14a9275da317ddd6` has two instances. Their backtraces should be similar and likely share the same root cause.

> **A Note on Behavior:**
> When building and running test cases outside the fuzzing framework, crashes may manifest differently. For example, a "use after poison" crash (from data on the heap surrounded by poisoned pages) might become a "global buffer overflow" in the test harness (where data is stored in a global). Either way, the underlying bug is an out-of-bounds read or write.

## Heisenbugs: Out-of-bounds reads

The `triage` directory may contain a `heisenbug` directory. These inputs may only trigger a crash when run by the fuzzer or trigger unreliably outside of it.

This is often due to out-of-bounds reads (e.g., off-by-one errors). The contents of out-of-bounds memory can be random, causing intermittent failures. These inputs are found by a fuzzer job that runs with ASAN read instrumentation disabled, which achieves more coverage by ignoring OOB reads.

The C harness code for heisenbugs is different. It runs the code in a loop, setting the byte *after* the test buffer to every possible value (`0x00` to `0xff`) to try and trigger the bug.

```c
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
```

In most cases, this loop should reproduce the crash. If not, enabling the address sanitizer for the C harness code should reveal the underlying out-of-bounds read.

