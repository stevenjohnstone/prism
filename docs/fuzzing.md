# Fuzzing

We use fuzzing to test the various entrypoints to the library. The fuzzer we use is [AFL++](https://aflplus.plus). All files related to fuzzing live within the `test/fuzz` directory, which has the following structure:

```
test/fuzz
├── Makefile                  make targets for building, running, triaging, and coverage
├── aflplusplus.patch         patch for AFL++ LTO/PCGUARD passes to skip sanitizer checks
├── corpus
│   └── parse                 fuzzing corpus for parsing (a symlink to our fixtures)
├── coverage.c                driver for coverage collection
├── dict                      an AFL++ dictionary containing various tokens
├── docker
│   └── Dockerfile            for building a container with the fuzzer toolchain
├── fuzz.c                    generic entrypoint for fuzzing
├── grammar
│   ├── grammar-mutator.patch patch for AFL++ Grammar-Mutator
│   └── ruby.json             Ruby grammar for AFL++ Grammar-Mutator
├── include
│   └── prism_xallocator.h    custom allocator header for fast leak detection
├── parse.c                   fuzz harness for parsing, serialization, and formatting
├── run.sh                    script to launch the parallel fuzzing session in tmux
└── tools
    ├── build.sh              builds a test case
    ├── build.asan.sh         builds a test case with ASAN/UBSAN enabled
    ├── build.memory.sh       builds a test case with MSAN enabled
    ├── corpus.rb             script to prepare and minimize a fuzzing corpus
    ├── coverage.sh           generate coverage report in html
    ├── halfempty.sh          script to use Google Project Zero's halfempty minimizer
    ├── halfempty_compare.sh  identifies similar backtraces
    ├── kill.sh               manages graceful shutdown of tmux
     ├── signature.sh          generates a crash signature hash
     ├── status.rb             live terminal dashboard for the fuzzer fleet
     ├── test_afl_patch.sh     verifies sanitizer-free AFL++ coverage guidance
     └── triage.rb             automagic triage of crashes
```

## Requirements


> Fuzzing runs inside a Docker container. If Docker is installed on the host platform, then fuzzing should work without installing any other dependencies. Everything required to fuzz and triage crashes is included in the container.

## Usage

There is currently one fuzzing target:
* `pm_parse_success_p`

* **To run the parse fuzzer:**
    In the root directory of this repository run
    ```bash
    # builds and runs fuzzing code in a container (defaults to nproc / 2 workers, minimum 4)
    make fuzz-run

    # or specify a custom number of fuzzer workers:
    FUZZ_WORKERS=14 make fuzz-run
    ```

This command will start a docker container running `FUZZ_WORKERS` fuzzers (defaulting to half the available CPU cores, or at least 4):
1. a primary fuzzer using ASAN, UBSAN, and CmpLog (`main`)
2. a grammar-driven fuzzer using custom leak detection (`grammar`, since LSAN/ASAN are slower on deep syntax trees)
3. a fuzzer using MSAN (memory sanitizer) (`msan`)
4. additional secondary workers (`main-2`, `main-3`, ...) scaling out `./build/fuzz` with varied AFL++ power schedules (`explore`, `coe`, `fast`)

> **CmpLog and `pm_strncasecmp`**: The `main` fuzzer runs alongside a CmpLog binary (`build/fuzz.cmplog`) built with `AFL_LLVM_CMPLOG=1`. When building `build/fuzz.cmplog`, `pm_strncasecmp` is replaced with the standard `strncasecmp` function (`-Dpm_strncasecmp=strncasecmp`, excluding `src/strncasecmp.c`) so AFL++'s CmpLog runtime hooks can instrument case-insensitive string comparisons and solve multi-byte comparisons (such as encoding names and magic comments) for better coverage.
>
> **Fast Leak Detection (`build/fuzz.ldet` on `grammar`)**: Running LeakSanitizer (LSAN) or ASAN on every fuzzing iteration slows down the `grammar` fuzzer on larger ASTs. Instead, `build/fuzz.ldet` is compiled with `-DPRISM_XALLOCATOR -Itest/fuzz/include`, which hooks `xmalloc`, `xcalloc`, `xrealloc`, and `xfree` (via `test/fuzz/include/prism_xallocator.h`) to lightweight wrappers in `test/fuzz/fuzz.c`. Each allocation prepends its size in a `size_t` header and updates a running byte counter (`allocated`), and `LLVMFuzzerTestOneInput` asserts `allocated == 0` at the end of every input to catch memory leaks without ASAN/LSAN overhead. During `make fuzz-triage`, crashes found by `fuzz.ldet` are tested against `build/fuzz` (for assertions/crashes) and `build/fuzz.lsan` (to produce detailed leak backtraces).
>
> **Grammar-Mutator (`test/fuzz/grammar/ruby.json` and `test/fuzz/grammar/grammar-mutator.patch`)**: The `grammar` worker uses AFL++'s [Grammar-Mutator](https://github.com/AFLplusplus/Grammar-Mutator) (pinned to commit `b108ec696ad60b2ad88babace7ebda138276bde3` in `test/fuzz/docker/Dockerfile`) compiled during `make fuzz-build` against our custom Prism Ruby grammar (`test/fuzz/grammar/ruby.json`), which includes the 4-byte fuzz option header (`<OPT0>..<OPT3>`) followed by Ruby syntax rules, producing `build/libgrammarmutator-ruby.so` and `build/grammar_generator-ruby`. At startup, `test/fuzz/run.sh` runs `./build/grammar_generator-ruby 500 500` to generate 500 initial Ruby seeds alongside their pre-serialized derivation `.tree` files in `/tmp/afl-tmpdir/grammar/{seeds,trees}`, and runs `grammar` with `AFL_NO_SYNC=1` so sync is one-way (`grammar -> main -> fleet`): `grammar` does not pull raw byte-mutated inputs from `main` (which have no `.tree` files and would otherwise pre-empt `grammar`'s `virgin_bits` and `top_rated[]` slots), while `main` still imports all coverage-increasing inputs from `$AFL_DIR/grammar/queue`. Before building, `test/fuzz/Makefile` applies `test/fuzz/grammar/grammar-mutator.patch` to `Grammar-Mutator` to:
> - **Store serialized `.tree` files in `tmpfs` (`/tmp/afl-tmpdir/grammar/trees`) and persist to `$AFL_DIR/.grammar-trees` on exit**: Serialized `.tree` files are read from and written directly to `/tmp/afl-tmpdir/grammar/trees` on `tmpfs` during fuzzing for fast RAM I/O without pre-creating `$AFL_DIR/grammar`, and persisted to `$AFL_DIR/.grammar-trees` when `run.sh` exits so `AFL_AUTORESUME=1` can restore them across container runs.
> - **Disable runtime ANTLR4 reverse-parsing (`load_tree_from_test_case`) and preserve `trimmed_tree` across `afl_custom_post_trim(data, 0)`**: Because `grammar` starts from `grammar_generator-ruby` seeds that already have `.tree` files and every grammar mutation/trim already has its `tree_t` in memory (`data->mutated_tree` / `data->trimmed_tree`), runtime ANTLR4 reverse-parsing of raw byte files (`load_tree_from_test_case`) is skipped. In addition, `data->trimmed_tree` is kept alive across `afl_custom_post_trim(data, 0)` so that when a trim step discovers a new coverage edge and `trim_case_custom` subsequently calls `save_if_interesting() -> afl_custom_queue_new_entry()`, the trimmed `tree_t` is saved to `/tmp/afl-tmpdir/grammar/trees` and added to `chunk_store`.
> - **Track grammar file changes and set `$ORIGIN` `RPATH`**: Ensures `GNUmakefile` rebuilds generated code when `test/fuzz/grammar/ruby.json` changes and links `grammar_generator-ruby` with `-Wl,-rpath,'$ORIGIN'` so `./build/grammar_generator-ruby` locates `./build/libgrammarmutator-ruby.so` across container runs.
>
> **Arena Granularity (`-DPM_ARENA_INITIAL_SIZE=0`)**: By default, Prism's arena allocator (`src/arena.c`) sub-allocates AST nodes and strings out of 8 KB blocks, which means an out-of-bounds read or write on one arena allocation can silently spill into adjacent allocations within the same block without triggering AddressSanitizer. Fuzzing and triage binaries are compiled with `-DPM_ARENA_INITIAL_SIZE=0` so `pm_arena_next_block_size` always returns the exact requested size (`min_size`). Every `pm_arena_alloc` call therefore allocates its own exact-sized `xmalloc` block surrounded by ASAN heap redzones, while `pm_arena_cleanup` still walks the block list and frees all blocks without leaking memory.
>
> **Write-Only ASAN (`-asan-instrument-reads=0`)**: `build/fuzz` (used by the `main` and `main-2..N` fuzzers) is compiled with `-mllvm -asan-instrument-reads=0 -Wl,-mllvm,-asan-instrument-reads=0` so AddressSanitizer only instruments stores (illegal writes) and does not abort on out-of-bounds reads, leaving read issues to the `msan` fuzzer (`build/fuzz.msan`).
>
> **Sanitizer-Free Coverage Instrumentation (`test/fuzz/aflplusplus.patch`)**: In LTO mode (`afl-clang-lto`), Clang runs AddressSanitizer, MemorySanitizer, and UBSAN during `-c` pre-link compilation before `SanitizerCoverageLTO.so` runs in `ld.lld`. Unpatched AFL++ instruments every sanitizer check branch, trap block, ASAN stack-use-after-return prologue/epilogue, and MSAN shadow `select`/`icmp`, inflating the coverage map of `build/fuzz` and `build/fuzz.msan` by 40–130%. During `make fuzz-build`, `test/fuzz/Makefile` applies `test/fuzz/aflplusplus.patch` and builds patched `SanitizerCoverageLTO.so` and `SanitizerCoveragePCGUARD.so` plugins into `build/afl/` (passed via `AFL_PATH`), stripping sanitizer-synthesized CFG edges and branchless shadow selects so all fuzzers (`fuzz`, `fuzz.ldet`, `fuzz.lsan`, and `fuzz.msan`) share near-identical coverage maps focused solely on Prism's control flow. In addition, `build/fuzz.msan` omits `-fsanitize-memory-track-origins=2` for higher fuzzing throughput and cleaner CFG structure, while `test/fuzz/tools/build.memory.sh` retains `-fsanitize-memory-track-origins=2` to report full uninitialized-memory origin chains when reproducing crashes.

### Fleet Dashboard

The terminal opens in a `tmux` session inside the container:
- **Window 0 (`dashboard`)** runs `test/fuzz/tools/status.rb`, displaying a live two-page fleet dashboard.
- **Windows 1..N** each run an individual `afl-fuzz` instance with its full native [AFL++ status screen](https://aflplus.plus/docs/status_screen/). Press `Ctrl+B, w` to pick any fuzzer window from an interactive list, `Ctrl+B, n`/`p` for next/previous window, or `Ctrl+B, 0` to return to the dashboard.

Inside the dashboard (`Window 0`), press **`Tab`**, **`Space`**, **`1`**, **`2`**, or the left/right arrow keys (`h`/`l`) to switch between the two pages:

1. **Page 1 (`[1: Overview]`)** — compact health and findings view:
   ```text
   Prism AFL++ Fleet Dashboard (uptime: 26m 16s, dir: ./tmp/fuzz/afl)   [1: Overview]  2: Queue & Sync

     Workers: 12/12 alive   Speed: 21,927/s   Execs: 34,420,027   Corpus: 18,540   Max Cov: 69.91%   Crashes: 0   Hangs: 0

   FUZZER     STATE     SCHED          EXEC/S    COV %             EDGES  CRASHES  HANGS
   -------------------------------------------------------------------------------------
   main       RUNNING   exploit       1,720/s   47.66%   15,288 / 32,905        0      0
   grammar    RUNNING   explore       2,309/s   69.91%   16,234 / 24,169        0      0
   msan       RUNNING   fast          5,773/s   37.59%   18,890 / 55,121        0      0
   main-2     RUNNING   explore       1,218/s   47.42%   15,276 / 32,905        0      0
   ...
   -------------------------------------------------------------------------------------
   [Tab/Space/1/2] Switch page   [Ctrl+B, w] Fuzzer window   [Ctrl+B, n/p] Next/Prev   [Ctrl+B, 0] Dashboard   [Ctrl+B, d] Detach   [Ctrl+C] Stop all
   ```

2. **Page 2 (`[2: Queue & Sync]`)** — detailed corpus progression and cross-fuzzer contribution metrics:
   ```text
   Prism AFL++ Fleet Dashboard (uptime: 26m 16s, dir: ./tmp/fuzz/afl)    1: Overview  [2: Queue & Sync]

     Workers: 12/12 alive   Speed: 21,927/s   Execs: 34,420,027   Corpus: 18,540   Max Cov: 69.91%   Crashes: 0   Hangs: 0

   FUZZER     STATE     SCHED          EXEC/S    TOTAL EXECS CYCLES   CORPUS   SHARED DESCENDANTS      LAST FIND  PENDING PEND FAV
   -------------------------------------------------------------------------------------------------------------------------------
   main       RUNNING   exploit       1,720/s      2,710,481      0   16,619    1,575       2,207         1s ago   16,339    1,968
   grammar    RUNNING   explore       2,309/s      3,519,253      0   16,216    4,940         664         1s ago   14,970    1,798
   msan       RUNNING   fast          5,773/s      9,096,279      0   18,540    3,542       3,655         1s ago   12,144        0
   main-2     RUNNING   explore       1,218/s      1,918,326      0   14,451      104         220         2s ago   14,050    1,905
   ...
   ```
   - **`SHARED` and `DESCENDANTS`**: Show how useful a fuzzer's outputs have been to the rest of the fleet (refreshed every 15 seconds while viewing Page 2). `SHARED` is how many seeds originated by that fuzzer were imported by other fuzzers (`sync:<name>`), and `DESCENDANTS` is how many additional coverage paths other fuzzers discovered by mutating those imported seeds (`src:<id>`).
   - **`PENDING` and `PEND FAV`**: Total unfuzzed queue entries and unfuzzed favored entries.

Minimized input corpus files will be generated in `tmp/fuzz/corpus`, and AFL++ fuzzing output will be written to `tmp/fuzz/afl`.

To end a fuzzing job, interrupt with **CTRL+C**.

To delete fuzzing run data (`tmp/fuzz/afl`, `tmp/fuzz/corpus`, and `tmp/fuzz/coverage`) while preserving already-triaged results in `tmp/fuzz/triage`, run
```bash
make fuzz-clean
```
> **WARNING**: `make fuzz-clean` deletes `tmp/fuzz/afl`, so run `make fuzz-triage` first to save any untriaged crashes or hangs into `tmp/fuzz/triage`.

## Coverage

To view coverage information in the browser, run
```
make fuzz-coverage
open tmp/fuzz/coverage/report/index.html
```

> **NOTE** the coverage is calculated over the functions which are reachable in the target


## Triaging Crashes and Hangs

From the prism directory where fuzzing is running, run
```bash
make fuzz-triage
```


This will create a `tmp/fuzz/triage/` directory with crashes organized by type. Each leaf directory contains:

1.  A C program (`testcase.c`)
2.  The minimized Ruby program that causes the crash (`input.min`)
3.  The original unminimized AFL++ crash file (`id:...`), whose filename records the signal (`sig:`), source queue entry, and fuzzer metadata

For example, the `tmp/fuzz/triage` directory may look like this:


```
tmp/fuzz/triage
├── ABRT
│  	├── 14a9275da317ddd6
│  	│  	├── input.min
│  	│  	└── testcase.c

```
In this case, an `ABRT` (abort signal) crashes was found, most likely from a failing program assert.

### Reproducing a Crash

To demonstrate a crash, you can build and run a specific test case:

```bash
# Build the test case with ASAN enabled
./test/fuzz/tools/build.asan.sh ./tmp/fuzz/triage/ABRT/d0a90c13bfbe209b/testcase.c

# Run the test case
./testcase
```

> **NOTE** if you do not have a compiler which supports ASAN (clang, gcc) installed on the host, run `make fuzz-debug` to start a container with clang, fuzzing tools etc installed and follow the instructions as above


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
You can then debug the crash using gdb (or lldb):
```bash
gdb ./testcase
```

It may be useful to set a break point on `__sanitizer::Die` to stop the program exiting after the ASAN/UBSAN
handler completes.



## Crash Similarity

Crashes are deemed to be **identifcal** if:

  * They are in the same category (e.g., `ABRT`, `SEGV`).
  * Their backtraces have the same hash signature after being stripped of random elements (like memory addresses).

Similar crashes are stored in the output directory under their category and backtrace signature. For example:

```
tmp/fuzz/triage
├── ABRT  <------------------------type of crash
│   ├── 14a9275da317ddd6     <-----backtrace signature
│   │   ├── build.sh
│   │   ├── input.min
│   │   └── testcase.c
```


> **A Note on Behavior:**
> When building and running test cases outside the fuzzing framework, crashes may manifest differently. For example, a "use after poison" crash (from data on the heap surrounded by poisoned pages) might become a "global buffer overflow" in the test harness (where data is stored in a global). Either way, the underlying bug is an out-of-bounds read or write.

