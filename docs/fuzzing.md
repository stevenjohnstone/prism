# Fuzzing

We use coverage-guided fuzzing with [AFL++](https://aflplus.plus) to test `pm_parse` and its downstream consumers (`pm_serialize`, `pm_errors_format`, `pm_prettyprint`, and `pm_dump_json`). All fuzzing files live in `test/fuzz`:

```
test/fuzz
├── Makefile                      make targets for building, running, triaging, and coverage
├── debug
│   ├── backtrace.sh              generates gdb backtraces for a crash directory
│   ├── build.asan.sh             builds a test case with ASAN/UBSAN enabled
│   ├── build.memory.sh           builds a test case with MSAN enabled
│   ├── build.sh                  builds a test case without sanitizers
│   └── minimize.sh               minimizes crash/hang inputs in a directory via afl-tmin
├── dict                          an AFL++ dictionary containing Ruby tokens
├── docker
│   └── Dockerfile                for building a container with the fuzzer toolchain
├── harness
│   ├── coverage.c                driver for coverage collection
│   ├── fuzz.c                    generic entrypoint for fuzzing
│   ├── heisenbug.c               standalone harness template for non-deterministic crashes
│   ├── include
│   │   └── prism_xallocator.h    custom allocator header for fast leak detection
│   └── parse.c                   fuzz harness for parsing, serialization, and formatting
├── patches
│   ├── aflplusplus.md            explanation of the AFL++ sanitizer coverage patch
│   ├── aflplusplus.patch         patch for AFL++ LTO/PCGUARD passes to skip sanitizer checks
│   └── test_afl_patch.sh         verifies sanitizer-free AFL++ coverage guidance
├── report
│   ├── coverage.sh               generates LCOV, HTML, and text source coverage reports
│   └── plot.rb                   generates interactive HTML graphs from AFL++ telemetry
├── runtime
│   ├── corpus.rb                 prepares and minimizes the initial seed corpus
│   ├── grammar.rb                generates grammar-guided Ruby seeds via lrama-fuzz
│   ├── kill.sh                   manages graceful shutdown of the tmux session
│   ├── run.sh                    launches the parallel fuzzing fleet in tmux
│   └── status.rb                 live terminal dashboard for the fuzzer fleet
└── triage
    ├── halfempty.sh              minimizes crash inputs with Google Project Zero's halfempty
    ├── halfempty_compare.sh      identifies similar backtraces during minimization
    ├── signature.sh              hashes stack traces into a crash signature
    └── triage.rb                 deduplicates, minimizes, and packages crashes into C reproducers
```

## Requirements

Docker: runs on Linux, Windows and Mac OS.

Everything needed to build the fuzzers, run a campaign, and triage crashes is self-contained inside the Docker image.

## Usage

### Quick Start

1. **Start the fuzzer** from the repository root:
   ```bash
   make fuzz-run
   ```
   This builds the Docker image and fuzzing binaries (if out of date), prepares the seed corpus from `test/prism/fixtures`, and opens a `tmux` dashboard running a fleet of parallel AFL++ workers.

2. **Wait for a crash** to appear in the `CRASHES` column of the dashboard, then press **`Ctrl+C`** (and `y` to confirm) to stop all fuzzers cleanly and exit the container.

3. **Triage the findings**:
   ```bash
   make fuzz-triage
   ```
   Triage runs every crash and hang from `tmp/fuzz/afl/` against the sanitizer binaries, deduplicates them by backtrace signature, minimizes the triggering input, and writes standalone reproducers into `tmp/fuzz/triage/`.

### Where to Find Crashes and How to Reproduce

`make fuzz-triage` organizes unique bugs under `tmp/fuzz/triage/<category>/<signature>/`:

```
tmp/fuzz/triage
└── ABRT                          <-- crash category (e.g., ABRT, SEGV, heap-buffer-overflow, memory-leak)
    └── 14a9275da317ddd6          <-- hash of the normalized backtrace
        ├── id:000000,sig:06,...  <-- original unminimized AFL++ crash input
        ├── input.min             <-- minimized raw input (4-byte option header + Ruby source)
        └── testcase.c            <-- self-contained C program that reproduces the crash
```

Each `testcase.c` embeds the decoded `pm_options_t` settings, the Ruby source as a C byte array (with a readable string dump in a comment at the top), and the sanitizer output captured during triage.

To compile and run a `testcase.c` reproducer:

```bash
# Build with AddressSanitizer and UndefinedBehaviorSanitizer:
./test/fuzz/debug/build.asan.sh ./tmp/fuzz/triage/ABRT/14a9275da317ddd6/testcase.c

# Or, for uninitialized-memory crashes (use-of-uninitialized-value), build with MemorySanitizer:
./test/fuzz/debug/build.memory.sh ./tmp/fuzz/triage/use-of-uninitialized-value/<signature>/testcase.c

# Or build without sanitizers for plain gdb/lldb debugging:
./test/fuzz/debug/build.sh ./tmp/fuzz/triage/ABRT/14a9275da317ddd6/testcase.c

# Run the compiled reproducer:
./testcase
```

> **Note:** If your host machine does not have `clang` with sanitizer support (for example on macOS when reproducing MSAN crashes), run `make fuzz-debug` to open an interactive shell inside the fuzzing container and run the commands above there.

Running `./testcase` prints the assertion failure or sanitizer report:

```
testcase: src/util/pm_newline_list.c:51: _Bool pm_newline_list_append(pm_newline_list_t *, const uint8_t *): Assertion `list->size == 0 || newline_offset > list->offsets[list->size - 1]' failed.
AddressSanitizer:DEADLYSIGNAL
=================================================================
==143==ERROR: AddressSanitizer: ABRT on unknown address 0x03e80000008f
    #0 0xffff91cf2008 in __pthread_kill_implementation nptl/pthread_kill.c:44:76
    ...
    #5 0xaaaad388572c in pm_newline_list_append /prism/src/util/pm_newline_list.c:51:5
    #6 0xaaaad38c5b1c in parser_lex /prism/src/prism.c:12248:25
```

You can then inspect it in `gdb` or `lldb`:

```bash
gdb ./testcase
```

Tip: set a breakpoint on `__sanitizer::Die` if you want the debugger to stop before the ASAN/UBSAN handler exits.

> **Note on crash categories:** When compiled as a standalone `testcase.c`, `input` is a `static const uint8_t[]` array in `.rodata` rather than a heap buffer. An out-of-bounds read that originally triggered `heap-buffer-overflow` inside the fuzzer may therefore report as `global-buffer-overflow` in `./testcase`; the underlying bug is the same.

---

### Running in the Background (Daemon Mode) and Custom Worker Counts

By default, `make fuzz-run` launches half the available CPU cores (minimum 4). You can override the worker count or run the campaign in the background:

```bash
# Run with a specific number of workers:
FUZZ_WORKERS=14 make fuzz-run

# Launch in the background as a Docker daemon (container name defaults to prism-fuzz):
make fuzz-daemon

# Attach to the running tmux dashboard at any time:
make fuzz-attach
# (Press Ctrl+B then d to detach without stopping the fuzzers)

# Stop the background daemon cleanly:
make fuzz-stop
```

### Navigating the Fleet Dashboard

Inside the `tmux` session:

- **Window 0 (`dashboard`)** runs `test/fuzz/runtime/status.rb`, showing a live two-page summary of all workers. Press `Tab`, `Space`, `1`, `2`, or the arrow keys to toggle between:
  - **`[1: Overview]`**: Worker health, execution speed, coverage percentage, edges found, crashes, and hangs.
  - **`[2: Queue & Sync]`**: Total executions, queue cycles, corpus size, cross-worker `SHARED` and `DESCENDANTS` counts (how many inputs discovered by a worker were imported and further mutated by peers), and pending favored items.
- **Windows 1..N** each display an individual worker's native [AFL++ status screen](https://aflplus.plus/docs/status_screen/). Use `Ctrl+B, w` to pick a window from a list, `Ctrl+B, n`/`p` for next/previous window, or `Ctrl+B, 0` to return to the dashboard.

### Telemetry Plots and Source Coverage

- **Interactive telemetry plots** (coverage growth, throughput, corpus size, and cross-worker queue sync breakdowns):
  ```bash
  make fuzz-plot
  open tmp/fuzz/plots/index.html
  ```
- **Source-level coverage** (computed across all reachable library functions over the deduplicated corpus in `tmp/fuzz/afl`):
  ```bash
  make fuzz-coverage
  ```
  `make fuzz-coverage` prints a per-file coverage table to the terminal and writes four artifacts to `tmp/fuzz/coverage/`:
  - `tmp/fuzz/coverage/lcov.info` — workspace-relative LCOV line, function, and branch coverage for IDE integration:
    - **VS Code / Cursor / Antigravity**: Install [Coverage Gutters](https://marketplace.visualstudio.com/items?itemName=ryanluker.vscode-coverage-gutters) and run *Coverage Gutters: Display Coverage* (or *Watch*) to highlight covered/uncovered lines and branches inline in the editor.
    - **CLion**: Use *Run -> Show Coverage Data...* (`Cmd+Option+F6` / `Ctrl+Alt+F6`) and select `tmp/fuzz/coverage/lcov.info`.
    - **Neovim**: Point [`nvim-coverage`](https://github.com/andythigpen/nvim-coverage) (`lcov_file`) at `tmp/fuzz/coverage/lcov.info`.
  - `tmp/fuzz/coverage/report/index.html` — standalone HTML report with line and branch counts (`open tmp/fuzz/coverage/report/index.html`).
  - `tmp/fuzz/coverage/coverage.profdata` — merged LLVM profile data for custom `llvm-cov` queries.
  - `tmp/fuzz/coverage/summary.txt` — saved copy of the terminal summary table.

### Cleaning Up

To delete the current campaign data (`tmp/fuzz/afl`, `tmp/fuzz/corpus`, `tmp/fuzz/coverage`, and `tmp/fuzz/plots`) while keeping already-triaged bugs in `tmp/fuzz/triage`:

```bash
make fuzz-clean
```

Run `make fuzz-triage` before `make fuzz-clean` if your campaign has untriaged crashes or hangs.

---

## Technical Details

For background on coverage-guided greybox fuzzing and AFL++, see:

- [The Fuzzing Book — Greybox Fuzzing](https://www.fuzzingbook.org/html/GreyboxFuzzer.html) and [Mutation-Based Fuzzing](https://www.fuzzingbook.org/html/MutationFuzzer.html)
- [AFL++ Documentation](https://aflplus.plus/docs/) and [Best Practices](https://aflplus.plus/docs/best_practices/)

### Harness and Input Format (`test/fuzz/harness/parse.c`)

Every fuzz input begins with a **4-byte options header** consumed by `harness()` before the remaining bytes are passed to `harness_parse()` as Ruby source:

| Byte | Bits | Option Mapped to `pm_options_t` |
| :--- | :--- | :--- |
| `input[0]` | `0..5` | Boolean flags: `freeze`, `partial_script`, `attach_comments`, `encoding_locked`, `has_frozen_string_literal`, `frozen_string_literal` |
| `input[1]` | `0..5`, `6` | Command-line flags (`-a`, `-e`, `-l`, `-n`, `-p`, `-x`) and `main_script` |
| `input[2]` | `0..1`, `2..3`, `4..7` | Ruby syntax version (`3.3`, `3.4`, `3.5`, `4.1`), enclosing `scopes_count` (`0..3`), and parameter forwarding flags (`*`, `**`, `&`, `...`) |
| `input[3]` | `0..7` (signed) | `start_line` (`-128..127`) |

Putting options in the input header lets AFL++ mutate parser configuration alongside Ruby syntax so version-specific grammar rules, magic-comment overrides, command-line loops (`-n`/`-p`), and local scope forwarding are all explored automatically.

After `pm_parse()` returns, `harness_parse()` checks two invariants on every run:

1. **Monotonic line offsets**: Verifies that `parser->line_offsets` is strictly increasing.
2. **AST location bounds (`check_node_location`)**: Walks the entire AST with `pm_visit_node` and aborts if any node has `start > end`, `start < input`, or `end > input + size`.

### Parse-Only Fast Workers vs. `-DSLOW` Post-Processing

Running `pm_serialize`, `pm_errors_format`, `pm_prettyprint`, and `pm_dump_json` on every fuzzing iteration would slow down parser exploration and pollute the coverage bitmap with output-formatter edges. We split the build into two modes:

- **Fast parse-only binaries** (`build/fuzz`, `build/fuzz.native`, `build/fuzz.ldet`, `build/fuzz.sand`, `build/fuzz.cmplog`): Compiled with `-DPRISM_EXCLUDE_SERIALIZATION -DPRISM_EXCLUDE_JSON -DPRISM_EXCLUDE_PRETTYPRINT`. They only run `pm_parse` and the AST/line-offset invariant checks.
- **Slow full-pipeline binaries** (`build/fuzz.msan`, `build/fuzz.lsan`, `build/fuzz.coverage`, and the `test/fuzz/debug/build*.sh` scripts): Compiled with `-DSLOW`, which additionally runs `pm_serialize`, `pm_errors_format` (plain and color), `pm_prettyprint`, and `pm_dump_json` on every input. Because these serializers and printers read every AST node, token, error, and line offset, running them under MemorySanitizer (`fuzz.msan`) catches uninitialized fields anywhere in the parse tree.

### Worker Fleet Architecture

`test/fuzz/runtime/run.sh` launches `FUZZ_WORKERS` workers that coordinate through `tmp/fuzz/afl`:

1. **`main`** (`build/fuzz` + `build/fuzz.cmplog`): Primary ASAN+UBSAN worker (`-M main`) with CmpLog enabled, seeded with the full minimized fixture corpus.
2. **`grammar`** (`test/fuzz/runtime/grammar.rb`): Structure-aware Ruby seed generator powered by [`lrama-fuzz`](https://github.com/kddnewton/lrama-fuzz), continuously feeding `ldet` via foreign sync.
3. **`msan`** (`build/fuzz.msan`): Runs the full `-DSLOW` pipeline under MemorySanitizer to catch uninitialized memory reads and out-of-bounds reads across parsing, serialization, pretty-printing, and JSON dumping.
4. **`ldet`** (`build/fuzz.ldet`): Fast native worker (`-M ldet -F /tmp/afl-tmpdir/grammar/seeds`) with custom leak detection and IJON state-guided instrumentation enabled, acting as the intake filter for grammar-generated seeds and sharing IJON/CFG discoveries with `main`, `msan`, and secondary workers.
5. **`main-2 .. main-N`** (`build/fuzz.native` + `-w ./build/fuzz.sand`): Secondary workers running AFL++ **SAND** (`AFL_SAN_ABSTRACTION=coverage_increase`). They execute mutations at native speed without sanitizer overhead, and only forward inputs that discover new coverage to the forkserver-only ASAN+UBSAN binary (`build/fuzz.sand`). Secondary workers cycle through different AFL++ power schedules (`explore`, `fast`, `coe`, `lin`, `quad`, `exploit`, `rare`, `mmopt`), mutation modes (MOpt `-L 0`, `-P explore/exploit`, `-Z`), and disjoint shards of the initial seed corpus.

### Fast Leak Detection (`PRISM_XALLOCATOR`)

Enabling LeakSanitizer (LSAN) or ASAN per-allocation redzones on every fuzzing execution significantly reduces throughput on inputs that allocate deep ASTs.

For `build/fuzz.native` and `build/fuzz.ldet`, we compile without sanitizers and enable Prism's custom allocator hook (`-DPRISM_XALLOCATOR -Itest/fuzz/harness/include`). `test/fuzz/harness/include/prism_xallocator.h` routes `xmalloc`, `xcalloc`, `xrealloc`, and `xfree` to wrappers in `test/fuzz/harness/fuzz.c` that prepend an 8-byte size header to each allocation and maintain a running `allocated` byte counter. At the end of `LLVMFuzzerTestOneInput`, `assert(allocated == 0)` immediately aborts if any memory was leaked during the parse, with near-zero runtime overhead. Wrappers also enforce a per-input cumulative allocation cap (`FUZZ_MAX_ALLOCATED_BYTES`, 128 MiB) to catch exponential memory-blowup bugs early.

When `make fuzz-triage` processes a leak crash from `fuzz.ldet` or `fuzz.native`, it re-runs the input against `build/fuzz.lsan` so the generated `testcase.c` includes a full LeakSanitizer allocation backtrace.

### Sanitizer-Free Coverage Instrumentation (`test/fuzz/patches/aflplusplus.patch`)

When Clang compiles code with ASAN, UBSAN, or MSAN before LTO linking, it injects thousands of conditional branches for shadow-memory checks, overflow traps, stack-use-after-return prologues, MSAN shadow `select`s, and `assert()` macros. Out of the box, AFL++ instruments all of those compiler-generated branches, inflating the coverage map by 40–130% and breaking dominator-based block pruning.

During `make fuzz-build`, `test/fuzz/Makefile` applies [`test/fuzz/patches/aflplusplus.patch`](../test/fuzz/patches/aflplusplus.patch) to AFL++'s LTO and PCGUARD passes so sanitizer checks and `assert()` traps are invisible to coverage instrumentation. As a result, `fuzz`, `fuzz.msan`, `fuzz.lsan`, and `fuzz.native` share nearly identical coverage maps focused purely on Prism's control flow.

See [`test/fuzz/patches/aflplusplus.md`](../test/fuzz/patches/aflplusplus.md) for a detailed walkthrough of the patch and `make fuzz-test` verification suite.

### Grammar-Guided Seed Generation (`lrama-fuzz` and `test/fuzz/runtime/grammar.rb`)

Byte-level mutations struggle to discover bugs that require syntactically rich Ruby constructs (such as nested heredocs, pattern matching, or endless method definitions inside blocks).

The `grammar` worker runs `test/fuzz/runtime/grammar.rb`, which uses [`lrama-fuzz`](https://github.com/kddnewton/lrama-fuzz) (`ComposedEvolver` and `Evolver`) derived directly from CRuby's `parse.y` grammar to evolve structurally rich valid and near-valid Ruby programs (including multi-heredoc and nested-heredoc rewrites). Each unique snippet is prefixed with the 4-byte options header, written atomically to `/tmp/afl-tmpdir/grammar/seeds` on `tmpfs`, imported into `ldet` via AFL++'s `-F` foreign sync whenever it discovers new CFG edges or IJON parser/lexer state transitions, and automatically pruned from `tmpfs` once scanned.

### CmpLog and `pm_strncasecmp`

The `main` worker runs with a companion CmpLog binary (`build/fuzz.cmplog`, built with `AFL_LLVM_CMPLOG=1`) that logs operands of comparisons so AFL++'s redqueen mutator can solve multi-byte magic strings without guessing byte-by-byte.

Prism normally uses its own `pm_strncasecmp` implementation (`src/strncasecmp.c`) for case-insensitive magic comments and encoding names. When compiling `build/fuzz.cmplog`, we pass `-Dpm_strncasecmp=strncasecmp` and exclude `src/strncasecmp.c` so calls go through libc `strncasecmp`, which AFL++'s CmpLog runtime hooks intercept automatically.

### IJON State-Guided Fuzzing (`PRISM_FUZZ_IJON`)

Many parser and lexer bugs in Prism depend on combinations of state stacks and bitflags (`parser->lex_modes`, `parser->current_context`, `parser->lex_state`, `parser->error_list`, `do_loop_stack`, `accepts_block_stack`, and `current_scope->parameters`) that pass through shared helper functions and therefore produce no new CFG edges on their own.

`build/fuzz.ldet` is compiled with `AFL_LLVM_IJON=1 -DPRISM_FUZZ_IJON`. In `test/fuzz/harness/parse.c`, this registers `fuzz_ijon_lex_callback` via `pm_parser_lex_callback_set` (requiring no changes to `src/`). On each token boundary where a tracked state changes, `FUZZ_IJON_SET` hashes the transition into AFL++'s 64 KB IJON bitmap region for:

1. Lexer mode stack transitions (top 4 modes in `parser->lex_modes`, including balanced delimiter nesting and heredoc quote/indent flags).
2. Parser context stack transitions (current and parent `pm_context_t` plus the enclosing `current_context->mask`).
3. Parser mode flags (`command_start`, `in_keyword_arg`, `in_endless_def_body`, `pattern_matching_newlines`, nesting counters, `do_loop_stack.top`, and `accepts_block_stack.top`) combined with `lex_state`.
4. Scope parameter, `closed`, and `shareable_constant` flags across the current and parent `pm_scope_t`.
5. Syntax error recovery transitions (`error_list.size`, `recovering`) and non-trivial `PM_TOKEN_EOF` states.

When `ldet` reaches a novel state combination and saves the input to `ldet/queue/`, `main` and `msan` automatically test that input under ASAN/UBSAN/MSAN during queue sync.

### Compile-Time Prism Tunings for Fuzzing

`test/fuzz/Makefile` sets several preprocessor flags when building the fuzz binaries:

- **Per-allocation arena redzones (`-DPM_ARENA_INITIAL_SIZE=0`)**: By default, `src/arena.c` bump-allocates AST nodes and strings out of 8 KB blocks, which hides intra-block buffer overflows from AddressSanitizer and MemorySanitizer. Sanitizer builds (`fuzz`, `fuzz.sand`, `fuzz.msan`, `fuzz.lsan`) set `-DPM_ARENA_INITIAL_SIZE=0` so `pm_arena_next_block_size` returns the exact requested size and every `pm_arena_alloc` call gets its own `xmalloc` heap block surrounded by ASAN/MSAN redzones. Non-sanitized builds (`fuzz.native`, `fuzz.ldet`, `fuzz.cmplog`, `fuzz.coverage`) keep the default 8 KB blocks so the normal arena growth and bump-allocation paths are also tested at full speed.
- **Reachable bignum divide-and-conquer (`-DPM_INTEGER_DIVIDE_THRESHOLD=8`)**: By default, `src/integer.c` only switches from schoolbook decimal parsing to divide-and-conquer parsing (and Karatsuba multiplication in `src/bignum.c`) above 224 chunks (2,017 digits), which cannot be reached within `FUZZ_MAX_INPUT_SIZE` (1,024 bytes). Lowering the threshold to 8 chunks (72 digits) exercises both schoolbook (20–72 digits) and divide-and-conquer / Karatsuba (73–1,020 digits) within the 1 KB input limit.
- **Reachable recursion depth limit (`-DPRISM_DEPTH_MAXIMUM=128`)**: Lowering `PRISM_DEPTH_MAXIMUM` from `10000` to `128` makes `PM_ERR_NESTING_TOO_DEEP` error-recovery paths in `parse_expression` and `parse_pattern` reachable within 1 KB inputs and prevents deeply nested expressions from causing quadratic indentation buffer growth in `pm_prettyprint`.
- **Write-only ASAN (`-mllvm -asan-instrument-reads=0`)**: `build/fuzz` and `build/fuzz.sand` disable ASAN read instrumentation so they only trap on illegal writes, UBSAN errors, and assertion failures, leaving out-of-bounds and uninitialized reads to `build/fuzz.msan`.
