# Fuzzing

We use coverage-guided fuzzing with [AFL++](https://aflplus.plus) to test `pm_parse` and its downstream consumers (`pm_serialize`, `pm_errors_format`, `pm_prettyprint`, and `pm_dump_json`). All fuzzing files live in `test/fuzz`:

```
test/fuzz
├── Makefile                      make targets for building, running, triaging, and coverage
├── dict                          an AFL++ dictionary containing Ruby tokens
├── docker
│   └── Dockerfile                for building a container with the fuzzer toolchain
├── harness
│   ├── coverage.c                driver for coverage collection
│   ├── fuzz.c                    generic entrypoint for fuzzing
│   ├── include
│   │   └── prism_xallocator.h    custom allocator header for fast leak detection
│   └── parse.c                   fuzz harness for parsing, serialization, and formatting
├── oss-fuzz
│   ├── Dockerfile                OSS-Fuzz builder image setup
│   ├── README.md                 OSS-Fuzz targets, usage, and differences from local fuzzing
│   ├── build.sh                  OSS-Fuzz build script (prism_parse_fuzzer and prism_full_fuzzer)
│   ├── prism_full_fuzzer.options options for the -DSLOW full pipeline target
│   ├── prism_parse_fuzzer.options options for the fast parse-only target
│   ├── project.yaml              OSS-Fuzz project metadata, engines, and sanitizers
│   └── test_oss_fuzz.sh          smoke test for OSS-Fuzz build and seed corpus replay
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
    ├── cluster.rb                  groups triaged buckets into root-cause clusters (clusters.json)
    ├── clustering.md               mathematical specification and calibration for cluster.rb
    ├── halfempty.sh                minimizes crash inputs with Google Project Zero's halfempty
    ├── halfempty_compare.sh        identifies similar backtraces during minimization
    ├── retriage.rb                 removes cured buckets and re-triages surviving failures into fresh buckets
    ├── signature.sh                hashes stack traces into a crash signature
    ├── test_triage.sh              verifies signature normalization, minimization, triage, and verification
    ├── triage.md                   implementation details for triage, metadata schemas, and verification
    ├── triage.rb                   deduplicates, minimizes, archives raw crashes, and writes C reproducers
    ├── verify.rb                   sweeps triaged buckets or root-cause clusters after a fix (PASS / PARTIAL / FAIL)
    ├── verify_bucket.sh            compiles verify_runner.<profile> and runs a bucket's archived inputs
    └── verify_runner.c             fast forked C batch runner for archived crashers
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
   Triage runs every crash and hang from `tmp/fuzz/afl/` and `tmp/fuzz/afl-ijon/` against the sanitizer binaries, deduplicates them by backtrace signature, minimizes a representative triggering input, archives **all** unique raw crash inputs for each bucket, and writes standalone C reproducers and verification scripts into `tmp/fuzz/triage/`.

### Where to Find Crashes and How to Reproduce

`make fuzz-triage` organizes unique bugs under `tmp/fuzz/triage/<category>/<signature>/`:

```
tmp/fuzz/triage
├── clusters.json                     <-- root-cause bucket clusters derived from metadata.json
├── metadata.json                     <-- global index of buckets, counts, and corpus/bucket coverage
└── ABRT                              <-- crash category (e.g., ABRT, SEGV, heap-buffer-overflow, memory-leak)
    └── 14a9275da317ddd6              <-- hash of the normalized backtrace
        ├── build.sh                  <-- executable compiler script with the exact flags for this crash
        ├── id:000000,sig:06,...      <-- original unminimized AFL++ crash input that created the bucket
        ├── input.min                 <-- minimized raw input (4-byte option header + Ruby source)
        ├── inputs.tar.gz             <-- archive of all unique raw crash inputs collapsed into this bucket
        ├── meta.json                 <-- structured metadata, decoded options, frames, and edge coverage
        ├── occurrences.jsonl         <-- append-only log of every unique raw crash seen in this bucket
        ├── testcase.c                <-- self-contained C program that reproduces the crash
        └── verify.sh                 <-- executable script to test input.min and inputs.tar.gz after a fix
```

Each `testcase.c` is synthesized as a minimal, self-contained `<prism.h>` program: `triage.rb` minimizes both the Ruby source and the 4-byte options header, emits only the non-default `pm_options_*` calls and the specific invariant or downstream consumer (`pm_serialize`, `pm_errors_format`, `pm_prettyprint`, or `pm_dump_json`) needed to trigger the crash, and includes a readable string dump, [Prism Loupe](https://stevenjohnstone.github.io/prism-loupe/) link, and captured sanitizer report in comments. Alongside it, `build.sh` compiles `testcase.c` into `testcase` with the specific sanitizer (`address,undefined`, `memory`, `leak`, or `undefined`) and compile-time `-D` tunings needed for that finding. (See [`test/fuzz/triage/triage.md`](../test/fuzz/triage/triage.md) for implementation details of the triage pipeline, metadata schemas, and archiving internals.)

To reproduce a triaged finding, you can either pass `input.min` directly to the prebuilt fuzzer binaries (inside `make fuzz-debug`) or run its generated `build.sh`:

```bash
# Replay input.min directly against a prebuilt fuzzer binary (inside make fuzz-debug):
./build/fuzz ./tmp/fuzz/triage/ABRT/14a9275da317ddd6/input.min

# Or compile and run the standalone testcase.c reproducer via its build.sh:
./tmp/fuzz/triage/ABRT/14a9275da317ddd6/build.sh
./tmp/fuzz/triage/ABRT/14a9275da317ddd6/testcase
```

> **Note:** `build.sh` locates the Prism repository root automatically (or accepts `PRISM_ROOT=/path/to/prism` if moved outside the checkout) and forwards any extra arguments (`"$@"`) to `${CC:-clang}`. If your host machine does not have `clang` with the required sanitizer (for example on macOS when reproducing `use-of-uninitialized-value` MSAN or `memory-leak` LSAN crashes), run `make fuzz-debug` to open an interactive shell inside the fuzzing container and run `./tmp/fuzz/triage/.../build.sh` there.

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

### Testing a Fix Across All Related Crashers

During triage, many distinct raw crashes (often hundreds or thousands) can collapse into a single signature bucket, while `halfempty.sh` only minimizes one representative crash into `input.min` and `testcase.c`. Checking only `./testcase` after writing a fix leaves a blind spot: your patch might cure the minimized `input.min` while an unminimized sibling archived in `inputs.tar.gz` still fails—either because your fix only handled the simplified case in `input.min`, or because two distinct root causes happened to share the same crash signature.

Every bucket therefore archives all of its unique raw crash inputs in `inputs.tar.gz` and ships with a verifier (`verify.sh` / `make fuzz-verify`) built directly against your current `src/` working tree.

#### Running Verification

After editing files under `src/`, `include/`, or `templates/` (templates are regenerated automatically):

```bash
# Verify all buckets belonging to a root-cause cluster (cluster ID, index, or any member bucket):
make fuzz-verify CLUSTER=cluster-01
make fuzz-verify CLUSTER=1
make fuzz-verify CLUSTER=ABRT/14a9275da317ddd6

# Verify a single bucket (tests input.min plus every archived crasher in inputs.tar.gz):
make fuzz-verify BUCKET=ABRT/14a9275da317ddd6

# Verify all buckets in a category (e.g., ABRT or undefined-behavior):
make fuzz-verify REASON=ABRT

# Verify every triaged bucket at once (add BY_CLUSTER=1 to group output and rollups by cluster):
make fuzz-verify
make fuzz-verify BY_CLUSTER=1
```

To inspect available clusters first:

```bash
make fuzz-verify VERIFY_ARGS=--list-clusters
```

When `clusters.json` is absent or older than `metadata.json`, `make fuzz-verify CLUSTER=...` / `BY_CLUSTER=1` automatically refreshes it via [`cluster.rb`](../test/fuzz/triage/cluster.rb) and tests each cluster's canonical representative bucket first.

`make fuzz-verify` regenerates templates automatically if any file under `templates/` (or `config.yml`) changed, and incrementally compiles only the lightweight C batch verifier (`build/verify/verify_runner.<profile>`) for the required sanitizer profiles (`asan_ubsan`, `msan_slow`, `lsan_slow`, `xallocator`)—it does **not** trigger a slow rebuild of the full AFL++ instrumentation suite. When working inside `make fuzz-debug`, you can also execute a bucket's `verify.sh` directly:

```bash
./tmp/fuzz/triage/ABRT/14a9275da317ddd6/verify.sh
```

Useful verification options (pass as env vars to `make fuzz-verify` or CLI flags to `verify.sh` / `verify.rb`):

- `CLUSTER=...` (`--cluster PATTERN`): Verify all buckets in matching root-cause cluster(s) (accepts cluster ID `cluster-01`, numeric shorthand `1`, or any member `bucket_id`/signature; comma-separated or repeatable). Exits non-zero if no cluster matches.
- `BY_CLUSTER=1` (`--by-cluster`): Group verification order, progress headers, and summary rollups by root-cause cluster.
- `CLUSTERS_FILE=...` (`--clusters-file PATH`): Override the default `<triage_dir>/clusters.json` file.
- `TRIAGE_DIR=...` (`--triage-dir DIR`): Verify against an alternate triage directory (default `tmp/fuzz/triage`).
- `VERIFY_SYMBOLIZE=1` (`--symbolize`): Enable external `llvm-symbolizer` output on failing inputs. Disabled by default so large buckets verify in seconds while still printing `INVARIANT[...]` descriptors and UBSAN `file:line:col` locations; turn on when you want symbolized stack traces on surviving crashes.
- `VERIFY_VERBOSE=1` (`--verbose`): Print every still-failing archived filename and failure headline rather than just the first few.
- `VERIFY_MAX_FAILURES=1` (`--max-failures 1`): Stop checking a bucket on its first failing archived input for quick `PASS` vs `PARTIAL`/`FAIL` checks.
- `VERIFY_TIMEOUT=10` (`--timeout 10`): Override the default 5-second per-input timeout.
- `VERIFY_UNREPRODUCIBLE=1` (`--include-unreproducible`): Include `unreproducible/` buckets in full sweeps (`BUCKET=...` and `REASON=unreproducible` already include them automatically).
- `VERIFY_INPUT_MIN_ONLY=1` (`--input-min-only`): Check only each bucket's minimized `input.min` (ignoring archived raw inputs in `inputs.tar.gz`). Useful when bisecting regressions across historical commits where old unminimized archive inputs fail on unrelated pre-existing bugs.
- `VERIFY_SKIP_MIN=1` (`--skip-min`): Skip `input.min` and check archived inputs only.
- `TARGET=/path/to/worktree` (`PRISM_TARGET=...`, `--target DIR`): Verify against another Prism checkout or `git worktree` (templates in the target tree are regenerated automatically, and `verify_runner` compiles against the target's `src/` and `include/` using this checkout's harnesses).
- `REV=<git-ref>` (`PRISM_REV=...`): Check out a git revision into a temporary detached worktree under `build/.fuzz-target-worktree` and run verification against it.
- `VERIFY_FAIL_FAST=1` (`--fail-fast`): Stop verifying further buckets after the first `FAIL` or `PARTIAL` bucket.
- `VERIFY_INVERT=1` (`--invert`): Invert the verdict exit code (`0` on `FAIL`/`PARTIAL`, `1` on `PASS`), useful when manually driving `git bisect run` to find a fix.

#### What the Results Mean (`PASS`, `PARTIAL`, `FAIL`, `EMPTY`)

`make fuzz-verify` tests `input.min` first, followed by every unique raw input archived in `inputs.tar.gz`, and reports one status per bucket:

- **`PASS`**: Both `input.min` and **every** archived raw crasher in `inputs.tar.gz` exited cleanly without sanitizer errors, invariant failures, memory leaks, or timeouts. All related crashes captured in the bucket are fixed.
- **`PARTIAL`** (`input.min PASSED, X/Y archived STILL FAIL!`): Your fix cured the minimized representative `input.min`, **but at least one archived raw input in `inputs.tar.gz` still fails**. This happens for one of three reasons:
  1. **Incomplete fix**: Your patch fixed the simplified pattern or options in `input.min`, while larger raw siblings still hit an unhandled branch, encoding, option combination (`pm_options_t`), or `-DSLOW` post-parse consumer.
  2. **Signature collision**: Two distinct bugs shared the same normalized crash signature (for example, the same `INVARIANT[...]` descriptor or top stack frames reached through different parser states) and your fix only resolved one of them.
  3. **Masked secondary bug**: Fixing the original crash allowed parsing to get further into a complex raw crasher and reach a different pre-existing bug.
- **`FAIL`**: `input.min` itself (and typically archived siblings) still fails with a crash, leak, or timeout. Re-run with `VERIFY_SYMBOLIZE=1 VERIFY_MAX_FAILURES=1` or rebuild `./testcase` via `build.sh` to inspect the remaining failure.
- **`EMPTY`**: No `input.min` or archived inputs were present in the bucket.

`make fuzz-verify` exits cleanly (`0`) only when all checked buckets report `PASS` (or `EMPTY`).

#### Investigating `PARTIAL` Fixes and Surviving Crashers

When a bucket reports `PARTIAL`, extract the raw inputs that still fail so you can inspect or re-triage them individually:

```bash
# Copy still-failing raw inputs to tmp/fuzz/survivors/<reason>/<signature>/
make fuzz-verify BUCKET=ABRT/14a9275da317ddd6 VERIFY_EXTRACT_SURVIVORS=tmp/fuzz/survivors
```

From there:

1. Inspect the surviving crash headlines and stack traces directly with `VERIFY_VERBOSE=1 VERIFY_SYMBOLIZE=1`:
   ```bash
   make fuzz-verify BUCKET=ABRT/14a9275da317ddd6 VERIFY_VERBOSE=1 VERIFY_SYMBOLIZE=1
   ```
2. Replay a specific survivor inside `make fuzz-debug` (after rebuilding the fuzzer binaries with `make fuzz-build`; use `./build/fuzz.msan` or `./build/fuzz.lsan` if `meta.json`'s `reproduced_by` says `fuzz.msan`/`fuzz.lsan`):
   ```bash
   ./build/fuzz tmp/fuzz/survivors/ABRT/14a9275da317ddd6/<sha256>
   ```
   Or minimize a single survivor cleanly while keeping its 4-byte options header:
   ```bash
   ./test/fuzz/triage/halfempty.sh ./build/fuzz tmp/fuzz/survivors/ABRT/14a9275da317ddd6/<sha256> /tmp/survivor.min
   ```
3. **Re-triage remaining failures into fresh buckets** (recommended whenever partial fixes shift backtraces/line numbers or unmask secondary bugs):
   ```bash
   # Preview what would be removed vs re-triaged:
   make fuzz-retriage RETRIAGE_DRY_RUN=1

   # Remove cured PASS buckets and replace failing/partial buckets with freshly triaged buckets:
   make fuzz-retriage

   # Or scope retriage to a single cluster/bucket:
   make fuzz-retriage CLUSTER=cluster-01
   ```
   `make fuzz-retriage` verifies the selected buckets first, marks cured raw hashes `#skip` in `.processed/` (so an uncleaned `tmp/fuzz/afl/` won't dump fixed crashes into `unreproducible/`), rebuilds the classifying fuzzer binaries if survivors remain, removes the cured and old stale buckets, and re-runs `triage.rb` + `cluster.rb` on only the still-failing inputs—giving every remaining bug fresh `input.min`, `testcase.c`, current line numbers, coverage maps, and `clusters.json` while preserving original AFL worker provenance in `occurrences.jsonl`.
4. Extend your fix until `make fuzz-verify BUCKET=...` / `make fuzz-retriage` leaves zero failing buckets, then run `make fuzz-build` and `make fuzz-test` (and optionally a fresh `make fuzz-run` campaign) before committing.

#### Verifying & Bisecting Against Earlier Revisions

Because the triage buckets and harnesses (`test/fuzz/`) live in your current branch, checking out an older Prism revision directly would lose or downgrade the verifier. Instead, pass an external worktree (`TARGET=...`) or git revision (`REV=...`):

```bash
# Verify a bucket or cluster against a specific revision using an auto-managed worktree:
make fuzz-verify REV=main CLUSTER=cluster-01

# Or verify against your own git worktree (`git worktree add ../prism-old <rev>`):
make fuzz-verify TARGET=../prism-old BUCKET=ABRT/14a9275da317ddd6
```

To automate `git bisect` without disturbing your working tree, use `make fuzz-bisect` (which creates a temporary detached worktree, checks endpoints first, uses `--fail-fast --max-failures 1` per step, and cleans up automatically). By default, every retained input (`input.min` and `inputs.tar.gz`) is tested at each step; pass `VERIFY_INPUT_MIN_ONLY=1` (`--input-min-only`) when bisecting regressions against only each bucket's minimized `input.min` (or `VERIFY_SKIP_MIN=1` / `--skip-min` for archived inputs only). When bisecting a `CLUSTER` or multiple buckets, `bisect.rb` automatically runs a non-`--fail-fast` check (`--max-failures 0`) on the identified commit and its parent (plus the `BAD`/`BROKEN` endpoint when split buckets remain) and warns if only a subset of the cluster transitioned there:

```bash
# Find which commit introduced a failure (good -> bad):
make fuzz-bisect GOOD=main~100 BAD=HEAD BUCKET=ABRT/14a9275da317ddd6

# Bisect a cluster using only minimized input.min representatives (ignores archived inputs):
make fuzz-bisect GOOD=main~100 BAD=HEAD CLUSTER=cluster-01 VERIFY_INPUT_MIN_ONLY=1

# Find which commit fixed an existing failure (broken -> fixed):
make fuzz-bisect BROKEN=main~50 FIXED=HEAD CLUSTER=cluster-01
```

Compatibility & skip behavior across revisions:
- [`verify_bucket.sh`](../test/fuzz/triage/verify_bucket.sh) regenerates target templates automatically whenever `config.yml` or `templates/` changes, and probes 2024–2026 Prism C API differences across headers (pre-opaque struct vs. opaque pointer APIs for options/arena/parser/buffer/diagnostics/comments, `pm_newline_list_t` vs. `pm_line_offset_list_t`, pointer vs. offset `pm_location_t`, list/iterator/`_each`/`_first` traversal, optional options setters, and optional visitor/stream/`pm_errors_format`/`pm_dump_json` helpers) so [`parse.c`](../test/fuzz/harness/parse.c) compiles across historical commits. [`bisect.rb`](../test/fuzz/triage/bisect.rb) also restores clean tracked state in the temporary worktree after each step so regenerated non-C template files cannot abort `git bisect` checkouts.
- Commits lacking the core Prism C parser APIs (`pm_parse` and `pm_parser_new`/`pm_parser_init`), or commits that fail template generation or compilation, exit **`125`**, causing `git bisect` to skip them automatically.

For implementation details on cross-worker replay normalization, signature hashing, `inputs.tar.gz` compaction, `meta.json` / `metadata.json` schemas, and `verify_runner.c`, see [`test/fuzz/triage/triage.md`](../test/fuzz/triage/triage.md).

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

### Telemetry Plots, Crash Lineage, and Source Coverage

- **Unified telemetry, crash lineage, & coverage dashboard**:
  ```bash
  make fuzz-plot
  open tmp/fuzz/plots/index.html
  ```
  `make fuzz-plot` automatically runs `test/fuzz/report/coverage.sh` if `tmp/fuzz/coverage/coverage.json` is missing or older than the queues in `tmp/fuzz/afl` or `tmp/fuzz/afl-ijon` (set `FUZZ_SKIP_COVERAGE=1` to skip coverage collection).

  The generated dashboard (`tmp/fuzz/plots/index.html`) includes:
  - **Fleet Overview & Peer Sync Telemetry**: Interactive time-series charts for coverage growth, throughput, corpus size, and pending queue items, plus a cross-worker sync yield breakdown showing how each worker's queue discoveries are tested and imported by peers.
  - **Crash Lineage & Multi-Worker Evolution (`Origin → ... → Crash Discoverer`)**: Because AFL++ preserves every queue item across `tmp/fuzz/afl/<worker>/queue/` and `tmp/fuzz/afl-ijon/ijon/queue/` (including unmutated copies of `-F` grammar seeds imported into `ijon/queue/` before `grammar.rb` prunes the temporary staging file), `test/fuzz/report/plot.rb` walks backwards from every saved crash/hang file through local mutation pointers (`src:NNNNNN`), foreign sync pointers (`sync:ijon_0,src:id:NNNNNN`), and peer sync pointers (`sync:<peer>,src:NNNNNN`) all the way to the root seed (`corpus` vs. `grammar`):
    - Breaks down all crashes by their full multi-worker evolutionary pathway (e.g., `★ grammar → ijon → main` or `corpus → main → main-7 → main → msan`).
    - Clicking any pathway (or any crash-producing seed on the `#grammar` tab) expands an inline **Step-by-Step Testcase Evolution** chain showing `Step 0 (Root Seed)` → intermediate queue mutations/syncs (`op:flip2`, `op:havoc`, decoded 4-byte `opts:` header, byte size) → final `Crash`, with the formatted Ruby snippet at each step.
    - Every step in the evolution chain (as well as every triaged `testcase.c`) includes an **Animate in [Prism Loupe](https://stevenjohnstone.github.io/prism-loupe/) ↗** link (`?code=<base64>` plus explicit `pm_options_t` / `stream` query parameters decoded from the 4-byte options header) so you can watch Prism's lexer mode stack, parser context stack, recursive-descent call stack, and line offsets animate step by step under the exact fuzzing options for the root seed, any intermediate mutation, or the crashing testcase.
    - On the `#grammar` tab, tracks fleet-wide queue propagation (`grammar → ijon → main → main-* / msan`) and lists every `lrama-fuzz` seed that produced a crash alongside direct Prism Loupe links for both the generated seed and the crash.
  - **Per-Origin LLVM Source Coverage & Exclusive Code Hunks**: Partitions all campaign inputs by root origin (`corpus`, `grammar`, `main`, `ijon`, `msan`, `main-2..N`) and computes three metrics per origin:
    1. **Standalone coverage**: lines/branches covered by that origin's inputs alone.
    2. **Gain vs. Corpus**: marginal lines/branches added when merged with the initial seed corpus (`merge(corpus, origin) - corpus`).
    3. **Exclusive coverage (`combined - merge(all_other_origins)`)**: lines and branches uniquely covered *only* by that worker/generator.
    - Clicking any file with exclusive coverage (on the **Source Coverage** tab or on a worker's tab) opens an inline C source code drawer showing the exact exclusive lines (`LINE Nx`) and conditional branch outcomes (`BR → True (Nx)` / `BR → False (Nx)`), with exact sub-expression highlighting on compound `&&`/`||` lines and macro expansion resolution (e.g., showing which `case` inside `PM_CASE_KEYWORD` matched).
- **Standalone coverage collection**:
  ```bash
  make fuzz-coverage
  ```
  `make fuzz-coverage` prints the combined per-file coverage table to the terminal, updates `tmp/fuzz/plots/index.html`, and writes:
  - `tmp/fuzz/coverage/lcov.info` — workspace-relative LCOV line, function, and branch coverage for IDE integration:
    - **VS Code / Cursor / Antigravity**: Install [Coverage Gutters](https://marketplace.visualstudio.com/items?itemName=ryanluker.vscode-coverage-gutters) and run *Coverage Gutters: Display Coverage* (or *Watch*) to highlight covered/uncovered lines and branches inline in the editor.
    - **CLion**: Use *Run -> Show Coverage Data...* (`Cmd+Option+F6` / `Ctrl+Alt+F6`) and select `tmp/fuzz/coverage/lcov.info`.
    - **Neovim**: Point [`nvim-coverage`](https://github.com/andythigpen/nvim-coverage) (`lcov_file`) at `tmp/fuzz/coverage/lcov.info`.
  - `tmp/fuzz/coverage/report/index.html` — combined annotated HTML source report (`open tmp/fuzz/coverage/report/index.html`).
  - `tmp/fuzz/coverage/workers/<origin>/report/index.html` — per-origin annotated HTML source reports (`corpus`, `grammar`, `main`, `ijon`, `msan`, `main-2..N`), post-processed to highlight exclusive lines/branches inline and add a `next exclusive to <origin> (E)` keyboard shortcut (`E`).
  - `tmp/fuzz/coverage/coverage.json` — structured JSON breakdown of combined and per-origin coverage, gains over `corpus`, and exclusive leave-one-out source hunks and branch outcomes.
  - `tmp/fuzz/coverage/coverage.profdata` — merged LLVM profile data for custom `llvm-cov` queries.
  - `tmp/fuzz/coverage/summary.txt` — saved copy of the terminal summary table.

### Cleaning Up

To delete the current campaign data (`tmp/fuzz/afl`, `tmp/fuzz/afl-ijon`, `tmp/fuzz/corpus`, `tmp/fuzz/seeds`, `tmp/fuzz/coverage`, and `tmp/fuzz/plots`) while keeping already-triaged bugs and their `inputs.tar.gz` archives in `tmp/fuzz/triage`:

```bash
make fuzz-clean
```

Run `make fuzz-triage` before `make fuzz-clean` if your campaign has untriaged crashes or hangs so both minimized reproducers and archived raw crashers are preserved for `make fuzz-verify`.

### OSS-Fuzz Integration

Standalone OSS-Fuzz configuration lives in [`test/fuzz/oss-fuzz/`](../test/fuzz/oss-fuzz/README.md) (`project.yaml`, `Dockerfile`, `build.sh`, and `.options` for `prism_parse_fuzzer` and `prism_full_fuzzer`). It builds both parse-only and `-DSLOW` targets without local AFL++ IJON/`lrama-fuzz`/`tmux` infrastructure while reusing `test/fuzz/harness/parse.c`, `test/fuzz/harness/fuzz.c`, `test/fuzz/dict`, and `test/fuzz/runtime/corpus.rb --no-minimize`.

### Testing the Fuzzing Infrastructure

To run the automated regression suites for the custom AFL++ instrumentation patch (`test/fuzz/patches/test_afl_patch.sh`), crash triage, archiving, and post-fix verification pipeline (`test/fuzz/triage/test_triage.sh`), grammar seed generator (`test/fuzz/runtime/test_grammar.sh`), and OSS-Fuzz build/corpus smoke test (`test/fuzz/oss-fuzz/test_oss_fuzz.sh`):

```bash
make fuzz-test
```

---

## Technical Details

For background on coverage-guided greybox fuzzing and AFL++, see:

- [The Fuzzing Book — Greybox Fuzzing](https://www.fuzzingbook.org/html/GreyboxFuzzer.html) and [Mutation-Based Fuzzing](https://www.fuzzingbook.org/html/MutationFuzzer.html)
- [AFL++ Documentation](https://aflplus.plus/docs/) and [Best Practices](https://aflplus.plus/docs/best_practices/)

### Harness and Input Format (`test/fuzz/harness/parse.c`)

Every fuzz input begins with a **4-byte options header** consumed by `harness()` before the remaining bytes are passed to `harness_parse()` as Ruby source:

| Byte | Bits | Option Mapped to `pm_options_t` |
| :--- | :--- | :--- |
| `input[0]` | `0..5`, `6`, `7` | Boolean flags (`freeze`, `partial_script`, `attach_comments`, `encoding_locked`, `has_frozen_string_literal`, `frozen_string_literal`), `stream_mode` (`pm_parse_stream`), and `has_encoding_opts` (`pm_options_encoding_set`, `filepath`, `shebang_callback`, outer-scope forwarding / 0-local scope) |
| `input[1]` | `0..5`, `6`, `7` | Command-line flags (`-a`, `-e`, `-l`, `-n`, `-p`, `-x`), `main_script`, and `has_limit_opts` (`stack_budget` + extreme `int32_t` `start_line`) |
| `input[2]` | `0..1`, `2..3`, `4..7` | Ruby syntax version (`3.3`, `3.4`, `3.5`, `4.1`), enclosing `scopes_count` (`0..3`), and parameter forwarding flags (`*`, `**`, `&`, `...`) |
| `input[3]` | `0..7` | Signed `start_line` (`-128..127` when `has_limit_opts` is unset) and `aux_byte` selector for `has_encoding_opts` / `has_limit_opts` |

Putting options in the input header lets AFL++ mutate parser configuration alongside Ruby syntax so version-specific grammar rules, streaming input (`pm_parse_stream`), non-UTF-8 initial encodings, shebang callbacks, stack budgets, `int32_t` line boundaries, command-line loops (`-n`/`-p`), and local scope forwarding are all explored automatically.

After `pm_parse()` or `pm_parse_stream()` returns, `harness_parse()` checks four post-parse invariants against the parsed source length (`parsed_size`) on every run:

1. **Monotonic line offsets**: Verifies that `parser->line_offsets` starts at `0`, is strictly increasing, and never exceeds `parsed_size`.
2. **AST location bounds (`check_node_location`)**: Walks the entire AST with `pm_visit_node` and aborts if any node span exceeds `parsed_size`.
3. **Diagnostic and magic-comment span bounds**: Verifies every error, warning, and magic-comment key/value location fits within `parsed_size`.
4. **Comment span bounds and `attach_comments` sort order**: Verifies every comment location fits within `parsed_size` and, when `attach_comments` is set, that comments are ordered monotonically by `start` offset.

Because these checks run after `pm_parse()` / `pm_parse_stream()` has unwound, `fuzz_invariant_fail()` prints a position-independent `INVARIANT[...]` descriptor to `stderr` (such as the diagnostic type, AST node type, comment/magic-comment kind, or lexical line-offset context, followed by raw offsets in `[detail: ...]`) right before calling `abort()`. `test/fuzz/triage/signature.sh` strips `[detail: ...]` and hashes the `INVARIANT[...]` descriptor so `triage.rb` and `halfempty` separate distinct invariant bugs while still minimizing away unrelated surrounding Ruby code.

### Parse-Only Fast Workers vs. `-DSLOW` Post-Processing

Running `pm_serialize`, `pm_errors_format`, `pm_prettyprint`, and `pm_dump_json` on every fuzzing iteration would slow down parser exploration and pollute the coverage bitmap with output-formatter edges. We split the build into two modes:

- **Fast parse-only binaries** (`build/fuzz`, `build/fuzz.native`, `build/fuzz.ijon`, `build/fuzz.sand`, `build/fuzz.cmplog`): Compiled with `-DPRISM_EXCLUDE_SERIALIZATION -DPRISM_EXCLUDE_JSON -DPRISM_EXCLUDE_PRETTYPRINT`. They only run `pm_parse` and the AST/line-offset invariant checks.
- **Slow full-pipeline binaries** (`build/fuzz.msan`, `build/fuzz.lsan`, and `build/fuzz.coverage`): Compiled with `-DSLOW`, which additionally runs `pm_serialize`, `pm_errors_format` (plain and color), `pm_prettyprint`, and `pm_dump_json` on every input. Because these serializers and printers read every AST node, token, error, and line offset, running them under MemorySanitizer (`fuzz.msan`) catches uninitialized fields anywhere in the parse tree.

### Worker Fleet Architecture and Sync Topology

`test/fuzz/runtime/run.sh` launches `FUZZ_WORKERS` workers across two single-master AFL++ sync directories (`tmp/fuzz/afl-ijon` and `tmp/fuzz/afl`):

```
/tmp/afl-tmpdir/grammar/seeds     tmp/fuzz/afl-ijon             tmp/fuzz/afl
┌───────────────────────────┐    ┌──────────────────┐         ┌──────────────────┐
│ grammar (lrama-fuzz)      ├───►│ -M ijon          ├────────►│ -M main          │
│ ~500 Ruby seeds/s + USR2  │ -F │ (fuzz.ijon)      │  peer   │ (ASAN+UBSAN +    │
└───────────────────────────┘    └──────────────────┘         │  fuzz.cmplog)    │
                                                              └────────▲─────────┘
                                                                       │ peer sync
                                                                       │ (-M / -S)
                                                       ┌───────────────┴───────────────┐
                                                       ▼                               ▼
                                              ┌──────────────────┐           ┌──────────────────┐
                                              │ -S msan          │           │ -S main-2 .. N   │
                                              │ (fuzz.msan SLOW) │           │ (fuzz.native +   │
                                              └──────────────────┘           │  -w fuzz.sand)   │
                                                                             └──────────────────┘
```

 AFL++ restricts `-F` (foreign testcase import) to `-M` master instances, and inside `sync_fuzzers()` a `-M` node scans every peer queue in its `-o` sync directory *before* calling `read_foreign_testcases()`. Keeping two separate single-master sync roots avoids multi-master contention:

- In `tmp/fuzz/afl-ijon`, `-M ijon` has **no** peer queues to scan, so every foreign sync goes straight to `/tmp/afl-tmpdir/grammar/seeds` at native speed (~45k execs/s) and filters generated Ruby snippets by both CFG edges and IJON parser/lexer state transitions.
- In `tmp/fuzz/afl`, `-M main` is the sole master: it imports `ijon`'s curated queue sequentially via a one-way shadow peer directory (`tmp/fuzz/afl/ijon_peer/queue -> ../../afl-ijon/ijon/queue`, with no `is_main_node` marker so `-S` secondaries skip it while `main` tracks exact `id:NNNNNN` cursors in `.synced/ijon_peer` without 1-second `-F` `mtime` loss) and exchanges queue discoveries bidirectionally with `-S msan` and `-S main-2..N`. (When `FUZZ_WORKERS < 4`, `ijon` is omitted and `main` ingests `/tmp/afl-tmpdir/grammar/seeds` directly via `-F`.)

The workers are:

1. **`main`** (`build/fuzz` + `build/fuzz.cmplog`): Primary ASAN+UBSAN master (`-M main -o tmp/fuzz/afl`) with CmpLog enabled, seeded with the full minimized fixture corpus and pulling filtered discoveries from `ijon` via `ijon_peer`.
2. **`grammar`** (`test/fuzz/runtime/grammar.rb`): Structure-aware Ruby seed generator powered by [`lrama-fuzz`](https://github.com/kddnewton/lrama-fuzz), writing candidate seeds to `/tmp/afl-tmpdir/grammar/seeds` and nudging `ijon` via `SIGUSR2`.
3. **`msan`** (`build/fuzz.msan`): Secondary worker (`-S msan`) running the full `-DSLOW` pipeline under MemorySanitizer to catch uninitialized memory reads and out-of-bounds reads across parsing, serialization, pretty-printing, and JSON dumping.
4. **`ijon`** (`build/fuzz.ijon`): Isolated native master (`-M ijon -o tmp/fuzz/afl-ijon -F /tmp/afl-tmpdir/grammar/seeds`) with custom leak detection and IJON state-guided instrumentation enabled, acting as a high-throughput state-space filter for grammar seeds and exploring mutations with `-p explore` before `main` imports its winners.
5. **`main-2 .. main-N`** (`build/fuzz.native` + `-w ./build/fuzz.sand`): Secondary workers (`-S main-2..N`) running AFL++ **SAND** (`AFL_SAN_ABSTRACTION=coverage_increase`). They execute mutations at native speed without sanitizer overhead, and only forward inputs that discover new coverage to the forkserver-only ASAN+UBSAN binary (`build/fuzz.sand`). Secondary workers cycle through different AFL++ power schedules (`explore`, `fast`, `coe`, `lin`, `quad`, `exploit`, `rare`, `mmopt`), mutation modes (MOpt `-L 0`, `-P explore/exploit`, `-Z`), and disjoint shards of the initial seed corpus.

### Fast Leak Detection (`PRISM_XALLOCATOR`)

Enabling LeakSanitizer (LSAN) or ASAN per-allocation redzones on every fuzzing execution significantly reduces throughput on inputs that allocate deep ASTs.

For `build/fuzz.native` and `build/fuzz.ijon`, we compile without sanitizers and enable Prism's custom allocator hook (`-DPRISM_XALLOCATOR -Itest/fuzz/harness/include`). `test/fuzz/harness/include/prism_xallocator.h` routes `xmalloc`, `xcalloc`, `xrealloc`, `xrealloc_sized`, `xfree`, and `xfree_sized` to wrappers in `test/fuzz/harness/fuzz.c` that prepend a 16-byte naturally aligned size header to each allocation, assert that sized frees and reallocations pass the exact recorded size, and maintain a running `allocated` byte counter. At the end of `LLVMFuzzerTestOneInput`, `assert(allocated == 0)` immediately aborts if any memory was leaked during the parse, with near-zero runtime overhead. Wrappers also enforce a per-input cumulative allocation cap (`FUZZ_MAX_ALLOCATED_BYTES`, 128 MiB) to catch exponential memory-blowup bugs early.

When `make fuzz-triage` processes a leak crash from `fuzz.ijon` or `fuzz.native`, it re-runs the input against `build/fuzz.lsan` so the generated `testcase.c` includes a full LeakSanitizer allocation backtrace.

### Sanitizer-Free Coverage Instrumentation (`test/fuzz/patches/aflplusplus.patch`)

When Clang compiles code with ASAN, UBSAN, or MSAN before LTO linking, it injects thousands of conditional branches for shadow-memory checks, overflow traps, stack-use-after-return prologues, MSAN shadow `select`s, and `assert()` macros. Out of the box, AFL++ instruments all of those compiler-generated branches, inflating the coverage map by 40–130% and breaking dominator-based block pruning.

During `make fuzz-build`, `test/fuzz/Makefile` applies [`test/fuzz/patches/aflplusplus.patch`](../test/fuzz/patches/aflplusplus.patch) to AFL++'s LTO and PCGUARD passes so sanitizer checks and `assert()` traps are invisible to coverage instrumentation. As a result, `fuzz`, `fuzz.msan`, `fuzz.lsan`, and `fuzz.native` share nearly identical coverage maps focused purely on Prism's control flow.

See [`test/fuzz/patches/aflplusplus.md`](../test/fuzz/patches/aflplusplus.md) for a detailed walkthrough of the patch and `make fuzz-test` verification suite.

### Grammar-Guided Seed Generation (`lrama-fuzz` and `test/fuzz/runtime/grammar.rb`)

Byte-level mutations struggle to discover bugs that require syntactically rich Ruby constructs (such as nested heredocs, pattern matching, or endless method definitions inside blocks).

The `grammar` worker runs `test/fuzz/runtime/grammar.rb`, which uses [`lrama-fuzz`](https://github.com/kddnewton/lrama-fuzz) (`ComposedEvolver` and `Evolver`) derived directly from CRuby's `parse.y` grammar to evolve structurally rich valid and near-valid Ruby programs (including multi-heredoc and nested-heredoc rewrites). Each unique snippet is prefixed with the 4-byte options header, written atomically to `/tmp/afl-tmpdir/grammar/seeds` on `tmpfs`, imported into `ijon` via AFL++'s `-F` foreign sync whenever it discovers new CFG edges or IJON parser/lexer state transitions (`grammar.rb` sends `SIGUSR2` to `ijon` to trigger immediate syncs), and automatically pruned from `tmpfs` once scanned. On container shutdown, `run.sh` persists up to 5,000 unread pending seeds to `tmp/fuzz/seeds` so post-run `make fuzz-coverage` and subsequent resumed runs retain unimported seeds. Because `ijon` writes an unmutated copy of each imported seed to `tmp/fuzz/afl-ijon/ijon/queue/id:NNNNNN,sync:seeds_0,src:<sha1>`, the original generated seed remains preserved in `ijon/queue/` even after `tmpfs` pruning, allowing `make fuzz-plot` to trace downstream queue entries and crashes across `grammar → ijon → main → secondaries` all the way back to the exact `lrama-fuzz` seed.

### CmpLog and `pm_strncasecmp`

The `main` worker runs with a companion CmpLog binary (`build/fuzz.cmplog`, built with `AFL_LLVM_CMPLOG=1`) that logs operands of comparisons so AFL++'s redqueen mutator can solve multi-byte magic strings without guessing byte-by-byte.

Prism normally uses its own `pm_strncasecmp` implementation (`src/strncasecmp.c`) for case-insensitive magic comments and encoding names. When compiling `build/fuzz.cmplog`, we pass `-Dpm_strncasecmp=strncasecmp` and exclude `src/strncasecmp.c` so calls go through libc `strncasecmp`, which AFL++'s CmpLog runtime hooks intercept automatically.

### IJON State-Guided Fuzzing (`PRISM_FUZZ_IJON`)

Many parser and lexer bugs in Prism depend on combinations of state stacks and bitflags (`parser->lex_modes`, `parser->current_context`, `parser->lex_state`, `parser->error_list`, `do_loop_stack`, `accepts_block_stack`, and `current_scope->parameters`) that pass through shared helper functions and therefore produce no new CFG edges on their own.

`build/fuzz.ijon` is compiled with `AFL_LLVM_IJON=1 -DPRISM_FUZZ_IJON`. In `test/fuzz/harness/parse.c`, this forces `stream_mode = false` (since `pm_parse_stream` constructs and runs its internal `pm_parser_t` without exposing a pre-parse hook, and non-IJON workers already cover `pm_parse_stream`) and registers `fuzz_ijon_lex_callback` via `pm_parser_lex_callback_set` on every execution (requiring no changes to `src/`). On each token boundary where a tracked state changes, `FUZZ_IJON_SET` hashes the transition into AFL++'s IJON bitmap region (while `FUZZ_IJON_MAX` tracks maximum lexer-mode and parser-context stack depths) for:

1. Lexer mode stack transitions (top 4 modes in `parser->lex_modes`, including balanced delimiter nesting and heredoc quote/indent flags).
2. Parser context stack transitions (current and parent `pm_context_t` plus the enclosing `current_context->mask`).
3. Parser mode flags (`command_start`, `in_keyword_arg`, `in_endless_def_body`, `pattern_matching_newlines`, nesting counters, `do_loop_stack.top`, and `accepts_block_stack.top`) combined with `lex_state`.
4. Scope parameter, `closed`, and `shareable_constant` flags across the current and parent `pm_scope_t`.
5. Syntax error recovery transitions (`error_list.size`, `recovering`) and non-trivial `PM_TOKEN_EOF` states.

When `ijon` reaches a novel state combination and saves the input to `tmp/fuzz/afl-ijon/ijon/queue/`, `main` imports interesting entries via `tmp/fuzz/afl/ijon_peer` under ASAN+UBSAN and redistributes them to `msan` and `main-2..N` via peer sync.

### Compile-Time Prism Tunings for Fuzzing

`test/fuzz/Makefile` sets several preprocessor flags when building the fuzz binaries:

- **Per-allocation arena redzones (`-DPM_ARENA_INITIAL_SIZE=0`)**: By default, `src/arena.c` bump-allocates AST nodes and strings out of 8 KB blocks, which hides intra-block buffer overflows from AddressSanitizer and MemorySanitizer. Sanitizer builds (`fuzz`, `fuzz.sand`, `fuzz.msan`, `fuzz.lsan`) set `-DPM_ARENA_INITIAL_SIZE=0` so `pm_arena_next_block_size` returns the exact requested size and every `pm_arena_alloc` call gets its own `xmalloc` heap block surrounded by ASAN/MSAN redzones. Non-sanitized builds (`fuzz.native`, `fuzz.ijon`, `fuzz.cmplog`, `fuzz.coverage`) keep the default 8 KB blocks so the normal arena growth and bump-allocation paths are also tested at full speed.
- **Reachable bignum divide-and-conquer (`-DPM_INTEGER_DIVIDE_THRESHOLD=8`)**: By default, `src/integer.c` only switches from schoolbook decimal parsing to divide-and-conquer parsing (and Karatsuba multiplication in `src/bignum.c`) above 224 chunks (2,017 digits), which cannot be reached within `FUZZ_MAX_INPUT_SIZE` (1,024 bytes). Lowering the threshold to 8 chunks (72 digits) exercises both schoolbook (20–72 digits) and divide-and-conquer / Karatsuba (73–1,020 digits) within the 1 KB input limit.
- **Reachable recursion depth limit (`-DPRISM_DEPTH_MAXIMUM=128`)**: Lowering `PRISM_DEPTH_MAXIMUM` from `10000` to `128` makes `PM_ERR_NESTING_TOO_DEEP` error-recovery paths in `parse_expression` and `parse_pattern` reachable within 1 KB inputs and prevents deeply nested expressions from causing quadratic indentation buffer growth in `pm_prettyprint`.
- **Write-only ASAN (`-mllvm -asan-instrument-reads=0`)**: `build/fuzz` and `build/fuzz.sand` disable ASAN read instrumentation so they only trap on illegal writes, UBSAN errors, and assertion failures, leaving out-of-bounds and uninitialized reads to `build/fuzz.msan`.
