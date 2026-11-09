# AFL++ Sanitizer-Free Coverage Patch (`aflplusplus.patch`)

[`aflplusplus.patch`](aflplusplus.patch) patches AFL++'s `SanitizerCoverageLTO.so` and `SanitizerCoveragePCGUARD.so` LLVM passes (along with shared helpers in `afl-llvm-common.cc`) so that compiler-inserted sanitizer checks and `assert()` branches do not pollute the fuzzer's edge coverage map.

## The Problem

In LTO mode (`afl-clang-lto`), Clang runs AddressSanitizer (ASAN), MemorySanitizer (MSAN), and UndefinedBehaviorSanitizer (UBSAN) during compilation (`-c`), **before** `SanitizerCoverageLTO.so` instruments the control-flow graph (CFG) during link-time optimization (`ld.lld`).

Every sanitizer check and `assert()` macro expands into conditional branches in the LLVM IR:

- **ASAN** inserts shadow-memory checks (`if (shadow != 0) __asan_report_*`) before memory accesses, plus stack-use-after-return (UAR) prologues (`__asan_option_detect_stack_use_after_return`, `__asan_stack_malloc_*`) and epilogues.
- **UBSAN** inserts overflow, shift, alignment, and bounds checks that branch to `__ubsan_handle_*` or `llvm.ubsantrap`.
- **MSAN** inserts shadow-propagation instructions (`select`, `icmp`) and uninitialized-read checks branching to `__msan_warning_with_origin_noreturn`.
- **`assert(expr)`** expands into `if (!expr) __assert_fail(...)`. Worse, compound assertions like `assert(A && B)` create short-circuit intermediate basic blocks where the failure path of `A` and the failure path of `B` both jump to the same `__assert_fail` block.

Because unpatched AFL++ sees these sanitizer and assertion branches as ordinary CFG edges:

1. **Coverage map bloat**: Instrumenting Prism with ASAN+UBSAN or MSAN inflates the number of instrumented edges by **40–130%** compared to an unsanitized build (`build/fuzz.native`).
2. **Broken dominator pruning**: AFL++ normally skips instrumenting a basic block if it is a *full dominator* of its successors (`isFullDominator`) or a *full post-dominator* with multiple predecessors (`isFullPostDominator`). When a basic block branches to both its normal continuation block and a sanitizer trap block, or when `SplitAllCriticalEdges` splits edges into shared trap blocks, the original program block is no longer a full dominator/post-dominator in the raw LLVM CFG—causing AFL++ to insert redundant coverage guards on straight-line code.
3. **Spurious coverage edges from MSAN shadow `select` and `icmp` instructions**: In addition to basic-block edges, AFL++ instruments branchless `select`, `icmp`, and `fcmp` instructions inline (`isAflCovInterestingInstruction`) by allocating two bitmap IDs (`id_true`, `id_false`), selecting between them with a `select` instruction, and incrementing `__afl_area_ptr[chosen_id]`. Under MSAN, LLVM emits `select` and `icmp` instructions purely to propagate and test uninitialized shadow bits, causing unpatched AFL++ to allocate two coverage bitmap slots for every shadow operation.

## What the Patch Does

### 1. Identifying Sanitizer Trap Calls and Trap Blocks (`isSanitizerTrapCall`, `isSanitizerTrapBlock`)

A call instruction is classified as a sanitizer/assertion trap if it invokes:

- `llvm.ubsantrap`, or `llvm.trap` carrying `!nosanitize` metadata
- `__assert_fail`, `__assert_perror_fail`, `__assert_rtn`, or `__assert`
- `__asan_report_*`, `__ubsan_handle_*`, `__msan_warning*`, `__hwasan_tag_mismatch*`, or `__cfi_check_fail*`

A basic block is classified as a trap block (`isSanitizerTrapBlock`) if it terminates in `unreachable` (or chains unconditionally within a few hops to one) and contains only sanitizer trap calls, lifetime intrinsics, or `!nosanitize` instructions.

### 2. Reconstructing the Pre-Sanitizer CFG (`analyzeSanitizerPreSplit`, `finalizeSanitizerCFG`)

Before `SplitAllCriticalEdges` runs, `analyzeSanitizerPreSplit` scans each function to collapse sanitizer-synthesized CFG structures back into the logical straight-line chains of the original program:

- **Fast-path / slow-path sanitizer checks**: When a block `X` branches conditionally to a normal continuation `Y` and either a trap block or a side-effect-free ASAN slow-path check block (`getSanitizerSlowPathTrap`) that itself branches to `Y` or a trap block, `X -> Y` is recorded as a single logical chain (`ChainNext[X] = Y`, `ChainPrev[Y] = X`), and the check/trap blocks are marked as internal skipped blocks.
- **Compound assertion chains (`assert(A && B)`)**: When a side-effect-free block `Y` only tests an additional condition and branches to the same trap block as its predecessor `X`, `Y` is folded into the chain so intermediate short-circuit `assert` clauses are not instrumented as separate program branches.
- **ASAN Stack-Use-After-Return (UAR) prologues and epilogues**: Recognizes the two-branch reconverging ("diamond") CFG blocks around `__asan_option_detect_stack_use_after_return` and `__asan_stack_malloc_*` (where a block `X` branches to two blocks that both jump to the same continuation block) and marks their internal blocks as skipped while chaining `X` directly to the continuation block.

After `SplitAllCriticalEdges` runs, `finalizeSanitizerCFG` marks any newly created critical-edge split blocks that lead into trap blocks or sanitizer check paths as skipped, and updates `shouldInstrumentBlock`, `isFullDominator`, and `isFullPostDominator` to evaluate dominance over the logical pre-sanitizer chains (`SanCFG->getHead(BB)` / `SanCFG->getTail(BB)`).

### 3. Skipping Sanitizer-Only `select` and `icmp` Instructions (`isSanitizerOnlyValue`)

When `isAflCovInterestingInstruction` decides whether to instrument a branchless `select`, `icmp`, or `fcmp` instruction inline, `isSanitizerOnlyValue` performs a forward dataflow walk over the instruction's users. If the result only flows into sanitizer trap branches, `__msan_*`/`__asan_*`/`__ubsan_*` runtime calls, shadow globals, or MSAN shadow pointer stores (`inttoptr`), `isAflCovInterestingInstruction` returns `false` so no coverage bitmap slots are allocated for it.

## Verification (`test_afl_patch.sh`)

Run `make fuzz-test` (which executes [`test_afl_patch.sh`](test_afl_patch.sh) inside the container) to verify the patch:

1. Compiles a multi-stage nested-`if` target (`maze.c`) containing compound assertions and arithmetic/array operations under `none`, `ubsan`, `asan+ubsan`, and `msan` with both unpatched and patched AFL++.
2. Verifies that patched edge counts match across sanitizer modes (`patched_msan == patched_none`, and `patched_asan_ubsan` within a few edges of `patched_none`).
3. Runs `afl-showmap` across progressive input prefixes (`"aaaaaaaa"` through `"PRISM_OK"`) to confirm every real program branch still produces a distinct coverage edge.
4. Runs live `afl-fuzz` without CmpLog or dictionaries against the patched ASAN+UBSAN and MSAN binaries to verify coverage feedback solves the 8-byte nested condition and triggers the target crash.

