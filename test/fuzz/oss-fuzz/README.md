# OSS-Fuzz Integration for Prism

This directory holds the [OSS-Fuzz](https://github.com/google/oss-fuzz) project definition for standalone Prism (`ruby/prism`), adapted from the local AFL++ harness in `test/fuzz/`.

## Layout

- [`project.yaml`](project.yaml) — OSS-Fuzz metadata (`c` language, `libfuzzer`/`afl`/`honggfuzz`/`centipede` engines, `address`/`undefined`/`memory` sanitizers). Update `primary_contact` to a Google-account email before opening a PR against `google/oss-fuzz`.
- [`Dockerfile`](Dockerfile) — Based on `gcr.io/oss-fuzz-base/base-builder`; installs `ruby` (used only for stdlib `templates/template.rb` and `test/fuzz/runtime/corpus.rb --no-minimize`) and `zip`.
- [`build.sh`](build.sh) — Regenerates C sources/headers via `ruby templates/template.rb`, compiles both fuzz targets with `$CC $CFLAGS` and `-std=c99` (linking `$LIB_FUZZING_ENGINE` with `$CXX $CXXFLAGS`), installs `<target>.dict` and `<target>.options`, and packs `<target>_seed_corpus.zip`.
- [`prism_parse_fuzzer.options`](prism_parse_fuzzer.options) — Runtime options (`max_len = 8192`, dictionary) for the fast parse/AST-traversal target.
- [`prism_full_fuzzer.options`](prism_full_fuzzer.options) — Runtime options (`max_len = 1024`, dictionary) for the `-DSLOW` serialization/formatting/prettyprint/JSON target.

## Fuzz Targets

1. **`prism_parse_fuzzer`** (`-DPRISM_EXCLUDE_SERIALIZATION -DPRISM_EXCLUDE_JSON -DPRISM_EXCLUDE_PRETTYPRINT`): Exercises parsing (both `pm_parse` and `pm_parse_stream`), options decoding via the 4-byte input header, AST visitation, comments, diagnostics, and encoding handling up to `max_len = 8192`.
2. **`prism_full_fuzzer`** (`-DSLOW`): Adds `pm_serialize_parse`, `pm_serialize_parse_stream`, `pm_errors_format`, `pm_prettyprint`, and `pm_dump_json` checks up to `max_len = 1024`.

Both targets reuse [`test/fuzz/harness/parse.c`](../harness/parse.c), [`test/fuzz/harness/fuzz.c`](../harness/fuzz.c), [`test/fuzz/dict`](../dict), and [`test/fuzz/runtime/corpus.rb`](../runtime/corpus.rb). Building with `-DPRISM_OSS_FUZZ` omits `__asan_default_options()` and `__ubsan_default_options()` in `fuzz.c` so ClusterFuzz controls sanitizer flags cleanly via environment variables. Compile-time fuzzing tunings (`-DPM_ARENA_INITIAL_SIZE=0`, `-DPM_INTEGER_DIVIDE_THRESHOLD=8`, `-DPRISM_DEPTH_MAXIMUM=128`) match `test/fuzz/Makefile`.

## Differences from Local `make fuzz-run`

The local `make fuzz-run` Docker setup uses custom components that are intentionally omitted from OSS-Fuzz:

- **IJON state instrumentation (`PRISM_FUZZ_IJON`)** and **`test/fuzz/patches/aflplusplus.patch`** rely on custom AFL++ compiler passes and forks not present in stock `oss-fuzz-base/base-builder`, and `ijon_set`/`ijon_max`/`ijon_hashstr` do not exist in non-AFL engines (`libfuzzer`, `honggfuzz`, `centipede`).
- **Grammar seed worker (`test/fuzz/runtime/grammar.rb` / `lrama-fuzz`)**, **`PRISM_XALLOCATOR`** fast leak checks, and the **`tmux` fleet** are local-only; OSS-Fuzz uses its own scheduler across engines (`libfuzzer`, `afl`, `honggfuzz`, `centipede`) and LeakSanitizer/ASan/UBSan/MSan. When `compile_afl` exports `AFL_LLVM_CMPLOG=1`, [`build.sh`](build.sh) swaps `pm_strncasecmp` for libc `strncasecmp` (excluding `src/strncasecmp.c`) so AFL++ CmpLog/Redqueen hooks case-insensitive magic-comment and encoding comparisons just like local `build/fuzz.cmplog`.

## Testing Locally with OSS-Fuzz Tooling

To validate in a full `google/oss-fuzz` checkout:

```bash
cp -r test/fuzz/oss-fuzz /path/to/oss-fuzz/projects/prism
cd /path/to/oss-fuzz
python3 infra/helper.py build_image prism
python3 infra/helper.py build_fuzzers prism
python3 infra/helper.py check_build prism
```

To test compilation and seed replay without a separate `oss-fuzz` checkout, run `make fuzz-test` (which runs `test/fuzz/oss-fuzz/test_oss_fuzz.sh` inside the `prism/fuzz` container).

## Reproducing OSS-Fuzz / ClusterFuzz Crashes Locally

Crash inputs downloaded from ClusterFuzz already carry the 4-byte option header expected by `test/fuzz/harness/parse.c` and can be replayed with `./build/fuzz <reproducer>` (or dropped into `tmp/fuzz/afl/main/crashes/` and triaged into `testcase.c` buckets with `make fuzz-triage`).

