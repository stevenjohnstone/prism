FUZZ_DIR = $(CURDIR)/tmp/fuzz
FUZZ_AFL_DIR = $(FUZZ_DIR)/afl
FUZZ_AFL_IJON_DIR = $(FUZZ_DIR)/afl-ijon
FUZZ_CORPUS_DIR = $(FUZZ_DIR)/corpus
FUZZ_SEEDS_DIR = $(FUZZ_DIR)/seeds
FUZZ_COVERAGE_DIR = $(FUZZ_DIR)/coverage
FUZZ_PLOTS_DIR = $(FUZZ_DIR)/plots
FUZZ_TRIAGE_DIR = $(FUZZ_DIR)/triage
# Maximum input size in bytes for fuzzing and coverage.
FUZZ_MAX_INPUT_SIZE ?= 1024
# Maximum single allocation / live heap size in MB for fuzzing and triage.
FUZZ_MAX_ALLOCATED ?= 128
FUZZ_HARD_RSS_LIMIT := $(shell echo $$(( $(FUZZ_MAX_ALLOCATED) * 16 )))
# Set PM_ARENA_INITIAL_SIZE=0 on sanitizer builds so each arena allocation gets
# its own exact-sized xmalloc block with ASAN/MSAN heap redzones around it
# instead of packing into 8 KB blocks, while still freeing all blocks via
# pm_arena_cleanup. Non-sanitized builds (fuzz.ijon, fuzz.native, fuzz.coverage)
# use the default 8 KB arena blocks for higher throughput and full arena coverage.
FUZZ_SANITIZER_FLAGS := -DPM_ARENA_INITIAL_SIZE=0
# Set PM_INTEGER_DIVIDE_THRESHOLD=8 (72 decimal digits instead of the default
# 224 chunks / 2,017 digits) so divide-and-conquer decimal parsing and base-2^32
# bignum arithmetic (schoolbook and Karatsuba) are reachable within
# FUZZ_MAX_INPUT_SIZE.
# Set PRISM_DEPTH_MAXIMUM=128 (instead of the default 10,000) so depth-limit
# error recovery (PM_ERR_NESTING_TOO_DEEP) is reachable within
# FUZZ_MAX_INPUT_SIZE and quadratic indentation growth in pm_prettyprint stays
# well within FUZZ_MAX_ALLOCATED.
# Exclude serialization, JSON, and prettyprint from fast parse-only fuzzers so
# their translation units and coverage edges are omitted; enable -DSLOW on
# fuzz.slow, fuzz.msan, and fuzz.lsan to exercise serialization, error
# formatting, prettyprint, and JSON dumping.
FUZZ_FAST_FLAGS := -DPRISM_EXCLUDE_SERIALIZATION -DPRISM_EXCLUDE_JSON -DPRISM_EXCLUDE_PRETTYPRINT
FUZZ_SLOW_FLAGS := -DSLOW
FUZZ_FLAGS := -DPM_INTEGER_DIVIDE_THRESHOLD=8 -DPRISM_DEPTH_MAXIMUM=128 -DFUZZ_MAX_INPUT_SIZE=$(FUZZ_MAX_INPUT_SIZE) -DFUZZ_MAX_ALLOCATED=$(FUZZ_MAX_ALLOCATED) -DFUZZ_HARD_RSS_LIMIT=$(FUZZ_HARD_RSS_LIMIT) -Wno-gnu-statement-expression-from-macro-expansion -Wno-shorten-64-to-32 -Wno-switch -Wno-implicit-function-declaration $(FUZZ_FLAGS)
FUZZ_SOURCES := $(SOURCES) test/fuzz/harness/parse.c test/fuzz/harness/fuzz.c

FUZZ_DOCKER_STAMP := ./build/.fuzz.docker.stamp
FUZZ_AFL_STAMP := ./build/.fuzz.afl.stamp
FUZZ_BUILD_STAMP := ./build/.fuzz.build.stamp
FUZZ_GEN_TEMPLATES_STAMP := ./build/.fuzz.gen_templates.stamp
FUZZ_TEMPLATE_DEPS := config.yml $(shell find templates -type f 2>/dev/null)
FUZZ_TMPFS_FLAGS := --tmpfs /tmp:rw,exec,mode=1777
FUZZ_CONTAINER_NAME ?= prism-fuzz
PRISM_TARGET ?= $(TARGET)
PRISM_REV ?= $(REV)
FUZZ_EXTERNAL_TARGET := $(strip $(PRISM_TARGET)$(PRISM_REV))
ifneq ($(FUZZ_DAEMON),)
FUZZ_RUN_DOCKER_FLAGS := -d --name $(FUZZ_CONTAINER_NAME) -e FUZZ_DAEMON=1
else
FUZZ_RUN_DOCKER_FLAGS := -it --name $(FUZZ_CONTAINER_NAME)
endif

fuzz-build: $(FUZZ_AFL_STAMP) $(FUZZ_BUILD_STAMP)
	$(ECHO) "Fuzzers up to date"

$(FUZZ_AFL_STAMP): test/fuzz/patches/aflplusplus.patch
	$(Q) $(MAKEDIRS) $(@D) build/afl
	$(ECHO) "patching and building AFL++ instrumentation passes"
	$(Q) rm -rf build/afl-src
	$(Q) $(MAKEDIRS) build/afl-src
	$(Q) cp -r /AFLplusplus/instrumentation /AFLplusplus/include /AFLplusplus/GNUmakefile.llvm build/afl-src/
	$(Q) ln -sf /AFLplusplus/afl-showmap build/afl-src/afl-showmap
	$(Q) git apply --unsafe-paths --directory=build/afl-src $(CURDIR)/test/fuzz/patches/aflplusplus.patch
	$(Q) $(MAKE) -C build/afl-src -f GNUmakefile.llvm LLVM_CONFIG=llvm-config-20 ./SanitizerCoverageLTO.so ./SanitizerCoveragePCGUARD.so
	$(Q) ln -sf /usr/local/lib/afl/* build/afl/
	$(Q) cp -f build/afl-src/SanitizerCoverageLTO.so build/afl-src/SanitizerCoveragePCGUARD.so build/afl/
	$(Q) rm -rf build/afl-src
	$(Q) touch $@


$(FUZZ_BUILD_STAMP): $(FUZZ_AFL_STAMP) $(FUZZ_SOURCES) $(HEADERS) $(wildcard ext/prism/*) test/fuzz/harness/include/prism_xallocator.h test/fuzz/Makefile
	$(Q) $(MAKEDIRS) $(@D)
	$(ECHO) "building with MSAN (SLOW)"
	$(Q) AFL_PATH=$(CURDIR)/build/afl AFL_USE_MSAN=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_SANITIZER_FLAGS) $(FUZZ_SLOW_FLAGS) $(FUZZ_FLAGS) -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.msan $(FUZZ_SOURCES)
	$(ECHO) "building with LSAN (SLOW)"
	$(Q) AFL_PATH=$(CURDIR)/build/afl AFL_USE_LSAN=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_SANITIZER_FLAGS) $(FUZZ_SLOW_FLAGS) $(FUZZ_FLAGS) -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.lsan $(FUZZ_SOURCES)
	$(ECHO) "building with IJON state tracking and custom leak detector"
	# Enable IJON state tracking (AFL_LLVM_IJON=1 -DPRISM_FUZZ_IJON) on fuzz.ijon
	# for the ijon worker.
	$(Q) AFL_PATH=$(CURDIR)/build/afl AFL_LLVM_IJON=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_FAST_FLAGS) $(FUZZ_FLAGS) -DPRISM_FUZZ_IJON -Itest/fuzz/harness/include -DPRISM_XALLOCATOR -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.ijon $(FUZZ_SOURCES)
	$(ECHO) "building native leak detector for SAND workers"
	$(Q) AFL_PATH=$(CURDIR)/build/afl afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_FAST_FLAGS) $(FUZZ_FLAGS) -Itest/fuzz/harness/include -DPRISM_XALLOCATOR -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.native $(FUZZ_SOURCES)
	$(ECHO) "building main fuzz binary"
	$(Q) rm -f $(CURDIR)/build/fuzz.ids && AFL_PATH=$(CURDIR)/build/afl AFL_LLVM_DOCUMENT_IDS=$(CURDIR)/build/fuzz.ids AFL_USE_UBSAN=1 AFL_UBSAN_VERBOSE=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_SANITIZER_FLAGS) $(FUZZ_FAST_FLAGS) $(FUZZ_FLAGS) -fsanitize=address,fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz $(FUZZ_SOURCES)
	$(ECHO) "building SAND sanitizer binary (forkserver-only ASAN+UBSAN)"
	$(Q) AFL_PATH=$(CURDIR)/build/afl AFL_LLVM_ONLY_FSRV=1 AFL_USE_UBSAN=1 AFL_UBSAN_VERBOSE=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_SANITIZER_FLAGS) $(FUZZ_FAST_FLAGS) $(FUZZ_FLAGS) -fsanitize=address,fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.sand $(FUZZ_SOURCES)
	$(ECHO) "building ASAN+UBSAN (SLOW) binary"
	$(Q) AFL_PATH=$(CURDIR)/build/afl AFL_USE_UBSAN=1 AFL_UBSAN_VERBOSE=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_SANITIZER_FLAGS) $(FUZZ_SLOW_FLAGS) $(FUZZ_FLAGS) -fsanitize=address,fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.slow $(FUZZ_SOURCES)
	$(ECHO) "building cmplog binary"
	# Replace pm_strncasecmp with standard strncasecmp so AFL++ CmpLog hooks
	# can instrument case-insensitive string comparisons for better coverage.
	$(Q) AFL_PATH=$(CURDIR)/build/afl AFL_LLVM_CMPLOG=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_FAST_FLAGS) $(FUZZ_FLAGS) -Dpm_strncasecmp=strncasecmp -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.cmplog $(filter-out src/strncasecmp.c,$(FUZZ_SOURCES))
	$(ECHO) "building workspace Ruby C extension for grammar generator"
	$(Q) $(MAKEDIRS) build/fuzz-ruby-ext/prism
	$(Q) cd build/fuzz-ruby-ext/prism && ruby $(CURDIR)/ext/prism/extconf.rb && $(MAKE)
	$(Q) $(MAKEDIRS) build
	$(Q) touch $@

fuzz-docker-build: $(FUZZ_DOCKER_STAMP)
	$(ECHO) "Docker image is up to date"

$(FUZZ_DOCKER_STAMP): test/fuzz/docker/Dockerfile Gemfile Gemfile.lock prism.gemspec
	$(ECHO) "building docker image"
	$(Q) docker build -t prism/fuzz -f test/fuzz/docker/Dockerfile .
	$(Q) $(MAKEDIRS) build
	$(Q) touch $@

fuzz-debug: fuzz-docker-build
	$(ECHO) "entering debug shell"
	$(Q) $(MAKEDIRS) $(FUZZ_DIR)
	$(Q) docker run -it --rm $(FUZZ_TMPFS_FLAGS) -e HISTFILE=/prism/tmp/fuzz/.bash_history -v $(CURDIR):/prism prism/fuzz

fuzz-triage: fuzz-docker-build fuzz-gen-templates
	$(ECHO) "starting triage -- may take a long time"
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) -v $(CURDIR):/prism prism/fuzz /bin/bash -c "FUZZ_FLAGS=\"$(FUZZ_FLAGS)\" make fuzz-build"
	@if [ -t 1 ]; then \
		DOCKER_ARGS="-it"; \
	fi; \
	docker run $${DOCKER_ARGS} --init --rm $(FUZZ_TMPFS_FLAGS) -e TRIAGE_MINIMIZE -e TRIAGE_RECOUNT -e TRIAGE_THREADS -e TRIAGE_COVERAGE_BIN -e TRIAGE_CORPUS_DIR -e FUZZ_MAX_ALLOCATED=$(FUZZ_MAX_ALLOCATED) -e HISTFILE=/prism/tmp/fuzz/.bash_history -v $(CURDIR):/prism prism/fuzz ruby ./test/fuzz/triage/triage.rb

FUZZ_VERIFY_ENV_FLAGS := -e TRIAGE_DIR -e CLUSTER -e CLUSTERS_FILE -e BY_CLUSTER -e BUCKET -e REASON -e VERIFY_TIMEOUT -e VERIFY_MAX_FAILURES -e VERIFY_EXTRACT_SURVIVORS -e VERIFY_INPUT_MIN_ONLY -e VERIFY_SKIP_MIN -e VERIFY_UNREPRODUCIBLE -e VERIFY_REBUILD -e VERIFY_SYMBOLIZE -e VERIFY_FAIL_FAST -e VERIFY_INVERT -e VERIFY_BISECT -e VERIFY_VERBOSE -e VERIFY_QUIET -e FUZZ_MAX_INPUT_SIZE=$(FUZZ_MAX_INPUT_SIZE) -e FUZZ_MAX_ALLOCATED=$(FUZZ_MAX_ALLOCATED)

ifeq ($(FUZZ_EXTERNAL_TARGET),)
fuzz-verify: fuzz-docker-build fuzz-gen-templates
	@if [ -t 1 ]; then \
		DOCKER_ARGS="-it"; \
	fi; \
	docker run $${DOCKER_ARGS} --init --rm $(FUZZ_TMPFS_FLAGS) $(FUZZ_VERIFY_ENV_FLAGS) -v $(CURDIR):/prism prism/fuzz ruby ./test/fuzz/triage/verify.rb $(VERIFY_ARGS)
else
fuzz-verify: fuzz-docker-build
	@if [ -n "$(strip $(PRISM_TARGET))" ] && [ -n "$(strip $(PRISM_REV))" ]; then \
		echo "Specify either TARGET=... or REV=..., not both." >&2; \
		exit 2; \
	fi; \
	if [ -n "$(strip $(PRISM_REV))" ]; then \
		target_dir="$$(./test/fuzz/triage/target_worktree.sh "$(PRISM_REV)")" || exit $$?; \
	else \
		target_dir="$$(cd "$(PRISM_TARGET)" 2>/dev/null && pwd)" || { echo "Invalid TARGET directory: $(PRISM_TARGET)" >&2; exit 2; }; \
	fi; \
	if [ ! -f "$$target_dir/include/prism.h" ] || [ ! -d "$$target_dir/src" ]; then \
		echo "Invalid Prism target directory: $$target_dir (missing include/prism.h or src/)" >&2; \
		exit 2; \
	fi; \
	if [ -t 1 ]; then \
		DOCKER_ARGS="-it"; \
	fi; \
	docker run $${DOCKER_ARGS} --init --rm $(FUZZ_TMPFS_FLAGS) $(FUZZ_VERIFY_ENV_FLAGS) -e VERIFY_TARGET=/target -v $(CURDIR):/prism -v "$$target_dir:/target" prism/fuzz ruby ./test/fuzz/triage/verify.rb $(VERIFY_ARGS)
endif

fuzz-bisect: fuzz-docker-build
	$(Q) FUZZ_TMPFS_FLAGS="$(FUZZ_TMPFS_FLAGS)" FUZZ_MAX_INPUT_SIZE="$(FUZZ_MAX_INPUT_SIZE)" FUZZ_MAX_ALLOCATED="$(FUZZ_MAX_ALLOCATED)" ruby ./test/fuzz/triage/bisect.rb $(BISECT_ARGS)

fuzz-retriage: fuzz-docker-build fuzz-gen-templates
	@if [ -t 1 ]; then \
		DOCKER_ARGS="-it"; \
	fi; \
	docker run $${DOCKER_ARGS} --init --rm $(FUZZ_TMPFS_FLAGS) -e TRIAGE_DIR -e CLUSTER -e CLUSTERS_FILE -e BUCKET -e REASON -e VERIFY_TIMEOUT -e VERIFY_UNREPRODUCIBLE -e VERIFY_REBUILD -e VERIFY_VERBOSE -e VERIFY_QUIET -e TRIAGE_MINIMIZE -e TRIAGE_THREADS -e TRIAGE_COVERAGE_BIN -e TRIAGE_CORPUS_DIR -e RETRIAGE_BUILD -e RETRIAGE_DRY_RUN -e FUZZ_FLAGS -e FUZZ_MAX_INPUT_SIZE=$(FUZZ_MAX_INPUT_SIZE) -e FUZZ_MAX_ALLOCATED=$(FUZZ_MAX_ALLOCATED) -e HISTFILE=/prism/tmp/fuzz/.bash_history -v $(CURDIR):/prism prism/fuzz ruby ./test/fuzz/triage/retriage.rb $(RETRIAGE_ARGS)

fuzz-gen-templates: $(FUZZ_GEN_TEMPLATES_STAMP)
	$(ECHO) "Templates up to date"

$(FUZZ_GEN_TEMPLATES_STAMP): $(FUZZ_TEMPLATE_DEPS) | $(FUZZ_DOCKER_STAMP)
	$(ECHO) "generating templates"
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) -v $(CURDIR):/prism prism/fuzz /bin/bash -c "bundle exec rake templates"
	$(Q) $(MAKEDIRS) build
	$(Q) touch $@

fuzz-run: fuzz-docker-build fuzz-gen-templates
	$(ECHO) "running fuzzer"
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) -v $(CURDIR):/prism prism/fuzz /bin/bash -c "FUZZ_FLAGS=\"$(FUZZ_FLAGS)\" make fuzz-build"
	$(ECHO) "starting AFL++ run"
	$(Q) $(MAKEDIRS) $(FUZZ_AFL_DIR)
	$(Q) docker run $(FUZZ_RUN_DOCKER_FLAGS) --init --rm $(FUZZ_TMPFS_FLAGS) -e FUZZ_WORKERS -e FUZZ_MAX_INPUT_SIZE=$(FUZZ_MAX_INPUT_SIZE) -e FUZZ_MAX_ALLOCATED=$(FUZZ_MAX_ALLOCATED) -v $(CURDIR):/prism prism/fuzz /bin/bash -c "exec ./test/fuzz/runtime/run.sh"
ifneq ($(FUZZ_DAEMON),)
	$(ECHO) "Fuzzer daemon started in container '$(FUZZ_CONTAINER_NAME)'."
	$(ECHO) "Attach to tmux with: make fuzz-attach (or: docker exec -it $(FUZZ_CONTAINER_NAME) tmux -2 attach-session -t fuzzer)"
	$(ECHO) "Stop the daemon with: make fuzz-stop (or: docker stop $(FUZZ_CONTAINER_NAME))"
endif

fuzz-daemon:
	$(Q) $(MAKE) fuzz-run FUZZ_DAEMON=1

fuzz-attach:
	$(Q) docker exec -it $(FUZZ_CONTAINER_NAME) tmux -2 attach-session -t fuzzer

fuzz-stop:
	$(Q) docker stop $(FUZZ_CONTAINER_NAME)

define FUZZ_RUN_COVERAGE
( \
	LIVE_SEEDS_TAR=""; \
	trap 'rc=$$?; rm -f "$$LIVE_SEEDS_TAR"; exit $$rc' EXIT; \
	trap 'exit 130' INT; \
	trap 'exit 143' TERM; \
	if [ -n "$$(docker ps -q -f name="^/$(FUZZ_CONTAINER_NAME)$$" 2>/dev/null)" ]; then \
		mkdir -p $(FUZZ_DIR); \
		LIVE_SEEDS_TAR="tmp/fuzz/.live-seeds.$$$$.tar"; \
		docker exec $(FUZZ_CONTAINER_NAME) bash -c 'test -d /tmp/afl-tmpdir/grammar/seeds && find /tmp/afl-tmpdir/grammar/seeds -maxdepth 1 -type f ! -name ".*" -printf "%f\0" | sort -z | head -z -n 5000 | tar --atime-preserve=system --ignore-failed-read --warning=no-file-changed --warning=no-file-removed -C /tmp/afl-tmpdir/grammar/seeds --null -T - -cf -' > "$$LIVE_SEEDS_TAR" 2>/dev/null || { rm -f "$$LIVE_SEEDS_TAR"; LIVE_SEEDS_TAR=""; }; \
	fi; \
	docker run --rm $(FUZZ_TMPFS_FLAGS) -e FUZZ_FLAGS="$(FUZZ_FLAGS)" -e FUZZ_LIVE_SEEDS_TAR="$$LIVE_SEEDS_TAR" -v $(CURDIR):/prism prism/fuzz ./test/fuzz/report/coverage.sh \
)
endef

fuzz-coverage: fuzz-docker-build fuzz-gen-templates
	$(ECHO) "collecting coverage"
	@$(FUZZ_RUN_COVERAGE)
	$(Q) ruby ./test/fuzz/report/plot.rb $(FUZZ_AFL_DIR) $(FUZZ_PLOTS_DIR)/index.html $(FUZZ_COVERAGE_DIR)/coverage.json

fuzz-plot: fuzz-docker-build fuzz-gen-templates
	@if [ -z "$(FUZZ_SKIP_COVERAGE)" ] && [ -d "$(FUZZ_AFL_DIR)" ]; then \
		if [ ! -f "$(FUZZ_COVERAGE_DIR)/coverage.json" ] || [ -n "$$(find $(FUZZ_AFL_DIR) $(FUZZ_AFL_IJON_DIR) \( -name 'queue' -o -name 'crashes' -o -name 'hangs' \) -newer $(FUZZ_COVERAGE_DIR)/coverage.json -print -quit 2>/dev/null)" ] || [ -n "$$(find $(FUZZ_SEEDS_DIR) -newer $(FUZZ_COVERAGE_DIR)/coverage.json -print -quit 2>/dev/null)" ]; then \
			echo "collecting coverage (set FUZZ_SKIP_COVERAGE=1 to skip)"; \
			$(FUZZ_RUN_COVERAGE); \
		fi; \
	fi
	$(ECHO) "generating AFL++ plots"
	$(Q) ruby ./test/fuzz/report/plot.rb $(FUZZ_AFL_DIR) $(FUZZ_PLOTS_DIR)/index.html $(FUZZ_COVERAGE_DIR)/coverage.json

fuzz-bench: fuzz-docker-build fuzz-gen-templates
	$(ECHO) "benchmarking grammar seed generator"
	$(Q) $(MAKEDIRS) $(FUZZ_DIR)
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) -v $(CURDIR):/prism prism/fuzz ruby ./test/fuzz/runtime/grammar_bench.rb --json tmp/fuzz/grammar-bench.json $(GRAMMAR_BENCH_ARGS)

fuzz-test: fuzz-docker-build fuzz-gen-templates
	$(ECHO) "testing AFL++ instrumentation patch, crash triage, grammar generator, and OSS-Fuzz build"
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) -v $(CURDIR):/prism prism/fuzz /bin/bash -c "make $(FUZZ_AFL_STAMP) && ./test/fuzz/patches/test_afl_patch.sh && ./test/fuzz/triage/test_triage.sh && ./test/fuzz/runtime/test_grammar.sh && ./test/fuzz/oss-fuzz/test_oss_fuzz.sh"

define FUZZ_CLEAN_CONFIRM
@if [ -t 1 ]; then \
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"; \
	echo "@         WARNING: DESTRUCTIVE OPERATION AHEAD!           @"; \
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"; \
	echo "This will permanently delete:"; \
	echo "  - tmp/fuzz/afl      ($(FUZZ_FINDINGS) crash/hang findings)"; \
	echo "  - tmp/fuzz/afl-ijon"; \
	echo "  - tmp/fuzz/corpus"; \
	echo "  - tmp/fuzz/seeds"; \
	echo "  - tmp/fuzz/coverage"; \
	echo "  - tmp/fuzz/plots"; \
	echo ""; \
	echo "Preserved:"; \
	echo "  - tmp/fuzz/triage"; \
	echo ""; \
	printf "Continue? (Y/n) "; \
	read response; \
	case "$$response" in \
		[Y]*) \
			;; \
		*) \
			echo "Aborting."; \
			exit 1; \
			;; \
	esac; \
fi
endef

fuzz-clean: FUZZ_FINDINGS := $(shell find $(FUZZ_AFL_DIR)/*/{crashes,hangs} $(FUZZ_AFL_IJON_DIR)/*/{crashes,hangs} -name "id*" -print 2>/dev/null | wc -l | tr -d ' ' || echo "0")
fuzz-clean:
	$(FUZZ_CLEAN_CONFIRM)
	$(ECHO) "Removing fuzz data (preserving tmp/fuzz/triage)"
	$(Q) $(RMALL) $(FUZZ_AFL_DIR) $(FUZZ_AFL_IJON_DIR) $(FUZZ_CORPUS_DIR) $(FUZZ_SEEDS_DIR) $(FUZZ_COVERAGE_DIR) $(FUZZ_PLOTS_DIR) $(FUZZ_DIR)/.coverage.* $(FUZZ_DIR)/.live-seeds.*
	$(ECHO) "done"

.PHONY: fuzz-clean fuzz-docker-build fuzz-gen-templates fuzz-build fuzz-debug fuzz-triage fuzz-retriage fuzz-verify fuzz-bisect fuzz-run fuzz-daemon fuzz-attach fuzz-stop fuzz-coverage fuzz-plot fuzz-bench fuzz-test

