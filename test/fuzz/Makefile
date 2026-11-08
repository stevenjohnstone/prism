FUZZ_DIR = $(CURDIR)/tmp/fuzz
FUZZ_AFL_DIR = $(FUZZ_DIR)/afl
FUZZ_CORPUS_DIR = $(FUZZ_DIR)/corpus
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
# pm_arena_cleanup. Non-sanitized builds (fuzz.ldet, fuzz.coverage) use the
# default 8 KB arena blocks for higher throughput and full arena coverage.
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
# fuzz.msan and fuzz.lsan to exercise serialization, error formatting,
# prettyprint, and JSON dumping.
FUZZ_FAST_FLAGS := -DPRISM_EXCLUDE_SERIALIZATION -DPRISM_EXCLUDE_JSON -DPRISM_EXCLUDE_PRETTYPRINT
FUZZ_SLOW_FLAGS := -DSLOW
FUZZ_FLAGS := -DPM_INTEGER_DIVIDE_THRESHOLD=8 -DPRISM_DEPTH_MAXIMUM=128 -DFUZZ_MAX_INPUT_SIZE=$(FUZZ_MAX_INPUT_SIZE) -DFUZZ_MAX_ALLOCATED=$(FUZZ_MAX_ALLOCATED) -DFUZZ_HARD_RSS_LIMIT=$(FUZZ_HARD_RSS_LIMIT) -Wno-gnu-statement-expression-from-macro-expansion -Wno-shorten-64-to-32 -Wno-switch -Wno-implicit-function-declaration $(FUZZ_FLAGS)
FUZZ_SOURCES := $(SOURCES) test/fuzz/parse.c test/fuzz/fuzz.c

FUZZ_DOCKER_STAMP := ./build/.fuzz.docker.stamp
FUZZ_AFL_STAMP := ./build/.fuzz.afl.stamp
FUZZ_BUILD_STAMP := ./build/.fuzz.build.stamp
FUZZ_GRAMMAR_STAMP := ./build/.fuzz.grammar.stamp
FUZZ_GEN_TEMPLATES_STAMP := ./build/.fuzz.gen_templates.stamp
FUZZ_TMPFS_FLAGS := --tmpfs /tmp:rw,exec,mode=1777
FUZZ_CONTAINER_NAME ?= prism-fuzz
ifneq ($(FUZZ_DAEMON),)
FUZZ_RUN_DOCKER_FLAGS := -d --name $(FUZZ_CONTAINER_NAME) -e FUZZ_DAEMON=1
else
FUZZ_RUN_DOCKER_FLAGS := -it --name $(FUZZ_CONTAINER_NAME)
endif

fuzz-build: $(FUZZ_AFL_STAMP) $(FUZZ_BUILD_STAMP) $(FUZZ_GRAMMAR_STAMP)
	$(ECHO) "Fuzzers up to date"

$(FUZZ_AFL_STAMP): test/fuzz/aflplusplus.patch
	$(Q) $(MAKEDIRS) $(@D) build/afl
	$(ECHO) "patching and building AFL++ instrumentation passes"
	$(Q) rm -rf build/afl-src
	$(Q) $(MAKEDIRS) build/afl-src
	$(Q) cp -r /AFLplusplus/instrumentation /AFLplusplus/include /AFLplusplus/GNUmakefile.llvm build/afl-src/
	$(Q) ln -sf /AFLplusplus/afl-showmap build/afl-src/afl-showmap
	$(Q) git apply --unsafe-paths --directory=build/afl-src $(CURDIR)/test/fuzz/aflplusplus.patch
	$(Q) $(MAKE) -C build/afl-src -f GNUmakefile.llvm LLVM_CONFIG=llvm-config-20 ./SanitizerCoverageLTO.so ./SanitizerCoveragePCGUARD.so
	$(Q) ln -sf /usr/local/lib/afl/* build/afl/
	$(Q) cp -f build/afl-src/SanitizerCoverageLTO.so build/afl-src/SanitizerCoveragePCGUARD.so build/afl/
	$(Q) rm -rf build/afl-src
	$(Q) touch $@

$(FUZZ_GRAMMAR_STAMP): test/fuzz/grammar/ruby.json test/fuzz/grammar/grammar-mutator.patch
	$(Q) $(MAKEDIRS) $(@D)
	$(ECHO) "building grammar mutator"
	$(Q) git -C /AFLplusplus/Grammar-Mutator checkout -- .
	$(Q) git -C /AFLplusplus/Grammar-Mutator apply $(CURDIR)/test/fuzz/grammar/grammar-mutator.patch
	$(Q) $(MAKE) -C /AFLplusplus/Grammar-Mutator GRAMMAR_FILE=$(CURDIR)/test/fuzz/grammar/ruby.json
	$(Q) rm -f build/libgrammarmutator-ruby.so build/grammar_generator-ruby
	$(Q) cp -f /AFLplusplus/Grammar-Mutator/src/libgrammarmutator-ruby.so build/libgrammarmutator-ruby.so
	$(Q) cp -f /AFLplusplus/Grammar-Mutator/src/grammar_generator-ruby build/grammar_generator-ruby
	$(Q) touch $@

$(FUZZ_BUILD_STAMP): $(FUZZ_AFL_STAMP) $(FUZZ_SOURCES) $(HEADERS) test/fuzz/include/prism_xallocator.h test/fuzz/Makefile
	$(Q) $(MAKEDIRS) $(@D)
	$(ECHO) "building with MSAN (SLOW)"
	$(Q) AFL_PATH=$(CURDIR)/build/afl AFL_USE_MSAN=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_SANITIZER_FLAGS) $(FUZZ_SLOW_FLAGS) $(FUZZ_FLAGS) -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.msan $(FUZZ_SOURCES)
	$(ECHO) "building with LSAN (SLOW)"
	$(Q) AFL_PATH=$(CURDIR)/build/afl AFL_USE_LSAN=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_SANITIZER_FLAGS) $(FUZZ_SLOW_FLAGS) $(FUZZ_FLAGS) -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.lsan $(FUZZ_SOURCES)
	$(ECHO) "building with custom leak detector (IJON)"
	# Enable IJON state tracking (AFL_LLVM_IJON=1 -DPRISM_FUZZ_IJON) on fuzz.ldet
	# for the ldet worker.
	$(Q) AFL_PATH=$(CURDIR)/build/afl AFL_LLVM_IJON=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_FAST_FLAGS) $(FUZZ_FLAGS) -DPRISM_FUZZ_IJON -Itest/fuzz/include -DPRISM_XALLOCATOR -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.ldet $(FUZZ_SOURCES)
	$(ECHO) "building native leak detector for grammar and SAND workers"
	$(Q) AFL_PATH=$(CURDIR)/build/afl afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_FAST_FLAGS) $(FUZZ_FLAGS) -Itest/fuzz/include -DPRISM_XALLOCATOR -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.native $(FUZZ_SOURCES)
	$(ECHO) "building main fuzz binary"
	# Disable ASAN read instrumentation (-asan-instrument-reads=0) so the main
	# and grammar fuzzers focus on illegal writes, UBSAN, and assertions without
	# stopping on out-of-bounds reads (covered by MSAN). Both -mllvm and
	# -Wl,-mllvm are required because afl-clang-lto runs ASAN during LTO linking.
	$(Q) AFL_PATH=$(CURDIR)/build/afl AFL_USE_UBSAN=1 AFL_UBSAN_VERBOSE=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_SANITIZER_FLAGS) $(FUZZ_FAST_FLAGS) $(FUZZ_FLAGS) -fsanitize=address,fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz $(FUZZ_SOURCES)
	$(ECHO) "building SAND sanitizer binary (forkserver-only ASAN+UBSAN)"
	$(Q) AFL_PATH=$(CURDIR)/build/afl AFL_LLVM_ONLY_FSRV=1 AFL_USE_UBSAN=1 AFL_UBSAN_VERBOSE=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_SANITIZER_FLAGS) $(FUZZ_FAST_FLAGS) $(FUZZ_FLAGS) -fsanitize=address,fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.sand $(FUZZ_SOURCES)
	$(ECHO) "building cmplog binary"
	# Replace pm_strncasecmp with standard strncasecmp so AFL++ CmpLog hooks
	# can instrument case-insensitive string comparisons for better coverage.
	$(Q) AFL_PATH=$(CURDIR)/build/afl AFL_LLVM_CMPLOG=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_FAST_FLAGS) $(FUZZ_FLAGS) -Dpm_strncasecmp=strncasecmp -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.cmplog $(filter-out src/strncasecmp.c,$(FUZZ_SOURCES))
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
	docker run $${DOCKER_ARGS} --init --rm $(FUZZ_TMPFS_FLAGS) -e TRIAGE_MINIMIZE -e FUZZ_MAX_ALLOCATED=$(FUZZ_MAX_ALLOCATED) -e HISTFILE=/prism/tmp/fuzz/.bash_history -v $(CURDIR):/prism prism/fuzz ruby ./test/fuzz/tools/triage.rb

fuzz-gen-templates: $(FUZZ_GEN_TEMPLATES_STAMP)
	$(ECHO) "Templates up to date"

$(FUZZ_GEN_TEMPLATES_STAMP):
	$(ECHO) "generating templates"
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) -v $(CURDIR):/prism prism/fuzz /bin/bash -c "bundle exec rake templates"
	$(Q) $(MAKEDIRS) build
	$(Q) touch $@

fuzz-run: fuzz-docker-build fuzz-gen-templates
	$(ECHO) "running fuzzer"
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) -v $(CURDIR):/prism prism/fuzz /bin/bash -c "FUZZ_FLAGS=\"$(FUZZ_FLAGS)\" make fuzz-build"
	$(ECHO) "starting AFL++ run"
	$(Q) $(MAKEDIRS) $(FUZZ_AFL_DIR)
	$(Q) docker run $(FUZZ_RUN_DOCKER_FLAGS) --init --rm $(FUZZ_TMPFS_FLAGS) -e FUZZ_WORKERS -e FUZZ_MAX_INPUT_SIZE=$(FUZZ_MAX_INPUT_SIZE) -e FUZZ_MAX_ALLOCATED=$(FUZZ_MAX_ALLOCATED) -v $(CURDIR):/prism prism/fuzz /bin/bash -c "./test/fuzz/run.sh"
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

fuzz-coverage: fuzz-docker-build fuzz-gen-templates
	$(ECHO) "collecting coverage"
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) -e FUZZ_FLAGS="$(FUZZ_FLAGS)" -v $(CURDIR):/prism prism/fuzz ./test/fuzz/tools/coverage.sh

fuzz-plot:
	$(ECHO) "generating AFL++ plots"
	$(Q) ruby ./test/fuzz/tools/plot.rb $(FUZZ_AFL_DIR) $(FUZZ_PLOTS_DIR)/index.html

fuzz-test: fuzz-docker-build
	$(ECHO) "testing AFL++ instrumentation patch"
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) -v $(CURDIR):/prism prism/fuzz /bin/bash -c "make $(FUZZ_AFL_STAMP) && ./test/fuzz/tools/test_afl_patch.sh"

define TTY_CONFIRM
@if [ -t 1 ]; then \
	echo "$(1) (Y/n)"; \
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

fuzz-clean: FUZZ_FINDINGS := $(shell find $(FUZZ_AFL_DIR)/*/{crashes,hangs} -name "id*" -print 2>/dev/null | wc -l | tr -d ' ' || echo "0")
fuzz-clean:
	$(call TTY_CONFIRM,This will destroy $(FUZZ_FINDINGS) fuzz findings in $(FUZZ_AFL_DIR) ($(FUZZ_TRIAGE_DIR) will be preserved). Continue?)
	$(ECHO) "Removing fuzz data (preserving $(FUZZ_TRIAGE_DIR))"
	$(Q) $(RMALL) $(FUZZ_AFL_DIR) $(FUZZ_CORPUS_DIR) $(FUZZ_COVERAGE_DIR) $(FUZZ_PLOTS_DIR)
	$(ECHO) "done"

.PHONY: fuzz-clean fuzz-docker-build fuzz-gen-templates fuzz-build fuzz-debug fuzz-triage fuzz-run fuzz-daemon fuzz-attach fuzz-stop fuzz-coverage fuzz-plot fuzz-test

