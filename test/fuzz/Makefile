FUZZ_DIR = $(CURDIR)/tmp/fuzz
FUZZ_AFL_DIR = $(FUZZ_DIR)/afl
FUZZ_CORPUS_DIR = $(FUZZ_DIR)/corpus
FUZZ_COVERAGE_DIR = $(FUZZ_DIR)/coverage
FUZZ_TRIAGE_DIR = $(FUZZ_DIR)/triage
# Maximum input size in bytes for fuzzing and coverage.
FUZZ_MAX_INPUT_SIZE ?= 1024
# Maximum single allocation / live heap size in MB for fuzzing and triage.
FUZZ_MAX_ALLOCATED ?= 64
FUZZ_HARD_RSS_LIMIT := $(shell echo $$(( $(FUZZ_MAX_ALLOCATED) * 32 )))
# Set PM_ARENA_INITIAL_SIZE=0 so each arena allocation gets its own exact-sized
# xmalloc block with ASAN heap redzones around it instead of packing into 8 KB
# blocks, while still freeing all blocks via pm_arena_cleanup.
FUZZ_FLAGS := -DPM_ARENA_INITIAL_SIZE=0 -DFUZZ_MAX_INPUT_SIZE=$(FUZZ_MAX_INPUT_SIZE) -DFUZZ_MAX_ALLOCATED=$(FUZZ_MAX_ALLOCATED) -DFUZZ_HARD_RSS_LIMIT=$(FUZZ_HARD_RSS_LIMIT) -Wno-gnu-statement-expression-from-macro-expansion -Wno-shorten-64-to-32 -Wno-switch -Wno-implicit-function-declaration $(FUZZ_FLAGS)
FUZZ_SOURCES := $(SOURCES) test/fuzz/parse.c test/fuzz/fuzz.c

FUZZ_DOCKER_STAMP := ./build/.fuzz.docker.stamp
FUZZ_BUILD_STAMP := ./build/.fuzz.build.stamp
FUZZ_GRAMMAR_STAMP := ./build/.fuzz.grammar.stamp
FUZZ_GEN_TEMPLATES_STAMP := ./build/.fuzz.gen_templates.stamp
FUZZ_TMPFS_FLAGS := --tmpfs /tmp:rw,exec,mode=1777

fuzz-build: $(FUZZ_BUILD_STAMP) $(FUZZ_GRAMMAR_STAMP)
	$(ECHO) "Fuzzers up to date"

$(FUZZ_GRAMMAR_STAMP): test/fuzz/grammar/ruby.json test/fuzz/grammar/grammar-mutator.patch
	$(Q) $(MAKEDIRS) $(@D)
	$(ECHO) "building grammar mutator"
	$(Q) git -C /AFLplusplus/Grammar-Mutator checkout -- .
	$(Q) git -C /AFLplusplus/Grammar-Mutator apply $(CURDIR)/test/fuzz/grammar/grammar-mutator.patch
	$(Q) $(MAKE) -C /AFLplusplus/Grammar-Mutator GRAMMAR_FILE=$(CURDIR)/test/fuzz/grammar/ruby.json
	$(Q) cp -f /AFLplusplus/Grammar-Mutator/src/libgrammarmutator-ruby.so build/libgrammarmutator-ruby.so
	$(Q) cp -f /AFLplusplus/Grammar-Mutator/src/grammar_generator-ruby build/grammar_generator-ruby
	$(Q) touch $@

$(FUZZ_BUILD_STAMP): $(FUZZ_SOURCES) $(HEADERS) test/fuzz/include/prism_xallocator.h test/fuzz/Makefile
	$(Q) $(MAKEDIRS) $(@D)
	$(ECHO) "building with MSAN"
	$(Q) AFL_USE_MSAN=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_FLAGS) -fsanitize=fuzzer -fsanitize-memory-track-origins=2 -ggdb3 -std=c99 -Iinclude -o build/fuzz.msan $(FUZZ_SOURCES)
	$(ECHO) "building with LSAN"
	$(Q) AFL_USE_LSAN=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_FLAGS) -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.lsan $(FUZZ_SOURCES)
	$(ECHO) "building with custom leak detector"
	$(Q) afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_FLAGS) -Itest/fuzz/include -DPRISM_XALLOCATOR -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.ldet $(FUZZ_SOURCES)
	$(ECHO) "building main fuzz binary"
	# Disable ASAN read instrumentation (-asan-instrument-reads=0) so the main
	# and grammar fuzzers focus on illegal writes, UBSAN, and assertions without
	# stopping on out-of-bounds reads (covered by MSAN). Both -mllvm and
	# -Wl,-mllvm are required because afl-clang-lto runs ASAN during LTO linking.
	$(Q) AFL_USE_UBSAN=1 AFL_UBSAN_VERBOSE=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_FLAGS) -mllvm -asan-instrument-reads=0 -Wl,-mllvm,-asan-instrument-reads=0 -fsanitize=address,fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz $(FUZZ_SOURCES)
	$(ECHO) "building cmplog binary"
	# Replace pm_strncasecmp with standard strncasecmp so AFL++ CmpLog hooks
	# can instrument case-insensitive string comparisons for better coverage.
	$(Q) AFL_LLVM_CMPLOG=1 afl-clang-lto $(DEBUG_FLAGS) $(CPPFLAGS) $(CFLAGS) $(FUZZ_FLAGS) -Dpm_strncasecmp=strncasecmp -fsanitize=fuzzer -ggdb3 -std=c99 -Iinclude -o build/fuzz.cmplog $(filter-out src/strncasecmp.c,$(FUZZ_SOURCES))
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
	$(Q) docker run -it --init --rm $(FUZZ_TMPFS_FLAGS) -e FUZZ_WORKERS -e FUZZ_MAX_INPUT_SIZE=$(FUZZ_MAX_INPUT_SIZE) -e FUZZ_MAX_ALLOCATED=$(FUZZ_MAX_ALLOCATED) -v $(CURDIR):/prism prism/fuzz /bin/bash -c "./test/fuzz/run.sh"

fuzz-coverage: fuzz-docker-build fuzz-gen-templates
	$(ECHO) "collecting coverage"
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) -e FUZZ_FLAGS="$(FUZZ_FLAGS)" -v $(CURDIR):/prism prism/fuzz ./test/fuzz/tools/coverage.sh

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
	$(Q) $(RMALL) $(FUZZ_AFL_DIR) $(FUZZ_CORPUS_DIR) $(FUZZ_COVERAGE_DIR)
	$(ECHO) "done"

.PHONY: fuzz-clean fuzz-docker-build fuzz-gen-templates fuzz-build fuzz-debug fuzz-triage fuzz-run fuzz-coverage

