# ═══════════════════════════════════════════════════════════════
#  Makefile — ch14-fileformat
#  Custom .cdat format parser for chapter 14 (sanitizers)
#
#  Targets:
#    make all       — all variants
#    make asan      — ASan + UBSan (chapter 14)
#    make msan      — MSan / Clang (chapter 14)
#    make afl       — AFL++ instrumentation
#    make sample    — create a test .cdat file
#    make clean     — cleanup
# ═══════════════════════════════════════════════════════════════

CC      = gcc
CLANG   = clang
AFL_CC  = afl-gcc
SRC     = fileformat.c
WARN    = -Wall -Wextra

TARGETS = fileformat_O0 fileformat_O2 fileformat_O3 \
          fileformat_strip fileformat_O2_strip

.PHONY: all asan msan afl sample clean

all: $(TARGETS)

# ── With symbols ─────────────────────────────────────────────────

fileformat_O0: $(SRC)
	$(CC) $(WARN) -O0 -g -o $@ $<

fileformat_O2: $(SRC)
	$(CC) $(WARN) -O2 -g -o $@ $<

fileformat_O3: $(SRC)
	$(CC) $(WARN) -O3 -g -o $@ $<

# ── Without symbols ──────────────────────────────────────────────

fileformat_strip: $(SRC)
	$(CC) $(WARN) -O0 -s -o $@ $<

fileformat_O2_strip: $(SRC)
	$(CC) $(WARN) -O2 -s -o $@ $<

# ── Sanitizers (chapter 14) ──────────────────────────────────────

asan: $(SRC)
	$(CC) $(WARN) -O0 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined \
		-o fileformat_asan $<
	@echo "→ fileformat_asan (ASan + UBSan)"
	@echo "  Create a sample first: ./fileformat_asan create test.cdat"
	@echo "  Then parse:            ./fileformat_asan parse test.cdat"

msan: $(SRC)
	$(CLANG) $(WARN) -O0 -g -fno-omit-frame-pointer \
		-fsanitize=memory -fsanitize-memory-track-origins=2 \
		-o fileformat_msan $<
	@echo "→ fileformat_msan (MSan, Clang)"

# ── AFL++ ──────────────────────────────────────────────

afl: $(SRC)
	$(AFL_CC) $(WARN) -O2 -g \
		-fsanitize=address,undefined \
		-o fileformat_afl $<
	@echo "→ fileformat_afl (AFL++ instrumented + ASan)"
	@echo "  mkdir -p afl_in afl_out"
	@echo "  ./fileformat_O0 create afl_in/seed.cdat"
	@echo "  afl-fuzz -i afl_in -o afl_out -- ./fileformat_afl parse @@"

# ── Test file ────────────────────────────────────────────────────

sample: fileformat_O0
	./fileformat_O0 create sample.cdat
	@echo "→ sample.cdat created (for ImHex, Valgrind, fuzzing...)"

# ── Cleanup ──────────────────────────────────────────────────────

clean:
	rm -f $(TARGETS) fileformat_asan fileformat_msan fileformat_afl
	rm -f *.cdat
	rm -f callgrind.out.* asan.* msan.*
	rm -rf afl_in afl_out
