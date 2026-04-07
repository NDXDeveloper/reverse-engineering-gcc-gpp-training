# ═══════════════════════════════════════════════════════════════
#  Makefile — binaries/ch15-fileformat/
#
#  Custom CSTM format parser for chapter 15.
#  Produces variants at different optimization levels,
#  with and without symbols, and instrumented builds for fuzzing.
#
#  Usage:
#    make              — compile all standard variants
#    make fuzz         — compile AFL++ and libFuzzer variants
#    make coverage     — compile the gcov build for coverage
#    make all          — compile everything (standard + fuzz + coverage)
#    make clean        — remove all binaries and artifacts
# ═══════════════════════════════════════════════════════════════

# ── Compilers ──
CC       ?= gcc
AFL_CC   ?= afl-gcc
CLANG    ?= clang

# ── Source ──
SRC      = fileformat.c
HARNESS  = fuzz_fileformat.c

# ── Common flags ──
CFLAGS_BASE   = -Wall -Wextra
LDFLAGS       =

# ═════════════════════════
#  Standard targets (GCC)
# ═════════════════════════

TARGETS_STD = fileformat_O0 fileformat_O2 fileformat_O3 \
              fileformat_O0_strip fileformat_O2_strip

.PHONY: standard fuzz coverage all clean help

standard: $(TARGETS_STD)

fileformat_O0: $(SRC)
	$(CC) $(CFLAGS_BASE) -O0 -g -o $@ $< $(LDFLAGS)

fileformat_O2: $(SRC)
	$(CC) $(CFLAGS_BASE) -O2 -g -o $@ $< $(LDFLAGS)

fileformat_O3: $(SRC)
	$(CC) $(CFLAGS_BASE) -O3 -g -o $@ $< $(LDFLAGS)

fileformat_O0_strip: fileformat_O0
	cp $< $@
	strip $@

fileformat_O2_strip: fileformat_O2
	cp $< $@
	strip $@

# ═════════════════════════════════
#  Fuzzing targets (AFL++ & Clang)
# ═════════════════════════════════

TARGETS_FUZZ = fileformat_afl fileformat_afl_asan

fuzz: $(TARGETS_FUZZ)

# AFL++ — standard instrumentation
fileformat_afl: $(SRC)
	$(AFL_CC) $(CFLAGS_BASE) -O0 -g -o $@ $< $(LDFLAGS)

# AFL++ — instrumentation + AddressSanitizer
fileformat_afl_asan: $(SRC)
	AFL_USE_ASAN=1 $(AFL_CC) $(CFLAGS_BASE) -O0 -g -o $@ $< $(LDFLAGS)

# libFuzzer (requires Clang and the fuzz_fileformat.c harness)
# -DFUZZ_TARGET excludes main() from fileformat.c and makes functions non-static
fuzz_fileformat: $(SRC) $(HARNESS)
	$(CLANG) -DFUZZ_TARGET -fsanitize=fuzzer,address,undefined -g -O1 \
		$(CFLAGS_BASE) -o $@ $(HARNESS) $(SRC)

# ═══════════════════════════════
#  Coverage target (gcov/lcov)
# ═══════════════════════════════

coverage: fileformat_gcov

fileformat_gcov: $(SRC)
	$(CC) --coverage $(CFLAGS_BASE) -O0 -g -o $@ $< $(LDFLAGS)

# ═════════════════
#  Global target
# ═════════════════

all: standard fuzz coverage
	@echo ""
	@echo "=== All binaries compiled ==="
	@ls -la fileformat_* fuzz_fileformat 2>/dev/null || true

# ═════════════════
#  Cleanup
# ═════════════════

clean:
	rm -f fileformat_O0 fileformat_O2 fileformat_O3
	rm -f fileformat_O0_strip fileformat_O2_strip
	rm -f fileformat_afl fileformat_afl_asan
	rm -f fileformat_gcov
	rm -f fuzz_fileformat
	rm -f *.o *.gcno *.gcda *.gcov *.info
	rm -rf cov_report/ cov_html/

# ═════════════════
#  Help
# ═════════════════

help:
	@echo "Available targets:"
	@echo "  make              Standard variants (O0, O2, O3, strip)"
	@echo "  make fuzz         AFL++ builds (afl, afl+asan)"
	@echo "  make coverage     gcov build for lcov/genhtml"
	@echo "  make all          Compile everything"
	@echo "  make clean        Remove artifacts"
	@echo ""
	@echo "Overridable variables:"
	@echo "  CC=gcc            C compiler (default: gcc)"
	@echo "  AFL_CC=afl-gcc    AFL++ compiler (default: afl-gcc)"
	@echo "  CLANG=clang       Clang compiler for libFuzzer"
