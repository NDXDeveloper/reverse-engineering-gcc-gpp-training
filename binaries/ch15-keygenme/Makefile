# ═══════════════════════════════════════════════════════════════
#  Makefile — binaries/ch15-keygenme/
#
#  Training keygenme for chapter 15.
#  Produces variants at different optimization levels,
#  with and without symbols, and instrumented builds for fuzzing.
#
#  Usage:
#    make              — compile all standard variants
#    make fuzz         — compile AFL++ variants
#    make all          — compile everything (standard + fuzz)
#    make clean        — remove all binaries and artifacts
#    make test         — run a quick test with a valid key
# ═══════════════════════════════════════════════════════════════

# ── Compilers ──
CC       ?= gcc
AFL_CC   ?= afl-gcc

# ── Source ──
SRC      = keygenme.c

# ── Common flags ──
CFLAGS_BASE = -Wall -Wextra

# ═════════════════════════
#  Standard targets (GCC)
# ═════════════════════════

TARGETS_STD = keygenme_O0 keygenme_O2 keygenme_O3 \
              keygenme_O0_strip keygenme_O2_strip

.PHONY: standard fuzz all clean help test

standard: $(TARGETS_STD)

keygenme_O0: $(SRC)
	$(CC) $(CFLAGS_BASE) -O0 -g -o $@ $<

keygenme_O2: $(SRC)
	$(CC) $(CFLAGS_BASE) -O2 -g -o $@ $<

keygenme_O3: $(SRC)
	$(CC) $(CFLAGS_BASE) -O3 -g -o $@ $<

keygenme_O0_strip: keygenme_O0
	cp $< $@
	strip $@

keygenme_O2_strip: keygenme_O2
	cp $< $@
	strip $@

# ══════════════════════════════
#  Fuzzing targets (AFL++)
# ══════════════════════════════

TARGETS_FUZZ = keygenme_afl keygenme_afl_asan

fuzz: $(TARGETS_FUZZ)

# AFL++ — standard instrumentation
keygenme_afl: $(SRC)
	$(AFL_CC) $(CFLAGS_BASE) -O0 -g -o $@ $<

# AFL++ — instrumentation + AddressSanitizer
keygenme_afl_asan: $(SRC)
	AFL_USE_ASAN=1 $(AFL_CC) $(CFLAGS_BASE) -O0 -g -o $@ $<

# ═════════════════
#  Global target
# ═════════════════

all: standard fuzz
	@echo ""
	@echo "=== All binaries compiled ==="
	@ls -la keygenme_* 2>/dev/null || true

# ═════════════════
#  Quick test
# ═════════════════

# Valid key computed:
#   g1 = 0x1234
#   g2 = g1 XOR 0xBEEF = 0x1234 XOR 0xBEEF = 0xACDB
#   g3 = (g1 + g2) & 0xFFFF = (0x1234 + 0xACDB) & 0xFFFF = 0xBF0F
#   → RENG-1234-ACDB-BF0F

TEST_KEY = RENG-1234-ACDB-BF0F

test: keygenme_O0
	@echo "=== Test with valid key: $(TEST_KEY) ==="
	@./keygenme_O0 "$(TEST_KEY)" && echo "[PASS]" || echo "[FAIL]"
	@echo ""
	@echo "=== Test with invalid key: RENG-0000-0000-0000 ==="
	@./keygenme_O0 "RENG-0000-0000-0000" && echo "[UNEXPECTED PASS]" || echo "[PASS — rejected as expected]"
	@echo ""
	@echo "=== Test with too-short input: AAAA ==="
	@./keygenme_O0 "AAAA" && echo "[UNEXPECTED PASS]" || echo "[PASS — rejected as expected]"

# ═════════════════
#  Cleanup
# ═════════════════

clean:
	rm -f keygenme_O0 keygenme_O2 keygenme_O3
	rm -f keygenme_O0_strip keygenme_O2_strip
	rm -f keygenme_afl keygenme_afl_asan
	rm -f *.o

# ═════════════════
#  Help
# ═════════════════

help:
	@echo "Available targets:"
	@echo "  make              Standard variants (O0, O2, O3, strip)"
	@echo "  make fuzz         AFL++ builds (afl, afl+asan)"
	@echo "  make all          Compile everything"
	@echo "  make test         Run tests with valid/invalid keys"
	@echo "  make clean        Remove artifacts"
	@echo ""
	@echo "Overridable variables:"
	@echo "  CC=gcc            C compiler (default: gcc)"
	@echo "  AFL_CC=afl-gcc    AFL++ compiler (default: afl-gcc)"
	@echo ""
	@echo "Key format: RENG-XXXX-XXXX-XXXX"
	@echo "  Group 1 XOR Group 2 = 0xBEEF"
	@echo "  Group 3 = (Group 1 + Group 2) & 0xFFFF"
	@echo "  Group 1 != 0x0000"
