# ═══════════════════════════════════════════════════════════════
#  ch13-keygenme — Makefile
#  Reverse Engineering Training — Chapter 13
#
# Compiles the keygenme crackme at different optimization levels,
# with and without debug symbols.
#
# Targets:
#   make all       — compile all variants
#   make debug     — compile only keygenme_O0
#   make clean     — remove all generated binaries
#
# Produced variants:
#   keygenme_O0          -O0 -g          (no optimization, DWARF symbols)
#   keygenme_O2          -O2 -g          (optimized, symbols)
#   keygenme_O3          -O3 -g          (aggressive optimizations, symbols)
#   keygenme_strip       -O0 -s          (no optimization, stripped)
#   keygenme_O2_strip    -O2 -s          (optimized + stripped)
#
# The keygenme_O0 binary is the primary target for chapter 13.
# The optimized and stripped variants are used in advanced
# chapters (16, 18, 19).

# ═══════════════════════════════════════════════════════════════

CC      := gcc
CFLAGS  := -Wall -Wextra -std=c11
LDFLAGS :=

SRC     := keygenme.c

# ═══════════════════════════════════════════════
# Target list
# ═══════════════════════════════════════════════

ALL_BINS := keygenme_O0 keygenme_O2 keygenme_O3 keygenme_strip keygenme_O2_strip

# ═══════════════════════════════════════════════
# Main targets
# ═══════════════════════════════════════════════

.PHONY: all debug clean info

all: $(ALL_BINS)
	@echo ""
	@echo "All variants compiled:"
	@ls -lh $(ALL_BINS)
	@echo ""
	@echo "Size comparison:"
	@printf "  %-20s %s\n" "keygenme_O0" "$$(stat -c%s keygenme_O0 2>/dev/null || stat -f%z keygenme_O0) bytes"
	@printf "  %-20s %s\n" "keygenme_O2" "$$(stat -c%s keygenme_O2 2>/dev/null || stat -f%z keygenme_O2) bytes"
	@printf "  %-20s %s\n" "keygenme_O3" "$$(stat -c%s keygenme_O3 2>/dev/null || stat -f%z keygenme_O3) bytes"
	@printf "  %-20s %s\n" "keygenme_strip" "$$(stat -c%s keygenme_strip 2>/dev/null || stat -f%z keygenme_strip) bytes"
	@printf "  %-20s %s\n" "keygenme_O2_strip" "$$(stat -c%s keygenme_O2_strip 2>/dev/null || stat -f%z keygenme_O2_strip) bytes"
	@echo ""

debug: keygenme_O0
	@echo "Debug variant compiled: keygenme_O0"

clean:
	rm -f $(ALL_BINS)
	@echo "Cleaned."

info:
	@echo "Valid key: GCC-RE-2024-XPRO"
	@echo ""
	@echo "Checks in order:"
	@echo "  1. Length == 16"
	@echo "  2. Format XXX-XX-XXXX-XXXX (dashes at positions 3, 6, 11)"
	@echo "  3. \"GCC\" prefix"
	@echo "  4. Additive checksum == 0x03DB"
	@echo "  5. strcmp with reference key (XOR-decoded)"

# ═══════════════════════════════════════════════
# Compilation variants
# ═══════════════════════════════════════════════

# -O0 -g: no optimization, full debug symbols.
# This is the primary target for learning RE.
# The assembly code closely follows the C source structure:
# no inlining, no reordering, classic stack with
# rbp prologue/epilogue.
keygenme_O0: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -o $@ $< $(LDFLAGS)

# -O2 -g: standard GCC optimizations.
# Partial inlining, instruction reordering,
# dead code elimination, possible tail calls.
# DWARF symbols are present but source↔assembly
# correspondences are less direct.
keygenme_O2: $(SRC)
	$(CC) $(CFLAGS) -O2 -g -o $@ $< $(LDFLAGS)

# -O3 -g: aggressive optimizations.
# More aggressive inlining, vectorization, loop unrolling.
# Some functions may disappear (inlined into main).
keygenme_O3: $(SRC)
	$(CC) $(CFLAGS) -O3 -g -o $@ $< $(LDFLAGS)

# -O0 -s: no optimization but stripped.
# Function names (validate_key, check_length, etc.)
# disappear from the symbol table. The assembly remains
# readable (no optimization) but functions must be found
# through static analysis.
keygenme_strip: $(SRC)
	$(CC) $(CFLAGS) -O0 -s -o $@ $< $(LDFLAGS)

# -O2 -s: optimized AND stripped.
# The hardest case: code reorganized by optimizations,
# functions potentially inlined, and no symbols for
# orientation. This is the target of the chapter 18
# checkpoint (symbolic execution with angr).
keygenme_O2_strip: $(SRC)
	$(CC) $(CFLAGS) -O2 -s -o $@ $< $(LDFLAGS)
