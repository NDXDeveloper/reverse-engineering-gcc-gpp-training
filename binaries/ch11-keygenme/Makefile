# ══════════════════════════════════════════════════════════════════════
# binaries/ch11-keygenme/Makefile
# ══════════════════════════════════════════════════════════════════════
#
# Produces the keygenme binary at different optimization levels,
# with and without debug symbols, with and without stripping.
#
# These variants are used from chapter 11 (GDB) and throughout
# Part V (practical cases).
#
# Produced variants:
#
#   keygenme_O0            -O0 -g       Full debug, no optimization
#   keygenme_O0_strip      -O0 stripped  No symbols, no optimization
#   keygenme_O2            -O2 -g       Optimized with symbols
#   keygenme_O2_strip      -O2 stripped  Optimized without symbols (realistic case)
#   keygenme_O3            -O3 -g       Aggressive optimization with symbols
#   keygenme_O3_strip      -O3 stripped  Aggressive optimization without symbols
#   keygenme_pie           -O2 -g -pie  PIE with symbols
#   keygenme_pie_strip     -O2 -pie     PIE stripped (ASLR + no symbols)
#
# Usage:
#   make              Compile all variants
#   make clean        Remove all generated binaries
#   make keygenme_O0  Compile a specific variant
#
# ══════════════════════════════════════════════════════════════════════

CC      = gcc
SRC     = keygenme.c
CFLAGS  = -Wall -Wextra

# ── List of all targets ────────────────────────────────────────────

TARGETS = keygenme_O0       \
          keygenme_O0_strip  \
          keygenme_O2        \
          keygenme_O2_strip  \
          keygenme_O3        \
          keygenme_O3_strip  \
          keygenme_pie       \
          keygenme_pie_strip

.PHONY: all clean

all: $(TARGETS)
	@echo ""
	@echo "══════════════════════════════════════════════════════════"
	@echo "  All keygenme variants have been compiled."
	@echo "══════════════════════════════════════════════════════════"
	@echo ""
	@ls -lh keygenme_* 2>/dev/null | awk '{printf "  %-24s %s\n", $$NF, $$5}'
	@echo ""

# ── Full debug (-O0 -g) ────────────────────────────────────────────
# No optimization, full DWARF symbols.
# Used for learning GDB (sections 11.1 to 11.3).

keygenme_O0: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -no-pie -o $@ $<

# ── No optimization, stripped ──────────────────────────────────────
# Non-optimized code but without symbols.
# Standard prologue/epilogue, but no function names.

keygenme_O0_strip: $(SRC)
	$(CC) $(CFLAGS) -O0 -no-pie -o $@ $<
	strip $@

# ── Optimized with symbols (-O2 -g) ───────────────────────────────
# Optimized code with DWARF symbols.
# Variables "optimized out", reordered instructions (section 11.1).

keygenme_O2: $(SRC)
	$(CC) $(CFLAGS) -O2 -g -no-pie -o $@ $<

# ── Optimized and stripped (-O2, strip) ────────────────────────────
# The most realistic case: optimized, without any symbols.
# This is the primary target for section 11.4 techniques.

keygenme_O2_strip: $(SRC)
	$(CC) $(CFLAGS) -O2 -no-pie -o $@ $<
	strip $@

# ── Aggressive optimization with symbols (-O3 -g) ─────────────────
# Inlining, vectorization, loop unrolling (chapter 16).

keygenme_O3: $(SRC)
	$(CC) $(CFLAGS) -O3 -g -no-pie -o $@ $<

# ── Aggressive optimization, stripped ──────────────────────────────

keygenme_O3_strip: $(SRC)
	$(CC) $(CFLAGS) -O3 -no-pie -o $@ $<
	strip $@

# ── PIE with symbols (-O2 -g -pie) ────────────────────────────────
# Position-Independent Executable. Relative addresses.
# Used for the PIE + ASLR workflow (section 11.4).

keygenme_pie: $(SRC)
	$(CC) $(CFLAGS) -O2 -g -pie -o $@ $<

# ── PIE stripped (-O2 -pie, strip) ─────────────────────────────────
# The hardest case: PIE + ASLR + no symbols.
# Requires starti + base calculation (section 11.4).

keygenme_pie_strip: $(SRC)
	$(CC) $(CFLAGS) -O2 -pie -o $@ $<
	strip $@

# ── Cleanup ────────────────────────────────────────────────────────

clean:
	rm -f $(TARGETS)
	@echo "Cleanup complete."
