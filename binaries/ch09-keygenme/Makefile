# ============================================================================
# Makefile — keygenme (Reverse Engineering Training)
#
# Produces the same binary at different optimization levels,
# with and without debug symbols, to illustrate the impact
# of compilation flags on reverse engineering.
#
# Produced variants:
#   keygenme_O0          -O0 -g   (no optim, DWARF symbols)
#   keygenme_O0_strip    -O0      (no optim, stripped)
#   keygenme_O2          -O2 -g   (standard optim, symbols)
#   keygenme_O2_strip    -O2      (standard optim, stripped)
#   keygenme_O3          -O3 -g   (aggressive optim, symbols)
#   keygenme_O3_strip    -O3      (aggressive optim, stripped)
#
# Usage:
#   make            — compile all variants
#   make clean      — remove binaries
#   make info       — display size and sections of each variant
# ============================================================================

CC      := gcc
SRC     := keygenme.c
CFLAGS  := -Wall -Wextra

# All variants to produce
TARGETS := keygenme_O0      keygenme_O0_strip \
           keygenme_O2      keygenme_O2_strip \
           keygenme_O3      keygenme_O3_strip

# ── Main targets ────────────────────────────────────────────────────────────

.PHONY: all clean info

all: $(TARGETS)

# ── Variants with symbols (-g) ──────────────────────────────────────────────

keygenme_O0: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -o $@ $<

keygenme_O2: $(SRC)
	$(CC) $(CFLAGS) -O2 -g -o $@ $<

keygenme_O3: $(SRC)
	$(CC) $(CFLAGS) -O3 -g -o $@ $<

# ── Stripped variants ───────────────────────────────────────────────────────
# We first compile with -g then strip, to be able to optionally
# keep a separate .debug file (not done here, but possible with
# objcopy --only-keep-debug).

keygenme_O0_strip: $(SRC)
	$(CC) $(CFLAGS) -O0 -o $@ $<
	strip $@

keygenme_O2_strip: $(SRC)
	$(CC) $(CFLAGS) -O2 -o $@ $<
	strip $@

keygenme_O3_strip: $(SRC)
	$(CC) $(CFLAGS) -O3 -o $@ $<
	strip $@

# ── Cleanup ─────────────────────────────────────────────────────────────────

clean:
	rm -f $(TARGETS)

# ── Info: quick comparison of variants ──────────────────────────────────────
# Displays the size of each binary and the number of visible symbols.
# Useful for the chapter 2 checkpoint and for comparing flag impact.

info: all
	@echo ""
	@echo "══════════════════════════════════════════════════════════════"
	@echo "  Variant                 Size        Symbols (.symtab)"
	@echo "══════════════════════════════════════════════════════════════"
	@for bin in $(TARGETS); do \
		size=$$(stat --format='%s' $$bin 2>/dev/null || stat -f '%z' $$bin 2>/dev/null); \
		syms=$$(nm $$bin 2>/dev/null | wc -l || echo "0"); \
		printf "  %-24s %6s B    %s symbols\n" "$$bin" "$$size" "$$syms"; \
	done
	@echo "══════════════════════════════════════════════════════════════"
	@echo ""
