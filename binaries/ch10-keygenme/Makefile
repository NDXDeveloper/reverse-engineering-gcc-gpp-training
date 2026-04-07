# ============================================================================
# Makefile — Chapter 10: Binary Diffing
# Reverse Engineering Training — Applications compiled with the GNU toolchain
#
# Produces keygenme_v1 and keygenme_v2 binaries at different optimization
# levels, with and without debug symbols, with and without stripping.
#
# Usage:
#   make              Compile all variants
#   make clean        Remove all generated binaries
#   make v1           Compile only v1 variants
#   make v2           Compile only v2 variants
#   make diff-quick   Run a quick triage with radiff2
#
# MIT License — Strictly educational and ethical use.
# ============================================================================

CC      = gcc
CFLAGS  = -Wall -Wextra

# Compilation variants
# -O0 -g   : no optimization, with symbols (ideal for debugging/RE)
# -O0      : no optimization, without DWARF symbols
# -O2      : optimized, with symbols
# -O2 -s   : optimized, stripped (realistic production binary case)
# -O3      : aggressive optimization, with symbols

# --- Main targets ---------------------------------------------------

all: v1 v2

v1: keygenme_v1_O0_dbg \
    keygenme_v1_O0 \
    keygenme_v1_O2_dbg \
    keygenme_v1_O2_strip \
    keygenme_v1_O3_dbg

v2: keygenme_v2_O0_dbg \
    keygenme_v2_O0 \
    keygenme_v2_O2_dbg \
    keygenme_v2_O2_strip \
    keygenme_v2_O3_dbg

# --- Convenience aliases for the chapter 10 checkpoint ------------------
# The names "keygenme_v1" and "keygenme_v2" used in the chapter
# point to the -O0 variants with symbols (the most readable).

keygenme_v1: keygenme_v1_O0_dbg
	cp $< $@

keygenme_v2: keygenme_v2_O0_dbg
	cp $< $@

checkpoint: keygenme_v1 keygenme_v2
	@echo "=== Checkpoint binaries ready ==="
	@echo "  keygenme_v1  (v1, -O0, symbols)"
	@echo "  keygenme_v2  (v2, -O0, symbols)"
	@echo ""
	@echo "Start your analysis with:"
	@echo "  radiff2 -s keygenme_v1 keygenme_v2"

# --- Version 1 (vulnerable) -----------------------------------------------

keygenme_v1_O0_dbg: keygenme_v1.c
	$(CC) $(CFLAGS) -O0 -g -o $@ $<

keygenme_v1_O0: keygenme_v1.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

keygenme_v1_O2_dbg: keygenme_v1.c
	$(CC) $(CFLAGS) -O2 -g -o $@ $<

keygenme_v1_O2_strip: keygenme_v1.c
	$(CC) $(CFLAGS) -O2 -s -o $@ $<

keygenme_v1_O3_dbg: keygenme_v1.c
	$(CC) $(CFLAGS) -O3 -g -o $@ $<

# --- Version 2 (fixed) -------------------------------------------------

keygenme_v2_O0_dbg: keygenme_v2.c
	$(CC) $(CFLAGS) -O0 -g -o $@ $<

keygenme_v2_O0: keygenme_v2.c
	$(CC) $(CFLAGS) -O0 -o $@ $<

keygenme_v2_O2_dbg: keygenme_v2.c
	$(CC) $(CFLAGS) -O2 -g -o $@ $<

keygenme_v2_O2_strip: keygenme_v2.c
	$(CC) $(CFLAGS) -O2 -s -o $@ $<

keygenme_v2_O3_dbg: keygenme_v2.c
	$(CC) $(CFLAGS) -O3 -g -o $@ $<

# --- Utilities -----------------------------------------------------------

# Quick triage: run radiff2 on checkpoint variants
diff-quick: keygenme_v1 keygenme_v2
	@echo "=== radiff2 -s triage ==="
	radiff2 -s keygenme_v1 keygenme_v2
	@echo ""
	@echo "=== Modified functions (radiff2 -AC) ==="
	radiff2 -AC keygenme_v1 keygenme_v2

# Compare stripped -O2 variants (realistic scenario)
diff-stripped: keygenme_v1_O2_strip keygenme_v2_O2_strip
	@echo "=== radiff2 -s triage (stripped, -O2) ==="
	radiff2 -s keygenme_v1_O2_strip keygenme_v2_O2_strip
	@echo ""
	@echo "=== Modified functions ==="
	radiff2 -AC keygenme_v1_O2_strip keygenme_v2_O2_strip

# Display sizes of all generated binaries
sizes: all
	@echo "=== Binary sizes ==="
	@ls -lhS keygenme_v* 2>/dev/null | awk '{print $$5, $$9}'

clean:
	rm -f keygenme_v1 keygenme_v2
	rm -f keygenme_v1_O0_dbg keygenme_v1_O0
	rm -f keygenme_v1_O2_dbg keygenme_v1_O2_strip
	rm -f keygenme_v1_O3_dbg
	rm -f keygenme_v2_O0_dbg keygenme_v2_O0
	rm -f keygenme_v2_O2_dbg keygenme_v2_O2_strip
	rm -f keygenme_v2_O3_dbg

.PHONY: all v1 v2 checkpoint clean diff-quick diff-stripped sizes
