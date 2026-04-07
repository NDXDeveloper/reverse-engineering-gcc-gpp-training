# ============================================================================
# Makefile — keygenme (Chapter 18)
#
# Produces multiple variants of the same binary to illustrate the impact
# of optimization levels and stripping on reverse engineering.
#
# Usage:
#   make            ← Compile all variants
#   make clean      ← Remove generated binaries
#   make keygenme_O0       ← Compile only the -O0 variant
#
# MIT License — Strictly educational use.
# ============================================================================

CC      := gcc
SRC     := keygenme.c
CFLAGS  := -Wall -Wextra

# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------

# Main variants
TARGETS := keygenme_O0        \
           keygenme_O0_strip   \
           keygenme_O2        \
           keygenme_O2_strip   \
           keygenme_O3        \
           keygenme_O3_strip

.PHONY: all clean info

all: $(TARGETS)
	@echo ""
	@echo "  All variants compiled successfully."
	@echo "  Run 'make info' to see details."
	@echo ""

# --------------------------------------------------------------------------
# With debug symbols (-g) — ideal for learning
# --------------------------------------------------------------------------

keygenme_O0: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -o $@ $<

keygenme_O2: $(SRC)
	$(CC) $(CFLAGS) -O2 -g -o $@ $<

keygenme_O3: $(SRC)
	$(CC) $(CFLAGS) -O3 -g -o $@ $<

# --------------------------------------------------------------------------
# Without symbols (strip) — realistic RE conditions
# --------------------------------------------------------------------------

keygenme_O0_strip: $(SRC)
	$(CC) $(CFLAGS) -O0 -s -o $@ $<

keygenme_O2_strip: $(SRC)
	$(CC) $(CFLAGS) -O2 -s -o $@ $<

keygenme_O3_strip: $(SRC)
	$(CC) $(CFLAGS) -O3 -s -o $@ $<

# --------------------------------------------------------------------------
# Cleanup
# --------------------------------------------------------------------------

clean:
	rm -f $(TARGETS)
	@echo "  Binaries removed."

# --------------------------------------------------------------------------
# Information about generated binaries
# --------------------------------------------------------------------------

info: all
	@echo ""
	@echo "  ╔══════════════════════════════════════════════════════════════╗"
	@echo "  ║           keygenme — Compiled variants                       ║"
	@echo "  ╠══════════════════════════════════════════════════════════════╣"
	@echo "  ║  File                 Optim   Symbols    Primary use         ║"
	@echo "  ╠══════════════════════════════════════════════════════════════╣"
	@echo "  ║  keygenme_O0         -O0     yes        Learning            ║"
	@echo "  ║  keygenme_O0_strip   -O0     no         RE without symbols  ║"
	@echo "  ║  keygenme_O2         -O2     yes        Optimizations       ║"
	@echo "  ║  keygenme_O2_strip   -O2     no         Ch.18 checkpoint    ║"
	@echo "  ║  keygenme_O3         -O3     yes        Vectorization       ║"
	@echo "  ║  keygenme_O3_strip   -O3     no         Advanced challenge  ║"
	@echo "  ╚══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "  Sizes:"
	@ls -lh $(TARGETS) | awk '{printf "    %-20s %s\n", $$NF, $$5}'
	@echo ""
