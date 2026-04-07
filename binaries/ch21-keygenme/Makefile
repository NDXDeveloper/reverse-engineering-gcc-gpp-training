# ═══════════════════════════════════════════════════════════════
#  ch21-keygenme — Makefile
#  Reverse Engineering Training — Chapter 21
#
# Makefile — Chapter 21: keygenme (5 variants)
#
# Produces:
#   keygenme_O0         -O0 -g          (debug, non-optimized)
#   keygenme_O2         -O2 -g          (optimized, with symbols)
#   keygenme_O3         -O3 -g          (aggressive optim, with symbols)
#   keygenme_strip      -O0    stripped  (non-optimized, no symbols)
#   keygenme_O2_strip   -O2    stripped  (optimized, no symbols)
#
# Usage:
#   make              → compile all variants
#   make clean        → remove binaries
#   make keygenme_O0  → compile a single variant

# ═══════════════════════════════════════════════════════════════

CC      := gcc
SRC     := keygenme.c

# Common flags: strict warnings, C11 standard
CFLAGS_COMMON := -Wall -Wextra -Wpedantic -std=c11

# ── Targets ────────────────────────────────────────────────

ALL := keygenme_O0 keygenme_O2 keygenme_O3 keygenme_strip keygenme_O2_strip

.PHONY: all clean info

all: $(ALL)
	@echo ""
	@echo "5 variants compiled successfully:"
	@ls -lh $(ALL)
	@echo ""

# ── Variant 1: -O0 with symbols ───────────────────────────

keygenme_O0: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 -g -o $@ $<
	@echo "  [OK] $@ (-O0 -g)"

# ── Variant 2: -O2 with symbols ───────────────────────────

keygenme_O2: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O2 -g -o $@ $<
	@echo "  [OK] $@ (-O2 -g)"

# ── Variant 3: -O3 with symbols ───────────────────────────

keygenme_O3: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O3 -g -o $@ $<
	@echo "  [OK] $@ (-O3 -g)"

# ── Variant 4: -O0 stripped ───────────────────────────────

keygenme_strip: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 -o $@ $<
	strip --strip-all $@
	@echo "  [OK] $@ (-O0, stripped)"

# ── Variant 5: -O2 stripped ───────────────────────────────

keygenme_O2_strip: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O2 -o $@ $<
	strip --strip-all $@
	@echo "  [OK] $@ (-O2, stripped)"

# ── Cleanup ────────────────────────────────────────────────

clean:
	rm -f $(ALL)
	@echo "Binaries removed."

# ── Info: display sizes and sections for comparison ────────

info: all
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════╗"
	@echo "║          Comparison of 5 variants                       ║"
	@echo "╚══════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "── Sizes ────────────────────────────────────────────────"
	@for bin in $(ALL); do \
		printf "  %-22s %s\n" "$$bin" "$$(stat --format='%s bytes' $$bin 2>/dev/null || stat -f '%z bytes' $$bin 2>/dev/null)"; \
	done
	@echo ""
	@echo "── .text sections ──────────────────────────────────────"
	@for bin in $(ALL); do \
		printf "  %-22s " "$$bin"; \
		readelf -S $$bin 2>/dev/null | grep '\.text' | awk '{print "size:", $$6, "bytes (hex)"}'; \
	done
	@echo ""
	@echo "── Symbols (nm) ────────────────────────────────────────"
	@for bin in $(ALL); do \
		count=$$(nm $$bin 2>/dev/null | wc -l); \
		printf "  %-22s %s symbols\n" "$$bin" "$$count"; \
	done
	@echo ""
	@echo "── file(1) ─────────────────────────────────────────────"
	@for bin in $(ALL); do \
		printf "  %-22s " "$$bin"; \
		file $$bin | cut -d: -f2; \
	done
	@echo ""
