# ═══════════════════════════════════════════════════════════════
#  ch08-oop — Makefile
#  Reverse Engineering Training — Chapter 8
#
# Makefile producing ch08-oop binary variants at different optimization
# levels, with and without symbols.
#
# Usage:
#   make all       — compile all variants
#   make clean     — remove generated binaries
#   make check     — compile and run the O0 variant (quick test)
#
# Produced variants:
#   ch08-oop_O0           -O0 -g     (debug, DWARF symbols, no optimization)
#   ch08-oop_O0_strip     -O0        (no symbols, no optimization)
#   ch08-oop_O2           -O2 -g     (optimized, with symbols)
#   ch08-oop_O2_strip     -O2        (optimized, no symbols — realistic case)
#   ch08-oop_O3           -O3 -g     (aggressive optimization, with symbols)

# ═══════════════════════════════════════════════════════════════

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra
SRC      := oop.cpp
STRIP    := strip

# Binary base names
BIN_O0       := ch08-oop_O0
BIN_O0_STRIP := ch08-oop_O0_strip
BIN_O2       := ch08-oop_O2
BIN_O2_STRIP := ch08-oop_O2_strip
BIN_O3       := ch08-oop_O3

ALL_BINS := $(BIN_O0) $(BIN_O0_STRIP) $(BIN_O2) $(BIN_O2_STRIP) $(BIN_O3)

# ============================================================================
# Main targets
# ============================================================================

.PHONY: all clean check

all: $(ALL_BINS)
	@echo ""
	@echo "=== All variants compiled ==="
	@ls -lh $(ALL_BINS)
	@echo ""
	@echo "Size comparison:"
	@for bin in $(ALL_BINS); do \
		printf "  %-25s %s\n" "$$bin" "$$(stat --printf='%s bytes' $$bin 2>/dev/null || stat -f '%z bytes' $$bin 2>/dev/null)"; \
	done

clean:
	rm -f $(ALL_BINS)

check: $(BIN_O0)
	@echo "=== Running $(BIN_O0) ==="
	./$(BIN_O0)

# ============================================================================
# Compilation variants
# ============================================================================

# -O0 -g: no optimization, full DWARF symbols.
# This is the easiest variant to analyze in Ghidra.
# The assembly code closely follows the C++ source structure.
$(BIN_O0): $(SRC)
	$(CXX) $(CXXFLAGS) -O0 -g -o $@ $<

# -O0 stripped: same code as O0, but without .symtab or DWARF.
# Local function names disappear. Dynamic imports and RTTI remain
# present (RTTI is required by the C++ runtime).
$(BIN_O0_STRIP): $(SRC)
	$(CXX) $(CXXFLAGS) -O0 -o $@ $<
	$(STRIP) $@

# -O2 -g: standard optimizations enabled, symbols preserved.
# Code is reorganized: short functions inlined, loops unrolled,
# variables in registers. Useful for observing optimization impact
# while keeping function names as reference points.
$(BIN_O2): $(SRC)
	$(CXX) $(CXXFLAGS) -O2 -g -o $@ $<

# -O2 stripped: this is the most realistic case in RE conditions.
# Distributed binaries (release builds) are typically compiled
# with -O2 and stripped. This is the hardest variant to analyze.
$(BIN_O2_STRIP): $(SRC)
	$(CXX) $(CXXFLAGS) -O2 -o $@ $<
	$(STRIP) $@

# -O3 -g: aggressive optimization. May produce SIMD vectorization,
# aggressive loop unrolling and extensive inlining.
# Symbols are preserved to facilitate comparison with -O0 and -O2.
$(BIN_O3): $(SRC)
	$(CXX) $(CXXFLAGS) -O3 -g -o $@ $<
