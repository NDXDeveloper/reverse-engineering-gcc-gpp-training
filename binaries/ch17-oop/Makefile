# ============================================================================
# Reverse Engineering Training — Chapter 17
# Makefile for the object-oriented C++ training binary
#
# Produces multiple variants of the same source to allow comparison
# in static and dynamic analysis:
#
#   oop_O0          → -O0 -g     (non-optimized, full symbols)
#   oop_O0_strip    → -O0 -s     (non-optimized, stripped)
#   oop_O2          → -O2 -g     (optimized, full symbols)
#   oop_O2_strip    → -O2 -s     (optimized, stripped)
#   oop_O3          → -O3 -g     (aggressive optimization, symbols)
#   oop_O3_strip    → -O3 -s     (aggressive optimization, stripped)
#
# Usage:
#   make all        → compile all variants
#   make clean      → remove all binaries
#   make oop_O0     → compile only the -O0 -g variant
#
# ============================================================================

CXX      := g++
CXXSTD   := -std=c++17
WARNINGS := -Wall -Wextra -Wpedantic
SRC      := oop.cpp
LDFLAGS  := -lm

# Common flags for all variants
# -rdynamic: exports dynamic symbols (useful for RTTI and dlopen)
# We do NOT use -fno-rtti to keep RTTI enabled (chapter 17.3 exercise)
COMMON   := $(CXXSTD) $(WARNINGS) -rdynamic

# ---- Binary prefix ---------------------------------------------------
# Produced binaries are prefixed with the chapter number.
PREFIX := ch17-oop

# ---- Targets ----------------------------------------------------------------

.PHONY: all clean info

all: $(PREFIX)_O0 $(PREFIX)_O0_strip $(PREFIX)_O2 $(PREFIX)_O2_strip $(PREFIX)_O3 $(PREFIX)_O3_strip

# --- Non-optimized variants (-O0) ---

$(PREFIX)_O0: $(SRC)
	$(CXX) $(COMMON) -O0 -g -o $@ $< $(LDFLAGS)
	@echo "[OK] $@ (non-optimized, full symbols)"

$(PREFIX)_O0_strip: $(SRC)
	$(CXX) $(COMMON) -O0 -s -o $@ $< $(LDFLAGS)
	@echo "[OK] $@ (non-optimized, stripped)"

# --- Optimized variants (-O2) ---

$(PREFIX)_O2: $(SRC)
	$(CXX) $(COMMON) -O2 -g -o $@ $< $(LDFLAGS)
	@echo "[OK] $@ (optimized -O2, full symbols)"

$(PREFIX)_O2_strip: $(SRC)
	$(CXX) $(COMMON) -O2 -s -o $@ $< $(LDFLAGS)
	@echo "[OK] $@ (optimized -O2, stripped)"

# --- Aggressively optimized variants (-O3) ---

$(PREFIX)_O3: $(SRC)
	$(CXX) $(COMMON) -O3 -g -o $@ $< $(LDFLAGS)
	@echo "[OK] $@ (optimized -O3, full symbols)"

$(PREFIX)_O3_strip: $(SRC)
	$(CXX) $(COMMON) -O3 -s -o $@ $< $(LDFLAGS)
	@echo "[OK] $@ (optimized -O3, stripped)"

# ---- Cleanup --------------------------------------------------------------

clean:
	rm -f $(PREFIX)_O0 $(PREFIX)_O0_strip $(PREFIX)_O2 $(PREFIX)_O2_strip $(PREFIX)_O3 $(PREFIX)_O3_strip
	@echo "[CLEAN] All binaries removed."

# ---- Useful info for RE -------------------------------------------------

BINS_ALL   := $(PREFIX)_O0 $(PREFIX)_O0_strip $(PREFIX)_O2 $(PREFIX)_O2_strip $(PREFIX)_O3 $(PREFIX)_O3_strip
BINS_SYM   := $(PREFIX)_O0 $(PREFIX)_O2 $(PREFIX)_O3
BINS_STRIP := $(PREFIX)_O0_strip $(PREFIX)_O2_strip $(PREFIX)_O3_strip

info: all
	@echo ""
	@echo "====== Size comparison ======"
	@ls -lh $(BINS_ALL)
	@echo ""
	@echo "====== .text sections (code size) ======"
	@for bin in $(BINS_ALL); do \
		printf "%-24s " "$bin:"; \
		size --format=SysV "$bin" 2>/dev/null | grep '\.text' | awk '{print $2 " bytes"}'; \
	done
	@echo ""
	@echo "====== Symbol count ======"
	@for bin in $(BINS_SYM); do \
		printf "%-24s " "$bin:"; \
		nm "$bin" 2>/dev/null | wc -l; \
	done
	@for bin in $(BINS_STRIP); do \
		printf "%-24s " "$bin:"; \
		echo "(stripped — nm finds nothing or almost nothing)"; \
	done
	@echo ""
	@echo "====== Protections (checksec) ======"
	@if command -v checksec > /dev/null 2>&1; then \
		for bin in $(PREFIX)_O0 $(PREFIX)_O2_strip; do \
			echo "--- $bin ---"; \
			checksec --file="$bin" 2>/dev/null || checksec "$bin" 2>/dev/null; \
		done; \
	else \
		echo "checksec not installed — see chapter 4"; \
	fi
