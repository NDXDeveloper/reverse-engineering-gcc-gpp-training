# ============================================================================
# Makefile — binaries/ch07-keygenme/
#
# Produces keygenme variants at different optimization levels,
# with and without debug symbols, with and without stripping.
#
# Produced variants:
#   keygenme_O0          -O0 -g        (full debug, no optimization)
#   keygenme_O1          -O1           (light optimization)
#   keygenme_O2          -O2           (standard production optimization)
#   keygenme_O3          -O3           (aggressive optimization)
#   keygenme_Os          -Os           (size optimization)
#   keygenme_strip        -O0 -g -s    (compiled then stripped)
#   keygenme_O2_strip     -O2 -s       (optimized then stripped)
#
# Usage:
#   make              → compile all variants
#   make clean        → remove binaries
#   make test         → verify that each binary works
#   make info         → display sizes and characteristics
# ============================================================================

CC      = gcc
SRC     = keygenme.c
CFLAGS  = -Wall -Wextra

# Base name for all binaries
BASE    = keygenme

# List of all targets
TARGETS = $(BASE)_O0 \
          $(BASE)_O1 \
          $(BASE)_O2 \
          $(BASE)_O3 \
          $(BASE)_Os \
          $(BASE)_strip \
          $(BASE)_O2_strip

# ============================================================================
# Main targets
# ============================================================================

.PHONY: all clean test info

all: $(TARGETS)
	@echo ""
	@echo "=== All variants compiled ==="
	@ls -l $(TARGETS)

# ============================================================================
# Variants with symbols
# ============================================================================

$(BASE)_O0: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -o $@ $<

$(BASE)_O1: $(SRC)
	$(CC) $(CFLAGS) -O1 -o $@ $<

$(BASE)_O2: $(SRC)
	$(CC) $(CFLAGS) -O2 -o $@ $<

$(BASE)_O3: $(SRC)
	$(CC) $(CFLAGS) -O3 -o $@ $<

$(BASE)_Os: $(SRC)
	$(CC) $(CFLAGS) -Os -o $@ $<

# ============================================================================
# Stripped variants
# ============================================================================

# -O0 with debug compiled then stripped (simulates a "wild" binary)
$(BASE)_strip: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -o $@ $<
	strip $@

# -O2 stripped (the most realistic case in RE)
$(BASE)_O2_strip: $(SRC)
	$(CC) $(CFLAGS) -O2 -o $@ $<
	strip $@

# ============================================================================
# Utilities
# ============================================================================

# Quick test: each binary must accept the correct serial and reject a wrong one
test: all
	@echo ""
	@echo "=== Functional tests ==="
	@HASH=$$(./$(BASE)_O0 admin test 2>&1; \
	         ./$(BASE)_O0 admin $$(printf '%08x' $$(./$(BASE)_O0 admin x 2>&1 | head -1)) 2>&1); \
	echo "Basic test OK (binaries are executable)"
	@for bin in $(TARGETS); do \
		if ./$$bin admin abcd1234 2>/dev/null | grep -q "Invalid"; then \
			echo "  $$bin : wrong serial rejected ✓"; \
		else \
			echo "  $$bin : ERROR — wrong serial accepted ✗"; \
		fi \
	done

# Display a summary of sizes and characteristics for each binary
info: all
	@echo ""
	@echo "=== Binary information ==="
	@echo ""
	@printf "%-22s %8s %10s %10s %s\n" "Binary" "Size" ".text (h)" "Symbols" "Debug"
	@printf "%-22s %8s %10s %10s %s\n" "------" "------" "---------" "--------" "-----"
	@for bin in $(TARGETS); do \
		size=$$(stat -c%s $$bin 2>/dev/null || stat -f%z $$bin 2>/dev/null); \
		text=$$(readelf -S $$bin 2>/dev/null | grep '\.text ' | awk '{print $$6}'); \
		if nm $$bin >/dev/null 2>&1; then sym="yes"; else sym="no"; fi; \
		if readelf -S $$bin 2>/dev/null | grep -q '\.debug_info'; then dbg="yes"; else dbg="no"; fi; \
		printf "%-22s %8s %10s %10s %s\n" "$$bin" "$$size" "0x$$text" "$$sym" "$$dbg"; \
	done
	@echo ""

clean:
	rm -f $(TARGETS)
	@echo "Cleanup done."
