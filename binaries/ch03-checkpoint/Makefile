# ═══════════════════════════════════════════════════════════════
#  ch03-checkpoint — Makefile
#  Reverse Engineering Training — Chapter 3
#
# Makefile to compile count_lowercase.c at different optimization
# levels, with and without symbols.
#
# Produced targets:
#   count_lowercase_O0          -O0 -g  (debug, with frame pointer)
#   count_lowercase_O2          -O2 -g  (optimized, frame pointer omitted)
#   count_lowercase_O0_strip    -O0     (stripped, as in the checkpoint)
#
# Usage:
#   make all       Compile all variants
#   make clean     Remove generated binaries
#   make disass    Display disassembly of count_lowercase (-O0 stripped variant)
#   make compare   Display side-by-side disassembly -O0 vs -O2

# ═══════════════════════════════════════════════════════════════

CC      = gcc
SRC     = count_lowercase.c
NAME    = count_lowercase

# Common flags
CFLAGS_COMMON = -Wall -Wextra -no-pie

# Variants
BIN_O0       = $(NAME)_O0
BIN_O2       = $(NAME)_O2
BIN_O0_STRIP = $(NAME)_O0_strip

ALL_BINS = $(BIN_O0) $(BIN_O2) $(BIN_O0_STRIP)

.PHONY: all clean disass compare

all: $(ALL_BINS)

# -O0 with debug symbols (for studying with GDB)
$(BIN_O0): $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 -g -o $@ $<

# -O2 with symbols (for comparing optimizations)
$(BIN_O2): $(SRC)
	$(CC) $(CFLAGS_COMMON) -O2 -g -o $@ $<

# -O0 stripped (checkpoint version — no symbols)
$(BIN_O0_STRIP): $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 -o $@ $<
	strip $@

# Disassemble count_lowercase from the -O0 variant (with symbols)
# then also show the stripped version for comparison
disass: $(BIN_O0) $(BIN_O0_STRIP)
	@echo "═══════════════════════════════════════════════════"
	@echo " Disassembly -O0 (with symbols)"
	@echo "═══════════════════════════════════════════════════"
	objdump -d -M intel $(BIN_O0) | sed -n '/<count_lowercase>:/,/^$$/p'
	@echo ""
	@echo "═══════════════════════════════════════════════════"
	@echo " Disassembly -O0 stripped (checkpoint version)"
	@echo "═══════════════════════════════════════════════════"
	@echo "(Use objdump -d -M intel $(BIN_O0_STRIP) and look for"
	@echo " the function manually by its push rbp prologue)"

# Compare -O0 vs -O2 disassembly of count_lowercase
compare: $(BIN_O0) $(BIN_O2)
	@echo "═══════════════════════════════════════════════════"
	@echo " count_lowercase — GCC -O0"
	@echo "═══════════════════════════════════════════════════"
	objdump -d -M intel $(BIN_O0) | sed -n '/<count_lowercase>:/,/^$$/p'
	@echo ""
	@echo "═══════════════════════════════════════════════════"
	@echo " count_lowercase — GCC -O2"
	@echo "═══════════════════════════════════════════════════"
	objdump -d -M intel $(BIN_O2) | sed -n '/<count_lowercase>:/,/^$$/p'

clean:
	rm -f $(ALL_BINS)
