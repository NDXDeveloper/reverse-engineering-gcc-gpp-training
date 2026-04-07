# ═══════════════════════════════════════════════════════════════
#  ch20-keygenme — Makefile
#  Reverse Engineering Training — Chapter 20
#
# Produces 6 binary variants:
#   keygenme_O0        — no optimization, no debug
#   keygenme_O0_dbg    — no optimization, with DWARF symbols
#   keygenme_O2        — optimized -O2, with symbols
#   keygenme_O2_strip  — optimized -O2, stripped, non-PIE
#   keygenme_O3        — optimized -O3, with symbols
#   keygenme_O3_strip  — optimized -O3, stripped, non-PIE
#
# Usage:
#   make            — compile all variants
#   make clean      — remove binaries

# ═══════════════════════════════════════════════════════════════

CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11
SRC     = keygenme.c
BIN_DIR = .

TARGETS = keygenme_O0        \
          keygenme_O0_dbg     \
          keygenme_O2         \
          keygenme_O2_strip   \
          keygenme_O3         \
          keygenme_O3_strip

.PHONY: all clean

all: $(TARGETS)

# -O0 without debug symbols
keygenme_O0: $(SRC)
	$(CC) $(CFLAGS) -O0 -o $(BIN_DIR)/$@ $<

# -O0 with DWARF symbols (debug)
keygenme_O0_dbg: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -o $(BIN_DIR)/$@ $<

# -O2 with symbols
keygenme_O2: $(SRC)
	$(CC) $(CFLAGS) -O2 -o $(BIN_DIR)/$@ $<

# -O2 stripped (no symbols, no debug)
keygenme_O2_strip: $(SRC)
	$(CC) $(CFLAGS) -O2 -s -no-pie -o $(BIN_DIR)/$@ $<

# -O3 with symbols
keygenme_O3: $(SRC)
	$(CC) $(CFLAGS) -O3 -o $(BIN_DIR)/$@ $<

# -O3 stripped
keygenme_O3_strip: $(SRC)
	$(CC) $(CFLAGS) -O3 -s -no-pie -o $(BIN_DIR)/$@ $<

clean:
	rm -f $(TARGETS)
