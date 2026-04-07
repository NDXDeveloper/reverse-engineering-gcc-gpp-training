# ═══════════════════════════════════════════════════════════════
#  ch13-oop — Makefile
#  Reverse Engineering Training — Chapter 13
#
# Produces 6 variants of the binary:
#   oop_O0        — no optimization, no debug
#   oop_O0_dbg    — no optimization, with DWARF symbols
#   oop_O2        — optimized -O2, with symbols
#   oop_O2_strip  — optimized -O2, stripped
#   oop_O3        — optimized -O3, with symbols
#   oop_O3_strip  — optimized -O3, stripped
#
# Usage:
#   make            — compile all variants
#   make clean      — remove binaries

# ═══════════════════════════════════════════════════════════════

CXX      = g++
CXXFLAGS = -Wall -Wextra -std=c++17
LDFLAGS  = -ldl
SRC      = oop.cpp
BIN_DIR  = .

TARGETS = oop_O0        \
          oop_O0_dbg     \
          oop_O2         \
          oop_O2_strip   \
          oop_O3         \
          oop_O3_strip

.PHONY: all clean

all: $(TARGETS)

oop_O0: $(SRC)
	$(CXX) $(CXXFLAGS) -O0 -o $(BIN_DIR)/$@ $< $(LDFLAGS)

oop_O0_dbg: $(SRC)
	$(CXX) $(CXXFLAGS) -O0 -g -o $(BIN_DIR)/$@ $< $(LDFLAGS)

oop_O2: $(SRC)
	$(CXX) $(CXXFLAGS) -O2 -o $(BIN_DIR)/$@ $< $(LDFLAGS)

oop_O2_strip: $(SRC)
	$(CXX) $(CXXFLAGS) -O2 -s -o $(BIN_DIR)/$@ $< $(LDFLAGS)

oop_O3: $(SRC)
	$(CXX) $(CXXFLAGS) -O3 -o $(BIN_DIR)/$@ $< $(LDFLAGS)

oop_O3_strip: $(SRC)
	$(CXX) $(CXXFLAGS) -O3 -s -o $(BIN_DIR)/$@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)
