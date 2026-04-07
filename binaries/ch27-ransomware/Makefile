# ============================================================================
#  Reverse Engineering Training — Chapter 27
#  Makefile: compilation of the educational ransomware sample
# ============================================================================
#
#  Strictly educational use — sandboxed VM required.
#
#  Targets:
#    make all        → compile all 3 variants
#    make debug      → ransomware_O0       (debug, DWARF symbols)
#    make optimized  → ransomware_O2       (optimized, symbols)
#    make stripped   → ransomware_O2_strip (optimized, no symbols)
#    make testenv    → create /tmp/test/ with test files
#    make clean      → remove compiled binaries
#    make reset      → remove /tmp/test/ and recreate it clean
#
#  Dependency: libssl-dev
#    sudo apt install libssl-dev
# ============================================================================

CC        := gcc
SRC       := ransomware_sample.c
LIBS      := -lssl -lcrypto
WARNINGS  := -Wall -Wextra -Wpedantic

# --- Flags per variant ---------------------------------------------------

CFLAGS_DBG   := $(WARNINGS) -O0 -g3 -ggdb -DDEBUG
CFLAGS_OPT   := $(WARNINGS) -O2 -g
CFLAGS_STRIP := $(WARNINGS) -O2 -s

# --- Output binary names -------------------------------------------

BIN_DBG   := ransomware_O0
BIN_OPT   := ransomware_O2
BIN_STRIP := ransomware_O2_strip

# --- Test directory and files ----------------------------------------

TEST_DIR    := /tmp/test

# ============================================================================
#  Targets
# ============================================================================

.PHONY: all debug optimized stripped clean testenv reset help

all: debug optimized stripped
	@echo ""
	@echo "[+] 3 variants compiled:"
	@ls -lh $(BIN_DBG) $(BIN_OPT) $(BIN_STRIP)
	@echo ""
	@echo "Remember to run 'make testenv' to prepare /tmp/test/"

# --- Debug variant (O0, DWARF symbols) -----------------------------------

debug: $(BIN_DBG)

$(BIN_DBG): $(SRC)
	$(CC) $(CFLAGS_DBG) -o $@ $< $(LIBS)
	@echo "[+] $@ compiled (debug, DWARF symbols)"

# --- Optimized variant (O2, symbols) -------------------------------------

optimized: $(BIN_OPT)

$(BIN_OPT): $(SRC)
	$(CC) $(CFLAGS_OPT) -o $@ $< $(LIBS)
	@echo "[+] $@ compiled (optimized, with symbols)"

# --- Stripped variant (O2, no symbols) ----------------------------------

stripped: $(BIN_STRIP)

$(BIN_STRIP): $(SRC)
	$(CC) $(CFLAGS_STRIP) -o $@ $< $(LIBS)
	strip --strip-all $@
	@echo "[+] $@ compiled (optimized, stripped)"

# --- Test environment preparation ---------------------------------

testenv:
	@echo "[*] Creating $(TEST_DIR) with test files..."
	@mkdir -p $(TEST_DIR)
	@mkdir -p $(TEST_DIR)/subfolder
	@echo "This is a very important confidential document." > $(TEST_DIR)/document.txt
	@echo "# Meeting notes\n\n- Point 1\n- Point 2\n- Point 3" > $(TEST_DIR)/notes.md
	@echo "Fictitious PDF report content for the exercise." > $(TEST_DIR)/report.pdf
	@head -c 2048 /dev/urandom > $(TEST_DIR)/photo.jpg
	@echo "name,firstname,salary\nDupont,Jean,45000\nMartin,Claire,52000" > $(TEST_DIR)/budget.csv
	@echo "File in a subfolder to test recursion." > $(TEST_DIR)/subfolder/nested.txt
	@echo ""
	@echo "[+] Test environment ready:"
	@find $(TEST_DIR) -type f | sort
	@echo ""
	@echo "Take a VM snapshot NOW before running the sample."

# --- Reset: clean and recreate the test environment ----------------------

reset:
	@echo "[*] Removing $(TEST_DIR)..."
	@rm -rf $(TEST_DIR)
	@$(MAKE) --no-print-directory testenv

# --- Binary cleanup -------------------------------------------------

clean:
	rm -f $(BIN_DBG) $(BIN_OPT) $(BIN_STRIP)
	@echo "[+] Binaries removed."

# --- Help -------------------------------------------------------------------

help:
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════╗"
	@echo "║  Chapter 27 — Ransomware sample Makefile                ║"
	@echo "╠══════════════════════════════════════════════════════════╣"
	@echo "║  make all        Compile all 3 variants                 ║"
	@echo "║  make debug      ransomware_O0       (-O0 -g3)         ║"
	@echo "║  make optimized  ransomware_O2       (-O2 -g)          ║"
	@echo "║  make stripped   ransomware_O2_strip (-O2, strip)       ║"
	@echo "║  make testenv    Create /tmp/test/ with test files      ║"
	@echo "║  make reset      Clean and recreate /tmp/test/          ║"
	@echo "║  make clean      Remove binaries                        ║"
	@echo "║  make help       Display this help                      ║"
	@echo "╠══════════════════════════════════════════════════════════╣"
	@echo "║  Sandboxed VM required for execution!                   ║"
	@echo "║  Dependency: sudo apt install libssl-dev                ║"
	@echo "╚══════════════════════════════════════════════════════════╝"
	@echo ""
