# ============================================================================
# Makefile — Chapter 2: The GNU Compilation Chain
#
# Produces all hello binary variants used in the chapter.
# Usage:
#   make              Compile all variants
#   make intermediates Generate intermediate files (.i, .s, .o)
#   make compare      Display a comparative size table
#   make clean        Remove all generated files
#
# MIT License — This content is strictly educational and ethical.
# ============================================================================

CC      = gcc
SRC     = hello.c
CFLAGS  = -Wall -Wextra

# ────────────────────────────────────────────────────────────
# Main targets
# ────────────────────────────────────────────────────────────

# All binary variants produced by this Makefile
BINS = hello_O0 hello_O1 hello_O2 hello_O3 hello_Os \
       hello_debug hello_debug_O2 \
       hello_stripped hello_release \
       hello_nopie hello_static \
       hello_partial_relro hello_fullrelro \
       hello_canary hello_hardened

# Intermediate files (section 2.2)
INTERMEDIATES = hello.i hello.s hello.o \
                hello_O0.s hello_O1.s hello_O2.s hello_O3.s hello_Os.s \
                hello_intel.s

.PHONY: all intermediates compare clean help

all: $(BINS)
	@echo ""
	@echo "All variants compiled successfully."
	@echo "   Run 'make compare' to see the comparative table."

# ────────────────────────────────────────────────────────────
# Section 2.2 — Intermediate files
# ────────────────────────────────────────────────────────────

intermediates: $(INTERMEDIATES)
	@echo ""
	@echo "Intermediate files generated:"
	@ls -lh hello.i hello.s hello.o 2>/dev/null
	@echo ""
	@echo "   hello.i  → Preprocessor output (gcc -E)"
	@echo "   hello.s  → Compiler output, AT&T syntax (gcc -S)"
	@echo "   hello.o  → Relocatable ELF object file (gcc -c)"
	@echo ""
	@echo "   .s files per optimization level:"
	@ls -lh hello_O0.s hello_O1.s hello_O2.s hello_O3.s hello_Os.s 2>/dev/null
	@echo ""
	@echo "   hello_intel.s → Intel syntax (gcc -S -masm=intel)"

# Preprocessor only (section 2.1, 2.2)
hello.i: $(SRC)
	$(CC) -E $(SRC) -o $@

# Compilation only — AT&T assembly (section 2.1, 2.2)
hello.s: $(SRC)
	$(CC) -S -O0 $(SRC) -o $@

# Compilation only — Intel syntax (section 2.2, 7.2)
hello_intel.s: $(SRC)
	$(CC) -S -O0 -masm=intel $(SRC) -o $@

# Assembly only — object file (section 2.2)
hello.o: $(SRC)
	$(CC) -c -O0 $(SRC) -o $@

# Assembly at each optimization level (section 2.2, 2.5)
hello_O0.s: $(SRC)
	$(CC) -S -O0 $(SRC) -o $@

hello_O1.s: $(SRC)
	$(CC) -S -O1 $(SRC) -o $@

hello_O2.s: $(SRC)
	$(CC) -S -O2 $(SRC) -o $@

hello_O3.s: $(SRC)
	$(CC) -S -O3 $(SRC) -o $@

hello_Os.s: $(SRC)
	$(CC) -S -Os $(SRC) -o $@

# ────────────────────────────────────────────────────────────
# Section 2.5 — Optimization levels
# ────────────────────────────────────────────────────────────

hello_O0: $(SRC)
	$(CC) $(CFLAGS) -O0 -o $@ $(SRC)

hello_O1: $(SRC)
	$(CC) $(CFLAGS) -O1 -o $@ $(SRC)

hello_O2: $(SRC)
	$(CC) $(CFLAGS) -O2 -o $@ $(SRC)

hello_O3: $(SRC)
	$(CC) $(CFLAGS) -O3 -o $@ $(SRC)

hello_Os: $(SRC)
	$(CC) $(CFLAGS) -Os -o $@ $(SRC)

# ────────────────────────────────────────────────────────────
# Section 2.5, 2.6 — Debug and stripping
# ────────────────────────────────────────────────────────────

# Full debug: no optimization + DWARF (section 2.6)
hello_debug: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -o $@ $(SRC)

# Debug + optimization: DWARF present but variables sometimes "optimized out"
hello_debug_O2: $(SRC)
	$(CC) $(CFLAGS) -O2 -g -o $@ $(SRC)

# Stripped at compilation (section 2.5)
hello_stripped: $(SRC)
	$(CC) $(CFLAGS) -O0 -s -o $@ $(SRC)

# Typical release build: optimized + stripped (checkpoint)
hello_release: $(SRC)
	$(CC) $(CFLAGS) -O2 -s -o $@ $(SRC)

# ────────────────────────────────────────────────────────────
# Section 2.5, 2.8 — PIE and code positioning
# ────────────────────────────────────────────────────────────

# Non-PIE: fixed addresses, no ASLR for the binary (section 2.8)
hello_nopie: $(SRC)
	$(CC) $(CFLAGS) -O0 -no-pie -o $@ $(SRC)

# Statically linked: no PLT/GOT, no .so (section 2.7, 2.9)
hello_static: $(SRC)
	$(CC) $(CFLAGS) -O0 -static -o $@ $(SRC)

# ────────────────────────────────────────────────────────────
# Section 2.9 — RELRO and protections
# ────────────────────────────────────────────────────────────

# Partial RELRO (default, made explicit here for clarity)
hello_partial_relro: $(SRC)
	$(CC) $(CFLAGS) -O0 -Wl,-z,relro -o $@ $(SRC)

# Full RELRO: GOT read-only after resolution (section 2.9)
hello_fullrelro: $(SRC)
	$(CC) $(CFLAGS) -O0 -Wl,-z,relro,-z,now -o $@ $(SRC)

# Explicit stack canary (section 2.5)
hello_canary: $(SRC)
	$(CC) $(CFLAGS) -O0 -fstack-protector-all -o $@ $(SRC)

# "Hardened" build: all protections (section 2.5, 2.8, 2.9)
hello_hardened: $(SRC)
	$(CC) $(CFLAGS) -O2 -s -pie \
		-fstack-protector-strong \
		-D_FORTIFY_SOURCE=2 \
		-Wl,-z,relro,-z,now \
		-o $@ $(SRC)

# ────────────────────────────────────────────────────────────
# Utilities
# ────────────────────────────────────────────────────────────

# Comparative table of sizes and properties
compare: $(BINS)
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════════╗"
	@echo "║           Variant Comparison — Chapter 2                       ║"
	@echo "╠═══════════════════════╦════════╦═════════╦══════════╦══════════╣"
	@echo "║ Variant               ║  Size  ║ Stripped║ Sections ║ .debug_* ║"
	@echo "╠═══════════════════════╬════════╬═════════╬══════════╬══════════╣"
	@for bin in $(BINS); do \
		size=$$(du -h $$bin | cut -f1); \
		stripped=$$(file $$bin | grep -q 'not stripped' && echo "no " || echo "YES"); \
		nsections=$$(readelf -S $$bin 2>/dev/null | grep -c '\['); \
		ndebug=$$(readelf -S $$bin 2>/dev/null | grep -c '\.debug_'); \
		printf "║ %-21s ║ %6s ║ %7s ║ %8s ║ %8s ║\n" \
			"$$bin" "$$size" "$$stripped" "$$nsections" "$$ndebug"; \
	done
	@echo "╚═══════════════════════╩════════╩═════════╩══════════╩══════════╝"
	@echo ""

clean:
	rm -f $(BINS) $(INTERMEDIATES)
	rm -f hello hello.i hello.s hello.o
	rm -f *.txt
	@echo "Cleanup complete."

help:
	@echo ""
	@echo "Available targets:"
	@echo "  make              Compile all binary variants"
	@echo "  make intermediates Generate intermediate files (.i, .s, .o)"
	@echo "  make compare      Display a comparative table of variants"
	@echo "  make hello_debug  Compile a specific variant"
	@echo "  make clean        Remove all generated files"
	@echo "  make help         Display this help"
	@echo ""
	@echo "Available variants:"
	@echo "  hello_O0 hello_O1 hello_O2 hello_O3 hello_Os"
	@echo "  hello_debug hello_debug_O2"
	@echo "  hello_stripped hello_release"
	@echo "  hello_nopie hello_static"
	@echo "  hello_partial_relro hello_fullrelro"
	@echo "  hello_canary hello_hardened"
	@echo ""
