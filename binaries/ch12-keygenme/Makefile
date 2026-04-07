# ============================================================================
# Makefile — binaries/ch12-keygenme/
#
# Produces the keygenme crackme at different optimization levels,
# with and without debug symbols, to serve as support for
# chapter 12 of the Reverse Engineering training.
#
# Produced variants:
#   keygenme_O0          -O0 -g   (no optim, with DWARF symbols)
#   keygenme_O2          -O2 -g   (optimized, with symbols)
#   keygenme_O3          -O3 -g   (aggressive optim, with symbols)
#   keygenme_strip       -O0 -s   (no optim, stripped)
#   keygenme_O2_strip    -O2 -s   (optimized, stripped)
#
# Usage:
#   make                 — compile all variants
#   make keygenme_O0     — compile only the -O0 variant
#   make clean           — remove all binaries
#   make info            — display file + checksec for each variant
# ============================================================================

CC       := gcc
SRC      := keygenme.c
CFLAGS   := -Wall -Wextra

# Common security flags (reproduce the default GCC behavior
# on recent distributions — useful for checksec chapters)
SECFLAGS := -fstack-protector-strong -pie -Wl,-z,relro,-z,now

# List of all targets
TARGETS  := keygenme_O0 \
            keygenme_O2 \
            keygenme_O3 \
            keygenme_strip \
            keygenme_O2_strip

# ──────────────────────────────────────────────
# Default target: compile everything
# ──────────────────────────────────────────────
.PHONY: all clean info

all: $(TARGETS)

# ──────────────────────────────────────────────
# Variants with debug symbols (-g)
# ──────────────────────────────────────────────

# -O0: no optimization — the assembly code corresponds almost
# line-by-line to the C code. Ideal for early chapters (7, 12).
keygenme_O0: $(SRC)
	$(CC) $(CFLAGS) $(SECFLAGS) -O0 -g -o $@ $<
	@echo "[+] $@ compiled (-O0, DWARF symbols)"

# -O2: standard optimization — inlining, loop reorganization,
# dead code elimination. Assembly code diverges noticeably
# from C source. Used in chapters 7, 16 and 18.
keygenme_O2: $(SRC)
	$(CC) $(CFLAGS) $(SECFLAGS) -O2 -g -o $@ $<
	@echo "[+] $@ compiled (-O2, DWARF symbols)"

# -O3: aggressive optimization — vectorization, loop unrolling,
# aggressive inlining. Disassembly may differ greatly from source.
keygenme_O3: $(SRC)
	$(CC) $(CFLAGS) $(SECFLAGS) -O3 -g -o $@ $<
	@echo "[+] $@ compiled (-O3, DWARF symbols)"

# ──────────────────────────────────────────────
# Stripped variants (-s)
# ──────────────────────────────────────────────

# -O0 stripped: no optimization but no symbols.
# Forces the analyst to find main and check_password
# without the help of function names. Chapter 11 (section 11.4).
keygenme_strip: $(SRC)
	$(CC) $(CFLAGS) $(SECFLAGS) -O0 -s -o $@ $<
	@echo "[+] $@ compiled (-O0, stripped)"

# -O2 stripped: optimized AND without symbols — the most
# difficult variant to reverse. Target of the chapter 18
# checkpoint (solving with angr in < 30 lines of Python).
keygenme_O2_strip: $(SRC)
	$(CC) $(CFLAGS) $(SECFLAGS) -O2 -s -o $@ $<
	@echo "[+] $@ compiled (-O2, stripped)"

# ──────────────────────────────────────────────
# Cleanup
# ──────────────────────────────────────────────
clean:
	rm -f $(TARGETS)
	@echo "[+] Binaries removed"

# ──────────────────────────────────────────────
# Info: display metadata for each variant
# Useful for verifying protections after compilation
# ──────────────────────────────────────────────
info: all
	@echo ""
	@echo "════════════════════════════════════════════"
	@echo " Keygenme variant metadata"
	@echo "════════════════════════════════════════════"
	@for bin in $(TARGETS); do \
		echo ""; \
		echo "── $$bin ──"; \
		file $$bin; \
		size $$bin; \
		if command -v checksec >/dev/null 2>&1; then \
			checksec --file=$$bin 2>/dev/null || true; \
		fi; \
		echo ""; \
	done
