# ═══════════════════════════════════════════════════════════════
#  Makefile — Chapter 28: ELF Dropper with network communication
# ═══════════════════════════════════════════════════════════════
#
#  The produced binaries are STRICTLY EDUCATIONAL.
#  Only run them in an isolated sandboxed VM.
#
#  Targets:
#    make all          → Compile all variants
#    make dropper_O0   → -O0 -g  (symbols, no optimization)
#    make dropper_O2   → -O2 -g  (optimized, with symbols)
#    make dropper_O2_strip → -O2, stripped (realistic)
#    make clean        → Remove binaries
#
# ═══════════════════════════════════════════════════════════════

CC      = gcc
SRC     = dropper_sample.c

# Common flags
CFLAGS_COMMON = -Wall -Wextra -std=c11

# Realistic security flags (so checksec shows protections)
CFLAGS_SEC    = -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS_SEC   = -Wl,-z,relro,-z,now -pie

# ─── Variants ────────────────────────────────────────────────

# Variant 1: debug, no optimization, full DWARF symbols
#   → Ideal for learning and step-by-step GDB tracing
CFLAGS_O0     = $(CFLAGS_COMMON) -O0 -g -gdwarf-4 $(CFLAGS_SEC) -fPIE
LDFLAGS_O0    = $(LDFLAGS_SEC)

# Variant 2: optimized -O2, DWARF symbols preserved
#   → Observe the impact of optimizations while keeping names
CFLAGS_O2     = $(CFLAGS_COMMON) -O2 -g -gdwarf-4 $(CFLAGS_SEC) -fPIE
LDFLAGS_O2    = $(LDFLAGS_SEC)

# Variant 3: optimized -O2, stripped (no symbols)
#   → Realistic conditions for analyzing a real sample
CFLAGS_O2S    = $(CFLAGS_COMMON) -O2 $(CFLAGS_SEC) -fPIE
LDFLAGS_O2S   = $(LDFLAGS_SEC) -s

# ─── Targets ───────────────────────────────────────────────────

.PHONY: all clean info

all: dropper_O0 dropper_O2 dropper_O2_strip

dropper_O0: $(SRC)
	$(CC) $(CFLAGS_O0) $(LDFLAGS_O0) -o $@ $<
	@echo "[+] Built $@ (debug, -O0, with symbols)"
	@ls -lh $@
	@file $@

dropper_O2: $(SRC)
	$(CC) $(CFLAGS_O2) $(LDFLAGS_O2) -o $@ $<
	@echo "[+] Built $@ (optimized, -O2, with symbols)"
	@ls -lh $@
	@file $@

dropper_O2_strip: $(SRC)
	$(CC) $(CFLAGS_O2S) $(LDFLAGS_O2S) -o $@ $<
	@echo "[+] Built $@ (optimized, -O2, stripped)"
	@ls -lh $@
	@file $@

# ─── Utilities ──────────────────────────────────────────────

# Display a summary of produced binaries (size, sections, protections)
info: all
	@echo ""
	@echo "══════════════════════════════════════════════════"
	@echo "  Summary of produced binaries"
	@echo "══════════════════════════════════════════════════"
	@echo ""
	@for bin in dropper_O0 dropper_O2 dropper_O2_strip; do \
		echo "--- $$bin ---"; \
		file $$bin; \
		size $$bin; \
		echo "Sections:"; \
		readelf -S $$bin 2>/dev/null | grep -E '\.text|\.data|\.bss|\.rodata|\.plt|\.got' || true; \
		if command -v checksec >/dev/null 2>&1; then \
			checksec --file=$$bin 2>/dev/null || true; \
		fi; \
		echo ""; \
	done

clean:
	rm -f dropper_O0 dropper_O2 dropper_O2_strip
	@echo "[*] Cleaned all binaries"
