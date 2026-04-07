# ============================================================================
# Makefile — Chapter 29: Packing detection, unpacking and reconstruction
# Reverse Engineering Training — GNU Toolchain
#
# Produced targets:
#   packed_sample_O0          → -O0 -g        (reference, with DWARF symbols)
#   packed_sample_O0_strip    → -O0, stripped  (reference without symbols)
#   packed_sample_O2          → -O2 -g        (optimized, with symbols)
#   packed_sample_O2_strip    → -O2, stripped  (optimized without symbols)
#   packed_sample_upx         → -O2, stripped, standard UPX packed
#   packed_sample_upx_tampered→ -O2, stripped, UPX packed with altered magic
#                                (resists `upx -d`, requires dynamic unpacking)
#
# Usage:
#   make all          Compile all variants
#   make clean        Remove generated binaries
#   make check        Verify that UPX is installed
#   make compare      Display sizes of all variants
#   make entropy      Display section entropy (requires binwalk)
#
# Prerequisites:
#   - gcc
#   - strip   (binutils)
#   - upx     (apt install upx-ucl)
#   - python3 (for UPX magic byte alteration)
#   - binwalk (optional, for `make entropy`)
#   - readelf (binutils, for `make compare`)
# ============================================================================

CC        := gcc
CFLAGS_O0 := -O0 -g -Wall -Wextra -std=c11
CFLAGS_O2 := -O2 -g -Wall -Wextra -std=c11
LDFLAGS   := -no-pie
STRIP     := strip
UPX       := upx

SRC       := packed_sample.c

# Main targets
BIN_O0          := packed_sample_O0
BIN_O0_STRIP    := packed_sample_O0_strip
BIN_O2          := packed_sample_O2
BIN_O2_STRIP    := packed_sample_O2_strip
BIN_UPX         := packed_sample_upx
BIN_UPX_TAMPER  := packed_sample_upx_tampered

ALL_BINS := $(BIN_O0) $(BIN_O0_STRIP) $(BIN_O2) $(BIN_O2_STRIP) \
            $(BIN_UPX) $(BIN_UPX_TAMPER)

# ============================================================================
# Targets
# ============================================================================

.PHONY: all clean check compare entropy

all: check $(ALL_BINS)
	@echo ""
	@echo "══════════════════════════════════════════════════════"
	@echo " Chapter 29 — All binaries generated successfully"
	@echo "══════════════════════════════════════════════════════"
	@echo ""
	@$(MAKE) --no-print-directory compare

# --- Prerequisite verification ---
check:
	@command -v $(CC) >/dev/null 2>&1 || \
		{ echo "[!] gcc not found. Install build-essential."; exit 1; }
	@command -v $(UPX) >/dev/null 2>&1 || \
		{ echo "[!] upx not found. Install: apt install upx-ucl"; exit 1; }
	@command -v $(STRIP) >/dev/null 2>&1 || \
		{ echo "[!] strip not found. Install binutils."; exit 1; }
	@command -v python3 >/dev/null 2>&1 || \
		{ echo "[!] python3 not found. Install python3."; exit 1; }
	@echo "[OK] All required tools are available."

# --- O0 binary with symbols (reference for debugging) ---
$(BIN_O0): $(SRC)
	$(CC) $(CFLAGS_O0) $(LDFLAGS) -o $@ $<
	@echo "[+] $@ compiled (-O0 -g, with DWARF symbols)"

# --- O0 stripped binary ---
$(BIN_O0_STRIP): $(BIN_O0)
	cp $< $@
	$(STRIP) --strip-all $@
	@echo "[+] $@ generated (-O0, stripped)"

# --- O2 binary with symbols ---
$(BIN_O2): $(SRC)
	$(CC) $(CFLAGS_O2) $(LDFLAGS) -o $@ $<
	@echo "[+] $@ compiled (-O2 -g, with DWARF symbols)"

# --- O2 stripped binary (base for packing) ---
$(BIN_O2_STRIP): $(BIN_O2)
	cp $< $@
	$(STRIP) --strip-all $@
	@echo "[+] $@ generated (-O2, stripped)"

# --- Standard UPX packed (decompressible with `upx -d`) ---
$(BIN_UPX): $(BIN_O2_STRIP)
	cp $< $@
	$(UPX) --best --force $@ >/dev/null 2>&1
	@echo "[+] $@ generated (standard UPX, decompressible with upx -d)"

# --- UPX packed with altered magic bytes ---
#     We corrupt the "UPX!" signature (0x55505821) in the binary
#     to prevent `upx -d` from working. The student will need to
#     use the dynamic approach (memory dump via GDB).
#
#     Method: replace "UPX!" bytes with "FKP!" at each occurrence
#     in the packed file.
$(BIN_UPX_TAMPER): $(BIN_O2_STRIP)
	cp $< $@
	$(UPX) --best --force $@ >/dev/null 2>&1
	@# Alter all UPX! signatures → FKP! (0x464B5021)
	@python3 -c "\
import sys; \
data = open('$@','rb').read(); \
patched = data.replace(b'UPX!', b'FKP!'); \
patched = patched.replace(b'UPX0', b'XP_0'); \
patched = patched.replace(b'UPX1', b'XP_1'); \
patched = patched.replace(b'UPX2', b'XP_2'); \
open('$@','wb').write(patched); \
n = data.count(b'UPX!'); \
print(f'[+] {n} UPX! signature(s) altered in $@')"
	@echo "[+] $@ generated (altered UPX, resists upx -d)"

# --- Size comparison ---
compare:
	@echo ""
	@echo "┌─────────────────────────────────┬──────────┬─────────────────────┐"
	@echo "│ Binary                          │ Size     │ Type                │"
	@echo "├─────────────────────────────────┼──────────┼─────────────────────┤"
	@for bin in $(ALL_BINS); do \
		if [ -f "$$bin" ]; then \
			size=$$(stat -c%s "$$bin" 2>/dev/null || stat -f%z "$$bin" 2>/dev/null); \
			type=$$(file -b "$$bin" | cut -c1-19); \
			printf "│ %-31s │ %6s B │ %-19s │\n" "$$bin" "$$size" "$$type"; \
		fi; \
	done
	@echo "└─────────────────────────────────┴──────────┴─────────────────────┘"
	@echo ""
	@echo "Tip: compare UPX vs original sizes and run"
	@echo "     strings packed_sample_upx | wc -l"
	@echo "     vs"
	@echo "     strings packed_sample_O2_strip | wc -l"

# --- Entropy analysis (requires binwalk) ---
entropy:
	@command -v binwalk >/dev/null 2>&1 || \
		{ echo "[!] binwalk not found. Install: apt install binwalk"; exit 1; }
	@echo ""
	@echo "=== Entropy: NON-packed binary ==="
	@binwalk -E $(BIN_O2_STRIP) 2>/dev/null || true
	@echo ""
	@echo "=== Entropy: UPX packed binary ==="
	@binwalk -E $(BIN_UPX) 2>/dev/null || true
	@echo ""
	@echo "=== Entropy: altered UPX packed binary ==="
	@binwalk -E $(BIN_UPX_TAMPER) 2>/dev/null || true

# --- Cleanup ---
clean:
	rm -f $(ALL_BINS)
	@echo "[OK] Binaries removed."
