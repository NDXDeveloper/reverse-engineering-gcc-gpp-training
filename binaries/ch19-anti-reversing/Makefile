# ═══════════════════════════════════════════════════════════════
# Makefile — Chapter 19: Anti-reversing and compiler protections
# Reverse Engineering Training — GNU Toolchain
#
# Produces many variants of the same binary to illustrate
# the impact of each protection.
#
# Usage:
#   make all          — compile all variants
#   make anti_debug   — anti-debug variants only
#   make protections  — compiler protection variants
#   make packed       — packed variants (requires upx)
#   make clean        — remove all binaries
#   make list         — display target list
#   make checksec     — run checksec on all variants
#
# Strictly educational use — MIT License
# ═══════════════════════════════════════════════════════════════

CC       = gcc
CFLAGS   = -Wall -Wextra
LDFLAGS  =

# Output directory
OUT      = build
$(shell mkdir -p $(OUT))

# ───────────────────────────────────────────
# Source files
# ───────────────────────────────────────────
SRC_ANTI   = anti_reverse.c
SRC_VULN   = vuln_demo.c

# ───────────────────────────────────────────
# Targets: anti_reverse (protected crackme)
# ───────────────────────────────────────────

# 1. Base version with symbols (for comparison)
ANTI_TARGETS  = $(OUT)/anti_reverse_debug

# 2. Stripped versions (section 19.1)
ANTI_TARGETS += $(OUT)/anti_reverse_stripped

# 3. Versions with selective protections (section 19.7-19.8)
ANTI_TARGETS += $(OUT)/anti_reverse_ptrace_only
ANTI_TARGETS += $(OUT)/anti_reverse_timing_only
ANTI_TARGETS += $(OUT)/anti_reverse_procfs_only
ANTI_TARGETS += $(OUT)/anti_reverse_int3_only
ANTI_TARGETS += $(OUT)/anti_reverse_all_checks

# 4. Versions at different optimization levels
ANTI_TARGETS += $(OUT)/anti_reverse_O0
ANTI_TARGETS += $(OUT)/anti_reverse_O2
ANTI_TARGETS += $(OUT)/anti_reverse_O3
ANTI_TARGETS += $(OUT)/anti_reverse_Os

# 5. UPX packed version (section 19.2)
ANTI_PACKED   = $(OUT)/anti_reverse_upx

# ───────────────────────────────────────────
# Targets: vuln_demo (compiler protections)
# ───────────────────────────────────────────

# 6. Canary demonstration (section 19.5)
VULN_TARGETS  = $(OUT)/vuln_no_canary
VULN_TARGETS += $(OUT)/vuln_canary
VULN_TARGETS += $(OUT)/vuln_canary_all

# 7. PIE demonstration (section 19.5)
VULN_TARGETS += $(OUT)/vuln_no_pie
VULN_TARGETS += $(OUT)/vuln_pie

# 8. NX demonstration (section 19.5)
VULN_TARGETS += $(OUT)/vuln_execstack

# 9. RELRO demonstration (section 19.6)
VULN_TARGETS += $(OUT)/vuln_no_relro
VULN_TARGETS += $(OUT)/vuln_partial_relro
VULN_TARGETS += $(OUT)/vuln_full_relro

# 10. Combinations (section 19.9 — checksec audit)
VULN_TARGETS += $(OUT)/vuln_max_protection
VULN_TARGETS += $(OUT)/vuln_min_protection

# ═══════════════════════════════════════════
# Main rules
# ═══════════════════════════════════════════

.PHONY: all anti_debug protections packed clean list checksec

all: anti_debug protections packed
	@echo ""
	@echo "══════════════════════════════════════════"
	@echo " All variants compiled in $(OUT)/"
	@echo "══════════════════════════════════════════"
	@echo ""

anti_debug: $(ANTI_TARGETS)
	@echo "[OK] Anti-debug variants compiled."

protections: $(VULN_TARGETS)
	@echo "[OK] Compiler protection variants compiled."

packed: $(ANTI_PACKED)
	@echo "[OK] Packed variants compiled."

# ═══════════════════════════════════════════
# anti_reverse — variants
# ═══════════════════════════════════════════

# Anti-debug protection control macros
DISABLE_ALL  = -DENABLE_PTRACE_CHECK=0 -DENABLE_PROCFS_CHECK=0 \
               -DENABLE_TIMING_CHECK=0 -DENABLE_INT3_SCAN=0   \
               -DENABLE_CHECKSUM=0
ENABLE_ONLY_PTRACE = $(DISABLE_ALL) -DENABLE_PTRACE_CHECK=1
ENABLE_ONLY_TIMING = $(DISABLE_ALL) -DENABLE_TIMING_CHECK=1
ENABLE_ONLY_PROCFS = $(DISABLE_ALL) -DENABLE_PROCFS_CHECK=1
ENABLE_ONLY_INT3   = $(DISABLE_ALL) -DENABLE_INT3_SCAN=1

# Debug version: symbols, no optim, no anti-debug protections
$(OUT)/anti_reverse_debug: $(SRC_ANTI)
	$(CC) $(CFLAGS) -O0 -g $(DISABLE_ALL) -o $@ $< -lrt

# Stripped version: O2, no symbols
$(OUT)/anti_reverse_stripped: $(SRC_ANTI)
	$(CC) $(CFLAGS) -O2 $(DISABLE_ALL) -o $@ $< -lrt
	strip $@

# ptrace protection only
$(OUT)/anti_reverse_ptrace_only: $(SRC_ANTI)
	$(CC) $(CFLAGS) -O0 -g $(ENABLE_ONLY_PTRACE) -o $@ $< -lrt

# Timing protection only
$(OUT)/anti_reverse_timing_only: $(SRC_ANTI)
	$(CC) $(CFLAGS) -O0 -g $(ENABLE_ONLY_TIMING) -o $@ $< -lrt

# /proc/self/status protection only
$(OUT)/anti_reverse_procfs_only: $(SRC_ANTI)
	$(CC) $(CFLAGS) -O0 -g $(ENABLE_ONLY_PROCFS) -o $@ $< -lrt

# int3 scan protection only
$(OUT)/anti_reverse_int3_only: $(SRC_ANTI)
	$(CC) $(CFLAGS) -O0 -g $(ENABLE_ONLY_INT3) -o $@ $< -lrt

# All anti-debug protections enabled
$(OUT)/anti_reverse_all_checks: $(SRC_ANTI)
	$(CC) $(CFLAGS) -O2 -o $@ $< -lrt
	strip $@

# Optimization levels (without anti-debug to isolate the effect)
$(OUT)/anti_reverse_O0: $(SRC_ANTI)
	$(CC) $(CFLAGS) -O0 -g $(DISABLE_ALL) -o $@ $< -lrt

$(OUT)/anti_reverse_O2: $(SRC_ANTI)
	$(CC) $(CFLAGS) -O2 -g $(DISABLE_ALL) -o $@ $< -lrt

$(OUT)/anti_reverse_O3: $(SRC_ANTI)
	$(CC) $(CFLAGS) -O3 -g $(DISABLE_ALL) -o $@ $< -lrt

$(OUT)/anti_reverse_Os: $(SRC_ANTI)
	$(CC) $(CFLAGS) -Os -g $(DISABLE_ALL) -o $@ $< -lrt

# UPX packed version (requires upx installed)
$(OUT)/anti_reverse_upx: $(SRC_ANTI)
	$(CC) $(CFLAGS) -O2 -no-pie $(DISABLE_ALL) -o $(OUT)/.anti_reverse_pre_upx $< -lrt
	strip $(OUT)/.anti_reverse_pre_upx
	@if command -v upx >/dev/null 2>&1; then \
		upx -9 -o $@ $(OUT)/.anti_reverse_pre_upx; \
	else \
		echo "[WARN] upx not found — copying unpacked binary"; \
		cp $(OUT)/.anti_reverse_pre_upx $@; \
	fi
	@rm -f $(OUT)/.anti_reverse_pre_upx

# ═══════════════════════════════════════════
# vuln_demo — compiler protection variants
# ═══════════════════════════════════════════

# Common flags for vuln_demo
VULN_BASE = $(CFLAGS) -O0 -g

# --- Stack canary (section 19.5) ---

$(OUT)/vuln_no_canary: $(SRC_VULN)
	$(CC) $(VULN_BASE) -fno-stack-protector -o $@ $<

$(OUT)/vuln_canary: $(SRC_VULN)
	$(CC) $(VULN_BASE) -fstack-protector -o $@ $<

$(OUT)/vuln_canary_all: $(SRC_VULN)
	$(CC) $(VULN_BASE) -fstack-protector-all -o $@ $<

# --- PIE / No-PIE (section 19.5) ---

$(OUT)/vuln_no_pie: $(SRC_VULN)
	$(CC) $(VULN_BASE) -no-pie -fno-pie -o $@ $<

$(OUT)/vuln_pie: $(SRC_VULN)
	$(CC) $(VULN_BASE) -pie -fPIE -o $@ $<

# --- NX / Execstack (section 19.5) ---

$(OUT)/vuln_execstack: $(SRC_VULN)
	$(CC) $(VULN_BASE) -z execstack -o $@ $<

# --- RELRO (section 19.6) ---

$(OUT)/vuln_no_relro: $(SRC_VULN)
	$(CC) $(VULN_BASE) -Wl,-z,norelro -no-pie -o $@ $<

$(OUT)/vuln_partial_relro: $(SRC_VULN)
	$(CC) $(VULN_BASE) -Wl,-z,relro -no-pie -o $@ $<

$(OUT)/vuln_full_relro: $(SRC_VULN)
	$(CC) $(VULN_BASE) -Wl,-z,relro,-z,now -no-pie -o $@ $<

# --- Extreme combinations (section 19.9) ---

# Maximum protection: everything enabled
$(OUT)/vuln_max_protection: $(SRC_VULN)
	$(CC) $(CFLAGS) -O2 \
		-fstack-protector-all \
		-pie -fPIE \
		-Wl,-z,relro,-z,now \
		-D_FORTIFY_SOURCE=2 \
		-o $@ $<
	strip $@

# Minimum protection: everything disabled
$(OUT)/vuln_min_protection: $(SRC_VULN)
	$(CC) $(CFLAGS) -O0 -g \
		-fno-stack-protector \
		-no-pie -fno-pie \
		-Wl,-z,norelro \
		-z execstack \
		-o $@ $<

# ═══════════════════════════════════════════
# Utilities
# ═══════════════════════════════════════════

# Run checksec on all variants
checksec: all
	@echo ""
	@echo "═══════════════════════════════════════════════"
	@echo " checksec audit of all variants"
	@echo "═══════════════════════════════════════════════"
	@echo ""
	@if command -v checksec >/dev/null 2>&1; then \
		for bin in $(OUT)/*; do \
			if [ -f "$$bin" ] && [ -x "$$bin" ]; then \
				echo "── $$bin ──"; \
				checksec --file="$$bin"; \
				echo ""; \
			fi; \
		done; \
	else \
		echo "[ERROR] checksec is not installed."; \
		echo "  → apt install checksec  (Debian/Ubuntu)"; \
		echo "  → pip install checksec  (Python)"; \
	fi

# List all targets
list:
	@echo ""
	@echo "anti_reverse (protected crackme):"
	@echo "  anti_reverse_debug          — symbols, O0, no anti-debug protection"
	@echo "  anti_reverse_stripped        — O2, stripped, no anti-debug protection"
	@echo "  anti_reverse_ptrace_only     — ptrace check only"
	@echo "  anti_reverse_timing_only     — timing check only"
	@echo "  anti_reverse_procfs_only     — /proc/self/status check only"
	@echo "  anti_reverse_int3_only       — int3 scan only"
	@echo "  anti_reverse_all_checks      — all protections, stripped, O2"
	@echo "  anti_reverse_O0 / O2 / O3 / Os — optimization levels"
	@echo "  anti_reverse_upx             — packed with UPX"
	@echo ""
	@echo "vuln_demo (compiler protections):"
	@echo "  vuln_no_canary               — without stack canary"
	@echo "  vuln_canary                  — with -fstack-protector"
	@echo "  vuln_canary_all              — with -fstack-protector-all"
	@echo "  vuln_no_pie                  — without PIE"
	@echo "  vuln_pie                     — with PIE"
	@echo "  vuln_execstack               — executable stack (NX disabled)"
	@echo "  vuln_no_relro                — without RELRO"
	@echo "  vuln_partial_relro           — Partial RELRO"
	@echo "  vuln_full_relro              — Full RELRO"
	@echo "  vuln_max_protection          — everything enabled, stripped, O2"
	@echo "  vuln_min_protection          — everything disabled, symbols, O0"
	@echo ""

clean:
	rm -rf $(OUT)
	@echo "[OK] $(OUT)/ directory removed."
