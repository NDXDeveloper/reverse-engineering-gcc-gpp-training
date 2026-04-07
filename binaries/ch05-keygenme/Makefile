# ═══════════════════════════════════════════════════════════════
#  ch05-keygenme — Makefile
#  Reverse Engineering Training — Chapter 5
#
# Compiles keygenme.c into multiple variants to cover the different
# analysis scenarios of the tutorial.
#
# Usage:
#   make              → compile all variants
#   make keygenme_O0  → compile a specific variant
#   make clean        → remove compiled binaries
#   make verify       → display properties of each variant
#
# Produced variants:
#   keygenme_O0           -O0 -g        (no optimization, debug symbols)
#   keygenme_O1           -O1 -g        (light optimization, debug symbols)
#   keygenme_O2           -O2 -g        (standard optimization, debug symbols)
#   keygenme_O3           -O3 -g        (aggressive optimization, debug symbols)
#   keygenme_Os           -Os -g        (size optimization, debug symbols)
#   keygenme_strip        -O0           (no optimization, stripped)
#   keygenme_O2_strip     -O2           (optimized + stripped = most realistic)
#   keygenme_O3_strip     -O3           (aggressive optimization + stripped)
#   keygenme_nopie        -O0 -g -no-pie (without PIE, for checksec comparison)
#   keygenme_nocanary     -O0 -g -fno-stack-protector (without canary)

# ═══════════════════════════════════════════════════════════════

CC      = gcc
SRC     = keygenme.c

# Common flags for all variants
CFLAGS_COMMON = -Wall -Wextra

# Security flags (Full RELRO + canary + PIE)
SECURITY_FLAGS = -fstack-protector-strong -pie -Wl,-z,relro,-z,now

# ──────────────────────────────────────────────
# Variants with symbols (not stripped)
# Used for learning (chapter 5)
# ──────────────────────────────────────────────

keygenme_O0: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 -g $(SECURITY_FLAGS) -o $@ $<

keygenme_O1: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O1 -g $(SECURITY_FLAGS) -o $@ $<

keygenme_O2: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O2 -g $(SECURITY_FLAGS) -o $@ $<

keygenme_O3: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O3 -g $(SECURITY_FLAGS) -o $@ $<

keygenme_Os: $(SRC)
	$(CC) $(CFLAGS_COMMON) -Os -g $(SECURITY_FLAGS) -o $@ $<

# ──────────────────────────────────────────────
# Stripped variants (without symbols)
# Realistic conditions (chapter 5)
# ──────────────────────────────────────────────

keygenme_strip: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 $(SECURITY_FLAGS) -o $@ $<
	strip $@

keygenme_O2_strip: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O2 $(SECURITY_FLAGS) -o $@ $<
	strip $@

keygenme_O3_strip: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O3 $(SECURITY_FLAGS) -o $@ $<
	strip $@

# ──────────────────────────────────────────────
# Variants with reduced protections
# For comparison with checksec (chapter 5 section 5.6)
# ──────────────────────────────────────────────

keygenme_nopie: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 -g -fstack-protector-strong -no-pie -Wl,-z,relro,-z,now -o $@ $<

keygenme_nocanary: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 -g -fno-stack-protector -pie -Wl,-z,relro,-z,now -o $@ $<

# ──────────────────────────────────────────────
# Variants for diffing
# keygenme_v1 and keygenme_v2 have a slight difference in check_license
# ──────────────────────────────────────────────

keygenme_v1: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O1 -g $(SECURITY_FLAGS) -DVERSION=1 -o $@ $<

keygenme_v2: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O1 -g $(SECURITY_FLAGS) -DVERSION=2 -DPATCH_EXTRA_CHECK -o $@ $<

# ──────────────────────────────────────────────
# Utility targets
# ──────────────────────────────────────────────

# All main variants
all: keygenme_O0 keygenme_O1 keygenme_O2 keygenme_O3 keygenme_Os \
     keygenme_strip keygenme_O2_strip keygenme_O3_strip \
     keygenme_nopie keygenme_nocanary \
     keygenme_v1 keygenme_v2

# Quick check: display file + checksec for each binary
verify: all
	@echo "═══════════════════════════════════════════════"
	@echo "  Verification of keygenme variants"
	@echo "═══════════════════════════════════════════════"
	@for bin in keygenme_O0 keygenme_O2 keygenme_O2_strip \
	            keygenme_nopie keygenme_nocanary; do \
		echo ""; \
		echo "--- $$bin ---"; \
		file $$bin; \
		checksec --file=$$bin 2>/dev/null || echo "(checksec not available)"; \
	done

# Comparative sizes
sizes: all
	@echo "═══════════════════════════════════════════════"
	@echo "  Variant sizes"
	@echo "═══════════════════════════════════════════════"
	@ls -lhS keygenme_* | awk '{print $$5, $$9}'

clean:
	rm -f keygenme_O0 keygenme_O1 keygenme_O2 keygenme_O3 keygenme_Os \
	      keygenme_strip keygenme_O2_strip keygenme_O3_strip \
	      keygenme_nopie keygenme_nocanary \
	      keygenme_v1 keygenme_v2

.PHONY: all clean verify sizes
