# ═══════════════════════════════════════════════════════════════
#  ch05-mystery_bin — Makefile
#  Reverse Engineering Training — Chapter 5
#
# Compiles mystery_bin into multiple variants for the checkpoint.
#
# Usage:
#   make              → compile all variants
#   make mystery_bin  → compile the default variant (checkpoint)
#   make clean        → remove compiled binaries
#
# The default checkpoint variant is compiled with -O1 and without strip,
# which offers a good balance: symbols are present (triage is rich),
# but the code has undergone some optimizations (not trivial).

# ═══════════════════════════════════════════════════════════════

CC      = gcc
CFLAGS_COMMON = -Wall -Wextra

# Source
SRC = mystery_bin.c

# ──────────────────────────────────────────────
# Default variant: the one used in the checkpoint
# -O1          : light optimization (some inlining, readable code)
# -g           : DWARF symbols (readelf -S will show .debug_*)
# -fstack-protector-strong : canary enabled (visible in checksec/nm)
# -pie         : PIE enabled (GCC default, made explicit here for clarity)
# -Wl,-z,relro,-z,now : Full RELRO
# ──────────────────────────────────────────────
mystery_bin: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O1 -g \
		-fstack-protector-strong \
		-pie \
		-Wl,-z,relro,-z,now \
		-o $@ $<

# ──────────────────────────────────────────────
# Additional variants (for free exploration)
# ──────────────────────────────────────────────

# No optimization, with full symbols
mystery_bin_O0: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 -g \
		-fstack-protector-strong \
		-pie \
		-Wl,-z,relro,-z,now \
		-o $@ $<

# Optimized -O2, stripped (increased difficulty)
mystery_bin_O2_strip: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O2 \
		-fstack-protector-strong \
		-pie \
		-Wl,-z,relro,-z,now \
		-o $@ $<
	strip $@

# Without canary and without PIE (for checksec comparison)
mystery_bin_no_protections: $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 -g \
		-fno-stack-protector \
		-no-pie \
		-Wl,-z,norelro \
		-o $@ $<

# ──────────────────────────────────────────────
# Utility targets
# ──────────────────────────────────────────────

all: mystery_bin mystery_bin_O0 mystery_bin_O2_strip mystery_bin_no_protections

clean:
	rm -f mystery_bin mystery_bin_O0 mystery_bin_O2_strip mystery_bin_no_protections

.PHONY: all clean
