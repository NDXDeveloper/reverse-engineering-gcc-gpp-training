# ============================================================================
# Makefile — Chapter 24: Reversing an encrypted binary
# Reverse Engineering Training — Applications compiled with the GNU toolchain
#
# Targets:
#   crypto_O0          No optimization, debug symbols
#   crypto_O2          Optimized -O2, debug symbols
#   crypto_O3          Optimized -O3, debug symbols
#   crypto_O2_strip    Optimized -O2, stripped (no symbols)
#   crypto_static      Statically linked to libcrypto (for FLIRT exercise)
#   secret.txt.enc     Encrypted file generated from secret.txt
#
# Prerequisites: gcc, libssl-dev (or libssl-devel)
#   Ubuntu/Debian: sudo apt install libssl-dev
#   Fedora/RHEL:   sudo dnf install openssl-devel
# ============================================================================

CC       = gcc
CFLAGS   = -Wall -Wextra
LDFLAGS  = -lcrypto
SRC      = crypto.c
TARGETS  = crypto_O0 crypto_O2 crypto_O3 crypto_O2_strip crypto_static

.PHONY: all clean test generate_plaintext

# --- Default target: compile everything + generate secret.enc ----------------
all: $(TARGETS) secret.txt.enc secret.enc

# --- Compilation variants ---------------------------------------------

crypto_O0: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -o $@ $< $(LDFLAGS)
	@echo "[OK] $@ (debug, no optimization)"

crypto_O2: $(SRC)
	$(CC) $(CFLAGS) -O2 -g -o $@ $< $(LDFLAGS)
	@echo "[OK] $@ (optimized -O2, with symbols)"

crypto_O3: $(SRC)
	$(CC) $(CFLAGS) -O3 -g -o $@ $< $(LDFLAGS)
	@echo "[OK] $@ (optimized -O3, with symbols)"

crypto_O2_strip: crypto_O2
	cp crypto_O2 $@
	strip $@
	@echo "[OK] $@ (optimized -O2, stripped)"

crypto_static: $(SRC)
	$(CC) $(CFLAGS) -O2 -static -o $@ $< $(LDFLAGS)
	@echo "[OK] $@ (static link — for FLIRT/signature exercises)"

# --- Test plaintext file --------------------------------------------

secret.txt:
	@echo "=== CONFIDENTIAL FILE ===" > $@
	@echo "" >> $@
	@echo "Project: Operation Midnight Sun" >> $@
	@echo "Classification: TOP SECRET" >> $@
	@echo "" >> $@
	@echo "Rendezvous points:" >> $@
	@echo "  - Alpha: 48.8566 N, 2.3522 E (Paris)" >> $@
	@echo "  - Bravo: 51.5074 N, 0.1278 W (London)" >> $@
	@echo "  - Charlie: 40.7128 N, 74.0060 W (New York)" >> $@
	@echo "" >> $@
	@echo "Activation code: SIERRA-TANGO-4729-FOXTROT" >> $@
	@echo "" >> $@
	@echo "This file will self-destruct in 5 seconds..." >> $@
	@echo "(no, not really, this is just an exercise)" >> $@
	@echo "[OK] secret.txt generated"

# --- Encrypted file generation ----------------------------------------

secret.txt.enc: crypto_O0 secret.txt
	./crypto_O0 secret.txt
	@echo "[OK] secret.txt.enc generated (encrypted with crypto_O0)"

# Short alias for .md sections that reference "secret.enc"
secret.enc: secret.txt.enc
	cp secret.txt.enc secret.enc
	@echo "[OK] secret.enc (copy of secret.txt.enc)"

# --- Quick test: verify that all binaries work ------------

test: all
	@echo ""
	@echo "=== Binary verification ==="
	@file crypto_O0 crypto_O2 crypto_O3 crypto_O2_strip crypto_static
	@echo ""
	@echo "=== Symbols in crypto_O0 vs crypto_O2_strip ==="
	@echo "crypto_O0:       $$(nm crypto_O0 2>/dev/null | wc -l) symbols"
	@echo "crypto_O2_strip: $$(nm crypto_O2_strip 2>/dev/null | wc -l) symbols"
	@echo ""
	@echo "=== Dynamic dependencies ==="
	@ldd crypto_O0 2>/dev/null || true
	@echo ""
	@echo "=== crypto_static (no dynamic dependencies) ==="
	@ldd crypto_static 2>/dev/null || echo "(statically linked)"
	@echo ""
	@echo "=== Binary sizes ==="
	@ls -lh crypto_O0 crypto_O2 crypto_O3 crypto_O2_strip crypto_static
	@echo ""
	@echo "=== Verification of secret.txt.enc ==="
	@xxd secret.txt.enc | head -4
	@echo "[OK] All checks passed."

# --- Cleanup ------------------------------------------------------------

clean:
	rm -f $(TARGETS) secret.txt secret.txt.enc secret.enc
	@echo "[OK] Cleaned."
