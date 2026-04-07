# ═══════════════════════════════════════════════════════════════
#  Makefile — ch14-crypto
#  Produces the encryption binary at different optimization
#  levels, with and without symbols, for RE analysis.
#
#  Main targets:
#    make all       — compile all variants
#    make asan      — compile with ASan + UBSan (chapter 14)
#    make msan      — compile with MSan via Clang (chapter 14)
#    make clean     — clean all artifacts
#
#  Stripped variants (-s) have no symbols: these are the ones
#  the student will practice RE on in "real-world conditions".
# ═══════════════════════════════════════════════════════════════

CC      = gcc
CLANG   = clang
SRC     = crypto.c
WARN    = -Wall -Wextra

# ── Standard targets ─────────────────────────────────────────────

TARGETS = crypto_O0 crypto_O2 crypto_O3 crypto_strip crypto_O2_strip

.PHONY: all asan msan clean

all: $(TARGETS)

# With debug symbols (-g) — for Valgrind, GDB, Callgrind
crypto_O0: $(SRC)
	$(CC) $(WARN) -O0 -g -o $@ $<

crypto_O2: $(SRC)
	$(CC) $(WARN) -O2 -g -o $@ $<

crypto_O3: $(SRC)
	$(CC) $(WARN) -O3 -g -o $@ $<

# Without symbols (-s) — "realistic" binaries for RE
crypto_strip: $(SRC)
	$(CC) $(WARN) -O0 -s -o $@ $<

crypto_O2_strip: $(SRC)
	$(CC) $(WARN) -O2 -s -o $@ $<

# ── Sanitizer targets (chapter 14) ──────────────────────────────

# ASan + UBSan — memory error and undefined behavior detection
asan: $(SRC)
	$(CC) $(WARN) -O0 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined \
		-o crypto_asan $<
	@echo "→ Compiled: crypto_asan (ASan + UBSan)"
	@echo "  Run with:"
	@echo "  ASAN_OPTIONS=\"halt_on_error=0:detect_leaks=1\" \\"
	@echo "  UBSAN_OPTIONS=\"print_stacktrace=1:halt_on_error=0\" \\"
	@echo "    ./crypto_asan encrypt input.txt output.enc password"

# MSan — uninitialized read detection (Clang only)
msan: $(SRC)
	$(CLANG) $(WARN) -O0 -g -fno-omit-frame-pointer \
		-fsanitize=memory -fsanitize-memory-track-origins=2 \
		-o crypto_msan $<
	@echo "→ Compiled: crypto_msan (MSan, Clang)"
	@echo "  Run with:"
	@echo "  MSAN_OPTIONS=\"halt_on_error=0\" \\"
	@echo "    ./crypto_msan encrypt input.txt output.enc password"

# ── Cleanup ──────────────────────────────────────────────────────

clean:
	rm -f $(TARGETS) crypto_asan crypto_msan
	rm -f *.out *.enc *.txt.dec
	rm -f callgrind.out.* asan.* msan.*
