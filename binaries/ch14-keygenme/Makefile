# ═══════════════════════════════════════════════════════════════
#  Makefile — ch14-keygenme
#  Crackme for chapters 14 (Callgrind profiling)
#  and 18 (angr solving).
#
#  Targets:
#    make all       — all variants
#    make asan      — ASan + UBSan (chapter 14)
#    make msan      — MSan / Clang (chapter 14)
#    make clean     — cleanup
# ═══════════════════════════════════════════════════════════════

CC      = gcc
CLANG   = clang
SRC     = keygenme.c
WARN    = -Wall -Wextra

TARGETS = keygenme_O0 keygenme_O2 keygenme_O3 keygenme_strip keygenme_O2_strip

.PHONY: all asan msan clean

all: $(TARGETS)

# ── With symbols ─────────────────────────────────────────────────

keygenme_O0: $(SRC)
	$(CC) $(WARN) -O0 -g -o $@ $<

keygenme_O2: $(SRC)
	$(CC) $(WARN) -O2 -g -o $@ $<

keygenme_O3: $(SRC)
	$(CC) $(WARN) -O3 -g -o $@ $<

# ── Without symbols (RE "real-world conditions") ─────────────────

keygenme_strip: $(SRC)
	$(CC) $(WARN) -O0 -s -o $@ $<

keygenme_O2_strip: $(SRC)
	$(CC) $(WARN) -O2 -s -o $@ $<

# ── Sanitizers (chapter 14) ──────────────────────────────────────

asan: $(SRC)
	$(CC) $(WARN) -O0 -g -fno-omit-frame-pointer \
		-fsanitize=address,undefined \
		-o keygenme_asan $<
	@echo "→ keygenme_asan (ASan + UBSan)"
	@echo "  ./keygenme_asan ABCD-1234-EFGH-5678"

msan: $(SRC)
	$(CLANG) $(WARN) -O0 -g -fno-omit-frame-pointer \
		-fsanitize=memory -fsanitize-memory-track-origins=2 \
		-o keygenme_msan $<
	@echo "→ keygenme_msan (MSan, Clang)"

# ── Cleanup ──────────────────────────────────────────────────────

clean:
	rm -f $(TARGETS) keygenme_asan keygenme_msan
	rm -f callgrind.out.* asan.* msan.*
