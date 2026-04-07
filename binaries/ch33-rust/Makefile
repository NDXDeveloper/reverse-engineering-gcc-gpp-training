# ============================================================================
# Reverse Engineering Training — Chapter 33
# Makefile for the Rust crackme
#
# Produces 3 binary variants:
#   1. crackme_rust_debug      — non-optimized, full DWARF symbols
#   2. crackme_rust_release    — optimized -O3, symbols preserved
#   3. crackme_rust_strip      — optimized -O3, stripped, LTO, panic=abort
#
# Prerequisites:
#   - rustc / cargo (https://rustup.rs)
#   - The GNU ld linker (installed with gcc/binutils)
#
# Quick check:
#   $ rustc --version
#   $ cargo --version
#   $ ld --version
# ============================================================================

CARGO       := cargo
STRIP       := strip
READELF     := readelf
FILE_CMD    := file

CRATE_DIR   := crackme_rust
TARGET_DIR  := $(CRATE_DIR)/target

# Output binary names (copied to the ch33 folder root)
OUT_DEBUG   := crackme_rust_debug
OUT_RELEASE := crackme_rust_release
OUT_STRIP   := crackme_rust_strip

# ── Main targets ─────────────────────────────────────────

.PHONY: all debug release release-strip clean info help

all: debug release release-strip info

# ── Debug: opt-level 0, full symbols ─────────────────────

debug:
	@echo "══════════════════════════════════════════════"
	@echo "  [1/3] DEBUG compilation (opt-level 0, DWARF symbols)"
	@echo "══════════════════════════════════════════════"
	cd $(CRATE_DIR) && $(CARGO) build 2>&1
	cp $(TARGET_DIR)/debug/crackme_rust ./$(OUT_DEBUG)
	@echo "[OK] $(OUT_DEBUG) generated."
	@echo ""

# ── Release: opt-level 3, symbols preserved ──────────────────

release:
	@echo "══════════════════════════════════════════════"
	@echo "  [2/3] RELEASE compilation (opt-level 3, symbols)"
	@echo "══════════════════════════════════════════════"
	cd $(CRATE_DIR) && $(CARGO) build --release 2>&1
	cp $(TARGET_DIR)/release/crackme_rust ./$(OUT_RELEASE)
	@echo "[OK] $(OUT_RELEASE) generated."
	@echo ""

# ── Stripped release: optimized, LTO, panic=abort, strip ───────

release-strip:
	@echo "══════════════════════════════════════════════"
	@echo "  [3/3] STRIPPED RELEASE compilation (LTO, panic=abort, strip)"
	@echo "══════════════════════════════════════════════"
	cd $(CRATE_DIR) && $(CARGO) build --profile release-strip 2>&1
	cp $(TARGET_DIR)/release-strip/crackme_rust ./$(OUT_STRIP)
	@# Double strip for safety (some cargo versions strip incompletely)
	$(STRIP) --strip-all ./$(OUT_STRIP) 2>/dev/null || true
	@echo "[OK] $(OUT_STRIP) generated."
	@echo ""

# ── Information about produced binaries ─────────────────────

info: 
	@echo "══════════════════════════════════════════════"
	@echo "  Summary of generated binaries"
	@echo "══════════════════════════════════════════════"
	@echo ""
	@for bin in $(OUT_DEBUG) $(OUT_RELEASE) $(OUT_STRIP); do \
		if [ -f $$bin ]; then \
			echo "── $$bin ──"; \
			echo "  Size: $$(du -h $$bin | cut -f1)"; \
			echo "  Type   : $$($(FILE_CMD) $$bin | cut -d: -f2-)"; \
			echo "  Sections : $$($(READELF) -S $$bin 2>/dev/null | grep -c '\\[')"; \
			echo "  Symbols: $$($(READELF) -s $$bin 2>/dev/null | grep -c 'FUNC')"; \
			echo ""; \
		fi \
	done
	@echo "══════════════════════════════════════════════"
	@echo "  Compare sizes and symbol counts"
	@echo "  between the 3 variants — this is the starting point"
	@echo "  of chapter 33."
	@echo "══════════════════════════════════════════════"

# ── Cleanup ──────────────────────────────────────────────────

clean:
	cd $(CRATE_DIR) && $(CARGO) clean 2>/dev/null || true
	rm -f $(OUT_DEBUG) $(OUT_RELEASE) $(OUT_STRIP)
	@echo "[OK] Cleanup complete."

# ── Help ───────────────────────────────────────────────────────

help:
	@echo "Available targets:"
	@echo "  make all            — Compile all 3 variants + display summary"
	@echo "  make debug          — Compile in debug (opt-level 0, DWARF)"
	@echo "  make release        — Compile in release (opt-level 3, symbols)"
	@echo "  make release-strip  — Compile stripped release (LTO, strip)"
	@echo "  make info           — Display info about existing binaries"
	@echo "  make clean          — Remove all binaries and the cargo cache"
	@echo "  make help           — Display this help"
