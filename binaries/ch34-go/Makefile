# ============================================================================
# Makefile — Chapter 34: Reverse Engineering Go binaries
# Reverse Engineering Training — Applications compiled with the GNU toolchain
#
# Produces multiple crackme variants to illustrate Go RE challenges:
#   - crackme_go            : standard binary with symbols
#   - crackme_go_strip      : stripped binary (strip -s)
#   - crackme_go_upx        : stripped binary + UPX compressed
#   - crackme_go_nopie      : binary without PIE (facilitates static analysis)
#   - crackme_go_race       : binary compiled with -race (data race detector)
#
# Usage :
#   make              — compile all variants
#   make clean        — remove produced binaries
#   make info         — display sizes and metadata of each variant
#
# Prerequisites:
#   - go >= 1.21       (check with: go version)
#   - strip            (GNU binutils)
#   - upx              (optional, for the packed variant)
#
# MIT License — Strictly educational use.
# ============================================================================

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------
GO         := go
GOFLAGS    :=
STRIP      := strip
UPX        := upx
SRC_DIR    := crackme_go
MODULE     := $(SRC_DIR)/main.go

OUT_DIR    := build
BIN        := $(OUT_DIR)/crackme_go
BIN_STRIP  := $(OUT_DIR)/crackme_go_strip
BIN_UPX    := $(OUT_DIR)/crackme_go_upx
BIN_NOPIE  := $(OUT_DIR)/crackme_go_nopie
BIN_RACE   := $(OUT_DIR)/crackme_go_race

# Check for UPX presence (optional)
HAS_UPX    := $(shell command -v $(UPX) 2>/dev/null)

# List of main targets
TARGETS    := $(BIN) $(BIN_STRIP) $(BIN_NOPIE) $(BIN_RACE)
ifdef HAS_UPX
TARGETS    += $(BIN_UPX)
endif

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
.PHONY: all clean info check-go

all: check-go $(TARGETS)
	@echo ""
	@echo "══════════════════════════════════════════════════════════"
	@echo "  ✅  Chapter 34 — All variants compiled."
	@echo "══════════════════════════════════════════════════════════"
	@echo ""
	@$(MAKE) --no-print-directory info

# --- Environment verification ----------------------------------------
check-go:
	@command -v $(GO) >/dev/null 2>&1 || \
		{ echo "❌ Error: 'go' not found. Install Go >= 1.21."; exit 1; }
	@echo "[*] Go detected: $$($(GO) version)"

# --- Standard binary (symbols preserved) -----------------------------------
$(BIN): $(MODULE) | $(OUT_DIR)
	@echo "[*] Compiling: $@ (symbols preserved)"
	cd $(SRC_DIR) && $(GO) build $(GOFLAGS) -o ../$(BIN) .

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# --- Stripped binary ---------------------------------------------------------
$(BIN_STRIP): $(BIN)
	@echo "[*] Stripping : $@"
	cp $(BIN) $(BIN_STRIP)
	$(STRIP) -s $(BIN_STRIP)

# --- Stripped binary + UPX ---------------------------------------------------
$(BIN_UPX): $(BIN_STRIP)
ifdef HAS_UPX
	@echo "[*] Compression UPX : $@"
	cp $(BIN_STRIP) $(BIN_UPX)
	$(UPX) --best --lzma -q $(BIN_UPX) >/dev/null 2>&1 || \
		{ echo "⚠️  UPX failed (normal on some recent Go versions). Raw copy."; \
		  cp $(BIN_STRIP) $(BIN_UPX); }
else
	@echo "⚠️  UPX not installed — variant $@ skipped."
endif

# --- Binary without PIE (fixed addresses, facilitates static analysis) ----------
$(BIN_NOPIE): $(MODULE)
	@echo "[*] Compiling: $@ (without PIE)"
	cd $(SRC_DIR) && CGO_ENABLED=0 $(GO) build \
		-ldflags="-extldflags=-no-pie" \
		-o ../$(BIN_NOPIE) .

# --- Binary with data race detector ------------------------------------
#     Illustrates the additional runtime instrumentation visible in RE.
$(BIN_RACE): $(MODULE)
	@echo "[*] Compiling: $@ (race detector enabled)"
	cd $(SRC_DIR) && CGO_ENABLED=1 $(GO) build -race -o ../$(BIN_RACE) . 2>/dev/null || \
		{ echo "⚠️  -race requires CGO. Compiling without -race as fallback."; \
		  cd $(SRC_DIR) && $(GO) build -o ../$(BIN_RACE) .; }

# --- Variant information -----------------------------------------
info:
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║  Produced variants — Chapter 34                         ║"
	@echo "╠════════════════════════════╦═══════════╦════════════════════╣"
	@echo "║ File                    ║ Size    ║ Type               ║"
	@echo "╠════════════════════════════╬═══════════╬════════════════════╣"
	@for f in $(BIN) $(BIN_STRIP) $(BIN_UPX) $(BIN_NOPIE) $(BIN_RACE); do \
		if [ -f "$$f" ]; then \
			size=$$(du -h "$$f" | cut -f1); \
			type=$$(file -b "$$f" | cut -d',' -f1); \
			printf "║ %-26s ║ %-9s ║ %-18s ║\n" "$$f" "$$size" "$$type"; \
		fi; \
	done
	@echo "╚════════════════════════════╩═══════════╩════════════════════╝"
	@echo ""
	@echo "💡 Tip: compare sizes between the standard and stripped versions."
	@echo "   Then run 'strings <binary> | grep main\\.' to see the effect"
	@echo "   of stripping on Go function names."

# --- Cleanup ---------------------------------------------------------------
clean:
	@echo "[*] Cleaning chapter 34 binaries..."
	rm -rf $(OUT_DIR)
	@echo "[✓] Cleanup complete."
