# ============================================================================
# Chapter 16 — Understanding Compiler Optimizations
# Makefile — Generates all training binary variants
# ============================================================================
#
# Usage:
#   make all          Compile all binaries at all levels
#   make clean        Remove all generated binaries
#   make s16_1        Compile only section 16.1 binaries
#   make s16_2        Compile only section 16.2 binaries
#   make s16_3        Compile only section 16.3 binaries
#   make s16_4        Compile only section 16.4 binaries
#   make s16_5        Compile only section 16.5 binaries (LTO)
#   make s16_6        Compile only section 16.6 binaries
#   make s16_7        Compile section 16.7 binaries (GCC vs Clang — requires clang)
#
# Each binary is produced in 6 variants:
#   _O0          -O0 -g    (non-optimized reference, DWARF symbols)
#   _O1          -O1 -g    (conservative optimizations)
#   _O2          -O2 -g    (standard optimizations)
#   _O3          -O3 -g    (aggressive optimizations)
#   _Os          -Os -g    (size optimization)
#   _O2_strip    -O2 -s    (realistic production: optimized + stripped)
#
# Section 16.3 additionally produces a _O3_avx2 variant with -mavx2.
# Section 16.7 produces _clang_O0 and _clang_O2 variants.
# ============================================================================

CC      := gcc
CXX     := g++
CLANG   := clang
CFLAGS  := -Wall -Wextra -std=c11
CXXFLAGS:= -Wall -Wextra -std=c++17

# Output directory
OUT     := build

# Optimization levels (except strip, handled separately)
OPT_LEVELS := O0 O1 O2 O3 Os

# ============================================================================
# Sources per section
# ============================================================================

# 16.1 — Optimization level impact
SRC_16_1 := opt_levels_demo.c

# 16.2 — Inlining
SRC_16_2 := inlining_demo.c

# 16.3 — Loop unrolling and vectorization
SRC_16_3 := loop_unroll_vec.c

# 16.4 — Tail call optimization
SRC_16_4 := tail_call.c

# 16.5 — Link-Time Optimization (multi-file)
SRC_16_5_MAIN := lto_main.c
SRC_16_5_MATH := lto_math.c
SRC_16_5_UTIL := lto_utils.c

# 16.6 — GCC patterns and idioms
SRC_16_6 := gcc_idioms.c

# 16.7 — GCC vs Clang (reuses existing sources)
SRCS_16_7 := opt_levels_demo.c gcc_idioms.c

# ============================================================================
# Per-section targets (binary base names)
# ============================================================================

BIN_16_1 := opt_levels_demo
BIN_16_2 := inlining_demo
BIN_16_3 := loop_unroll_vec
BIN_16_4 := tail_call
BIN_16_5 := lto_demo
BIN_16_6 := gcc_idioms

# List of single-file binaries using generic rules.
# NOTE: BIN_16_3 is EXCLUDED because it has a special _O3_avx2 variant.
SINGLE_BINS := $(BIN_16_1) $(BIN_16_2) $(BIN_16_4) $(BIN_16_6)

# ============================================================================
# Target list generation
# ============================================================================

# All single-file binaries (generic rules) at all levels + strip
ALL_SINGLE := $(foreach bin,$(SINGLE_BINS),\
                $(foreach opt,$(OPT_LEVELS),$(OUT)/$(bin)_$(opt)) \
                $(OUT)/$(bin)_O2_strip)

# Section 16.3 — written manually to add the _O3_avx2 variant
ALL_16_3 := $(foreach opt,$(OPT_LEVELS),$(OUT)/$(BIN_16_3)_$(opt)) \
            $(OUT)/$(BIN_16_3)_O2_strip \
            $(OUT)/$(BIN_16_3)_O3_avx2

# LTO binaries (section 16.5) — without and with -flto
ALL_LTO := $(foreach opt,$(OPT_LEVELS),$(OUT)/$(BIN_16_5)_$(opt)) \
           $(OUT)/$(BIN_16_5)_O2_strip \
           $(foreach opt,$(OPT_LEVELS),$(OUT)/$(BIN_16_5)_$(opt)_flto) \
           $(OUT)/$(BIN_16_5)_O2_flto_strip

# Section 16.7 — Clang variants (optional, see s16_7 target)
ALL_CLANG := $(foreach src,$(SRCS_16_7),\
               $(OUT)/$(basename $(src))_clang_O0 \
               $(OUT)/$(basename $(src))_clang_O2)

# Everything except Clang (Clang is optional — does not block make all)
ALL_CORE := $(ALL_SINGLE) $(ALL_16_3) $(ALL_LTO)

# Everything including Clang
ALL := $(ALL_CORE) $(ALL_CLANG)

# ============================================================================
# Main rules
# ============================================================================

.PHONY: all all_with_clang clean s16_1 s16_2 s16_3 s16_4 s16_5 s16_6 s16_7

all: $(ALL_CORE)
	@echo ""
	@echo "========================================"
	@echo " Chapter 16 GCC binaries compiled"
	@echo " in $(OUT)/"
	@echo ""
	@echo " For Clang variants (section 16.7):"
	@echo "   make s16_7"
	@echo "========================================"
	@echo ""
	@ls -lhS $(OUT)/

all_with_clang: $(ALL)
	@echo ""
	@echo "========================================"
	@echo " All binaries (GCC + Clang)"
	@echo " compiled in $(OUT)/"
	@echo "========================================"
	@echo ""
	@ls -lhS $(OUT)/

clean:
	rm -rf $(OUT)

$(OUT):
	mkdir -p $(OUT)

# ============================================================================
# Per-section targets (selective compilation)
# ============================================================================

s16_1: $(foreach opt,$(OPT_LEVELS),$(OUT)/$(BIN_16_1)_$(opt)) \
       $(OUT)/$(BIN_16_1)_O2_strip

s16_2: $(foreach opt,$(OPT_LEVELS),$(OUT)/$(BIN_16_2)_$(opt)) \
       $(OUT)/$(BIN_16_2)_O2_strip

s16_3: $(ALL_16_3)

s16_4: $(foreach opt,$(OPT_LEVELS),$(OUT)/$(BIN_16_4)_$(opt)) \
       $(OUT)/$(BIN_16_4)_O2_strip

s16_5: $(ALL_LTO)

s16_6: $(foreach opt,$(OPT_LEVELS),$(OUT)/$(BIN_16_6)_$(opt)) \
       $(OUT)/$(BIN_16_6)_O2_strip

s16_7: $(ALL_CLANG)
	@echo ""
	@echo "=== Clang variants compiled ==="
	@ls -lh $(ALL_CLANG)

# ============================================================================
# Generic rules — Single-file C binaries
# ============================================================================

# Macro to generate 6 compilation rules (O0/O1/O2/O3/Os + O2_strip)
# $(1) = binary base name, $(2) = source file
define SINGLE_C_RULES

$(OUT)/$(1)_O0: $(2) | $(OUT)
	$(CC) $(CFLAGS) -O0 -g -o $$@ $$<

$(OUT)/$(1)_O1: $(2) | $(OUT)
	$(CC) $(CFLAGS) -O1 -g -o $$@ $$<

$(OUT)/$(1)_O2: $(2) | $(OUT)
	$(CC) $(CFLAGS) -O2 -g -o $$@ $$<

$(OUT)/$(1)_O3: $(2) | $(OUT)
	$(CC) $(CFLAGS) -O3 -g -o $$@ $$<

$(OUT)/$(1)_Os: $(2) | $(OUT)
	$(CC) $(CFLAGS) -Os -g -o $$@ $$<

$(OUT)/$(1)_O2_strip: $(2) | $(OUT)
	$(CC) $(CFLAGS) -O2 -s -o $$@ $$<

endef

# Instantiate rules for generic single-file binaries
$(eval $(call SINGLE_C_RULES,$(BIN_16_1),$(SRC_16_1)))
$(eval $(call SINGLE_C_RULES,$(BIN_16_2),$(SRC_16_2)))
$(eval $(call SINGLE_C_RULES,$(BIN_16_4),$(SRC_16_4)))
$(eval $(call SINGLE_C_RULES,$(BIN_16_6),$(SRC_16_6)))

# ============================================================================
# Specific rules — Section 16.3 (loop_unroll_vec)
#
# Written manually to add the _O3_avx2 variant without
# duplicate rule conflict with the generic macro.
# ============================================================================

$(OUT)/$(BIN_16_3)_O0: $(SRC_16_3) | $(OUT)
	$(CC) $(CFLAGS) -O0 -g -o $@ $<

$(OUT)/$(BIN_16_3)_O1: $(SRC_16_3) | $(OUT)
	$(CC) $(CFLAGS) -O1 -g -o $@ $<

$(OUT)/$(BIN_16_3)_O2: $(SRC_16_3) | $(OUT)
	$(CC) $(CFLAGS) -O2 -g -o $@ $<

$(OUT)/$(BIN_16_3)_O3: $(SRC_16_3) | $(OUT)
	$(CC) $(CFLAGS) -O3 -g -o $@ $<

$(OUT)/$(BIN_16_3)_Os: $(SRC_16_3) | $(OUT)
	$(CC) $(CFLAGS) -Os -g -o $@ $<

$(OUT)/$(BIN_16_3)_O2_strip: $(SRC_16_3) | $(OUT)
	$(CC) $(CFLAGS) -O2 -s -o $@ $<

# Special variant: O3 + AVX2 (256-bit ymm registers)
# Compare with _O3 (SSE only) to see the vectorization difference.
$(OUT)/$(BIN_16_3)_O3_avx2: $(SRC_16_3) | $(OUT)
	$(CC) $(CFLAGS) -O3 -g -mavx2 -o $@ $<

# ============================================================================
# Specific rules — Section 16.5 (LTO, multi-file)
# ============================================================================

LTO_SRCS := $(SRC_16_5_MAIN) $(SRC_16_5_MATH) $(SRC_16_5_UTIL)
LTO_HDRS := lto_math.h lto_utils.h

# --- Without LTO (classic multi-file compilation) ---

$(OUT)/$(BIN_16_5)_O0: $(LTO_SRCS) $(LTO_HDRS) | $(OUT)
	$(CC) $(CFLAGS) -O0 -g -o $@ $(LTO_SRCS) -lm

$(OUT)/$(BIN_16_5)_O1: $(LTO_SRCS) $(LTO_HDRS) | $(OUT)
	$(CC) $(CFLAGS) -O1 -g -o $@ $(LTO_SRCS) -lm

$(OUT)/$(BIN_16_5)_O2: $(LTO_SRCS) $(LTO_HDRS) | $(OUT)
	$(CC) $(CFLAGS) -O2 -g -o $@ $(LTO_SRCS) -lm

$(OUT)/$(BIN_16_5)_O3: $(LTO_SRCS) $(LTO_HDRS) | $(OUT)
	$(CC) $(CFLAGS) -O3 -g -o $@ $(LTO_SRCS) -lm

$(OUT)/$(BIN_16_5)_Os: $(LTO_SRCS) $(LTO_HDRS) | $(OUT)
	$(CC) $(CFLAGS) -Os -g -o $@ $(LTO_SRCS) -lm

$(OUT)/$(BIN_16_5)_O2_strip: $(LTO_SRCS) $(LTO_HDRS) | $(OUT)
	$(CC) $(CFLAGS) -O2 -s -o $@ $(LTO_SRCS) -lm

# --- With LTO (-flto) — the core of section 16.5 ---

$(OUT)/$(BIN_16_5)_O0_flto: $(LTO_SRCS) $(LTO_HDRS) | $(OUT)
	$(CC) $(CFLAGS) -O0 -g -flto -o $@ $(LTO_SRCS) -lm

$(OUT)/$(BIN_16_5)_O1_flto: $(LTO_SRCS) $(LTO_HDRS) | $(OUT)
	$(CC) $(CFLAGS) -O1 -g -flto -o $@ $(LTO_SRCS) -lm

$(OUT)/$(BIN_16_5)_O2_flto: $(LTO_SRCS) $(LTO_HDRS) | $(OUT)
	$(CC) $(CFLAGS) -O2 -g -flto -o $@ $(LTO_SRCS) -lm

$(OUT)/$(BIN_16_5)_O3_flto: $(LTO_SRCS) $(LTO_HDRS) | $(OUT)
	$(CC) $(CFLAGS) -O3 -g -flto -o $@ $(LTO_SRCS) -lm

$(OUT)/$(BIN_16_5)_Os_flto: $(LTO_SRCS) $(LTO_HDRS) | $(OUT)
	$(CC) $(CFLAGS) -Os -g -flto -o $@ $(LTO_SRCS) -lm

$(OUT)/$(BIN_16_5)_O2_flto_strip: $(LTO_SRCS) $(LTO_HDRS) | $(OUT)
	$(CC) $(CFLAGS) -O2 -s -flto -o $@ $(LTO_SRCS) -lm

# ============================================================================
# Specific rules — Section 16.7 (GCC vs Clang)
#
# Compiles the same sources with Clang to compare optimization
# patterns. Requires clang to be installed.
# ============================================================================

# Macro for Clang rules
# $(1) = base name, $(2) = source file
define CLANG_RULES

$(OUT)/$(1)_clang_O0: $(2) | $(OUT)
	@command -v $(CLANG) >/dev/null 2>&1 || \
		{ echo "ERROR: clang is not installed. Install it for section 16.7."; exit 1; }
	$(CLANG) $(CFLAGS) -O0 -g -o $$@ $$<

$(OUT)/$(1)_clang_O2: $(2) | $(OUT)
	@command -v $(CLANG) >/dev/null 2>&1 || \
		{ echo "ERROR: clang is not installed. Install it for section 16.7."; exit 1; }
	$(CLANG) $(CFLAGS) -O2 -g -o $$@ $$<

endef

$(eval $(call CLANG_RULES,opt_levels_demo,opt_levels_demo.c))
$(eval $(call CLANG_RULES,gcc_idioms,gcc_idioms.c))

# ============================================================================
# Utility targets
# ============================================================================

.PHONY: list sizes disasm_compare lto_compare

# List all expected binaries
list:
	@echo "=== GCC Binaries (make all) ==="
	@for f in $(sort $(ALL_CORE)); do echo "  $$f"; done
	@echo ""
	@echo "=== Clang Binaries (make s16_7) ==="
	@for f in $(sort $(ALL_CLANG)); do echo "  $$f"; done

# Compare sizes of all compiled binaries
sizes: all
	@echo ""
	@echo "=== Size comparison ==="
	@echo ""
	@printf "%-45s %10s\n" "Binary" "Size"
	@printf "%-45s %10s\n" "---------------------------------------------" "----------"
	@for f in $(sort $(ALL_CORE)); do \
		if [ -f "$$f" ]; then \
			printf "%-45s %10s\n" "$$(basename $$f)" \
				"$$(stat -c%s "$$f" 2>/dev/null || stat -f%z "$$f" 2>/dev/null)"; \
		fi; \
	done

# Compare main() disassembly between O0 and O2 for a given binary
# Usage: make disasm_compare BIN=opt_levels_demo
disasm_compare:
ifndef BIN
	@echo "Usage: make disasm_compare BIN=<base_name>"
	@echo ""
	@echo "Examples:"
	@echo "  make disasm_compare BIN=opt_levels_demo"
	@echo "  make disasm_compare BIN=inlining_demo"
	@echo "  make disasm_compare BIN=gcc_idioms"
	@echo "  make disasm_compare BIN=tail_call"
else
	@echo "=== $(BIN) at -O0 ==="
	@echo ""
	@objdump -d -M intel $(OUT)/$(BIN)_O0 | sed -n '/<main>:/,/^$$/p' | head -60
	@echo ""
	@echo "=== $(BIN) at -O2 ==="
	@echo ""
	@objdump -d -M intel $(OUT)/$(BIN)_O2 | sed -n '/<main>:/,/^$$/p' | head -60
endif

# Compare symbols with and without LTO
# Shows the disappearance of cross-module inlined functions
lto_compare: s16_5
	@echo ""
	@echo "=== Functions (T = text) WITHOUT LTO (-O2) ==="
	@nm $(OUT)/$(BIN_16_5)_O2 2>/dev/null | grep ' T ' | sort
	@echo ""
	@echo "=== Functions (T = text) WITH LTO (-O2 -flto) ==="
	@nm $(OUT)/$(BIN_16_5)_O2_flto 2>/dev/null | grep ' T ' | sort
	@echo ""
	@echo "=== Size difference ==="
	@printf "  Without LTO: %s bytes\n" \
		"$$(stat -c%s $(OUT)/$(BIN_16_5)_O2 2>/dev/null || stat -f%z $(OUT)/$(BIN_16_5)_O2 2>/dev/null)"
	@printf "  With LTO: %s bytes\n" \
		"$$(stat -c%s $(OUT)/$(BIN_16_5)_O2_flto 2>/dev/null || stat -f%z $(OUT)/$(BIN_16_5)_O2_flto 2>/dev/null)"
