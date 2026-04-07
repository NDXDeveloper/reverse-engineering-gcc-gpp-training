# ============================================================
#  Makefile — Chapter 25: Reversing a custom file format
#
#  Produces the fileformat binary at multiple optimization levels,
#  with and without debug symbols, for RE training.
#
#  Targets:
#    make all       — build all variants
#    make samples   — generate sample .cfr archives (requires O0 build)
#    make clean     — remove all generated files
# ============================================================

CC       = gcc
CFLAGS   = -Wall -Wextra -std=c11
SRC      = fileformat.c
BIN_DIR  = .
SAMPLE_DIR = samples

# ---- Binary variants ----

TARGETS  = fileformat_O0      \
           fileformat_O1      \
           fileformat_O2      \
           fileformat_O3      \
           fileformat_Os      \
           fileformat_strip   \
           fileformat_O2_strip \
           fileformat_O3_strip

.PHONY: all samples clean

all: $(TARGETS)

# ---- With debug symbols ----

fileformat_O0: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -o $@ $<

fileformat_O1: $(SRC)
	$(CC) $(CFLAGS) -O1 -g -o $@ $<

fileformat_O2: $(SRC)
	$(CC) $(CFLAGS) -O2 -g -o $@ $<

fileformat_O3: $(SRC)
	$(CC) $(CFLAGS) -O3 -g -o $@ $<

fileformat_Os: $(SRC)
	$(CC) $(CFLAGS) -Os -g -o $@ $<

# ---- Stripped (no symbols) ----

fileformat_strip: $(SRC)
	$(CC) $(CFLAGS) -O0 -s -o $@ $<

fileformat_O2_strip: $(SRC)
	$(CC) $(CFLAGS) -O2 -s -o $@ $<

fileformat_O3_strip: $(SRC)
	$(CC) $(CFLAGS) -O3 -s -o $@ $<

# ---- Sample archives ----
#  Generates .cfr files for the training exercises.
#  Requires fileformat_O0 to be built first.

samples: fileformat_O0
	@mkdir -p $(SAMPLE_DIR)
	@echo "=== Generating demo archive (with XOR) ==="
	./fileformat_O0 generate $(SAMPLE_DIR)/demo.cfr
	@echo ""
	@echo "=== Creating sample input files ==="
	@echo "This is a plain text test file for packing." > $(SAMPLE_DIR)/test.txt
	@echo "chapter=25"  > $(SAMPLE_DIR)/info.meta
	@echo "topic=fileformat" >> $(SAMPLE_DIR)/info.meta
	@printf '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52' > $(SAMPLE_DIR)/fake.bin
	@printf '\xDE\xAD\xC0\xDE\xFE\xED\xFA\xCE\x01\x02\x03\x04\x05\x06\x07\x08' >> $(SAMPLE_DIR)/fake.bin
	@echo ""
	@echo "=== Packing files without XOR ==="
	./fileformat_O0 pack $(SAMPLE_DIR)/packed_noxor.cfr \
		$(SAMPLE_DIR)/test.txt \
		$(SAMPLE_DIR)/info.meta \
		$(SAMPLE_DIR)/fake.bin
	@echo ""
	@echo "=== Packing files with XOR ==="
	./fileformat_O0 pack -x $(SAMPLE_DIR)/packed_xor.cfr \
		$(SAMPLE_DIR)/test.txt \
		$(SAMPLE_DIR)/info.meta \
		$(SAMPLE_DIR)/fake.bin
	@echo ""
	@echo "=== Validating all archives ==="
	./fileformat_O0 validate $(SAMPLE_DIR)/demo.cfr
	@echo ""
	./fileformat_O0 validate $(SAMPLE_DIR)/packed_noxor.cfr
	@echo ""
	./fileformat_O0 validate $(SAMPLE_DIR)/packed_xor.cfr
	@echo ""
	@echo "=== Listing demo archive ==="
	./fileformat_O0 list $(SAMPLE_DIR)/demo.cfr
	@echo ""
	@echo "[+] All samples generated in $(SAMPLE_DIR)/"

# ---- Cleanup ----

clean:
	rm -f $(TARGETS)
	rm -rf $(SAMPLE_DIR)
