# ============================================================
# Makefile — binaries/ch06-fileformat/
# Reverse Engineering Training — Chapter 6
#
# Produces the fileformat binary at different optimization
# levels, with and without symbols, then generates
# sample data files sample.cdb and sample.pkt.
#
# Main targets:
#   make all       — compile everything + generate samples
#   make binaries  — compile binaries only
#   make samples   — generate .cdb and .pkt files
#   make clean     — remove binaries and samples
# ============================================================

CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic
SRC     = fileformat.c

# --- Binary targets ---

TARGETS = fileformat_O0 \
          fileformat_O0_strip \
          fileformat_O2 \
          fileformat_O2_strip \
          fileformat_O3

# --- Generated data files ---

SAMPLES = sample.cdb sample.pkt

# ============================================================
#  Main rules
# ============================================================

.PHONY: all binaries samples clean

all: binaries samples

binaries: $(TARGETS)

samples: sample.cdb sample.pkt

# ============================================================
#  Compilation at different optimization levels
# ============================================================

# -O0 with debug symbols (primary target for RE)
fileformat_O0: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -o $@ $<

# -O0 without symbols (stripped)
fileformat_O0_strip: fileformat_O0
	cp fileformat_O0 $@
	strip $@

# -O2 with symbols
fileformat_O2: $(SRC)
	$(CC) $(CFLAGS) -O2 -g -o $@ $<

# -O2 without symbols (stripped)
fileformat_O2_strip: fileformat_O2
	cp fileformat_O2 $@
	strip $@

# -O3 with symbols
fileformat_O3: $(SRC)
	$(CC) $(CFLAGS) -O3 -g -o $@ $<

# ============================================================
#  Data file generation
# ============================================================

# We use the -O0 version to generate the samples.
# The produced files are identical regardless of the
# binary's optimization level — it's the output format
# that matters, not performance.

sample.cdb sample.pkt: fileformat_O0
	./fileformat_O0 --output-dir .

# ============================================================
#  Cleanup
# ============================================================

clean:
	rm -f $(TARGETS) $(SAMPLES)
