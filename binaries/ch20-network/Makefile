# ═══════════════════════════════════════════════════════════════
#  ch20-network — Makefile
#  Reverse Engineering Training — Chapter 20
#
#  Produces client and server binaries at multiple optimization
#  levels, with and without debug symbols.
#
#  Usage:
#    make              — compile all variants
#    make clean        — remove binaries
# ═══════════════════════════════════════════════════════════════

CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11
SRC_SRV = server.c
SRC_CLI = client.c
BIN_DIR = .

TARGETS = server_O0        \
          server_O0_dbg     \
          server_O2         \
          server_O2_strip   \
          client_O0         \
          client_O0_dbg     \
          client_O2         \
          client_O2_strip
# Note: *_strip variants are compiled with -no-pie
# for fixed addresses (0x400000+), better suited for the RE exercise.

.PHONY: all clean

all: $(TARGETS)

# --- Server ---

server_O0: $(SRC_SRV) protocol.h
	$(CC) $(CFLAGS) -O0 -o $(BIN_DIR)/$@ $<

server_O0_dbg: $(SRC_SRV) protocol.h
	$(CC) $(CFLAGS) -O0 -g -o $(BIN_DIR)/$@ $<

server_O2: $(SRC_SRV) protocol.h
	$(CC) $(CFLAGS) -O2 -o $(BIN_DIR)/$@ $<

server_O2_strip: $(SRC_SRV) protocol.h
	$(CC) $(CFLAGS) -O2 -s -no-pie -o $(BIN_DIR)/$@ $<

# --- Client ---

client_O0: $(SRC_CLI) protocol.h
	$(CC) $(CFLAGS) -O0 -o $(BIN_DIR)/$@ $<

client_O0_dbg: $(SRC_CLI) protocol.h
	$(CC) $(CFLAGS) -O0 -g -o $(BIN_DIR)/$@ $<

client_O2: $(SRC_CLI) protocol.h
	$(CC) $(CFLAGS) -O2 -o $(BIN_DIR)/$@ $<

client_O2_strip: $(SRC_CLI) protocol.h
	$(CC) $(CFLAGS) -O2 -s -no-pie -o $(BIN_DIR)/$@ $<

clean:
	rm -f $(TARGETS)

# --- END Makefile
