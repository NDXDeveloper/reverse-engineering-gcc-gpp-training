# ═══════════════════════════════════════════════════════════════
#  ch13-network — Makefile
#  Reverse Engineering Training — Chapter 13
#
# Compiles the GCRP client and server at different optimization
# levels, with and without symbols.
#
# Targets:
#   make all       — compile all variants
#   make debug     — compile only -O0 -g variants
#   make clean     — remove all generated binaries
#
# Produced variants for each binary:
#   *_O0          -O0 -g          (no optimizations, with DWARF symbols)
#   *_O2          -O2 -g          (optimized, with symbols)
#   *_O3          -O3 -g          (aggressive optimizations, with symbols)
#   *_strip       -O0 -s          (no optimizations, stripped)
#   *_O2_strip    -O2 -s          (optimized + stripped)

# ═══════════════════════════════════════════════════════════════

CC      := gcc
CFLAGS  := -Wall -Wextra -std=c11
LDFLAGS :=

# Source files
SERVER_SRC := server.c
CLIENT_SRC := client.c
HEADER     := protocol.h

# ═══════════════════════════════════════════════
# Target list
# ═══════════════════════════════════════════════

SERVER_BINS := server_O0 server_O2 server_O3 server_strip server_O2_strip
CLIENT_BINS := client_O0 client_O2 client_O3 client_strip client_O2_strip

ALL_BINS := $(SERVER_BINS) $(CLIENT_BINS)

# ═══════════════════════════════════════════════
# Main targets
# ═══════════════════════════════════════════════

.PHONY: all debug clean

all: $(ALL_BINS)
	@echo ""
	@echo "All variants compiled:"
	@ls -lh server_O0 server_O2 server_strip client_O0 client_O2 client_strip
	@echo ""

debug: server_O0 client_O0
	@echo "Debug variants compiled: server_O0, client_O0"

clean:
	rm -f $(ALL_BINS)
	@echo "Cleaned."

# ═══════════════════════════════════════════════
# Server — variants
# ═══════════════════════════════════════════════

server_O0: $(SERVER_SRC) $(HEADER)
	$(CC) $(CFLAGS) -O0 -g -o $@ $(SERVER_SRC) $(LDFLAGS)

server_O2: $(SERVER_SRC) $(HEADER)
	$(CC) $(CFLAGS) -O2 -g -o $@ $(SERVER_SRC) $(LDFLAGS)

server_O3: $(SERVER_SRC) $(HEADER)
	$(CC) $(CFLAGS) -O3 -g -o $@ $(SERVER_SRC) $(LDFLAGS)

server_strip: $(SERVER_SRC) $(HEADER)
	$(CC) $(CFLAGS) -O0 -s -o $@ $(SERVER_SRC) $(LDFLAGS)

server_O2_strip: $(SERVER_SRC) $(HEADER)
	$(CC) $(CFLAGS) -O2 -s -o $@ $(SERVER_SRC) $(LDFLAGS)

# ═══════════════════════════════════════════════
# Client — variants
# ═══════════════════════════════════════════════

client_O0: $(CLIENT_SRC) $(HEADER)
	$(CC) $(CFLAGS) -O0 -g -o $@ $(CLIENT_SRC) $(LDFLAGS)

client_O2: $(CLIENT_SRC) $(HEADER)
	$(CC) $(CFLAGS) -O2 -g -o $@ $(CLIENT_SRC) $(LDFLAGS)

client_O3: $(CLIENT_SRC) $(HEADER)
	$(CC) $(CFLAGS) -O3 -g -o $@ $(CLIENT_SRC) $(LDFLAGS)

client_strip: $(CLIENT_SRC) $(HEADER)
	$(CC) $(CFLAGS) -O0 -s -o $@ $(CLIENT_SRC) $(LDFLAGS)

client_O2_strip: $(CLIENT_SRC) $(HEADER)
	$(CC) $(CFLAGS) -O2 -s -o $@ $(CLIENT_SRC) $(LDFLAGS)
