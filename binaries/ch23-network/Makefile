# ═══════════════════════════════════════════════════════════════
#  ch23-network — Makefile
#  Reverse Engineering Training — Chapter 23
#
#  Produces client and server binaries at multiple optimization
#  levels, with and without debug symbols.
#
#  Usage:
#    make              — compile all variants
#    make clean        — remove binaries
#    make run-server   — start the server (-O0 -g variant)
#    make run-client   — start the client (-O0 -g variant)
#    make test         — start server + client automatically
# ═══════════════════════════════════════════════════════════════

CC       = gcc
CFLAGS   = -Wall -Wextra -Wpedantic -std=c11
LDFLAGS  =

# Output directory
OUTDIR   = build

# ───────────────────────────────────────────
#  Target list
# ───────────────────────────────────────────

SERVER_TARGETS = \
	$(OUTDIR)/server_O0        \
	$(OUTDIR)/server_O2        \
	$(OUTDIR)/server_O3        \
	$(OUTDIR)/server_Os        \
	$(OUTDIR)/server_strip     \
	$(OUTDIR)/server_O2_strip

CLIENT_TARGETS = \
	$(OUTDIR)/client_O0        \
	$(OUTDIR)/client_O2        \
	$(OUTDIR)/client_O3        \
	$(OUTDIR)/client_Os        \
	$(OUTDIR)/client_strip     \
	$(OUTDIR)/client_O2_strip

ALL_TARGETS = $(SERVER_TARGETS) $(CLIENT_TARGETS)

# ───────────────────────────────────────────
#  Main targets
# ───────────────────────────────────────────

.PHONY: all clean run-server run-client test help

all: $(OUTDIR) $(ALL_TARGETS)
	@echo ""
	@echo "══════════════════════════════════════════════"
	@echo "  Build complete. Binaries in $(OUTDIR)/"
	@echo "══════════════════════════════════════════════"
	@echo ""
	@ls -lh $(OUTDIR)/
	@echo ""

$(OUTDIR):
	mkdir -p $(OUTDIR)

clean:
	rm -rf $(OUTDIR)

help:
	@echo "Available targets:"
	@echo "  all          — compile all variants"
	@echo "  clean        — remove the build/ directory"
	@echo "  run-server   — start server_O0 on port 4444"
	@echo "  run-client   — start client_O0 towards 127.0.0.1:4444"
	@echo "  test         — start server + client automatically"
	@echo ""
	@echo "Produced variants for each binary:"
	@echo "  _O0         — -O0 -g  (debug, non-optimized)"
	@echo "  _O2         — -O2 -g  (optimized, with symbols)"
	@echo "  _O3         — -O3 -g  (aggressive optim, with symbols)"
	@echo "  _Os         — -Os -g  (size optimized, with symbols)"
	@echo "  _strip      — -O0, stripped (no symbols)"
	@echo "  _O2_strip   — -O2, stripped (optimized + no symbols)"

# ───────────────────────────────────────────
#  Server — variants
# ───────────────────────────────────────────

$(OUTDIR)/server_O0: server.c | $(OUTDIR)
	$(CC) $(CFLAGS) -O0 -g -o $@ $< $(LDFLAGS)

$(OUTDIR)/server_O2: server.c | $(OUTDIR)
	$(CC) $(CFLAGS) -O2 -g -o $@ $< $(LDFLAGS)

$(OUTDIR)/server_O3: server.c | $(OUTDIR)
	$(CC) $(CFLAGS) -O3 -g -o $@ $< $(LDFLAGS)

$(OUTDIR)/server_Os: server.c | $(OUTDIR)
	$(CC) $(CFLAGS) -Os -g -o $@ $< $(LDFLAGS)

$(OUTDIR)/server_strip: server.c | $(OUTDIR)
	$(CC) $(CFLAGS) -O0 -o $@ $< $(LDFLAGS)
	strip $@

$(OUTDIR)/server_O2_strip: server.c | $(OUTDIR)
	$(CC) $(CFLAGS) -O2 -o $@ $< $(LDFLAGS)
	strip $@

# ───────────────────────────────────────────
#  Client — variants
# ───────────────────────────────────────────

$(OUTDIR)/client_O0: client.c | $(OUTDIR)
	$(CC) $(CFLAGS) -O0 -g -o $@ $< $(LDFLAGS)

$(OUTDIR)/client_O2: client.c | $(OUTDIR)
	$(CC) $(CFLAGS) -O2 -g -o $@ $< $(LDFLAGS)

$(OUTDIR)/client_O3: client.c | $(OUTDIR)
	$(CC) $(CFLAGS) -O3 -g -o $@ $< $(LDFLAGS)

$(OUTDIR)/client_Os: client.c | $(OUTDIR)
	$(CC) $(CFLAGS) -Os -g -o $@ $< $(LDFLAGS)

$(OUTDIR)/client_strip: client.c | $(OUTDIR)
	$(CC) $(CFLAGS) -O0 -o $@ $< $(LDFLAGS)
	strip $@

$(OUTDIR)/client_O2_strip: client.c | $(OUTDIR)
	$(CC) $(CFLAGS) -O2 -o $@ $< $(LDFLAGS)
	strip $@

# ───────────────────────────────────────────
#  Utility targets
# ───────────────────────────────────────────

run-server: $(OUTDIR)/server_O0
	@echo "[*] Starting server on port 4444..."
	./$(OUTDIR)/server_O0

run-client: $(OUTDIR)/client_O0
	@echo "[*] Connecting client to 127.0.0.1:4444..."
	./$(OUTDIR)/client_O0 127.0.0.1

# Start server in background, run client, then kill server
test: $(OUTDIR)/server_O0 $(OUTDIR)/client_O0
	@echo "══════════════════════════════════════════════"
	@echo "  Automated test: server + client"
	@echo "══════════════════════════════════════════════"
	@echo ""
	@echo "[*] Starting server in background..."
	@./$(OUTDIR)/server_O0 &                                      \
	 SERVER_PID=$$!;                                               \
	 sleep 0.5;                                                    \
	 echo "[*] Running client...";                                 \
	 echo "";                                                      \
	 ./$(OUTDIR)/client_O0 127.0.0.1;                              \
	 CLIENT_RC=$$?;                                                \
	 echo "";                                                      \
	 echo "[*] Stopping server (PID $$SERVER_PID)...";             \
	 kill $$SERVER_PID 2>/dev/null;                                \
	 wait $$SERVER_PID 2>/dev/null;                                \
	 echo "";                                                      \
	 if [ $$CLIENT_RC -eq 0 ]; then                                \
	     echo "Test PASSED — session completed successfully";      \
	 else                                                          \
	     echo "Test FAILED — client exited with error";            \
	 fi
