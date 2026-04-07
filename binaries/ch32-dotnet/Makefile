# ═══════════════════════════════════════════════════════════════
#  ch32-dotnet — Makefile
#  Reverse Engineering Training — Chapter 32
#
# Prerequisites:
#   - gcc
#   - dotnet SDK 8.0+
#
# Targets:
#   make all     — compile the native library + the .NET application
#   make native  — compile only libnative_check.so
#   make dotnet  — compile only the .NET application
#   make run     — run the application
#   make clean   — clean all compilation artifacts

# ═══════════════════════════════════════════════════════════════

.PHONY: all native dotnet run clean

NATIVE_SRC   = native/native_check.c
NATIVE_LIB   = native/libnative_check.so
DOTNET_PROJ  = LicenseChecker/LicenseChecker.csproj
DOTNET_OUT   = LicenseChecker/bin/Release/net8.0/linux-x64

CC      = gcc
CFLAGS  = -shared -fPIC -O2 -Wall -Wextra

all: native dotnet
	@echo ""
	@echo "══════════════════════════════════════════════════════════"
	@echo " ✅ Build complete."
	@echo " .NET binary : $(DOTNET_OUT)/LicenseChecker"
	@echo " Lib native   : $(NATIVE_LIB)"
	@echo "══════════════════════════════════════════════════════════"
	@echo ""
	@echo " Run: make run"
	@echo " Or     : cd $(DOTNET_OUT) && LD_LIBRARY_PATH=. ./LicenseChecker"
	@echo ""

native: $(NATIVE_LIB)

$(NATIVE_LIB): $(NATIVE_SRC)
	@mkdir -p native
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[OK] libnative_check.so compiled"

dotnet: native
	dotnet publish $(DOTNET_PROJ) \
		-c Release \
		-r linux-x64 \
		--self-contained false \
		-o $(DOTNET_OUT)
	cp $(NATIVE_LIB) $(DOTNET_OUT)/
	@echo "[OK] .NET application compiled"

run: all
	@echo "── Launching LicenseChecker ──"
	@cd $(DOTNET_OUT) && LD_LIBRARY_PATH=. ./LicenseChecker

clean:
	rm -f $(NATIVE_LIB)
	rm -rf LicenseChecker/bin/ LicenseChecker/obj/
	@echo "[OK] Cleanup done"
