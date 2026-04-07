# ==========================================================================
# Makefile — Chapter 22: Reversing an object-oriented C++ application
#
# Reverse Engineering Training — MIT License
#
# Produced targets:
#   oop_O0           → -O0 -g          (debug, direct correspondence)
#   oop_O2           → -O2 -g          (optimized with symbols)
#   oop_O2_strip     → -O2 -s          (optimized without symbols — realistic)
#   plugins/plugin_alpha.so  → -O2 -g  (ROT13 plugin)
#   plugins/plugin_beta.so   → -O2 -g  (XOR plugin)
#
# Usage:
#   make all         → compile everything
#   make run         → compile and run oop_O0 with plugins
#   make run-strip   → run the stripped version
#   make clean       → remove binaries and plugins/ directory
# ==========================================================================

CXX      := g++
CXXFLAGS := -Wall -Wextra -std=c++17

# Common flags for plugins (.so)
PLUGIN_FLAGS := -shared -fPIC -O2 -g

# Default test text
TEST_TEXT := "Hello World 42 from Reverse Engineering"

# ---- Main targets ----

.PHONY: all clean run run-strip dirs

all: dirs oop_O0 oop_O2 oop_O2_strip plugins/plugin_alpha.so plugins/plugin_beta.so

dirs:
	@mkdir -p plugins

# ---- Main application ----

oop_O0: oop.cpp processor.h
	$(CXX) $(CXXFLAGS) -O0 -g -rdynamic -o $@ $< -ldl

oop_O2: oop.cpp processor.h
	$(CXX) $(CXXFLAGS) -O2 -g -rdynamic -o $@ $< -ldl

oop_O2_strip: oop.cpp processor.h
	$(CXX) $(CXXFLAGS) -O2 -s -rdynamic -o $@ $< -ldl

# Note: -rdynamic is required so that the executable's symbols are
# visible to plugins loaded via dlopen (RTTI resolution).

# ---- Plugins (.so) ----

plugins/plugin_alpha.so: plugin_alpha.cpp processor.h | dirs
	$(CXX) $(CXXFLAGS) $(PLUGIN_FLAGS) -o $@ $<

plugins/plugin_beta.so: plugin_beta.cpp processor.h | dirs
	$(CXX) $(CXXFLAGS) $(PLUGIN_FLAGS) -o $@ $<

# ---- Test execution ----

run: all
	@echo "=========================================="
	@echo " Running oop_O0 with plugins"
	@echo "=========================================="
	./oop_O0 -p ./plugins $(TEST_TEXT)

run-strip: all
	@echo "=========================================="
	@echo " Running oop_O2_strip with plugins"
	@echo "=========================================="
	./oop_O2_strip -p ./plugins $(TEST_TEXT)

# ---- RE utility targets ----

.PHONY: symbols vtables sections

# Display demangled symbols of the executable
symbols: oop_O0
	@echo "=== Symbols of oop_O0 (demangled) ==="
	nm -C oop_O0 | grep -E '(Processor|Pipeline|Upper|Reverse)' | sort

# Display vtables in .rodata
vtables: oop_O0
	@echo "=== Vtables (filtered objdump -t) ==="
	objdump -t -C oop_O0 | grep -i 'vtable'

# Display ELF sections
sections: oop_O0
	@echo "=== ELF Sections ==="
	readelf -S oop_O0

# ---- Cleanup ----

clean:
	rm -f oop_O0 oop_O2 oop_O2_strip
	rm -rf plugins/
