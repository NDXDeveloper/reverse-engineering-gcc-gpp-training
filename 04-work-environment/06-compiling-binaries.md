🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 4.6 — Compile all training binaries in one command (`make all`)

> 🎯 **Goal of this section**: compile all the training binaries from the provided sources, verify that compilation went smoothly, and understand what each target produces.

---

## Prerequisites

Before launching the compilation, make sure that:

- The **wave 1** tools (section 4.2) are installed — in particular `gcc`, `g++`, and `make`.  
- The training repository is cloned inside your VM (section 4.5).  
- Your Python virtual environment is activated (`source ~/re-venv/bin/activate`) — some Makefiles invoke Python tools for post-processing steps.

Quick check:

```bash
[vm] gcc --version && g++ --version && make --version
```

If any of these commands fails, go back to section 4.2.

---

## Full compilation: `make all`

Go to the root of the `binaries/` directory and launch the compilation:

```bash
[vm] cd ~/formation-re/binaries
[vm] make all
```

The root Makefile iterates over each sub-folder and runs `make all` inside it. You will see compilation lines scroll by, grouped by chapter:

```
=== Compiling ch21-keygenme ===
gcc -Wall -Wextra -O0 -g -o keygenme_O0 keygenme.c  
gcc -Wall -Wextra -O2 -g -o keygenme_O2 keygenme.c  
gcc -Wall -Wextra -O3 -g -o keygenme_O3 keygenme.c  
cp keygenme_O0 keygenme_O0_strip  
strip keygenme_O0_strip  
cp keygenme_O2 keygenme_O2_strip  
strip keygenme_O2_strip  
=== Compiling ch22-oop ===
g++ -Wall -Wextra -O0 -g -o oop_O0 oop.cpp  
g++ -Wall -Wextra -O2 -g -o oop_O2 oop.cpp  
...
```

Compiling everything generally takes **less than a minute** on a properly sized VM (4 vCPU, 8 GB RAM). On a macOS Apple Silicon via UTM in x86-64 emulation, count 2 to 4 minutes.

---

## What `make all` produces

After a successful compilation, each `binaries/` sub-folder contains its original sources **plus** the generated binaries. Here is the full inventory:

### C binaries (GCC)

| Sub-folder | Binaries produced | Notes |  
|---|---|---|  
| `ch21-keygenme/` | `keygenme_O0`, `keygenme_O2`, `keygenme_O3`, `keygenme_O0_strip`, `keygenme_O2_strip` | Crackme — 5 variants |  
| `ch23-network/` | `client_O0`, `client_O2`, `server_O0`, `server_O2` + stripped variants | Separate client and server |  
| `ch24-crypto/` | `crypto_O0`, `crypto_O2` + stripped variants | Linked with `-lcrypto` (OpenSSL) |  
| `ch25-fileformat/` | `fileformat_O0`, `fileformat_O2` + stripped variants | Custom-format parser |  
| `ch27-ransomware/` | `ransomware_O0`, `ransomware_O2` + stripped variants | ⚠️ Sandbox only |  
| `ch28-dropper/` | `dropper_O0`, `dropper_O2` + stripped variants | ⚠️ Sandbox only |  
| `ch29-packed/` | `packed_O0`, `packed_O0_upx` | Original binary + UPX-packed version |

### C++ binaries (G++)

| Sub-folder | Binaries produced | Notes |  
|---|---|---|  
| `ch22-oop/` | `oop_O0`, `oop_O2`, `oop_O3` + stripped variants | Object-oriented application with vtables |

### Rust and Go binaries (optional)

| Sub-folder | Binaries produced | Notes |  
|---|---|---|  
| `ch33-rust/` | `crackme_rust`, `crackme_rust_strip` | Requires `rustc`/`cargo` |  
| `ch34-go/` | `crackme_go`, `crackme_go_strip` | Requires `go` |

> 💡 In total, `make all` produces roughly **35 to 40 binaries** depending on available toolchains. This is the entire practical material of the training.

---

## Special compilation cases

### `ch24-crypto` — OpenSSL dependency

The Chapter 24 binary uses OpenSSL's cryptographic functions. The Makefile links it with `-lcrypto`:

```makefile
$(NAME)_O0: $(SRC)
	$(CC) $(CFLAGS) -O0 -g -o $@ $< -lcrypto
```

If compilation fails with an error like `cannot find -lcrypto`, install the OpenSSL development headers:

```bash
[vm] sudo apt install -y libssl-dev
```

This package should already be installed if you followed section 4.2.

### `ch29-packed` — UPX packing

The Chapter 29 Makefile first compiles the binary normally, then compresses it with UPX to produce the packed variant:

```makefile
$(NAME)_O0_upx: $(NAME)_O0
	cp $< $@
	upx --best $@
```

If UPX is not installed, this target will fail. Other targets of the same sub-folder (non-packed) will still be produced normally.

```bash
[vm] sudo apt install -y upx-ucl    # if not already installed
```

### `ch33-rust` — Rust compilation

The Chapter 33 Makefile invokes `cargo build`:

```makefile
all:
	cd crackme_rust && cargo build --release
	cp crackme_rust/target/release/crackme_rust .
	cp crackme_rust .
	strip -o crackme_rust_strip crackme_rust
```

If Rust is not installed, you will see:

```
make[1]: cargo: No such file or directory
```

This is expected if you chose not to install Rust (optional tool in section 4.2). Chapter 33 is a bonus (Part VIII) and is not required for the main path.

### `ch34-go` — Go compilation

Same logic for Go:

```makefile
all:
	cd crackme_go && go build -o ../crackme_go .
	strip -o crackme_go_strip crackme_go
```

Without the Go toolchain installed, this target fails without affecting the rest.

---

## Verifying the compilation

### Quick check by counting

A quick way to verify everything went well is to count the produced ELF binaries:

```bash
[vm] cd ~/formation-re/binaries
[vm] find . -type f -executable | xargs file | grep "ELF" | wc -l
```

The expected result is roughly **35–40** (depending on optional toolchains). If the number is significantly lower, re-read the output of `make all` to find the errors.

### Detailed check per sub-folder

To inspect the binaries of a specific sub-folder:

```bash
[vm] ls -lh ch21-keygenme/
```

Expected output:

```
-rw-r--r-- 1 re re  2.1K  keygenme.c
-rw-r--r-- 1 re re   487  Makefile
-rwxr-xr-x 1 re re  18K   keygenme_O0
-rwxr-xr-x 1 re re  17K   keygenme_O2
-rwxr-xr-x 1 re re  17K   keygenme_O3
-rwxr-xr-x 1 re re  15K   keygenme_O0_strip
-rwxr-xr-x 1 re re  15K   keygenme_O2_strip
```

A few observations that confirm the compilation is correct:

- Non-stripped binaries (`_O0`, `_O2`, `_O3`) are **bigger** than stripped variants — DWARF information and the symbol table take space.  
- The `-O0` binary is generally a bit **bigger** than `-O2` — functions are not inlined, code is not factored. It is not always the case (optimizations can also unroll loops and grow the code), but the trend holds.  
- All files carry the executable bit (`-rwxr-xr-x`).

### Verification with `file`

Confirm that each binary is indeed an x86-64 ELF:

```bash
[vm] file ch21-keygenme/keygenme_O0
```

Expected output:

```
keygenme_O0: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=..., for GNU/Linux 3.2.0, with debug_info, not stripped  
```

Points to check:

- `ELF 64-bit` — it is indeed a 64-bit binary.  
- `x86-64` — correct architecture.  
- `with debug_info, not stripped` — DWARF symbols are present (non-stripped variant).

For a stripped variant:

```bash
[vm] file ch21-keygenme/keygenme_O0_strip
```

```
keygenme_O0_strip: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped  
```

Note the difference: `stripped` instead of `with debug_info, not stripped`. That is exactly the expected behavior.

### Verification with `readelf`

To go further and verify the presence of debug sections:

```bash
[vm] readelf -S ch21-keygenme/keygenme_O0 | grep debug
```

Expected output (excerpts):

```
  [29] .debug_aranges    PROGBITS  ...
  [30] .debug_info       PROGBITS  ...
  [31] .debug_abbrev     PROGBITS  ...
  [32] .debug_line       PROGBITS  ...
  [33] .debug_str        PROGBITS  ...
```

On the stripped variant, this command returns nothing — confirmation that `strip` did remove the debug information.

> 📌 These commands (`file`, `readelf`, `strings`, `objdump`) will be detailed in Chapter 5. For now, they only serve to validate the compilation. If the outputs match what is described above, everything is in order.

---

## Recompiling a specific sub-folder

You do not need to recompile the whole repository every time. To recompile only the binaries of a given chapter:

```bash
[vm] cd ~/formation-re/binaries/ch21-keygenme
[vm] make clean    # removes the existing binaries
[vm] make all      # recompiles all variants
```

It is useful when you modify a source to experiment (for example, adding a `printf` to understand a behavior) and you want to recompile quickly.

---

## Cleaning up binaries

To remove all compiled binaries and go back to a "sources only" state:

```bash
[vm] cd ~/formation-re/binaries
[vm] make clean
```

After this command, each sub-folder only contains its source files and its Makefile. A new `make all` will reproduce exactly the same binaries.

> 💡 **When to clean?** After a GCC update (`apt upgrade` installing a new version), it is recommended to do `make clean && make all` so that all binaries are recompiled with the same compiler version. It avoids inconsistencies if you compare binaries with each other (Chapter 10 — diffing).

---

## Compiling with a different compiler or flags

The Makefiles use variables (`CC`, `CXX`, `CFLAGS`) that you can override from the command line. For example, to compile with Clang instead of GCC:

```bash
[vm] cd ~/formation-re/binaries/ch21-keygenme
[vm] make clean
[vm] make all CC=clang
```

Or to add a specific flag, such as stack-protection:

```bash
[vm] make all CFLAGS="-Wall -Wextra -fstack-protector-strong"
```

This flexibility is used in Chapter 16 (GCC vs Clang comparison, section 16.7) and Chapter 19 (enabling/disabling compiler protections, section 19.5). Being able to recompile the same sources with different options and observe the impact on the binary is a fundamental RE exercise.

> ⚠️ **Caution**: overriding `CFLAGS` replaces the value defined in the Makefile (which typically includes `-Wall -Wextra`). If you add flags, think to include the base ones. Alternatively, use the `EXTRA_CFLAGS` variable if the Makefile supports it:  
> ```bash  
> [vm] make all EXTRA_CFLAGS="-fstack-protector-strong"  
> ```

---

## Post-compilation snapshot

Once all binaries are compiled and verified, it is the right time to take a new snapshot of your VM:

```bash
# VirtualBox: Machine → Take a Snapshot → "tools-ready"
# QEMU/KVM:
[host] virsh snapshot-create-as RE-Lab tools-ready --description "Tools installed, binaries compiled"
# UTM: camera icon → "tools-ready"
```

This `tools-ready` snapshot is the reference state for the whole training. All tools are installed, all binaries are compiled, the environment is ready. If a later operation corrupts your VM, you can come back here in seconds.

---

## Summary

- `make all` from `binaries/` compiles all variants of all training binaries in a single command. Compilation takes less than a minute.  
- Each source produces **several binaries**: different optimization levels (`-O0`, `-O2`, `-O3`), with or without symbols, with or without stripping, and sometimes with packing (UPX).  
- The Rust and Go targets are **optional** — their failure does not affect the C/C++ binaries.  
- Verify the compilation with `find` + `file` + `readelf` to confirm the type, architecture, and presence of debug symbols.  
- The Makefiles accept **variable overrides** (`CC=clang`, `CFLAGS=...`) to experiment with other compilers or options.  
- Take a **`tools-ready` snapshot** after compilation — it is your reference state for the entire training.

---


⏭️ [Verify installation: provided `check_env.sh` script](/04-work-environment/07-verify-installation.md)
