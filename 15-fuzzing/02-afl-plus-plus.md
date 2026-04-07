🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 15.2 — AFL++: installation, instrumentation, and first run on a GCC application

> 🔗 **Prerequisites**: Chapter 2 (GNU compilation chain, GCC flags), Chapter 4 (work environment), Section 15.1 (positioning fuzzing in RE)

---

## AFL++ in brief

AFL++ (*American Fuzzy Lop plus plus*) is the community successor to AFL, the grey-box fuzzer that revolutionized vulnerability research starting in 2013. The original project, created by Michał Zalewski (lcamtuf) at Google, has been unmaintained since 2017. AFL++ took over by integrating years of academic research and practical improvements: new mutation algorithms, extended instrumentation mode support, native sanitizer integration, and significantly superior performance.

For a reverse engineer, AFL++ offers several decisive advantages:

- **Compile-time instrumentation with GCC** — since our training binaries come with their sources, we can recompile them with `afl-gcc` or `afl-clang-fast` to get nearly free instrumentation in terms of performance.  
- **QEMU mode** (`-Q`) — for binaries whose sources are unavailable, AFL++ can instrument at runtime via QEMU emulation. Slower, but indispensable in real-world RE.  
- **Frida mode** — an alternative to QEMU mode, using Frida (cf. Chapter 13) as the runtime instrumentation engine. Often faster than QEMU on Linux x86-64 targets.  
- **Real-time text interface** — AFL++'s dashboard continuously displays the coverage reached, crash count, execution speed, and exploration status. It provides immediate visual feedback on "what the fuzzer has understood" about the binary.

---

## Installing AFL++

### From packages (Debian/Ubuntu)

The quickest method on Debian 12+ or Ubuntu 22.04+:

```bash
$ sudo apt update
$ sudo apt install -y afl++
```

This installation provides the main binaries: `afl-fuzz`, `afl-gcc`, `afl-clang-fast`, `afl-tmin`, `afl-cmin`, `afl-showmap`, as well as QEMU mode if the `afl++-qemu` package is available.

Verify the installation:

```bash
$ afl-fuzz --version
afl-fuzz++4.x (something)
```

> ⚠️ **Warning** — Packages from official repositories are sometimes one or two versions behind. For production or CTF use, prefer compiling from source (below). For following this chapter, the repository version is sufficient.

### From source (recommended for the latest version)

```bash
$ sudo apt install -y build-essential python3-dev automake cmake git flex bison \
    libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev \
    lld llvm llvm-dev clang
$ git clone https://github.com/AFLplusplus/AFLplusplus.git
$ cd AFLplusplus
$ make distrib    # compiles everything, including QEMU and Frida support
$ sudo make install
```

The `make distrib` target takes longer than `make all` because it also compiles the QEMU and Frida modes. If you don't need QEMU mode immediately, `make all` is sufficient and faster.

Verify that the key components are present:

```bash
$ which afl-fuzz afl-gcc afl-clang-fast afl-showmap afl-tmin afl-cmin
```

### On Kali Linux

Kali includes AFL++ in its repositories. A simple `sudo apt install afl++` is generally sufficient. Verify the version with `afl-fuzz --version`.

---

## Instrumentation: the heart of grey-box fuzzing

Before launching AFL++, you need to understand **what instrumentation does** and **why it's indispensable**.

### The problem without instrumentation

If you run a standard binary with random inputs, all you can observe from the outside is: "did the program crash, yes or no?" You have no idea **which paths** each input traversed inside the code. Two very different inputs can produce the same visible result (no crash) while having traversed completely distinct branches. Without this information, the fuzzer cannot learn — it mutates blindly, which is the black-box regime.

### What instrumentation adds

Instrumentation consists of injecting, at compile time, small code snippets at the program's branch points. At each transition from one basic block to another, the instrumented code updates a **coverage bitmap** shared with the fuzzer. This bitmap is an array in shared memory where each cell corresponds to a (source block → destination block) pair.

Concretely, at each branch, the injected code does something like:

```
shared_mem[hash(previous_block XOR current_block)] += 1
```

After each execution, AFL++ compares the resulting bitmap with those from previous executions. If new cells have been activated (or if their counters have changed significantly), it means this input triggered a **new behavior** — and it deserves to be kept in the corpus.

> 💡 **For RE** — This bitmap is exactly the "binary map" mentioned in Section 15.1. Each activated cell corresponds to a transition between two basic blocks that the fuzzer managed to trigger. At the end of a fuzzing campaign, this map tells you which portions of the code were reached — and more importantly, which ones weren't.

### AFL++ instrumentation modes

AFL++ offers several instrumentation engines, adapted to different scenarios:

| Mode | Command | When to use | Performance |  
|------|---------|-------------|-------------|  
| `afl-gcc` | Compile with `afl-gcc` / `afl-g++` | Sources available, existing GCC chain | Good |  
| `afl-clang-fast` | Compile with `afl-clang-fast` / `afl-clang-fast++` | Sources available, better LLVM instrumentation | Excellent |  
| QEMU | `-Q` flag to `afl-fuzz` | No sources, precompiled binary | Moderate (~2-5× slower) |  
| Frida | `-O` flag to `afl-fuzz` | No sources, alternative to QEMU | Good (~1.5-3× slower) |  
| Unicorn | Via `afl-unicorn` | Isolated code fragments (firmware) | Variable |

For this chapter, we'll primarily use **`afl-gcc`** since our training binaries come with their C sources. It's the simplest mode to set up and the one that fits our training context (GNU chain).

If you want optimal performance and have Clang/LLVM installed, `afl-clang-fast` is the superior choice: its LLVM IR-level instrumentation is finer and faster than `afl-gcc`'s assembly instrumentation. But both work perfectly for our purposes.

---

## Compiling a binary with AFL++ instrumentation

Let's take a concrete example. Suppose we have a small C program that reads a file and parses it — exactly the type of ideal fuzzing target:

```c
// simple_parser.c — Minimalist parser for demonstration
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_input(const char *data, size_t len) {
    if (len < 4) return -1;

    // Check a magic number
    if (data[0] != 'R' || data[1] != 'E') return -1;

    // Check a version field
    unsigned char version = data[2];
    if (version == 1) {
        // v1 path: basic processing
        if (len < 8) return -1;
        int value = *(int *)(data + 4);
        if (value > 1000) {
            // Rarely reached path
            printf("Extended mode activated\n");
        }
    } else if (version == 2) {
        // v2 path: advanced processing
        if (len < 16) return -1;
        // ... more complex logic ...
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(size);
    if (!buf) { fclose(f); return 1; }

    fread(buf, 1, size, f);
    fclose(f);

    int result = parse_input(buf, size);
    free(buf);

    return result;
}
```

### Standard compilation (without instrumentation)

For reference, here's how you would normally compile:

```bash
$ gcc -O0 -g -o simple_parser simple_parser.c
```

This binary is perfectly functional, but AFL++ won't be able to observe its internal coverage (except in QEMU/Frida mode).

### Compilation with `afl-gcc`

Simply replace `gcc` with `afl-gcc`:

```bash
$ afl-gcc -O0 -g -o simple_parser_afl simple_parser.c
```

During compilation, you'll see an AFL++ message confirming instrumentation:

```
[+] Instrumented X locations (non-hardened mode, ratio 100%).
```

The number `X` corresponds to the number of instrumented branch points. It's a good indicator of the program's "size" from the fuzzer's perspective.

### Compilation with `afl-clang-fast` (LLVM alternative)

```bash
$ afl-clang-fast -O0 -g -o simple_parser_afl simple_parser.c
```

The confirmation message will be similar, but the underlying instrumentation is different (LLVM IR pass vs assembly insertion). In practice, fuzzing results are comparable; `afl-clang-fast` is simply a bit faster.

### Adding sanitizers to compilation

One of the most powerful combinations for RE is coupling AFL++ instrumentation with sanitizers (cf. Chapter 14). AddressSanitizer (ASan) detects invalid memory accesses, buffer overflows, use-after-free — bugs that don't always cause a visible crash without a sanitizer.

```bash
$ AFL_USE_ASAN=1 afl-gcc -O0 -g -o simple_parser_asan simple_parser.c
```

Or equivalently:

```bash
$ afl-gcc -O0 -g -fsanitize=address -o simple_parser_asan simple_parser.c
```

With UndefinedBehaviorSanitizer as a complement:

```bash
$ AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-gcc -O0 -g -o simple_parser_asan_ubsan simple_parser.c
```

> ⚠️ **Warning** — ASan significantly increases memory consumption (approximately 2 to 3×) and slightly reduces execution speed. For long fuzzing sessions on memory-hungry programs, it may be preferable to fuzz first *without* ASan for speed, then replay interesting inputs on an ASan build to detect subtle bugs. This strategy is called *ASan triage*.

### Adapting an existing Makefile

The training binaries use dedicated `Makefile`s that include a preconfigured `fuzz` target for AFL++:

```bash
$ cd binaries/ch15-fileformat/
$ make clean
$ make fuzz
```

If a third-party project's `Makefile` doesn't have a fuzzing target, the general technique is to override the `CC` variable (or `CXX` for C++):

```bash
$ make clean
$ make CC=afl-gcc CFLAGS="-O0 -g"
```

This works as long as the `Makefile` uses `$(CC)` and `$(CFLAGS)` in its compilation rules — which is the standard convention. For a C++ project:

```bash
$ make CXX=afl-g++ CXXFLAGS="-O0 -g"
```

---

## Preparing a fuzzing campaign

Before launching `afl-fuzz`, three elements must be in place: an **instrumented binary**, an **initial corpus**, and a **directory structure**.

### The initial corpus (seed corpus)

The initial corpus is a set of valid (or nearly valid) input files that the fuzzer will use as a starting point for its mutations. The quality of the corpus directly influences how fast the fuzzer will reach the code's deeper layers.

For our `simple_parser`, let's create an `in/` directory with a few seeds:

```bash
$ mkdir in
$ echo -ne 'RE\x01\x00AAAA' > in/seed_v1.bin    # Magic "RE", version 1, 8 bytes
$ echo -ne 'RE\x02\x00AAAAAAAAAAAAAAAA' > in/seed_v2.bin  # Magic "RE", version 2, 18 bytes
$ echo -ne 'RE\x00\x00' > in/seed_v0.bin          # Magic "RE", unknown version
```

> 💡 **Where do these seeds come from in an RE context?** — In practice, the initial corpus is built from information gathered during triage (Chapter 5) and static analysis:  
> - `strings` on the binary can reveal format strings, magic bytes, error messages that indicate the expected format.  
> - Analysis of parsing functions in Ghidra shows constants compared at the beginning of processing.  
> - If the binary is a client/server, network captures (Wireshark) provide examples of real inputs.  
> - At worst, a single-byte file `\x00` is enough — the fuzzer will eventually find its way, but it will be much slower.

### The directory structure

AFL++ expects at minimum an input directory (`-i`) and an output directory (`-o`):

```
fuzzing_session/
├── in/               ← Initial corpus (seeds)
│   ├── seed_v1.bin
│   ├── seed_v2.bin
│   └── seed_v0.bin
├── out/              ← Created automatically by AFL++
│   ├── queue/        ← Inputs that discovered new paths
│   ├── crashes/      ← Inputs that caused crashes
│   ├── hangs/        ← Inputs that caused timeouts
│   └── ...
└── simple_parser_afl ← Instrumented binary
```

The `out/` directory is created and managed by AFL++. Don't create it manually before the first launch — or if you do, make sure it's empty.

---

## Preliminary system configuration

AFL++ needs a few system adjustments to function optimally. Without these adjustments, it will still work but will display warnings and be less performant.

### Disable CPU frequency scaling

AFL++ recommends setting CPUs to performance mode:

```bash
$ echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

> 💡 **In a VM** — This setting generally has no effect in a virtual machine. You can ignore AFL++'s warning about this if you're working in the Chapter 4 VM.

### Configure kernel crash behavior

By default, Linux may send core dumps to an external handler (like `apport` on Ubuntu), which slows down fuzzing. AFL++ wants to handle crashes itself:

```bash
$ echo core | sudo tee /proc/sys/kernel/core_pattern
```

If you don't make this adjustment, AFL++ will refuse to start and display an explicit error message asking you to do so.

---

## Launching the first run

Everything is in place. Let's launch AFL++:

```bash
$ afl-fuzz -i in -o out -- ./simple_parser_afl @@
```

Let's break down this command:

| Element | Role |  
|---------|------|  
| `afl-fuzz` | The main fuzzer |  
| `-i in` | Initial corpus directory |  
| `-o out` | Output directory (results) |  
| `--` | Separator between AFL++ options and the target command |  
| `./simple_parser_afl` | The instrumented binary to fuzz |  
| `@@` | Placeholder replaced by the path of the input file generated by AFL++ |

The `@@` is crucial: it tells AFL++ that the target program expects a **filename** as an argument. AFL++ writes each mutated input to a temporary file and replaces `@@` with that file's path before each execution.

> 💡 **If the program reads from stdin** — Some programs read their input from standard input rather than from a file. In that case, omit `@@`:  
> ```bash  
> $ afl-fuzz -i in -o out -- ./my_program  
> ```  
> AFL++ will send the data directly to the program's stdin.

### The AFL++ interface: reading the dashboard

As soon as it launches, AFL++ displays a text-mode dashboard that updates in real time:

```
                        american fuzzy lop ++4.09a
┌─ process timing ────────────────────────────────────┬─ overall results ───┐
│        run time : 0 days, 0 hrs, 2 min, 37 sec      │  cycles done : 14   │
│   last new find : 0 days, 0 hrs, 0 min, 3 sec       │ corpus count : 23   │
│ last saved crash : 0 days, 0 hrs, 1 min, 12 sec     │saved crashes : 3    │
│  last saved hang : none seen yet                    │  saved hangs : 0    │
├─ cycle progress ───────────────────┬─ map coverage ─┴─────────────────────┤
│  now processing : 17.2 (73.9%)     │    map density : 1.42% / 2.87%       │
│  runs timed out : 0 (0.00%)        │ count coverage : 4.31 bits/tuple     │
├─ stage progress ───────────────────┼─ findings in depth ──────────────────┤
│  now trying : havoc                │ favored items : 8 (34.8%)            │
│ stage execs : 1247/2048 (60.9%)    │  new edges on : 12 (52.2%)           │
│ total execs : 87.3k                │ total crashes : 7 (3 saved)          │
│  exec speed : 2341/sec             │  total tmouts : 0 (0 saved)          │
├─ fuzzing strategy yields ──────────┴──────────────────────────────────────┤
│ ...                                                                       │
└───────────────────────────────────────────────────────────────────────────┘
```

The essential indicators for the reverse engineer:

**`corpus count`** — The number of inputs in the queue. Each input represents a distinct path through the binary. If this number increases steadily, the fuzzer continues discovering new parts of the code. If it stagnates, the fuzzer has probably explored everything it can reach with its current strategy — it may be time to enrich the dictionary or refine the corpus (Section 15.6).

**`saved crashes`** — The number of inputs that caused a crash. Each crash is a potential entry point for analysis with GDB (Section 15.4). AFL++ deduplicates crashes by execution path: two inputs that crash at the same place in the same way count only once.

**`map density`** — The percentage of the coverage bitmap that has been activated. The two values indicate current coverage and maximum cumulative coverage. On a small program, 2-5% is common; on a larger program, even 0.5% can represent significant coverage. This number is relative to the bitmap size (64 KB by default), not to the total number of branches in the program.

**`exec speed`** — The number of executions per second. For a simple program read from a file, you typically expect between 1,000 and 10,000 exec/s. Below 100 exec/s, fuzzing will be very slow and you should investigate (program too slow, disk I/O, missing instrumentation). Above 10,000, conditions are excellent.

**`cycles done`** — The number of times the fuzzer has traversed its entire current corpus. After the first complete cycle, discoveries become rarer. If this counter reaches several dozen without a new crash or new input, the campaign has probably converged.

**`last new find`** — The time elapsed since the last discovery of a new path. If this counter exceeds 30 minutes to 1 hour on a simple program, the campaign has probably reached the end of its useful life.

---

## Stopping and resuming a session

AFL++ can be interrupted at any time with `Ctrl+C`. The complete campaign state is saved in the output directory. To resume:

```bash
$ afl-fuzz -i - -o out -- ./simple_parser_afl @@
```

The `-i -` (dash) tells AFL++ to resume from the existing state in `out/` rather than starting from an initial corpus. Previously discovered inputs, crashes, and the coverage bitmap are restored.

> ⚠️ **Warning** — **Never** relaunch with `-i in` on an existing output directory that already contains results. AFL++ will refuse to avoid overwriting your discoveries. If you want to start from scratch, first delete the `out/` directory.

---

## Parallel fuzzing on multiple cores

By default, `afl-fuzz` uses a single CPU core. To leverage a multi-core machine, AFL++ offers a master/slave mode (renamed *main/secondary* in recent versions):

```bash
# Terminal 1 — Main instance (deterministic)
$ afl-fuzz -i in -o out -M main -- ./simple_parser_afl @@

# Terminal 2 — Secondary instance (random)
$ afl-fuzz -i in -o out -S secondary01 -- ./simple_parser_afl @@

# Terminal 3 — Another secondary instance
$ afl-fuzz -i in -o out -S secondary02 -- ./simple_parser_afl @@
```

All instances share the same output directory `out/` and automatically synchronize their discoveries. The `-M` instance performs deterministic mutations (systematic bit flips, interesting value insertions), while `-S` instances perform random mutations (*havoc*). The combination covers more ground than N identical instances.

As a general rule, launch **one `-M` instance and N-1 `-S` instances**, where N is the number of available cores. On the VM recommended in Chapter 4 (2 to 4 cores), two to three instances is a good compromise.

---

## Fuzzing a binary without sources (QEMU mode)

In real-world RE, you don't always have the sources. AFL++ can then instrument the binary **at runtime** via QEMU emulation:

```bash
# Compile the binary normally (not with afl-gcc)
$ gcc -O2 -o target_nosrc target.c
$ strip target_nosrc

# Fuzz in QEMU mode
$ afl-fuzz -Q -i in -o out -- ./target_nosrc @@
```

The `-Q` flag activates QEMU user-mode. AFL++ runs the binary in an emulator that instruments each basic block on the fly. It's transparent to the target program — it doesn't know it's being emulated.

The performance cost is significant: expect 2 to 5 times slower speed compared to compile-time instrumentation. On a fast program (10,000 exec/s instrumented), QEMU mode will typically yield 2,000 to 5,000 exec/s — which remains perfectly usable.

The Frida alternative (`-O` instead of `-Q`) is sometimes faster on x86-64 binaries and doesn't require compiling QEMU support:

```bash
$ afl-fuzz -O -i in -o out -- ./target_nosrc @@
```

> 💡 **RE strategy** — If you have the sources, always use compile-time instrumentation (that's our case in this training). Reserve QEMU/Frida for closed targets. And if you have sources for *part* of the project (for example the parsing library but not the main program), you can write a **harness** that directly calls the parsing function — we'll see this approach with libFuzzer in Section 15.3.

---

## First results: exploring the output directory

After a few minutes of fuzzing, the `out/` directory contains AFL++'s discoveries:

```bash
$ ls out/default/
crashes/  hangs/  queue/  cmdline  fuzz_bitmap  fuzzer_stats  plot_data
```

### `queue/` — The discovered corpus

```bash
$ ls out/default/queue/
id:000000,time:0,execs:0,orig:seed_v1.bin  
id:000001,time:0,execs:0,orig:seed_v2.bin  
id:000002,time:0,execs:0,orig:seed_v0.bin  
id:000003,time:137,execs:4821,op:havoc,rep:2,+cov  
id:000004,time:298,execs:11037,op:havoc,rep:4,+cov  
...
```

Each file in `queue/` is an input that triggered a new path. The name encodes metadata: the timestamp, the number of executions at the time of discovery, the mutation operation that produced it, and `+cov` indicates it added coverage.

For RE, these files are valuable: by examining them with `xxd` or ImHex, you can observe how the fuzzer progressively "learned" the format expected by the parser. The first inputs resemble the seeds; the later ones may be radically different, reflecting deep paths in the program's logic.

### `crashes/` — Inputs that crash the program

```bash
$ ls out/default/crashes/
README.txt  
id:000000,sig:11,src:000003,time:1842,execs:52341,op:havoc,rep:8  
id:000001,sig:06,src:000004,time:3107,execs:89023,op:havoc,rep:2  
```

Each file is an input that caused the program to terminate with a signal. `sig:11` is a SIGSEGV (segfault), `sig:06` is a SIGABRT (typically triggered by ASan or an `assert`). These files are the starting point for detailed analysis in Section 15.4.

To reproduce a crash:

```bash
$ ./simple_parser_afl out/default/crashes/id:000000,sig:11,*
Segmentation fault
```

Or with GDB for in-depth analysis:

```bash
$ gdb -q ./simple_parser_afl
(gdb) run out/default/crashes/id:000000,sig:11,src:000003,time:1842,execs:52341,op:havoc,rep:8
```

### `hangs/` — Inputs that cause a timeout

AFL++ considers a program to "hang" if it exceeds the configured timeout (by default, automatically determined from the seeds' execution time, typically a few hundred milliseconds). Hangs often indicate infinite loops or blocking waits — useful information for understanding the parser's boundary conditions.

### `fuzzer_stats` — Statistics in text format

```bash
$ cat out/default/fuzzer_stats
start_time        : 1711000000  
last_update       : 1711000157  
run_time          : 157  
execs_done        : 87342  
execs_per_sec     : 2341.00  
corpus_count      : 23  
saved_crashes     : 3  
...
```

This file is useful for scripting: you can monitor a fuzzing campaign from an external script by reading these statistics.

---

## Useful `afl-fuzz` options

A few frequently used options, beyond the basic launch:

| Option | Effect |  
|--------|--------|  
| `-t 1000` | Sets the timeout to 1000 ms (useful if the program is slow) |  
| `-m none` | Disables the memory limit (necessary with ASan, which consumes a lot of virtual memory) |  
| `-x dict.txt` | Provides a token dictionary (cf. Section 15.6) |  
| `-p exploit` | Selects the `exploit` power schedule (favors exploiting known paths vs exploring new ones — useful late in a campaign) |  
| `-D` | Enables deterministic mutations even in secondary mode |

For a session with ASan, the typical complete command is:

```bash
$ afl-fuzz -i in -o out -m none -t 5000 -- ./simple_parser_asan @@
```

The `-m none` is essential because ASan uses a very large amount of virtual memory (via `mmap`) that AFL++'s default limit would block.

---

## Putting it into practice: first run on `ch15-keygenme`

The previous examples used a fictitious `simple_parser.c` to illustrate the concepts. Let's move to a real training binary: the keygenme from Chapter 21. This program reads a key from `argv[1]` (or stdin depending on the variant) and verifies its validity — a classic use case for fuzzing.

### Instrumented compilation of the keygenme

```bash
$ cd binaries/ch15-keygenme/
$ make clean
$ make fuzz
```

The `Makefile`'s `fuzz` target directly compiles the AFL++ instrumented variants (`keygenme_afl` and `keygenme_afl_asan`) using `afl-gcc`. If `afl-gcc` isn't in the standard PATH, you can override:

```bash
$ make fuzz AFL_CC=/path/to/afl-gcc
```

Alternatively, you can compile directly without going through the Makefile:

```bash
$ afl-gcc -O0 -g -o keygenme_afl keygenme.c
```

Verification:

```bash
$ echo -n "AAAA" | afl-showmap -o /dev/stdout -- ./keygenme_afl 2>/dev/null | wc -l
```

The number of edges should be greater than zero.

### Initial corpus and dictionary

The keygenme expects a character string as an argument. Let's prepare a minimal corpus:

```bash
$ mkdir in_keygen
$ echo -n "AAAA" > in_keygen/seed1.bin
$ echo -n "0000" > in_keygen/seed2.bin
$ echo -n "ABCD1234" > in_keygen/seed3.bin
```

A small dictionary with characters typical of license keys:

```bash
$ cat > dict_keygen.txt << 'EOF'
digits="0123456789"  
dash="-"  
upper="ABCDEFGHIJKLMNOPQRSTUVWXYZ"  
hex_prefix="0x"  
EOF  
```

### Launch

The keygenme accepts a key either via `argv[1]` (direct mode) or via stdin (interactive mode, when no argument is provided). For fuzzing with AFL++, we use **stdin mode** — that is, without `@@` — because AFL++ will send the content of each mutated input directly to the program's standard input:

```bash
$ afl-fuzz -i in_keygen -o out_keygen -x dict_keygen.txt \
    -- ./keygenme_afl
```

> 💡 **Why not `@@` here?** — The `@@` marker tells AFL++ to replace it with a **file path**. This is suited for programs that *open and read* a file (like the `ch25-fileformat` parser). Here, the keygenme uses `argv[1]` as the **key string itself**, not as a filename — passing a path like `/tmp/.cur_input` as a key would be meaningless. The stdin mode works around this problem: AFL++ writes the mutated data to stdin, and the keygenme reads it via `fgets`.

### What we observe

The keygenme is a very fast program (no file I/O, no complex parsing). Expect speeds of 5,000 to 20,000 exec/s. The `corpus count` should rise quickly in the first few minutes — each string that takes a different path through the validation routine is kept.

Crashes will be rare (the keygenme is a simple program without risky buffer manipulation), but the **corpus** produced is valuable: it contains strings that exercise different branches of the verification routine. By examining them with `xxd` or `cat`, you can deduce the expected key structure — prefix, separators, length, valid character set.

```bash
# Examine the corpus inputs that exercise the most branches
$ for f in out_keygen/default/queue/id:*; do
    edges=$(afl-showmap -q -o /dev/stdout -- ./keygenme_afl < "$f" 2>/dev/null | wc -l)
    echo "$edges $(cat "$f")"
  done | sort -rn | head -10
```

The inputs with the highest number of edges are those that penetrate deepest into the validation routine — they're the best candidates for understanding the key verification logic.

> 🔗 **This keygenme will be analyzed in detail in Chapter 21** with all techniques (static analysis, GDB, patching, angr). Fuzzing here serves as a first contact: in a few minutes, it reveals clues about the expected key structure that static analysis will then confirm.

---

## Summary

Installing and getting started with AFL++ follows a straightforward workflow:

1. **Install** AFL++ from packages or source.  
2. **Compile** the target binary with `afl-gcc` (or `afl-clang-fast`) instead of `gcc`, optionally with ASan.  
3. **Prepare** an initial corpus from knowledge acquired during triage and static analysis.  
4. **Configure** the system (core_pattern, CPU governor).  
5. **Launch** `afl-fuzz` and observe the dashboard.  
6. **Exploit** the results in `out/` — crashes, corpus, statistics.

The fuzzer is now running. But AFL++ isn't the only tool available: in Section 15.3, we'll see **libFuzzer**, which takes a different approach — *in-process* fuzzing — particularly effective when you want to target a specific parsing function rather than the entire program.

---


⏭️ [libFuzzer — in-process fuzzing with sanitizers](/15-fuzzing/03-libfuzzer.md)
