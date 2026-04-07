🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 6.2 — Installation and interface tour (Pattern Editor, Data Inspector, Bookmarks, Diff)

> 🎯 **Goal of this section**: Install ImHex on your Linux distribution, open a first ELF binary, and identify the interface's main panels so you can navigate the tool efficiently throughout the rest of the chapter.

---

## Installation

### From official packages (recommended method)

ImHex ships pre-built binaries for the major Linux distributions. This is the simplest method and the one that guarantees an up-to-date version.

**Flatpak (universal)** — works on any distribution with Flatpak installed:

```bash
flatpak install flathub net.werwolv.ImHex
```

To launch ImHex afterwards:

```bash
flatpak run net.werwolv.ImHex
```

**Ubuntu / Debian** — a `.deb` is available on the GitHub releases page:

```bash
# Download the .deb from https://github.com/WerWolv/ImHex/releases
# Then install:
sudo dpkg -i imhex-*.deb  
sudo apt-get install -f   # resolve missing dependencies if needed  
```

**Arch Linux / Manjaro**:

```bash
# From the community repositories
sudo pacman -S imhex
```

**AppImage** — portable alternative, no system-wide install:

```bash
chmod +x ImHex-*.AppImage
./ImHex-*.AppImage
```

> 💡 **Which version to pick?** For this training, any version ≥ 1.33 works. The features we use (`.hexpat` patterns, Data Inspector, Diff, YARA) have been stable for several releases. If you use your distribution's packaged version and it is older, prefer the Flatpak or AppImage to get a recent version.

### Compiling from source

If you want the very latest version or plan to contribute to the project, building from source is possible but requires several dependencies (CMake ≥ 3.16, GCC ≥ 11 or Clang ≥ 14, and a series of libraries). The detailed procedure is documented in the GitHub repo's `README.md`. For this training, the pre-built packages are largely sufficient.

### Verifying the install

Launch ImHex. If the application opens and shows the welcome screen with **Open File**, **Open Project** options and links to the documentation, you are set. You can also check from the terminal:

```bash
imhex --version
```

> ⚠️ **Flatpak note**: If you installed via Flatpak, the `imhex` command is not directly in your `PATH`. Use `flatpak run net.werwolv.ImHex` or create an alias in your `.bashrc`:  
> ```bash  
> alias imhex='flatpak run net.werwolv.ImHex'  
> ```

### Installing the Content Store (community patterns and plugins)

On first launch, ImHex offers to download the **Content Store** — a collection of pre-written `.hexpat` patterns for common formats (ELF, PE, PNG, ZIP, JPEG, etc.), as well as plugins and magic files. Accept this download: these patterns will serve as references and examples throughout the chapter.

If you declined or the download failed, you can access it at any time via **Help → Content Store**.

---

## First contact: opening an ELF binary

Before detailing each interface panel, let's open a file to have something concrete in front of us. Use one of the binaries you compiled in Chapter 2 or 4 — for example the `hello` compiled with symbols:

```bash
# If you do not have a binary at hand:
echo '#include <stdio.h>  
int main() { printf("Hello RE!\\n"); return 0; }' > /tmp/hello.c  
gcc -O0 -g -o /tmp/hello /tmp/hello.c  
```

Open it in ImHex:

- via the **File → Open File** menu and navigate to the binary, or  
- directly from the terminal: `imhex /tmp/hello`

The interface fills immediately. You see hexadecimal columns, an ASCII representation on the right, and several panels around the main view. That is the interface we will now methodically explore.

---

## Anatomy of the interface

ImHex's interface is organized around a **central hex view** surrounded by **auxiliary panels** that can be shown, hidden, resized, and rearranged freely. Each panel has a precise role in the analysis workflow. Let's go through them.

### The hex view (Hex Editor)

This is the heart of the interface, the view you will have in front of you at all times. It shows the file's content in three synchronized columns:

- **Offsets** (left column) — the address of each line in the file, in hexadecimal. By default, ImHex displays 16 bytes per line, so offsets increment by `0x10` each time.  
- **Hexadecimal values** (central columns) — each byte represented by two hex digits. Bytes are grouped in pairs or blocks depending on configuration.  
- **ASCII representation** (right column) — each byte interpreted as an ASCII character. Non-printable bytes are shown as dots (`.`).

When you click a byte in the hex view, the cursor moves there and all auxiliary panels update to reflect the data at that offset. This is a fundamental behavior: **the cursor is the central pivot** of the entire interface.

**Basic navigation**:

- `Ctrl+G` — go to a precise offset (Go to address). You can enter an address in hexadecimal (`0x1040`) or decimal.  
- `Ctrl+F` — search for a byte sequence, an ASCII string, or a UTF-16 string.  
- Mouse wheel or scrollbar — linear navigation in the file.  
- `Ctrl+Z` / `Ctrl+Y` — undo / redo modifications (ImHex keeps a full edit history).

**Direct editing**: you can modify bytes directly in the hex view by typing new values. Modified bytes appear in a different color (red by default) to distinguish them from the original data. This feature is essential for the binary patching we will see in Chapter 21.

### The Pattern Editor

The Pattern Editor is the panel that sets ImHex apart from competitors. It has two parts: a **code editor** (on top) where you write your `.hexpat` patterns, and a **results view** (at the bottom, often called "Pattern Data") where ImHex shows the parsed structures as a tree.

The workflow is: you write (or load) a `.hexpat` pattern in the editor, click the **Evaluate** button (▶ icon) or press `F5`, and ImHex parses the file according to your description. Structures appear in the results tree, and the corresponding regions are colorized in the hex view.

For example, if your pattern declares a 64-byte `Elf64_Ehdr` structure at offset 0, the first 64 bytes of the file will be colorized and each field will be named and displayed with its interpreted value in the tree.

The code editor offers syntax highlighting, autocompletion, and error highlighting. If your pattern has a syntax error, ImHex shows a clear message with the line number. We will explore the `.hexpat` language in depth starting in section 6.3.

> 💡 **Tip**: The Pattern Data panel can be detached from the main window (right-click on the tab → **Detach**). On a multi-monitor setup, placing the pattern tree on one screen and the hex view on the other is a considerable comfort gain.

### The Data Inspector

The Data Inspector is the panel that answers the question "what does this byte mean?" in every possible form. It takes the bytes under the cursor and simultaneously interprets them as every common data type.

Here is what the Data Inspector shows when the cursor sits on a byte sequence:

- **Integers**: `uint8_t`, `int8_t`, `uint16_t`, `int16_t`, `uint32_t`, `int32_t`, `uint64_t`, `int64_t` — in little-endian and big-endian.  
- **Floats**: `float` (32-bit IEEE 754), `double` (64-bit IEEE 754).  
- **Boolean**: interpretation as `true` / `false`.  
- **Character**: ASCII, UTF-8, wide char.  
- **Timestamp**: interpretation as 32-bit and 64-bit Unix timestamps (readable date and time).  
- **Color**: 32-bit RGBA (useful for graphics formats).  
- **Address**: interpretation as a 32-bit or 64-bit pointer.

This panel is particularly valuable in the exploration phase, when you do not yet know what type of data sits at a given offset. Rather than guessing and converting manually, you scan the file with the cursor and the Data Inspector shows every interpretation in real time. When a value "makes sense" — a timestamp that lands on a plausible date, an integer that matches a section size, a float that looks like a coordinate — you have a strong hint about the field's type.

> 💡 **Customization**: You can individually enable or disable each type in the Data Inspector via the context menu. If you only work on integer structures, hiding floats and timestamps reduces visual noise.

### Bookmarks

The Bookmarks panel lets you create **named, colored markers** on regions of the file. Each bookmark associates an offset range (start + size) with a name, a color, and a free-form comment.

To create a bookmark: select a byte range in the hex view (click + drag), then right-click → **Create Bookmark**, or use the `Ctrl+B` shortcut. A dialog asks for a name and a comment. The region is immediately highlighted in the hex view with the chosen color.

Bookmarks let you **document your analysis as you go**. When you identify that a byte range is the header, that another one contains a string table, that a third looks like an encryption key, you bookmark them immediately. That creates a progressive map of the file that persists between sessions if you save an ImHex project.

The Bookmarks panel lists every bookmark with its offset, size, and comment. Clicking a bookmark in the list jumps the hex view to the matching offset — it is an efficient way to navigate a bulky file by points of interest rather than by numeric addresses.

### The Diff view

The Diff view lets you compare **two open files** side by side with differences highlighted. To use it, open two files in separate tabs (ImHex supports multiple tabs), then enable the Diff view via **View → Diff**.

ImHex displays both files in parallel columns with color coding: identical bytes are on a neutral background, differing bytes are highlighted. Scrolling is synchronized between the two views — scrolling in one file makes the other follow. Navigation buttons let you jump to the previous or next difference.

This feature is useful in several RE scenarios we will encounter in the training:

- Compare a binary compiled with `-O0` and the same with `-O2` to see optimization impact on machine code (complementing the disassembly-level diff in Chapter 7).  
- Compare a binary before and after stripping (`strip`) to visualize the removed sections.  
- Compare an original binary with a patched binary to check that your patch only touches the intended bytes (Chapter 21).  
- Compare two versions of a binary to locate the changes introduced by a security fix (Chapter 10).

---

## Other useful panels and views

Beyond the five main panels described above, ImHex offers several complementary views that we will use occasionally in the following sections.

### Information (File → Information)

This panel displays **global statistics** about the open file: size, entropy per block, byte value distribution (histogram), detected type. The **entropy analysis** is particularly useful in RE: a high-entropy area (close to 8 bits/byte) in a binary suggests compressed or encrypted data, while a low-entropy area suggests text, padding zeros, or regularly structured data. We will exploit this analysis in Chapter 29 to detect packers.

### Hashes

ImHex can compute **cryptographic hashes** (MD5, SHA-1, SHA-256, CRC32…) on the entire file or on a selection. That avoids leaving the editor to run `sha256sum` when you need to verify a sample's integrity or document an IOC (Indicator of Compromise) in a malware-analysis report.

### Strings

Similar to the `strings` CLI command but with a graphical interface. ImHex scans the file for sequences of printable characters and displays them with their offsets. Clicking a string jumps the hex view to the matching offset. ImHex supports ASCII and UTF-16 searches (useful for Windows binaries compiled with MinGW).

### Disassembler and YARA

ImHex integrates a **disassembler** (based on the Capstone library) and a **YARA engine** directly accessible from the interface. We will devote dedicated sections to them (6.9 and 6.10) later in this chapter.

---

## Organizing the workspace

ImHex's interface is fully modular. You can rearrange panels by drag-and-drop, stack them in tabs, detach them into floating windows, or hide them completely via the **View** menu.

Here is an efficient work layout for reverse engineering that we recommend as a starting point:

- **Center**: the hex view in a large area — it takes up the most space.  
- **Right**: the Data Inspector, always visible, to interpret bytes under the cursor in real time.  
- **Bottom**: the Pattern Editor (code editor + results tree), which you will enlarge when you work on a `.hexpat`.  
- **Left**: the Bookmarks, to navigate between your annotations.

This layout is just a suggestion — adapt it to your screen and workflow. What matters is that the Data Inspector stays always visible (it is used constantly) and that the hex view has enough space to show a comfortable number of columns.

> 💡 **ImHex projects**: If you work on a file for an extended period (which will be the case in the practical-case chapters), save your work as a **project** via **File → Save Project**. An ImHex project keeps the opened file, your bookmarks, your loaded patterns, and your panel layout. That lets you resume exactly where you left off.

---

## Summary

ImHex installs in seconds via Flatpak, `.deb`, or AppImage. Its interface is organized around the central hex view, enriched by the Pattern Editor (structural parsing), the Data Inspector (real-time multi-type interpretation), the Bookmarks (integrated documentation), and the Diff view (visual comparison). These panels form a cohesive whole where every click in the hex view updates all panels simultaneously — the cursor as the central pivot of the analysis. Before diving into the `.hexpat` language in section 6.3, take a few minutes to open various binaries from your `binaries/` folder and explore the interface freely: move the cursor, watch the Data Inspector, create a bookmark or two, try the Diff view between two versions of the same binary.

---


⏭️ [The `.hexpat` pattern language — syntax and base types](/06-imhex/03-hexpat-language.md)
