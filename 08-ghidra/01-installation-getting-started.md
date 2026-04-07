🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 8.1 — Installation and getting started with Ghidra

> **Chapter 8 — Advanced disassembly with Ghidra**  
> **Part II — Static Analysis**

---

## Ghidra: context and philosophy

Ghidra was developed internally by the NSA for over a decade before being made public in March 2019 at the RSA conference. Its release under the Apache 2.0 license was a major event in the reverse-engineering community: for the first time, a professional-caliber tool — integrating a quality decompiler — became freely available and open source.

Before Ghidra, the landscape schematically divided into two camps. On one side, IDA Pro with its Hex-Rays decompiler, considered the industrial reference, but whose license costs several thousand euros per year per architecture. On the other, free tools like Radare2, powerful but with a steep learning curve and lacking a comparable integrated decompiler. Ghidra bridged this gap by offering a multi-architecture decompiler in an open-source framework, extensible through scripts and plugins.

Today, Ghidra is used by security researchers, malware analysts, CTF participants, as well as developers who need to understand a binary without access to the source code. It is actively maintained by the NSA on GitHub, with community contributions.

> ⚠️ **Note on the NSA origin** — The fact that Ghidra is developed by the NSA sometimes raises legitimate concerns. The source code is fully public and auditable on GitHub (`NationalSecurityAgency/ghidra`). Many independent researchers have examined it without finding a back door. Ghidra is an analysis tool, not an exploitation tool: it reads binaries, it does not execute them. That said, as with any software, it is recommended to download it exclusively from official sources.

---

## System requirements

### Java Development Kit (JDK)

Ghidra is written in Java (with a native decompiler in C++). It requires a **compatible JDK** to function — a simple JRE is not enough.

Recent versions of Ghidra (11.x) require **JDK 17 or higher** (recommended LTS: JDK 17 or JDK 21). JDK 21+ versions are supported starting with Ghidra 11.0. Always check the official download page to know the minimum version required by the Ghidra version you're installing.

Recommended JDK distributions (all are free and work with Ghidra):

- **Eclipse Temurin** (Adoptium) — the reference community distribution, available at `adoptium.net`;  
- **Amazon Corretto** — distribution maintained by Amazon;  
- **Oracle JDK** — Oracle's official distribution, free for personal use since the NFTC license.

Verify that Java is installed and accessible:

```bash
java -version
```

The output must indicate version 17 or higher. If multiple Java versions coexist on your system, make sure the `JAVA_HOME` environment variable points to the right one:

```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
```

On Debian/Ubuntu distributions, you can install the JDK with:

```bash
sudo apt update  
sudo apt install openjdk-17-jdk  
```

On Kali Linux, the JDK is generally already present. Just verify the version.

### Hardware resources

Ghidra is not a lightweight tool. For comfortable use:

- **RAM**: 4 GB minimum, 8 GB recommended. Analyzing large C++ binaries (with template instantiations, STL, etc.) can consume a lot of memory.  
- **Disk**: Ghidra itself weighs about 500 MB once decompressed. Each analysis project creates a local database that can reach several hundred MB for a complex binary.  
- **CPU**: automatic analysis is CPU-intensive during the initial import. A multi-core processor significantly speeds up this phase.

---

## Download and installation

### Step 1 — Download Ghidra

Go to the official GitHub releases page:

```
https://github.com/NationalSecurityAgency/ghidra/releases
```

Download the `.zip` archive matching the latest stable version. The filename follows the format `ghidra_VERSION_PUBLIC_DATE.zip` (for example `ghidra_11.3_PUBLIC_20250108.zip`). Never download Ghidra from a third-party site — only the NSA's official GitHub repository guarantees the software's integrity.

> ⚠️ **Check the current version** on the [GitHub releases page](https://github.com/NationalSecurityAgency/ghidra/releases) — version numbers and dates evolve regularly.

> 💡 **Integrity verification** — Each release provides SHA-256 checksums. Get into the habit of verifying them:  
> ```bash  
> sha256sum ghidra_*_PUBLIC_*.zip  
> ```  
> Compare the obtained hash with the one published on the release page.

### Step 2 — Extract the archive

Ghidra does not require an installer. Simply decompress the archive into a directory of your choice:

```bash
cd /opt  
sudo unzip ~/Downloads/ghidra_*_PUBLIC_*.zip  
sudo ln -sf /opt/ghidra_*_PUBLIC /opt/ghidra    # symlink for stable access  
```

> 💡 Chapter 4 (section 4.2) creates this `/opt/ghidra` symlink. All examples in this chapter and the rest of the training use `/opt/ghidra/` as the path.

The `/opt` directory is a common choice for third-party tools under Linux, but you can install Ghidra wherever you wish (`~/tools/ghidra`, `/usr/local/share/ghidra`, etc.). The key is to choose a stable location you won't move, because Ghidra records absolute paths in its projects.

The structure of the decompressed directory looks like this:

```
ghidra_VERSION_PUBLIC/
├── ghidraRun                  ← Main launch script (Linux/macOS)
├── ghidraRun.bat              ← Launch script (Windows)
├── support/
│   ├── analyzeHeadless        ← Launch in headless mode (section 8.9)
│   ├── launch.properties      ← JVM memory configuration
│   └── ...
├── Ghidra/
│   ├── Features/              ← Analysis modules (processors, formats, etc.)
│   ├── Processors/            ← Architecture definitions
│   └── Extensions/            ← Installable extensions
├── docs/                      ← Integrated documentation
├── server/                    ← Ghidra Server (multi-user collaboration)
└── LICENSE
```

### Step 3 — Configure JVM memory

By default, Ghidra allocates a modest amount of memory to the JVM. For the analysis of substantial C++ binaries, it is recommended to increase this allocation. Edit the `support/launch.properties` file:

```bash
nano /opt/ghidra/support/launch.properties
```

Look for the `MAXMEM` line and adjust it according to your available RAM:

```properties
MAXMEM=4G
```

A 4 GB value suits most binaries we will analyze in this tutorial. If you work on very large binaries (several tens of MB) or projects containing many files, consider 8 GB.

### Step 4 — Create an alias or a launcher

For quick access, add an alias in your `~/.bashrc` or `~/.zshrc` file:

```bash
alias ghidra='/opt/ghidra/ghidraRun'
```

Reload the file:

```bash
source ~/.bashrc
```

You'll now be able to launch Ghidra simply by typing `ghidra` in a terminal.

> 💡 **Alternative: `.desktop` file** — If you prefer a graphical launcher, create a `~/.local/share/applications/ghidra.desktop` file with the `Exec`, `Icon` (an icon is provided in `docs/images/`) and `Name` fields.

---

## First launch

Launch Ghidra:

```bash
ghidra
```

or directly:

```bash
/opt/ghidra/ghidraRun
```

### License acceptance

On the very first launch, Ghidra displays the Apache 2.0 license. Read it and accept it to continue. This step happens only once.

### The Project Manager window

The interface that opens is **not** the analysis environment — it's the **Project Manager**. It's Ghidra's entry point, the one from which you create projects, import binaries, and launch the various tools.

The Project Manager consists of:

- **The menu bar** — access to project creation, import, configuration, and help functions.  
- **The active project's file tree** — once a project is opened, imported binaries appear here as a tree.  
- **The "Tool Chest" panel** — the icons of available tools. The most important is the **CodeBrowser** (green dragon icon), which we'll use almost exclusively.

### Tip: updating Ghidra

Ghidra does not have an automatic update mechanism. To update, download the new version, decompress it into a new directory, and recreate your alias. Your existing projects remain compatible: Ghidra knows how to migrate project databases to a more recent format when opening. However, this migration is irreversible — once a project is opened in a newer version, it can no longer be opened in an earlier version.

---

## Creating a project

Ghidra organizes work into **projects**. A project is a container that groups one or more analyzed binaries, along with all annotations, custom types, comments, and renamings you've made. Each project corresponds to a directory on disk containing a proprietary database.

There are two types of projects:

- **Non-Shared Project** — local project, stored only on your machine. This is the type we'll use in this tutorial.  
- **Shared Project** — project hosted on a Ghidra Server, allowing multiple analysts to work simultaneously on the same binaries. Useful in a professional context, but outside the scope of this chapter.

### Create a local project

1. In the Project Manager, click **File → New Project…**  
2. Select **Non-Shared Project**, then click **Next**.  
3. Choose a **directory** to store the project. Create a dedicated folder, for example `~/ghidra-projects/`.  
4. Give the project a **name**. For this tutorial, name it `training-re` or `chapter-08`.  
5. Click **Finish**.

The project is created. The file tree is empty — it's time to import a first binary.

> 💡 **Naming convention** — Adopt a naming convention for your projects from the start. For example, one project per chapter (`ch08-ghidra`, `ch21-keygenme`…) or a single `training-re` project with internal folders to organize binaries. Ghidra lets you create folders in a project's tree via right-click → **New Folder**.

---

## Understanding the structure of a project on disk

When you create a project named `training-re` in `~/ghidra-projects/`, Ghidra creates two elements:

```
~/ghidra-projects/
├── training-re.gpr          ← Project file (pointer, metadata)
└── training-re.rep/         ← Database directory
    ├── project.prp
    ├── idata/                 ← Index data
    ├── user/                  ← User preferences for this project
    └── ...
```

The `.gpr` file is the entry point: that's what you open to find your project again. The `.rep` directory contains all analysis data. These files are not meant to be edited manually.

To save or share a project, simply copy the `.gpr` file and the associated `.rep` directory. You can also use **File → Archive Current Project…** to create a portable `.gar` archive.

---

## Importing a first binary (quick preview)

To verify that your installation works correctly, let's import a simple binary. We'll detail the import process and its options in section 8.2 — here, the goal is simply to validate the environment.

1. From the Project Manager, click **File → Import File…** (or drag-and-drop a file directly into the project tree).  
2. Select the `keygenme_O0` binary from `binaries/ch08-keygenme/`.  
3. Ghidra displays an **Import** dialog:  
   - **Format**: Ghidra automatically detects the format. For a Linux ELF binary, it displays `Executable and Linking Format (ELF)`.  
   - **Language**: Ghidra detects the architecture. For an x86-64 binary, it proposes `x86:LE:64:default` (x86, Little Endian, 64 bits).  
   - If these values are correct — and they will be in the vast majority of cases with GCC binaries — click **OK**.  
4. A summary dialog displays with import details. Click **OK**.  
5. Ghidra offers to launch **automatic analysis**. Click **Yes** and accept the default options for now (we'll detail them in 8.2).

Analysis takes a few seconds for a small binary. Once finished, the **CodeBrowser** opens with the binary loaded. You should see the assembly listing, the decompiler panel, and the symbol tree.

If everything displays correctly, your installation is functional.

---

## Interface tour (overview)

The CodeBrowser is Ghidra's main workspace. We'll detail it in section 8.3, but here is a first orientation so you don't feel lost when opening it.

The interface is divided into several panels that can be arranged by drag-and-drop:

- **Program Trees** (top left) — displays the binary structure as a tree: segments, sections, memory fragments. Useful for navigating by ELF section.  
- **Symbol Tree** (bottom left) — lists all detected functions, labels, classes, namespaces, and imports/exports. It's your main entry point for navigating the binary. Double-click a function name to access it directly.  
- **Listing** (center) — the disassembly. It's here that you read assembly code, address by address. This panel is interactive: you can click an instruction to see its references, rename elements, add comments.  
- **Decompiler** (right) — the C pseudo-code produced by Ghidra's decompiler. This panel synchronizes with the Listing: clicking a pseudo-code line highlights the matching assembly instructions, and vice versa.  
- **Console** (bottom) — displays analysis messages, script errors, and various logs.  
- **Data Type Manager** (accessible via the **Window** menu) — the type manager. It's here that you'll define your custom structures, enums, and typedefs.

> 💡 **Customizable layout** — All panels can be moved, stacked as tabs, resized, or detached into floating windows. If you accidentally close a panel, find it via the **Window** menu. To return to the default layout, use **Window → Reset Window Layout**.

---

## Essential keyboard shortcuts

Here are the shortcuts you'll use most frequently from your first sessions. No need to memorize them all now — they'll come naturally with practice.

| Shortcut | Action |  
|---|---|  
| `G` | **Go To Address** — jump to a precise address |  
| `L` | **Rename** — rename the function, variable, or label under the cursor |  
| `;` | **Set Comment** — add an EOL (End Of Line) comment |  
| `Ctrl+;` | Add a Pre comment (above the instruction) |  
| `T` | **Set Data Type** — change the type of a variable or parameter |  
| `X` | **Show References** — display all cross-references to the element under the cursor |  
| `Ctrl+Shift+F` | **Search for Strings** — search for strings in the binary |  
| `F` | **Edit Function** — modify a function's signature (name, return type, parameters) |  
| `Space` | Toggle between the Listing view and the Function Graph view |  
| `Ctrl+E` | Export the program (various formats) |

---

## Ghidra and security updates

Ghidra embeds a local web server (for its built-in help feature) and uses Java components. Like any software, it can be affected by vulnerabilities. A few good practices:

- **Keep Ghidra updated** by following releases on GitHub. Release notes systematically mention security fixes.  
- **Keep your JDK updated** — Java vulnerabilities are regularly patched in quarterly updates.  
- **Don't run Ghidra as root** — it's neither necessary nor desirable. Ghidra only needs read access to the binaries being analyzed and write access in the project directory.  
- **Don't open untrusted binaries outside an isolated VM** — while Ghidra is a static-analysis tool (it doesn't execute the binary), some format parsers could theoretically be exploited by a malformed file. In the context of malware analysis (Part VI), always work in the sandboxed VM of Chapter 26.

---

## Summary

At this stage, you have a functional Ghidra installation with a compatible JDK, a created project, and a first imported binary. You have an overview of the interface — the Project Manager for project management and the CodeBrowser for analysis — as well as the keyboard shortcuts that will speed up your daily work.

The next section dives into the details of the import process and automatic-analysis options, which determine the quality of the result before you even start reading the disassembly.

---


⏭️ [Importing an ELF binary — automatic analysis and options](/08-ghidra/02-elf-import-analysis.md)
