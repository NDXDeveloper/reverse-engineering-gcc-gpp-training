/*
 * packer_signatures.yar — Detection of packers, protections and ELF anomalies
 * Reverse Engineering Training — Applications compiled with the GNU toolchain
 *
 * This file contains YARA rules to detect:
 *   - Packed binaries (UPX, and generic patterns)
 *   - Stripped binaries (absence of .symtab)
 *   - Control flow obfuscation indicators
 *   - Common anti-debugging techniques
 *   - Suspicious ELF structural anomalies
 *   - Markers specific to training binaries (ch25, ch29)
 *
 * Usage:
 *   yara -r packer_signatures.yar binaries/
 *   yara -s -m packer_signatures.yar binaries/ch29-packed/
 *
 * MIT License — Strictly educational use.
 */

import "elf"

/* ============================================================
 *  UPX — Ultimate Packer for eXecutables
 * ============================================================ */

rule UPX_Packed_ELF
{
    meta:
        description = "ELF binary packed with UPX"
        category    = "packer"
        packer      = "UPX"
        chapter     = "29"
        reference   = "https://upx.github.io/"
        unpacking   = "upx -d <binary>"

    strings:
        // ASCII signature "UPX!" present in the decompression stub
        $upx_magic = "UPX!"

        // UPX section names (replace original sections)
        $sect_upx0 = "UPX0"
        $sect_upx1 = "UPX1"
        $sect_upx2 = "UPX2"

        // UPX version string (e.g.: "UPX 4.2.1")
        $upx_version = /UPX\x20[0-9]+\.[0-9]+/

        // UPX header: magic followed by version and compression info
        // First 4 bytes of the internal UPX header
        $upx_hdr = { 55 50 58 21 }     // "UPX!" in hex

        // Copyright information embedded in the stub
        $upx_copyright = "the UPX Team"

    condition:
        // Valid ELF
        uint32(0) == 0x464C457F and     // \x7FELF
        // At least the magic + a UPX section name
        $upx_magic and
        (1 of ($sect_upx0, $sect_upx1, $sect_upx2))
}

rule UPX_Packed_Stripped_ELF
{
    meta:
        description = "ELF binary packed with UPX AND stripped (double protection)"
        category    = "packer"
        packer      = "UPX"
        chapter     = "29"
        difficulty  = "high"

    strings:
        $upx_magic = "UPX!"
        $sect_upx0 = "UPX0"
        $sect_upx1 = "UPX1"

    condition:
        uint32(0) == 0x464C457F and
        $upx_magic and
        ($sect_upx0 or $sect_upx1) and
        // No .symtab section (stripping indicator)
        not for any i in (0..elf.number_of_sections - 1) : (
            elf.sections[i].name == ".symtab"
        )
}

/* ============================================================
 *  Generic packing detection (heuristics)
 * ============================================================ */

rule ELF_High_Entropy_Text
{
    meta:
        description = "ELF with suspicious .text section (high entropy suggests packing or encryption)"
        category    = "packer"
        note        = "Heuristic: a compressed or encrypted .text section has entropy > 6.8"

    strings:
        // Long sequences of high-entropy bytes are rare in legitimate
        // non-optimized code. We look for the absence of classic patterns
        // combined with the presence of ELF markers.

        // Standard GCC prologue (push rbp; mov rbp, rsp)
        $gcc_prologue = { 55 48 89 E5 }

        // nop sled (padding between functions)
        $nop_sled = { 90 90 90 90 90 90 90 90 }

        // endbr64 (CET, present in recent GCC binaries)
        $endbr64 = { F3 0F 1E FA }

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        // A normal GCC binary contains prologues and padding
        // A packed binary does not (original code is compressed)
        not $gcc_prologue and
        not $nop_sled and
        not $endbr64
}

rule ELF_Single_Load_Segment
{
    meta:
        description = "ELF with only one LOAD segment (typical of custom packers)"
        category    = "packer"
        note        = "A normal GCC ELF has at least 2 LOAD segments (RX + RW)"

    condition:
        uint32(0) == 0x464C457F and
        elf.number_of_segments > 0 and
        // Count LOAD segments
        for 1 i in (0..elf.number_of_segments - 1) : (
            elf.segments[i].type == elf.PT_LOAD
        ) and
        not for 2 i in (0..elf.number_of_segments - 1) : (
            elf.segments[i].type == elf.PT_LOAD
        )
}

rule ELF_Writable_Text
{
    meta:
        description = "ELF with writable .text section (self-modifying code or packer stub)"
        category    = "packer"
        note        = "A legitimate .text is R-X, never RWX"

    condition:
        uint32(0) == 0x464C457F and
        for any i in (0..elf.number_of_sections - 1) : (
            elf.sections[i].name == ".text" and
            // SHF_WRITE (0x1) enabled
            elf.sections[i].flags & 0x1 != 0
        )
}

/* ============================================================
 *  Stripped binaries
 * ============================================================ */

rule ELF_Stripped
{
    meta:
        description = "ELF binary without .symtab (stripped of debug symbols)"
        category    = "protection"
        chapter     = "19"
        note        = "Stripping removes .symtab and .strtab but preserves .dynsym"

    condition:
        uint32(0) == 0x464C457F and
        // No section named .symtab
        not for any i in (0..elf.number_of_sections - 1) : (
            elf.sections[i].name == ".symtab"
        )
}

rule ELF_Stripped_No_Debug
{
    meta:
        description = "ELF binary stripped AND without DWARF debug info"
        category    = "protection"
        chapter     = "19"

    strings:
        $debug_info = ".debug_info"
        $debug_abbrev = ".debug_abbrev"
        $debug_line = ".debug_line"

    condition:
        uint32(0) == 0x464C457F and
        not for any i in (0..elf.number_of_sections - 1) : (
            elf.sections[i].name == ".symtab"
        ) and
        not $debug_info and
        not $debug_abbrev and
        not $debug_line
}

/* ============================================================
 *  Anti-debugging techniques
 * ============================================================ */

rule Anti_Debug_Ptrace_Self
{
    meta:
        description = "Binary may use ptrace(PTRACE_TRACEME) as anti-debugging technique"
        category    = "anti_debug"
        chapter     = "19"
        technique   = "ptrace self-attach"
        reference   = "Section 19.7 — Debugger detection techniques"

    strings:
        // ptrace is syscall #101 on x86-64
        // PTRACE_TRACEME = 0
        //
        // Pattern 1: call via libc (call ptrace@plt)
        // We look for "ptrace" string in .dynstr (dynamic import)
        $ptrace_import = "ptrace"

        // Pattern 2: direct syscall invocation
        // mov rax, 101 (0x65) ; ... ; syscall
        $syscall_ptrace_a = { 48 C7 C0 65 00 00 00 }   // mov rax, 0x65
        $syscall_ptrace_b = { B8 65 00 00 00 }          // mov eax, 0x65

        // PTRACE_TRACEME = 0 in rdi (first argument)
        $traceme_rdi = { 48 31 FF }     // xor rdi, rdi (= 0)
        $traceme_rdi2 = { BF 00 00 00 00 }  // mov edi, 0

    condition:
        uint32(0) == 0x464C457F and
        (
            // ptrace import (usage via libc)
            $ptrace_import or
            // Direct syscall with PTRACE_TRACEME
            (1 of ($syscall_ptrace_a, $syscall_ptrace_b) and
             1 of ($traceme_rdi, $traceme_rdi2))
        )
}

rule Anti_Debug_Proc_Status
{
    meta:
        description = "Binary reads /proc/self/status (TracerPid detection)"
        category    = "anti_debug"
        chapter     = "19"
        technique   = "TracerPid check via procfs"

    strings:
        $proc_status  = "/proc/self/status"
        $tracer_pid   = "TracerPid"
        $proc_self_fd = "/proc/self/fd"

    condition:
        uint32(0) == 0x464C457F and
        ($proc_status or $tracer_pid)
}

rule Anti_Debug_Timing_Check
{
    meta:
        description = "Binary may use timing-based anti-debugging (rdtsc or clock_gettime)"
        category    = "anti_debug"
        chapter     = "19"
        technique   = "Timing check"

    strings:
        // RDTSC instruction (0F 31) — reads the timestamp counter
        $rdtsc = { 0F 31 }

        // RDTSCP instruction (0F 01 F9) — serializing variant
        $rdtscp = { 0F 01 F9 }

        // clock_gettime import (libc alternative)
        $clock_gettime = "clock_gettime"

    condition:
        uint32(0) == 0x464C457F and
        (
            // At least 2 occurrences of RDTSC (before and after measured code)
            (#rdtsc >= 2) or
            (#rdtscp >= 2) or
            // clock_gettime imported (can be legitimate, but worth investigating)
            $clock_gettime
        )
}

rule Anti_Debug_Int3_Scanning
{
    meta:
        description = "Binary may scan for software breakpoints (INT3 = 0xCC)"
        category    = "anti_debug"
        chapter     = "19"
        technique   = "Breakpoint detection via memory scanning"
        reference   = "Section 19.8 — Breakpoint countermeasures"

    strings:
        // Comparison with 0xCC (INT3) — often via: cmp byte [reg], 0xCC
        $cmp_cc_a = { 80 38 CC }    // cmp byte [rax], 0xCC
        $cmp_cc_b = { 80 39 CC }    // cmp byte [rcx], 0xCC
        $cmp_cc_c = { 80 3B CC }    // cmp byte [rbx], 0xCC
        $cmp_cc_d = { 3C CC }       // cmp al, 0xCC

        // Searching for 0xCC in a buffer (movzx + cmp pattern)
        $scan_loop = { 0F B6 ?? 3D CC 00 00 00 }  // movzx + cmp eax, 0xCC

    condition:
        uint32(0) == 0x464C457F and
        2 of ($cmp_cc_a, $cmp_cc_b, $cmp_cc_c, $cmp_cc_d, $scan_loop)
}

/* ============================================================
 *  Control flow obfuscation
 * ============================================================ */

rule OLLVM_Control_Flow_Flattening
{
    meta:
        description = "Potential OLLVM/Hikari control flow flattening (dispatcher pattern)"
        category    = "obfuscation"
        chapter     = "19"
        technique   = "Control Flow Flattening (CFF)"
        note        = "Heuristic: large switch in a loop = CFF dispatcher"

    strings:
        // Typical CFF pattern: a large number of cases in a switch
        // manifests as many consecutive cmp + je comparisons
        //   cmp eax, IMM32 ; je TARGET
        // repeated many times

        // cmp eax, imm32 ; je rel32
        $cmp_je = { 3D ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? }

        // Variant: cmp edx, imm32 ; je rel32
        $cmp_je_edx = { 81 FA ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? }

    condition:
        uint32(0) == 0x464C457F and
        // A CFF dispatcher produces dozens of these consecutive patterns
        (#cmp_je > 20 or #cmp_je_edx > 20)
}

rule Bogus_Control_Flow
{
    meta:
        description = "Potential bogus control flow (opaque predicates)"
        category    = "obfuscation"
        chapter     = "19"
        technique   = "Bogus Control Flow / Opaque Predicates"

    strings:
        // Classic OLLVM opaque predicates:
        // x * (x - 1) is always even => test with AND 1
        // Manifests as sequences: imul + dec + and + test + jz/jnz
        // on global values read from .bss/.data

        // Repeated access to same global address followed by computation + jump
        // Simplified pattern: mov reg, [rip+disp] ; ... ; test ; jz
        $opaque_load = { 8B 05 ?? ?? ?? ?? }    // mov eax, [rip+disp32]

        // Constant comparison that is always true/false
        $always_true  = { 83 F8 00 74 }         // cmp eax, 0 ; jz (after opaque computation)
        $always_false = { 83 F8 01 75 }          // cmp eax, 1 ; jnz

    condition:
        uint32(0) == 0x464C457F and
        #opaque_load > 30 and
        (1 of ($always_true, $always_false))
}

/* ============================================================
 *  Training-specific markers: formats and binaries
 * ============================================================ */

rule CFR_Format_Handler
{
    meta:
        description = "Binary that reads or writes CFR archives (Chapter 25)"
        category    = "training"
        chapter     = "25"

    strings:
        // CFR format magics
        $hdr_magic = "CFRM"
        $ftr_magic = "CRFE"

        // XOR key used for data obfuscation
        $xor_key = { 5A 3C 96 F1 }

        // Command names in the code
        $cmd_generate = "generate"
        $cmd_pack     = "pack"
        $cmd_validate = "validate"
        $cmd_unpack   = "unpack"

    condition:
        uint32(0) == 0x464C457F and
        $hdr_magic and $ftr_magic and
        (2 of ($cmd_generate, $cmd_pack, $cmd_validate, $cmd_unpack))
}

rule CFR_Archive_File
{
    meta:
        description = "CFR archive file (Custom Format Records, Chapter 25)"
        category    = "training"
        chapter     = "25"
        filetype    = "data"

    strings:
        $hdr_magic = "CFRM"
        $ftr_magic = "CRFE"

    condition:
        // Header magic at the beginning, version 2
        $hdr_magic at 0 and
        uint16(4) == 0x0002 and
        // Check that record count is reasonable (< 1024)
        uint32(8) > 0 and uint32(8) < 1024 and
        // Footer magic somewhere at the end
        (filesize > 44 and $ftr_magic in (filesize - 12 .. filesize))
}

/* ============================================================
 *  Compilation protection detection (GCC hardening)
 * ============================================================ */

rule ELF_Has_Stack_Canary
{
    meta:
        description = "ELF binary compiled with -fstack-protector (imports __stack_chk_fail)"
        category    = "protection"
        chapter     = "19"

    strings:
        $canary_func = "__stack_chk_fail"

    condition:
        uint32(0) == 0x464C457F and
        $canary_func
}

rule ELF_Full_RELRO
{
    meta:
        description = "ELF binary with Full RELRO (GOT is read-only after relocation)"
        category    = "protection"
        chapter     = "19"
        note        = "Checks for PT_GNU_RELRO segment + DT_BIND_NOW tag (x86-64)"

    strings:
        // DT_BIND_NOW: Elf64_Dyn with d_tag = 24 (0x18), d_val = 0
        // 16 bytes: tag (8 LE) + value (8 LE)
        $dt_bind_now_64 = { 18 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        uint32(0) == 0x464C457F and
        elf.machine == elf.EM_X86_64 and
        // PT_GNU_RELRO segment present
        for any i in (0..elf.number_of_segments - 1) : (
            elf.segments[i].type == elf.PT_GNU_RELRO
        ) and
        // DT_BIND_NOW tag in .dynamic
        $dt_bind_now_64
}

rule ELF_PIE_Executable
{
    meta:
        description = "Position-Independent Executable (PIE)"
        category    = "protection"
        chapter     = "19"

    condition:
        // A PIE has type ET_DYN (3) but is an executable
        uint32(0) == 0x464C457F and
        elf.type == elf.ET_DYN and
        // Distinguish PIE from a shared library: presence of an interpreter
        for any i in (0..elf.number_of_segments - 1) : (
            elf.segments[i].type == elf.PT_INTERP
        )
}

/* ============================================================
 *  Composite rule: suspicious binary (accumulated indicators)
 * ============================================================ */

rule Suspicious_ELF_Binary
{
    meta:
        description = "ELF binary with multiple suspicious characteristics"
        category    = "triage"
        note        = "Combines multiple heuristics — investigate manually"

    condition:
        uint32(0) == 0x464C457F and
        (
            // Packed or obfuscated
            (UPX_Packed_ELF or ELF_Writable_Text or OLLVM_Control_Flow_Flattening)
            or
            // Anti-debug + stripped
            (ELF_Stripped and
             (Anti_Debug_Ptrace_Self or Anti_Debug_Proc_Status or Anti_Debug_Int3_Scanning))
            or
            // Packed + anti-debug
            (UPX_Packed_ELF and Anti_Debug_Ptrace_Self)
        )
}
