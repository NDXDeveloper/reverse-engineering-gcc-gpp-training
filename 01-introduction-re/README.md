🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 1 — Introduction to Reverse Engineering

> **Part I — Fundamentals & Environment**  
> 📦 No specific technical prerequisites — this chapter is accessible to all profiles targeted by this training.

---

## Why this chapter?

Before opening a disassembler or setting a breakpoint, it is essential to understand what reverse engineering is, why we practice it, and in what framework we are allowed to do it. This chapter lays the conceptual, methodological, and ethical foundations on which the entire training rests.

Too many tutorials plunge straight into tools without taking the time to define the objectives or the scope. The result is often an accumulation of technical recipes with no big-picture view, and above all no awareness of the legal limits. This chapter corrects that from the start.

---

## What you will learn

This chapter covers six themes which, taken together, will give you a clear vision of the discipline before entering the practical work:

**Definition and objectives of RE** — What is reverse engineering applied to software? How does it differ from simple debugging? What are the concrete objectives an analyst pursues when facing an unknown binary?

**Legal and ethical framework** — RE touches on intellectual property and computer law. We will examine the laws that govern it (CFAA in the United States, EUCD directive in Europe, DMCA) and the gray areas in which it is easy to find oneself unintentionally. This section is not a law course, but it will give you the essential landmarks to practice legally.

**Legitimate use cases** — Reverse engineering is not a marginal activity reserved for hackers. It is practiced daily by professionals in perfectly legal contexts: commissioned security auditing, CTF competitions, advanced debugging when source code is unavailable, interoperability between systems, and vulnerability research. We will review these use cases to anchor the training in concrete and legitimate scenarios.

**Static vs dynamic analysis** — RE rests on two complementary approaches. Static analysis consists of examining a binary without executing it (disassembly, decompilation, hexadecimal inspection). Dynamic analysis consists of observing the program during its execution (debugging, instrumentation, tracing). Understanding the distinction between these two families of techniques — and above all their complementarity — is fundamental to structuring any analysis effort.

**Overview of the methodology and tools** — We will present the general workflow that this training teaches, from first contact with an unknown binary to the reconstruction of its internal logic. You will discover the list of tools used throughout the tutorial and their place in this workflow, without going into installation details (that will be the subject of Chapter 4).

**Target taxonomy** — The term "reverse engineering" covers a very broad spectrum: native binaries (ELF, PE, Mach-O), managed bytecode (.NET CIL, JVM), embedded firmware, network protocols, file formats… This training focuses on **native ELF binaries compiled with the GNU toolchain** under Linux x86-64. We will situate this scope within the global RE landscape so that you know exactly what this tutorial covers — and what it does not (or covers only partially in the bonus parts).

---

## Chapter outline

- 1.1 — [Definition and objectives of RE](/01-introduction-re/01-definition-objectives.md)  
- 1.2 — [Legal and ethical framework (licenses, CFAA / EUCD / DMCA laws)](/01-introduction-re/02-legal-ethical-framework.md)  
- 1.3 — [Legitimate use cases: security auditing, CTF, advanced debugging, interoperability](/01-introduction-re/03-legitimate-use-cases.md)  
- 1.4 — [Difference between static RE and dynamic RE](/01-introduction-re/04-static-vs-dynamic.md)  
- 1.5 — [Overview of the methodology and tools used in this tutorial](/01-introduction-re/05-methodology-tools.md)  
- 1.6 — [Target taxonomy: native binary, bytecode, firmware — where this tutorial fits](/01-introduction-re/06-target-taxonomy.md)  
- 🎯 — [Checkpoint: classify 5 given scenarios as "static" or "dynamic"](/01-introduction-re/checkpoint.md)

---

## Estimated time

Count roughly **1 h to 1 h 30** to go through the entire chapter, checkpoint included. This is a chapter of reading and reflection — no tool to install, no binary to handle. The goal is for you to approach Chapter 2 with a clear understanding of what RE is, what you are allowed to do, and the overall approach you will follow.

---

> 💡 **If you are already familiar with RE** and know the legal framework, you can skim this chapter and go directly to the checkpoint to verify your knowledge. If the checkpoint poses no difficulty, move straight on to Chapter 2.

⏭️ [Definition and objectives of RE](/01-introduction-re/01-definition-objectives.md)
