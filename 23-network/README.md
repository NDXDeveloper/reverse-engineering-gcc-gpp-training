🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# Chapter 23 — Reversing a Network Binary (Client/Server)

> 📦 **Chapter binaries**: `binaries/ch23-network/`  
> The directory contains a client and a server compiled at multiple optimization levels (`-O0`, `-O2`, `-O3`) with and without symbols. Recompilable via `make` with the dedicated `Makefile`.  
> 📝 **ImHex patterns**: `hexpat/ch23_protocol.hexpat`

---

## Chapter objectives

Reverse engineering a network binary adds a dimension that purely local programs lack: the **communication protocol**. When analyzing a keygenme or a crypto binary, all the logic is contained within a single executable. Here, the logic is **split between two processes** — a client and a server — that exchange data in a format unknown in advance.

The objective of this chapter is to learn how to reconstruct a proprietary network protocol from binaries alone, without access to the source code, then write a replacement client capable of communicating with the original server.

By the end of this chapter, you will be able to:

- **Identify network system calls** (`socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`, `close`) in a binary, and understand the connection establishment sequence.  
- **Capture and dissect traffic** between client and server using `strace` on the system side and Wireshark on the network side, to get a first view of the protocol.  
- **Reconstruct the packet parser's state machine**: identify magic bytes, length fields, command types, handshake sequences, and response codes.  
- **Visualize binary frames with ImHex** and formalize the protocol structure by writing a reusable `.hexpat` pattern.  
- **Replay a captured communication** (replay attack) to validate your understanding of the protocol and observe the server's reaction.  
- **Write a complete replacement client** in Python with `pwntools`, capable of reproducing the handshake, authentication, and command exchange with the server.

---

## Context: the `ch23-network` binary

This chapter's training binary simulates a realistic scenario: a **server** listens on a TCP port and awaits connections from **clients** that must authenticate then send commands via a custom binary protocol.

The protocol is documented nowhere. It uses:

- A **magic byte** at the head of each packet to identify the start of a valid frame.  
- A **type field** that distinguishes different commands (handshake, authentication, data request, response, error).  
- A **length field** that indicates the size of the following payload.  
- A **payload** whose format varies depending on the command type.  
- An **initial handshake** mechanism before any operation.

This type of architecture is frequently found in industrial software, proprietary IoT protocols, online games, and network implants analyzed in forensics.

---

## Why network RE is different

### Two binaries, one logic

Unlike a standalone binary, a network program does nothing interesting by itself. The client sends data that the server interprets, and vice versa. The reverse engineer must therefore **analyze both sides** to understand the complete protocol. In practice, you often start with the side you have (sometimes you only have the client, sometimes only the server) and infer the rest.

### Traffic observation as entry point

Before even disassembling anything, you can learn a great deal by **observing the network traffic**. Running the client and server on the same machine while capturing exchanges with Wireshark or `tcpdump` immediately gives an idea of message sizes, their frequency, the presence of recurring patterns (magic bytes, fixed headers), and the protocol's nature (request/response, streaming, multiplexed...).

### `strace` reveals the call structure

Where Wireshark shows raw data on the network, `strace` shows **how the program manipulates this data on the system side**. You see the `send()` and `recv()` calls with their buffers, sizes, and you can correlate each network packet to the system call that produced it. This dual vision — network and system — is the key to reconstructing the protocol quickly.

### The parser is the primary target

In a network binary, the most interesting function is almost always the **packet parser**: the routine that reads incoming bytes, checks magic bytes, extracts the type and length, then dispatches to the appropriate handler. This state machine is what must be reconstructed first. Once the parser is understood, the rest of the protocol follows naturally.

---

## Tools used in this chapter

This chapter synthesizes many tools seen in previous parts, applied to the network context:

| Tool | Usage in this chapter |  
|---|---|  
| `strace` | Tracing network system calls (`socket`, `connect`, `send`, `recv`...) |  
| Wireshark / `tcpdump` | Capturing and analyzing network traffic between client and server |  
| `strings`, `readelf`, `checksec` | Initial triage of client and server binaries |  
| Ghidra | Disassembly and decompilation of the packet parser and protocol logic |  
| ImHex | Hexadecimal visualization of captured frames, writing a `.hexpat` for the protocol |  
| GDB (+ GEF/pwndbg) | Dynamic analysis, breakpoints on `send`/`recv`, buffer inspection in memory |  
| `pwntools` | Writing the replacement client in Python |

---

## General methodology

The approach followed in this chapter breaks down into five phases corresponding to the five sections:

1. **Observe** — Run the binaries, capture traffic with `strace` and Wireshark, note patterns visible to the naked eye (section 23.1).  
2. **Understand** — Disassemble the packet parser in Ghidra, reconstruct the state machine and the format of each message type (section 23.2).  
3. **Formalize** — Write a `.hexpat` pattern in ImHex that visually decodes captured frames, confirming or correcting the static analysis (section 23.3).  
4. **Validate** — Replay a network capture to the server to verify that the protocol understanding is correct (section 23.4).  
5. **Reproduce** — Write a standalone Python client capable of communicating with the server without the original client (section 23.5).

Each phase feeds the next: observation guides disassembly, disassembly guides formalization, formalization is validated by replay, and everything culminates in writing the client.

---

## Prerequisites

Before tackling this chapter, make sure you are comfortable with:

- **Chapter 5** — Basic inspection tools (`strace`, `strings`, `readelf`, `checksec`), as they constitute the triage starting point.  
- **Chapter 6** — ImHex and the `.hexpat` language, essential for section 23.3.  
- **Chapter 8** — Ghidra, used intensively to reconstruct the packet parser.  
- **Chapter 11** — GDB, for setting breakpoints on network functions and inspecting buffers.  
- **Chapter 11, section 11.9** — `pwntools`, used to write the final client.  
- **Basic networking concepts**: TCP client/server model, socket concept, what `bind`, `listen`, `accept`, `connect` do. Being a network expert is not necessary, but you need to understand the lifecycle of a TCP connection.

---

## Chapter outline

- **23.1** — [Identifying the custom protocol with `strace` + Wireshark](/23-network/01-identifying-protocol.md)  
- **23.2** — [RE of the packet parser (state machine, fields, magic bytes)](/23-network/02-re-packet-parser.md)  
- **23.3** — [Visualizing binary frames with ImHex and writing a `.hexpat` for the protocol](/23-network/03-frames-imhex-hexpat.md)  
- **23.4** — [Replay Attack: replaying a captured request](/23-network/04-replay-attack.md)  
- **23.5** — [Writing a complete replacement client with `pwntools`](/23-network/05-client-pwntools.md)  
- **🎯 Checkpoint** — [Write a Python client capable of authenticating to the server without knowing the source code](/23-network/checkpoint.md)

⏭️ [Identifying the custom protocol with `strace` + Wireshark](/23-network/01-identifying-protocol.md)
