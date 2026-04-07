🔝 Back to [Table of Contents](/TABLE-OF-CONTENTS.md)

# 23.3 — Visualizing Binary Frames with ImHex and Writing a `.hexpat` for the Protocol

> 🎯 **Objective of this section**: leverage the network captures from section 23.1 and the specification reconstructed in section 23.2 to write a `.hexpat` pattern capable of automatically decoding the custom protocol's frames in ImHex. By the end of this section, you will have a `ch23_protocol.hexpat` file that colorizes and annotates every field of every message, transforming a raw byte stream into a structured reading of the protocol.

---

## Why ImHex at This Stage

We now have two complementary sources of information:

- The **network captures** (`.pcap` file or raw export from Wireshark) that contain the actual data exchanged between client and server.  
- The **protocol specification** reconstructed through disassembly, which describes the expected format of each field.

ImHex bridges the two. By writing a `.hexpat` pattern, we apply the specification to real data and **visually verify** that each byte falls in the right place. If a field is misaligned or a length is inconsistent, the colorization reveals it immediately. It is a powerful validation tool: an error in the specification that would go unnoticed when reading pseudo-code becomes obvious when the colors do not match the data.

Beyond validation, the `.hexpat` is also a **reusable deliverable**. It can be used to decode new captures without reopening Ghidra, to train other analysts on the protocol, or to debug the replacement client we will write in section 23.5.

---

## Preparing the Data for Analysis

### Exporting the Raw TCP Stream from Wireshark

ImHex works on raw binary files. We therefore need to extract the application payload from the `.pcap` capture, removing the Ethernet, IP, and TCP headers.

In Wireshark:

1. Open `ch23_capture.pcap`.  
2. Apply the filter `tcp.port == 4444 && tcp.len > 0`.  
3. Right-click on the first packet of the conversation → **Follow → TCP Stream**.  
4. In the window that opens, choose **Show data as: Raw**.  
5. Click **Save as…** → save as `ch23_stream.bin`.

This file contains the entire reassembled TCP stream: all client and server messages concatenated in order, without the network headers. This is exactly what the server's parser sees after the TCP layer.

> ⚠️ **Warning**: Wireshark's "Follow TCP Stream" concatenates both directions into a single stream. By default, it alternates client data (in red) and server data (in blue) in the text view, but the raw export mixes them together. For a clean `.hexpat`, it is often preferable to export **each direction separately** using the directional filter in the Follow Stream window (radio button "Client → Server" then "Server → Client") and save two separate files. You can also export the full stream and handle the alternation in the pattern — this is more complex but more realistic.

### Alternative: Recording from `strace`

If we traced the exchanges with `strace -x -s 1024`, we can extract the buffers manually. This is tedious but useful when no Wireshark capture is available. A small Python script does the job:

```python
import re, sys

with open(sys.argv[1]) as f:
    for line in f:
        # Look for write() or send() lines with hex data
        m = re.search(r'(?:write|send)\(\d+, "(.*?)", \d+\)', line)
        if m:
            raw = m.group(1)
            # Convert \x.. sequences to bytes
            data = bytes.fromhex(
                re.sub(r'\\x([0-9a-f]{2})', r'\1',
                re.sub(r'[^\\x]|\\[^x]', '', raw) if False else
                raw.replace('\\x', ''))
            )
            sys.stdout.buffer.write(data)
```

We redirect the output into a binary file that we open in ImHex.

### Opening the File in ImHex

We launch ImHex and open `ch23_stream.bin`. The hex editor displays the raw bytes. If the export is correct, we should visually spot the magic byte `0xC0` at regular intervals — each occurrence marks the beginning of a new message.

Before writing any pattern, a quick visual scan is useful:

- **`Ctrl+F`** → search for the sequence `C0 01` to locate the HELLO Request.  
- **`Ctrl+F`** → search for `C0 81` for the HELLO Response.  
- Verify that the distances between magic bytes match the expected lengths (4-byte header + payload_len).

This scan confirms that the data is correctly aligned and ready for the pattern.

---

## Writing the `.hexpat` Pattern — Step by Step

The ImHex `.hexpat` language is designed to describe binary structures declaratively. We will build the pattern incrementally, validating each addition against real data.

### Step 1 — The Header Alone

We start with the bare minimum: decoding a single 4-byte header.

```hexpat
#pragma endian big   // the protocol uses big-endian for multi-byte fields

import std.io;

enum MsgType : u8 {
    HELLO_REQ    = 0x01,
    AUTH_REQ     = 0x02,
    CMD_REQ      = 0x03,
    QUIT_REQ     = 0x04,
    HELLO_RESP   = 0x81,
    AUTH_RESP    = 0x82,
    CMD_RESP     = 0x83,
    QUIT_RESP    = 0x84,
    ERROR        = 0xFF
};

struct ProtoHeader {
    u8      magic;
    MsgType msg_type;
    u16     payload_len;
};

ProtoHeader header @ 0x00;
```

We save this file as `ch23_protocol.hexpat` and apply it in ImHex via the **Pattern Editor** (left side panel → paste the code → click the ▶ "Evaluate" button).

Immediate result: the first 4 bytes of the file are decoded and colorized. The `magic` field appears with the value `0xC0`, the `msg_type` field displays `HELLO_REQ (0x01)` thanks to the enum, and `payload_len` shows the length in decimal. If everything matches, we move on to the next step.

> 💡 **ImHex tip**: the `#pragma endian big` pragma applies globally. If some fields were in little-endian, we could use the `le u16` type on a case-by-case basis to override it. Here, the protocol is entirely big-endian so the global pragma is sufficient.

### Step 2 — Typed Payloads

The header alone is not enough: we also need to decode the payload that follows, and its format depends on the `msg_type`. This is where the pattern gets interesting — we use the conditional capabilities of the `.hexpat` language.

```hexpat
struct LPString {
    u8   len;
    char value[len];
};

struct HelloPayload {
    char  identifier[5];    // "HELLO"
    u8    padding[parent.header.payload_len - 5];
};

struct WelcomePayload {
    char  banner[7];        // "WELCOME"
    u8    challenge[parent.header.payload_len - 7];
};

struct AuthRequestPayload {
    LPString username;
    LPString password;
};

struct AuthResponsePayload {
    u8 reserved;
    u8 status;
};

struct GenericPayload {
    u8 data[parent.header.payload_len];
};
```

Each payload structure corresponds to a message type. The `LPString` (Length-Prefixed String) structure captures the pattern identified in section 23.2: a length byte followed by the data.

The key point is the use of `parent.header.payload_len` to dynamically size the arrays. The `.hexpat` language allows referencing fields already parsed in the same structure (or the parent structure) to compute sizes on the fly.

### Step 3 — The Complete Message with Dispatch

We assemble everything into a `ProtoMessage` structure that combines the header and the appropriate payload:

```hexpat
struct ProtoMessage {
    ProtoHeader header;
    
    if (header.payload_len > 0) {
        match (header.msg_type) {
            (MsgType::HELLO_REQ):    HelloPayload        payload;
            (MsgType::HELLO_RESP):   WelcomePayload      payload;
            (MsgType::AUTH_REQ):     AuthRequestPayload   payload;
            (MsgType::AUTH_RESP):    AuthResponsePayload  payload;
            (_):                     GenericPayload       payload;
        }
    }
};
```

The `match` is the `.hexpat` equivalent of `switch`: it selects the payload structure based on the message type. The default case `(_)` uses a `GenericPayload` that reads raw bytes without interpretation — useful for types that have not been analyzed in detail yet.

> ⚠️ **Pitfall**: if the calculated size of a typed payload (for example `AuthRequestPayload`) does not match `payload_len` exactly, ImHex will display an error or a shift in the colorization. This is precisely the point of this step: any misalignment signals an error in the specification that must be corrected before going further.

### Step 4 — The Complete Message Sequence

A single `ProtoMessage` is not enough: the file contains a sequence of messages. We declare an array of messages that consumes the entire file:

```hexpat
ProtoMessage messages[while($ < std::mem::size())] @ 0x00;
```

The `[while($ < std::mem::size())]` syntax tells ImHex to keep instantiating `ProtoMessage` as long as the read cursor (`$`) has not reached the end of the file. Each message is read sequentially: the header gives the payload size, the payload is read, then the cursor advances to the next message.

If the file contains the full stream (client + server mixed together, as in a "Follow TCP Stream" export), the pattern decodes requests and responses alternately. The type-based colorization makes the conversation perfectly readable.

### Step 5 — Visualization Attributes

The `.hexpat` language allows adding color attributes and comments to enhance the visualization:

```hexpat
struct ProtoHeader {
    u8      magic       [[color("FF6B6B")]];  // red — immediate visual marker
    MsgType msg_type    [[color("4ECDC4")]];  // turquoise
    u16     payload_len [[color("45B7D1")]];  // blue
} [[format("format_header")]];

fn format_header(ProtoHeader h) {
    return std::format("Type: {} | Payload: {} bytes", h.msg_type, h.payload_len);
};
```

The `[[color(...)]]` attribute assigns an RGB hex color to each field. The `[[format(...)]]` attribute associates a formatting function that controls what is displayed in the **Data Inspector** panel and in tooltips when hovering over a header.

We can also add colors to payloads to visually distinguish requests from responses:

```hexpat
struct HelloPayload {
    char identifier[5]  [[color("A8E6CF")]];  // light green
    u8   padding[parent.header.payload_len - 5] [[color("808080")]];
};

struct AuthRequestPayload {
    LPString username [[color("FFD93D")]];    // yellow
    LPString password [[color("FF6B6B")]];    // red — draws attention to credentials
};
```

The choice of colors is not arbitrary: we use intuitive conventions. Red for sensitive data (magic byte, passwords), green for informational data, gray for padding. These conventions help immediately spot areas of interest in a large stream.

---

## The Complete Assembled Pattern

Here is the complete `.hexpat` pattern, ready to be loaded in ImHex:

```hexpat
/*!
 * ch23_protocol.hexpat
 * ImHex pattern for the ch23-network custom protocol
 * Reconstructed through reverse engineering (sections 23.1 and 23.2)
 */

#pragma endian big
#pragma pattern_limit 1024

import std.io;  
import std.mem;  

// ═══════════════════════════════════
//  Constants and enums
// ═══════════════════════════════════

#define PROTO_MAGIC 0xC0

enum MsgType : u8 {
    HELLO_REQ    = 0x01,
    AUTH_REQ     = 0x02,
    CMD_REQ      = 0x03,
    QUIT_REQ     = 0x04,
    HELLO_RESP   = 0x81,
    AUTH_RESP    = 0x82,
    CMD_RESP     = 0x83,
    QUIT_RESP    = 0x84,
    ERROR        = 0xFF
};

enum AuthStatus : u8 {
    AUTH_FAIL = 0x00,
    AUTH_OK   = 0x01
};

// ═══════════════════════════════════
//  Base structures
// ═══════════════════════════════════

struct LPString {
    u8   len                           [[color("AAAAAA")]];
    char value[len]                    [[color("FFD93D")]];
} [[format("format_lpstring")]];

fn format_lpstring(LPString s) {
    return std::format("\"{}\" ({} bytes)", s.value, s.len);
};

// ═══════════════════════════════════
//  Protocol header
// ═══════════════════════════════════

struct ProtoHeader {
    u8      magic                      [[color("FF6B6B")]];
    MsgType msg_type                   [[color("4ECDC4")]];
    u16     payload_len                [[color("45B7D1")]];
} [[static, format("format_header")]];

fn format_header(ProtoHeader h) {
    return std::format("[0x{:02X}] {} — {} bytes",
                       h.magic, h.msg_type, h.payload_len);
};

// ═══════════════════════════════════
//  Payloads by message type
// ═══════════════════════════════════

struct HelloPayload {
    char identifier[5]                 [[color("A8E6CF")]];
    
    if (parent.header.payload_len > 5) {
        u8 padding[parent.header.payload_len - 5]
                                       [[color("808080")]];
    }
};

struct WelcomePayload {
    char banner[7]                     [[color("A8E6CF")]];
    u8   challenge[parent.header.payload_len - 7]
                                       [[color("C9B1FF")]];
};

struct AuthRequestPayload {
    LPString username;
    LPString password;
};

struct AuthResponsePayload {
    u8         reserved                [[color("808080")]];
    AuthStatus status                  [[color("FF6B6B")]];
};

struct CmdRequestPayload {
    u8 command_id                      [[color("4ECDC4")]];
    
    if (parent.header.payload_len > 1) {
        u8 args[parent.header.payload_len - 1]
                                       [[color("FFD93D")]];
    }
};

struct CmdResponsePayload {
    u8 status_code                     [[color("4ECDC4")]];
    
    if (parent.header.payload_len > 1) {
        u8 data[parent.header.payload_len - 1]
                                       [[color("A8E6CF")]];
    }
};

struct GenericPayload {
    u8 data[parent.header.payload_len] [[color("CCCCCC")]];
};

// ═══════════════════════════════════
//  Complete message (header + payload)
// ═══════════════════════════════════

struct ProtoMessage {
    ProtoHeader header;
    
    // Magic byte validation
    std::assert(header.magic == PROTO_MAGIC,
                "Invalid magic byte — stream may be misaligned");
    
    if (header.payload_len > 0) {
        match (header.msg_type) {
            (MsgType::HELLO_REQ):    HelloPayload        payload;
            (MsgType::HELLO_RESP):   WelcomePayload      payload;
            (MsgType::AUTH_REQ):     AuthRequestPayload   payload;
            (MsgType::AUTH_RESP):    AuthResponsePayload  payload;
            (MsgType::CMD_REQ):      CmdRequestPayload    payload;
            (MsgType::CMD_RESP):     CmdResponsePayload   payload;
            (_):                     GenericPayload       payload;
        }
    }
} [[format("format_message")]];

fn format_message(ProtoMessage m) {
    return std::format("{} — {} bytes payload",
                       m.header.msg_type, m.header.payload_len);
};

// ═══════════════════════════════════
//  Entry point — full stream
// ═══════════════════════════════════

ProtoMessage messages[while($ < std::mem::size())] @ 0x00;
```

---

## Reading the Result in ImHex

### The Pattern Data Panel

Once the pattern is evaluated (▶ button), the **Pattern Data** panel (at the bottom or on the side) displays a hierarchical tree:

```
▼ messages [6 entries]
  ▼ [0] ProtoMessage — HELLO_REQ — 8 bytes payload
    ▼ header
        magic      = 0xC0
        msg_type   = HELLO_REQ (0x01)
        payload_len = 8
    ▼ payload (HelloPayload)
        identifier = "HELLO"
        padding    = [00 00 00]
  ▼ [1] ProtoMessage — HELLO_RESP — 15 bytes payload
    ▼ header
        magic      = 0xC0
        msg_type   = HELLO_RESP (0x81)
        payload_len = 15
    ▼ payload (WelcomePayload)
        banner    = "WELCOME"
        challenge = [A3 7B 01 F9 8C 22 D4 5E]
  ▼ [2] ProtoMessage — AUTH_REQ — 18 bytes payload
    ...
```

Each entry is clickable: clicking on a field causes ImHex to highlight the corresponding bytes in the hex view and positions the cursor at their offset. Conversely, clicking on a byte in the hex view highlights the field it belongs to in the Pattern Data panel.

### The Colorized Hex View

The most spectacular effect is the **colorization of the hex view**. Each protocol field is colored according to the `[[color(...)]]` attributes defined in the pattern. At a single glance, you can immediately see:

- The **magic bytes** in red, regularly spaced throughout the stream.  
- The **message types** in turquoise, alternating between requests (`01`, `02`, `03`...) and responses (`81`, `82`, `83`...).  
- The **lengths** in blue.  
- The **strings** (usernames, banners) in yellow.  
- The **challenge** in purple.  
- The **padding** and reserved fields in gray.

This visual rendering transforms an opaque byte stream into a structured map of the protocol. Alignment errors become obvious: if a yellow field (string) encroaches on an area that should be red (magic byte), then the specification is incorrect somewhere.

### Bookmarks for Annotation

In addition to the pattern, you can use ImHex's **Bookmarks** to annotate specific regions:

- Mark the **challenge** of each session with a bookmark named `"Session 1 — challenge"`.  
- Mark the **credentials** with a bookmark `"AUTH — admin/password"`.  
- Mark **anomalies** if certain bytes do not match the specification.

Bookmarks are saved with the ImHex project and persist between sessions — useful for documenting a long-running analysis.

---

## Pattern Debugging Techniques

Writing a `.hexpat` that works on the first try is rare. Here are the most common errors and how to diagnose them.

### Stream Misalignment

**Symptom**: the first message decodes correctly, but the second one shows an invalid magic byte.

**Probable cause**: the calculated payload size does not match the actual size. The read cursor advances too far or not far enough, and the next message is read from an incorrect offset.

**Diagnosis**: manually verify in the hex view that the first message's `payload_len` matches the actual number of bytes between the end of the header and the next `0xC0`. If the count does not match, the problem is either in the specification (misinterpreted length — reversed endianness for example) or in the stream export (missing or duplicated data).

**Fix**: if endianness is the cause, replace the pragma `#pragma endian big` with `#pragma endian little` (or vice versa) and re-evaluate. If the problem is in the export, redo the capture.

### Payload Too Short for the Structure

**Symptom**: ImHex displays an `"Array index out of range"` or `"Pattern extends past end of data"` error on a payload.

**Probable cause**: the payload structure (for example `AuthRequestPayload`) reads more bytes than `payload_len` indicates. This happens when the length-prefixed string format was misinterpreted (for example, the length byte includes or excludes the null terminator, or the length is 2 bytes instead of 1).

**Diagnosis**: temporarily replace the typed payload with a `GenericPayload` (which reads exactly `payload_len` bytes without interpretation) and examine the raw bytes to verify the actual format.

### The `match` Does Not Select the Correct Payload

**Symptom**: an AUTH message is decoded with the `GenericPayload` structure instead of `AuthRequestPayload`.

**Probable cause**: the `msg_type` value does not match any case in the `match`. Verify that the values in the `MsgType` enum correspond exactly to the bytes observed in the stream.

**Diagnosis**: temporarily add a `std::print(...)` in the pattern to display the raw type value:

```hexpat
std::print("msg_type = 0x{:02X}", header.msg_type);
```

The output appears in the ImHex console (**Console** or **Log** panel).

---

## Handling Advanced Cases

### Mixed Bidirectional Stream

If the file contains both directions of the stream (client and server) concatenated by Wireshark's "Follow TCP Stream", the pattern above works directly because each message — whether a request or a response — starts with the same magic byte and follows the same header format. The `match` on `msg_type` automatically selects the correct payload structure.

However, if you want to **visually distinguish** client messages from server messages, you can add a conditional color attribute on the `ProtoMessage` itself:

```hexpat
fn is_response(MsgType t) {
    return (u8(t) & 0x80) != 0;
};

// In ProtoMessage, after the header:
if (is_response(header.msg_type)) {
    // Server response — light blue background via automatic bookmark
    std::print("[SERVER] {} at offset 0x{:X}", header.msg_type, $);
} else {
    std::print("[CLIENT] {} at offset 0x{:X}", header.msg_type, $);
}
```

### Protocol with Length Field Including the Header

Some protocols count the total message length (header included) rather than the payload length alone. If this is the case, the payload read must be adjusted:

```hexpat
// If payload_len includes the 4-byte header:
u8 data[header.payload_len - 4];

// If payload_len is the payload length only:
u8 data[header.payload_len];
```

This is a very common source of errors. When in doubt, go back to the data: take a message whose exact content is known (the HELLO with 8 bytes of payload), check whether the length field reads `8` (payload only) or `12` (payload + 4-byte header), and adjust accordingly.

### Fragmented or Concatenated Messages

If the raw stream was exported from a capture where TCP concatenated multiple application messages into a single segment (Nagle), or conversely fragmented a message across multiple segments, Wireshark's "Follow TCP Stream" export reassembles the stream in order. But a packet-by-packet export (`File → Export Packet Bytes`) does not. You then get message fragments that do not align on protocol boundaries.

**Solution**: always use "Follow TCP Stream" for the export, never the raw export of individual packets.

---

## Validating the Pattern on Multiple Captures

A good pattern should not work on only one capture. To ensure its robustness, we test it on several scenarios:

- **Successful authentication** — the nominal case, already covered.  
- **Failed authentication** — the server returns an `AUTH_RESP` with `status = AUTH_FAIL`. The pattern must correctly decode this case (same structure, different value).  
- **Various commands** — if the protocol supports multiple command types (`CMD_REQ` with different `command_id` values), we capture a session using each type and verify the decoding.  
- **Protocol errors** — send an invalid magic byte or an unknown type and observe the error response (`MSG_ERROR = 0xFF`). The `GenericPayload` default case must absorb these cases without crashing.  
- **Multiple sessions** — concatenate several sessions in the same file (possible with `cat session1.bin session2.bin > multi.bin`) to verify that the pattern loops correctly.

Each passing test strengthens confidence in the specification. Each failing test reveals an uncovered case and enriches the pattern.

---

## Section Summary

| Step | Action | Result |  
|------|--------|--------|  
| Prepare the data | "Follow TCP Stream" export from Wireshark in raw | `.bin` file containing the raw application stream |  
| Header alone | `ProtoHeader` with magic, type, length | Validation of the first 4 bytes in the stream |  
| Typed payloads | Structures per message type + `match` | Complete decoding of each message |  
| Complete sequence | `messages[while(...)]` array | Entire stream decoded at once |  
| Visual attributes | `[[color(...)]]` + `[[format(...)]]` | Readable colorization and annotations |  
| Validation | Tests on various captures (success, failure, errors) | Confidence in the protocol specification |

The `.hexpat` pattern produced in this section is a **permanent artifact** of the analysis. It encodes the protocol knowledge in an executable and visually verifiable form. In the next section (**23.4**), we will move from passive to active by replaying a captured communication to the real server to test our hypotheses under dynamic conditions.

⏭️ [Replay Attack: Replaying a Captured Request](/23-network/04-replay-attack.md)
