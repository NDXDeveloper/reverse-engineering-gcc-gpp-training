/**
 * solutions/ch13-checkpoint-solution.js
 *
 * Frida Agent — Chapter 13 Checkpoint
 * Logs all calls to send() with their buffers,
 * and intercepts connect() to contextualize connections.
 *
 * CLI usage:
 *   frida -f ./client_O0 -l ch13-checkpoint-solution.js --no-pause
 *
 * Python usage:
 *   See ch13-checkpoint-solution.py (orchestration client)
 */
'use strict';

// ═══════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════

const CONFIG = {
    // Filter by file descriptor (-1 = disabled, capture everything)
    filterFd: -1,

    // Maximum size of hexdump displayed in console
    hexdumpMaxBytes: 128,

    // Also hook write() on known socket fds
    hookWrite: true,
};

// ═══════════════════════════════════════════════════════════
// GLOBAL STATE
// ═══════════════════════════════════════════════════════════

const startTime = Date.now();
let sequenceNumber = 0;

// Known connections table: fd → { ip, port }
const connections = new Map();

// Known socket fds table (to filter write() on sockets)
const knownSocketFds = new Set();

// ═══════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════

/**
 * Returns the number of milliseconds elapsed since
 * tracing started.
 */
function elapsed() {
    return Date.now() - startTime;
}

/**
 * Parses a sockaddr_in structure pointed to by `addrPtr`.
 * Returns { family, ip, port } or null if the family
 * is not AF_INET (2).
 */
function parseSockaddrIn(addrPtr) {
    try {
        const family = addrPtr.readU16();
        if (family !== 2) {  // AF_INET
            return { family, ip: null, port: null };
        }

        // sin_port: 2 bytes in network byte order (big-endian)
        const portHi = addrPtr.add(2).readU8();
        const portLo = addrPtr.add(3).readU8();
        const port = (portHi << 8) | portLo;

        // sin_addr: 4 bytes
        const ip = [
            addrPtr.add(4).readU8(),
            addrPtr.add(5).readU8(),
            addrPtr.add(6).readU8(),
            addrPtr.add(7).readU8()
        ].join('.');

        return { family, ip, port };
    } catch (e) {
        return null;
    }
}

/**
 * Checks if a fd should be logged according to the
 * filter configuration.
 */
function shouldLog(fd) {
    if (CONFIG.filterFd === -1) return true;
    return fd === CONFIG.filterFd;
}

// ═══════════════════════════════════════════════════════════
// HOOK: connect()
// ═══════════════════════════════════════════════════════════

Interceptor.attach(Module.findExportByName(null, "connect"), {
    onEnter(args) {
        try {
            this.fd = args[0].toInt32();
            this.addr = parseSockaddrIn(args[1]);
        } catch (e) {
            this.addr = null;
        }
    },
    onLeave(retval) {
        try {
            const result = retval.toInt32();

            if (this.addr && this.addr.ip) {
                // Record the connection
                connections.set(this.fd, {
                    ip: this.addr.ip,
                    port: this.addr.port
                });
                knownSocketFds.add(this.fd);

                const status = result === 0 ? 'OK' : `ERROR (${result})`;
                const msg = `[CONNECT] fd ${this.fd} → ${this.addr.ip}:${this.addr.port} — ${status}`;
                console.log(`\n${msg}`);

                send({
                    event: 'connect',
                    timestamp_ms: elapsed(),
                    fd: this.fd,
                    ip: this.addr.ip,
                    port: this.addr.port,
                    result: result
                });
            } else if (this.addr) {
                // Non AF_INET family (AF_UNIX, AF_INET6...)
                console.log(`[CONNECT] fd ${this.fd} — family ${this.addr.family} (non-IPv4)`);
            }
        } catch (e) {
            console.log(`[!] Error in connect/onLeave: ${e.message}`);
        }
    }
});

// ═══════════════════════════════════════════════════════════
// HOOK: send()
// ═══════════════════════════════════════════════════════════

Interceptor.attach(Module.findExportByName(null, "send"), {
    onEnter(args) {
        try {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.len = args[2].toInt32();
            this.flags = args[3].toInt32();
            this.shouldLog = shouldLog(this.fd);
        } catch (e) {
            this.shouldLog = false;
            console.log(`[!] Error in send/onEnter: ${e.message}`);
        }
    },
    onLeave(retval) {
        if (!this.shouldLog) return;

        try {
            const bytesSent = retval.toInt32();

            // Increment sequence number
            sequenceNumber++;
            const seq = sequenceNumber;
            const ts = elapsed();

            // Prepare metadata
            const conn = connections.get(this.fd);
            const meta = {
                event: 'send',
                seq: seq,
                timestamp_ms: ts,
                fd: this.fd,
                requested_len: this.len,
                bytes_sent: bytesSent,
                flags: this.flags,
                dest_ip: conn ? conn.ip : null,
                dest_port: conn ? conn.port : null,
            };

            // If send() failed, log the error but don't read the buffer
            if (bytesSent < 0) {
                console.log(`\n[SEND #${seq}] fd ${this.fd} — ERROR (return ${bytesSent})`);
                send(meta);
                return;
            }

            // Read the buffer: at most len bytes, at most bytesSent
            const readSize = Math.min(this.len, bytesSent);
            const bufferData = this.buf.readByteArray(readSize);

            // Console display
            const destStr = conn ? ` → ${conn.ip}:${conn.port}` : '';
            console.log(`\n[SEND #${seq}] +${ts}ms | fd ${this.fd}${destStr} | ${bytesSent}/${this.len} bytes`);
            console.log(hexdump(this.buf, {
                length: Math.min(readSize, CONFIG.hexdumpMaxBytes)
            }));

            // Send to Python: JSON + raw binary buffer
            send(meta, bufferData);

        } catch (e) {
            console.log(`[!] Error in send/onLeave: ${e.message}`);
        }
    }
});

// ═══════════════════════════════════════════════════════════
// OPTIONAL HOOK: write() (for sockets)
// ═══════════════════════════════════════════════════════════

if (CONFIG.hookWrite) {
    Interceptor.attach(Module.findExportByName(null, "write"), {
        onEnter(args) {
            try {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.len = args[2].toInt32();
                // Only log write() on known socket fds
                this.shouldLog = knownSocketFds.has(this.fd) && shouldLog(this.fd);
            } catch (e) {
                this.shouldLog = false;
            }
        },
        onLeave(retval) {
            if (!this.shouldLog) return;

            try {
                const bytesWritten = retval.toInt32();
                if (bytesWritten < 0) return;

                sequenceNumber++;
                const seq = sequenceNumber;
                const ts = elapsed();
                const readSize = Math.min(this.len, bytesWritten);
                const bufferData = this.buf.readByteArray(readSize);

                const conn = connections.get(this.fd);
                const destStr = conn ? ` → ${conn.ip}:${conn.port}` : '';

                console.log(`\n[WRITE #${seq}] +${ts}ms | fd ${this.fd}${destStr} | ${bytesWritten}/${this.len} bytes`);
                console.log(hexdump(this.buf, {
                    length: Math.min(readSize, CONFIG.hexdumpMaxBytes)
                }));

                send({
                    event: 'write',
                    seq: seq,
                    timestamp_ms: ts,
                    fd: this.fd,
                    requested_len: this.len,
                    bytes_sent: bytesWritten,
                    flags: 0,
                    dest_ip: conn ? conn.ip : null,
                    dest_port: conn ? conn.port : null,
                }, bufferData);

            } catch (e) {
                console.log(`[!] Error in write/onLeave: ${e.message}`);
            }
        }
    });
}

// ═══════════════════════════════════════════════════════════
// HOOK: close() — clean up tracking tables
// ═══════════════════════════════════════════════════════════

Interceptor.attach(Module.findExportByName(null, "close"), {
    onEnter(args) {
        try {
            const fd = args[0].toInt32();
            if (connections.has(fd)) {
                const conn = connections.get(fd);
                console.log(`\n[CLOSE] fd ${fd} (${conn.ip}:${conn.port})`);
                send({
                    event: 'close',
                    timestamp_ms: elapsed(),
                    fd: fd,
                    ip: conn.ip,
                    port: conn.port
                });
                connections.delete(fd);
                knownSocketFds.delete(fd);
            }
        } catch (e) {
            // Silently ignore — close() is called very frequently
        }
    }
});

// ═══════════════════════════════════════════════════════════
// STARTUP MESSAGE
// ═══════════════════════════════════════════════════════════

console.log('═══════════════════════════════════════════════');
console.log('  Frida send() logger — Checkpoint Ch.13');
console.log(`  fd filter: ${CONFIG.filterFd === -1 ? 'disabled (capture all)' : 'fd ' + CONFIG.filterFd}`);
console.log(`  Hook write(): ${CONFIG.hookWrite ? 'yes' : 'no'}`);
console.log('  Ctrl+C to stop');
console.log('═══════════════════════════════════════════════\n');
