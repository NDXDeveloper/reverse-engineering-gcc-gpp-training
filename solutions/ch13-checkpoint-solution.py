#!/usr/bin/env python3
"""
solutions/ch13-checkpoint-solution.py

Python Orchestration Client — Chapter 13 Checkpoint
Spawns the target binary, loads the Frida agent, collects
send() calls and exports results to capture.json and capture.bin.

Usage:
    python3 ch13-checkpoint-solution.py ./binaries/ch13-network/client_O0

    # With arguments for the target binary:
    python3 ch13-checkpoint-solution.py ./binaries/ch13-network/client_O0 -- 127.0.0.1 4444

    # With filtering on a specific file descriptor:
    python3 ch13-checkpoint-solution.py ./binaries/ch13-network/client_O0 --filter-fd 3
"""
import frida
import sys
import os
import json
import time
import argparse
from pathlib import Path

# ═══════════════════════════════════════════════════════════
# CONFIGURATION AND ARGUMENTS
# ═══════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="Frida send() logger — Checkpoint Ch.13"
    )
    parser.add_argument(
        "binary",
        help="Path to the target binary"
    )
    parser.add_argument(
        "binary_args",
        nargs="*",
        help="Arguments to pass to the target binary"
    )
    parser.add_argument(
        "--filter-fd", type=int, default=-1,
        help="Only log this file descriptor (-1 = all)"
    )
    parser.add_argument(
        "--output-dir", type=str, default=".",
        help="Output directory for capture.json and capture.bin"
    )
    parser.add_argument(
        "--no-write-hook", action="store_true",
        help="Disable the write() hook"
    )
    return parser.parse_args()


# ═══════════════════════════════════════════════════════════
# MAIN CLASS
# ═══════════════════════════════════════════════════════════

class SendLogger:
    """Orchestrates the Frida session and collects results."""

    def __init__(self, binary, binary_args, filter_fd, output_dir, hook_write):
        self.binary = binary
        self.binary_args = binary_args
        self.filter_fd = filter_fd
        self.output_dir = Path(output_dir)
        self.hook_write = hook_write

        # Collected data
        self.events = []        # JSON metadata of each call
        self.buffers = []       # raw binary buffers (bytes)
        self.total_bytes = 0    # total bytes captured

        # Session state
        self.session = None
        self.script = None
        self.pid = None
        self.running = True

    def load_agent(self):
        """Loads the agent JavaScript code from the file."""
        agent_path = Path(__file__).parent / "ch13-checkpoint-solution.js"
        if not agent_path.exists():
            # Fallback: look next to the binary or in the CWD
            agent_path = Path("ch13-checkpoint-solution.js")
        if not agent_path.exists():
            print(f"[!] JS agent not found. Searched in:")
            print(f"    - {Path(__file__).parent / 'ch13-checkpoint-solution.js'}")
            print(f"    - {Path('ch13-checkpoint-solution.js').resolve()}")
            sys.exit(1)

        code = agent_path.read_text(encoding="utf-8")

        # Inject configuration into the agent code
        # (replace CONFIG default values)
        code = code.replace(
            "filterFd: -1,",
            f"filterFd: {self.filter_fd},",
        )
        code = code.replace(
            "hookWrite: true,",
            f"hookWrite: {'true' if self.hook_write else 'false'},",
        )

        return code

    def on_message(self, message, data):
        """
        Callback triggered by each send() on the agent JS side.

        - message: dict with 'type' and 'payload' (the JSON)
        - data:    bytes or None (the raw binary buffer)
        """
        if message["type"] == "send":
            payload = message["payload"]
            event_type = payload.get("event")

            if event_type == "connect":
                self._handle_connect(payload)

            elif event_type in ("send", "write"):
                self._handle_send(payload, data)

            elif event_type == "close":
                self._handle_close(payload)

        elif message["type"] == "error":
            print(f"\n[AGENT ERROR] {message.get('stack', message)}")

    def _handle_connect(self, payload):
        """Displays and records a connect() event."""
        result = payload["result"]
        status = "OK" if result == 0 else f"ERROR ({result})"
        ip = payload.get("ip", "?")
        port = payload.get("port", "?")

        print(f"\n+-- CONNECT fd {payload['fd']} -> {ip}:{port} [{status}]")
        self.events.append(payload)

    def _handle_send(self, payload, data):
        """Displays and records a send()/write() event."""
        seq = payload["seq"]
        ts = payload["timestamp_ms"]
        fd = payload["fd"]
        requested = payload["requested_len"]
        sent = payload["bytes_sent"]
        func = payload["event"].upper()
        dest_ip = payload.get("dest_ip")
        dest_port = payload.get("dest_port")

        dest = f" -> {dest_ip}:{dest_port}" if dest_ip else ""
        status = f"{sent}/{requested} bytes" if sent >= 0 else "ERROR"

        print(f"| [{func} #{seq:03d}] +{ts:>6d}ms | fd {fd}{dest} | {status}")

        if data:
            # Display a hex preview of the first 48 bytes
            preview = data[:48]
            hex_str = " ".join(f"{b:02x}" for b in preview)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
            suffix = "..." if len(data) > 48 else ""
            print(f"|   hex: {hex_str}{suffix}")
            print(f"|   asc: {ascii_str}{suffix}")

            self.buffers.append(data)
            self.total_bytes += len(data)

        # Record metadata (without the binary buffer)
        payload_copy = dict(payload)
        payload_copy["buffer_size"] = len(data) if data else 0
        self.events.append(payload_copy)

    def _handle_close(self, payload):
        """Displays and records a close() event."""
        ip = payload.get("ip", "?")
        port = payload.get("port", "?")
        print(f"+-- CLOSE fd {payload['fd']} ({ip}:{port})")
        self.events.append(payload)

    def on_detached(self, reason):
        """Callback when the process terminates."""
        print(f"\n[*] Session detached: {reason}")
        self.running = False

    def export_results(self):
        """Saves capture.json and capture.bin."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # -- capture.json --
        json_path = self.output_dir / "capture.json"
        export_data = {
            "binary": self.binary,
            "binary_args": self.binary_args,
            "filter_fd": self.filter_fd,
            "total_send_calls": sum(
                1 for e in self.events if e.get("event") in ("send", "write")
            ),
            "total_bytes_captured": self.total_bytes,
            "events": self.events,
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        print(f"[+] Metadata exported -> {json_path}")

        # -- capture.bin --
        bin_path = self.output_dir / "capture.bin"
        with open(bin_path, "wb") as f:
            for buf in self.buffers:
                f.write(buf)
        print(f"[+] Raw buffers exported -> {bin_path} ({self.total_bytes} bytes)")

    def run(self):
        """Main entry point."""
        # Verify the binary exists
        if not Path(self.binary).exists():
            print(f"[!] Binary not found: {self.binary}")
            sys.exit(1)

        # Load the agent
        agent_code = self.load_agent()

        # Spawn the process
        spawn_args = [self.binary] + self.binary_args
        print(f"[*] Spawn: {' '.join(spawn_args)}")
        self.pid = frida.spawn(spawn_args)
        self.session = frida.attach(self.pid)
        self.session.on("detached", self.on_detached)

        # Load the agent script
        self.script = self.session.create_script(agent_code)
        self.script.on("message", self.on_message)
        self.script.load()

        # Resume process execution
        frida.resume(self.pid)
        print(f"[*] Process launched (PID {self.pid}). Ctrl+C to stop.\n")

        # Wait loop
        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[*] User interrupt.")

        # Cleanup and export
        print(f"\n{'=' * 50}")
        print(f"  Capture Summary")
        print(f"{'=' * 50}")

        send_count = sum(
            1 for e in self.events if e.get("event") in ("send", "write")
        )
        connect_count = sum(
            1 for e in self.events if e.get("event") == "connect"
        )
        print(f"  Connections captured   : {connect_count}")
        print(f"  send()/write() calls   : {send_count}")
        print(f"  Total bytes            : {self.total_bytes}")
        print(f"{'=' * 50}\n")

        self.export_results()

        # Detach cleanly
        try:
            self.session.detach()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════

def main():
    args = parse_args()

    logger = SendLogger(
        binary=args.binary,
        binary_args=args.binary_args,
        filter_fd=args.filter_fd,
        output_dir=args.output_dir,
        hook_write=not args.no_write_hook,
    )
    logger.run()


if __name__ == "__main__":
    main()
