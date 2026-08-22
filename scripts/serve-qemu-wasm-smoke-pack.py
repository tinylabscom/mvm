#!/usr/bin/env python3
"""Serve the QEMU-Wasm smoke pack with COOP/COEP headers."""
import http.server
import os
import socketserver
import sys

class ReuseAddrTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class CoopCoepHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        super().end_headers()

    def log_message(self, fmt, *args):
        # Reduce noise; still print to stderr for debugging.
        print(f"[serve] {self.address_string()} {fmt % args}", file=sys.stderr)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    directory = sys.argv[2] if len(sys.argv) > 2 else "."
    os.chdir(directory)
    with ReuseAddrTCPServer(("127.0.0.1", port), CoopCoepHandler) as httpd:
        print(f"Serving {directory} at http://127.0.0.1:{port}", flush=True)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
