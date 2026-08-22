#!/usr/bin/env python3
"""Serve the staged WebLinux demo with the COOP/COEP headers required by
SharedArrayBuffer and Emscripten pthreads."""
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


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <staged-demo-dir> [port]", file=sys.stderr)
        sys.exit(2)
    demo_dir = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
    os.chdir(demo_dir)
    with ReuseAddrTCPServer(("127.0.0.1", port), CoopCoepHandler) as httpd:
        print(f"Serving {demo_dir} at http://127.0.0.1:{port}/")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
