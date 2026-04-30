"""Minimal HTTP server for mvm hello-python example."""

import os
from http.server import HTTPServer, BaseHTTPRequestHandler


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Hello from mvm (Python)!\n")

    def log_message(self, format, *args):
        # Log to stderr (captured by mvm guest agent)
        print(f"hello-python: {args[0]}", flush=True)


def main():
    port = int(os.environ.get("PORT", "8080"))
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"hello-python: listening on port {port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
