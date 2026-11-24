"""A dual-stack stdlib HTTP server and handler, and a QR code: enough to serve a
request and receive the answer without a web framework."""

from __future__ import annotations

import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Server(ThreadingHTTPServer):
    """Dual-stack on purpose: a tunnel told to forward `http://localhost:<port>`
    resolves that to ::1 first on macOS; an IPv4-only socket then refuses it
    and the wallet gets a 404 it can't explain."""

    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class Handler(BaseHTTPRequestHandler):
    """Quiet logging that still shows the wallet's calls, and reply helpers."""

    def log_message(self, fmt, *args):
        print(f"   {self.address_string()} {fmt % args}", flush=True)

    def reply(self, body: bytes, content_type: str, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def reply_json(self, value, status: int = 200):
        self.reply(json.dumps(value).encode(), "application/json", status)

    def read_body(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))


def qr_svg(text: str) -> str:
    """An SVG QR code (needs the `qr` extra: pip install eudi-pid[qr])."""
    import qrcode
    import qrcode.image.svg
    return qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, border=1).to_string().decode()
