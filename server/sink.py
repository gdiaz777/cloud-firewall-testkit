#!/usr/bin/env python3
"""HTTP sink for the "application" paths (/upload, /api, /login.php…): reads the whole body and answers 200.
nginx (proxy_request_buffering on) receives the full client body before passing it here."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class H(BaseHTTPRequestHandler):
    def _ok(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        msg = b"upload received\n" if self.path.startswith("/upload") else b"ok\n"
        self.send_response(200); self.send_header("Content-Type", "text/plain"); self.send_header("Content-Length", str(len(msg))); self.end_headers()
        self.wfile.write(msg)
    do_GET = do_POST = do_PUT = do_HEAD = _ok

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", 8001), H).serve_forever()
