#!/usr/bin/env python3
"""Hostile replication leader for ArangoDB's replication-v1 follower.

The role is inverted on purpose: arangod is the *client* here. We answer every
replication endpoint it calls (batch, inventory, dump, logger-follow) with a
hostile body, cycling through shapes: wrong types, missing members, truncated
payloads, huge arrays, 500s, and a body that claims to be VPack but is not.

Usage: hostile_leader.py <port> <logfile>
"""
import http.server
import itertools
import json
import socketserver
import sys

# The bodies cycle per request so one follower run meets all of them.
BODIES = [
    b"",
    b"{}",
    b"[]",
    b"null",
    b'{"id": 1}',                                  # batch with wrong type
    b'{"id": "x", "count": "y"}',
    b'{"result": {}}',                              # inventory with no collections
    b'{"collections": [{"id": 1, "name": 2}]}',     # wrong member types
    b'{"collections": [{"id": 1, "name": "c", "parameters": []}]}',
    b'{"tick": "notanumber", "serverId": 1}',       # logger-state
    b'{"state": {"running": "yes"}}',
    b'{"error": true, "errorMessage": "boom", "errorNum": 1}',
    b"[" * 500 + b"]" * 500,                        # depth bomb
    b'{"a": "\\ud800"}',                            # lone surrogate
    b'{"x": 1e999999}',                             # huge exponent
    b"\xff\xfe\x00\x01",                            # invalid utf-8 / binary
    b'{"result": [1,2,3], "extra": {"nested": ' + b'[' * 200 + b'0' + b']' * 200 + b'}}',
]

requests_seen = []


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _serve(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        path = self.path.split("?")[0]
        requests_seen.append(path)
        with open(sys.argv[2], "a") as f:
            f.write(f"{self.command} {path}\n")

        n = len(requests_seen) - 1
        body = BODIES[n % len(BODIES)]
        status = 500 if n % 11 == 5 else 200
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = _serve
    do_POST = _serve
    do_PUT = _serve
    do_DELETE = _serve
    do_HEAD = _serve
    do_PATCH = _serve


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(sys.argv[1])
    print(f"hostile leader on {port}, {len(BODIES)} body shapes", flush=True)
    Server(("127.0.0.1", port), Handler).serve_forever()
