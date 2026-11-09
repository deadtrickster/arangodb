#!/usr/bin/env python3
"""HTTP conversation fuzzer for ArangoDB: multi-request sessions, protocol oracles.

The target is out-of-process on purpose. A single response can be correct while
the *conversation* around it is broken — a cursor that answers after it was
deleted, a transaction whose writes survive an abort, a stream cursor whose
batches repeat or arrive out of order, a connection left unusable after a
malformed request. Those are what this driver looks for: each input is a script
of several requests against a live, sanitized arangod, and every response is
checked against the protocol invariants below, not just against "not 500".

Usage:
    fuzz/http_conversation.py                      # boot, verify, 100 fuzz iterations
    fuzz/http_conversation.py -n 500 --seed 7
    fuzz/http_conversation.py --replay 7:41        # one iteration, verbosely
    fuzz/http_conversation.py --conversations auth,cursor --verify-only
    fuzz/http_conversation.py --server-url http://127.0.0.1:8529 --jwt-secret s3cr3t...
    fuzz/http_conversation.py --list

What the server is booted with, and why:
  * authentication is ENABLED with a secret this script writes, so the auth
    conversation can produce real 401s; every other request carries a token
    forged with that secret (HS256, ``iss: arangodb``, ``preferred_username:
    root``). Booting with auth off would make the whole first conversation
    untestable. ``--no-auth`` boots without auth and drops that conversation.
  * ``--transaction.streaming-idle-timeout`` is set to a few seconds so the
    abandoned-transaction oracle (server-side rollback) is observable inside a
    test run instead of after the default 60 s.
  * ``--configuration none`` because the packaged /etc config points the log at
    a path this process cannot write.

Measured API shape of this tree (4.0.0-devel) that the scripts encode — the
documented-in-3.x forms that no longer exist are probed too, and their answers
are asserted as invariants rather than treated as failures:
  * cursor next batch is POST /_api/cursor/<id>; PUT and GET answer 405.
  * streaming cursors return Content-Type: application/json (this tree has no
    application/json-seq type); a batch body is still one JSON object per line,
    which is the framing the oracle checks. A json-seq content type is accepted
    if a future tree emits it.
  * /_api/batch is not routed at all: every method answers 404 with an empty
    body. The batch conversation therefore asserts that, and exercises the
    multi-request framing it used to provide with HTTP pipelining on one
    socket.
  * /_api/replication/logger-follow is gone (404 "invalid command"); the
    handshake is logger-state -> POST batch -> inventory?batchId ->
    dump?collection=...&batchId=... -> DELETE batch.
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import hmac
import http.client
import itertools
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse

DEFAULT_ARANGOD = os.environ.get("ARANGOD_BIN", "/build/build-asan/bin/arangod")
DEFAULT_PORT = 8529
COLLECTION = "hc_coll"
COLLECTION2 = "hc_other"

JSON_CT = "application/json"
VPACK_CT = "application/x-velocypack"
DUMP_CT = "application/x-arango-dump"
SEQUENCE_CT = "application/json-seq"
TEXT_CT = "text/plain"
HTML_CT = "text/html"
KNOWN_CONTENT_TYPES = {
    JSON_CT,
    VPACK_CT,
    DUMP_CT,
    SEQUENCE_CT,
    TEXT_CT,
    HTML_CT,
}
# Bodies whose framing the oracle can read line by line.
LINE_JSON_TYPES = {DUMP_CT, SEQUENCE_CT}

PLACEHOLDER = re.compile(r"\{(\w+)\}")


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def base_content_type(value):
    if not value:
        return ""
    return value.split(";", 1)[0].strip().lower()


def header_value(headers, name):
    """First value of a header in a list of (name, value) pairs, case-insensitive."""
    name = name.lower()
    for key, value in headers:
        if key.lower() == name:
            return value
    return None


def preview(resp, limit=240):
    body = resp.body[:limit]
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = repr(body)
    return f"{resp.status} {resp.headers_content_type() or '-'} {text!r}"


def json_path(value, path):
    """Walk a dotted path ("result.id") through parsed JSON."""
    for part in path.split("."):
        if isinstance(value, dict):
            if part not in value:
                return None
            value = value[part]
        elif isinstance(value, list):
            try:
                value = value[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return value


class Unresolved(Exception):
    """A step referenced a variable that no earlier response captured."""


# ---------------------------------------------------------------------------
# JWTs: forged locally, because the harness owns the server's secret
# ---------------------------------------------------------------------------
class Tokens:
    """Mints the token shapes the auth conversation needs to see rejected."""

    def __init__(self, secret):
        self.secret = secret

    @staticmethod
    def _b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    def mint(self, username="root", ttl=3600, issuer="arangodb", secret=None, now=None):
        now = int(time.time()) if now is None else now
        header = self._b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        claims = {
            "iss": issuer,
            "iat": now,
            "exp": now + ttl,
            "preferred_username": username,
        }
        body = self._b64(json.dumps(claims).encode())
        message = f"{header}.{body}"
        key = self.secret if secret is None else secret
        signature = self._b64(hmac.new(key, message.encode(), hashlib.sha256).digest())
        return f"{message}.{signature}"

    def get(self, kind):
        if kind == "valid":
            return self.mint()
        if kind == "expired":
            return self.mint(ttl=-3600, now=int(time.time()) - 7200)
        if kind == "bad_signature":
            return self.mint(secret=b"x" * len(self.secret))
        if kind == "bad_issuer":
            return self.mint(issuer="not-arangodb")
        if kind == "wrong_user":
            return self.mint(username="hc-no-such-user")
        if kind == "malformed":
            return "abc.def.ghi"
        if kind == "garbage":
            return "!!!"
        if kind == "none":
            return None
        raise ValueError(f"unknown token kind {kind!r}")

    ALL_KINDS = (
        "valid",
        "expired",
        "bad_signature",
        "bad_issuer",
        "wrong_user",
        "malformed",
        "garbage",
        "none",
    )


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
class TransportError(RuntimeError):
    """The request never produced a well-formed HTTP response."""


@dataclasses.dataclass
class Response:
    method: str
    path: str
    status: int
    headers: list
    body: bytes
    elapsed: float = 0.0

    def header(self, name, default=None):
        value = header_value(self.headers, name)
        return default if value is None else value

    def headers_content_type(self):
        return self.header("content-type")

    def base_content_type(self):
        return base_content_type(self.header("content-type"))

    def json_ok(self):
        try:
            return True, json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return False, None

    def json(self):
        ok, value = self.json_ok()
        if not ok:
            raise ValueError(f"body is not JSON: {self.body[:120]!r}")
        return value


class Client:
    """One keep-alive HTTP connection; a broken connection is reported, not hidden."""

    def __init__(self, host, port, timeout=60.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._conn = None

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def _connection(self):
        if self._conn is None:
            self._conn = http.client.HTTPConnection(
                self.host, self.port, timeout=self.timeout
            )
        return self._conn

    def request(self, method, path, body=None, headers=None):
        payload = None
        if body is not None:
            payload = body if isinstance(body, bytes) else body.encode("utf-8")
        headers = dict(headers or {})
        started = time.monotonic()
        try:
            conn = self._connection()
            conn.request(method, path, body=payload, headers=headers)
            raw = conn.getresponse()
            data = raw.read()
        except (http.client.HTTPException, OSError) as exc:
            self.close()
            raise TransportError(f"{method} {path}: {type(exc).__name__}: {exc}") from exc
        resp = Response(
            method, path, raw.status, list(raw.getheaders()), data,
            time.monotonic() - started,
        )
        if (resp.header("connection") or "").lower() == "close":
            self.close()
        return resp


class FramingError(RuntimeError):
    """A response on a raw socket could not be parsed as HTTP/1.x."""


@dataclasses.dataclass
class RawResponse:
    status: int
    headers: list
    body: bytes

    def header(self, name, default=None):
        value = header_value(self.headers, name)
        return default if value is None else value

    def base_content_type(self):
        return base_content_type(self.header("content-type"))


class RawReader:
    """Reads one HTTP/1.x response at a time off a socket, length-delimited."""

    def __init__(self, sock, timeout):
        self.sock = sock
        self.buf = b""
        self.sock.settimeout(timeout)

    def _more(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError("connection closed by server")
        self.buf += chunk

    def _until(self, marker):
        while marker not in self.buf:
            self._more()
        end = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:end], self.buf[end:]
        return out

    def _exact(self, count):
        while len(self.buf) < count:
            self._more()
        out, self.buf = self.buf[:count], self.buf[count:]
        return out

    def read_response(self):
        head = self._until(b"\r\n\r\n")
        lines = head[:-4].split(b"\r\n")
        status_line = lines[0].decode("latin-1")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/"):
            raise FramingError(f"bad status line {status_line!r}")
        try:
            status = int(parts[1])
        except ValueError:
            raise FramingError(f"bad status code in {status_line!r}") from None
        headers = []
        for line in lines[1:]:
            if not line:
                continue
            if b":" not in line:
                raise FramingError(f"bad header line {line!r}")
            name, value = line.split(b":", 1)
            headers.append((name.decode("latin-1"), value.decode("latin-1").strip()))
        length = header_value(headers, "content-length")
        if length is None:
            if header_value(headers, "transfer-encoding"):
                raise FramingError("chunked response on a raw socket")
            try:
                while True:
                    self._more()
            except EOFError:
                pass
            body, self.buf = self.buf, b""
        else:
            if not length.isdigit():
                raise FramingError(f"bad content-length {length!r}")
            body = self._exact(int(length))
        return RawResponse(status, headers, body)


def raw_roundtrip(host, port, payload, max_responses, timeout=5.0):
    """Send raw bytes, read up to max_responses, never raise for junk input."""
    responses = []
    error = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return responses, f"connect: {exc}"
    try:
        sock.sendall(payload)
        reader = RawReader(sock, timeout)
        for _ in range(max_responses):
            try:
                responses.append(reader.read_response())
            except EOFError:
                break
            except socket.timeout:
                break
            except (FramingError, OSError) as exc:
                error = f"{type(exc).__name__}: {exc}"
                break
    except OSError as exc:
        error = f"send: {exc}"
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return responses, error


# ---------------------------------------------------------------------------
# Steps, conversations, sessions
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class Step:
    name: str
    method: str = "GET"
    path: str = ""
    body: object = None
    headers: dict = dataclasses.field(default_factory=dict)
    token: str = "valid"
    expect: tuple = None
    capture: dict = dataclasses.field(default_factory=dict)
    check: object = None
    # raw-socket steps: bytes to send, statuses expected in order (None = don't care)
    raw: bytes = None
    raw_expect: tuple = None
    # poll steps: repeat until the status lands in `expect`
    poll: bool = False
    poll_timeout: float = 20.0
    poll_interval: float = 0.25
    mutated: str = ""


@dataclasses.dataclass
class Conversation:
    name: str
    steps: list
    slow: bool = False
    post: object = None
    threads: list = None


@dataclasses.dataclass
class Violation:
    kind: str
    detail: str
    step: str


class Session:
    """Runs one conversation, applying the oracles to every response."""

    def __init__(self, env, name, steps):
        self.env = env
        self.name = name
        self.steps = steps
        self.client = env.client()
        self.vars = dict(env.base_vars())
        self.vars["key"] = env.new_key()
        self.vars["key2"] = env.new_key("b")
        self.trace = []
        self.violations = []
        self.soft = []
        self.responses = {}
        self.completed = set()
        self.state = {}
        self.cursors = []
        self.deleted_cursors = []
        self.transactions = []
        self.batches = []
        self.crashed = False

    # -- recording ---------------------------------------------------------
    def fail(self, kind, detail, step=None):
        self.violations.append(Violation(kind, detail, step or ""))

    def note(self, kind, detail):
        self.soft.append((kind, detail))

    def skip(self, step, why):
        self.trace.append({"step": step.name, "skipped": why})

    def auth_headers(self, kind):
        headers = dict(self.env.auth_headers(kind))
        return headers

    # -- substitution ------------------------------------------------------
    def _subst_text(self, text):
        def repl(match):
            name = match.group(1)
            if name not in self.vars:
                raise Unresolved(name)
            return str(self.vars[name])

        return PLACEHOLDER.sub(repl, text)

    def _subst(self, value):
        if isinstance(value, str):
            return self._subst_text(value)
        if isinstance(value, bytes):
            return value
        if isinstance(value, dict):
            return {self._subst(k): self._subst(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._subst(v) for v in value]
        return value

    # -- oracles -----------------------------------------------------------
    def _check_envelope(self, step, status, body, headers, where):
        ctype = base_content_type(header_value(headers, "content-type"))
        if body:
            if header_value(headers, "content-type") is None:
                self.fail("content-type-missing", f"{where}: body without content-type", step.name)
            elif ctype not in KNOWN_CONTENT_TYPES:
                self.fail("content-type-unknown", f"{where}: {ctype!r}", step.name)
        if ctype == JSON_CT:
            if not body:
                # The no-handler path answers 404 with Content-Type: JSON and
                # nothing in it. Worth counting, not worth failing on; a 5xx
                # with no body is already a finding through the status oracle.
                if status < 500:
                    self.note("empty-json-body", f"{where}: {status} claims JSON, body empty")
                return
            try:
                value = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                self.fail("body-not-json", f"{where}: {body[:160]!r}", step.name)
                return
            self._check_json_shape(step, status, value, where)
        elif ctype in LINE_JSON_TYPES:
            for number, line in enumerate(body.split(b"\n")):
                if not line.strip():
                    continue
                try:
                    json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    self.fail(
                        "body-not-json-seq",
                        f"{where}: line {number} is not JSON: {line[:120]!r}",
                        step.name,
                    )
                    break
        elif ctype == VPACK_CT and not body:
            self.fail("empty-vpack-body", f"{where}: velocypack response with no body", step.name)
        length = header_value(headers, "content-length")
        if length is not None and length.isdigit() and int(length) != len(body):
            self.fail(
                "content-length-mismatch",
                f"{where}: header {length} but {len(body)} bytes",
                step.name,
            )

    def _check_json_shape(self, step, status, value, where):
        if isinstance(value, dict):
            code = value.get("code")
            if code is not None and code != status:
                self.fail("envelope-code", f"{where}: code={code!r} status={status}", step.name)
            error = value.get("error")
            if error is not None and bool(error) != (status >= 400):
                self.fail(
                    "envelope-error",
                    f"{where}: error={error!r} status={status}",
                    step.name,
                )
        if status >= 400 and isinstance(value, dict):
            errnum = value.get("errorNum")
            if not isinstance(errnum, int):
                self.fail("error-no-errornum", f"{where}: {value!r}"[:200], step.name)
            message = value.get("errorMessage")
            if not isinstance(message, str) or not message:
                self.fail("error-no-message", f"{where}: {value!r}"[:200], step.name)

    def _check_status(self, step, status, where, body=b""):
        # 501 (chunked framing) and 505 (bad HTTP version) are deliberate
        # answers to malformed framing, not server errors. 500-class alone is.
        server_error = status in (500, 502, 503, 504)
        if step.expect is not None and status not in step.expect:
            if server_error:
                self.fail(
                    "server-error",
                    f"{where}: {status} where {sorted(step.expect)} was expected, "
                    f"body {body[:200]!r}",
                    step.name,
                )
            else:
                self.fail(
                    "status",
                    f"{where}: expected {sorted(step.expect)} got {status} {body[:160]!r}",
                    step.name,
                )
        elif server_error:
            self.fail("server-error", f"{where}: {status} {body[:200]!r}", step.name)

    def _oracle_response(self, step, resp):
        where = f"{resp.method} {resp.path}"
        self._check_status(step, resp.status, where, resp.body)
        self._check_envelope(step, resp.status, resp.body, resp.headers, where)

    def _oracle_raw(self, step, resp):
        where = f"raw {step.name}"
        self._check_status(step, resp.status, where, resp.body)
        self._check_envelope(step, resp.status, resp.body, resp.headers, where)

    # -- running -----------------------------------------------------------
    def run(self):
        for step in self.steps:
            if self.crashed:
                break
            try:
                self._run_step(step)
            except TransportError as exc:
                # A mutation is allowed to leave a connection in a state the
                # server closes; the same drop on an unmutated step is a finding.
                if step.mutated:
                    self.note("connection-drop", f"{step.name}: {exc}")
                else:
                    self.fail("transport", f"{step.name}: {exc}", step.name)
                self.client = self.env.client()
            if self.env.server is not None and not self.env.server.alive():
                self.fail("server-crash", f"server died after step {step.name!r}", step.name)
                self.crashed = True
        return self

    def _run_step(self, step):
        if step.raw is not None:
            return self._run_raw(step)
        try:
            path = self._subst(step.path)
            body = self._subst(step.body)
            headers = self._subst(step.headers)
        except Unresolved as exc:
            self.skip(step, f"unresolved {exc}")
            return
        headers = {**self.auth_headers(step.token), **headers}
        payload = None
        if body is not None:
            if isinstance(body, bytes):
                payload = body
            elif isinstance(body, str):
                payload = body.encode("utf-8")
            else:
                payload = json.dumps(body).encode("utf-8")
                headers.setdefault("Content-Type", JSON_CT)

        if step.poll:
            resp = self._poll(step, path, payload, headers)
        else:
            resp = self.client.request(step.method, path, payload, headers)
        self.trace.append(
            {"step": step.name, "method": step.method, "path": path,
             "status": resp.status, "mutated": step.mutated}
        )
        self.responses[step.name] = resp
        self._oracle_response(step, resp)
        if step.expect is not None and resp.status in step.expect:
            self.completed.add(step.name)
        for var, path_expr in step.capture.items():
            value = json_path(self._safe_json(resp), path_expr)
            if value is None:
                self.fail("capture", f"{step.name}: no {path_expr!r} in {preview(resp)}", step.name)
            else:
                self.vars[var] = str(value)
        if step.check is not None:
            try:
                step.check(resp, self)
            except Exception:  # a broken check is a harness bug, surface it loudly
                self.fail("check-exception", traceback.format_exc(limit=3), step.name)

    def _poll(self, step, path, payload, headers):
        deadline = time.monotonic() + step.poll_timeout
        resp = None
        while True:
            resp = self.client.request(step.method, path, payload, headers)
            if resp.status >= 500:
                self.fail(
                    "server-error",
                    f"{step.name}: {resp.status} while polling {preview(resp)}",
                    step.name,
                )
                return resp
            if step.expect is None or resp.status in step.expect:
                return resp
            if time.monotonic() >= deadline:
                self.fail(
                    "poll-timeout",
                    f"{step.name}: still {resp.status} after {step.poll_timeout:.0f}s",
                    step.name,
                )
                return resp
            time.sleep(step.poll_interval)

    def _run_raw(self, step):
        try:
            payload = self._subst(step.raw)
        except Unresolved as exc:
            self.skip(step, f"unresolved {exc}")
            return
        expected = step.raw_expect
        want = len(expected) if expected else 2
        responses, error = raw_roundtrip(self.env.host, self.env.port, payload, want)
        self.trace.append(
            {"step": step.name, "raw": payload[:80].decode("latin-1"),
             "responses": [r.status for r in responses], "mutated": step.mutated}
        )
        if error is not None:
            self.fail("framing", f"{step.name}: {error}", step.name)
        if expected is not None:
            if len(responses) != len(expected):
                self.fail(
                    "framing-count",
                    f"{step.name}: {len(responses)} responses, expected {len(expected)}",
                    step.name,
                )
            for index, (resp, want_status) in enumerate(zip(responses, expected)):
                if want_status is not None and resp.status != want_status:
                    self.fail(
                        "framing-status",
                        f"{step.name}: response {index} is {resp.status}, expected {want_status}",
                        step.name,
                    )
        for resp in responses:
            self._oracle_raw(step, resp)

    @staticmethod
    def _safe_json(resp):
        ok, value = resp.json_ok()
        return value if ok else None


# ---------------------------------------------------------------------------
# shared check helpers
# ---------------------------------------------------------------------------
def chain(*checks):
    """One step check out of several."""

    def check(resp, sess):
        for item in checks:
            item(resp, sess)

    return check


def expect_errnum(number, label=""):
    def check(resp, sess):
        ok, value = resp.json_ok()
        if not ok or not isinstance(value, dict) or value.get("errorNum") != number:
            sess.fail(
                "errnum",
                f"{label or resp.path}: expected errorNum {number}, got {preview(resp)}",
            )

    return check


def expect_errnum_if_404(number, label=""):
    """For commands a future tree may implement: only pin the error shape now."""

    def check(resp, sess):
        if resp.status != 404:
            return
        ok, value = resp.json_ok()
        if not ok or not isinstance(value, dict) or value.get("errorNum") != number:
            sess.fail(
                "errnum",
                f"{label or resp.path}: expected errorNum {number}, got {preview(resp)}",
            )

    return check


def expect_json(path, wanted, label=""):
    def check(resp, sess):
        value = json_path(sess._safe_json(resp), path)
        ok = wanted(value) if callable(wanted) else value == wanted
        if not ok:
            sess.fail(
                "json-field",
                f"{label or resp.path}: {path} = {value!r}, wanted {wanted!r}",
            )

    return check


def record(attribute, var):
    """Remember a captured id on the session so post-checks can revisit it."""

    def check(resp, sess):
        value = sess.vars.get(var)
        if value is not None:
            getattr(sess, attribute).append(value)

    return check


def stream_batch_check(resp, sess):
    """One streaming batch is exactly one JSON object on the wire."""
    lines = [line for line in resp.body.split(b"\n") if line.strip()]
    if len(lines) != 1:
        sess.fail(
            "stream-framing",
            f"{resp.path}: {len(lines)} JSON lines in one batch: {resp.body[:160]!r}",
        )
    value = sess._safe_json(resp)
    if isinstance(value, dict):
        sess.state["stream_results"] = sess.state.get("stream_results", []) + list(
            value.get("result") or []
        )
        # Only a drained cursor has a total to compare: a mutation may cut the
        # drain short, and that is not a server-side violation.
        sess.state["stream_drained"] = value.get("hasMore") is False
        next_batch = value.get("nextBatchId")
        previous = sess.state.get("stream_next_batch")
        if next_batch is not None:
            if previous is not None and int(next_batch) != int(previous) + 1:
                sess.fail(
                    "stream-batch-id",
                    f"nextBatchId jumped {previous} -> {next_batch}",
                )
            sess.state["stream_next_batch"] = next_batch


# ---------------------------------------------------------------------------
# the conversations
# ---------------------------------------------------------------------------
def conv_auth(env):
    """a. Every credential shape the server must reject, then a good one again."""
    steps = [
        # No endpoint is public in this tree: the version probe itself is 401
        # without a token, which is the first rejection to pin down.
        Step("version-anon", "GET", "/_api/version", token="none",
             expect=(401,), check=expect_errnum(11, "anon version")),
        Step("version-valid", "GET", "/_api/version", token="valid", expect=(200,),
             check=expect_json("version", lambda v: isinstance(v, str))),
        Step("collection-anon", "GET", "/_api/collection", token="none",
             expect=(401,), check=expect_errnum(11, "anon")),
        Step("collection-valid", "GET", "/_api/collection", token="valid", expect=(200,)),
        Step("collection-expired", "GET", "/_api/collection", token="expired",
             expect=(401,), check=expect_errnum(11, "expired")),
        Step("collection-bad-signature", "GET", "/_api/collection", token="bad_signature",
             expect=(401,), check=expect_errnum(11, "bad signature")),
        Step("collection-bad-issuer", "GET", "/_api/collection", token="bad_issuer",
             expect=(401,), check=expect_errnum(11, "bad issuer")),
        Step("collection-unknown-user", "GET", "/_api/collection", token="wrong_user",
             expect=(401,), check=expect_errnum(11, "unknown user")),
        Step("collection-malformed", "GET", "/_api/collection", token="malformed",
             expect=(401,), check=expect_errnum(11, "malformed")),
        Step("collection-garbage", "GET", "/_api/collection", token="garbage",
             expect=(401,), check=expect_errnum(11, "garbage")),
        # The rejected requests must not have poisoned the good token's cache
        # entry, and must not have downgraded the connection.
        Step("collection-valid-again", "GET", "/_api/collection", token="valid", expect=(200,)),
        Step("replication-anon", "GET", "/_api/replication/logger-state", token="none",
             expect=(401,)),
        Step("transaction-begin-anon", "POST", "/_api/transaction/begin",
             body={"collections": {"write": [env.collection]}}, token="none",
             expect=(401,)),
    ]
    return Conversation("auth", steps)


def conv_cursor(env):
    """b. Cursor lifecycle, including the paths the old API documented and this
    tree does not implement, plus the server-side TTL."""
    body = {"query": "FOR i IN 1..10 RETURN i", "batchSize": 2, "count": True}
    steps = [
        Step("create", "POST", "/_api/cursor", body=dict(body), expect=(201,),
             capture={"cursor": "id"},
             check=chain(expect_json("result", lambda v: v == [1, 2]),
                         record("cursors", "cursor"))),
        Step("batch-2", "POST", "/_api/cursor/{cursor}", expect=(200,),
             check=expect_json("result", lambda v: v == [3, 4])),
        Step("batch-3", "POST", "/_api/cursor/{cursor}", expect=(200,),
             check=expect_json("result", lambda v: v == [5, 6])),
        Step("batch-4", "POST", "/_api/cursor/{cursor}", expect=(200,),
             check=expect_json("result", lambda v: v == [7, 8])),
        Step("batch-5-last", "POST", "/_api/cursor/{cursor}", expect=(200,),
             check=expect_json("hasMore", False)),
        # An exhausted cursor is destroyed: both verbs must say so, and the
        # error must be a clean 404, not a 500 or a stale 200.
        Step("after-exhaustion-post", "POST", "/_api/cursor/{cursor}", expect=(404,),
             check=expect_errnum(1600)),
        Step("after-exhaustion-delete", "DELETE", "/_api/cursor/{cursor}", expect=(404,)),
        Step("create-2", "POST", "/_api/cursor",
             body={"query": "FOR i IN 1..10 RETURN i", "batchSize": 2},
             expect=(201,), capture={"cursor2": "id"},
             check=record("cursors", "cursor2")),
        # PUT/GET are the 3.x spellings of "next batch"; this API version
        # answers 405, and the cursor must survive the attempt.
        Step("put-next-batch", "PUT", "/_api/cursor/{cursor2}", expect=(405,)),
        Step("get-next-batch", "GET", "/_api/cursor/{cursor2}", expect=(405,)),
        Step("delete-2", "DELETE", "/_api/cursor/{cursor2}", expect=(202,),
             check=record("deleted_cursors", "cursor2")),
        Step("post-deleted", "POST", "/_api/cursor/{cursor2}", expect=(404,),
             check=expect_errnum(1600)),
        Step("delete-deleted", "DELETE", "/_api/cursor/{cursor2}", expect=(404,)),
        # Small results are returned inline: no cursor id, and nothing to delete.
        Step("inline-result", "POST", "/_api/cursor",
             body={"query": "FOR i IN 1..3 RETURN i"}, expect=(201,),
             check=expect_json("id", lambda v: v is None, "inline cursor id")),
        Step("syntax-error", "POST", "/_api/cursor", body={"query": "FOR i IN RETURN i"},
             expect=(400,), check=expect_errnum(1501)),
        Step("unknown-collection", "POST", "/_api/cursor",
             body={"query": "FOR d IN hc_no_such_collection RETURN d"},
             expect=(404,), check=expect_errnum(1203)),
        Step("empty-query", "POST", "/_api/cursor", body={"batchSize": 2}, expect=(400,),
             check=expect_errnum(1502)),
        Step("non-object-body", "POST", "/_api/cursor", body=b"[1,2,3]", expect=(400,)),
        # Server-side TTL: a cursor nobody deletes must vanish on its own.
        Step("create-ttl", "POST", "/_api/cursor",
             body={"query": "FOR i IN 1..10 RETURN i", "batchSize": 2, "ttl": 1},
             expect=(201,), capture={"ttl_cursor": "id"},
             check=record("cursors", "ttl_cursor")),
        Step("ttl-cursor-expires", "POST", "/_api/cursor/{ttl_cursor}",
             poll=True, poll_timeout=20.0, expect=(404,)),
    ]
    return Conversation("cursor", steps, post=post_cursor)


def probe(env, sess, method, path):
    """A request from a post-check: own connection, so a connection a mutation
    left in a bad state cannot be mistaken for a server-side violation."""
    client = env.client()
    try:
        return client.request(method, path, None, sess.auth_headers("valid"))
    finally:
        client.close()


def post_cursor(env, sess):
    """Oracles that need the whole conversation: deletion is permanent, ids unique."""
    if len(sess.cursors) != len(set(sess.cursors)):
        sess.fail("cursor-id-duplicate", f"ids reused: {sess.cursors}")
    for cursor in sess.deleted_cursors:
        for method in ("POST", "DELETE"):
            try:
                resp = probe(env, sess, method, f"/_api/cursor/{cursor}")
            except TransportError as exc:
                sess.fail("transport", f"probing deleted cursor {cursor}: {exc}")
                continue
            if resp.status != 404:
                sess.fail(
                    "cursor-resurrection",
                    f"{method} on deleted cursor {cursor} -> {preview(resp)}",
                )
    if sess.state.get("stream_drained"):
        want = list(range(1, 11))
        if sess.state["stream_results"] != want:
            sess.fail(
                "stream-results",
                f"streamed {sess.state['stream_results']!r}, wanted {want!r}",
            )


def conv_stream(env):
    """c. Streaming cursor: per-batch framing, monotonic batch ids, full result set."""
    steps = [
        Step("create", "POST", "/_api/cursor",
             body={"query": "FOR i IN 1..10 RETURN i", "batchSize": 2, "stream": True},
             expect=(201,), capture={"scursor": "id"},
             check=chain(stream_batch_check, record("cursors", "scursor"))),
        Step("batch-2", "POST", "/_api/cursor/{scursor}", expect=(200,),
             check=stream_batch_check),
        Step("batch-3", "POST", "/_api/cursor/{scursor}", expect=(200,),
             check=stream_batch_check),
        Step("batch-4", "POST", "/_api/cursor/{scursor}", expect=(200,),
             check=stream_batch_check),
        Step("batch-5-last", "POST", "/_api/cursor/{scursor}", expect=(200,),
             check=stream_batch_check),
        Step("after-exhaustion", "POST", "/_api/cursor/{scursor}", expect=(404,)),
        # The 3.x GET spelling for the next stream batch is gone in this tree.
        Step("create-2", "POST", "/_api/cursor",
             body={"query": "FOR i IN 1..10 RETURN i", "batchSize": 2, "stream": True},
             expect=(201,), capture={"scursor2": "id"},
             check=record("cursors", "scursor2")),
        Step("get-stream-batch", "GET", "/_api/cursor/{scursor2}", expect=(405,)),
        Step("delete-2", "DELETE", "/_api/cursor/{scursor2}", expect=(202,),
             check=record("deleted_cursors", "scursor2")),
        Step("delete-2-again", "DELETE", "/_api/cursor/{scursor2}", expect=(404,)),
        # stream+count is either rejected or answered with a consistent cursor;
        # both are acceptable, a 500 or a truncated body is not.
        Step("stream-with-count", "POST", "/_api/cursor",
             body={"query": "FOR i IN 1..10 RETURN i", "batchSize": 2,
                   "stream": True, "count": True},
             expect=(201, 400)),
        Step("stream-bad-batch-size", "POST", "/_api/cursor",
             body={"query": "FOR i IN 1..10 RETURN i", "stream": True, "batchSize": -1},
             expect=(400, 201)),
    ]
    return Conversation("stream", steps, post=post_cursor)


def conv_transaction(env):
    """d. Stream transaction: isolation before commit, visibility after, no
    operation outside the declared collections, idempotent commit."""
    steps = [
        Step("begin", "POST", "/_api/transaction/begin",
             body={"collections": {"write": [env.collection]}}, expect=(201,),
             capture={"txn": "result.id"},
             check=expect_json("result.status", "running")),
        Step("insert", "POST", "/_api/document/{coll}", body={"_key": "{key}"},
             headers={"x-arango-trx-id": "{txn}"}, expect=(202,),
             check=record("transactions", "txn")),
        # Uncommitted writes are invisible outside the transaction.
        Step("read-outside", "GET", "/_api/document/{coll}/{key}", expect=(404,),
             check=expect_errnum(1202, "uncommitted document visible outside")),
        Step("read-inside", "GET", "/_api/document/{coll}/{key}",
             headers={"x-arango-trx-id": "{txn}"}, expect=(200,)),
        Step("state-running", "GET", "/_api/transaction/{txn}", expect=(200,),
             check=expect_json("result.status", "running")),
        # A collection the transaction did not declare is refused, not written.
        Step("undeclared-collection", "POST", "/_api/document/{coll2}",
             body={"_key": "{key2}"}, headers={"x-arango-trx-id": "{txn}"},
             expect=(400,), check=expect_errnum(1652)),
        Step("unknown-transaction", "POST", "/_api/document/{coll}",
             body={"_key": "{key2}"}, headers={"x-arango-trx-id": "999999999"},
             expect=(404,), check=expect_errnum(1655)),
        Step("malformed-transaction", "POST", "/_api/document/{coll}",
             body={"_key": "{key2}"}, headers={"x-arango-trx-id": "not-a-number"},
             expect=(400,)),
        Step("commit", "PUT", "/_api/transaction/{txn}", expect=(200,),
             check=expect_json("result.status", "committed")),
        Step("read-after-commit", "GET", "/_api/document/{coll}/{key}", expect=(200,)),
        Step("commit-again", "PUT", "/_api/transaction/{txn}", expect=(200,),
             check=expect_json("result.status", "committed")),
        Step("abort-after-commit", "DELETE", "/_api/transaction/{txn}", expect=(400,),
             check=expect_errnum(1653)),
        Step("state-after-commit", "GET", "/_api/transaction/{txn}", expect=(200,),
             check=expect_json("result.status", "committed")),
    ]
    return Conversation("transaction", steps, post=post_transaction)


def post_transaction(env, sess):
    if "commit" in sess.completed:
        key = sess.vars["key"]
        try:
            resp = probe(env, sess, "GET", f"/_api/document/{env.collection}/{key}")
        except TransportError as exc:
            sess.fail("transport", f"probing committed {key}: {exc}")
            return
        if resp.status != 200:
            sess.fail("commit-lost", f"committed {key} reads back as {preview(resp)}")
    # Nothing this conversation started may still be running.
    try:
        resp = probe(env, sess, "GET", "/_api/transaction")
    except TransportError as exc:
        sess.fail("transport", f"listing transactions: {exc}")
        return
    ok, value = resp.json_ok()
    running = set()
    if ok and isinstance(value, dict):
        for entry in value.get("transactions") or []:
            if isinstance(entry, dict) and entry.get("status") == "running":
                running.add(str(entry.get("id")))
    leaked = running & set(sess.transactions)
    if leaked:
        sess.fail("transaction-leak", f"still running after the conversation: {sorted(leaked)}")


def conv_transaction_abandoned(env):
    """e. A transaction nobody finishes must roll back server-side."""
    steps = [
        Step("begin", "POST", "/_api/transaction/begin",
             body={"collections": {"write": [env.collection]}}, expect=(201,),
             capture={"txn": "result.id"},
             check=record("transactions", "txn")),
        Step("insert", "POST", "/_api/document/{coll}", body={"_key": "{key}"},
             headers={"x-arango-trx-id": "{txn}"}, expect=(202,)),
        Step("invisible-outside", "GET", "/_api/document/{coll}/{key}", expect=(404,)),
        # The idle timeout configured at boot must reap it.
        Step("expires", "GET", "/_api/transaction/{txn}", poll=True,
             poll_timeout=30.0, expect=(404,)),
        Step("no-data-left", "GET", "/_api/document/{coll}/{key}", expect=(404,),
             check=expect_errnum(1202, "abandoned transaction left a document")),
        # The explicit abort path, with the same post-condition.
        Step("begin-2", "POST", "/_api/transaction/begin",
             body={"collections": {"write": [env.collection]}}, expect=(201,),
             capture={"txn2": "result.id"},
             check=record("transactions", "txn2")),
        Step("insert-2", "POST", "/_api/document/{coll}", body={"_key": "{key2}"},
             headers={"x-arango-trx-id": "{txn2}"}, expect=(202,)),
        Step("abort-2", "DELETE", "/_api/transaction/{txn2}", expect=(200,),
             check=expect_json("result.status", "aborted")),
        Step("abort-2-again", "DELETE", "/_api/transaction/{txn2}", expect=(200,),
             check=expect_json("result.status", "aborted")),
        Step("no-data-after-abort", "GET", "/_api/document/{coll}/{key2}", expect=(404,),
             check=expect_errnum(1202, "aborted transaction left a document")),
    ]
    return Conversation("transaction-abandoned", steps, slow=True,
                        post=post_transaction)


def conv_batch(env):
    """f. The batch endpoint is gone in this API version; its framing is
    exercised with pipelining on one socket instead."""
    multipart = (
        b"--hc\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Id: 1\r\n\r\n"
        b'{"query":"RETURN 1"}\r\n'
        b"--hc\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Id: 2\r\n\r\n"
        b'{"query":"RETURN 2"}\r\n'
        b"--hc--\r\n"
    )
    auth = env.auth_headers("valid").get("Authorization")
    auth_line = f"Authorization: {auth}\r\n" if auth else ""
    pipeline = (
        f"GET /_api/version HTTP/1.1\r\nHost: hc\r\n{auth_line}\r\n"
        f"GET /_api/collection HTTP/1.1\r\nHost: hc\r\n{auth_line}\r\n"
        f"GET /_api/nonexistent HTTP/1.1\r\nHost: hc\r\n{auth_line}\r\n"
    ).encode()
    steps = [
        Step("batch-multipart", "POST", "/_api/batch", body=multipart,
             headers={"Content-Type": 'multipart/form-data; boundary=hc'},
             expect=(404, 200), check=batch_shape),
        Step("batch-json", "POST", "/_api/batch", body={"requests": []}, expect=(404, 200),
             check=batch_shape),
        Step("batch-get", "GET", "/_api/batch", expect=(404, 200), check=batch_shape),
        Step("batch-subpath", "POST", "/_api/batch/1", body={}, expect=(404, 200),
             check=batch_shape),
        # Three requests written before any response is read: three
        # responses, in order, each length-delimited and well framed.
        Step("pipeline", raw=pipeline, raw_expect=(200, 200, 404)),
        Step("after-pipeline", "GET", "/_api/version", expect=(200,)),
    ]
    return Conversation("batch", steps)


def batch_shape(resp, sess):
    """If a tree implements /_api/batch, its multipart answer must be coherent."""
    if resp.status != 200:
        return
    ctype = resp.base_content_type()
    boundary = re.search(r'boundary="?([^";]+)"?', resp.header("content-type") or "")
    if ctype != "multipart/mixed" or boundary is None:
        sess.fail(
            "batch-content-type",
            f"200 from /_api/batch without multipart/mixed + boundary: {preview(resp)}",
        )
        return
    marker = b"--" + boundary.group(1).encode()
    parts = [part for part in resp.body.split(marker) if part.strip() not in (b"", b"--")]
    for index, part in enumerate(parts):
        head, _, body = part.partition(b"\r\n\r\n")
        if b"Content-Id" not in head:
            sess.fail("batch-content-id", f"part {index} has no Content-Id: {head[:120]!r}")
        try:
            json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            sess.fail("batch-part-body", f"part {index} body is not JSON: {body[:120]!r}")


def conv_replication(env):
    """g. Replication handshake: logger-state, batch, inventory, dump, and the
    commands this API version dropped."""
    steps = [
        # A document before the batch, so the dump has something at its tick and
        # its line framing is actually exercised.
        Step("seed-document", "POST", "/_api/document/{coll}", body={"_key": "{key}"},
             expect=(202,)),
        Step("logger-state", "GET", "/_api/replication/logger-state", expect=(200,),
             check=expect_json("state.running", True)),
        Step("batch", "POST", "/_api/replication/batch", body={"ttl": 60}, expect=(200,),
             capture={"batch": "id"},
             check=expect_json("lastTick", lambda v: isinstance(v, str))),
        Step("inventory", "GET", "/_api/replication/inventory?batchId={batch}",
             expect=(200,), check=expect_json("collections", lambda v: isinstance(v, list))),
        # Extending a batch takes an object too; a non-object body must be a
        # client error, not an empty 500 (see fuzz/findings/2026-11-09-*).
        Step("batch-extend", "PUT", "/_api/replication/batch/{batch}", body={"ttl": 60},
             expect=(204,)),
        Step("batch-create-non-object", "POST", "/_api/replication/batch",
             body=b"[]", expect=(400,)),
        Step("batch-extend-non-object", "PUT", "/_api/replication/batch/{batch}",
             body=b"[]", expect=(400,)),
        Step("dump", "GET", "/_api/replication/dump?collection={coll}&batchId={batch}",
             # 204 is the answer for an empty snapshot (no documents at the
             # batch's tick), which is legitimate and common on a fresh server.
             expect=(200, 204), check=dump_shape),
        # logger-follow existed up to 3.x; this tree answers a clean 404.
        Step("logger-follow", "GET", "/_api/replication/logger-follow?from=0",
             expect=(404, 200), check=expect_errnum_if_404(404, "logger-follow")),
        Step("inventory-without-batch", "GET", "/_api/replication/inventory",
             expect=(404,), check=expect_errnum(1600)),
        Step("dump-without-batch", "GET", "/_api/replication/dump?collection={coll}",
             expect=(404, 400)),
        Step("dump-unknown-collection",
             "GET", "/_api/replication/dump?collection=hc_no_such_collection&batchId={batch}",
             expect=(400, 404)),
        Step("batch-delete", "DELETE", "/_api/replication/batch/{batch}", expect=(204,),
             check=record("batches", "batch")),
        Step("inventory-after-delete", "GET", "/_api/replication/inventory?batchId={batch}",
             expect=(404,), check=expect_errnum(1600)),
    ]
    if env.tokens is not None:
        steps.append(
            Step("logger-state-anon", "GET", "/_api/replication/logger-state",
                 token="none", expect=(401,))
        )
    return Conversation("replication", steps)


def dump_shape(resp, sess):
    if resp.status != 200:
        return
    if resp.base_content_type() != DUMP_CT:
        sess.fail("dump-content-type", f"dump answered {resp.headers_content_type()!r}")
    for line in resp.body.split(b"\n"):
        if not line.strip():
            continue
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            sess.fail("dump-line", f"dump line is not JSON: {line[:120]!r}")
            return
        if not isinstance(value, dict) or not isinstance(value.get("type"), int):
            sess.fail("dump-line-shape", f"dump line without an int type: {value!r}"[:200])
            return


def conv_concurrent(env):
    """Oracle: two cursors over the same query, interleaved, must not interfere."""
    threads = []
    for index, batch_size in enumerate((2, 3)):
        steps = [
            Step(f"create-{index}", "POST", "/_api/cursor",
                 body={"query": "FOR i IN 1..12 RETURN i", "batchSize": batch_size},
                 expect=(201,), capture={"c": "id"},
                 check=chain(record("cursors", "c"), collect_results)),
            Step(f"drain-{index}", "POST", "/_api/cursor/{c}", poll=False, expect=(200,),
                 check=collect_results),
            Step(f"drain2-{index}", "POST", "/_api/cursor/{c}", expect=(200,),
                 check=collect_results),
            Step(f"drain3-{index}", "POST", "/_api/cursor/{c}", expect=(200, 404),
                 check=collect_results),
            Step(f"drain4-{index}", "POST", "/_api/cursor/{c}", expect=(200, 404),
                 check=collect_results),
            Step(f"drain5-{index}", "POST", "/_api/cursor/{c}", expect=(200, 404),
                 check=collect_results),
            Step(f"drain6-{index}", "POST", "/_api/cursor/{c}", expect=(200, 404),
                 check=collect_results),
            Step(f"delete-{index}", "DELETE", "/_api/cursor/{c}", expect=(202, 404)),
        ]
        threads.append(steps)
    return Conversation("concurrent", [], threads=threads, post=post_concurrent)


def collect_results(resp, sess):
    value = sess._safe_json(resp)
    if isinstance(value, dict):
        sess.state.setdefault("results", []).extend(value.get("result") or [])


def post_concurrent(env, sess):
    """Both cursors are drained in separate sessions; the runner compares."""
    return


# ---------------------------------------------------------------------------
# mutators: turn a script into an unexpected script
# ---------------------------------------------------------------------------
JUNK_REQUESTS = [
    ("GET", "/_api/nonexistent", None, {}),
    ("GET", "/", None, {}),
    ("GET", "/_admin/status", None, {}),
    ("POST", "/_api/cursor", b"{", {"Content-Type": JSON_CT}),
    ("POST", "/_api/cursor", b"[1,2,3]", {"Content-Type": JSON_CT}),
    ("POST", "/_api/cursor", b'{"query":1}', {"Content-Type": JSON_CT}),
    ("DELETE", "/_api/cursor/0", None, {}),
    ("PUT", "/_api/transaction/0", None, {}),
    ("POST", "/_api/transaction/begin", b"null", {"Content-Type": JSON_CT}),
    ("GET", "/_api/replication/inventory", None, {}),
    ("OPTIONS", "/_api/cursor", None, {}),
    ("PATCH", "/_api/cursor", None, {}),
    ("GET", "/_api/collection/hc_no_such_collection", None, {}),
    ("GET", "/_api/document/hc_coll/..%2f..%2f..", None, {}),
    ("GET", "/_api/version?pad=" + "A" * 900, None, {}),
]

BAD_BODIES = [
    b"",
    b"{",
    b"}",
    b"[",
    b"null",
    b"[]",
    b"true",
    b"1",
    b'{"query": 1}',
    b'{"query": "RETURN 1", "batchSize": -1}',
    b'{"query": "RETURN 1", "batchSize": 1e400}',
    b'{"query": "RETURN 1", "ttl": -1}',
    b'{"query": "RETURN 1", "ttl": "x"}',
    b'{"query": "RETURN 1", "stream": "yes"}',
    b'{"query": "RETURN 1", "options": []}',
    b'{"query": "RETURN 1", "bindVars": []}',
    b'{"collections": []}',
    b'{"collections": {"write": "hc_coll"}}',
    b"{" * 2000,
    b'{"a":' * 1500 + b"1" + b"}" * 1500,
    b'{"query": "RETURN 1", "query": "RETURN 2"}',
    b'{"query": "\\ud800"}',
    b"\xff\xfe\x00\x01",
    b"\x0b\x00\x00\x00\x00",
    b'{"query": "RETURN 1"}' + b" " * 4096 + b"garbage",
    b'{"query": "FOR i IN 1..100000 RETURN i"}',
    b'{"query": "RETURN", "bindVars": {"@c": "hc_coll"}}',
    b'{"query": "RETURN 1", "batchSize": 0}',
    b'{"query": "RETURN 1", "count": "true"}',
    b'{"query": "RETURN 1", "memoryLimit": -1}',
]

BAD_HEADERS = [
    {"Content-Type": VPACK_CT},
    {"Content-Type": TEXT_CT},
    {"Accept": VPACK_CT},
    {"Accept": SEQUENCE_CT},
    {"Accept": "*/*"},
    {"X-Arango-Transaction-Id": "999999999"},
    {"x-arango-trx-id": "not-a-number"},
    {"Authorization": "Bearer " + "A" * 3000},
    {"Authorization": "Basic " + base64.b64encode(b"root:x").decode()},
    {"Authorization": ""},
    {"Content-Encoding": "gzip"},
    {"X-Arango-Allow-Dirty-Read": "true"},
    {"User-Agent": "hc/" + "z" * 2000},
]

BAD_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD", "TRACE"]


def mutate_path(path, rng):
    choice = rng.randrange(9)
    if choice == 0:
        return path + "/.."
    if choice == 1:
        return path + "/%00"
    if choice == 2:
        return path + "?a=1&a=2&b=%zz"
    if choice == 3:
        return path + "#fragment"
    if choice == 4:
        return path.replace("/", "//", 1)
    if choice == 5:
        return path + "/." + "/." * rng.randrange(1, 4)
    if choice == 6:
        return path + "/" + "A" * rng.choice((64, 1024, 8192))
    if choice == 7:
        return path.upper()
    return path + "?"


def relax(step, tag):
    """A mutated step is no longer the scripted one: keep only the protocol oracles."""
    return dataclasses.replace(
        step, expect=None, check=None, capture={}, raw_expect=None,
        mutated=tag or step.mutated,
    )


def mutate(steps, rng, env):
    """Apply one mutation.

    Returns (steps, tag, start, end): the slice [start, end) of the new script
    is the part whose scripted expectations no longer hold — a mutation at
    index i can invalidate every later step, because they depend on the state
    it was supposed to create.
    """
    steps = list(steps)
    if not steps:
        return steps, "none", 0, 0
    kind = rng.choice(
        [
            "insert_junk",
            "malformed_body",
            "duplicate",
            "drop",
            "reorder",
            "token",
            "method",
            "header",
            "path",
            "raw_close",
            "raw_pipeline",
            "raw_junk",
        ]
    )
    index = rng.randrange(len(steps))

    if kind == "insert_junk":
        method, path, body, headers = rng.choice(JUNK_REQUESTS)
        step = Step(f"junk-{index}", method, path, body=body, headers=headers,
                    token=rng.choice(Tokens.ALL_KINDS), mutated="insert_junk")
        steps.insert(index, step)
        return steps, f"insert_junk@{index}:{method} {path}", index, len(steps)

    if kind == "malformed_body":
        candidates = [i for i, s in enumerate(steps) if s.body is not None and s.raw is None]
        if not candidates:
            return steps, "malformed_body:none", 0, 0
        index = rng.choice(candidates)
        steps[index] = dataclasses.replace(
            steps[index], body=rng.choice(BAD_BODIES), expect=None, check=None,
            mutated="malformed_body",
        )
        return steps, f"malformed_body@{index}:{steps[index].name}", index, len(steps)

    if kind == "duplicate":
        step = dataclasses.replace(steps[index], name=steps[index].name + "-dup",
                                   expect=None, check=None, mutated="duplicate")
        steps.insert(index, step)
        return steps, f"duplicate@{index}:{step.name}", index, len(steps)

    if kind == "drop":
        if len(steps) < 2:
            return steps, "drop:none", 0, 0
        removed = steps.pop(index)
        return steps, f"drop@{index}:{removed.name}", index, len(steps)

    if kind == "reorder":
        if len(steps) < 2:
            return steps, "reorder:none", 0, 0
        other = (index + 1) % len(steps)
        steps[index], steps[other] = steps[other], steps[index]
        return steps, f"reorder@{index},{other}", min(index, other), len(steps)

    if kind == "token":
        steps[index] = dataclasses.replace(
            steps[index], token=rng.choice(Tokens.ALL_KINDS), expect=None, check=None,
            mutated="token",
        )
        return steps, f"token@{index}:{steps[index].token}", index, index + 1

    if kind == "method":
        steps[index] = dataclasses.replace(
            steps[index], method=rng.choice(BAD_METHODS), expect=None, check=None,
            mutated="method",
        )
        return steps, f"method@{index}:{steps[index].method} {steps[index].path}", index, len(steps)

    if kind == "header":
        steps[index] = dataclasses.replace(
            steps[index], headers={**steps[index].headers, **rng.choice(BAD_HEADERS)},
            expect=None, check=None, mutated="header",
        )
        return steps, f"header@{index}:{steps[index].name}", index, index + 1

    if kind == "path":
        steps[index] = dataclasses.replace(steps[index], path=mutate_path(steps[index].path, rng),
                                           expect=None, check=None, mutated="path")
        return steps, f"path@{index}:{steps[index].path}", index, len(steps)

    if kind == "raw_close":
        partial = rng.choice(
            [
                b"POST /_api/cursor HTTP/1.1\r\nHost: hc\r\nContent-Length: 500\r\n\r\n{\"query\"",
                b"GET /_api/version HTTP/1.1\r\nHost: hc\r\n",
                b"POST /_api/cursor HTTP/1.1\r\nHost: hc\r\nContent-Length: 20\r\n\r\n{",
                b"GET /_api/version\r\n\r\n",
            ]
        )
        step = Step(f"raw-close-{index}", raw=partial, raw_expect=None, mutated="raw_close")
        steps.insert(index, step)
        return steps, f"raw_close@{index}", index, index + 1

    if kind == "raw_pipeline":
        auth = env.auth_headers("valid").get("Authorization", "")
        payload = b"".join(
            f"{method} {path} HTTP/1.1\r\nHost: hc\r\nAuthorization: {auth}\r\n"
            f"Content-Length: {len(body or b'')}\r\nContent-Type: application/json\r\n\r\n".encode()
            + (body or b"")
            for method, path, body in (
                ("GET", "/_api/version", None),
                ("POST", "/_api/cursor", b'{"query":"RETURN 1"}'),
                ("GET", "/_api/nonexistent", None),
            )
        )
        step = Step(f"raw-pipeline-{index}", raw=payload, raw_expect=(200, 201, 404),
                    mutated="raw_pipeline")
        steps.insert(index, step)
        return steps, f"raw_pipeline@{index}", index, index + 1

    if kind == "raw_junk":
        junk = rng.choice(
            [
                b"GARBAGE\r\n\r\n",
                b"GET /_api/version HTTP/9.9\r\nHost: hc\r\n\r\n",
                b"GET /_api/version HTTP/1.1\r\nHost: hc\r\nX-Junk: " + b"j" * 70000 + b"\r\n\r\n",
                b"GET /_api/version\x00 HTTP/1.1\r\nHost: hc\r\n\r\n",
                b"POST /_api/cursor HTTP/1.1\r\nHost: hc\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
                b"\x00\x01\x02\x03\r\n\r\n",
                b"GET " + b"/" * 8000 + b" HTTP/1.1\r\nHost: hc\r\n\r\n",
                b"GET /_api/version HTTP/1.1\r\n" + b"X-Dup: 1\r\n" * 500 + b"\r\n",
            ]
        )
        step = Step(f"raw-junk-{index}", raw=junk, raw_expect=None, mutated="raw_junk")
        steps.insert(index, step)
        return steps, f"raw_junk@{index}", index, index + 1

    return steps, "none", 0, 0


def mutate_script(conversation, rng, env, count):
    """Apply up to `count` mutations and relax everything they can invalidate.

    From the first mutated step on, the script's own expectations are dropped:
    a mutated step may fail to create the state the later steps assume, so their
    statuses, checks and captures no longer mean what the script says. What
    remains for the whole run is the protocol oracle set.
    """
    steps = list(conversation.steps)
    tags = []
    for _ in range(count):
        steps, tag, start, _end = mutate(steps, rng, env)
        if tag != "none":
            tags.append(tag)
            for index in range(start, len(steps)):
                steps[index] = relax(steps[index], tag)
    return dataclasses.replace(conversation, steps=steps), tags


# ---------------------------------------------------------------------------
# the server under test
# ---------------------------------------------------------------------------
class BootError(RuntimeError):
    pass


def free_port(preferred):
    for candidate in [preferred] + random.sample(range(20000, 40000), 40):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", candidate))
            except OSError:
                continue
            return candidate
    raise BootError("no free port")


class Server:
    """Boots arangod on a temp datadir and watches it for crashes and reports."""

    # Startup noise that is not a finding: rocksdb's crc32c helper trips UBSan's
    # alignment check on every start of this build, before the server listens.
    KNOWN_NOISE = ("crc32c::align_to_8", "crc32c::crc32c_3way")

    def __init__(self, binary, port=DEFAULT_PORT, auth=True, idle_timeout=3.0,
                 datadir=None, extra_args=(), log_level="info", verbose=False):
        self.binary = binary
        self.auth = auth
        self.idle_timeout = idle_timeout
        self.datadir = datadir or tempfile.mkdtemp(prefix="arangod-hc-")
        self.owns_datadir = datadir is None
        self.extra_args = list(extra_args)
        self.log_level = log_level
        self.verbose = verbose
        self.secret = os.urandom(24).hex().encode()
        self.port = free_port(port)
        self.proc = None
        self._stderr_offset = 0
        self._log_offset = 0
        self.starts = 0

    # -- lifecycle ---------------------------------------------------------
    def _paths(self):
        return {
            "db": os.path.join(self.datadir, "db"),
            "secret": os.path.join(self.datadir, "jwtsecret"),
            "log": os.path.join(self.datadir, "arangod.log"),
            "stderr": os.path.join(self.datadir, "stderr.log"),
        }

    def _write_secret(self):
        path = self._paths()["secret"]
        with open(path, "wb") as handle:
            handle.write(self.secret + b"\n")
        os.chmod(path, 0o600)

    def command(self):
        paths = self._paths()
        args = [
            self.binary,
            "--configuration", "none",
            "--database.directory", paths["db"],
            "--server.endpoint", f"tcp://127.0.0.1:{self.port}",
            "--server.authentication", "true" if self.auth else "false",
            "--server.statistics", "false",
            "--transaction.streaming-idle-timeout", str(self.idle_timeout),
            "--log.level", self.log_level,
            "--log.output", "file://" + paths["log"],
        ]
        if self.auth:
            args += ["--server.jwt-secret-keyfile", paths["secret"]]
        args += self.extra_args
        return args

    def start(self):
        os.makedirs(self._paths()["db"], exist_ok=True)
        self._write_secret()
        env = dict(os.environ)
        # UBSan must stay recoverable: this build trips a known alignment check
        # inside rocksdb at startup, and halt_on_error turns that into no server.
        env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:symbolize=1"
        env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=0"
        stderr = open(self._paths()["stderr"], "ab")
        try:
            self.proc = subprocess.Popen(
                self.command(), stdout=stderr, stderr=stderr, env=env,
                cwd=self.datadir, start_new_session=True,
            )
        finally:
            stderr.close()
        self.starts += 1
        self.wait_ready()
        # Everything written so far is startup noise (the rocksdb crc32c UBSan
        # report among it); diagnostics start from here.
        self.reset_diagnostics()
        return self

    def reset_diagnostics(self):
        for key in ("stderr", "log"):
            path = self._paths()[key]
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            if key == "stderr":
                self._stderr_offset = size
            else:
                self._log_offset = size

    def wait_ready(self, timeout=240.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise BootError(
                    f"arangod exited with {self.proc.returncode} during startup:\n"
                    + self.tail()
                )
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    pass
            except OSError:
                time.sleep(0.2)
                continue
            client = Client("127.0.0.1", self.port, timeout=5)
            try:
                resp = client.request("GET", "/_api/version")
            except TransportError:
                time.sleep(0.2)
                continue
            finally:
                client.close()
            # Any HTTP answer means the endpoint is serving: /_api/version is
            # not public in this tree, so 401 is the normal unauthenticated
            # reply and says as much about readiness as 200 does.
            if 200 <= resp.status < 500:
                return self
            time.sleep(0.2)
        raise BootError(f"arangod did not become ready on port {self.port}:\n{self.tail()}")

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def restart(self):
        self.stop()
        self.start()
        return self

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
        self.proc = None

    def cleanup(self):
        self.stop()
        if self.owns_datadir and os.path.isdir(self.datadir):
            shutil.rmtree(self.datadir, ignore_errors=True)

    # -- diagnostics -------------------------------------------------------
    def _read_from(self, path, offset):
        try:
            with open(path, "rb") as handle:
                handle.seek(offset)
                data = handle.read()
                return data, handle.tell()
        except FileNotFoundError:
            return b"", offset

    def diagnostics(self):
        """New sanitizer/assertion reports since the last call, known noise removed."""
        findings = []
        for key in ("stderr", "log"):
            path = self._paths()[key]
            offset = self._stderr_offset if key == "stderr" else self._log_offset
            data, new_offset = self._read_from(path, offset)
            if key == "stderr":
                self._stderr_offset = new_offset
            else:
                self._log_offset = new_offset
            if not data:
                continue
            text = data.decode("utf-8", "replace")
            for marker in ("AddressSanitizer", "runtime error:", "Assertion failed",
                           "Assertion `", "FATAL", "terminate called"):
                if marker in text:
                    lines = [
                        line for line in text.splitlines()
                        if marker in line or "SUMMARY:" in line
                    ]
                    kept = [
                        line for line in lines
                        if not any(noise in line for noise in self.KNOWN_NOISE)
                    ]
                    if kept:
                        findings.append(f"{key}: " + " | ".join(kept[:4])[:600])
                    break
        return findings

    def tail(self, lines=40):
        out = []
        for key in ("log", "stderr"):
            path = self._paths()[key]
            try:
                with open(path, "rb") as handle:
                    data = handle.read().decode("utf-8", "replace")
            except FileNotFoundError:
                continue
            if data:
                out.append(f"--- {key} ---\n" + "\n".join(data.splitlines()[-lines:]))
        return "\n".join(out) or "(no log)"


# ---------------------------------------------------------------------------
# environment and runner
# ---------------------------------------------------------------------------
class Env:
    def __init__(self, host, port, tokens, server=None):
        self.host = host
        self.port = port
        self.tokens = tokens
        self.server = server
        self.collection = COLLECTION
        self.collection2 = COLLECTION2
        self._counter = itertools.count(1)
        self._lock = threading.Lock()

    def new_key(self, prefix="k"):
        with self._lock:
            return f"{prefix}{next(self._counter)}"

    def client(self):
        return Client(self.host, self.port)

    def base_vars(self):
        return {"coll": self.collection, "coll2": self.collection2}

    def auth_headers(self, kind):
        if self.tokens is None or kind == "none":
            return {}
        token = self.tokens.get(kind)
        return {"Authorization": f"Bearer {token}"} if token else {}


CONVERSATIONS = {
    "auth": conv_auth,
    "cursor": conv_cursor,
    "stream": conv_stream,
    "transaction": conv_transaction,
    "transaction-abandoned": conv_transaction_abandoned,
    "batch": conv_batch,
    "replication": conv_replication,
    "concurrent": conv_concurrent,
}


@dataclasses.dataclass
class Finding:
    kind: str
    conversation: str
    step: str
    detail: str
    iteration: int
    seed: int
    trace: list
    tags: list


class Runner:
    def __init__(self, args):
        self.args = args
        self.env = None
        self.server = None
        self.findings = []
        self.counts = {}
        self.requests = 0
        self.soft = {}
        self.iterations_run = 0

    # -- setup -------------------------------------------------------------
    def setup(self):
        if self.args.server_url:
            parsed = urllib.parse.urlparse(self.args.server_url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or DEFAULT_PORT
            secret = self.args.jwt_secret.encode() if self.args.jwt_secret else None
            self.env = Env(host, port, Tokens(secret) if secret else None)
            self.env.collection = COLLECTION
            self.env.collection2 = COLLECTION2
            self.log(f"attached to {host}:{port}")
        else:
            self.server = Server(
                self.args.arangod,
                port=self.args.port,
                auth=not self.args.no_auth,
                idle_timeout=self.args.idle_timeout,
                datadir=self.args.datadir,
                log_level="info" if not self.args.verbose else "debug",
            )
            self.server.start()
            self.log(
                f"arangod up on 127.0.0.1:{self.server.port} "
                f"(auth={'on' if self.server.auth else 'off'}, "
                f"idle-timeout={self.server.idle_timeout}s, datadir={self.server.datadir})"
            )
            tokens = Tokens(self.server.secret) if self.server.auth else None
            self.env = Env("127.0.0.1", self.server.port, tokens, server=self.server)
        self.ensure_schema()

    def ensure_schema(self):
        """Collections the conversations need; idempotent across restarts."""
        client = self.env.client()
        for name in (COLLECTION, COLLECTION2):
            resp = client.request("POST", "/_api/collection", json.dumps({"name": name}).encode(),
                                  {**self.env.auth_headers("valid"), "Content-Type": JSON_CT})
            if resp.status not in (200, 201, 409):
                raise BootError(f"cannot create collection {name}: {preview(resp)}")
            ok, value = resp.json_ok()
            if ok and isinstance(value, dict) and value.get("error") is True \
                    and value.get("errorNum") != 1207:
                raise BootError(f"cannot create collection {name}: {preview(resp)}")
        client.close()

    def available(self, include_slow):
        names = self.args.conversations.split(",") if self.args.conversations else list(CONVERSATIONS)
        out = []
        for name in names:
            name = name.strip()
            if name not in CONVERSATIONS:
                raise SystemExit(f"unknown conversation {name!r}; try --list")
            if name == "auth" and self.env.tokens is None:
                continue
            if CONVERSATIONS[name](self.env).slow and not include_slow:
                continue
            out.append(name)
        return out

    # -- one conversation --------------------------------------------------
    def build(self, name):
        conversation = CONVERSATIONS[name](self.env)
        return conversation

    def run_conversation(self, conversation, seed, iteration, tags):
        sessions = []
        if conversation.threads:
            results = [None] * len(conversation.threads)
            errors = []

            def worker(index, steps):
                try:
                    session = Session(self.env, conversation.name, steps)
                    results[index] = session.run()
                except Exception:
                    errors.append(traceback.format_exc(limit=6))

            threads = [
                threading.Thread(target=worker, args=(index, steps), daemon=True)
                for index, steps in enumerate(conversation.threads)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=180)
            for message in errors:
                self.record("harness-exception", conversation.name, "", message,
                            iteration, seed, [], tags)
            sessions = [session for session in results if session is not None]
            self.check_concurrent(conversation, sessions, iteration, seed, tags)
        else:
            session = Session(self.env, conversation.name, conversation.steps)
            session.run()
            sessions = [session]

        for session in sessions:
            self.requests += len(session.trace)
            for kind, detail in session.soft:
                self.soft[kind] = self.soft.get(kind, 0) + 1
            for violation in session.violations:
                self.record(violation.kind, conversation.name, violation.step,
                            violation.detail, iteration, seed, session.trace, tags)
            if conversation.post is not None and not session.crashed:
                before = len(session.violations)
                try:
                    conversation.post(self.env, session)
                except TransportError as exc:
                    session.fail("transport", f"post-check: {exc}", "post")
                except Exception:
                    session.fail("check-exception", traceback.format_exc(limit=6), "post")
                for violation in session.violations[before:]:
                    self.record(violation.kind, conversation.name, violation.step,
                                violation.detail, iteration, seed, session.trace, tags)
        return sessions

    def check_concurrent(self, conversation, sessions, iteration, seed, tags):
        if len(sessions) < 2:
            return
        results = [session.state.get("results", []) for session in sessions]
        cursors = [session.vars.get("c") for session in sessions]
        if len(set(cursors)) != len(cursors):
            self.record("cursor-id-duplicate", conversation.name, "create",
                        f"concurrent cursors share an id: {cursors}",
                        iteration, seed, [], tags)
        if results[0] != results[1]:
            self.record("cursor-interference", conversation.name, "drain",
                        f"same query, different results: {results[0]!r} vs {results[1]!r}",
                        iteration, seed, [], tags)
        if sorted(results[0]) != list(range(1, 13)):
            self.record("cursor-results", conversation.name, "drain",
                        f"cursor returned {results[0]!r}, wanted 1..12",
                        iteration, seed, [], tags)

    # -- campaign ----------------------------------------------------------
    def campaign(self):
        # Every script runs unmutated first: that is how a harness bug in a
        # script is told apart from a server violation.
        for name in self.available(include_slow=True):
            self.run_conversation(self.build(name), self.args.seed, -1, ["verify"])
            self.counts[name] = self.counts.get(name, 0) + 1
            if not self.server_ok():
                return
        self.log(
            f"verify pass done: {self.requests} requests, "
            f"{len(self.findings)} finding(s)"
        )
        if self.args.verify_only:
            return
        names = self.fuzz_names()
        self.log(f"fuzzing: {', '.join(names)}")
        for iteration in range(self.args.iterations):
            self.iterations_run += 1
            rng = random.Random(f"{self.args.seed}:{iteration}")
            name = rng.choice(names)
            conversation = self.build(name)
            conversation, tags = mutate_script(
                conversation, rng, self.env,
                rng.randrange(0, self.args.mutations + 1),
            )
            self.run_conversation(conversation, self.args.seed, iteration, tags)
            self.counts[name] = self.counts.get(name, 0) + 1
            if self.args.progress and (iteration + 1) % self.args.progress == 0:
                self.log(
                    f"  {iteration + 1}/{self.args.iterations} iterations, "
                    f"{self.requests} requests, {len(self.findings)} finding(s)"
                )
            if not self.server_ok():
                return

    def fuzz_names(self):
        """The list rng.choice indexes into; --replay must see the same one."""
        return self.available(self.args.include_slow)

    def server_ok(self):
        if self.server is None:
            return True
        if not self.server.alive():
            self.record("server-crash", "server", "", "arangod is gone",
                        0, self.args.seed, [], ["crash"])
            if self.args.restarts <= 0:
                return False
            self.log("server died; restarting")
            try:
                self.server.restart()
            except BootError as exc:
                self.record("server-boot", "server", "", str(exc)[:2000], 0,
                            self.args.seed, [], ["crash"])
                return False
            self.ensure_schema()
            return True
        for report in self.server.diagnostics():
            self.record("sanitizer", "server", "", report, 0, self.args.seed, [], [])
        return True

    def replay(self):
        seed, _, iteration = self.args.replay.partition(":")
        self.args.seed = int(seed)
        names = self.fuzz_names()
        for index in range(int(iteration or 0), int(iteration or 0) + 1):
            rng = random.Random(f"{self.args.seed}:{index}")
            name = rng.choice(names)
            conversation = self.build(name)
            conversation, tags = mutate_script(
                conversation, rng, self.env,
                rng.randrange(0, self.args.mutations + 1),
            )
            self.log(f"replaying {name} iteration {index} tags={tags}")
            self.run_conversation(conversation, self.args.seed, index, tags)
        self.dump_traces()

    def dump_traces(self):
        for finding in self.findings:
            self.log(f"\n[{finding.kind}] {finding.conversation}/{finding.step}: {finding.detail}")
            for entry in finding.trace:
                self.log(f"    {entry}")

    # -- reporting ---------------------------------------------------------
    def record(self, kind, conversation, step, detail, iteration, seed, trace, tags):
        self.findings.append(
            Finding(kind, conversation, step, detail, iteration, seed,
                    list(trace[-12:]), list(tags))
        )

    def log(self, message):
        print(message, flush=True)

    def report(self):
        self.log("")
        self.log("=" * 72)
        self.log(
            f"http_conversation: {self.iterations_run} fuzz iterations, "
            f"{self.requests} requests, seed {self.args.seed}"
        )
        if self.counts:
            self.log("  conversations: " + ", ".join(f"{k} x{v}" for k, v in sorted(self.counts.items())))
        if self.soft:
            self.log("  soft observations: " + ", ".join(f"{k} x{v}" for k, v in sorted(self.soft.items())))
        if not self.findings:
            self.log("  no protocol violations")
            self.log("=" * 72)
            return 0
        self.log(f"  {len(self.findings)} violation(s):")
        seen = {}
        for finding in self.findings:
            key = (finding.kind, finding.conversation, finding.step)
            seen.setdefault(key, []).append(finding)
        for (kind, conversation, step), group in sorted(seen.items(), key=lambda kv: -len(kv[1])):
            first = group[0]
            self.log(f"  [{kind}] x{len(group)}  {conversation}/{step}")
            self.log(f"      {first.detail}")
            if first.iteration < 0:
                self.log(f"      repro: --verify-only --conversations {conversation}")
            else:
                self.log(f"      repro: --replay {first.seed}:{first.iteration}  tags={first.tags}")
            if self.args.verbose:
                for entry in first.trace:
                    self.log(f"      {entry}")
        self.log("=" * 72)
        return 1


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Multi-request HTTP conversation fuzzer for ArangoDB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[1].split("Measured API")[0] if "Usage:" in __doc__ else "",
    )
    parser.add_argument("-n", "--iterations", type=int, default=100,
                        help="fuzz iterations after the verify pass (default 100)")
    parser.add_argument("--seed", type=int, default=1, help="campaign seed (default 1)")
    parser.add_argument("--mutations", type=int, default=3,
                        help="maximum mutations applied to one script (default 3)")
    parser.add_argument("--arangod", default=DEFAULT_ARANGOD, help="arangod binary")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port to try first (default {DEFAULT_PORT})")
    parser.add_argument("--datadir", default=None, help="reuse a datadir instead of a temp one")
    parser.add_argument("--idle-timeout", type=float, default=3.0,
                        help="--transaction.streaming-idle-timeout for the booted server")
    parser.add_argument("--no-auth", action="store_true",
                        help="boot without authentication (drops the auth conversation)")
    parser.add_argument("--server-url", default=None,
                        help="attach to a running server instead of booting one")
    parser.add_argument("--jwt-secret", default=None,
                        help="secret to forge tokens with when attaching")
    parser.add_argument("--conversations", default=None,
                        help="comma separated subset (see --list)")
    parser.add_argument("--include-slow", action="store_true",
                        help="include conversations that wait for a server-side timeout")
    parser.add_argument("--verify-only", action="store_true",
                        help="run every script unmutated and stop")
    parser.add_argument("--replay", default=None, metavar="SEED:ITER",
                        help="re-run one iteration and print its trace")
    parser.add_argument("--restarts", type=int, default=2,
                        help="how often a dead server is restarted (default 2)")
    parser.add_argument("--progress", type=int, default=25,
                        help="print progress every N iterations (0 = never)")
    parser.add_argument("--keep", action="store_true", help="keep the temp datadir")
    parser.add_argument("--verbose", action="store_true", help="print traces of violations")
    parser.add_argument("--list", action="store_true", help="list conversations and exit")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.list:
        for name, builder in CONVERSATIONS.items():
            slow = " (slow)" if name == "transaction-abandoned" else ""
            print(f"{name}{slow}")
        return 0
    runner = Runner(args)
    status = 0
    try:
        runner.setup()
        if args.replay:
            runner.replay()
        else:
            runner.campaign()
        status = runner.report()
    except BootError as exc:
        print(f"cannot start the server under test:\n{exc}", file=sys.stderr)
        status = 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        status = 130
    finally:
        if runner.server is not None:
            if args.keep:
                print(f"datadir kept at {runner.server.datadir}")
                runner.server.stop()
            else:
                runner.server.cleanup()
    return status


if __name__ == "__main__":
    sys.exit(main())
