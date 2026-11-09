#!/usr/bin/env python3
"""Privilege / roles fuzzer for ArangoDB — out-of-process, AQL and REST.

The shape of the test: one server, two ordinary users.  ``victim`` owns a
database with a secret collection whose documents carry a canary string.
``attacker`` is a normal user who must never reach that data.  Every request in
this file is sent with the attacker's JWT and checked against the victim's data
before and after.

Grant profiles
--------------
Two profiles are run, because they exercise different code paths:

``outsider``
    the attacker has no grant on the victim database at all.  Only the
    database-level gate and cross-database references (``DOCUMENT("db/coll/k")``,
    ``/_db/victimdb/...``) can be reached.

``collection-denied``
    the attacker has read on the victim database but an explicit ``none`` on
    the secret collection (and on the edge collection).  Queries execute, so
    every AQL function that resolves a collection *by name* is exercised:
    ``DOCUMENT``, ``SHARD_ID``, ``COLLECTION_COUNT``, ``SCHEMA_GET``,
    ``COLLECTIONS``, views, graph traversals, streaming transactions.

Oracles
-------
R1 canary        a canary string appears in the attacker's response.  Each
                 canary is planted in exactly one object, so a hit names what
                 leaked (document data vs. analyzer config vs. edge label).
R2 data-equal    a read probe marked ``victim_data`` gets a 2xx whose result is
                 byte-identical (after stripping volatile fields) to the
                 superuser's result, and that result is not a silent miss
                 (``[null]``/``[]``).  Catches leaks that carry no canary
                 (counts, keys, existence).
R3 denied-but-2xx  a probe that must be refused answers 2xx.
R4 write         the victim's data fingerprint changed.
R5 escalation    the attacker's own grants, or the user list, changed.
R6 crash         the server died mid-run (it is a sanitized build; a crash is
                 a finding, with the stderr tail attached).
R7 name          a successful response names a collection the attacker cannot
                 read (metadata such as graph definitions is readable at
                 database level).
R8 existence     a denied collection and a missing one answer with different
                 error codes, so names can be enumerated.

A query that answers 2xx with a *silent* miss (``[null]``, ``[]``) is not a
finding: the target did not resolve for the superuser either.

The superuser's result for each read probe is fetched first and used as the
ground truth; it also primes the AQL query cache and the plan cache, so the
attacker's identical query exercises the caches' permission checks.

Usage
-----
    python3 fuzz/privilege_fuzzer.py --arangod /build/build-asan/bin/arangod
    python3 fuzz/privilege_fuzzer.py --quick --fail-on high
    python3 fuzz/privilege_fuzzer.py --self-test      # prove the oracles fire
    python3 fuzz/privilege_fuzzer.py --attach http://127.0.0.1:8529 --jwt-secret <hex>

--self-test over-grants the attacker on purpose and fails unless the canary
and denied-but-2xx oracles report it, so an empty report can be told apart
from a broken oracle.

Exit status: 0 no finding at or above --fail-on, 1 findings, 2 harness error.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

# --------------------------------------------------------------------------
# the fixture
# --------------------------------------------------------------------------

VICTIM_DB = "victimdb"
ATTACKER_DB = "attackerdb"
SYSTEM_DB = "_system"

SECRET_COLL = "secret_coll"
SECRET_EDGES = "secret_edges"
SECRET_VIEW = "secret_view"
SECRET_ANALYZER = "secret_analyzer"
SECRET_GRAPH = "secret_graph"
PUBLIC_COLL = "victim_public_coll"      # canary data in _system
ATTACKER_COLL = "attacker_coll"         # control: the attacker may read this

VICTIM_USER = "victim"
VICTIM_PASSWD = "victimpass"
ATTACKER_USER = "attacker"
ATTACKER_PASSWD = "attackerpass"

CANARY_DATA = "CANARY_VICTIM_DATA_12345"
CANARY_ANALYZER = "CANARY_VICTIM_ANALYZER_67890"
CANARY_EDGE = "CANARY_VICTIM_EDGE_24680"
CANARY_CONTROL = "CANARY_ATTACKER_DATA_13579"

# canary -> (where it was planted, data|meta, what a hit means)
CANARIES = {
    CANARY_DATA: (f"{VICTIM_DB}.{SECRET_COLL} documents", "data",
                  "document data from a collection the attacker cannot read"),
    CANARY_EDGE: (f"{VICTIM_DB}.{SECRET_EDGES} edge documents", "data",
                  "edge data from a collection the attacker cannot read"),
    CANARY_ANALYZER: (f"{VICTIM_DB}::{SECRET_ANALYZER} analyzer properties", "meta",
                      "analyzer configuration, readable at database level even "
                      "though the linked collection is denied"),
    CANARY_CONTROL: (f"{ATTACKER_DB}.{ATTACKER_COLL} (control, readable by attacker)",
                     "control", "control: the attacker's own data"),
}

# collection names the attacker must not be able to learn about
DENIED_NAMES = (SECRET_COLL, SECRET_EDGES)

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


# --------------------------------------------------------------------------
# JWT (HS256, the server's --server.jwt-secret)
# --------------------------------------------------------------------------


def _b64url(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def make_jwt(secret: str, user: str, ttl: int = 3600) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"},
                                separators=(",", ":")).encode())
    claims = _b64url(json.dumps({"preferred_username": user, "iss": "arangodb",
                                 "exp": int(time.time()) + ttl},
                                separators=(",", ":")).encode())
    signature = _b64url(hmac.new(secret.encode(), header + b"." + claims,
                                 hashlib.sha256).digest())
    return (header + b"." + claims + b"." + signature).decode()


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


def _empty(value) -> bool:
    """True for null / empty containers — a miss, not a value."""
    if value is None:
        return True
    if isinstance(value, dict):
        return all(_empty(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return len(value) == 0 or all(_empty(item) for item in value)
    if isinstance(value, str):
        return len(value) == 0
    return False


class Response:
    __slots__ = ("status", "body")

    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body

    def json(self):
        try:
            return json.loads(self.body)
        except ValueError:
            return None

    def is_error_body(self) -> bool:
        doc = self.json()
        return isinstance(doc, dict) and doc.get("error") is True

    def success(self) -> bool:
        return 200 <= self.status < 300 and not self.is_error_body()

    def result(self):
        """The AQL ``result`` array, or None."""
        doc = self.json()
        if isinstance(doc, dict) and "result" in doc:
            return doc["result"]
        return None

    def brief(self, limit: int = 400) -> str:
        text = " ".join(self.body.split())
        return text if len(text) <= limit else text[:limit] + "..."


class Api:
    def __init__(self, base: str, secret: str, timeout: float = 60.0):
        self.base = base.rstrip("/")
        self.secret = secret
        self.timeout = timeout
        self._tokens: dict[str, str] = {}
        self.requests = 0

    def token(self, user: str) -> str:
        if user not in self._tokens:
            self._tokens[user] = make_jwt(self.secret, user)
        return self._tokens[user]

    def request(self, method: str, path: str, *, as_user: str | None = None,
                body=None, db: str | None = None, headers=None) -> Response:
        url = self.base
        if db is not None:
            url += "/_db/" + urllib.request.quote(db, safe="")
        url += path
        data = None
        if body is not None:
            data = json.dumps(body).encode() if not isinstance(body, bytes) else body
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if as_user:
            req.add_header("Authorization", "Bearer " + self.token(as_user))
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        self.requests += 1
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return Response(resp.status, raw.decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            return Response(exc.code, raw.decode("utf-8", "replace"))

    def get(self, path: str, **kw) -> Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, body=None, **kw) -> Response:
        return self.request("POST", path, body=body, **kw)

    def put(self, path: str, body=None, **kw) -> Response:
        return self.request("PUT", path, body=body, **kw)

    def delete(self, path: str, body=None, **kw) -> Response:
        return self.request("DELETE", path, body=body, **kw)

    def aql(self, query: str, *, db: str, as_user: str,
            bind_vars=None, options=None, headers=None) -> Response:
        body = {"query": query}
        if bind_vars:
            body["bindVars"] = bind_vars
        if options:
            body["options"] = options
        return self.post("/_api/cursor", body, as_user=as_user, db=db,
                         headers=headers)


# --------------------------------------------------------------------------
# the server under test
# --------------------------------------------------------------------------


class BootError(RuntimeError):
    pass


class SetupError(RuntimeError):
    pass


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ArangodServer:
    """Starts a real arangod with authentication on and a random JWT secret."""

    def __init__(self, binary: str, datadir: str, port: int,
                 extra_args: list[str] | None = None,
                 startup_timeout: float = 180.0):
        self.binary = binary
        self.datadir = datadir
        self.port = port
        self.extra_args = list(extra_args or [])
        self.startup_timeout = startup_timeout
        self.proc: subprocess.Popen | None = None
        self.secret = ""
        self.stderr_path = os.path.join(datadir, "arangod.stderr")
        self._stderr = None
        self.base_url = f"http://127.0.0.1:{port}"

    # -- args ------------------------------------------------------------
    def _secret_file(self) -> str:
        path = os.path.join(self.datadir, "jwt.secret")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.secret)
        return path

    def _args(self) -> list[str]:
        return [
            self.binary,
            "--configuration", "none",
            "--server.endpoint", f"tcp://127.0.0.1:{self.port}",
            "--database.directory", self.datadir,
            "--server.authentication", "true",
            "--server.jwt-secret-keyfile", self._secret_file(),
            "--javascript.enabled", "false",
            "--log.output", "file://" + os.path.join(self.datadir, "arangod.log"),
            "--log.level", "info",
            # the query result cache has its own permission check; keep it on so
            # the attacker's identical query meets it
            "--query.cache-mode", "on",
            "--query.cache-entries", "64",
        ] + self.extra_args

    # -- lifecycle -------------------------------------------------------
    def start(self) -> None:
        if not os.path.isfile(self.binary):
            raise BootError(f"arangod binary not found: {self.binary}")
        self.secret = hashlib.sha256(os.urandom(32)).hexdigest()
        os.makedirs(self.datadir, exist_ok=True)

        env = dict(os.environ)
        # this is a sanitized build: a crash is what we want to see, leaks at
        # exit are noise, and UBSan reports (rocksdb has a few) must not kill
        # the server on every startup
        env["ASAN_OPTIONS"] = env.get(
            "ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1:handle_abort=1")
        env["UBSAN_OPTIONS"] = env.get("UBSAN_OPTIONS", "halt_on_error=0:print_stacktrace=0")

        args = self._args()
        for _ in range(6):
            self._stderr = open(self.stderr_path, "ab")
            self.proc = subprocess.Popen(args, stdout=self._stderr,
                                         stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True)
            if self._wait_ready():
                return
            tail = self.log_tail(4000)
            self.stop()
            # a version that does not know an option we passed: drop it
            match = re.search(r"unknown option '(--[a-z0-9.-]+)'", tail)
            if match:
                unknown = match.group(1)
                args = [a for a in args if a != unknown]
                if unknown == "--server.jwt-secret-keyfile":
                    # pre-3.12 spelling
                    args += ["--server.jwt-secret", self.secret]
                continue
            raise BootError(f"arangod did not come up:\n{tail}")
        raise BootError("arangod did not come up after dropping unknown options")

    def _wait_ready(self) -> bool:
        deadline = time.time() + self.startup_timeout
        url = self.base_url + "/_api/version"
        while time.time() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                return False
            try:
                with urllib.request.urlopen(url, timeout=2) as resp:
                    resp.read()
                    return True
            except urllib.error.HTTPError:
                # 401 without a token: the server is up and authenticating
                return True
            except (urllib.error.URLError, ConnectionError, OSError):
                time.sleep(0.25)
        return False

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def log_tail(self, limit: int = 4000) -> str:
        try:
            with open(self.stderr_path, "rb") as handle:
                data = handle.read()
        except OSError:
            return ""
        text = data.decode("utf-8", "replace")
        return text[-limit:]

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=30)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    self.proc.kill()
                    self.proc.wait(timeout=10)
                except (subprocess.TimeoutExpired, OSError):
                    pass
        if self._stderr is not None:
            try:
                self._stderr.close()
            except OSError:
                pass
            self._stderr = None


# --------------------------------------------------------------------------
# probes
# --------------------------------------------------------------------------


class Probe:
    """One request, its expected outcome and what it is trying to reach."""

    __slots__ = ("pid", "family", "kind", "db", "method", "path", "body",
                 "headers", "touches", "expect", "write", "note")

    def __init__(self, pid, family, kind, db, method, path, *, body=None,
                 headers=None, touches="victim_data", expect="denied",
                 write=False, note=""):
        self.pid = pid
        self.family = family
        self.kind = kind
        self.db = db
        self.method = method
        self.path = path
        self.body = body
        self.headers = headers
        self.touches = touches
        self.expect = expect
        self.write = write
        self.note = note

    def describe(self) -> str:
        if self.kind == "aql":
            query = (self.body or {}).get("query", "")
            extra = ""
            bind = (self.body or {}).get("bindVars")
            if bind:
                extra = f"  bindVars={json.dumps(bind, sort_keys=True)}"
            return f"[{self.db}] AQL {query}{extra}"
        return f"[{self.db}] {self.method} {self.path}"

    def key(self) -> tuple:
        return (self.db, self.method, self.path,
                json.dumps(self.body, sort_keys=True) if self.body else "",
                json.dumps(self.headers, sort_keys=True) if self.headers else "")


class Profile:
    def __init__(self, name: str, no_db_access: bool, note: str):
        self.name = name
        self.no_db_access = no_db_access
        self.note = note


PROFILES = [
    Profile("outsider", True,
            "attacker has no grant on victimdb"),
    Profile("collection-denied", False,
            "attacker has ro on victimdb but none on secret_coll/secret_edges"),
]


def expected_outcome(touches: str, profile: Profile, db: str,
                     must_be_denied: bool = False) -> str:
    """What a correct server does, for this probe, under this profile.

    denied  -- must be refused (4xx); a 2xx is a finding
    silent  -- may succeed, but can only return a silent miss (no victim data
               can be reached from this database); only the canary oracle applies
    allowed -- a control: the attacker may legitimately see this
    unknown -- metadata: may succeed, judged by the canary / name oracles
    """
    if db == VICTIM_DB and profile.no_db_access:
        return "denied"
    if must_be_denied:
        return "denied"
    if touches == "victim_data":
        return "denied" if db == VICTIM_DB else "silent"
    if touches == "system":
        return "denied" if db == SYSTEM_DB else "silent"
    if touches == "control":
        return "allowed"
    return "unknown"


# AQL seeds.  ``mutable`` seeds get the name-obfuscation mutations; ``write``
# seeds are never run as the superuser (they would change the fixture).
SEEDS = [
    # --- DOCUMENT ---------------------------------------------------------
    dict(f="document", q='RETURN DOCUMENT("secret_coll/k1")', t="victim_data", mutable=True,
         note="DOCUMENT by document id"),
    dict(f="document", q='RETURN DOCUMENT("secret_coll", "k1")', t="victim_data", mutable=True,
         note="DOCUMENT by collection + key"),
    dict(f="document", q='RETURN DOCUMENT(["secret_coll/k1", "secret_coll/k2"])', t="victim_data",
         note="DOCUMENT with an array of ids"),
    dict(f="document", q='RETURN DOCUMENT("victimdb/secret_coll/k1")', t="victim_data",
         note="DOCUMENT with a database-qualified id"),
    dict(f="document", q='RETURN DOCUMENT("victimdb::secret_coll/k1")', t="victim_data",
         note="DOCUMENT with a ::-qualified name"),
    dict(f="document", q='RETURN NOOPT(DOCUMENT("secret_coll/k1"))', t="victim_data",
         note="DOCUMENT behind NOOPT"),
    dict(f="document", q='RETURN DOCUMENT(@@c, @k)', t="victim_data",
         bv={"@c": SECRET_COLL, "k": "k1"}, note="DOCUMENT with bind parameters"),

    # --- SHARD_ID (the audit claim: no permission check) ------------------
    dict(f="shard_id", q='RETURN SHARD_ID("secret_coll", {})', t="victim_meta",
         d=True, mutable=True,
         note="SHARD_ID: cluster branch uses ClusterInfo without a permission check"),
    dict(f="shard_id", q='RETURN SHARD_ID("secret_coll", {_key: "k1"})', t="victim_meta",
         d=True, note="SHARD_ID with a shard key"),
    dict(f="shard_id", q='RETURN SHARD_ID("secret_edges", {})', t="victim_meta",
         d=True, note="SHARD_ID on the edge collection"),
    dict(f="shard_id", q=f'RETURN SHARD_ID("{PUBLIC_COLL}", {{}})', t="victim_meta",
         d=True, dbs=[SYSTEM_DB], note="SHARD_ID in _system"),

    # --- other collection-name functions ---------------------------------
    dict(f="collection_fn", q='RETURN COLLECTION_COUNT("secret_coll")', t="victim_data",
         mutable=True, note="COLLECTION_COUNT"),
    dict(f="collection_fn", q=f'RETURN COLLECTION_COUNT("{PUBLIC_COLL}")', t="victim_data",
         dbs=[SYSTEM_DB], note="COLLECTION_COUNT in _system"),
    dict(f="collection_fn", q='RETURN COLLECTIONS()', t="victim_meta",
         note="COLLECTIONS(): the list must be filtered"),
    dict(f="collection_fn", q='RETURN SCHEMA_GET("secret_coll")', t="victim_meta",
         d=True, note="SCHEMA_GET"),
    dict(f="collection_fn", q='RETURN IS_SAME_COLLECTION("secret_coll", "secret_coll")',
         t="control", note="name comparison only, no data"),

    # --- iteration --------------------------------------------------------
    dict(f="for", q='FOR d IN secret_coll RETURN d', t="victim_data", mutable=True,
         note="full scan"),
    dict(f="for", q='FOR d IN secret_coll RETURN d.v', t="victim_data", mutable=True,
         note="full scan, one attribute"),
    dict(f="for", q='FOR d IN secret_coll LIMIT 1 RETURN d', t="victim_data",
         note="scan with LIMIT"),
    dict(f="for", q=f'FOR d IN secret_coll FILTER d.v == "{CANARY_DATA}" RETURN d._key',
         t="victim_data", mutable=True, note="scan with the canary in a FILTER"),
    dict(f="for", q='RETURN LENGTH(FOR d IN secret_coll RETURN 1)', t="victim_data",
         mutable=True, note="count via a subquery"),
    dict(f="for", q='RETURN FIRST(FOR d IN secret_coll RETURN d)', t="victim_data",
         note="FIRST over a subquery"),
    dict(f="for", q='LET x = (FOR d IN secret_coll RETURN d) RETURN LENGTH(x)', t="victim_data",
         note="subquery bound to a LET"),
    dict(f="for", q='FOR d IN @@c RETURN d', t="victim_data",
         bv={"@c": SECRET_COLL}, note="collection name from a bind parameter"),
    dict(f="for", q='RETURN LENGTH(secret_coll)', t="victim_data",
         note="collection as an expression operand"),

    # --- views ------------------------------------------------------------
    dict(f="view", q='FOR d IN secret_view RETURN d', t="victim_data", mutable=True,
         note="ArangoSearch view over the denied collection"),
    dict(f="view", q=f'FOR d IN secret_view SEARCH d.v == "{CANARY_DATA}" RETURN d',
         t="victim_data", note="SEARCH over the view"),
    dict(f="view", q='FOR d IN secret_view RETURN d._key', t="victim_data",
         note="view, keys only"),
    dict(f="view", q='RETURN LENGTH(FOR d IN secret_view RETURN 1)', t="victim_data",
         note="view, count"),
    dict(f="view", q=f'FOR d IN secret_view SEARCH ANALYZER(d.v == "{CANARY_DATA}", '
                     f'"{SECRET_ANALYZER}") RETURN d', t="victim_data",
         note="view SEARCH with the victim's analyzer"),

    # --- graphs -----------------------------------------------------------
    dict(f="graph", q='FOR v IN 1..2 OUTBOUND "secret_coll/k1" GRAPH "secret_graph" RETURN v',
         t="victim_data", note="traversal via a named graph"),
    dict(f="graph", q='FOR v IN 1..2 OUTBOUND "secret_coll/k1" secret_edges RETURN v',
         t="victim_data", note="traversal via an edge collection"),
    dict(f="graph", q='FOR v,e,p IN 1..2 ANY "secret_coll/k1" GRAPH "secret_graph" RETURN p',
         t="victim_data", note="path traversal via a named graph"),

    # --- metadata collections --------------------------------------------
    dict(f="metadata", q='FOR g IN _graphs RETURN g', t="victim_meta",
         note="_graphs: graph definitions name the denied collections"),
    dict(f="metadata", q='FOR a IN _analyzers RETURN a', t="victim_meta",
         note="_analyzers: analyzer properties"),
    # a neutral word on purpose: the point is whether the analyzer is usable,
    # and a canary here would only be echoed back from the query itself
    dict(f="metadata", q=f'RETURN TOKENS("confidential", "{SECRET_ANALYZER}")',
         t="victim_meta", note="TOKENS with the victim's analyzer"),
    dict(f="metadata", q=f'RETURN TOKENS("confidential", "victimdb::{SECRET_ANALYZER}")',
         t="victim_meta", note="TOKENS with a database-qualified analyzer"),

    # --- system collections ----------------------------------------------
    dict(f="system", q='FOR u IN _users RETURN u', t="system",
         note="_users is always NONE for non-superusers"),
    dict(f="system", q='RETURN DOCUMENT("_users/root")', t="system",
         note="_users document by id"),
    dict(f="system", q='FOR s IN _statistics RETURN s', t="system",
         note="_statistics (absent in 4.0)"),
    dict(f="system", q='FOR q IN _queues RETURN q', t="system", note="_queues"),
    dict(f="system", q='FOR f IN _frontend RETURN f', t="system", note="_frontend"),

    # --- victim data in _system ------------------------------------------
    dict(f="system_data", q=f'FOR d IN {PUBLIC_COLL} RETURN d', t="victim_data",
         dbs=[SYSTEM_DB], mutable=True, note="canary collection in _system"),
    dict(f="system_data", q=f'RETURN DOCUMENT("{PUBLIC_COLL}/p1")', t="victim_data",
         dbs=[SYSTEM_DB], note="canary document in _system"),

    # --- controls ---------------------------------------------------------
    dict(f="control", q='RETURN 1', t="control", note="control: always allowed"),
    dict(f="control", q='RETURN CURRENT_USER()', t="control", note="control: identity"),
    dict(f="control", q='RETURN VERSION()', t="control", note="control: server version"),
    dict(f="control", q='FOR d IN attacker_coll RETURN d', t="control", dbs=[ATTACKER_DB],
         note="control: the attacker's own collection"),
    dict(f="control", q='RETURN DOCUMENT("attacker_coll/a1")', t="control",
         dbs=[ATTACKER_DB], note="control: the attacker's own document"),

    # --- writes (never run as root) --------------------------------------
    dict(f="write", q='INSERT {_key: "attacker-was-here", v: "pwn"} INTO secret_coll RETURN NEW',
         t="victim_data", dbs=[VICTIM_DB], write=True, note="INSERT into the denied collection"),
    dict(f="write", q='UPDATE "k1" WITH {v: "pwn"} IN secret_coll RETURN NEW',
         t="victim_data", dbs=[VICTIM_DB], write=True, note="UPDATE in the denied collection"),
    dict(f="write", q='REPLACE "k1" WITH {v: "pwn"} IN secret_coll RETURN NEW',
         t="victim_data", dbs=[VICTIM_DB], write=True, note="REPLACE in the denied collection"),
    dict(f="write", q='REMOVE "k1" IN secret_coll RETURN OLD',
         t="victim_data", dbs=[VICTIM_DB], write=True, note="REMOVE from the denied collection"),
    dict(f="write", q='UPSERT {_key: "k1"} INSERT {_key: "k1"} UPDATE {v: "pwn"} '
                      'IN secret_coll RETURN NEW',
         t="victim_data", dbs=[VICTIM_DB], write=True, note="UPSERT in the denied collection"),
    dict(f="write", q='LET x = (INSERT {_key: "attacker-was-here-2"} INTO secret_coll '
                      'RETURN NEW) RETURN x',
         t="victim_data", dbs=[VICTIM_DB], write=True, note="INSERT inside a subquery"),
    dict(f="write", q='INSERT {v: "pwn"} INTO _users RETURN NEW',
         t="system", dbs=[SYSTEM_DB], write=True, note="INSERT into _users"),
    dict(f="write", q=f'UPDATE "p1" WITH {{v: "pwn"}} IN {PUBLIC_COLL} RETURN NEW',
         t="victim_data", dbs=[SYSTEM_DB], write=True, note="UPDATE canary document in _system"),
]

# REST probes: (family, method, path, body, touches, db, write, note)
REST_PROBES = [
    # victimdb, reads
    ("rest", "GET", "/_api/collection/" + SECRET_COLL, None, "victim_data", VICTIM_DB, False,
     "collection info"),
    ("rest", "GET", f"/_api/collection/{SECRET_COLL}/count", None, "victim_data", VICTIM_DB,
     False, "document count"),
    ("rest", "GET", f"/_api/collection/{SECRET_COLL}/properties", None, "victim_data",
     VICTIM_DB, False, "collection properties"),
    ("rest", "GET", f"/_api/collection/{SECRET_COLL}/figures", None, "victim_data",
     VICTIM_DB, False, "collection figures"),
    ("rest", "GET", f"/_api/collection/{SECRET_COLL}/checksum", None, "victim_data",
     VICTIM_DB, False, "checksum"),
    ("rest", "GET", f"/_api/collection/{SECRET_COLL}/revision", None, "victim_data",
     VICTIM_DB, False, "revision"),
    ("rest", "GET", f"/_api/collection/{SECRET_COLL}/responsibleShard", None, "victim_meta",
     VICTIM_DB, False, "responsible shard"),
    ("rest", "GET", f"/_api/index?collection={SECRET_COLL}", None, "victim_data",
     VICTIM_DB, False, "index list"),
    ("rest", "GET", f"/_api/document/{SECRET_COLL}/k1", None, "victim_data", VICTIM_DB,
     False, "document by id"),
    ("rest", "HEAD", f"/_api/document/{SECRET_COLL}/k1", None, "victim_data", VICTIM_DB,
     False, "document by id, HEAD"),
    ("rest", "GET", f"/_api/edges/{SECRET_EDGES}?vertex={SECRET_COLL}/k1", None,
     "victim_data", VICTIM_DB, False, "edges of a denied vertex"),
    ("rest", "GET", f"/_api/gharial/{SECRET_GRAPH}/vertex/{SECRET_COLL}/k1", None,
     "victim_data", VICTIM_DB, False, "graph vertex document"),
    ("rest", "GET", f"/_api/gharial/{SECRET_GRAPH}/edge/{SECRET_EDGES}/e1", None,
     "victim_data", VICTIM_DB, False, "graph edge document"),
    ("rest", "GET", f"/_api/view/{SECRET_VIEW}/properties", None, "victim_data", VICTIM_DB,
     False, "view properties"),
    ("rest", "POST", "/_api/cursor", {"query": 'FOR d IN secret_coll RETURN d',
                                      "options": {"stream": True}},
     "victim_data", VICTIM_DB, False, "streaming cursor"),
    ("rest", "POST", "/_api/cursor", {"query": 'FOR d IN secret_coll RETURN d',
                                      "options": {"allowDirtyReads": True}},
     "victim_data", VICTIM_DB, False, "dirty-read cursor"),
    ("rest", "POST", "/_api/explain", {"query": 'FOR d IN secret_coll RETURN d'},
     "victim_data", VICTIM_DB, False, "EXPLAIN"),
    # victimdb, metadata (may legitimately be readable at database level)
    ("rest", "GET", "/_api/view", None, "victim_meta", VICTIM_DB, False, "view list"),
    ("rest", "GET", "/_api/analyzer", None, "victim_meta", VICTIM_DB, False, "analyzer list"),
    ("rest", "GET", f"/_api/analyzer/{SECRET_ANALYZER}", None, "victim_meta", VICTIM_DB,
     False, "analyzer properties"),
    ("rest", "GET", "/_api/gharial", None, "victim_meta", VICTIM_DB, False, "graph list"),
    ("rest", "GET", "/_api/collection", None, "victim_meta", VICTIM_DB, False,
     "collection list (must be filtered)"),
    # victimdb, writes / DDL
    ("rest", "POST", "/_api/collection", {"name": SECRET_COLL}, "victim_data", VICTIM_DB,
     True, "create a collection with the victim's name"),
    ("rest", "PUT", f"/_api/collection/{SECRET_COLL}/truncate", None, "victim_data",
     VICTIM_DB, True, "truncate"),
    ("rest", "PUT", f"/_api/collection/{SECRET_COLL}/rename", {"name": "stolen"},
     "victim_data", VICTIM_DB, True, "rename"),
    ("rest", "DELETE", f"/_api/collection/{SECRET_COLL}", None, "victim_data", VICTIM_DB,
     True, "drop"),
    ("rest", "POST", f"/_api/document/{SECRET_COLL}", {"v": "pwn"}, "victim_data",
     VICTIM_DB, True, "insert a document"),
    ("rest", "PUT", f"/_api/document/{SECRET_COLL}/k1", {"v": "pwn"}, "victim_data",
     VICTIM_DB, True, "replace a document"),
    ("rest", "DELETE", f"/_api/document/{SECRET_COLL}/k1", None, "victim_data", VICTIM_DB,
     True, "delete a document"),
    ("rest", "POST", "/_api/index?collection=" + SECRET_COLL,
     {"type": "persistent", "fields": ["v"]}, "victim_data", VICTIM_DB, True,
     "create an index"),
    # marked write so the superuser does not open a transaction that lingers
    ("rest", "POST", "/_api/transaction/begin",
     {"collections": {"read": [SECRET_COLL]}}, "victim_data", VICTIM_DB, True,
     "streaming transaction, read"),
    ("rest", "POST", "/_api/transaction/begin",
     {"collections": {"write": [SECRET_COLL]}}, "victim_data", VICTIM_DB, True,
     "streaming transaction, write"),
    # _system
    ("rest", "GET", "/_api/user", None, "system", SYSTEM_DB, False, "user list"),
    ("rest", "GET", f"/_api/user/{VICTIM_USER}", None, "system", SYSTEM_DB, False,
     "another user's record"),
    ("rest", "GET", f"/_api/user/{ATTACKER_USER}", None, "control", SYSTEM_DB, False,
     "own record"),
    ("rest", "GET", f"/_api/user/{ATTACKER_USER}/database", None, "control", SYSTEM_DB,
     False, "own grants"),
    ("rest", "PUT", f"/_api/user/{ATTACKER_USER}/database/{VICTIM_DB}", {"grant": "rw"},
     "system", SYSTEM_DB, True, "self-grant rw on the victim database"),
    ("rest", "PUT", f"/_api/user/{ATTACKER_USER}/database/{VICTIM_DB}/{SECRET_COLL}",
     {"grant": "rw"}, "system", SYSTEM_DB, True, "self-grant rw on the secret collection"),
    ("rest", "PUT", f"/_api/user/{ATTACKER_USER}/database/{SYSTEM_DB}", {"grant": "rw"},
     "system", SYSTEM_DB, True, "self-grant rw on _system"),
    ("rest", "POST", "/_api/user", {"user": "pwned", "passwd": "pwned"}, "system",
     SYSTEM_DB, True, "create a user"),
    ("rest", "PATCH", f"/_api/user/{VICTIM_USER}", {"passwd": "pwned"}, "system",
     SYSTEM_DB, True, "change the victim's password"),
    ("rest", "DELETE", f"/_api/user/{VICTIM_USER}", None, "system", SYSTEM_DB, True,
     "delete the victim"),
    ("rest", "POST", "/_api/database", {"name": "pwned"}, "system", SYSTEM_DB, True,
     "create a database"),
    ("rest", "DELETE", f"/_api/database/{VICTIM_DB}", None, "system", SYSTEM_DB, True,
     "drop the victim database"),
    ("rest", "GET", "/_admin/statistics", None, "system", SYSTEM_DB, False,
     "server statistics"),
    ("rest", "GET", "/_api/replication/inventory", None, "system", SYSTEM_DB, False,
     "replication inventory"),
    ("rest", "POST", "/_api/cursor", {"query": "FOR u IN _users RETURN u"}, "system",
     SYSTEM_DB, False, "AQL over _users"),
]


def mutations(query: str) -> list[tuple[str, str, dict | None]]:
    """Name-obfuscation mutations: the same target, spelled differently."""
    out = []
    if f'"{SECRET_COLL}"' in query:
        out.append(("concat", query.replace(f'"{SECRET_COLL}"',
                                            'CONCAT("secret", "_coll")'), None))
        out.append(("unicode", query.replace(f'"{SECRET_COLL}"',
                                             '"secret_\\u0063oll"'), None))
        out.append(("bindparam", query.replace(f'"{SECRET_COLL}"', "@@c"),
                    {"@c": SECRET_COLL}))
        out.append(("case", query.replace(f'"{SECRET_COLL}"', '"SECRET_COLL"'), None))
    if query.startswith("FOR "):
        out.append(("subquery", "RETURN (" + query + ")", None))
    elif query.startswith("RETURN "):
        out.append(("subquery", "RETURN (" + query[len("RETURN "):] + ")", None))
        out.append(("lowercase", "return " + query[len("RETURN "):], None))
    return out


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------


class Finding:
    __slots__ = ("severity", "kind", "profile", "probe", "response", "leaked",
                 "note", "count")

    def __init__(self, severity, kind, profile, probe, response, leaked, note=""):
        self.severity = severity
        self.kind = kind
        self.profile = profile
        self.probe = probe
        self.response = response
        self.leaked = leaked
        self.note = note
        self.count = 1

    def group(self) -> tuple:
        return (self.kind, self.probe.family, self.probe.db, self.profile)

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "id": self.probe.pid,
            "profile": self.profile,
            "family": self.probe.family,
            "db": self.probe.db,
            "request": self.probe.describe(),
            "status": self.response.status,
            "response": self.response.brief(1200),
            "leaked": self.leaked,
            "note": self.note,
            "count": self.count,
        }


# --------------------------------------------------------------------------
# the fuzzer
# --------------------------------------------------------------------------


class PrivilegeFuzzer:
    def __init__(self, args):
        self.args = args
        self.rng = random.Random(args.seed)
        self.findings: list[Finding] = []
        self._finding_index: dict[tuple, Finding] = {}
        self.probes_run = 0
        self.root_cache: dict[tuple, Response] = {}
        self.profile: Profile | None = None
        self._datadir_owned = False

        self.server = None
        if args.attach:
            self.base = args.attach.rstrip("/")
            self.secret = args.jwt_secret or ""
        else:
            datadir = args.datadir or tempfile.mkdtemp(prefix="privilege-fuzzer-")
            self._datadir_owned = args.datadir is None
            os.makedirs(datadir, exist_ok=True)
            port = args.port or free_port()
            self.server = ArangodServer(args.arangod, datadir, port,
                                        startup_timeout=args.startup_timeout)
            self.base = self.server.base_url
            self.secret = ""
        self.api = Api(self.base, self.secret, timeout=args.request_timeout)

    # -- lifecycle -------------------------------------------------------
    def boot(self) -> None:
        if self.server is not None:
            self.server.start()
            self.secret = self.server.secret
            self.api.secret = self.secret
            self.base = self.server.base_url
            if self.args.verbose:
                print(f"arangod up at {self.base} (datadir {self.server.datadir})",
                      flush=True)
        version = self.api.get("/_api/version", as_user="root")
        if version.status != 200:
            raise BootError(f"cannot authenticate as root: {version.status} "
                            f"{version.brief()}")
        self.version = version.json()

    def close(self) -> None:
        if self.server is not None:
            if self.args.keep_server:
                print(f"server left running at {self.base}")
                print(f"  jwt secret: {self.secret}")
                print(f"  datadir   : {self.server.datadir}")
            else:
                self.server.stop()
                if self.args.keep_datadir:
                    print(f"datadir kept at {self.server.datadir}")
                elif self._datadir_owned:
                    shutil.rmtree(self.server.datadir, ignore_errors=True)

    # -- setup -----------------------------------------------------------
    def setup(self) -> None:
        api = self.api
        self._ok(api.post("/_api/user", {"user": VICTIM_USER, "passwd": VICTIM_PASSWD},
                          as_user="root"), "create victim")
        self._ok(api.post("/_api/user", {"user": ATTACKER_USER, "passwd": ATTACKER_PASSWD},
                          as_user="root"), "create attacker")
        self._ok(api.post("/_api/database", {"name": VICTIM_DB, "users": [
            {"username": VICTIM_USER, "passwd": VICTIM_PASSWD}]}, as_user="root"),
            "create victimdb")
        self._ok(api.post("/_api/database", {"name": ATTACKER_DB, "users": [
            {"username": ATTACKER_USER, "passwd": ATTACKER_PASSWD}]}, as_user="root"),
            "create attackerdb")

        # victim's data
        self._ok(api.post("/_api/collection", {"name": SECRET_COLL},
                          as_user=VICTIM_USER, db=VICTIM_DB), "create secret_coll")
        self._ok(api.post("/_api/document/" + SECRET_COLL, [
            {"_key": "k1", "v": CANARY_DATA, "n": 1},
            {"_key": "k2", "v": CANARY_DATA, "n": 2},
        ], as_user=VICTIM_USER, db=VICTIM_DB), "insert victim documents")
        self._ok(api.post("/_api/collection", {"name": SECRET_EDGES, "type": 3},
                          as_user=VICTIM_USER, db=VICTIM_DB), "create secret_edges")
        self._ok(api.post("/_api/document/" + SECRET_EDGES, [
            {"_key": "e1", "_from": f"{SECRET_COLL}/k1", "_to": f"{SECRET_COLL}/k2",
             "label": CANARY_EDGE},
        ], as_user=VICTIM_USER, db=VICTIM_DB), "insert victim edge")
        self._ok(api.post("/_api/index?collection=" + SECRET_COLL,
                          {"type": "persistent", "fields": ["v"]},
                          as_user=VICTIM_USER, db=VICTIM_DB), "create victim index")
        self._ok(api.post("/_api/view", {
            "name": SECRET_VIEW, "type": "arangosearch",
            "links": {SECRET_COLL: {"includeAllFields": True}},
        }, as_user=VICTIM_USER, db=VICTIM_DB), "create victim view")
        self._ok(api.post("/_api/analyzer", {
            "name": SECRET_ANALYZER, "type": "text",
            "properties": {"locale": "en", "stopwords": [CANARY_ANALYZER]},
        }, as_user=VICTIM_USER, db=VICTIM_DB), "create victim analyzer")
        self._ok(api.post("/_api/gharial", {
            "name": SECRET_GRAPH,
            "edgeDefinitions": [{"collection": SECRET_EDGES,
                                 "from": [SECRET_COLL], "to": [SECRET_COLL]}],
        }, as_user=VICTIM_USER, db=VICTIM_DB), "create victim graph")

        # attacker's own data (control)
        self._ok(api.post("/_api/collection", {"name": ATTACKER_COLL},
                          as_user=ATTACKER_USER, db=ATTACKER_DB), "create attacker_coll")
        self._ok(api.post("/_api/document/" + ATTACKER_COLL, [
            {"_key": "a1", "v": CANARY_CONTROL}],
            as_user=ATTACKER_USER, db=ATTACKER_DB), "insert attacker document")

        # canary data in _system, and the attacker may read _system but not this
        self._ok(api.post("/_api/collection", {"name": PUBLIC_COLL}, as_user="root",
                          db=SYSTEM_DB), "create _system canary collection")
        self._ok(api.post("/_api/document/" + PUBLIC_COLL, [
            {"_key": "p1", "v": CANARY_DATA}], as_user="root", db=SYSTEM_DB),
            "insert _system canary document")
        self.verify_fixture()

    def _ok(self, resp: Response, what: str) -> None:
        if resp.success():
            return
        doc = resp.json() or {}
        # a re-run against a server that already holds the fixture
        if doc.get("errorNum") in (1207, 1702, 1208):
            return
        if "collision" in str(doc.get("errorMessage", "")).lower():
            return
        raise SetupError(f"{what}: {resp.status} {resp.brief()}")

    def verify_fixture(self) -> None:
        """The oracles are only meaningful if the canaries are where we put them."""
        api = self.api
        checks = [
            ("documents", api.aql(f'FOR d IN {SECRET_COLL} RETURN d.v', db=VICTIM_DB,
                                   as_user="root"), CANARY_DATA),
            ("edge", api.aql(f'FOR e IN {SECRET_EDGES} RETURN e.label', db=VICTIM_DB,
                              as_user="root"), CANARY_EDGE),
            ("_system document", api.aql(f'FOR d IN {PUBLIC_COLL} RETURN d.v',
                                         db=SYSTEM_DB, as_user="root"), CANARY_DATA),
            ("analyzer", api.get(f"/_api/analyzer/{SECRET_ANALYZER}", as_user="root",
                                  db=VICTIM_DB), CANARY_ANALYZER),
        ]
        for what, resp, canary in checks:
            if not resp.success() or canary not in resp.body:
                raise SetupError(
                    f"fixture check failed for the {what} canary: {resp.status} "
                    f"{resp.brief(200)} — the datadir holds an older fixture; "
                    f"run without --datadir (or empty it) for a clean one")

    # -- grant profiles ---------------------------------------------------
    def apply_profile(self, profile: Profile) -> None:
        api = self.api
        # start from a clean slate for the attacker
        for db in (VICTIM_DB, SYSTEM_DB, ATTACKER_DB):
            api.put(f"/_api/user/{ATTACKER_USER}/database/{db}",
                    {"grant": "none"}, as_user="root")
        api.put(f"/_api/user/{ATTACKER_USER}/database/{ATTACKER_DB}",
                {"grant": "rw"}, as_user="root")
        api.put(f"/_api/user/{ATTACKER_USER}/database/{SYSTEM_DB}",
                {"grant": "ro"}, as_user="root")
        api.put(f"/_api/user/{ATTACKER_USER}/database/{SYSTEM_DB}/{PUBLIC_COLL}",
                {"grant": "none"}, as_user="root")

        if not profile.no_db_access:
            api.put(f"/_api/user/{ATTACKER_USER}/database/{VICTIM_DB}",
                    {"grant": "ro"}, as_user="root")
        # collection-level denials in both profiles, so a leftover grant from an
        # earlier run can never widen the fixture
        for coll in (SECRET_COLL, SECRET_EDGES):
            api.put(f"/_api/user/{ATTACKER_USER}/database/{VICTIM_DB}/{coll}",
                    {"grant": "none"}, as_user="root")

        # verify what the server actually granted, and fail loudly if not
        grants = api.get(f"/_api/user/{ATTACKER_USER}/database", as_user="root")
        self._ok(grants, "read attacker grants")
        got = (grants.json() or {}).get("result", {})
        want_victim = "none" if profile.no_db_access else "ro"
        # an explicit "none" is reported as no entry at all
        if got.get(VICTIM_DB, "none") != want_victim:
            raise SetupError(f"profile {profile.name}: victimdb grant is "
                             f"{got.get(VICTIM_DB)!r}, wanted {want_victim!r}")

        # the attacker must not be able to read the secret collection
        probe = api.aql(f"FOR d IN {SECRET_COLL} RETURN d", db=VICTIM_DB,
                        as_user=ATTACKER_USER)
        if probe.success():
            raise SetupError(f"profile {profile.name}: the fixture is broken — the "
                             f"attacker can already read {SECRET_COLL}: "
                             f"{probe.brief()}")
        # ... but in the collection-denied profile the database itself is open,
        # so a query with no collection must run.  Grant changes can be visible
        # to the attacker's next request only after a moment; poll for it.
        if not profile.no_db_access:
            deadline = time.time() + 20.0
            while True:
                allowed = api.aql("RETURN 1", db=VICTIM_DB, as_user=ATTACKER_USER)
                if allowed.success():
                    break
                if time.time() > deadline:
                    raise SetupError(
                        f"profile {profile.name}: the grant change did not take "
                        f"effect within 20s (last answer {allowed.status} "
                        f"{allowed.brief(200)})")
                time.sleep(0.25)
        if self.args.verbose:
            print(f"profile {profile.name}: {profile.note}", flush=True)

    # -- state fingerprints ----------------------------------------------
    def victim_state(self, db: str = VICTIM_DB) -> str | None:
        """Fingerprint of the data the attacker must not be able to change."""
        api = self.api
        if db == SYSTEM_DB:
            query = (f"RETURN {{docs: (FOR d IN {PUBLIC_COLL} SORT d._key "
                     f"RETURN [d._key, d._rev, d.v]), "
                     f"colls: (FOR c IN COLLECTIONS() SORT c.name RETURN c.name)}}")
        else:
            query = (f"RETURN {{docs: (FOR d IN {SECRET_COLL} SORT d._key "
                     f"RETURN [d._key, d._rev, d.v, d.n]), "
                     f"edges: (FOR e IN {SECRET_EDGES} SORT e._key "
                     f"RETURN [e._key, e._from, e._to, e.label]), "
                     f"colls: (FOR c IN COLLECTIONS() SORT c.name RETURN c.name)}}")
        resp = api.aql(query, db=db, as_user="root")
        if not resp.success():
            return None      # a failed fingerprint must not look like a change
        # only the result matters: the envelope carries executionTime and
        # cache flags that differ on every call
        return hashlib.sha256(json.dumps(resp.result(), sort_keys=True).encode()).hexdigest()

    def full_state(self) -> str:
        return f"{self.victim_state(VICTIM_DB)}:{self.victim_state(SYSTEM_DB)}"

    def escalation_state(self) -> str:
        api = self.api
        state = {
            "grants": api.get(f"/_api/user/{ATTACKER_USER}/database",
                              as_user="root").body,
            "users": api.get("/_api/user", as_user="root").body,
        }
        return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()

    # -- probe generation -------------------------------------------------
    def aql_probes(self, profile: Profile) -> list[Probe]:
        probes = []
        for seed in SEEDS:
            for db in seed.get("dbs", [VICTIM_DB, ATTACKER_DB, SYSTEM_DB]):
                variants = [("base", seed["q"], seed.get("bv"))]
                if seed.get("mutable") and not self.args.quick:
                    variants += mutations(seed["q"])
                for label, query, bind in variants:
                    body = {"query": query}
                    if bind:
                        body["bindVars"] = bind
                    pid = f"aql/{seed['f']}/{label}"
                    probes.append(Probe(
                        pid, seed["f"], "aql", db, "POST", "/_api/cursor",
                        body=body,
                        touches=seed["t"],
                        expect=expected_outcome(seed["t"], profile, db,
                                                seed.get("d", False)),
                        write=seed.get("write", False),
                        note=seed.get("note", "")))
        return probes

    def rest_probes(self, profile: Profile) -> list[Probe]:
        probes = []
        for i, (family, method, path, body, touches, db, write, note) in enumerate(REST_PROBES):
            probes.append(Probe(
                f"rest/{family}/{i}", family, "rest", db, method, path, body=body,
                touches=touches, expect=expected_outcome(touches, profile, db),
                write=write, note=note))
        return probes

    # -- running ----------------------------------------------------------
    def run(self) -> int:
        started = time.time()
        self.boot()
        self.setup()
        for profile in PROFILES:
            self.profile = profile
            self.apply_profile(profile)
            before = self.full_state()
            esc_before = self.escalation_state()
            probes = self.aql_probes(profile) + self.rest_probes(profile)
            self.rng.shuffle(probes)
            if self.args.max_probes:
                probes = probes[: self.args.max_probes]
            if self.args.verbose:
                print(f"profile {profile.name}: {len(probes)} probes", flush=True)
            self._run_probes(probes)
            self._check_state(before, esc_before, "after profile " + profile.name)
            if self.args.verbose:
                print(f"  requests so far: {self.api.requests}", flush=True)
        self._hijack_probes()
        self._existence_probe()
        self.duration = time.time() - started
        return self.report()

    def _run_probes(self, probes: list[Probe]) -> None:
        for probe in probes:
            if self.server is not None and not self.server.alive():
                self._server_died(probe)
                return
            check_db = SYSTEM_DB if probe.db == SYSTEM_DB else VICTIM_DB
            before = self.victim_state(check_db) if self.args.check_writes else None
            root_resp = None
            if not probe.write:
                root_resp = self._root_ground_truth(probe)
            resp = self.api.request(probe.method, probe.path,
                                    as_user=ATTACKER_USER, body=probe.body,
                                    db=probe.db, headers=probe.headers)
            self.probes_run += 1
            if self.args.verbose and self.args.trace:
                print(f"  {probe.expect:8s} {resp.status} {probe.describe()}",
                      flush=True)
            if self.server is not None and not self.server.alive():
                self._record(probe, resp, "crash", "critical",
                             "the server died while answering this request",
                             self.server.log_tail(3000))
                return
            if self.args.check_writes:
                after = self.victim_state(check_db)
                if before is not None and after is not None and after != before:
                    self._record(probe, resp, "write", "critical",
                                 "the victim's data fingerprint changed",
                                 "the request modified victim data; compare "
                                 "the response with the fingerprint change")
            self._evaluate(probe, resp, root_resp)

    def _root_ground_truth(self, probe: Probe) -> Response:
        key = probe.key()
        if key not in self.root_cache:
            self.root_cache[key] = self.api.request(
                probe.method, probe.path, as_user="root", body=probe.body,
                db=probe.db, headers=probe.headers)
        return self.root_cache[key]

    def _evaluate(self, probe: Probe, resp: Response, root_resp: Response | None) -> None:
        # R1 — canary in the response.  A canary that the request itself carries
        # only counts when it comes back in the result, not in an echo of the
        # query (e.g. an error message quoting it).
        request_text = json.dumps(probe.body) if probe.body else ""
        result_text = json.dumps(resp.result())
        if probe.touches != "control":
            for canary, (owner, kind, meaning) in CANARIES.items():
                if canary not in resp.body:
                    continue
                if canary in request_text and canary not in result_text:
                    continue
                sev = "high" if kind == "data" else "medium"
                self._record(probe, resp, "canary", sev,
                             f"{canary} (planted in {owner})", meaning)
                break

        # R3 — a request that must be refused succeeded
        if probe.expect == "denied" and resp.success():
            if probe.kind == "aql" and self._silent(resp):
                # a 2xx that carries nothing: only worth a line if the same
                # query *does* produce something for the superuser
                if root_resp is not None and not self._silent(root_resp):
                    self._record(probe, resp, "silent-success", "low",
                                 "nothing (the result is empty)",
                                 "2xx where a refusal was expected, but no data")
            else:
                sev = "high" if probe.touches == "victim_data" else "medium"
                leaked = self._what_came_back(resp)
                if (root_resp is not None and root_resp.success()
                        and self._same_result(resp, root_resp)):
                    sev = "high"
                    leaked += " (identical to the superuser's result)"
                self._record(probe, resp, "denied-but-2xx", sev, leaked,
                             "this request must be refused for the attacker")

        # R2 — same non-silent result as the superuser on a data probe
        if (probe.expect in ("denied", "silent") and probe.touches == "victim_data"
                and root_resp is not None and root_resp.success() and resp.success()
                and not self._silent(resp) and self._same_result(resp, root_resp)):
            self._record(probe, resp, "same-as-root", "high",
                         self._what_came_back(resp),
                         "the attacker got exactly the superuser's result")

        # R7 — a denied collection name in a successful response
        if resp.success() and probe.expect in ("unknown", "allowed"):
            for name in DENIED_NAMES:
                if name in resp.body:
                    self._record(probe, resp, "name-disclosure", "info",
                                 f"the name {name!r} of a collection the attacker "
                                 f"cannot read", "metadata readable at database level")
                    break

        # 5xx — not a privilege finding, but worth a line in the report
        if 500 <= resp.status < 600:
            self._record(probe, resp, "server-error", "info",
                         f"HTTP {resp.status}", "server error while handling the request")

    def _silent(self, resp: Response) -> bool:
        """True when the result carries nothing at all (a miss, not a leak)."""
        result = resp.result()
        if result is None:
            return True
        if not isinstance(result, list):
            return _empty(result)
        return all(_empty(value) for value in result)

    def _same_result(self, resp: Response, root_resp: Response) -> bool:
        return self._normalise(resp) == self._normalise(root_resp)

    def _normalise(self, resp: Response) -> str:
        doc = resp.json()
        if isinstance(doc, dict):
            doc = {k: v for k, v in doc.items()
                   if k not in ("extra", "cached", "error", "code")}
            if "result" in doc and isinstance(doc["result"], list):
                doc["result"] = self._strip_revs(doc["result"])
        return json.dumps(doc, sort_keys=True)

    def _strip_revs(self, value):
        if isinstance(value, list):
            return [self._strip_revs(v) for v in value]
        if isinstance(value, dict):
            return {k: self._strip_revs(v) for k, v in value.items()
                    if k not in ("_rev", "_id")}
        return value

    def _what_came_back(self, resp: Response) -> str:
        for canary, (owner, _kind, _meaning) in CANARIES.items():
            if canary in resp.body:
                return f"{canary} (from {owner})"
        result = resp.result()
        if result is not None:
            text = json.dumps(result)
            if len(text) > 200:
                text = text[:200] + "..."
            return f"AQL result {text}"
        return "a 2xx response body"

    # -- special probes: stealing another session's cursor / transaction --
    def _hijack_probes(self) -> None:
        api = self.api
        # the superuser opens a streaming transaction on the secret collection
        begun = api.post("/_api/transaction/begin",
                         {"collections": {"read": [SECRET_COLL]}},
                         as_user="root", db=VICTIM_DB)
        trx_id = None
        if begun.success():
            trx_id = ((begun.json() or {}).get("result") or {}).get("id")
        if trx_id:
            for pid, method, path, body, headers, note in [
                ("hijack/trx-cursor", "POST", "/_api/cursor",
                 {"query": f"FOR d IN {SECRET_COLL} RETURN d"},
                 {"x-arango-trx-id": trx_id}, "use the superuser's transaction"),
                ("hijack/trx-commit", "PUT", "/_api/transaction/" + trx_id, {},
                 None, "commit the superuser's transaction"),
                ("hijack/trx-abort", "DELETE", "/_api/transaction/" + trx_id, None,
                 None, "abort the superuser's transaction"),
            ]:
                probe = Probe(pid, "hijack", "rest", VICTIM_DB, method, path,
                              body=body, headers=headers, touches="victim_data",
                              expect="denied", note=note)
                resp = api.request(method, path, as_user=ATTACKER_USER, body=body,
                                   db=VICTIM_DB, headers=headers)
                self.probes_run += 1
                if resp.success():
                    self._record(probe, resp, "denied-but-2xx", "critical",
                                 "another user's streaming transaction",
                                 "a transaction id must be bound to its owner")
                elif self.args.verbose and self.args.trace:
                    print(f"  denied   {resp.status} {probe.describe()}", flush=True)
            api.request("PUT", "/_api/transaction/" + trx_id, body={}, as_user="root",
                        db=VICTIM_DB)

        # the superuser opens a cursor with a second batch pending
        opened = api.post("/_api/cursor",
                          {"query": f"FOR d IN {SECRET_COLL} RETURN d", "batchSize": 1},
                          as_user="root", db=VICTIM_DB)
        cursor_id = (opened.json() or {}).get("id") if opened.success() else None
        if cursor_id:
            for pid, method, note in [
                ("hijack/cursor-next", "PUT", "read the next batch of the superuser's cursor"),
                ("hijack/cursor-delete", "DELETE", "close the superuser's cursor"),
            ]:
                probe = Probe(pid, "hijack", "rest", VICTIM_DB, method,
                              f"/_api/cursor/{cursor_id}", body={} if method == "PUT" else None,
                              touches="victim_data", expect="denied", note=note)
                resp = api.request(method, probe.path, as_user=ATTACKER_USER,
                                   body=probe.body, db=VICTIM_DB)
                self.probes_run += 1
                if resp.success():
                    self._record(probe, resp, "denied-but-2xx", "critical",
                                 "another user's open cursor",
                                 "a cursor id must be bound to its owner")
                elif self.args.verbose and self.args.trace:
                    print(f"  denied   {resp.status} {probe.describe()}", flush=True)
            api.request("DELETE", f"/_api/cursor/{cursor_id}", as_user="root",
                        db=VICTIM_DB)

    # -- existence oracle --------------------------------------------------
    def _existence_probe(self) -> None:
        """Can the attacker tell an existing denied collection from a missing one?

        Runs last, so the attacker is still on the collection-denied profile:
        the database is readable, the collection is not.
        """
        if self.profile is None or self.profile.no_db_access:
            return
        probe = Probe("oracle/existence", "existence", "rest", VICTIM_DB, "POST",
                      "/_api/cursor", touches="victim_meta", expect="denied",
                      note="an existing but denied collection vs a missing one")
        seen = {}
        for name in (SECRET_COLL, "no_such_collection_zzz"):
            resp = self.api.aql(f"FOR d IN {name} RETURN 1", db=VICTIM_DB,
                                as_user=ATTACKER_USER)
            self.probes_run += 1
            seen[name] = (resp.status, (resp.json() or {}).get("errorNum"))
        real, missing = seen[SECRET_COLL], seen["no_such_collection_zzz"]
        if real[1] is not None and real[1] != missing[1]:
            self._record(probe, Response(real[0], json.dumps(seen)), "existence-oracle",
                         "low",
                         f"{SECRET_COLL} answers {real}, a missing collection answers "
                         f"{missing}",
                         "the error code distinguishes an existing collection from a "
                         "missing one, so a user who is denied the collection can "
                         "still enumerate names; COLLECTIONS() is filtered correctly")

    # -- findings ---------------------------------------------------------
    def _record(self, probe: Probe, resp: Response, kind: str, severity: str,
                leaked: str, note: str) -> None:
        finding = Finding(severity, kind, self.profile.name if self.profile else "-",
                          probe, resp, leaked, note)
        group = finding.group()
        if group in self._finding_index:
            self._finding_index[group].count += 1
            return
        self._finding_index[group] = finding
        self.findings.append(finding)

    def _check_state(self, victim_before: str, esc_before: str, when: str) -> None:
        if not self.args.check_writes:
            return
        if self.full_state() != victim_before:
            probe = Probe("state/" + when, "state", "rest", VICTIM_DB, "GET", "/",
                          touches="victim_data", expect="denied")
            self._record(probe, Response(0, ""), "write", "critical",
                         "the victim's data fingerprint changed",
                         f"victim data changed {when}")
        if self.escalation_state() != esc_before:
            probe = Probe("state/" + when, "state", "rest", SYSTEM_DB, "GET", "/",
                          touches="system", expect="denied")
            self._record(probe, Response(0, ""), "escalation", "critical",
                         "the attacker's grants or the user list changed",
                         f"privilege state changed {when}")

    def _server_died(self, probe: Probe) -> None:
        self._record(probe, Response(0, ""), "crash", "critical",
                     "the server process exited",
                     "the sanitized server died during the run")

    # -- audit claims -----------------------------------------------------
    def claims(self) -> list[dict]:
        """What the run says about the claims the fuzzer was asked to check."""
        out = []
        shard = [f for f in self.findings
                 if f.probe.family == "shard_id"
                 and f.kind in ("canary", "denied-but-2xx", "same-as-root",
                                "name-disclosure")]
        out.append({
            "claim": "SHARD_ID has no permission check (audit finding)",
            "reproduced": bool(shard),
            "detail": ("SHARD_ID answered a collection the attacker cannot read"
                       if shard else
                       "every SHARD_ID probe on the denied collection was refused "
                       "(404 'could not find collection' / 403). ShardId() resolves "
                       "through methods::Collections::lookup(), which calls "
                       "ExecContext::canUseCollection (VocBase/Methods/Collections.cpp). "
                       "The unchecked branch is the cluster one: "
                       "AQL/Function/CollectionFunctions.cpp uses "
                       "ClusterInfo::getCollection() for ROLE_COORDINATOR/ROLE_DBSERVER, "
                       "and ClusterInfo::getCollection does not check ExecContext. "
                       "A single server cannot exercise it."),
        })
        return out

    # -- self test --------------------------------------------------------
    def self_test(self) -> int:
        """Over-grant the attacker on purpose and prove the oracles fire.

        A fuzzer whose oracle cannot fire is indistinguishable from one that
        finds nothing, so this mode is the harness's own test: it grants the
        attacker what the profiles deny, then checks that the canary and
        denied-but-2xx oracles report it.
        """
        self.boot()
        self.setup()
        self.profile = PROFILES[-1]
        self.apply_profile(self.profile)
        api = self.api
        # collection-level grants override the database-level one, so the
        # collection has to be opened explicitly for the self-test
        opened = [f"/_api/user/{ATTACKER_USER}/database/{VICTIM_DB}",
                  f"/_api/user/{ATTACKER_USER}/database/{VICTIM_DB}/{SECRET_COLL}",
                  f"/_api/user/{ATTACKER_USER}/database/{VICTIM_DB}/{SECRET_EDGES}"]
        for path in opened:
            api.put(path, {"grant": "rw"}, as_user="root")
        allowed = api.aql(f"FOR d IN {SECRET_COLL} RETURN d", db=VICTIM_DB,
                          as_user=ATTACKER_USER)
        if not allowed.success():
            raise SetupError("self-test: could not open the fixture to the attacker: "
                             f"{allowed.status} {allowed.brief()}")
        probes = [p for p in self.aql_probes(self.profile)
                  if p.db == VICTIM_DB and not p.write
                  and p.family in ("document", "for", "view")]
        self.rng.shuffle(probes)
        self._run_probes(probes[:6])
        self._run_probes([p for p in self.rest_probes(self.profile)
                          if p.touches == "victim_data"][:4])
        for path in opened:
            api.put(path, {"grant": "none"}, as_user="root")

        kinds = {}
        for finding in self.findings:
            kinds[finding.kind] = kinds.get(finding.kind, 0) + 1
        print(f"self-test: attacker over-granted rw on {VICTIM_DB}, "
              f"{self.probes_run} probes, findings by kind: {kinds}")
        for finding in self.findings:
            print(f"  [{finding.severity}] {finding.kind}: "
                  f"{finding.probe.describe()} -> {finding.response.status} "
                  f"{finding.leaked}")
        ok = "canary" in kinds and "denied-but-2xx" in kinds
        if not ok:
            print("self-test FAILED: the oracles did not fire on a fixture that is "
                  "known to be readable", file=sys.stderr)
        return 0 if ok else 1

    # -- report -----------------------------------------------------------
    def report(self) -> int:
        findings = sorted(self.findings,
                          key=lambda f: (-SEVERITY_ORDER.index(f.severity),
                                         f.kind, f.probe.family))
        counts = {sev: sum(1 for f in findings if f.severity == sev)
                  for sev in reversed(SEVERITY_ORDER)}

        print()
        print("=" * 78)
        print("privilege fuzzer report")
        print("=" * 78)
        version = getattr(self, "version", {}) or {}
        print(f"server     : {version.get('version', '?')} at {self.base}")
        if self.server is not None:
            print(f"datadir    : {self.server.datadir}")
        print(f"profiles   : {', '.join(p.name for p in PROFILES)}")
        print(f"probes     : {self.probes_run}   requests: {self.api.requests}"
              f"   duration: {getattr(self, 'duration', 0.0):.1f}s")
        print(f"findings   : {len(findings)} " +
              " ".join(f"{k}={v}" for k, v in counts.items() if v))
        print()

        if not findings:
            print("no leak: every probe that touches victim data was refused, "
                  "the victim's data is unchanged and the attacker's grants did "
                  "not change.")
            print()

        for finding in findings:
            probe = finding.probe
            print(f"[{finding.severity}] {finding.kind}  profile={finding.profile}"
                  + (f"  x{finding.count}" if finding.count > 1 else ""))
            print(f"  probe   : {probe.describe()}")
            if probe.note:
                print(f"  tries   : {probe.note}")
            print(f"  response: {finding.response.status} {finding.response.brief(600)}")
            print(f"  leaked  : {finding.leaked}")
            if finding.note:
                print(f"  why     : {finding.note}")
            print()

        print("audit claims checked")
        for claim in self.claims():
            state = "REPRODUCED" if claim["reproduced"] else "not reproduced"
            print(f"  [{state}] {claim['claim']}")
            for line in self._wrap(claim["detail"], 72, "      "):
                print(line)
        print()

        if self.args.json:
            payload = {
                "server": {"version": version.get("version"),
                           "base": self.base,
                           "datadir": self.server.datadir if self.server else None},
                "profiles": [p.name for p in PROFILES],
                "stats": {"probes": self.probes_run, "requests": self.api.requests,
                          "duration_s": round(getattr(self, "duration", 0.0), 2),
                          "findings": counts},
                "findings": [f.as_dict() for f in findings],
                "claims": self.claims(),
            }
            with open(self.args.json, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
                handle.write("\n")
            print(f"json report written to {self.args.json}")

        if self.args.fail_on == "none":
            return 0
        worst = max((SEVERITY_ORDER.index(f.severity) for f in findings), default=-1)
        return 1 if worst >= SEVERITY_ORDER.index(self.args.fail_on) else 0

    @staticmethod
    def _wrap(text: str, width: int, indent: str) -> list[str]:
        words, lines, line = text.split(), [], ""
        for word in words:
            if len(line) + len(word) + 1 > width:
                lines.append(indent + line)
                line = word
            else:
                line = (line + " " + word).strip()
        if line:
            lines.append(indent + line)
        return lines


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Privilege / roles fuzzer for ArangoDB (out-of-process).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--arangod", default="/build/build-asan/bin/arangod",
                        help="arangod binary to start")
    parser.add_argument("--port", type=int, default=0, help="0 picks a free port")
    parser.add_argument("--datadir", default=None, help="database directory (default: temp)")
    parser.add_argument("--attach", default=None, metavar="URL",
                        help="use a running server instead of starting one")
    parser.add_argument("--jwt-secret", default=None,
                        help="JWT secret of the attached server")
    parser.add_argument("--seed", type=int, default=20260101, help="mutation order seed")
    parser.add_argument("--max-probes", type=int, default=0, help="0 = no limit")
    parser.add_argument("--quick", action="store_true", help="skip the name mutations")
    parser.add_argument("--no-write-check", dest="check_writes", action="store_false",
                        help="do not fingerprint the victim's data around every probe")
    parser.add_argument("--fail-on", default="medium",
                        choices=["none", "info", "low", "medium", "high", "critical"],
                        help="exit 1 at or above this severity")
    parser.add_argument("--json", default=None, metavar="PATH", help="write a JSON report")
    parser.add_argument("--keep-server", action="store_true", help="leave the server running")
    parser.add_argument("--self-test", action="store_true",
                        help="over-grant the attacker and check that the oracles fire")
    parser.add_argument("--keep-datadir", action="store_true", help="keep the temp datadir")
    parser.add_argument("--startup-timeout", type=float, default=180.0)
    parser.add_argument("--request-timeout", type=float, default=60.0)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--trace", action="store_true", help="print every probe's status")
    args = parser.parse_args(argv)
    if args.attach and not args.jwt_secret:
        parser.error("--attach needs --jwt-secret")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    fuzzer = PrivilegeFuzzer(args)
    try:
        if args.self_test:
            return fuzzer.self_test()
        return fuzzer.run()
    except (BootError, SetupError) as exc:
        print(f"harness error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 2
    finally:
        fuzzer.close()


if __name__ == "__main__":
    sys.exit(main())
