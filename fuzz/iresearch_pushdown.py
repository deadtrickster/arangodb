#!/usr/bin/env python3
"""Agreement oracle for ArangoSearch: the index must answer like a scan.

ArangoSearch views are a *pushdown* surface: the same predicate can be answered
by the IResearch index or by a collection scan, and the two answers must be the
same set of documents. A crash-only fuzzer never sees the interesting failure
mode here -- a filter that is pushed down wrongly returns *fewer or more*
documents than the scan, and the server stays up. This driver is an oracle for
exactly that: a matrix of (column type x predicate form) cells, each run twice,
once through the view and once through the collection, and compared.

    index: FOR doc IN <view> SEARCH <predicate> SORT doc._key RETURN doc
    scan:  FOR doc IN <coll> FILTER <equivalent> SORT doc._key RETURN doc

Both sides return whole documents, so the comparison is both the set of _keys
and the document contents. Any disagreement is a wrong answer.

The scan side of a cell must express the *documented* index semantics, not the
implementation's, or every cell would "fail". Two such semantics are encoded
explicitly and marked in the cell notes: ArangoSearch indexes array elements
individually (recursively for nested arrays), and a token-based index cannot
hold the empty string. Cells whose scan equivalent cannot be expressed in AQL
are not in the matrix at all -- a cell that cannot be compared measures
nothing.

The server is started from scratch on a temporary data directory, so a run
needs a built arangod and nothing else:

    python3 fuzz/iresearch_pushdown.py                 # whole matrix
    python3 fuzz/iresearch_pushdown.py --list-cells    # what the matrix holds
    python3 fuzz/iresearch_pushdown.py --cells phrase,numeric
    python3 fuzz/iresearch_pushdown.py --arangod /build/build-asan/bin/arangod

Exit status: 0 all cells agree (or diverge only where documented), 1 unexpected
disagreement, 2 the harness or the server failed.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

COLLECTION = "pd_fixture"
VIEW = "pd_view"
# Second view over the same collection with storeValues enabled. EXISTS() is
# answered from the column store, so the two views answer it differently --
# that is measured, not assumed.
VIEW_SV = "pd_view_sv"
ANALYZER = "text_en"
DATE = time.strftime("%Y-%m-%d", time.gmtime())

# Cells that fail for the same reason share a family, so the report counts
# bugs rather than cells. The text is what a reader needs to judge the finding.
FAMILIES = {
    "exists-without-store-values":
        "EXISTS() in SEARCH is answered from the column store, and the default "
        "link does not populate it (storeValues: none). The predicate then "
        "matches nothing at all, while the same predicate on the collection "
        "matches every document that has the attribute. The identical cell "
        "on a link with storeValues: id agrees, which is what makes this a "
        "configuration trap rather than a mis-specified scan side.",
    "exists-empty-array":
        "EXISTS() with storeValues enabled matches documents whose array "
        "attribute is non-empty, but not those whose array is empty. AQL's "
        "HAS() -- the scan equivalent -- matches both, so documents disappear "
        "from the view's answer.",
    "negative-zero":
        "A document value of -0.0 is indexed as a term that sorts below 0.0, "
        "while AQL reads -0.0 as equal to 0 and not less than 0. Equality "
        "with 0 therefore misses those documents, `n < 0` returns them, and "
        "`n >= 0` drops them. A -0.0 literal in the query is normalized to "
        "0, so the index cannot even be asked for the value it holds.",
    "int64-bounds-rounded-to-double":
        "A numeric bound beyond 2^53 is rounded to the nearest double before "
        "it reaches the index, so the comparison is done against a different "
        "number than the query named: `n == 2^53+1` returns the documents "
        "whose value is 2^53, `n > 2^53` drops the ones at 2^53+1, and "
        "`n > int64max-1` drops the documents at int64 max.",
    "phrase-offsets":
        "PHRASE(field, term, offset, term, offset, analyzer) returns nothing "
        "for every offset form tried, while the same terms without offsets "
        "match. A predicate that silently answers the empty set is a wrong "
        "answer, not a capability gap.",
    "negation-and-missing-attribute":
        "`SEARCH doc.field != null` returns a document that does not have the "
        "attribute at all, while AQL reads a missing attribute as null, for "
        "which `!= null` is false.",
}


class HarnessError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# fixture: 100 documents, every one of them a boundary value somewhere
# ---------------------------------------------------------------------------

STRINGS = [
    "",
    " ",
    "Hello",
    "hello",
    "HELLO",
    "hELLo",
    "Hello World",
    "Hello, World!",
    "hello world",
    "the quick brown fox",
    "quick brown",
    "quick fox",
    "quick lazy fox",
    "Ünïcode",
    "naïve café",
    "日本語",
    "🙂",
    "smile 🙂",
    "123",
    "007",
    "1.5",
    "-1",
    "a%b",
    "a_b",
    "a-b",
    "a b",
    "back\\slash",
    "quo'te",
    'dbl"quote',
    "trailing ",
    " leading",
    "\ttab",
    "line\nbreak",
    "x" * 64,
]

NUMBERS = [
    0,
    -0.0,
    1,
    -1,
    1.5,
    -1.5,
    2,
    3,
    4,
    5,
    7,
    10,
    100,
    1000,
    1e300,
    -1e300,
    1e-300,
    2**53,
    2**53 + 1,
    2**63 - 1,
    -(2**63),
    0.1,
    1 / 3,
    1e-7,
    123456789.123456789,
]

BOOLS = [True, False]

TAGS = [
    ["a"],
    ["a", "b"],
    ["b", "c"],
    [],
    ["A"],
    ["a b"],
    ["a%b"],
    ["zzz"],
    ["a", "a"],
    ["b"],
    ["", "a"],
]

# Nested arrays only live in their own column: ArangoSearch flattens them
# recursively, and a cell that mixes them with a flat `IN` scan would "fail"
# for a reason that is documented rather than wrong.
NEST = [[["a"]], [["a", "b"], ["c"]], [["zzz"]], [], [["A"]], [["a"]], [[]]]

OBJECTS = [
    {"k": "v"},
    {"k": "V"},
    {"k": "v", "n": 1},
    {},
    {"k": None},
    {"k": {"k": "v"}},
    {"k": "v v"},
    {"k": "é"},
]

# `nul` is null in some documents, missing in others (see the specials below)
# and an ordinary value in the rest -- that distinction is a classic source of
# wrong answers on both sides.
NULS = [None, "notnull", 0, False, ""]

MIXED = [
    "abc",
    7,
    True,
    None,
    ["abc"],
    [7],
    [True],
    "ABC",
    7.5,
    False,
    ["abc", "xyz"],
    {},
]


def build_fixture():
    """Return the fixture as a list of documents (exactly 100)."""
    docs = []
    for i in range(92):
        doc = {
            "_key": "k%03d" % i,
            "s": STRINGS[i % len(STRINGS)],
            "n": NUMBERS[(i * 7) % len(NUMBERS)],
            "b": BOOLS[i % len(BOOLS)],
            "tags": TAGS[i % len(TAGS)],
            "nest": NEST[i % len(NEST)],
            "obj": OBJECTS[i % len(OBJECTS)],
            "nul": NULS[i % len(NULS)],
            "mx": MIXED[i % len(MIXED)],
            "i": i,
        }
        docs.append(doc)

    # Specials: attributes deliberately absent, and one document per boundary
    # the generated block can miss.
    specials = [
        {"_key": "k092", "s": "", "n": 0, "b": True, "tags": [], "nest": [],
         "obj": {}, "mx": ""},
        {"_key": "k093", "s": "Hello", "n": -1, "b": False, "tags": ["a"],
         "nest": [[]], "obj": {"k": "v"}, "nul": None, "mx": 0},
        {"_key": "k094", "s": "a%b", "n": 1, "b": True, "tags": ["a%b"],
         "nest": [[["a"]]], "obj": {"k": {"k": "v"}}, "nul": "", "mx": []},
        {"_key": "k095", "s": "quick brown fox", "n": 2**63 - 1, "b": False,
         "tags": ["a", "b"], "nest": [[["a", "b"]]], "obj": {"k": "V"},
         "nul": 0, "mx": {}},
        {"_key": "k096", "s": "日本語テスト", "n": -(2**63), "b": True,
         "tags": ["日本語"], "nest": [], "obj": {"k": "日本語"}, "nul": None,
         "mx": "日本語"},
        {"_key": "k097", "s": " ", "n": 1e300, "b": False, "tags": [" "],
         "nest": [[]], "obj": {"k": " "}, "nul": False, "mx": " "},
        {"_key": "k098", "s": "x" * 64, "n": -1e300, "b": True,
         "tags": ["x" * 64], "nest": [[["x" * 64]]], "obj": {"k": "x" * 64},
         "nul": "notnull", "mx": ["abc"]},
        {"_key": "k099", "s": "the quick brown fox", "n": 0.1, "b": False,
         "tags": ["quick", "brown", "fox"], "nest": [[["a"]]],
         "obj": {"k": "v"}, "nul": None, "mx": None},
    ]
    docs.extend(specials)
    return docs


# ---------------------------------------------------------------------------
# the matrix
# ---------------------------------------------------------------------------

def build_cells():
    """(column type x predicate form) cells.

    `index` is the SEARCH predicate, `scan` the FILTER predicate that encodes
    the documented index semantics, `scan_lets` are LET clauses the scan side
    needs (SEARCH predicates cannot carry a LET). `view` names the view the
    index side runs against. `expect` is "agree" unless the divergence is
    inherent to the index ("diverge") or the form is one SEARCH rejects
    outright ("unsupported"), in which case the cell is still measured but
    reported in its own section instead of as a wrong answer.
    """
    cells = []

    def add(name, column, form, index, scan, expect="agree", note="",
            scan_lets=(), view=VIEW, family=None):
        cells.append({
            "name": name,
            "column": column,
            "form": form,
            "index": index,
            "scan": scan,
            "expect": expect,
            "note": note,
            "scan_lets": list(scan_lets),
            "view": view,
            "family": family or name,
        })

    # -- string, identity analyzer, scalar values only --------------------
    add("string-eq", "string", "equality", 'doc.s == "Hello"',
        'doc.s == "Hello"')
    add("string-eq-unicode", "string", "equality", 'doc.s == "Ünïcode"',
        'doc.s == "Ünïcode"')
    add("string-eq-empty", "string", "equality", 'doc.s == ""', 'doc.s == ""')
    add("string-eq-long", "string", "equality", 'doc.s == "%s"' % ("x" * 64),
        'doc.s == "%s"' % ("x" * 64))
    add("string-neq", "string", "inequality", 'doc.s != "Hello"',
        'doc.s != "Hello"')
    add("string-in", "string", "IN list",
        'doc.s IN ["Hello", "hello", "HELLO"]',
        'doc.s IN ["Hello", "hello", "HELLO"]')
    add("string-in-empty", "string", "IN list (empty)", "doc.s IN []",
        "doc.s IN []")
    add("string-range", "string", "range GTE/LTE",
        'doc.s >= "Hello" AND doc.s <= "Zzz"',
        'doc.s >= "Hello" AND doc.s <= "Zzz"', expect="diverge",
        note="AQL compares strings with the ICU collator, the index orders "
             "terms by bytes")
    add("string-range-lt", "string", "range LT", 'doc.s < "Hello"',
        'doc.s < "Hello"', expect="diverge",
        note="AQL compares strings with the ICU collator, the index orders "
             "terms by bytes")
    add("string-starts-with", "string", "STARTS_WITH",
        'STARTS_WITH(doc.s, "Hel")', 'STARTS_WITH(doc.s, "Hel")')
    add("string-starts-with-empty", "string", "STARTS_WITH (empty prefix)",
        'STARTS_WITH(doc.s, "")', 'STARTS_WITH(doc.s, "")')
    add("string-like-prefix", "string", "LIKE prefix", 'doc.s LIKE "Hel%"',
        'doc.s LIKE "Hel%"')
    add("string-like-infix", "string", "LIKE infix", 'doc.s LIKE "%ell%"',
        'doc.s LIKE "%ell%"')
    add("string-like-underscore", "string", "LIKE _ wildcard",
        'doc.s LIKE "H_llo"', 'doc.s LIKE "H_llo"')
    add("string-like-escaped-percent", "string", "LIKE escaped %",
        'doc.s LIKE "a\\\\%b"', 'doc.s LIKE "a\\\\%b"',
        note="a literal %% is written \\%% in a LIKE pattern; both sides must "
             "agree that it is not a wildcard")
    add("string-exists", "string", "EXISTS", "EXISTS(doc.s)",
        'HAS(doc, "s")', family="exists-without-store-values")
    add("string-exists-storevalues", "string", "EXISTS (storeValues)",
        "EXISTS(doc.s)", 'HAS(doc, "s")', view=VIEW_SV,
        note="same predicate on a view that stores values")
    add("string-fulltext", "string", "full-text (ANALYZER)",
        'ANALYZER(doc.s == "quick", "%s")' % ANALYZER,
        '"quick" IN TOKENS(doc.s, "%s")' % ANALYZER)
    add("string-fulltext-stemmed", "string", "full-text (stemming)",
        'ANALYZER(doc.s == "quicks", "%s")' % ANALYZER,
        '"quicks" IN TOKENS(doc.s, "%s")' % ANALYZER,
        note="text_en stems both the stored tokens and the search term")
    add("string-phrase", "string", "phrase",
        'PHRASE(doc.s, "quick brown", "%s")' % ANALYZER,
        "LENGTH(p) > 0 AND LENGTH(t) >= LENGTH(p) AND "
        "LENGTH(FOR i IN 0..MAX([LENGTH(t) - LENGTH(p), 0]) "
        "FILTER SLICE(t, i, LENGTH(p)) == p LIMIT 1 RETURN 1) > 0",
        scan_lets=[("t", 'TOKENS(doc.s, "%s")' % ANALYZER),
                   ("p", 'TOKENS("quick brown", "%s")' % ANALYZER)],
        note="phrase = the query tokens appear consecutively in the field")
    add("string-proximity", "string", "proximity",
        'PHRASE(doc.s, "quick", 1, "fox", 3, "%s")' % ANALYZER,
        "LENGTH(t) >= 3 AND "
        "LENGTH(FOR i IN 0..MAX([LENGTH(t) - 3, 0]) "
        "FILTER t[i] == \"quick\" AND t[i + 2] == \"fox\" "
        "LIMIT 1 RETURN 1) > 0",
        scan_lets=[("t", 'TOKENS(doc.s, "%s")' % ANALYZER)],
        note="offsets 1 and 3 = one token between the terms",
        family="phrase-offsets")

    # -- numeric ----------------------------------------------------------
    add("numeric-eq", "numeric", "equality", "doc.n == 1", "doc.n == 1")
    add("numeric-eq-zero", "numeric", "equality", "doc.n == 0", "doc.n == 0",
        family="negative-zero")
    add("numeric-eq-neg-zero", "numeric", "equality", "doc.n == -0.0",
        "doc.n == -0.0",
        note="AQL reads -0.0 as equal to 0, so the two sides must agree",
        family="negative-zero")
    add("numeric-eq-float", "numeric", "equality", "doc.n == 0.1",
        "doc.n == 0.1")
    add("numeric-eq-int64-max", "numeric", "equality",
        "doc.n == 9223372036854775807", "doc.n == 9223372036854775807")
    add("numeric-eq-int64-min", "numeric", "equality",
        "doc.n == -9223372036854775808", "doc.n == -9223372036854775808")
    add("numeric-eq-big-float", "numeric", "equality", "doc.n == 1e300",
        "doc.n == 1e300")
    add("numeric-eq-2p53", "numeric", "equality at 2^53",
        "doc.n == 9007199254740992", "doc.n == 9007199254740992",
        family="int64-bounds-rounded-to-double")
    add("numeric-eq-2p53p1", "numeric", "equality above 2^53",
        "doc.n == 9007199254740993", "doc.n == 9007199254740993",
        family="int64-bounds-rounded-to-double")
    add("numeric-neq", "numeric", "inequality", "doc.n != 1",
        "IS_NUMBER(doc.n) AND doc.n != 1",
        note="IS_NUMBER is not a SEARCH expression, so only the scan side "
             "can carry it; the column is numeric-only")
    add("numeric-lt", "numeric", "range LT", "doc.n < 0", "doc.n < 0",
        family="negative-zero")
    add("numeric-gt", "numeric", "range GT", "doc.n > 1000", "doc.n > 1000")
    add("numeric-gte-lte", "numeric", "range GTE/LTE",
        "doc.n >= 0 AND doc.n <= 1", "doc.n >= 0 AND doc.n <= 1",
        family="negative-zero")
    add("numeric-gte-zero", "numeric", "range GTE", "doc.n >= 0",
        "doc.n >= 0", family="negative-zero")
    add("numeric-le-zero", "numeric", "range LTE", "doc.n <= 0",
        "doc.n <= 0")
    add("numeric-extreme", "numeric", "range at 1e300", "doc.n > 1e300",
        "doc.n > 1e300")
    add("numeric-precision", "numeric", "range at 2^53",
        "doc.n > 9007199254740992", "doc.n > 9007199254740992",
        family="int64-bounds-rounded-to-double")
    add("numeric-int64-max-range", "numeric", "range near int64 max",
        "doc.n > 9223372036854775806", "doc.n > 9223372036854775806",
        family="int64-bounds-rounded-to-double")
    add("numeric-in", "numeric", "IN list", "doc.n IN [0, 1, 1.5, -1]",
        "doc.n IN [0, 1, 1.5, -1]", family="negative-zero")
    add("numeric-in-range", "numeric", "IN_RANGE",
        "IN_RANGE(doc.n, 1, 5, true, false)",
        "IS_NUMBER(doc.n) AND doc.n >= 1 AND doc.n < 5")
    add("numeric-exists", "numeric", "EXISTS", "EXISTS(doc.n)",
        'HAS(doc, "n")', family="exists-without-store-values")
    add("numeric-exists-storevalues", "numeric", "EXISTS (storeValues)",
        "EXISTS(doc.n)", 'HAS(doc, "n")', view=VIEW_SV)
    add("numeric-and", "numeric", "conjunction", "doc.n > 1 AND doc.n < 5",
        "doc.n > 1 AND doc.n < 5")

    # -- bool -------------------------------------------------------------
    add("bool-eq-true", "bool", "equality", "doc.b == true", "doc.b == true")
    add("bool-eq-false", "bool", "equality", "doc.b == false",
        "doc.b == false")
    add("bool-neq", "bool", "inequality", "doc.b != true", "doc.b != true")
    add("bool-in", "bool", "IN list", "doc.b IN [true]", "doc.b IN [true]")

    # -- array of strings -------------------------------------------------
    add("array-contains", "array", "array contains", 'doc.tags IN ["a"]',
        '"a" IN doc.tags',
        note="`value IN doc.array` is rejected by SEARCH, so the index side "
             "tests the attribute against a list, which is the supported "
             "form of membership")
    add("array-contains-missing", "array", "array contains (absent)",
        'doc.tags IN ["nope"]', '"nope" IN doc.tags')
    add("array-in-list", "array", "IN list of members",
        'doc.tags IN ["a", "zzz"]',
        '"a" IN doc.tags OR "zzz" IN doc.tags')
    add("array-elem-eq", "array", "equality against an array",
        'doc.tags == "a"', '"a" IN doc.tags',
        note="ArangoSearch indexes array elements individually, so comparing "
             "the array to a scalar is a membership test on the index side")
    add("array-and", "array", "conjunction of members",
        'doc.tags == "a" AND doc.tags == "b"',
        '"a" IN doc.tags AND "b" IN doc.tags')
    add("array-exists", "array", "EXISTS", "EXISTS(doc.tags)",
        'HAS(doc, "tags")', family="exists-without-store-values")
    add("array-exists-storevalues", "array", "EXISTS (storeValues)",
        "EXISTS(doc.tags)", 'HAS(doc, "tags")', view=VIEW_SV,
        note="an empty array has no column-store entry either",
        family="exists-empty-array")
    add("array-empty-member", "array", "array contains (empty string)",
        'doc.tags == ""', '"" IN doc.tags')
    add("array-nested-flatten", "array", "nested array flattening",
        'doc.nest == "a"', '"a" IN FLATTEN(doc.nest, 10)',
        note="nested arrays are flattened recursively by the index")
    add("array-in-unsupported", "array", "value IN attribute",
        '"a" IN doc.tags', '"a" IN doc.tags', expect="unsupported",
        note="SEARCH rejects a value on the left of IN (501, 'not "
             "implemented: noncompliant expression'); the scan answers it")

    # -- object -----------------------------------------------------------
    add("object-nested-eq", "object", "nested attribute equality",
        'doc.obj.k == "v"', 'doc.obj.k == "v"')
    add("object-nested-unicode", "object", "nested attribute equality",
        'doc.obj.k == "é"', 'doc.obj.k == "é"')
    add("object-deep-eq", "object", "deep attribute equality",
        'doc.obj.k.k == "v"', 'doc.obj.k.k == "v"')
    add("object-nested-null", "object", "nested attribute is null",
        "doc.obj.k == null", 'HAS(doc.obj, "k") AND doc.obj.k == null',
        note="the scan side must not read a missing attribute as null")
    add("object-exists", "object", "EXISTS on a nested attribute",
        "EXISTS(doc.obj.k)", 'HAS(doc.obj, "k")',
        family="exists-without-store-values")
    add("object-exists-storevalues", "object", "EXISTS (storeValues)",
        "EXISTS(doc.obj.k)", 'HAS(doc.obj, "k")', view=VIEW_SV)

    # -- null vs missing --------------------------------------------------
    add("null-eq", "null", "equality with null",
        "doc.nul == null", 'HAS(doc, "nul") AND doc.nul == null',
        note="the index only holds explicit nulls, so the scan side must "
             "exclude documents without the attribute")
    add("null-neq", "null", "inequality with null",
        "doc.nul != null", 'HAS(doc, "nul") AND doc.nul != null',
        family="negation-and-missing-attribute")
    add("null-exists", "null", "EXISTS on a nullable attribute",
        "EXISTS(doc.nul)", 'HAS(doc, "nul")',
        family="exists-without-store-values")
    add("null-exists-storevalues", "null", "EXISTS (storeValues)",
        "EXISTS(doc.nul)", 'HAS(doc, "nul")', view=VIEW_SV)
    add("null-missing-is-null", "null", "null vs missing (documented gap)",
        "doc.nul == null", "doc.nul == null", expect="diverge",
        note="AQL reads a missing attribute as null; the index has nothing "
             "to match, so the two sides differ by design")

    # -- mixed types ------------------------------------------------------
    add("mixed-eq-string", "mixed", "equality", 'doc.mx == "abc"',
        'doc.mx == "abc" OR (IS_ARRAY(doc.mx) AND '
        '"abc" IN FLATTEN(doc.mx, 10))')
    add("mixed-range", "mixed", "range", "doc.mx > 5",
        "(IS_NUMBER(doc.mx) AND doc.mx > 5) OR (IS_ARRAY(doc.mx) AND "
        "LENGTH(FOR v IN FLATTEN(doc.mx, 10) FILTER IS_NUMBER(v) AND v > 5 "
        "RETURN 1) > 0)",
        note="array elements are indexed individually")
    add("mixed-bool", "mixed", "equality", "doc.mx == true",
        "doc.mx == true OR (IS_ARRAY(doc.mx) AND "
        "true IN FLATTEN(doc.mx, 10))",
        note="array elements are indexed individually")
    add("mixed-null", "mixed", "equality with null", "doc.mx == null",
        'HAS(doc, "mx") AND doc.mx == null')
    add("mixed-in", "mixed", "IN list",
        'doc.mx IN ["abc", 7, true]',
        'doc.mx IN ["abc", 7, true] OR (IS_ARRAY(doc.mx) AND '
        'LENGTH(INTERSECTION(FLATTEN(doc.mx, 10), ["abc", 7, true])) > 0)')

    # -- no predicate at all: nothing may be lost -------------------------
    add("all-docs", "all", "no predicate", None, None)

    return cells


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class Client:
    def __init__(self, base, timeout=120.0):
        self.base = base
        self.timeout = timeout

    def request(self, method, path, body=None, timeout=None):
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data,
                                     method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                raw = r.read()
                status = r.status
        except urllib.error.HTTPError as e:
            raw = e.read()
            status = e.code
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            raise HarnessError("%s %s: %s" % (method, path, e)) from e
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = {"raw": raw.decode("utf-8", "replace")}
        return status, payload

    def query(self, aql, timeout=None):
        status, payload = self.request("POST", "/_api/cursor",
                                       {"query": aql}, timeout=timeout)
        if status != 200 and status != 201:
            return status, payload
        result = list(payload.get("result", []))
        extra = payload.get("extra") or {}
        while payload.get("hasMore"):
            status, payload = self.request("POST", "/_api/cursor/" + payload["id"],
                                           {}, timeout=timeout)
            if status != 200 and status != 201:
                return status, payload
            result.extend(payload.get("result", []))
        return 200, {"result": result, "extra": extra}


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def first_existing(paths):
    for path in paths:
        if path and os.path.exists(path):
            return path
    return None


class Server:
    """A throwaway single server: fresh data directory, no auth, no V8."""

    def __init__(self, arangod, datadir, port, tree, log_level="info"):
        self.arangod = arangod
        self.datadir = datadir
        self.port = port
        self.tree = tree
        self.log_level = log_level
        self.proc = None
        self.log_path = os.path.join(os.path.dirname(datadir), "arangod.log")
        self.asan_log_dir = os.path.join(os.path.dirname(datadir), "asan")

    @property
    def base(self):
        return "http://127.0.0.1:%d" % self.port

    def environment(self):
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = "detect_leaks=0:log_path=" + self.asan_log_dir
        env["UBSAN_OPTIONS"] = "halt_on_error=0:print_stacktrace=1"
        icu = first_existing([
            os.environ.get("ICU_DATA"),
            os.path.join(self.tree, "build", "bin"),
            os.path.join(self.tree, "3rdParty", "icu-legacy"),
        ])
        if icu:
            env.setdefault("ICU_DATA", icu)
            env["ICU_DATA_LEGACY"] = icu
        tz = first_existing([
            os.environ.get("TZ_DATA"),
            os.path.join(self.tree, "build", "bin", "tzdata"),
            os.path.join(self.tree, "build", "tests", "tzdata"),
            os.path.join(self.tree, "3rdParty", "tzdata"),
        ])
        if tz:
            env["TZ_DATA"] = tz
        return env

    def start(self):
        os.makedirs(self.datadir, exist_ok=True)
        os.makedirs(self.asan_log_dir, exist_ok=True)
        cmd = [
            self.arangod,
            "--configuration", "none",
            "--database.directory", self.datadir,
            "--server.endpoint", "tcp://127.0.0.1:%d" % self.port,
            "--server.authentication", "false",
            "--log.output", "file://" + self.log_path,
            "--log.level", self.log_level,
            "--rocksdb.max-total-wal-size", "1048576",
        ]
        log = open(self.log_path + ".stdout", "wb")
        self.proc = subprocess.Popen(cmd, stdout=log, stderr=log,
                                     env=self.environment())

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def wait_ready(self, deadline):
        client = Client(self.base, timeout=2.0)
        while time.time() < deadline:
            if not self.alive():
                raise HarnessError("arangod exited during startup (status %s)\n%s"
                                   % (self.proc.returncode, self.log_tail()))
            try:
                status, _ = client.request("GET", "/_api/version", timeout=2.0)
                if status == 200:
                    return
            except HarnessError:
                pass
            time.sleep(0.25)
        raise HarnessError("arangod did not answer within the deadline\n%s"
                           % self.log_tail())

    def log_tail(self, lines=40):
        try:
            with open(self.log_path, "r", encoding="utf-8",
                      errors="replace") as f:
                return "".join(f.readlines()[-lines:])
        except OSError:
            return "(no server log at %s)" % self.log_path

    def asan_reports(self):
        reports = []
        if os.path.isdir(self.asan_log_dir):
            for name in sorted(os.listdir(self.asan_log_dir)):
                reports.append(os.path.join(self.asan_log_dir, name))
        return reports

    def stop(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=30)
        self.proc = None


# ---------------------------------------------------------------------------
# fixture setup
# ---------------------------------------------------------------------------

def create_fixture(client, docs):
    status, payload = client.request("POST", "/_api/collection",
                                     {"name": COLLECTION, "type": 2})
    if status != 200:
        raise HarnessError("cannot create collection: %s %s" % (status, payload))

    status, payload = client.request("POST", "/_api/document/" + COLLECTION,
                                     docs)
    if status not in (200, 201, 202):
        raise HarnessError("cannot insert documents: %s %s" % (status, payload))
    if isinstance(payload, list):
        for item in payload:
            if item.get("error"):
                raise HarnessError("insert failed: %s" % item)

    # The create body is flat in 4.0: view properties sit next to name/type,
    # there is no "properties" sub-object (RestViewHandler.cpp reads
    # body.get("links") at the top level).
    def view_body(name, store_values=None):
        link = {
            "includeAllFields": True,
            # `s` also gets the text analyzer, so the full-text cells have
            # something to push down. identity stays first: it is the
            # default analyzer for a plain comparison.
            "fields": {"s": {"analyzers": ["identity", ANALYZER]}},
        }
        if store_values:
            link["storeValues"] = store_values
        return {"name": name, "type": "arangosearch",
                "commitIntervalMsec": 100, "links": {COLLECTION: link}}

    for name, store_values in ((VIEW, None), (VIEW_SV, "id")):
        status, payload = client.request("POST", "/_api/view",
                                        view_body(name, store_values))
        if status not in (200, 201, 202):
            raise HarnessError("cannot create view %s: %s %s"
                               % (name, status, payload))

    # Barrier: a view is fed asynchronously, so nothing may be asked of it
    # before every document is visible through it.
    for name in (VIEW, VIEW_SV):
        wait_for_view(client, name, len(docs))


def wait_for_view(client, view, expected, timeout=120.0):
    deadline = time.time() + timeout
    seen = -1
    while time.time() < deadline:
        status, payload = client.query("RETURN LENGTH(FOR doc IN %s RETURN 1)"
                                      % view)
        if status != 200:
            raise HarnessError("view enumeration of %s failed: %s %s"
                               % (view, status, payload))
        seen = payload["result"][0]
        if seen == expected:
            return
        time.sleep(0.2)
    raise HarnessError("view %s did not index the fixture: %d of %d documents"
                       % (view, seen, expected))


# ---------------------------------------------------------------------------
# the matrix run
# ---------------------------------------------------------------------------

def index_query(cell):
    view = cell.get("view", VIEW)
    if cell["index"] is None:
        return "FOR doc IN %s SORT doc._key RETURN doc" % view
    return "FOR doc IN %s SEARCH %s SORT doc._key RETURN doc" % (view,
                                                                 cell["index"])


def scan_query(cell):
    parts = ["FOR doc IN %s" % COLLECTION]
    for name, expr in cell["scan_lets"]:
        parts.append("LET %s = %s" % (name, expr))
    if cell["scan"] is not None:
        parts.append("FILTER %s" % cell["scan"])
    parts.append("SORT doc._key")
    parts.append("RETURN doc")
    return " ".join(parts)


def by_key(rows):
    out = {}
    for row in rows:
        if not isinstance(row, dict) or "_key" not in row:
            raise HarnessError("result row is not a document: %r" % (row,))
        out[row["_key"]] = row
    return out


def compare(cell, index_rows, scan_rows):
    """Return the disagreement, or None when the two sides agree."""
    index = by_key(index_rows)
    scan = by_key(scan_rows)
    missing = sorted(set(scan) - set(index))
    extra = sorted(set(index) - set(scan))
    changed = []
    for key in sorted(set(index) & set(scan)):
        if index[key] != scan[key]:
            fields = sorted(set(index[key]) | set(scan[key]))
            diff = {f: [index[key].get(f), scan[key].get(f)] for f in fields
                    if index[key].get(f) != scan[key].get(f)}
            changed.append({"key": key, "fields": diff})
    if not (missing or extra or changed):
        return None
    return {
        "missing_in_index": missing,
        "extra_in_index": extra,
        "content_mismatch": changed,
    }


def describe_diff(diff):
    bits = []
    if diff["missing_in_index"]:
        bits.append("the index is missing %d document(s): %s"
                    % (len(diff["missing_in_index"]),
                       ", ".join(diff["missing_in_index"][:10])))
    if diff["extra_in_index"]:
        bits.append("the index returns %d extra document(s): %s"
                    % (len(diff["extra_in_index"]),
                       ", ".join(diff["extra_in_index"][:10])))
    if diff["content_mismatch"]:
        first = diff["content_mismatch"][0]
        bits.append("%d document(s) differ in content, first %s: %s"
                    % (len(diff["content_mismatch"]), first["key"],
                       json.dumps(first["fields"], sort_keys=True)))
    return "; ".join(bits)


def run_cells(client, cells, log):
    results = []
    for cell in cells:
        iquery = index_query(cell)
        squery = scan_query(cell)
        istatus, ipayload = client.query(iquery)
        sstatus, spayload = client.query(squery)

        record = {
            "cell": {k: cell[k] for k in ("name", "column", "form", "expect",
                                          "note", "view", "family")},
            "index_query": iquery,
            "scan_query": squery,
        }
        if istatus != 200 or sstatus != 200:
            # A one-sided error is a disagreement of its own: the same question
            # must be answerable both ways.
            if cell["expect"] == "unsupported" and istatus != 200:
                record["verdict"] = "unsupported"
            else:
                record["verdict"] = ("known" if cell["expect"] == "diverge"
                                     else "unexpected")
            record["kind"] = "error"
            record["index"] = {"status": istatus,
                               "errorNum": (ipayload or {}).get("errorNum"),
                               "errorMessage": (ipayload or {}).get("errorMessage")}
            record["scan"] = {"status": sstatus,
                              "errorNum": (spayload or {}).get("errorNum"),
                              "errorMessage": (spayload or {}).get("errorMessage")}
            results.append(record)
            log("%-32s %-6s index=%s scan=%s %s"
                % (cell["name"], record["verdict"].upper(), istatus, sstatus,
                   str(record["index"].get("errorMessage")
                       or record["scan"].get("errorMessage") or "")[:110]))
            continue

        index_rows = ipayload["result"]
        scan_rows = spayload["result"]
        diff = compare(cell, index_rows, scan_rows)
        record["index"] = {"status": 200, "count": len(index_rows),
                           "keys": sorted(by_key(index_rows))}
        record["scan"] = {"status": 200, "count": len(scan_rows),
                          "keys": sorted(by_key(scan_rows))}
        warnings = (ipayload.get("extra") or {}).get("warnings")
        if warnings:
            record["index"]["warnings"] = warnings
        warnings = (spayload.get("extra") or {}).get("warnings")
        if warnings:
            record["scan"]["warnings"] = warnings

        if diff is None:
            record["verdict"] = "agree"
            log("%-32s ok     index=%-3d scan=%-3d" % (cell["name"],
                                                       len(index_rows),
                                                       len(scan_rows)))
        else:
            record["verdict"] = ("known" if cell["expect"] == "diverge"
                                 else "unexpected")
            record["kind"] = "disagreement"
            record["diff"] = diff
            record["diff_summary"] = describe_diff(diff)
            log("%-32s %-6s index=%-3d scan=%-3d  %s"
                % (cell["name"], record["verdict"].upper(), len(index_rows),
                   len(scan_rows), record["diff_summary"]))
        results.append(record)
    return results


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def write_report(outdir, results, server, fixture_docs):
    unexpected = [r for r in results if r["verdict"] == "unexpected"]
    known = [r for r in results if r["verdict"] == "known"]
    unsupported = [r for r in results if r["verdict"] == "unsupported"]
    agreed = [r for r in results if r["verdict"] == "agree"]

    # Every finding has to stand on its own: which binary, which fixture, which
    # queries, both answers.
    context = {
        "driver": "fuzz/iresearch_pushdown.py",
        "arangod": server.arangod,
        "collection": COLLECTION,
        "view": VIEW,
        "view_with_store_values": VIEW_SV,
        "documents": fixture_docs,
    }

    if unexpected:
        os.makedirs(outdir, exist_ok=True)
        for record in unexpected:
            record["context"] = context
            cell_dir = os.path.join(outdir, record["cell"]["name"])
            os.makedirs(cell_dir, exist_ok=True)
            with open(os.path.join(cell_dir, "finding.json"), "w",
                      encoding="utf-8") as f:
                json.dump(record, f, indent=2, sort_keys=True)
                f.write("\n")

    lines = []
    lines.append("# IResearch pushdown matrix: %d cell(s), %d wrong answer(s) "
                 "in %d failure group(s)"
                 % (len(results), len(unexpected),
                    len({r["cell"]["family"] for r in unexpected})))
    lines.append("")
    lines.append("Generated by `fuzz/iresearch_pushdown.py` against arangod "
                 "`%s`." % server.arangod)
    lines.append("")
    lines.append("Fixture: collection `%s`, %d documents; view `%s` "
                 "(includeAllFields, `s` also analyzed with `%s`) and view "
                 "`%s` over the same collection with `storeValues: id`."
                 % (COLLECTION, fixture_docs, VIEW, ANALYZER, VIEW_SV))
    lines.append("")
    lines.append("%d cell(s) agree, %d diverge by design, %d form(s) SEARCH "
                 "refuses, %d wrong answer(s)."
                 % (len(agreed), len(known), len(unsupported), len(unexpected)))
    lines.append("")
    lines.append("| cell | type | form | view | index | scan | verdict |")
    lines.append("| ---- | ---- | ---- | ---- | ----- | ---- | ------- |")
    for record in results:
        cell = record["cell"]
        counts = ("%s" % record["index"].get("count", record["index"].get("status")),
                  "%s" % record["scan"].get("count", record["scan"].get("status")))
        verdict = {"agree": "agree", "known": "known divergence",
                   "unsupported": "SEARCH refuses it",
                   "unexpected": "**WRONG ANSWER**"}[record["verdict"]]
        lines.append("| `%s` | %s | %s | %s | %s | %s | %s |"
                     % (cell["name"], cell["column"], cell["form"],
                        cell["view"], counts[0], counts[1], verdict))
    lines.append("")

    if unexpected:
        lines.append("## Wrong answers")
        lines.append("")
        lines.append("%d cell(s), %d distinct failure(s)."
                     % (len(unexpected),
                        len({r["cell"]["family"] for r in unexpected})))
        lines.append("")
        families = []
        for record in unexpected:
            if record["cell"]["family"] not in families:
                families.append(record["cell"]["family"])
        for family in families:
            records = [r for r in unexpected if r["cell"]["family"] == family]
            lines.append("### %s (%d cell(s))" % (family, len(records)))
            lines.append("")
            if family in FAMILIES:
                lines.append(FAMILIES[family])
                lines.append("")
            for record in records:
                cell = record["cell"]
                lines.append("#### `%s` (%s x %s)"
                             % (cell["name"], cell["column"], cell["form"]))
                lines.append("")
                if cell["note"]:
                    lines.append("Assumption: %s" % cell["note"])
                    lines.append("")
                lines.append("```aql")
                lines.append(record["index_query"])
                lines.append("```")
                lines.append("")
                lines.append("```aql")
                lines.append(record["scan_query"])
                lines.append("```")
                lines.append("")
                if record["kind"] == "error":
                    lines.append("One side failed: index `%s`, scan `%s`."
                                 % (json.dumps(record["index"]),
                                    json.dumps(record["scan"])))
                else:
                    lines.append("What differs: %s" % record["diff_summary"])
                    lines.append("")
                    lines.append("Index keys: `%s`"
                                 % json.dumps(record["index"]["keys"]))
                    lines.append("")
                    lines.append("Scan keys: `%s`"
                                 % json.dumps(record["scan"]["keys"]))
                lines.append("")

    if unsupported:
        lines.append("## Predicate forms SEARCH refuses")
        lines.append("")
        lines.append("The collection answers these, the view rejects them. "
                     "Not a wrong answer -- no data is returned at all -- but "
                     "a query that works on a collection and fails on a view "
                     "is still a pushdown trap.")
        lines.append("")
        for record in unsupported:
            cell = record["cell"]
            lines.append("- `%s` (%s x %s): `%s` -> HTTP %s %s"
                         % (cell["name"], cell["column"], cell["form"],
                            record["index_query"],
                            record["index"].get("status"),
                            str(record["index"].get("errorMessage"))[:200]))
        lines.append("")

    if known:
        lines.append("## Divergences by design")
        lines.append("")
        lines.append("Cells whose two sides are not supposed to agree; they "
                     "are measured so that a *new* divergence in the same "
                     "family is visible.")
        lines.append("")
        for record in known:
            cell = record["cell"]
            lines.append("- `%s` (%s x %s): %s"
                         % (cell["name"], cell["column"], cell["form"],
                            cell["note"] or "(no note)"))
            if record["kind"] == "disagreement":
                lines.append("  - %s" % record["diff_summary"])
        lines.append("")

    lines.append("## Reproduction")
    lines.append("")
    lines.append("```sh")
    lines.append("python3 fuzz/iresearch_pushdown.py")
    lines.append("```")
    lines.append("")
    lines.append("The driver starts its own server on a temporary data "
                 "directory, so this is the whole reproduction.")
    lines.append("")

    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "summary.md"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(lines))

    return unexpected, known, unsupported, agreed


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None):
    tree = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(
        description="IResearch pushdown matrix fuzzer (index vs scan oracle)")
    parser.add_argument("--arangod", default="/build/build-asan/bin/arangod",
                        help="arangod binary (default: the sanitized build)")
    parser.add_argument("--tree", default=tree,
                        help="source tree, used to find tzdata and ICU data")
    parser.add_argument("--port", type=int, default=0,
                        help="port for the test server (default: any free one)")
    parser.add_argument("--datadir", default=None,
                        help="data directory (default: a temporary one)")
    parser.add_argument("--keep-datadir", action="store_true",
                        help="do not delete the data directory on exit")
    parser.add_argument("--out", default=None,
                        help="report directory (default: "
                             "fuzz/findings/<date>-iresearch-pushdown)")
    parser.add_argument("--cells", default=None,
                        help="comma-separated substrings of cell names to run")
    parser.add_argument("--list-cells", action="store_true",
                        help="print the matrix and exit")
    parser.add_argument("--startup-timeout", type=float, default=180.0)
    parser.add_argument("--query-timeout", type=float, default=300.0)
    parser.add_argument("--log-level", default="info")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--self-test", action="store_true",
                        help="break the scan side of a few cells on purpose "
                             "and fail unless the oracle reports every one")
    args = parser.parse_args(argv)

    cells = build_cells()
    if args.list_cells:
        for cell in cells:
            print("%-30s %-8s %s" % (cell["name"], cell["column"],
                                     cell["form"]))
        print("\n%d cell(s)" % len(cells))
        return 0

    if args.cells:
        wanted = [w.strip() for w in args.cells.split(",") if w.strip()]
        cells = [c for c in cells if any(w in c["name"] for w in wanted)]
        if not cells:
            parser.error("--cells matched no cell; see --list-cells")

    # The oracle has to be shown to fire: a comparison that cannot fail would
    # report "no findings" for a broken server. --self-test runs a few cells
    # with a deliberately wrong scan side and demands a finding for each.
    if args.self_test:
        wrong_scan = {
            "string-eq": 'doc.s == "hello"',
            "numeric-eq": "doc.n == 2",
            "null-eq": 'HAS(doc, "nul") AND doc.nul == "x"',
            "all-docs": "false",
        }
        by_name = {c["name"]: c for c in cells}
        missing = [n for n in wrong_scan if n not in by_name]
        if missing:
            print("--self-test needs cell(s) %s; see --list-cells"
                  % ", ".join(missing), file=sys.stderr)
            return 2
        cells = [by_name[name] for name in wrong_scan]
        for cell in cells:
            cell["scan"] = wrong_scan[cell["name"]]
            cell["scan_lets"] = []
        print("self-test: %d cell(s) with a broken scan side" % len(cells))

    def log(message):
        if not args.quiet:
            print(message, flush=True)

    outdir = args.out or os.path.join(tree, "fuzz", "findings",
                                      DATE + "-iresearch-pushdown")
    if args.self_test and not args.out:
        # A self-test is not a finding; keep it out of the findings tree.
        outdir = os.path.join(tempfile.mkdtemp(prefix="pushdown-self-test-"),
                              "report")
    if not os.path.exists(args.arangod):
        print("arangod not found at %s" % args.arangod, file=sys.stderr)
        return 2

    datadir = args.datadir
    temporary = datadir is None
    if temporary:
        datadir = tempfile.mkdtemp(prefix="iresearch-pushdown-")
    port = args.port or free_port()

    server = Server(args.arangod, os.path.join(datadir, "db"), port, args.tree,
                    args.log_level)
    client = Client(server.base, timeout=args.query_timeout)
    docs = build_fixture()

    def on_signal(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_signal)

    exit_code = 0
    try:
        log("starting %s on port %d, data directory %s"
            % (args.arangod, port, datadir))
        server.start()
        server.wait_ready(time.time() + args.startup_timeout)
        log("server ready: %s" % json.dumps(client.request("GET",
                                                          "/_api/version")[1]))
        create_fixture(client, docs)
        log("fixture: %d documents in %s, views %s and %s"
            % (len(docs), COLLECTION, VIEW, VIEW_SV))
        results = run_cells(client, cells, log)
        unexpected, known, unsupported, agreed = write_report(
            outdir, results, server, len(docs))
        log("")
        log("%d cell(s): %d agree, %d by design, %d refused by SEARCH, "
            "%d WRONG ANSWER(s) in %d failure group(s)"
            % (len(results), len(agreed), len(known), len(unsupported),
               len(unexpected),
               len({r["cell"]["family"] for r in unexpected})))
        log("report: %s" % outdir)
        if args.self_test:
            silent = [r["cell"]["name"] for r in results
                      if r["verdict"] != "unexpected"]
            if silent:
                log("SELF-TEST FAILED: the oracle missed %s" % ", ".join(silent))
                exit_code = 2
            else:
                log("self-test ok: every deliberately broken cell was reported")
            if not server.alive():
                exit_code = 2
            return exit_code
        if not server.alive():
            log("arangod is gone; last log lines:\n%s" % server.log_tail())
            exit_code = 2
        elif unexpected:
            exit_code = 1
    except HarnessError as e:
        print("harness error: %s" % e, file=sys.stderr)
        if server.proc is not None:
            print(server.log_tail(), file=sys.stderr)
        exit_code = 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        exit_code = 2
    finally:
        reports = server.asan_reports()
        server.stop()
        if reports:
            print("sanitizer reports: %s" % ", ".join(reports), file=sys.stderr)
        if temporary and not args.keep_datadir:
            shutil.rmtree(datadir, ignore_errors=True)
        elif temporary:
            print("data directory kept at %s" % datadir, file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
