# 2026-11-08 AQL: a computed object key in a WINDOW spec aborts the parser

Found by `fuzz/aql_mutator.h`'s self-test run against a live 4.0.0-devel
maintainer build (`POST /_api/query` as the parse oracle). The mutant came from
the built-in seed `FOR doc IN col WINDOW { preceding: 1, following: 1 }
AGGREGATE s = SUM(doc.x) RETURN s`, mutated by the name/keyword operators.

## Reproduce

```sh
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"query": "FOR doc IN col WINDOW { [preceding]: 1, following: 1 } AGGREGATE s = SUM(doc.x) RETURN s"}' \
  http://127.0.0.1:8529/_api/query
```

The server dies, SIGABRT:

```
FATAL [a7902] {crash} thread 13 [SchedWorker] caught unexpected signal 6 (SIGABRT)
  assertion failed in arangod/Aql/Parser/grammar.y:413
  [bool (anonymous namespace)::validateWindowSpec(Parser *, const AstNode *, int, int)]:
  member->type == NODE_TYPE_OBJECT_ELEMENT
```

No collections need to exist: the query is rejected or asserted at parse time.

## Why it matters

`validateWindowSpec` walks the members of the `WINDOW` specification assuming
each one is a `NODE_TYPE_OBJECT_ELEMENT`. A computed key (`[expr]: value`)
inside that object literal produces a member of another type, and the
maintainer build asserts. In a release build `TRI_ASSERT` is compiled out, so
the same query continues into code that reads a member of the wrong node type —
that path, not the assert, is the bug worth chasing.

## What does not crash

* `FOR doc IN col WINDOW { preceding: 1, following: 1 } AGGREGATE s = SUM(doc.x) RETURN s`
  — the plain spec parses.
* `FOR doc IN col WINDOW { preceding: 1, following: 1 }{ name: 1 } AGGREGATE ...`
  — a 400 syntax error, `errorNum` 1501.

Three separate mutants of the same seed reproduced it in one self-test run
(`[preceding]`, `[following]`, and `[preceding]: 10`), so the trigger is the
computed key and nothing about the values.
