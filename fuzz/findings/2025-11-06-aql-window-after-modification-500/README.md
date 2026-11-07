# 2025-11-06 AQL: a WINDOW after a data modification answers 500 instead of 400

Same class as the `FOR w IN c IN c` finding (`errorNum 1568`), and found the same
way the test-suite corpus was supposed to help: this query is **harvested from
ArangoDB's own `tests/js`**, not mutated by hand.

## Reproduce

```sh
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"query": "FOR doc IN @@input INSERT {value: doc.value} into @@output WINDOW {preceding: 1, following: 1} AGGREGATE av = AVG(doc.value) RETURN av"}' \
  http://127.0.0.1:8529/_api/query
```

```
HTTP 500
{"code":500,"error":true,
 "errorMessage":"window operation after data-modification","errorNum":1595}
```

The same query through `POST /_api/query` — the parse-only endpoint — already
fails at analysis, so nothing is being executed; the status is purely the
error-to-HTTP mapping.

## Cause

`lib/Basics/errors.dat:290` defines the error as a *user* error:

```
ERROR_QUERY_WINDOW_AFTER_MODIFICATION,1595,"window operation after data-modification",
"Will be raised when a window node is created after a data-modification operation."
```

`lib/Rest/GeneralResponse.cpp` maps user errors to `400` through a long
allow-list switch; `TRI_ERROR_QUERY_WINDOW_AFTER_MODIFICATION` is **not in it**
(`grep -c ERROR_QUERY_WINDOW_AFTER_MODIFICATION lib/Rest/GeneralResponse.cpp` → 0),
so it falls through to the default `500`.

## Fix

One `case` in that switch, next to its siblings:

```cpp
case static_cast<int>(TRI_ERROR_QUERY_WINDOW_AFTER_MODIFICATION):
```

## How it was found

`aql-seeds.txt`: 9 071 AQL strings extracted from `tests/js/**/*.js` (backtick and
double-quoted literals containing AQL keywords, no `${…}` interpolation). 600 of
them sampled through `POST /_api/query` against a fresh server:

| status | count |
|---|---|
| 200 (parsed) | 467 |
| 400 (genuinely invalid fragment) | 120 |
| 501 (MATCH is experimental) | 12 |
| **500** | **1** ← this query |

The point worth keeping: the corpus that found this was *the project's own
tests*, and 77.8 % of harvested queries parse — a far better seed set than the
18 hand-written queries used earlier.
