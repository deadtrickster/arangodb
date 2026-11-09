# 2026-11-09 Replication batch: a non-object body answers 500 with an empty body

`POST /_api/replication/batch` (create a batch) and `PUT
/_api/replication/batch/<id>` (extend it) take a JSON object. Any other body —
an array, `null`, a number, a string, **or no body at all** — is answered with
`500` and a **completely empty response**: no `code`, no `error`, no
`errorNum`, no `errorMessage`. A malformed body (`{`) is answered correctly
with `400`/`errorNum 600`, so the bug is only on the "parsed, but not an
object" path.

## Reproduce

```sh
# create a batch: correct, 200 {"id":"...","lastTick":"..."}
curl -s -X POST -H 'Content-Type: application/json' --data '{"ttl":60}' \
  http://127.0.0.1:8529/_api/replication/batch

# every one of these answers 500 with an empty body (expected: 400 with an
# errorNum, as POST /_api/database and POST /_api/user do for the same input)
for body in '[]' '[1,2,3]' 'null' 'true' '1' '"x"' ''; do
  printf '%-10s -> ' "${body:-<none>}"
  curl -s -o /dev/null -w '%{http_code} %{size_download} bytes\n' \
    -X POST -H 'Content-Type: application/json' --data "$body" \
    http://127.0.0.1:8529/_api/replication/batch
done

# same on the extend path, with a live batch id
curl -s -o /dev/null -w '%{http_code} %{size_download} bytes\n' \
  -X PUT -H 'Content-Type: application/json' --data '[]' \
  http://127.0.0.1:8529/_api/replication/batch/<id>
```

Measured against a sanitized 4.0.0-devel build (community, maintainer mode,
`/build/build-asan/bin/arangod`, auth on):

| body | `POST .../batch` | `PUT .../batch/<id>` |
| ---- | ---------------- | -------------------- |
| `{}` / `{"ttl":60}` | 200 | 204 |
| `[]`, `[1,2,3]`, `null`, `true`, `1`, `"x"` | **500, 0 bytes** | **500, 0 bytes** |
| absent (`Content-Length: 0`) | **500, 0 bytes** | **500, 0 bytes** |
| `{` (unparseable) | 400, `errorNum 600` | 400, `errorNum 600` |

The connection survives and the server keeps serving; the defect is the status
class and the missing error envelope.

## Cause

`arangod/RocksDBEngine/RocksDBRestReplicationHandler.cpp`, both in
`handleCommandBatch()` (`POST`, ~line 86) and in the `PUT` branch (~line 164):

```cpp
bool parseSuccess = true;
VPackSlice body = this->parseVPackBody(parseSuccess);
if (!parseSuccess || !body.isObject()) {  // error already created
  co_return;
}
```

The comment is only true for the first half of the condition.
`RestBaseHandler::parseVPackBody` (`arangod/RestHandler/RestBaseHandler.cpp:50`)
sets `success = true` and returns the parsed slice whenever the body parses —
and for an absent body it returns a `noneSlice()` with `success = true`. So
`!body.isObject()` is reached with **no error generated**, and the handler
returns having written nothing: the response stays at the default `500` with an
empty payload.

The sibling handlers in `arangod/RestHandler/RestReplicationHandler.cpp` split
the two conditions correctly, e.g. `handleCommandAddFollower` (`:2053`):

```cpp
if (!success) { co_return; }                       // error already created
if (!body.isObject()) {                            // this one is not
  generateError(rest::ResponseCode::BAD, TRI_ERROR_HTTP_BAD_PARAMETER,
                "body needs to be an object with attributes ...");
  co_return;
}
```

## Fix

Same split at both sites, e.g.:

```cpp
if (!parseSuccess) {
  co_return;  // error already created
}
if (!body.isObject()) {
  generateError(rest::ResponseCode::BAD, TRI_ERROR_HTTP_BAD_PARAMETER,
                "request body must be a JSON object");
  co_return;
}
```

## How it was found

`fuzz/http_conversation.py` (the multi-request HTTP conversation fuzzer): its
replication conversation now sends a non-object body to both endpoints and
expects `400`. The same class is already known for `POST /_api/database` and
`POST /_api/user`; this driver found two more sites of it because it drives
the replication handshake end to end (logger-state → batch → inventory → dump →
delete) instead of probing single responses.

Revision: `d7e1119d5d2` on `devel` (4.0.0-devel, build-id 7633836a366f).
