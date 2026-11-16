# Limits audit: every network-facing buffer a client can fill

Tree: `/home/dead/Projects/arangodb/arangodb` @ `d7e1119d5d2` (4.0.0-devel, community,
maintainer mode). Read-only source audit of the request path; every bound below is
cited to the line that enforces it (or to the absence of one). Where a bound was in
doubt the shipped binary (`build/bin/arangod`, `-c none`, `--server.authentication
false`, loopback, 32 cores / 190 GiB) was run and `VmRSS`/`VmSize` read from
`/proc/<pid>/status` while a script filled exactly one buffer. Measured numbers are
marked **(measured)**; everything else is the source's own bound.

Reach is ordered **pre-auth** (before any credential is checked) → **auth** (any
authenticated user, any privilege level) → **admin** (root / db-RW).

## The table

| # | buffer | file:line | what bounds it | reach | the measurement that decides it |
|---|--------|-----------|----------------|-------|--------------------------------|
| 1 | connection slot (`_commTasks`) | `arangod/GeneralServer/GeneralServer.h:79`, accept at `AcceptorTcp.cpp:151` | **nothing** — one `std::map` entry per connection, no cap anywhere in `GeneralServer`/`Acceptor` | pre-auth | sockets opened vs server RSS: `held = n_idle × per_conn` **(measured 35 020 B/conn idle, 200 conns)** |
| 2 | per-connection read buffer (`asio::streambuf`) | `GeneralCommTask.h:61` (`ReadBlockSize` 32 KiB), prepared at `GeneralCommTask.cpp:118`, `HttpCommTask.cpp:497` | 32 KiB per read; grows only with bytes the parser does not consume | pre-auth | bytes sent vs RSS while a request is unfinished: **(measured 11 468 B/conn with a header section left open)** |
| 3 | request line / URL (`_url`) | `arangod/GeneralServer/HttpCommTask.cpp:133` (`_url.append`), `:260` → `parseUrl` | **nothing** — llhttp has no URL length limit and no cap is applied here | pre-auth | URL bytes sent vs RSS held: expect ≈1:1 with no ceiling |
| 4 | header name/value (`_lastHeaderField`, `_lastHeaderValue`, `_headers`) | `HttpCommTask.cpp:154-175`, stored at `:152`/`:188` → `lib/Rest/HttpRequest.cpp:620` (`_headers.try_emplace`) | **nothing** — no count, no length, no total | pre-auth | header bytes sent vs RSS held: **(measured 2.21 B held per byte sent for a single 64 MiB header value; +144 900 KiB)** |
| 5 | HTTP/1 body (`_payload`) | append `lib/Rest/HttpRequest.cpp:118-121`; the only check `HttpCommTask.cpp:206-210` against `CommTask.h:104` (`MaximalBodySize` = 1 GiB) | 1 GiB per request, checked at *headers_complete* — i.e. before any body byte is buffered | pre-auth (body is buffered at `HttpCommTask.cpp:243` long before `checkAuthHeader` at `:604`) | bytes sent vs bytes held for a body just under the cap: **(measured 1.06 B held per byte sent, 64 MiB body → +69 652 KiB)** |
| 6 | `Content-Length` pre-reservation | `lib/Rest/HttpRequest.cpp:583-587` — `reserve(min(2<<26, len))` = **128 MiB** on the header alone | 128 MiB of *virtual* per request, held from the header line until the request ends | pre-auth | `VmSize` per connection: **(measured 171 651 891 B VmSize per connection for `Content-Length: 1073741824` with no body; VmRSS unmoved, pages untouched)** |
| 7 | HTTP/2 header block per stream | `arangod/GeneralServer/H2CommTask.cpp:135-140` (`headerBuffSize` > 64 MiB → RST_STREAM) | 64 MiB per stream × 32 streams = **2 GiB per connection** | pre-auth (dispatch is at END_STREAM, `H2CommTask.cpp:175-185`) | header bytes sent vs RSS held, with 32 streams open at once: ratio should stay ≈1:1 up to 2 GiB |
| 8 | HTTP/2 body | `H2CommTask.cpp:205-225`; released at `:235-241` | 1 GiB per stream **and** 1 GiB per connection (`_bufferedBodyBytes`), RST + `ENHANCE_YOUR_CALM` over | pre-auth | bytes sent vs bytes held across 32 streams: which of the two caps fires first |
| 9 | HTTP/2 stream table (`_streams`) | `H2CommTask.h:140`, `createStream` `H2CommTask.cpp:1063`; cap advertised at `:371` (`H2MaxConcurrentStreams` = 32, `H2CommTask.h:41`) | 32 concurrent streams, enforced by nghttp2 on receive | pre-auth | distinct stream ids opened vs RST_STREAM/REFUSED: **(measured 1 200 fast requests → 1 068 RST_STREAM, 132 responses)** |
| 10 | HTTP/2 timing map (`_statisticsMap`) | `CommTask.cpp:543-547` (`acquireTimingData` per stream) vs `:554-563` (erase **only** in `stealTimingData`, i.e. on dispatch); `on_stream_close` (`H2CommTask.cpp:244-262`) does not erase | **nothing** for a stream that is reset before END_STREAM — the entry lives as long as the connection | pre-auth | distinct aborted stream ids vs RSS: **(measured 302–925 B/stream over 1 200 aborted streams; also: the server sent GOAWAY(INTERNAL_ERROR) at stream 2003 after ~1 001 abort-reset streams — see §2.4)** |
| 11 | TLS handshake | `AcceptorTcp.cpp:189` (60 s timer) | 60 s per connection, then the socket is shut down | pre-auth | connection lifetime vs timer: must die at 60 s |
| 12 | pre-first-byte (before 18 bytes) | `HttpCommTask.cpp:496-501` — `async_read(transfer_at_least(18))` with **no timer armed**; `setIOTimeout()` first runs inside `asyncReadSome` (`GeneralCommTask.cpp:121`) | **nothing** — a connection that never sends 18 bytes is never timed out | pre-auth | wall-clock lifetime of a connection that sends 0–17 bytes: unbounded is the bug |
| 13 | decompressed request body | `CommTask.cpp:955-958`; `GeneralServerFeature.cpp:406-409`; defaults `GeneralServerOptions.cpp:32` (10 % of RAM global) and `lib/Basics/EncodingUtils.h:35` (512 MiB per request) | 512 MiB per request + 10 % of physical RAM globally, both reserved before unpacking | auth (decode runs at `HttpCommTask.cpp:619`, after `prepareExecution`) | compressed bytes sent vs decompressed bytes held: ratio is the amplification the caps exist for |
| 14 | response body of an unwritten response | `HttpCommTask.cpp:783-787` (`stealBody`) → `:836-872` (`async_write`) | **nothing** — no write timer on HTTP/1 (see §3); body is held until the socket accepts it | auth | bytes held per stalled connection: **(measured 118.9 MB response unread on 4 connections → +74 552 KiB in 25 s; the kernel absorbed the first ~2–3 MB/socket, the rest stays in the response buffer)** |
| 15 | HTTP/2 response queue + held responses | `H2CommTask.h:136-138` (`boost::lockfree::queue`, capacity 32), push-retry at `H2CommTask.cpp:770-789`, bodies parked in `Stream::response` (`H2CommTask.h:96`) | 32 queued responses; bodies unbounded, one per stream | auth | 32 requests for large results with no reads: bytes held per connection |
| 16 | async job store (`x-arango-async: store`) | `AsyncJobManager.h:107` (`JobList _jobs`, `unordered_map`), insertion at `CommTask.cpp:492-507`, deletion only by `DELETE /_api/job/...` (`RestJobHandler.cpp:235`) | **nothing** — no TTL, no count cap, no eviction thread | auth | distinct job ids vs RSS: monotonic, one full response body per job |
| 17 | cursor registry | `arangod/Utils/CursorRepository.cpp:345` (`garbageCollect` — TTL only), TTL default `QueryRegistryOptionsProvider.cpp:420` (30 s single / 600 s coordinator); cluster side `Aql/QueryRegistry.cpp` | TTL expiry only; **no count cap, no byte cap**; each cursor's query memory is capped at 25 % of available RAM by default (`QueryRegistryFeatureOptions.cpp:118` + the `0.25*available` floor at `:110`) | auth | distinct live cursors vs RSS: creation rate vs expiry rate |
| 18 | AQL query result cache | `arangod/Aql/QueryCache.cpp:53-60` (128 entries, 256 MiB, 16 MiB/entry), enforced at `:643`, `:656-665` | per database: 128 entries / 256 MiB / 16 MiB per entry, LRU-ish eviction | auth | distinct query strings vs cache size: must plateau at 256 MiB × #databases (`--database.max-databases` default `SIZE_MAX`, `DatabaseFeatureOptions.h:41`) |
| 19 | JWT cache | `arangod/Auth/TokenCache.cpp:63` (`_jwtCache(16384)`) | LRU, 16 384 entries | auth | distinct JWTs presented vs entries: must plateau |
| 20 | basic-auth cache | `arangod/Auth/TokenCache.h:129` (`std::unordered_map _basicCache`), insert only on success `TokenCache.cpp:197-198` | **nothing** — one entry per distinct *valid* `Authorization` secret, cleared only when the user store version changes | auth | distinct valid secrets (e.g. many personal access tokens) vs RSS |
| 21 | analyzer definitions | `arangod/IResearch/IResearchAnalyzerFeature.cpp:103` (`ANALYZER_PROPERTIES_SIZE_MAX` 1 MiB), checked `:1221-1226`; map `IResearchAnalyzerFeature.h:531` | 1 MiB per definition, **no cap on the number of definitions** | auth with db-RW (`RestAnalyzerHandler.cpp:169` → `canUse(..., Modify)`) | distinct definitions vs RSS: instance cache (`_cache.emplace`, `:948`) dedups identical ones, so the key space is distinct (type, properties) |
| 22 | user store | `arangod/RestHandler/RestUsersHandler.cpp:362` (`canCreateUser`) | **nothing** — one `_users` document per user, bounded by disk | admin | distinct users vs RSS/collection size |

## 1. HTTP request body — when is `Content-Length` checked, when is the body buffered?

**Checked first, buffered second — for `Content-Length`.** `on_header_complete`
(`HttpCommTask.cpp:184-240`) runs `if (p->content_length > MaximalBodySize)` at
line 206 and answers 413 before a single body byte is accepted. `MaximalBodySize`
is a compile-time 1 GiB (`CommTask.h:104`) and is **not configurable** — there is no
`--http.max-request-body-size` option in this tree. The body then accumulates
unboundedly in `HttpRequest::_payload` (`HttpRequest.cpp:118-121`), which is correct
only because the cap was already applied; `appendBody` itself checks nothing.

**The 1 GiB is per request, and a request is per connection** (HTTP/1 processes one
message at a time), so the per-connection pre-auth ceiling is 1 GiB of body **plus**
128 MiB of reservation (below) **plus** the header section (unbounded, §1.1).

**`Content-Length` also buys a 128 MiB allocation before the body arrives**:
`HttpRequest::setHeader` special-cases the header and does
`_payload.reserve(min(2<<26, len))` (`HttpRequest.cpp:583-587`). Measured: 20
connections sending only headers with `Content-Length: 1073741824` grew `VmSize` by
3 352 576 KiB (171 651 891 B/connection ≈ 128 MiB + slack) with `VmRSS` unmoved —
untouched pages. So the *reservation* is cheap to hold but is a hard 128 MiB of
address space per in-flight request; the *body* is the 1:1 part (measured 1.06 B
held per byte sent).

**Chunked transfer encoding is not implemented**: `transferEncodingContainsChunked`
(`HttpCommTask.cpp:79-91`) answers 501 `"Support for Transfer-Encoding: chunked is
not implemented."` from `on_header_complete:196-198`. So there is no chunked path to
bound — the 1 GiB check is the only body path, and it is always reached because a
`Content-Length` is mandatory for a body.

### 1.1 The header section is the unbounded one

Nothing bounds the request line or the headers:
`_url.append` (`:133`), `_lastHeaderValue.append` (`:171`), and
`_headers.try_emplace` (`HttpRequest.cpp:620`) have no length, count or total check,
and llhttp imposes none (`3rdParty/llhttp` carries no URL or header length guard). A single header value of 64 MiB grew RSS by 144 900 KiB
(2.21 B held per byte sent — llhttp's token buffer plus `std::string` doubling) and
the request never has to complete: `_messageDone` stays false, `readCallback`
returns `HPE_OK` and `asyncReadSome` re-arms the keep-alive timer (300 s default,
`GeneralServerOptions.h:34`; armed at `HttpCommTask.cpp:434-460`), so one byte every 299 s keeps the connection and the
buffer alive forever.

## 2. HTTP/2 (nghttp2)

### 2.1 What the server advertises (measured)

`submitConnectionPreface` (`H2CommTask.cpp:367-383`); captured SETTINGS from the
shipped binary:

```
MAX_CONCURRENT_STREAMS = 32            (H2MaxConcurrentStreams, H2CommTask.h:41)
INITIAL_WINDOW_SIZE    = 1073741823    (window_size = (1<<30)-1, :367)
MAX_FRAME_SIZE         = 16384         (:376)
ENABLE_PUSH            = 0             (:377)
```

The connection-level window is deliberately **not** raised — the
`nghttp2_session_set_local_window_size` call is commented out (`:380-382`) — and
nghttp2's default is auto-window-update, so flow control is not used as
backpressure in either direction: every DATA chunk is consumed in
`on_data_chunk_recv` and a WINDOW_UPDATE goes back immediately.

### 2.2 Body

`on_data_chunk_recv` (`H2CommTask.cpp:205-225`) caps `strm->bodySize` (1 GiB) and
`_bufferedBodyBytes` (1 GiB for the whole connection) and resets the stream with
`ENHANCE_YOUR_CALM` over the limit; `releaseBufferedBody` (`:235-241`) returns the
bytes at dispatch (`:622`) and at stream close (`:260`, `:328`). Because dispatch
only happens at END_STREAM (`:175-185`), the 1 GiB is reachable **before** any
credential is looked at (`checkAuthHeader` is at `:693`).

### 2.3 Headers

`on_header` (`:135-140`) accumulates `headerBuffSize` per stream and RSTs above
64 MiB. That is per stream, and 32 streams are allowed, so **2 GiB per connection**
is the pre-auth header ceiling. nghttp2 does not bound this itself: its
`local_settings.max_header_list_size` defaults to `UINT32_MAX`
(`3rdParty/nghttp2-lib/lib/nghttp2_session.c:403`) and is only used when *sending*,
so the 64 MiB check is the only bound.

### 2.4 Two observations from driving it

* **32 streams is enforced**: 1 200 requests sent as fast as the socket accepted
  them produced 1 068 `RST_STREAM` (refused) and 132 responses.
* **Aborted streams leave a timing entry behind.** `on_begin_headers` calls
  `acquireTimingData(sid)` (`:98`); the only erase is `stealTimingData` on dispatch
  (`CommTask.cpp:554-563`). A client that sends HEADERS *without* END_STREAM and
  then RST_STREAM never dispatches, so the entry is never erased and `_streams` is
  cleaned (`H2CommTask.cpp:249-262`) but `_statisticsMap` is not. Measured RSS
  growth 302–925 B per aborted stream. The same loop made the server emit
  `GOAWAY(last_stream_id=2003, error=INTERNAL_ERROR)` once per connection after
  ~1 001 abort-reset streams (not reproduced with 1 200 *completed* requests, which
  produced no GOAWAY) — a client can make the server end the connection with an
  internal error, and the leak is bounded per connection at roughly that point.

## 3. Send buffer: a client that writes requests and never reads responses

**HTTP/1 has backpressure, but no write timeout.** After a complete message llhttp
is paused (`on_message_complete` returns `HPE_PAUSED`, `:269`), `readCallback`
returns false, and reads are re-armed only after the response has been written
(`:866-871`). So exactly one response is in flight per connection and further
requests are not even parsed. But `writeResponse` (`:836-872`) arms no timer, and
the keep-alive timer armed during the last read fires with both `wasReading` and
`wasWriting` stale (`setIOTimeout`, `:434-460`) and does nothing. The whole body
sits in `_response` (`stealBody`, `:784`) until the kernel accepts it.

Measured: a 118.9 MB cursor response left unread on 4 connections held
+74 552 KiB after 25 s (~18.6 MB/connection) — the socket buffers absorbed the
first few MB each and the rest stayed in the handler. A 2.4 MB response is absorbed
entirely by the socket buffer and costs nothing, which is why small-response tests
show no effect.

**HTTP/2 does not backpressure the reader at all.** `readCallback` returns true
unconditionally (`:537-542`) whatever the write state, so requests keep being
dispatched while responses are stuck. The only throttle is 32 concurrent streams
(§2.4) and the response queue of 32 (`H2CommTask.h:136-138`), after which
`sendResponse` spins 512 times and resets the stream (`:770-789`). The write timer
exists here (`WriteTimeout` 300 s, `GeneralCommTask.h:62`, used at `H2CommTask.cpp:556`)
but it only closes when `_numProcessing == 0` (`:571-582`) — a client that keeps
requests in flight never times out.

Net: bytes held per stalled connection = one response body (HTTP/1) or up to 32
(H2), with no ceiling on either body and no time bound on HTTP/1.

## 4. Pre-auth state

| surface | where | bound |
|---|---|---|
| accepted sockets | `AcceptorTcp.cpp:151-153`, `GeneralServer.h:79` | none — no `--server.max-connections`, no per-IO-thread task cap |
| TLS handshake | `AcceptorTcp.cpp:189-199` | 60 s |
| bytes 0–17 of a connection | `HttpCommTask.cpp:496-501` | **none** — no timer is armed before `asyncReadSome` |
| request line + headers | §1.1 | none |
| HTTP/1 body | `HttpCommTask.cpp:206` | 1 GiB |
| HTTP/2 headers | §2.3 | 64 MiB/stream × 32 |
| HTTP/2 body | §2.2 | 1 GiB/connection |
| protocol sniffing | `checkProtocolUpgrade` (`:463-501`) | reads 32 KiB, matches the h2 preface / VST preface, else falls through to HTTP/1 — there is no VST server any more (`arangod/GeneralServer/` has no `VstCommTask`) |

The one thing a client pays for is an accepted connection: 32 KiB read buffer plus
task objects, **measured 35 020 B per idle connection** (200 connections that sent
nothing, +6 840 KiB), and 11 468 B once a header section is open. With no connection
cap, that is the multiplier a connection-flood fuzzer should measure.

## 5. Persistent-key growth (caps and eviction)

| store | cap | eviction |
|---|---|---|
| AQL query result cache | 128 entries / 256 MiB / 16 MiB per entry, **per database** (`QueryCache.cpp:53-60`) | on insert, LRU-ish (`:643-665`) |
| cursor registry | none (`CursorRepository.cpp:345`) | TTL only (30 s single / 600 s coordinator), collected lazily on cursor creation (`:87`) |
| AQL query memory | per query 25 % of available RAM by default (`QueryRegistryFeatureOptions.cpp:118`, floor at `:110`); global 25 % | resource monitor refuses the allocation |
| analyzer definitions | 1 MiB per definition, no count cap (`IResearchAnalyzerFeature.cpp:103`) | none; identical (type, properties) share an instance (`:948`) |
| users | none | none |
| async job results | none (`AsyncJobManager.h:107`) | only `DELETE /_api/job/<id>` or `/expired?stamp=` (`RestJobHandler.cpp:235`) |
| JWT cache | 16 384 (`TokenCache.cpp:63`) | LRU |
| basic-auth cache | none (`TokenCache.h:129`) | cleared when the user store version changes |

Two of these are worth a fuzzer of their own: the **async job store** (an
authenticated client sets `x-arango-async: store`, gets a job id back and never
deletes it — one full response body per job, forever) and the **cursor registry**
(no count cap; TTL is the only exit, and a client can create faster than it
expires).

## 6. What a limits fuzzer should assert

Each row above reduces to one of three oracles. None of them needs a crash:

1. **Amplification** — bytes held / bytes sent. Fill one buffer with a slow drip,
   sample `VmRSS` (and `VmSize` for reservations), and flag a ratio above the
   expected one. Calibrated from this audit: body 1.06×, one header value 2.21×,
   `Content-Length` reservation 171 MB of address space for a 96-byte request.
2. **Distinct keys vs heap** — create N distinct keys (headers, cursors, jobs,
   analyzers, users), delete or abandon them, and compare the RSS slope to the
   expected plateau. A plateau is a cap working; a straight line is a missing one.
   The calibration points are in §5: query cache must plateau, cursors and jobs
   must not.
3. **Time-to-hold** — how long one connection, one stream or one cursor can be held
   for a fixed number of bytes. The unbounded cases are: connection that never
   sends 18 bytes (§4), connection dripping headers (§1.1), HTTP/1 stalled write
   (§3), async job (§5).

Two things in this audit are code-level claims without a measurement behind them,
and the fuzzer should settle them first: the `_statisticsMap` entry left behind by
an aborted HTTP/2 stream (§2.4 — the erase path really is only `stealTimingData`,
but the RSS slope I measured is also consistent with allocator noise), and the
"no eviction" verdicts on the async job store and the cursor registry (§5), which
were read from the code and not driven.

The caps already in the tree are the ones a fuzzer must not mistake for a
finding: 1 GiB body (`CommTask.h:104`), 512 MiB decompressed / 10 % of RAM
(`EncodingUtils.h:35`, `GeneralServerOptions.cpp:32`), 64 MiB of HTTP/2 headers and
32 streams (`H2CommTask.cpp:137`, `H2CommTask.h:41`).

## Reproducing the measurements

`build/bin/arangod -c none --server.endpoint tcp://127.0.0.1:<port>
--database.directory <fresh dir> --server.authentication false --log.level warn
--log.output file:///tmp/arango-audit.log` (`-c none` matters: the packaged
`/etc/arangodb/arangod.conf` points the log at `/var/log/arangodb4/`, which makes a
non-root start die in `Logger::prepare`). Fill one buffer per connection with a raw
socket, sleep, read `VmRSS`/`VmSize` from `/proc/<pid>/status`, and compare against
a baseline taken after a few warm-up requests. HTTP/2 needs only hand-rolled frames:
the client preface, an empty SETTINGS, and `HEADERS` built from HPACK literals
without indexing (`0x00, len(name), name, len(value), value`) — that is enough to
open, fill and reset streams without a client library.
