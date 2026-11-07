# 2025-11-06 vpack: `Validator::validateIndexedArray` out-of-bounds read (8-byte, before buffer)

ASan heap-buffer-overflow found by `vpack_fuzzer` about 10 seconds into its
first campaign run. UBSan flagged the same site as a pointer-arithmetic wrap
(`Validator.cpp:419`).

## Reproduce (exact command)

```sh
/tmp/fuzzverify/bin/vpack_fuzzer \
  /home/dead/Projects/arangodb/arangodb/fuzz/findings/2025-11-06-vpack-validator-indexed-array-oob/minimized-input
```

Minimised input (18 bytes):

```
00000000: 0900 0000 0000 0000 0000 39f4 0039 f400  ..........9..9..
00000010: 39f4                                     9.
```

Build it first with the configure/build commands in `fuzz/README.md`
(throwaway sanitized tree; on this box additionally
`-DBLAS_openblas_LIBRARY=... -DLAPACK_openblas_LIBRARY=...` and the
`-I/-L .../deps/omp` suffixes on `BASE_C_FLAGS`/`BASE_CXX_FLAGS` as in
`build-asan`).

## Report (top frames)

```
==3==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 8 ... thread T0
    #1 readIntegerFixed<unsigned long, 8ul>        3rdParty/velocypack/include/velocypack/velocypack-common.h:353
    #2 readIntegerNonEmpty<unsigned long>(...)     3rdParty/velocypack/include/velocypack/velocypack-common.h:387
    #3 velocypack::Validator::validateIndexedArray 3rdParty/velocypack/src/Validator.cpp:411
    #4 velocypack::Validator::validateArray        3rdParty/velocypack/src/Validator.cpp:278
    #5 velocypack::Validator::validatePart         3rdParty/velocypack/src/Validator.cpp:138
    #6 velocypack::Validator::validate             3rdParty/velocypack/src/Validator.cpp:74
    #7 LLVMFuzzerTestOneInput                      fuzz/vpack_fuzzer.cpp:45

0x... is located 8 bytes before 18-byte region  (allocated by libFuzzer)
SUMMARY: AddressSanitizer: heap-buffer-overflow in __asan_memcpy
```

## Analysis

Head byte `0x09` is an indexed array with 8-byte byte-length and 8-byte index
width. The claimed length makes `validateIndexedArray` compute the index-table
position outside the given buffer (here: 8 bytes *before* it), and it reads the
first 8-byte index entry without a bounds check against the `length` parameter.
`Validator::validate` is the API used to check *untrusted* VPack (e.g. request
bodies with `Content-Type: application/x-velocypack`), so a malformed body
reads out of bounds instead of throwing `velocypack::Exception`.

Found against tree revision `034a10b2f4337bbd16229a1c76a72a19823f461a`
(velocypack 0.1.33 per its CMakeLists, `include/velocypack/velocypack-version-number.h`
says 0.2.1).

Original crash artifact before minimisation: 36 bytes, hash
`05c38c7b88717f571d76bd10bb262a606e1cecdd`; minimisation via
`vpack_fuzzer -minimize_crash=1 -runs=100000 <artifact>`.

## Reachable from a running server (verified)

`lib/Rest/HttpRequest.cpp:893-905` runs `VPackValidator::validate()` on the raw
body whenever a request claims `Content-Type: application/x-velocypack`, so any
unauthenticated client reaches this code.

Body size decides whether the read lands outside the allocation. The 18-byte
minimised input posted on its own stays *inside* the connection's read buffer:
the server answers `400 "VPack error: Array index table is out of bounds"` and
lives. Padded to 200 bytes (`http-body-200.bin`, the same 18-byte prefix then
`A` bytes) the body gets its own allocation and the read hits the ASan redzone:

```sh
curl -X POST -H 'Content-Type: application/x-velocypack' \
     --data-binary @http-body-200.bin http://127.0.0.1:8536/_api/collection
```

```
==2==ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 8
  #1 readIntegerFixed<unsigned long, 8>   velocypack-common.h:353
  #2 readIntegerNonEmpty<unsigned long>   velocypack-common.h:387
  #3 Validator::validateIndexedArray      Validator.cpp:411
  #4 Validator::validateArray             Validator.cpp:278
  #6 Validator::validate                  Validator.cpp:74
```

followed by `{crash} 💥 ArangoDB 4.0.0-devel [linux-DEBUG] ... SIGABRT` in
`SchedWorker`; the full report is `server-asan-report.txt`.

Notes for reproducing the server side:
- the sanitized build must use `-DUSE_JEMALLOC=Off` (jemalloc and ASan cannot
  share `malloc`; without this the binary segfaults before `main`);
- `UBSAN_OPTIONS=halt_on_error=1` aborts on rocksdb's intentional misaligned
  CRC loads (`crc32c.cc:526`, `:1084`) — keep it recoverable for the server and
  treat `runtime error:` lines as leads;
- `ASAN_OPTIONS=log_path=<dir>/asan` keeps the report when the process aborts.

## Cause and fix (verified both directions)

`byteSize` is attacker-controlled and was only checked for being too *large*
(`byteSize > length`). The `nrItems` field and the index table both live inside
`byteSize`, so a `byteSize` smaller than them makes
`ptr + byteSize - byteSizeLength` point *before* `ptr`, and the read happens
before any range check.

`fix.diff` adds the missing lower bound in `validateIndexedArray`:

```cpp
if (byteSize < 2 * byteSizeLength + 1) {
  throw Exception(Exception::ValidatorInvalidLength, "Array length is too small");
}
```

Verified in both directions with a throwaway `-DUSE_FUZZERS=On` sanitized tree:

| build | `vpack_fuzzer minimized-input` |
|---|---|
| unpatched | `ERROR: AddressSanitizer: heap-buffer-overflow` in `readIntegerNonEmpty` (velocypack-common.h:387) |
| patched | exit 0, no report |

The fix is not applied in the tree (`3rdParty/velocypack` is clean); `fix.diff`
is the proposal. Note that this rejects only the impossible `byteSize`; the
upstream fix may prefer to clamp `nrItems` against `byteSize` as well.
