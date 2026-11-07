# 2026-11-07 RocksDB log::Reader spins forever on a recyclable type byte after a non-recyclable record

Found by the first `fuzz-infra` campaign against `rocksdb_wal_fuzzer` (the
pg-fuzz `xlogreader` port) — 27 seconds in, on a **2-byte input** (`88 00`).

## Reproduce

```sh
# build-asan tree, UBSan recoverable (rocksdb's crc32c reads unaligned on purpose)
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=0 \
  /build/build-asan/bin/rocksdb_wal_fuzzer \
  fuzz/findings/2026-11-07-rocksdb-logreader-recyclable-spin/input.bin
```

`input.bin` is `88 00`. The harness builds a valid three-record log around the
payload byte, flips the middle record's **type byte** to `136 % 16 = 8`
(`kRecyclableLastType`), and recomputes the CRC — so the record is
well-checksummed and the decoder parses it. `libFuzzer -timeout=25` fires:

```
#5 rocksdb::log::Reader::ReadPhysicalRecord   db/log_reader.cc:464
#6 rocksdb::log::Reader::ReadRecord           db/log_reader.cc:92
#7 LLVMFuzzerTestOneInput                     fuzz/rocksdb_wal_fuzzer.cpp:160
```

## Mechanism (verified in source)

`ReadPhysicalRecord` (db/log_reader.cc:486-491):

```cpp
if (is_recyclable_type) {
  header_size = kRecyclableHeaderSize;
  if (first_record_read_ && !recycled_) {
    return kBadRecord;      // ← buffer_ is NOT consumed
  }
```

and `ReadRecord`'s handler (db/log_reader.cc:274-280):

```cpp
case kBadRecord:
  if (in_fragmented_record) { ... }   // scratch cleanup only
  break;                              // ← back to the top of while(true)
```

A valid non-recyclable record is read first (`first_record_read_ = true`,
`recycled_ = false`); the next record's type byte then claims a recyclable type
(5–8 or 11). The guard returns `kBadRecord` **without advancing `buffer_` and
without setting `recycled_`**, the caller's `break` re-enters with the same
bytes, and the two frames spin forever. The CRC check at :534 is *after* the
guard, so checksum validity is irrelevant to reaching the loop.

## Reachability and impact

The mutated byte is exactly what byte-level WAL corruption produces: a flipped
type byte in an otherwise well-formed log. Recovery (`RocksDBRecoveryManager`
→ `log::Reader`) then hangs at 100% CPU with no progress and no report — a
**DoS on the data-recovery path**, the surface where a bug costs most. The
out-of-process WAL campaign never reached this: a flipped byte fails the CRC
and RocksDB discards the record before parsing it; only the CRC-recomputing
harness gets the decoder to execute on the mutant.

## Fix shape

The rejected header must not be re-read forever. Either consume it
(`buffer_.remove_prefix(kHeaderSize)` before returning `kBadRecord`, reporting
the drop), or set a sticky flag so the second visit takes a different branch.
The `recycled_`-related guards deserve the same audit for every early `return`
in that function — each one that leaves `buffer_` untouched is a candidate spin
when the caller retries.
