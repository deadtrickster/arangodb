# 2025-11-06 Replication2: `AppendEntriesRequest::fromVelocyPack` reads out of bounds on a non-object

A replicated-log message that is not a VelocyPack object takes the decoder out of
bounds. Two bytes are enough.

Found by `fuzz/replication2_message_fuzzer` (the etcd-`FuzzRaftStep` analogue: one
message in, `AppendEntriesRequest::fromVelocyPack` decodes it, the follower-side
fields are touched afterwards).

## Reproduce

```sh
ASAN_OPTIONS=detect_leaks=0 \
  build-asan/bin/replication2_message_fuzzer \
  fuzz/findings/2025-11-06-replication2-fromvelocypack-oob/input.bin
```

`input.bin` is `0e 7b` — head `0x0e` (an object-shaped type byte) with a length
byte that cannot describe an index table.

```
==5==ERROR: AddressSanitizer: heap-buffer-overflow
    #1 readIntegerFixed<unsigned long, 8>            velocypack-common.h:353
    #2 readIntegerNonEmpty<unsigned long>            velocypack-common.h:387
    #3 SliceBase<...>::get(string_view)              SliceBase.tpp:288
    #4 AppendEntriesRequest::fromVelocyPack          NetworkMessages.cpp:293
    #5 LLVMFuzzerTestOneInput                        fuzz/replication2_message_fuzzer.cpp:29
```

## Cause

`NetworkMessages.cpp:291-296` goes straight to `slice.get(...)`:

```cpp
auto leaderTerm = slice.get("leaderTerm").extract<LogTerm>();
auto leaderId   = ParticipantId{slice.get("leaderId").copyString()};
auto prevLogEntry = TermIndexPair::fromVelocyPack(slice.get("prevLogEntry"));
```

`Slice::get(key)` has **object** as a precondition; on any other type it computes
an index table from bytes that are not one, which is the out-of-bounds read. The
decoder never checks `slice.isObject()` — nor that the required fields exist and
have the expected types before `extract<>`/`copyString()`.

## Reachability

This is the message a follower decodes when its leader sends `AppendEntries`. So
the sender is a peer: a compromised or buggy leader, or anything that can inject
on the cluster-internal channel, can make followers read out of bounds — and, as
the sibling findings show, the same class of assumption is where the server-side
crashes live. It is not reachable from the public HTTP API by itself.

## Fix

Reject early and precisely:

```cpp
if (!slice.isObject()) {
  THROW_ARANGO_EXCEPTION_MESSAGE(TRI_ERROR_BAD_PARAMETER,
                                 "AppendEntriesRequest must be an object");
}
```

and then check each required member (`hasKey` + type) before `extract<>`, the same
way other decoders in the tree validate optional members.

## Note on the target

The harness deliberately does **not** run `Validator` first: with validation in
place it is saturated by the known `validateIndexedObject` OOB (see the
`velocypack` findings) and never reaches this decoder. Validation is its own
target; this one owns the decode path.
