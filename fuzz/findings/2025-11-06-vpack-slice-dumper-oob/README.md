# 2025-11-06 vpack: Validator accepts a body that Dumper then walks off (SEGV)

Found by `vpack_slice_fuzzer` (the VelocyPack *accessor* target) within seconds of
its first run. Distinct from the `validateIndexedArray` OOB in the sibling
finding: there the validator itself reads out of bounds; here the validator
**returns successfully** and the damage appears later, in the code that consumes
the slice.

## Reproduce

```sh
# 1. the validator-only target says this 9-byte body is FINE (no report)
/tmp/fv2/bin/vpack_fuzzer input.bin

# 2. the accessor target segfaults on the same bytes
ASAN_OPTIONS=detect_leaks=0 /tmp/fv2/bin/vpack_slice_fuzzer input.bin
```

`input.bin` (9 bytes): `1d 01 00 00 30 01 00 00 cb`

## Report (top frames)

```
==3==ERROR: AddressSanitizer: SEGV
    #0 SliceBase<...>::head()          include/velocypack/SliceBase.h:143
    #1 SliceBase<...>::type()          include/velocypack/SliceBase.h:152
    #2 Dumper::dumpValue(...)          src/Dumper.cpp:421
    #4 Dumper::dump(...)               src/Dumper.cpp:54
    #5 SliceBase<...>::toJson(...)     include/velocypack/SliceBase.tpp:148
    #7 (anonymous namespace)::exercise fuzz/vpack_slice_fuzzer.cpp:33
```

`report.txt` is the full run.

## What the harness does

`fuzz/vpack_slice_fuzzer.cpp`: for a binary body it runs
`Validator::validate()` (exactly as `lib/Rest/HttpRequest.cpp:893-905` does), and
only if that succeeds does it exercise the accessors a REST handler uses —
`toJson`, `get(key)`, `at(n)`, iterators, `length()`. So the input below reached
the accessor layer *through* the validator.

## Why it matters

The server's contract is "validated body ⇒ safe to read". Anything that consumes
a VPack body — a handler formatting an error, a logger dumping a slice, a
response serialiser — relies on it. Here the validator's acceptance is wrong (or
the Dumper lacks the bound the validator was supposed to guarantee); either way
the pair is inconsistent, which is what this finding is about.

## Root cause (located)

`Validator::validatePart` dispatches on `Slice::type()`, and its switch accepts the
"nothing to check" types by falling through:

```cpp
// 3rdParty/velocypack/src/Validator.cpp:100-108
case ValueType::MinKey:
case ValueType::MaxKey:
case ValueType::SmallInt:
...
case ValueType::Illegal: {
  break;          // ← accepted, nothing validated
}
```

A type byte that velocypack does not recognise is classified `ValueType::Illegal`
and the validator **returns success**. `validateArray` compounds it: it has cases
for `0x13`, `0x02-0x05`, `0x06-0x09`, `0x01` and no `else`, so an unrecognised
array-ish head validates nothing at all. Consumers that walk the slice
(`Dumper::dumpValue`) then interpret the unknown head their own way and leave the
buffer.

So the fix belongs in the validator: `ValueType::Illegal` must be a rejection, not
a pass — the same shape as the missing lower bound in the sibling finding. The
Dumper is a second question (whether it must be total on any slice), but with the
validator fixed its input never contains an Illegal head.

## Triage status

Cause located, fix not applied. Two candidate patches, both one-liners in
`Validator.cpp`: throw on `ValueType::Illegal` in `validatePart`, and add a
rejecting `else` in `validateArray`/`validateObject`. Worth re-running this
harness afterwards: like the sibling finding, it is saturated by this crash and
measures nothing until it is patched.

## History

Originally filed as "triage needed: which side is wrong"; resolved by reading
`validatePart`'s dispatch (see above).
