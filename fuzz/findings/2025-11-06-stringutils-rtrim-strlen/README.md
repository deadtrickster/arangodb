# 2025-11-06 StringUtils::rTrim reads past the buffer (wrong std::string ctor)

Found by `fuzz/basics_strings_fuzzer` on its **first seed** (`a,b,c,,d`, 7 bytes),
i.e. not a rare input — the function is wrong for any `string_view` that is not
NUL-terminated, which is what its signature accepts.

## The bug

```cpp
// lib/Basics/StringUtils.cpp:432-436
std::string rTrim(std::string_view sourceStr, std::string_view trimStr) {
  size_t e = sourceStr.find_last_not_of(trimStr);

  return std::string(sourceStr.data(), 0, e + 1);   // ← wrong ctor
}
```

`std::string(const char* s, size_type pos, size_type n)` is the **substring**
constructor: it calls `strlen(s)` before copying. A `string_view::data()` is not
NUL-terminated, so `strlen` runs past the end of the view. `lTrim` two functions
above does it correctly (`std::string(str.data(), s)` — pointer + count).

## Reproduce

```sh
ASAN_OPTIONS=detect_leaks=0 \
  build-asan/bin/basics_strings_fuzzer \
  fuzz/findings/2025-11-06-stringutils-rtrim-strlen/input.bin
```

```
==3==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 strlen
    #3 std::string(const char*, ...)
    #4 arangodb::basics::StringUtils::rTrim(...)  lib/Basics/StringUtils.cpp:435
    #5 LLVMFuzzerTestOneInput                     fuzz/basics_strings_fuzzer.cpp:33
```

`report.txt` is the full run.

## Severity: latent, not currently reachable

The only two callers pass a `std::string`, whose `data()` *is* NUL-terminated:

- `arangod/RestServer/DatabasePathFeature.cpp:80`
- `arangod/RestServer/DatabasePathOptionsProvider.cpp:87`

So no live path overflows today. It is still a real defect of the function's
contract: any future caller — or any refactor that hands it a view into a
request buffer (the natural thing to do with a header or path) — gets an
out-of-bounds read.

## Fix

```cpp
  return std::string(sourceStr.data(), e + 1);   // pointer + count
```
and note `e` can be `npos` when every character is trimmed (`e + 1 == 0`, which
also gives the right empty result, but only with the pointer+count ctor).

## Worth keeping

The harness found this in the first second because a 7-byte seed exercises
`rTrim`, `lTrim`, `escapeUnicode`, `tolower/toupper`, `replace` and `split` on
the same input. Cheap target, immediate signal.
