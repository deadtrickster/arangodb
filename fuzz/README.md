# libFuzzer harnesses

Coverage-guided fuzzing for ArangoDB's C++ decoding surfaces, modelled on
pg-fuzz's structure: **one binary per surface**, coverage-guided via
`-fsanitize=fuzzer-no-link` at compile time and `-fsanitize=fuzzer` at link
time, and a **crash-only oracle** (crash, assertion failure, ASan or USan
report — see below).

| binary        | surface                                                              |
| ------------- | -------------------------------------------------------------------- |
| `vpack_fuzzer`| VelocyPack binary validation (`velocypack::Validator`) and JSON parsing (`velocypack::Parser::fromJson`), over an instrumented copy of `3rdParty/velocypack` |

## Building

The fuzzers require **clang** and a **sanitized tree**. `fuzz/CMakeLists.txt`
fails configure with `FATAL_ERROR` if either is missing, because an
uninstrumented tree would give ASan/UBSan nothing to see (and the library
code no coverage feedback).

`-DUSE_FUZZERS=On` must be passed on the `cmake` command line: the `option()`
lives in `fuzz/CMakeLists.txt`, which is only added when the variable is
already set.

```sh
CC=/usr/lib/llvm-21/bin/clang CXX=/usr/lib/llvm-21/bin/clang++ \
cmake -G Ninja -S . -B build-fuzz \
  -DUSE_FUZZERS=On \
  -DCMAKE_BUILD_TYPE=Debug \
  -DUSE_ENTERPRISE=Off -DUSE_IPO=Off -DUSE_FRONTEND=Off \
  -DUSE_GOOGLE_TESTS=Off -DUSE_MAINTAINER_MODE=On \
  -DBASE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DBASE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
```

The `BASE_*` variables are how this tree turns a build into a sanitized build
(the existing `build-asan` tree is configured exactly this way). Then build
only a fuzzer target — this compiles the harness plus its own instrumented
library sources, not `arangod` or the rest of `3rdParty`:

```sh
cmake --build build-fuzz --target vpack_fuzzer -j 2
```

The binary lands in `build-fuzz/bin/vpack_fuzzer` (the tree redirects all
executables to `<build>/bin`); `ninja install` also installs it under `bin/`.

## Running

```sh
mkdir -p fuzz/corpus/vpack        # seed + accumulated corpus (checked in)
mkdir -p /tmp/fuzz-artifacts      # crash inputs land here

# halt_on_error makes UBSan findings fatal: without it libFuzzer logs a
# "runtime error" line and keeps going, and the violation is not stored as a crash.
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
build-fuzz/bin/vpack_fuzzer \
  fuzz/corpus/vpack \
  -dict=fuzz/vpack.dict \
  -max_total_time=600 -max_len=4096 -rss_limit_mb=4096 \
  -artifact_prefix=/tmp/fuzz-artifacts/ \
  -jobs=4 -workers=4
```

Useful switches:

* `-max_total_time=<seconds>` — stop after N seconds of fuzzing.
* `-jobs=N -workers=N` — run N parallel worker processes (each writes
  `fuzz-<n>.log` into the working directory).
* `-runs=N` — fixed number of executions instead of a time budget.
* `-max_len=N` — input size cap; keep small (1–4 KB) for parsers.
* `-artifact_prefix=DIR/` — where crash/minimize outputs are written.
* `-dict=fuzz/vpack.dict` — (optional) token dictionary.
* Reproduce one input: `vpack_fuzzer crashing-input-file`.
* Minimise a crasher: `vpack_fuzzer -minimize_crash=1 -runs=100000 crash-file`.

A second corpus directory can be passed (seeds, then growing corpus); see
`vpack_fuzzer -help=1` for everything else.

## Adding a new harness

1. Write `fuzz/<name>_fuzzer.cpp` with an `extern "C" int
   LLVMFuzzerTestOneInput(uint8_t const*, size_t)`. Return 0; make the
   function idempotent (state from one input must not affect the next).
2. Register it in `fuzz/CMakeLists.txt`:

   ```cmake
   add_fuzzer_target(<name>_fuzzer SOURCES <name>_fuzzer.cpp <instrumented library sources>)
   # plus target_include_directories / target_compile_definitions it needs
   ```

   The helper applies `-fsanitize=fuzzer-no-link,address,undefined` and
   `-fno-omit-frame-pointer` at compile time, `-fsanitize=fuzzer,address,undefined`
   at link time, and installs the binary under `bin/` — per target, so the
   flags never leak into `velocypack`, `arangod` or any other tree target.
3. If the surface lives in a tree library you cannot compile yourself (unlike
   velocypack, whose sources the vpack harness compiles directly), pass the
   target via `LIBS` — but then the whole tree must be sanitized, not just
   the fuzzer, or the linked-in code is invisible to ASan/UBSan and to
   coverage guidance.
4. Add seeds under `fuzz/corpus/<name>/` and a row to the table above.

## Oracle

**Crash-only**: a finding is a signal — SIGSEGV/SIGABRT, a failed
`ASSERT`/`TRI_ASSERT`, an ASan report (heap overflow, UAF, double free, …) or
a UBSan report. libFuzzer prints `==ERROR: libFuzzer: deadly signal` (or the
sanitizer's own report), saves the input via `-artifact_prefix`, and exits —
that is the only thing that counts.

Everything else is *not* a finding: a thrown `velocypack::Exception`, an
`errorNum`, a 4xx/5xx from higher layers, slow inputs (`ALARM: working on the
last input for X sec` is at most a separate performance issue), or OOM beyond
`-rss_limit_mb` (usually a runaway build, not a bug — verify before filing).
`-timeout=25` turns hangs into findings.

## Findings rule

Every finding must be **minimised and stored with the exact command**:

1. Reproduce: `<binary> <crash-file>` — confirm the sanitizer report.
2. Minimise: `<binary> -minimize_crash=1 -runs=100000 <crash-file>` (repeat
   until stable).
3. Store under `fuzz/findings/<YYYY-MM-DD>-<surface>-<slug>/`:
   * the minimised input,
   * a `README.md` with the sanitizer report (top frames), the exact build
     configuration, and the **exact reproduce command** — binary path,
     corpus/crash-file arguments and all flags — such that a clean checkout
     can re-run it,
   * the git revision of the tree it was found against (`git rev-parse HEAD`).
