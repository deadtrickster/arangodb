#!/bin/bash -eu
# oss-fuzz-style build recipe for ArangoDB's in-tree libFuzzer harnesses.
#
# Invoked by db-fuzz (engine=libfuzzer, project_dir= pointing here) or by an
# oss-fuzz clone: receives $OUT, $WORK, $CC, $CXX, $CFLAGS, $CXXFLAGS and
# $LIB_FUZZING_ENGINE like any oss-fuzz project. Sanitizer flags arrive in
# CFLAGS/CXXFLAGS; the fuzzing engine in LIB_FUZZING_ENGINE.
#
# Fast set (default): the two self-contained harnesses, minutes to build.
# Full set (ARANGO_FUZZ_FULL=1): adds the umbrella-linked pair, which needs a
# complete sanitized build of the tree (hours) — CI legs usually want the fast
# set and let a nightly take the full one.
#
# Build image needs the server's dependencies: flex, bison, OpenMP for the
# chosen compiler, and BLAS/LAPACK (faiss). On the oss-fuzz base image:
#   apt-get install -y flex bison libopenblas-dev libomp-<cc>-dev
# Anything machine-specific (custom libomp prefix, BLAS symlink dir) goes in
# $EXTRA_CMAKE_ARGS.

OUT="${OUT:-$PWD/out}"
WORK="${WORK:-$PWD/work}"
SRC="${SRC:-$PWD}"
mkdir -p "$OUT" "$WORK"

TARGETS="vpack_fuzzer vpack_slice_fuzzer http1_fuzzer http2_fuzzer"
if [ "${ARANGO_FUZZ_FULL:-0}" = "1" ]; then
  TARGETS="$TARGETS basics_strings_fuzzer replication2_message_fuzzer"
fi

# NOTE: $LIB_FUZZING_ENGINE is deliberately NOT in the global linker flags —
# applied project-wide it breaks CMake's compiler sanity test (every executable
# would get a fuzzer main). fuzz/CMakeLists.txt's add_fuzzer_target() adds the
# engine per target itself, so the harnesses link correctly without it; the
# variable is accepted for contract compatibility and ignored.

cmake -G Ninja -S "$SRC" -B "$WORK" \
  -DCMAKE_C_COMPILER="${CC:-clang}" \
  -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
  -DBASE_C_FLAGS="${CFLAGS:-}" \
  -DBASE_CXX_FLAGS="${CXXFLAGS:-}" \
  -DUSE_FUZZERS=On \
  -DUSE_JEMALLOC=Off \
  -DUSE_ENTERPRISE=Off \
  -DUSE_IPO=Off \
  -DUSE_FRONTEND=Off \
  -DUSE_GOOGLE_TESTS=Off \
  -DUSE_FAILURE_TESTS=Off \
  -DSTATIC_EXECUTABLES=Off \
  ${EXTRA_CMAKE_ARGS:-}

ninja -C "$WORK" $TARGETS

for t in $TARGETS; do
  cp "$WORK/bin/$t" "$OUT/"
done

# corpora and dictionaries: libFuzzer starts from whatever it is given
cp -r "$SRC/fuzz/corpus" "$OUT/corpus" 2>/dev/null || true
cp "$SRC"/fuzz/*.dict "$OUT/" 2>/dev/null || true

echo "built: $TARGETS"
echo "in: $OUT"
