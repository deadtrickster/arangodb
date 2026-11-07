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
# oss-fuzz runs `bash $SRC/build.sh` with SRC=/src: the recipe lives at $SRC
# and the tree at $SRC/$PROJECT_NAME. Locally (no SRC) the tree is the cwd.
SRC="${SRC:-$PWD}"
TREE="${ARANGO_TREE:-$SRC/${PROJECT_NAME:-arangodb}}"
[ -f "$TREE/CMakeLists.txt" ] || TREE="$SRC"
mkdir -p "$OUT" "$WORK"

# The tree has no libc++ support at all (nothing in CMakeLists or scripts
# references it); oss-fuzz's CXXFLAGS carry -stdlib=libc++ and velocypack's
# BasicString<uint8_t> needs std::char_traits<unsigned char>, which libc++
# does not specialise — so the whole build is libstdc++. Strip the flag
# wherever the environment may put it.
#
# CONSTRAINT: this is safe only because LIB_FUZZING_ENGINE is NOT linked
# (see the note below — our targets carry their own engine flag). A prebuilt
# engine .a compiled against libc++ would need a matching stdlib; if that
# ever changes, this strip must go and libc++ support must come to the tree
# first.
CFLAGS="${CFLAGS//-stdlib=libc++/}"
CXXFLAGS="${CXXFLAGS//-stdlib=libc++/}"

TARGETS="vpack_fuzzer vpack_slice_fuzzer http1_fuzzer http2_fuzzer"
if [ "${ARANGO_FUZZ_FULL:-0}" = "1" ]; then
  # rocksdb_wal_fuzzer links the rocksdb target (plus snappy, PRIVATEly linked
  # and non-propagating), so it joins the full set with the umbrella pair.
  TARGETS="$TARGETS basics_strings_fuzzer replication2_message_fuzzer rocksdb_wal_fuzzer"
fi

# NOTE: $LIB_FUZZING_ENGINE is deliberately NOT in the global linker flags —
# applied project-wide it breaks CMake's compiler sanity test (every executable
# would get a fuzzer main). fuzz/CMakeLists.txt's add_fuzzer_target() adds the
# engine per target itself, so the harnesses link correctly without it; the
# variable is accepted for contract compatibility and ignored.

# The oss-fuzz base-builder clang ships without libomp, and FindOpenMP is
# REQUIRED at top level. Nothing the six fuzz targets link pulls OpenMP
# (3rdParty is EXCLUDE_FROM_ALL; faiss never enters a harness link), so we
# pre-seed FindOpenMP's cache entries — with all of FLAGS/LIB_NAMES/_LIBRARY
# set, FindOpenMP skips its own compile test. ARANGO_LIBOMP overrides the
# located path; ARANGO_SEED_OPENMP=0 restores plain discovery. The seeded path
# should be real for ARANGO_FUZZ_FULL=1 (the umbrella lib does link what
# faiss needs), but the fast quartet never links it.
OMP_ARGS=""
if [ "${ARANGO_SEED_OPENMP:-1}" = "1" ]; then
  LIBOMP_PATH="${ARANGO_LIBOMP:-}"
  if [ -z "$LIBOMP_PATH" ]; then
    LIBOMP_PATH="$(ls /usr/lib/llvm-*/lib/libomp.so 2>/dev/null | head -n1 || true)"
  fi
  [ -z "$LIBOMP_PATH" ] && LIBOMP_PATH=/nonexistent/libomp.so
  OMP_ARGS="-DOpenMP_C_FLAGS=-fopenmp=libomp -DOpenMP_CXX_FLAGS=-fopenmp=libomp -DOpenMP_C_LIB_NAMES=omp -DOpenMP_CXX_LIB_NAMES=omp -DOpenMP_omp_LIBRARY=$LIBOMP_PATH -DOpenMP_pthread_LIBRARY=pthread"
fi

# Coverage instrumentation for the WHOLE tree, not just the harness TU.
# -fsanitize=fuzzer-no-link on the fuzz target alone (fuzz/CMakeLists.txt)
# instruments one translation unit; anything linked from the tree's libraries
# then carries no counters and libFuzzer steers on the harness's own branches
# (measured: 524 counters with libarango blind, 1905 with librocksdb blind,
# vs 33764 for the self-contained targets that compile their own copies).
# oss-fuzz's env already carries this flag; appending it here is idempotent
# for that case and fixes the case where it does not (bare project_dir=).
# fuzzer-NO-link: the engine is linked per-target, never tree-wide.
CFLAGS="${CFLAGS:-} -fsanitize=fuzzer-no-link"
CXXFLAGS="${CXXFLAGS:-} -fsanitize=fuzzer-no-link"

cmake -G Ninja -S "$TREE" -B "$WORK" \
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
  $OMP_ARGS \
  ${EXTRA_CMAKE_ARGS:-}

ninja -C "$WORK" $TARGETS

for t in $TARGETS; do
  cp "$WORK/bin/$t" "$OUT/"
done

# corpora and dictionaries: libFuzzer starts from whatever it is given.
# Contents, not the directory itself: a bare `cp -r dir out` on a second source
# nests (out/corpus/corpus), and QUARANTINE.md must NOT ride into the corpus a
# slice loads — it is the ledger, not an input.
COPIED_CORPUS=0
for _c in "$TREE/fuzz" "$SRC/fuzz"; do
  if [ -d "$_c/corpus" ] && [ "$COPIED_CORPUS" -eq 0 ]; then
    mkdir -p "$OUT/corpus"
    for _t in "$_c/corpus"/*/; do
      [ -d "$_t" ] && cp -r "$_t" "$OUT/corpus/" 2>/dev/null || true
    done
    COPIED_CORPUS=1
  fi
  cp "$_c"/*.dict "$OUT/" 2>/dev/null || true
done

echo "built: $TARGETS"
echo "in: $OUT"
