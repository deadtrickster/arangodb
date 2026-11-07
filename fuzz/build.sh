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

TARGETS="vpack_fuzzer vpack_slice_fuzzer http1_fuzzer http2_fuzzer"
if [ "${ARANGO_FUZZ_FULL:-0}" = "1" ]; then
  TARGETS="$TARGETS basics_strings_fuzzer replication2_message_fuzzer"
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

# corpora and dictionaries: libFuzzer starts from whatever it is given
# (the recipe dir may be outside the tree under db-fuzz; use both paths)
for _c in "$TREE/fuzz" "$SRC/fuzz"; do
  [ -d "$_c/corpus" ] && cp -r "$_c/corpus" "$OUT/corpus" 2>/dev/null || true
  cp "$_c"/*.dict "$OUT/" 2>/dev/null || true
done

echo "built: $TARGETS"
echo "in: $OUT"
