# ------------------------------------------------------------------------------
# libFuzzer harnesses, modelled on pg-fuzz's structure: one binary per
# surface, coverage-guided, crash/assert/ASan/UBSan-only oracle.
# See fuzz/README.md for how to build and run these.
# ------------------------------------------------------------------------------

option(USE_FUZZERS "build libFuzzer harnesses" OFF)

# Guard 1: clang. -fsanitize=fuzzer/fuzzer-no-link and the libFuzzer runtime
# are LLVM features (gcc has no -fsanitize=fuzzer).
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR
    " USE_FUZZERS requires clang (CC=$ENV{CC}, CXX=$ENV{CXX}), but "
    "CMAKE_CXX_COMPILER_ID is '${CMAKE_CXX_COMPILER_ID}' "
    "(${CMAKE_CXX_COMPILER}). Configure the tree with, for example, "
    "CC=/usr/lib/llvm-21/bin/clang CXX=/usr/lib/llvm-21/bin/clang++.")
endif()

# Guard 2: a sanitized tree. SOURCES handed to add_fuzzer_target are
# instrumented per target below, but LIBS are ordinary tree targets: linking
# them into an ASan binary only reports findings if the tree itself carries
# -fsanitize as well (the harnesses would also get no coverage feedback from
# library code).
set(FUZZ_TREE_FLAGS
  "${BASE_C_FLAGS} ${BASE_CXX_FLAGS} ${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS} ${CMAKE_EXE_LINKER_FLAGS}")
if(NOT FUZZ_TREE_FLAGS MATCHES "-fsanitize")
  message(FATAL_ERROR
    " USE_FUZZERS requires a sanitized build tree. Reconfigure with "
    "-DBASE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' "
    "-DBASE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' "
    "-DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' (this is how the "
    "existing build-asan tree is configured). Without them the fuzzers link "
    "uninstrumented libraries and ASan/UBSan see nothing inside them.")
endif()
unset(FUZZ_TREE_FLAGS)

# add_fuzzer_target(<name> SOURCES <source...> [LIBS <library...>])
#
# Builds one libFuzzer binary: SOURCES are compiled with sanitizer and
# coverage instrumentation (-fsanitize=fuzzer-no-link), and the libFuzzer
# runtime is linked in (-fsanitize=fuzzer). LIBS are linked uninstrumented;
# only tree targets from a sanitized tree (see guard above) make sense there.
#
# The flags are deliberately set with target_compile_options/target_link_options
# so they apply to the harness target only. add_compile_options/add_definitions
# at this scope would leak into every other target of the tree.
function(add_fuzzer_target name)
  cmake_parse_arguments(PARSE_ARGV 1 ARG "" "" "SOURCES;LIBS")

  if(NOT ARG_SOURCES)
    message(FATAL_ERROR "add_fuzzer_target(${name}): SOURCES is required")
  endif()

  add_executable(${name} ${ARG_SOURCES})

  target_compile_options(${name} PRIVATE
    -fsanitize=fuzzer-no-link,address,undefined
    -fno-omit-frame-pointer)
  target_link_options(${name} PRIVATE
    -fsanitize=fuzzer,address,undefined)

  if(ARG_LIBS)
    target_link_libraries(${name} PRIVATE ${ARG_LIBS})
  endif()

  install(TARGETS ${name} RUNTIME DESTINATION bin)
endfunction()

# ------------------------------------------------------------------------------
# vpack_fuzzer: VelocyPack binary validation + JSON parsing
# ------------------------------------------------------------------------------

# The tree's velocypack target is compiled without coverage instrumentation, so
# this harness compiles its own instrumented copy of the same translation units
# instead of linking the target (which would also drag in the whole 3rdParty
# build). Keep this list in sync with add_library(velocypack STATIC ...) in
# 3rdParty/velocypack/CMakeLists.txt.
set(VELOCYPACK_SOURCE_DIR ${PROJECT_SOURCE_DIR}/3rdParty/velocypack)

set(VELOCYPACK_FUZZ_SOURCES
  ${VELOCYPACK_SOURCE_DIR}/src/velocypack-common.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/AttributeTranslator.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Builder.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Collection.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Compare.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Dumper.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Exception.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/HashedStringRef.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/HexDump.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Iterator.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Options.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Parser.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Serializable.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/SharedSlice.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Slice.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/String.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Utf8Helper.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Validator.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Value.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/ValueType.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/Version.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/asm-functions.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/asm-utf8check.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/fpconv.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/string-functions.cpp
  ${VELOCYPACK_SOURCE_DIR}/src/xxhash.c
)

add_fuzzer_target(vpack_fuzzer
  SOURCES
    vpack_fuzzer.cpp
    ${VELOCYPACK_FUZZ_SOURCES}
)

target_include_directories(vpack_fuzzer PRIVATE
  ${VELOCYPACK_SOURCE_DIR}/include
  ${VELOCYPACK_SOURCE_DIR}/src
  ${VELOCYPACK_SOURCE_DIR}/external/fast_float
)

target_compile_definitions(vpack_fuzzer PRIVATE
  VELOCYPACK_XXHASH=1
  XXH_NAMESPACE=VELOCYPACK_
)

# Same SSE/NEON switch as 3rdParty/velocypack/CMakeLists.txt makes for the
# tree target (VELOCYPACK_ASM_OPTIMIZATIONS gates the SSE4.2 UTF-8 checker).
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|i.86)$")
  target_compile_definitions(vpack_fuzzer PRIVATE VELOCYPACK_ASM_OPTIMIZATIONS=1)
  target_compile_options(vpack_fuzzer PRIVATE -msse4.2)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|arm)")
  target_compile_definitions(vpack_fuzzer PRIVATE VELOCYPACK_ASM_OPTIMIZATIONS=1)
  target_include_directories(vpack_fuzzer PRIVATE
    ${VELOCYPACK_SOURCE_DIR}/external/sse2neon)
else()
  target_compile_definitions(vpack_fuzzer PRIVATE VELOCYPACK_ASM_OPTIMIZATIONS=0)
endif()

# ------------------------------------------------------------------------------
# vpack_slice_fuzzer: the VelocyPack ACCESSOR layer (get/at/keys/toJson)
# ------------------------------------------------------------------------------
# Where a REST handler meets a body it assumed was an object — the class of the
# "Expecting Object" findings. Same self-compiled velocypack sources as above.

add_fuzzer_target(vpack_slice_fuzzer
  SOURCES
    vpack_slice_fuzzer.cpp
    ${VELOCYPACK_FUZZ_SOURCES}
)

target_include_directories(vpack_slice_fuzzer PRIVATE
  ${VELOCYPACK_SOURCE_DIR}/include
  ${VELOCYPACK_SOURCE_DIR}/src
  ${VELOCYPACK_SOURCE_DIR}/external/fast_float
)

target_compile_definitions(vpack_slice_fuzzer PRIVATE
  VELOCYPACK_XXHASH=1
  XXH_NAMESPACE=VELOCYPACK_
)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|i.86)$")
  target_compile_definitions(vpack_slice_fuzzer PRIVATE VELOCYPACK_ASM_OPTIMIZATIONS=1)
  target_compile_options(vpack_slice_fuzzer PRIVATE -msse4.2)
else()
  target_compile_definitions(vpack_slice_fuzzer PRIVATE VELOCYPACK_ASM_OPTIMIZATIONS=0)
endif()

# ------------------------------------------------------------------------------
# basics_strings_fuzzer: StringUtils helpers behind the AQL string functions
# ------------------------------------------------------------------------------
# These live in lib/Basics and reach the Logger, so this target links the tree's
# `arango` umbrella library instead of compiling its own copy of the sources.

if(TARGET arango)
  add_fuzzer_target(basics_strings_fuzzer
    SOURCES basics_strings_fuzzer.cpp
    LIBS arango
  )
endif()

# ------------------------------------------------------------------------------
# replication2_message_fuzzer: a replicated-log message from a leader
# ------------------------------------------------------------------------------
# AppendEntriesRequest::fromVelocyPack is the entry a follower uses for the
# VPack a leader sends; this is the FuzzRaftStep analogue.

if(TARGET arango)
  add_fuzzer_target(replication2_message_fuzzer
    SOURCES replication2_message_fuzzer.cpp
    LIBS arango
  )
  target_include_directories(replication2_message_fuzzer PRIVATE
    ${PROJECT_SOURCE_DIR}/3rdParty/immer)
endif()

# ------------------------------------------------------------------------------
# http1_fuzzer / http2_fuzzer: the wire framing, both directions of the parser
# ------------------------------------------------------------------------------
# llhttp is a STATIC target with a PUBLIC include dir (3rdParty/CMakeLists.txt);
# nghttp2 exports the nghttp2::nghttp2 alias. Both harnesses are standalone —
# no umbrella link, seconds to build.

if(TARGET llhttp)
  add_fuzzer_target(http1_fuzzer
    SOURCES http1_fuzzer.cpp
    LIBS llhttp
  )
endif()

if(TARGET nghttp2::nghttp2)
  add_fuzzer_target(http2_fuzzer
    SOURCES http2_fuzzer.cpp
    LIBS nghttp2::nghttp2
  )
endif()

# ------------------------------------------------------------------------------
# rocksdb_wal_fuzzer: WAL record decoding with recomputed CRCs (xlogreader)
# ------------------------------------------------------------------------------
# The decoder runs on mutated bytes whose checksums are made valid again, the
# way pg-fuzz's xlogreader reaches PostgreSQL's record parser. Needs the
# rocksdb target, so it joins the full leg, not the fast quartet.

if(TARGET rocksdb)
  # rocksdb links snappy PRIVATEly, so it does not propagate through LIBS;
  # the harness must name it too.
  add_fuzzer_target(rocksdb_wal_fuzzer
    SOURCES rocksdb_wal_fuzzer.cpp
    LIBS rocksdb snappy
  )
  # rocksdb's CMakeLists sets -DOS_LINUX via add_definitions(), which is
  # directory-scoped: it does not reach this target, and port/port.h then
  # includes neither port_posix.h nor port_win.h, so port::Mutex and friends
  # are undeclared. Define the platform selection here too.
  target_compile_definitions(rocksdb_wal_fuzzer PRIVATE
    ROCKSDB_PLATFORM_POSIX=1 OS_LINUX=1)
  target_include_directories(rocksdb_wal_fuzzer PRIVATE
    ${PROJECT_SOURCE_DIR}/3rdParty/rocksdb
    ${PROJECT_SOURCE_DIR}/3rdParty/rocksdb/include)
endif()
