// Runtime tripwire for a C++ exception-ABI clash, included by every harness.
//
// A link line that mixes runtimes (libc++abi throwing, libstdc++ unwinding,
// or the reverse) passes every static ELF check that looks at only one side,
// and later fails as an unsymbolized terminate on an arbitrary input. This
// self-test throws and catches once, at static-init time, before any fuzzing:
// on a mismatched link the process dies here, with the self-test line directly
// above the abort, naming the problem instead of hiding behind input bytes.
//
// On a consistent link (arango is libstdc++ end to end) the catch runs and the
// harness starts normally. The one-time fprintf is the record that it ran.
//
// This is a local twin of pg-fuzz's shared pgfuzz::abi_selfcheck(): the fast
// quartet here must build standalone, with no pg-fuzz file vendored in.
//
// Implementation notes the compiler cannot be trusted to preserve: the throw
// is in a [[gnu::noinline]] function and the message is built from a runtime
// counter, because a throw-and-catch that never escapes is exactly the shape
// -O3+LTO discards - and a self-test that compiles away reports "ok" while
// testing nothing.
#pragma once

#include <cstdio>
#include <stdexcept>

namespace arangodb::fuzz {
namespace detail {

inline int abi_self_test_counter = 0;

[[gnu::noinline]] inline void throwOne() {
  // the counter makes the message non-constant at compile time
  char buf[48];
  std::snprintf(buf, sizeof buf, "abi self-test #%d", ++abi_self_test_counter);
  throw std::runtime_error(buf);
}

[[gnu::noinline]] inline bool runAbiSelfTest() {
  std::fprintf(stderr, "self-test: C++ exception ABI\n");
  try {
    throwOne();
  } catch (std::exception const& e) {
    std::fprintf(stderr, "self-test: caught ok (%s)\n", e.what());
    return true;
  }
  return false;  // unreachable on a working ABI
}

}  // namespace detail

struct AbiSelfTest {
  AbiSelfTest() { (void)detail::runAbiSelfTest(); }
};

}  // namespace arangodb::fuzz

// Including the header arms the tripwire for this translation unit.
#define ARANGO_FUZZ_ABI_SELF_TEST() \
  static ::arangodb::fuzz::AbiSelfTest arango_fuzz_abi_self_test_;
