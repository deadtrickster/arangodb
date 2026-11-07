// Fuzzes the string and NUMBER conversion helpers that back the AQL
// function families. String side: escapeUnicode, trim/lTrim/rTrim, replace
// (needle and replacement derived from the input, not fixed), tolower,
// toupper, split/join. Number side: uint64 / try_uint64 / toNumber — where
// conversion bugs actually live (StringUtils.h:338-371). Links the tree's
// `arango` umbrella library; the cheap standalone route does not link.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "Basics/ResultT.h"

#include "Basics/StringUtils.h"

#include "abi_self_test.h"

ARANGO_FUZZ_ABI_SELF_TEST()

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, std::size_t size) {
  if (size < 2 || size > 4096) {
    return 0;
  }

  std::string_view s(reinterpret_cast<char const*>(data), size);

  try {
    (void)arangodb::basics::StringUtils::escapeUnicode(s);
  } catch (...) {
  }
  try {
    (void)arangodb::basics::StringUtils::trim(s);
  } catch (...) {
  }
  try {
    (void)arangodb::basics::StringUtils::lTrim(s);
  } catch (...) {
  }
  try {
    (void)arangodb::basics::StringUtils::rTrim(s);
  } catch (...) {
  }
  try {
    // needle and replacement derive from the input, not constants — a fixed
    // "a"→"bb" exercises one shape of the matcher and nothing else
    std::string_view needle = s.substr(0, s.size() / 3);
    std::string_view repl = s.substr(s.size() / 3, s.size() / 3);
    (void)arangodb::basics::StringUtils::replace(
        s, std::string(needle.empty() ? "a" : needle), std::string(repl));
  } catch (...) {
  }
  try {
    (void)arangodb::basics::StringUtils::tolower(s);
  } catch (...) {
  }
  try {
    (void)arangodb::basics::StringUtils::toupper(s);
  } catch (...) {
  }
  try {
    std::string_view from = s.substr(0, s.size() / 2);
    std::vector<std::string> parts = arangodb::basics::StringUtils::split(
        std::string(s), std::string(from.empty() ? "," : from));
    (void)arangodb::basics::StringUtils::join(parts, ",");
  } catch (...) {
  }

  // --- number conversion: the half the old comment promised and never called --
  // uint64 is noexcept and documents "exclusively numeric characters -
  // otherwise the result will be wrong": exactly the contract a fuzzer probes.
  try {
    (void)arangodb::basics::StringUtils::uint64(s);
  } catch (...) {
  }
  try {
    auto parsed = arangodb::basics::StringUtils::try_uint64(s.data(), s.size());
    (void)parsed;  // ResultT<uint64_t>: ok() carries the verdict, the value
                   // is only read on ok, and the probe is the parse itself
  } catch (...) {
  }
  try {
    uint64_t out = 0;
    (void)arangodb::basics::StringUtils::toNumber(std::string(s), out);
  } catch (...) {
  }

  return 0;
}
