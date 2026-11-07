// Fuzzes the string/number conversion helpers that back the AQL function
// families (CONCAT/SUBSTRING-shaped code paths, TO_NUMBER/TO_STRING, LIKE's
// escaping). These live in lib/Basics and reach the Logger, so this target
// links the tree's `arango` umbrella library rather than compiling a handful of
// translation units itself — the cheap standalone route does not link.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

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
    (void)arangodb::basics::StringUtils::replace(s, "a", "bb");
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

  return 0;
}
