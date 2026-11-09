// Fuzzes ArangoDB's AQL function families by calling them directly — the
// pg-fuzz scalar_types/datetime/regex/encoding targets, transposed. Every
// registered AQL function shares one C++ signature (Functions.h:52):
//
//   AqlValue (*)(ExpressionContext*, AstNode const&, span<AqlValue const>)
//
// The function list is generated from AqlFunctionFeature.cpp (234
// fnImpls) so it cannot drift from the registration.
//
// DEVIATIONS (fuzzing-method §1):
//   - ExpressionContext is null: real callers provide query context. Functions
//     that dereference it will crash — that identifies the ones that need the
//     full query runtime, which this direct-call target deliberately does not
//     provide. Those functions are catalog-shaped and belong in the SQL
//     campaign target instead.
//   - AstNode is a default-constructed "unknown" node: real callers pass the
//     FCALL node. The fnImpls that read it use it for metadata.
//
// Input: [selector:2][args] — selector picks a function (% table size); the
// rest splits on 0xFF into up to 4 argument blobs, each parsed as VPack or,
// failing that, as a string AqlValue.
//
// Links the `arango` umbrella library, so it joins the full leg.
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include "Aql/AqlValue.h"
#include "Aql/AstNode.h"
#include "velocypack/Slice.h"
#include "velocypack/Validator.h"

#include "abi_self_test.h"
#include "null_expression_context.h"

ARANGO_FUZZ_ABI_SELF_TEST()

using namespace arangodb;

namespace arangodb::aql {
class ExpressionContext;  // forward declaration only; we pass nullptr
}

// The one signature every AQL function implementation shares (Functions.h:52).
// Declared here to avoid Functions.h's include chain (→ SmallVector.h →
// boost/container, which is a 154-dir FetchContent dep).
using FnImpl = arangodb::aql::AqlValue (*)(
    arangodb::aql::ExpressionContext*, arangodb::aql::AstNode const&,
    std::span<arangodb::aql::AqlValue const>);

std::vector<FnImpl> fnImpls;
bool initialised = false;

// Per-function arity: the generated .inc carries {impl, min, max} from the
// registration table's params string, so the harness clamps arguments to the
// range the parser would enforce. This is parser parity for arity, the same
// defence as the padding/bounding but per-function instead of global.
struct FnEntry {
  FnImpl impl;
  std::size_t minArgs;
  std::size_t maxArgs;
};
std::vector<FnEntry> fnTable;

arangodb::aql::AstNode node(arangodb::aql::NODE_TYPE_NOP);
arangodb::fuzz::NullExpressionContext ctx;

// The function list: generated from AqlFunctionFeature.cpp (234 extern
// declarations in the functions namespace + push_back lines).
// At file scope so the namespace declaration inside it is valid.
#include "aql_functions_list.inc"

static void ensureFunctions() {
  // fnTable is populated by the .inc at static init (the push_backs are
  // at namespace scope inside a static initializer struct, not in a
  // function — the generated code handles it)
  if (!initialised) {
    initialised = true;
  }
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, std::size_t size) {
  if (size < 3 || size > (1u << 15)) return 0;
  if (fnTable.empty()) return 0;

  uint16_t sel = static_cast<uint16_t>(data[0] | (data[1] << 8));
  auto const& entry = fnTable[sel % fnTable.size()];
  auto impl = entry.impl;

  std::vector<std::vector<uint8_t>> blobs;
  std::vector<uint8_t> cur;
  for (std::size_t i = 2; i < size; ++i) {
    if (data[i] == 0xFF && blobs.size() < 3) {
      blobs.push_back(std::move(cur));
      cur.clear();
    } else {
      cur.push_back(data[i]);
    }
  }
  blobs.push_back(std::move(cur));

  std::vector<aql::AqlValue> values;
  velocypack::Validator validator;
  for (auto const& blob : blobs) {
    if (blob.empty()) continue;
    bool valid = false;
    try {
      validator.validate(blob.data(), blob.size());
      valid = true;
    } catch (...) {}
    if (valid) {
      values.emplace_back(velocypack::Slice(blob.data()));
    } else {
      values.emplace_back(std::string(
          reinterpret_cast<char const*>(blob.data()), blob.size()));
    }
  }
  if (values.empty()) return 0;

  // Per-function arity clamping — parser parity. The .inc carries each
  // function's declared {min, max} from the registration table's params
  // string, so the harness clamps to the range the parser would enforce.
  // Functions with ADB_UNREACHABLE in their parameters.size() switch are
  // protected by arity they were declared with, not a global guess.
  while (values.size() < entry.minArgs) {
    values.emplace_back(std::string());
  }
  if (values.size() > entry.maxArgs) {
    values.resize(entry.maxArgs);
  }

  // ExpressionContext deliberately null (see DEVIATIONS above)
  try {
    aql::AqlValue result =
        impl(&ctx, node, std::span<aql::AqlValue const>(values));
    (void)result.slice();
    result.destroy();
  } catch (...) {
  }

  // AqlValue's destructor does NOT free: each one that owns a slice
  // (the VPack path) must be destroyed explicitly or the memory leaks
  // on every input. This was the leak the mutator subagent measured.
  for (auto& v : values) {
    v.destroy();
  }

  return 0;
}
