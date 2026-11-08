////////////////////////////////////////////////////////////////////////////////
/// DISCLAIMER
///
/// Copyright 2014-2026 ArangoDB GmbH, Cologne, Germany
/// Copyright 2004-2014 triAGENS GmbH, Cologne, Germany
///
/// Licensed under the Business Source License 1.1 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://github.com/arangodb/arangodb/blob/devel/LICENSE
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.
///
/// Copyright holder is ArangoDB GmbH, Cologne, Germany
///
////////////////////////////////////////////////////////////////////////////////

// The libFuzzer entry points for the structure-aware AQL mutator. The mutator
// itself is fuzz/aql_mutator.h; this translation unit exists so the binary
// carries one strong LLVMFuzzerCustomMutator and one LLVMFuzzerInitialize, and
// so the header is compiled once instead of once per including TU.
//
// The mutator is OFF unless AQLMUT is set: the only target it is linked into
// today (aql_functions_fuzzer) reads [selector:2][args], not AQL text, so its
// default has to be libFuzzer's own byte mutation. AQLMUT_SELFTEST runs the
// mutator's self-test and exits with its verdict.
//
// A target that CAN build a query context installs the engine's parser as the
// oracle, which is the only way the reported rate is the grammar's:
//
//   arangodb::fuzz::aqlmut::SetParseCheck(
//       [](char const* q, std::size_t n, void*) {
//         try {
//           auto ctx = aql::StandaloneCalculation::buildQueryContext(...);
//           auto ast = aql::Ast(*ctx);
//           auto qs = aql::QueryString(std::string_view(q, n));
//           aql::Parser parser(*ctx, &ctx->warnings(), ast, qs);
//           parser.parse();
//           return true;
//         } catch (...) {
//           return false;
//         }
//       },
//       nullptr, "aql-parser");
//
// Out of process, POST /_api/query is that same parse without the context: the
// rate quoted in the commit message was measured that way against a live
// arangod, with the server restarted when a mutant took it down.

#include "aql_mutator.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
  (void)argc;
  (void)argv;
  arangodb::fuzz::aqlmut::Init();
  return 0;
}

extern "C" std::size_t LLVMFuzzerCustomMutator(std::uint8_t* data,
                                               std::size_t size,
                                               std::size_t max_size,
                                               unsigned int seed) {
  return arangodb::fuzz::aqlmut::Mutate(data, size, max_size, seed);
}
