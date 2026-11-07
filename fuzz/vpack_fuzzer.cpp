////////////////////////////////////////////////////////////////////////////////
/// DISCLAIMER
///
/// Copyright 2025 ArangoDB GmbH, Cologne, Germany
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
/// @author ArangoDB fuzzing scaffolding
////////////////////////////////////////////////////////////////////////////////

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "velocypack/Builder.h"
#include "velocypack/Exception.h"
#include "velocypack/Parser.h"
#include "velocypack/Slice.h"
#include "velocypack/Validator.h"

#include "abi_self_test.h"

ARANGO_FUZZ_ABI_SELF_TEST()

// Fuzzes both VelocyPack decoding paths with the same input: binary VPack
// validation (what a server does with a request body already in VPack) and
// JSON parsing (what it does with a JSON request body). Malformed input is
// expected to throw velocypack::Exception, which is normal control flow, not
// a finding: the oracle is crash/assert/ASan/UBSan only.
extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, std::size_t size) {
  if (data == nullptr || size == 0) {
    return 0;
  }

  try {
    arangodb::velocypack::Validator validator;
    validator.validate(data, size);
  } catch (arangodb::velocypack::Exception const&) {
  }

  try {
    auto builder = arangodb::velocypack::Parser::fromJson(
        std::string_view(reinterpret_cast<char const*>(data), size));
    // touch a little of the downstream API on well-formed input
    arangodb::velocypack::Slice slice = builder->slice();
    (void)slice.length();
    (void)slice.hash();
    (void)slice.isNull();
  } catch (arangodb::velocypack::Exception const&) {
  }

  return 0;
}
