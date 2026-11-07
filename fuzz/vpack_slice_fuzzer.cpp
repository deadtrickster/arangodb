// Fuzzes the VelocyPack *accessor* layer, which is what a REST handler does with
// a request body after the body has already been accepted: get(key), at(n),
// keys(), length(), iterators, toJson. It is the layer where a handler that
// assumed an object meets an array ("VPack error: Expecting Object") — the class
// of the /_api/database and /_api/user findings.
//
// Input format: one byte selecting the content type (even = binary VPack,
// odd = JSON text), the rest is the body. Binary bodies are validated first,
// exactly as lib/Rest/HttpRequest.cpp does, so this target stays on the
// accessor layer and does not duplicate vpack_fuzzer's validator target.
#include <cstdint>
#include <memory>
#include <string>

#include <velocypack/Builder.h>
#include <velocypack/Iterator.h>
#include <velocypack/Options.h>
#include <velocypack/Parser.h>
#include <velocypack/Slice.h>
#include <velocypack/Validator.h>
#include <velocypack/velocypack-common.h>

#include "abi_self_test.h"

ARANGO_FUZZ_ABI_SELF_TEST()

using namespace arangodb::velocypack;

namespace {

// Every accessor a handler might reach for, called on whatever the body is.
void exercise(Slice const& s) {
  try {
    (void)s.isObject();
    (void)s.isArray();
    (void)s.isNull();
    (void)s.toJson();
  } catch (...) {
  }

  // "the handler assumed an object"
  for (char const* key : {"name", "query", "_key", "user", "passwd", "options"}) {
    try {
      (void)s.get(key);  // throws for non-objects: the bug class under test
    } catch (...) {
    }
  }

  // "the handler assumed an array"
  try {
    if (s.isArray()) {
      for (auto it : ArrayIterator(s)) {
        (void)it.isString();
      }
    }
  } catch (...) {
  }

  // "the handler assumed a document / read by index"
  try {
    auto len = s.length();
    for (std::size_t i = 0; i < len && i < 64; ++i) {
      if (s.isArray()) {
        (void)s.at(i);
      }
    }
  } catch (...) {
  }

  // keys()/values()
  try {
    if (s.isObject()) {
      for (auto it : ObjectIterator(s)) {
        (void)it.key.copyString();
      }
    }
  } catch (...) {
  }

  // one level of nesting, bounded
  try {
    if (s.isArray() && s.length() > 0) {
      auto first = s.at(0);
      (void)first.isObject();
      (void)first.toJson();
    }
  } catch (...) {
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, std::size_t size) {
  if (size < 2 || size > (1u << 16)) {
    return 0;
  }

  bool json = (data[0] & 1) != 0;
  uint8_t const* body = data + 1;
  std::size_t bodyLen = size - 1;

  if (json) {
    std::shared_ptr<Builder> b;
    try {
      b = Parser::fromJson(reinterpret_cast<char const*>(body), bodyLen);
    } catch (...) {
      return 0;  // malformed JSON: the parser target covers that
    }
    if (b) {
      exercise(b->slice());
    }
    return 0;
  }

  // binary VPack: validate as the server does, then exercise the slice
  try {
    Validator v(&Options::Defaults);
    v.validate(body, bodyLen);
  } catch (...) {
    return 0;  // the validator target owns this path
  }
  Slice s(body);
  exercise(s);
  return 0;
}
