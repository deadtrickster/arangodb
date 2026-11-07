// Minimal ExpressionContext for the AQL function fuzzer: absorbs warnings
// (the most common context use in scalar functions), throws for everything
// that genuinely needs the query runtime (variables, vocbase, transactions,
// ICU regex matchers). Those functions belong in the SQL campaign target,
// not this direct-call target.
#pragma once

#include <stdexcept>
#include <string_view>

#include "Aql/AqlValue.h"
#include "Aql/ExpressionContext.h"

namespace arangodb::fuzz {

struct NullExpressionContext final : public aql::ExpressionContext {
  // The two the scalar functions actually use: absorb rejections
  void registerWarning(ErrorCode, std::string_view) override {}
  void registerError(ErrorCode, std::string_view) override {}

  // Everything below throws: the caller documented as out of scope
  aql::AqlValue getVariableValue(aql::Variable const*, bool, bool&) const override {
    throw std::runtime_error("fuzz: no variables in direct-call mode");
  }
  icu_64_64::RegexMatcher* buildRegexMatcher(std::string_view, bool) override {
    throw std::runtime_error("fuzz: no ICU regex in direct-call mode");
  }
  icu_64_64::RegexMatcher* buildLikeMatcher(std::string_view, bool) override {
    throw std::runtime_error("fuzz: no ICU like in direct-call mode");
  }
  icu_64_64::RegexMatcher* buildSplitMatcher(
      aql::AqlValue, velocypack::Options const*, bool&) override {
    throw std::runtime_error("fuzz: no ICU split in direct-call mode");
  }
  arangodb::ValidatorBase* buildValidator(velocypack::Slice) override {
    throw std::runtime_error("fuzz: no validator in direct-call mode");
  }
  Database& vocbase() const override {
    throw std::runtime_error("fuzz: no vocbase in direct-call mode");
  }
  transaction::Methods& trx() const override {
    throw std::runtime_error("fuzz: no transaction in direct-call mode");
  }
  bool killed() const override { return false; }
  void setVariable(aql::Variable const*, velocypack::Slice) override {}
  void clearVariable(aql::Variable const*) noexcept override {}
};

}  // namespace arangodb::fuzz
