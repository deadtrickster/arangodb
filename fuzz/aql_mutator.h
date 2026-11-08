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

#pragma once

// A structure-aware AQL mutator: the port of serenedb's fuzz/sql_mutator.h
// (itself a port of pg-fuzz's fuzz_sqlmut.h). Byte mutation leaves most AQL
// unparseable, so every mutant here is built from the token stream of a seed
// that already parsed, and spliced tokens come from a ring of such seeds.
//
// Self-contained by design: no arangod header is included and nothing here
// links against the tree. The keyword table is the lexer's own vocabulary
// (arangod/Aql/Parser/tokens.ll — tokens.hh is flex output and lives in the
// build tree), and the parse oracle is a hook the harness installs: only it
// can construct the engine's Parser, which needs a Database.
//
// Excluded from coverage (SM_FN) because the donor ring depends on history.

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

extern "C" std::size_t LLVMFuzzerMutate(std::uint8_t* data, std::size_t size,
                                        std::size_t max_size);

#if defined(__has_attribute)
#if __has_attribute(no_profile_instrument_function)
#define SM_NOPROF __attribute__((no_profile_instrument_function))
#endif
#endif
#ifndef SM_NOPROF
#define SM_NOPROF
#endif
#if defined(__clang__)
#define SM_NOCOV __attribute__((no_sanitize("coverage")))
#else
#define SM_NOCOV
#endif

#define SM_FN inline SM_NOCOV SM_NOPROF
#define SM_ENTRY inline SM_NOCOV SM_NOPROF __attribute__((noinline))

namespace arangodb::fuzz::aqlmut {

/* ------------------------------------------------------------------ PRNG */
struct Rng {
  std::uint64_t s;
};

SM_FN std::uint64_t Next(Rng& r) {
  std::uint64_t z = (r.s += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

SM_FN std::uint32_t Below(Rng& r, std::uint32_t n) {
  return n == 0 ? 0 : static_cast<std::uint32_t>(Next(r) % n);
}

/* --------------------------------------------------------------- keywords */
// AQL's keyword vocabulary, transcribed from arangod/Aql/Parser/tokens.ll.
// Four classes, one bit each: a keyword swap stays inside its class, which is
// what keeps a mutated clause a clause. Multi-word lexer tokens (NOT IN,
// ALL LIKE, AT LEAST) are two words here — spliced as text they are still
// exactly what the engine's lexer reads.
enum { KW_CLAUSE, KW_MODIFIER, KW_LOGICAL, KW_LITERAL, KW_NCLASS };

struct KwDef {
  char const* name;
  std::uint8_t bit;
};

// clang-format off
inline constexpr KwDef kKeywordDefs[] = {
  // declarations and commands
  {"for", 1u << KW_CLAUSE}, {"let", 1u << KW_CLAUSE},
  {"filter", 1u << KW_CLAUSE}, {"return", 1u << KW_CLAUSE},
  {"collect", 1u << KW_CLAUSE}, {"sort", 1u << KW_CLAUSE},
  {"limit", 1u << KW_CLAUSE}, {"window", 1u << KW_CLAUSE},
  {"match", 1u << KW_CLAUSE}, {"while", 1u << KW_CLAUSE},
  {"until", 1u << KW_CLAUSE}, {"scan", 1u << KW_CLAUSE},
  {"fold", 1u << KW_CLAUSE}, {"remove", 1u << KW_CLAUSE},
  {"insert", 1u << KW_CLAUSE}, {"update", 1u << KW_CLAUSE},
  {"replace", 1u << KW_CLAUSE}, {"upsert", 1u << KW_CLAUSE},
  {"with", 1u << KW_CLAUSE}, {"graph", 1u << KW_CLAUSE},
  {"shortest_path", 1u << KW_CLAUSE}, {"k_shortest_paths", 1u << KW_CLAUSE},
  {"k_paths", 1u << KW_CLAUSE}, {"all_shortest_paths", 1u << KW_CLAUSE},
  {"inner_join", 1u << KW_CLAUSE}, {"left_join", 1u << KW_CLAUSE},
  {"right_join", 1u << KW_CLAUSE}, {"outer_join", 1u << KW_CLAUSE},
  // modifiers: sort direction, collect shape, traversal direction/quantifier
  {"asc", 1u << KW_MODIFIER}, {"desc", 1u << KW_MODIFIER},
  {"distinct", 1u << KW_MODIFIER}, {"aggregate", 1u << KW_MODIFIER},
  {"outbound", 1u << KW_MODIFIER}, {"inbound", 1u << KW_MODIFIER},
  {"all", 1u << KW_MODIFIER}, {"any", 1u << KW_MODIFIER},
  {"none", 1u << KW_MODIFIER}, {"into", 1u << KW_MODIFIER},
  // word operators
  {"and", 1u << KW_LOGICAL}, {"or", 1u << KW_LOGICAL},
  {"not", 1u << KW_LOGICAL}, {"in", 1u << KW_LOGICAL},
  {"like", 1u << KW_LOGICAL},
  // predefined value literals
  {"null", 1u << KW_LITERAL}, {"true", 1u << KW_LITERAL},
  {"false", 1u << KW_LITERAL},
};
// clang-format on

struct KeywordTable {
  std::vector<std::string> names;
  std::vector<std::uint8_t> bits;
  std::unordered_map<std::string, std::int16_t> index;
  std::vector<std::int16_t> by_class[KW_NCLASS];
};

SM_FN const KeywordTable& Keywords() {
  static const KeywordTable table = [] {
    KeywordTable t;
    for (const auto& kw : kKeywordDefs) {
      auto it = t.index.find(kw.name);
      if (it != t.index.end()) {
        t.bits[static_cast<std::size_t>(it->second)] |= kw.bit;
        continue;
      }
      const auto idx = static_cast<std::int16_t>(t.names.size());
      t.names.emplace_back(kw.name);
      t.bits.push_back(kw.bit);
      t.index.emplace(t.names.back(), idx);
    }
    for (std::size_t i = 0; i < t.names.size(); ++i) {
      for (int c = 0; c < KW_NCLASS; ++c) {
        if (t.bits[i] & (1u << c)) {
          t.by_class[c].push_back(static_cast<std::int16_t>(i));
        }
      }
    }
    return t;
  }();
  return table;
}

SM_FN const std::unordered_map<std::string, std::int16_t>& KeywordIndex() {
  return Keywords().index;
}

// Keyword indices the structure depends on, found once.
struct NamedKeywords {
  int in_ = -1;
  int into_ = -1;
  int null_ = -1;
  int true_ = -1;
  int false_ = -1;
  std::vector<bool> opener;   // starts a clause: a list boundary
  std::vector<bool> relnext;  // the name that follows names a data source
};

SM_FN const NamedKeywords& Named() {
  static const NamedKeywords named = [] {
    NamedKeywords out;
    const auto& t = Keywords();
    out.opener.assign(t.names.size(), false);
    out.relnext.assign(t.names.size(), false);
    auto find = [&](const char* w) -> int {
      auto it = t.index.find(w);
      return it == t.index.end() ? -1 : it->second;
    };
    for (std::size_t i = 0; i < t.names.size(); ++i) {
      out.opener[i] = (t.bits[i] & (1u << KW_CLAUSE)) != 0;
    }
    for (const char* w :
         {"in", "into", "graph", "with", "shortest_path", "k_shortest_paths",
          "k_paths", "all_shortest_paths", "outbound", "inbound", "all", "any",
          "none"}) {
      int k = find(w);
      if (k >= 0) {
        out.relnext[static_cast<std::size_t>(k)] = true;
      }
    }
    out.in_ = find("in");
    out.into_ = find("into");
    out.null_ = find("null");
    out.true_ = find("true");
    out.false_ = find("false");
    return out;
  }();
  return named;
}

/* ------------------------------------------------------------- tokenizer */
enum {
  T_IDENT,    // doc, $var, _key
  T_QIDENT,   // `doc`
  T_KEYWORD,  // FOR, null, ...
  T_STRING,   // 'x', "x"
  T_NUMBER,   // 1, 1.5, 0x1f, 0b101, 1e9
  T_PARAM,    // @p, @@collection
  T_OP,       // == != <= >= =~ !~ && || + - * / % ? :
  T_OPEN,     // ( [ {
  T_CLOSE,    // ) ] }
  T_COMMA,
  T_DOT,      // member access
  T_SCOPE,    // :: user function scope
  T_BAD,      // unterminated string, quoted identifier or comment
  T_OTHER,
};

struct Tok {
  std::uint8_t kind;
  std::int8_t kwclass;
  std::int16_t kw;
  std::int32_t off;
  std::int32_t len;
  std::int32_t depth;
  std::int32_t match;
};

constexpr int kMaxTok = 4096;

struct Lex {
  const std::uint8_t* s;
  std::size_t n;
  int ntok;
  Tok tok[kMaxTok];
};

SM_FN bool IdentStart(std::uint8_t c) {
  return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

SM_FN bool IdentChar(std::uint8_t c) {
  return IdentStart(c) || (c >= '0' && c <= '9');
}

SM_FN bool Digit(std::uint8_t c) { return c >= '0' && c <= '9'; }

SM_FN bool HexDigit(std::uint8_t c) {
  return Digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

SM_FN bool OpChar(std::uint8_t c) {
  return c != '\0' && std::strchr("=<>!|+-*/%?:&", c) != nullptr;
}

SM_FN bool Space(std::uint8_t c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
         c == '\v';
}

// AQL has no doubled-quote escape: inside a quoted run a backslash escapes the
// next byte, and only the closing quote ends it. An unterminated run is what
// makes a mutant unparseable, so the caller learns it from `closed`.
SM_FN std::size_t Quoted(const std::uint8_t* s, std::size_t n, std::size_t i,
                         std::uint8_t q, bool& closed) {
  std::size_t j = i + 1;
  closed = false;
  while (j < n) {
    if (s[j] == '\\' && j + 1 < n) {
      j += 2;
    } else if (s[j] == q) {
      closed = true;
      return j + 1;
    } else {
      ++j;
    }
  }
  return n;
}

SM_FN void Tokenize(Lex& L, const std::uint8_t* s, std::size_t n) {
  int stack[kMaxTok];
  int sp = 0;
  std::size_t i = 0;
  L.s = s;
  L.n = n;
  L.ntok = 0;
  while (i < n && L.ntok < kMaxTok) {
    std::uint8_t c = s[i];
    std::size_t j = i + 1;
    int kind = T_OTHER;
    if (Space(c)) {
      ++i;
      continue;
    }
    if (c == '/' && i + 1 < n && s[i + 1] == '/') {
      while (i < n && s[i] != '\n') {
        ++i;
      }
      continue;
    }
    if (c == '/' && i + 1 < n && s[i + 1] == '*') {
      // AQL block comments do not nest; an unterminated one is a parse error.
      bool closed = false;
      i += 2;
      while (i + 1 < n) {
        if (s[i] == '*' && s[i + 1] == '/') {
          i += 2;
          closed = true;
          break;
        }
        ++i;
      }
      if (!closed) {
        i = n;
        if (L.ntok < kMaxTok) {
          Tok* t = &L.tok[L.ntok];
          t->kind = T_BAD;
          t->off = 0;
          t->len = static_cast<std::int32_t>(n);
          t->kw = -1;
          t->kwclass = -1;
          t->match = -1;
          t->depth = sp;
          ++L.ntok;
        }
      }
      continue;
    }
    if (c == '\'' || c == '"') {
      bool closed = false;
      j = Quoted(s, n, i, c, closed);
      kind = closed ? T_STRING : T_BAD;
    } else if (c == '`') {
      bool closed = false;
      j = Quoted(s, n, i, c, closed);
      kind = closed ? T_QIDENT : T_BAD;
    } else if (c == '@') {
      // @param or @@collection
      kind = T_PARAM;
      if (j < n && s[j] == '@') {
        ++j;
      }
      while (j < n && IdentChar(s[j])) {
        ++j;
      }
    } else if (Digit(c) || (c == '.' && j < n && Digit(s[j]))) {
      kind = T_NUMBER;
      if (c == '0' && j < n && (s[j] == 'x' || s[j] == 'X')) {
        j = i + 2;
        while (j < n && HexDigit(s[j])) {
          ++j;
        }
      } else if (c == '0' && j < n && (s[j] == 'b' || s[j] == 'B')) {
        j = i + 2;
        while (j < n && (s[j] == '0' || s[j] == '1')) {
          ++j;
        }
      } else {
        j = i;
        while (j < n && Digit(s[j])) {
          ++j;
        }
        // "1..3" is a range, not a double: the dot must not be swallowed.
        if (j < n && s[j] == '.' && !(j + 1 < n && s[j + 1] == '.')) {
          ++j;
          while (j < n && Digit(s[j])) {
            ++j;
          }
        }
        if (j < n && (s[j] == 'e' || s[j] == 'E')) {
          std::size_t k = j + 1;
          if (k < n && (s[k] == '+' || s[k] == '-')) {
            ++k;
          }
          if (k < n && Digit(s[k])) {
            j = k;
            while (j < n && Digit(s[j])) {
              ++j;
            }
          }
        }
      }
    } else if (IdentStart(c)) {
      while (j < n && IdentChar(s[j])) {
        ++j;
      }
      kind = T_IDENT;
    } else if (c == '(' || c == '[' || c == '{') {
      kind = T_OPEN;
    } else if (c == ')' || c == ']' || c == '}') {
      kind = T_CLOSE;
    } else if (c == ',') {
      kind = T_COMMA;
    } else if (c == '.') {
      if (i + 2 < n && s[i + 1] == '.' && s[i + 2] == '.') {
        kind = T_OP;  // object spread
        j = i + 3;
      } else if (i + 1 < n && s[i + 1] == '.') {
        kind = T_OP;  // range
        j = i + 2;
      } else {
        kind = T_DOT;
      }
    } else if (c == ':' && j < n && s[j] == ':') {
      kind = T_SCOPE;
      ++j;
    } else if (OpChar(c)) {
      kind = T_OP;
      while (j < n && OpChar(s[j]) &&
             !(s[j] == '/' && j + 1 < n && (s[j + 1] == '/' || s[j + 1] == '*'))) {
        ++j;
      }
    }

    Tok* t = &L.tok[L.ntok];
    t->kind = static_cast<std::uint8_t>(kind);
    t->off = static_cast<std::int32_t>(i);
    t->len = static_cast<std::int32_t>(j - i);
    t->kw = -1;
    t->kwclass = -1;
    t->match = -1;
    if (kind == T_IDENT) {
      std::string lower;
      lower.reserve(static_cast<std::size_t>(t->len));
      for (std::int32_t k = 0; k < t->len; ++k) {
        lower.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(s[t->off + k]))));
      }
      auto it = KeywordIndex().find(lower);
      if (it != KeywordIndex().end()) {
        t->kind = T_KEYWORD;
        t->kw = it->second;
        const auto bits = Keywords().bits[static_cast<std::size_t>(t->kw)];
        for (int c2 = 0; c2 < KW_NCLASS; ++c2) {
          if (bits & (1u << c2)) {
            t->kwclass = static_cast<std::int8_t>(c2);
            break;
          }
        }
      }
    }
    if (kind == T_CLOSE && sp > 0) {
      --sp;
      t->match = stack[sp];
      L.tok[stack[sp]].match = L.ntok;
    }
    t->depth = sp;
    if (kind == T_OPEN) {
      stack[sp++] = L.ntok;
    }
    ++L.ntok;
    i = j;
  }
}

SM_FN std::int32_t End(const Lex& L, int k) {
  return L.tok[k].off + L.tok[k].len;
}

/* ----------------------------------------------------------------- spans */
enum {
  S_ELEM,     // one comma-separated element of a list
  S_GROUP,    // a bracketed run
  S_OPERAND,  // a postfix chain: name, name.x, name[0], name(x), ns::fn
};

struct Span {
  std::int32_t a;
  std::int32_t b;
  std::uint8_t kind;
  std::int32_t list;
  std::int32_t before;
  std::int32_t after;
};

constexpr int kMaxSpan = 8192;

struct SpanSet {
  int n;
  int nlists;
  Span v[kMaxSpan];
};

SM_FN void AddSpan(SpanSet& S, int a, int b, int kind, int list, int before,
                   int after) {
  if (S.n >= kMaxSpan) {
    return;
  }
  Span* p = &S.v[S.n++];
  p->a = a;
  p->b = b;
  p->kind = static_cast<std::uint8_t>(kind);
  p->list = list;
  p->before = before;
  p->after = after;
}

// A list element ends where a new clause starts: the clause keywords are AQL's
// statement separators, and there is no semicolon to lean on.
SM_FN bool Boundary(const Tok* t) {
  if (t->kind == T_CLOSE) {
    return true;
  }
  if (t->kind != T_KEYWORD || t->kw < 0) {
    return false;
  }
  return Named().opener[static_cast<std::size_t>(t->kw)];
}

SM_FN void Lists(const Lex& L, SpanSet& S, int lo, int hi) {
  int list = S.nlists++;
  int first = S.n;
  int seg = lo;
  int prevcomma = -1;
  bool commas = false;

  for (int k = lo; k <= hi + 1; ++k) {
    const Tok* t = k <= hi ? &L.tok[k] : nullptr;
    bool stop = t == nullptr;

    if (t != nullptr && t->kind == T_OPEN) {
      if (t->match > k && t->match <= hi) {
        k = t->match;
        continue;
      }
      stop = true;
    }
    if (stop || t->kind == T_COMMA || Boundary(t)) {
      bool comma = !stop && t->kind == T_COMMA;
      if (seg <= k - 1) {
        AddSpan(S, seg, k - 1, S_ELEM, list, prevcomma, comma ? k : -1);
      }
      if (comma) {
        prevcomma = k;
        commas = true;
      } else {
        if (!commas || S.n - first < 2) {
          S.n = first;
        }
        list = S.nlists++;
        first = S.n;
        commas = false;
        prevcomma = -1;
      }
      seg = k + 1;
      if (stop) {
        break;
      }
    }
  }
}

// The postfix chain an operand spans: doc.a.b, doc[0], doc[*].a, fn(x), ns::fn.
SM_FN int OperandEnd(const Lex& L, int k) {
  int e = k;
  for (;;) {
    int nx = e + 1;
    if (nx >= L.ntok) {
      break;
    }
    const Tok* t = &L.tok[nx];
    const int last = L.tok[e].kind;
    if (t->kind == T_DOT && nx + 1 < L.ntok &&
        (L.tok[nx + 1].kind == T_IDENT || L.tok[nx + 1].kind == T_QIDENT ||
         L.tok[nx + 1].kind == T_KEYWORD)) {
      e = nx + 1;
    } else if (t->kind == T_SCOPE && nx + 1 < L.ntok &&
               (L.tok[nx + 1].kind == T_IDENT ||
                L.tok[nx + 1].kind == T_QIDENT)) {
      e = nx + 1;
    } else if (t->kind == T_OPEN && t->match > nx &&
               (L.s[t->off] == '[' || last == T_IDENT || last == T_QIDENT ||
                last == T_KEYWORD)) {
      e = t->match;
    } else {
      break;
    }
  }
  return e;
}

SM_FN void Spans(const Lex& L, SpanSet& S) {
  S.n = 0;
  S.nlists = 0;
  if (L.ntok == 0) {
    return;
  }
  Lists(L, S, 0, L.ntok - 1);
  for (int k = 0; k < L.ntok; ++k) {
    const Tok* t = &L.tok[k];
    if (t->kind == T_OPEN && t->match > k) {
      AddSpan(S, k, t->match, S_GROUP, -1, -1, -1);
      if (t->match > k + 1) {
        Lists(L, S, k + 1, t->match - 1);
      }
    }
  }
  for (int k = 0; k < L.ntok; ++k) {
    const Tok* t = &L.tok[k];
    const Tok* p = k > 0 ? &L.tok[k - 1] : nullptr;
    if (p != nullptr && (p->kind == T_DOT || p->kind == T_SCOPE ||
                         p->kind == T_PARAM)) {
      continue;
    }
    const auto& named = Named();
    bool start =
        t->kind == T_IDENT || t->kind == T_QIDENT || t->kind == T_NUMBER ||
        t->kind == T_STRING || t->kind == T_PARAM ||
        (t->kind == T_KEYWORD &&
         (t->kw == named.null_ || t->kw == named.true_ ||
          t->kw == named.false_ ||
          (t->kwclass >= 0 && t->kwclass != KW_CLAUSE && k + 1 < L.ntok &&
           L.tok[k + 1].kind == T_OPEN && L.s[L.tok[k + 1].off] == '(')));
    if (start) {
      AddSpan(S, k, OperandEnd(L, k), S_OPERAND, -1, -1, -1);
    }
  }
}

/* ----------------------------------------------------------------- pools */
struct Pool {
  std::vector<std::string> v;
  void Add(const std::string& s) { v.push_back(s); }
  const char* Pick(Rng& r) const {
    return v.empty()
               ? nullptr
               : v[Below(r, static_cast<std::uint32_t>(v.size()))].c_str();
  }
};

struct Pools {
  Pool rels;     // collection, graph and view names
  Pool names;    // variables and attributes
  Pool funcs;    // AQL function names (fuzz/aql_functions_fuzzer.dict)
  Pool ops;      // the operator vocabulary of the lexer
  Pool lit_num;
  Pool lit_str;
  bool ready = false;
};

inline Pools& ThePools() {
  static Pools pools;
  return pools;
}

/* ---------------------------------------------------------- donor ring */
constexpr int kDonors = 4096;
constexpr int kDonorMax = 256;
struct DonorRing {
  char text[kDonors][kDonorMax];
  std::uint16_t len[kDonors];
  std::uint8_t kind[kDonors];
  int n = 0;
  Rng rng = {0x5eedd0a0};
};

inline DonorRing& Donors() {
  static DonorRing ring;
  return ring;
}

/* ------------------------------------------------------------- counters */
enum {
  OP_NAME,
  OP_LITERAL,
  OP_OPERATOR,
  OP_KEYWORD,
  OP_DELETE,
  OP_DUPLICATE,
  OP_SWAP,
  OP_SPLICE,
  OP_WRAP,
  SM_NOPS,
};

inline constexpr const char* kOpName[SM_NOPS] = {
    "name",      "literal", "operator", "keyword", "delete",
    "duplicate", "swap",    "splice",   "wrap"};

struct Stats {
  std::uint64_t calls = 0;
  std::uint64_t bytes = 0;
  std::uint64_t fallback = 0;
  std::uint64_t structured = 0;
  std::uint64_t valid = 0;
  std::uint64_t valid_first = 0;
  std::uint64_t attempts = 0;
  std::uint64_t applied[SM_NOPS] = {};
  std::uint64_t in_result[SM_NOPS] = {};
  std::uint64_t in_valid[SM_NOPS] = {};
  std::uint64_t donated = 0;
};

inline Stats& TheStats() {
  static Stats s;
  return s;
}

inline bool g_enabled = false;
inline bool g_selftesting = false;

/* ------------------------------------------------------------ parse hook */
// The engine's Parser needs a QueryContext, which needs a Database, so the
// mutator cannot own one: the harness installs the oracle. `ShapeCheck` is the
// default and is not the grammar — it is what the tokenizer can prove about a
// candidate on its own — so the report always names the check in force.
using ParseFn = bool (*)(char const* data, std::size_t len, void* user);

SM_FN bool ShapeCheck(char const* data, std::size_t len, void* /*user*/);

inline ParseFn g_parse = &ShapeCheck;
inline void* g_parse_user = nullptr;
inline char const* g_parse_name = "token-level shape";

SM_FN void SetParseCheck(ParseFn fn, void* user, char const* name) {
  g_parse = fn == nullptr ? &ShapeCheck : fn;
  g_parse_user = user;
  g_parse_name = name == nullptr ? "hook" : name;
}

SM_FN char const* ParseCheckName() { return g_parse_name; }

SM_FN void Report(const char* when) {
  auto& s = TheStats();
  const std::uint64_t st = s.structured;
  std::fprintf(
      stderr,
      "aqlmut: %s: %llu calls, parse-valid %.1f%% (first try %.1f%%) of %llu "
      "structured [check: %s], bytes %llu, fallback %llu, donors %d/%d; "
      "applied",
      when, static_cast<unsigned long long>(s.calls),
      st ? 100.0 * static_cast<double>(s.valid) / static_cast<double>(st) : 0.0,
      st ? 100.0 * static_cast<double>(s.valid_first) / static_cast<double>(st)
         : 0.0,
      static_cast<unsigned long long>(st), ParseCheckName(),
      static_cast<unsigned long long>(s.bytes),
      static_cast<unsigned long long>(s.fallback), Donors().n, kDonors);
  for (int i = 0; i < SM_NOPS; ++i) {
    std::fprintf(stderr, " %s=%llu", kOpName[i],
                 static_cast<unsigned long long>(s.applied[i]));
  }
  std::fputc('\n', stderr);
  std::fflush(stderr);
}

SM_FN void ReportAtExit() {
  if (TheStats().calls > 0) {
    Report("at exit");
  }
}

/* ---------------------------------------------------------- pool loading */
SM_FN void AddDefaults(Pool& rels, Pool& names, Pool& funcs, Pool& ops,
                       Pool& nums, Pool& strs) {
  for (const char* s :
       {"collection", "users", "edges", "vertices", "documents", "items",
        "orders", "products", "testCollection", "UnitTestsAhuacatlCollection",
        "UnitTestsAhuacatlEdge"}) {
    rels.Add(s);
  }
  for (const char* s :
       {"doc", "u", "v", "e", "p", "x", "y", "a", "b", "n", "i", "j", "item",
        "row", "obj", "arr", "key", "value", "count", "total", "old", "new",
        "_key", "_id", "_rev", "_from", "_to", "name", "age", "type"}) {
    names.Add(s);
  }
  // Fallback only: the dict file holds the 233 names AqlFunctionFeature.cpp
  // registers, and a name the engine does not know costs a parse.
  for (const char* s :
       {"LENGTH", "CONCAT", "SUM", "AVERAGE", "MIN", "MAX", "COUNT", "TO_STRING",
        "TO_NUMBER", "TO_BOOL", "TO_ARRAY", "IS_NULL", "IS_STRING", "ABS",
        "CEIL", "FLOOR", "ROUND", "SQRT", "POW", "UPPER", "LOWER", "SUBSTRING",
        "LEFT", "RIGHT", "TRIM", "UNIQUE", "SORTED", "FIRST", "LAST", "MERGE",
        "ATTRIBUTES", "VALUES", "HAS", "DOCUMENT", "UNSET", "KEEP", "PUSH",
        "APPEND", "REMOVE_VALUE", "REMOVE_VALUES", "DATE_NOW", "DATE_ISO8601"}) {
    funcs.Add(s);
  }
  for (const char* s :
       {"==", "!=", "<", ">", "<=", ">=", "=~", "!~", "+", "-", "*", "/", "%",
        "&&", "||", "IN", "NOT IN", "LIKE", "NOT LIKE", "AND", "OR"}) {
    ops.Add(s);
  }
  for (const char* s :
       {"0", "1", "-1", "2", "3", "10", "100", "0.5", "-0.5", "1.5",
        "9223372036854775807", "-9223372036854775808", "1e308", "1e-308",
        "0x1f", "0b101"}) {
    nums.Add(s);
  }
  for (const char* s :
       {"'a'", "'abc'", "''", "'%'", "'a%'", "'%a'", "'^a$'", "'[a-z]+'",
        "'2026-11-07T12:00:00Z'", "'1970-01-01T00:00:00Z'", "\"x\"",
        "\"collection\"", "'number'", "'string'", "'\\n'", "'\\t'"}) {
    strs.Add(s);
  }
}

// Function names come from the fuzzer's own dictionary — the same generated
// list the target's dictionary carries, so the two cannot drift. A missing
// file is a warning, not a failure: the fallback names are the common ones.
SM_FN void LoadDict(Pool& funcs) {
  const char* path = std::getenv("AQLMUT_DICT");
  if (path == nullptr) {
    path = "fuzz/aql_functions_fuzzer.dict";
  }
  std::ifstream in(path);
  if (!in) {
    std::fprintf(stderr,
                 "aqlmut: no %s -- the function pool is the %zu built-in "
                 "names (set AQLMUT_DICT to the dictionary)\n",
                 path, funcs.v.size());
    return;
  }
  Pool loaded;
  std::string line;
  while (std::getline(in, line)) {
    if (line.size() < 3 || line.front() != '"' || line.back() != '"') {
      continue;
    }
    std::string name = line.substr(1, line.size() - 2);
    if (!name.empty() && IdentStart(static_cast<std::uint8_t>(name[0]))) {
      bool ok = true;
      for (char ch : name) {
        ok = ok && IdentChar(static_cast<std::uint8_t>(ch));
      }
      if (ok) {
        loaded.Add(name);
      }
    }
  }
  if (!loaded.v.empty()) {
    funcs = loaded;
  }
}

SM_FN void LoadPools() {
  auto& pools = ThePools();
  if (pools.ready) {
    return;
  }
  pools.ready = true;
  AddDefaults(pools.rels, pools.names, pools.funcs, pools.ops, pools.lit_num,
              pools.lit_str);
  LoadDict(pools.funcs);
  std::fprintf(stderr,
               "aqlmut: pools: %zu data sources, %zu names, %zu functions, "
               "%zu operators; literals %zu numeric, %zu string\n",
               pools.rels.v.size(), pools.names.v.size(), pools.funcs.v.size(),
               pools.ops.v.size(), pools.lit_num.v.size(),
               pools.lit_str.v.size());
}

/* --------------------------------------------------------------- output */
struct Out {
  std::uint8_t* buf;
  std::size_t len;
  std::size_t cap;
  bool overflow;
};

SM_FN bool Glues(std::uint8_t a, std::uint8_t b) {
  return (IdentChar(a) && IdentChar(b)) || (OpChar(a) && OpChar(b)) ||
         (a == ':' && b == ':') || (a == '.' && Digit(b)) ||
         (Digit(a) && b == '.') || (a == '@' && IdentChar(b));
}

SM_FN void Put(Out& o, const void* p, std::size_t n) {
  const auto* b = static_cast<const std::uint8_t*>(p);
  if (n == 0 || o.overflow) {
    return;
  }
  if (o.len > 0 && Glues(o.buf[o.len - 1], b[0])) {
    if (o.len + 1 > o.cap) {
      o.overflow = true;
      return;
    }
    o.buf[o.len++] = ' ';
  }
  if (o.len + n > o.cap) {
    o.overflow = true;
    return;
  }
  std::memcpy(o.buf + o.len, b, n);
  o.len += n;
}

SM_FN void PutStr(Out& o, const char* s) { Put(o, s, std::strlen(s)); }

SM_FN void PutView(Out& o, std::string_view s) { Put(o, s.data(), s.size()); }

SM_FN bool Replace(Out& o, const Lex& L, std::int32_t a, std::int32_t b,
                   const char* rep, std::size_t replen) {
  o.len = 0;
  o.overflow = false;
  Put(o, L.s, static_cast<std::size_t>(a));
  Put(o, rep, replen);
  Put(o, L.s + b, L.n - static_cast<std::size_t>(b));
  return !o.overflow;
}

SM_FN bool ReplaceView(Out& o, const Lex& L, std::int32_t a, std::int32_t b,
                       std::string_view rep) {
  return Replace(o, L, a, b, rep.data(), rep.size());
}

/* ------------------------------------------------------------ operators */
struct Ctx {
  Lex* L;
  SpanSet* S;
  bool have_spans;
  Rng* r;
  Out* o;
};

SM_FN int PickToken(Ctx& C, bool (*want)(const Tok*)) {
  int n = 0;
  int pick = -1;
  for (int k = 0; k < C.L->ntok; ++k) {
    if (want(&C.L->tok[k]) &&
        Below(*C.r, static_cast<std::uint32_t>(++n)) == 0) {
      pick = k;
    }
  }
  return pick;
}

SM_FN void NeedSpans(Ctx& C) {
  if (!C.have_spans) {
    Spans(*C.L, *C.S);
    C.have_spans = true;
  }
}

SM_FN int PickSpan(Ctx& C, unsigned kinds) {
  int n = 0;
  int pick = -1;
  NeedSpans(C);
  for (int i = 0; i < C.S->n; ++i) {
    if ((kinds & (1u << C.S->v[i].kind)) &&
        Below(*C.r, static_cast<std::uint32_t>(++n)) == 0) {
      pick = i;
    }
  }
  return pick;
}

SM_FN bool IsName(const Tok* t) {
  return t->kind == T_IDENT || t->kind == T_QIDENT;
}
SM_FN bool IsLiteral(const Tok* t) {
  return t->kind == T_NUMBER || t->kind == T_STRING;
}
SM_FN bool IsOpTok(const Tok* t) { return t->kind == T_OP; }
SM_FN bool IsKeyword(const Tok* t) { return t->kind == T_KEYWORD; }

// A name means what its neighbours make it mean: a data source after IN,
// GRAPH or a traversal direction, a function when a call follows, a variable
// or attribute otherwise. Picking from the right pool is what keeps a mutated
// name a name of the same kind.
SM_FN bool OpName(Ctx& C) {
  const Lex& L = *C.L;
  auto& pools = ThePools();
  int k = PickToken(C, IsName);
  if (k < 0) {
    return false;
  }
  const Tok* prev = k > 0 ? &L.tok[k - 1] : nullptr;
  const Tok* next = k + 1 < L.ntok ? &L.tok[k + 1] : nullptr;
  const auto& named = Named();
  Pool* pool = &pools.names;
  if (prev != nullptr && prev->kind == T_KEYWORD && prev->kw >= 0 &&
      named.relnext[static_cast<std::size_t>(prev->kw)]) {
    pool = &pools.rels;
  } else if (next != nullptr && next->kind == T_OPEN &&
             L.s[next->off] == '(') {
    pool = &pools.funcs;
  }
  if (pool->v.empty()) {
    pool = &pools.names;
  }
  const char* rep = pool->Pick(*C.r);
  if (rep == nullptr) {
    return false;
  }
  return Replace(*C.o, L, L.tok[k].off, End(L, k), rep, std::strlen(rep));
}

SM_FN bool OpLiteral(Ctx& C) {
  const Lex& L = *C.L;
  auto& pools = ThePools();
  int k = PickToken(C, IsLiteral);
  if (k < 0) {
    return false;
  }
  const char* rep = nullptr;
  if (Below(*C.r, 8) != 0) {
    rep =
        (L.tok[k].kind == T_NUMBER ? pools.lit_num : pools.lit_str).Pick(*C.r);
  }
  if (rep == nullptr) {
    rep = "null";
  }
  return Replace(*C.o, L, L.tok[k].off, End(L, k), rep, std::strlen(rep));
}

SM_FN bool OpOperator(Ctx& C) {
  const Lex& L = *C.L;
  int k = PickToken(C, IsOpTok);
  if (k < 0) {
    return false;
  }
  const char* rep = ThePools().ops.Pick(*C.r);
  if (rep == nullptr) {
    return false;
  }
  return Replace(*C.o, L, L.tok[k].off, End(L, k), rep, std::strlen(rep));
}

SM_FN bool OpKeyword(Ctx& C) {
  const Lex& L = *C.L;
  int k = PickToken(C, IsKeyword);
  if (k < 0) {
    return false;
  }
  const int cls = L.tok[k].kwclass;
  if (cls < 0 || cls >= KW_NCLASS) {
    return false;
  }
  const auto& table = Keywords();
  const auto& bucket = table.by_class[cls];
  if (bucket.size() < 2) {
    return false;
  }
  const auto rep = table.names[static_cast<std::size_t>(
      bucket[Below(*C.r, static_cast<std::uint32_t>(bucket.size()))])];
  return ReplaceView(*C.o, L, L.tok[k].off, End(L, k), rep);
}

SM_FN bool OpDelete(Ctx& C) {
  const Lex& L = *C.L;
  int i = PickSpan(C, (1u << S_ELEM) | (1u << S_GROUP));
  if (i < 0) {
    return false;
  }
  const Span* p = &C.S->v[i];
  std::int32_t a = L.tok[p->a].off;
  std::int32_t b = End(L, p->b);
  if (p->kind == S_ELEM) {
    if (p->after >= 0) {
      b = End(L, p->after);
    } else if (p->before >= 0) {
      a = L.tok[p->before].off;
    }
  }
  return Replace(*C.o, L, a, b, "", 0);
}

SM_FN bool OpDuplicate(Ctx& C) {
  const Lex& L = *C.L;
  int i = PickSpan(C, (1u << S_ELEM) | (1u << S_GROUP));
  if (i < 0) {
    return false;
  }
  const Span* p = &C.S->v[i];
  const std::int32_t a = L.tok[p->a].off;
  const std::int32_t b = End(L, p->b);
  Out& o = *C.o;
  o.len = 0;
  o.overflow = false;
  Put(o, L.s, static_cast<std::size_t>(b));
  if (p->kind == S_ELEM) {
    PutStr(o, ", ");
  }
  Put(o, L.s + a, static_cast<std::size_t>(b - a));
  Put(o, L.s + b, L.n - static_cast<std::size_t>(b));
  return !o.overflow;
}

SM_FN bool OpSwap(Ctx& C) {
  const Lex& L = *C.L;
  int i = PickSpan(C, 1u << S_ELEM);
  if (i < 0) {
    return false;
  }
  int j = -1;
  int n = 0;
  for (int k = 0; k < C.S->n; ++k) {
    if (k != i && C.S->v[k].kind == S_ELEM &&
        C.S->v[k].list == C.S->v[i].list &&
        Below(*C.r, static_cast<std::uint32_t>(++n)) == 0) {
      j = k;
    }
  }
  if (j < 0) {
    return false;
  }
  const Span* x = &C.S->v[i < j ? i : j];
  const Span* y = &C.S->v[i < j ? j : i];
  Out& o = *C.o;
  o.len = 0;
  o.overflow = false;
  Put(o, L.s, static_cast<std::size_t>(L.tok[x->a].off));
  Put(o, L.s + L.tok[y->a].off,
      static_cast<std::size_t>(End(L, y->b) - L.tok[y->a].off));
  Put(o, L.s + End(L, x->b),
      static_cast<std::size_t>(L.tok[y->a].off - End(L, x->b)));
  Put(o, L.s + L.tok[x->a].off,
      static_cast<std::size_t>(End(L, x->b) - L.tok[x->a].off));
  Put(o, L.s + End(L, y->b), L.n - static_cast<std::size_t>(End(L, y->b)));
  return !o.overflow;
}

// Splice a span out of a donor of the same span kind: an element for an
// element, a bracketed group for a bracketed group.
SM_FN bool OpSplice(Ctx& C) {
  const Lex& L = *C.L;
  auto& ring = Donors();
  if (ring.n == 0) {
    return false;
  }
  int i = PickSpan(C, (1u << S_ELEM) | (1u << S_GROUP) | (1u << S_OPERAND));
  if (i < 0) {
    return false;
  }
  const Span* p = &C.S->v[i];
  int d = -1;
  for (int t = 0; t < 4; ++t) {
    d = static_cast<int>(Below(*C.r, static_cast<std::uint32_t>(ring.n)));
    if (ring.kind[d] == p->kind) {
      break;
    }
  }
  return Replace(*C.o, L, L.tok[p->a].off, End(L, p->b), ring.text[d],
                 ring.len[d]);
}

SM_FN bool OpWrap(Ctx& C) {
  const Lex& L = *C.L;
  auto& pools = ThePools();
  int i = PickSpan(C, (1u << S_ELEM) | (1u << S_GROUP) | (1u << S_OPERAND));
  if (i < 0) {
    return false;
  }
  const Span* p = &C.S->v[i];
  // A '(' that follows a name is a call's argument list, not an expression:
  // wrapping it would produce "FN NOT (...)". Same guard as the donor.
  if (p->kind == S_GROUP && L.s[L.tok[p->a].off] == '(' &&
      p->a > 0 &&
      (L.tok[p->a - 1].kind == T_IDENT || L.tok[p->a - 1].kind == T_KEYWORD ||
       L.tok[p->a - 1].kind == T_QIDENT)) {
    return false;
  }
  const std::int32_t a = L.tok[p->a].off;
  const std::int32_t b = End(L, p->b);
  int form = static_cast<int>(Below(*C.r, 8));
  const char* func = nullptr;
  if (form == 1 && (func = pools.funcs.Pick(*C.r)) == nullptr) {
    form = 7;
  }
  Out& o = *C.o;
  o.len = 0;
  o.overflow = false;
  Put(o, L.s, static_cast<std::size_t>(a));
  auto x = [&] { Put(o, L.s + a, static_cast<std::size_t>(b - a)); };
  switch (form) {
    case 0:
      PutStr(o, "TO_STRING(");
      x();
      PutStr(o, ")");
      break;
    case 1:
      PutStr(o, func);
      PutStr(o, "(");
      x();
      PutStr(o, ")");
      break;
    case 2:
      PutStr(o, "(");
      x();
      PutStr(o, ") ? 1 : 0");
      break;
    case 3:
      PutStr(o, "NOT (");
      x();
      PutStr(o, ")");
      break;
    case 4:
      PutStr(o, "[");
      x();
      PutStr(o, "]");
      break;
    case 5:
      PutStr(o, "(");
      x();
      PutStr(o, ") IN [1, 2]");
      break;
    case 6:
      PutStr(o, "(");
      x();
      PutStr(o, ") == null");
      break;
    default:
      PutStr(o, "(");
      x();
      PutStr(o, ")");
      break;
  }
  Put(o, L.s + b, L.n - static_cast<std::size_t>(b));
  return !o.overflow;
}

using OpFn = bool (*)(Ctx&);

inline constexpr OpFn kOps[SM_NOPS] = {
    OpName,      OpLiteral, OpOperator, OpKeyword, OpDelete,
    OpDuplicate, OpSwap,    OpSplice,   OpWrap,
};

/* --------------------------------------------------------------- mutate */
inline Lex g_lex;
inline Lex g_shape_lex;
inline SpanSet g_spans;
inline std::vector<std::uint8_t> g_bufs[3];

SM_FN std::size_t ByteMutate(std::uint8_t* data, std::size_t size,
                             std::size_t max_size) {
  return g_selftesting ? size : LLVMFuzzerMutate(data, size, max_size);
}

SM_ENTRY std::size_t Mutate(std::uint8_t* data, std::size_t size,
                            std::size_t max_size, unsigned int seed) {
  auto& S = TheStats();
  S.calls++;
  if ((S.calls & (S.calls - 1)) == 0 && S.calls >= 1024) {
    Report("progress");
  }
  if (!g_enabled || max_size == 0) {
    S.bytes++;
    return ByteMutate(data, size, max_size);
  }
  if (size > max_size) {
    size = max_size;
  }
  Rng r{static_cast<std::uint64_t>(seed) * 0x2545f4914f6cdd1dULL + 1};

  if (Below(r, 10) == 0) {
    S.bytes++;
    return ByteMutate(data, size, max_size);
  }
  if (g_bufs[0].size() < max_size) {
    for (auto& b : g_bufs) {
      b.resize(max_size);
    }
  }

  const ParseFn parses = g_parse;
  bool any = false;
  std::size_t lastlen = 0;
  unsigned lastops = 0;
  for (int attempt = 0; attempt < 5; ++attempt) {
    std::uint8_t* cur = g_bufs[0].data();
    std::size_t curlen = size;
    std::memcpy(cur, data, size);
    const int nops = 1 + static_cast<int>(Below(r, 4));
    unsigned ops = 0;
    for (int i = 0; i < nops; ++i) {
      Out o{g_bufs[1].data(), 0, max_size, false};
      Ctx C{&g_lex, &g_spans, false, &r, &o};
      Tokenize(g_lex, cur, curlen);
      for (int t = 0; t < 8; ++t) {
        const int op = static_cast<int>(Below(r, SM_NOPS));
        if (kOps[op](C)) {
          S.applied[op]++;
          ops |= 1u << op;
          std::swap(g_bufs[0], g_bufs[1]);
          cur = g_bufs[0].data();
          curlen = o.len;
          break;
        }
      }
    }
    if (ops == 0) {
      continue;
    }
    any = true;
    S.attempts++;
    lastlen = curlen;
    lastops = ops;
    std::memcpy(g_bufs[2].data(), cur, curlen);
    if (parses(reinterpret_cast<char const*>(cur), curlen, g_parse_user)) {
      S.valid++;
      if (attempt == 0) {
        S.valid_first++;
      }
      for (int k = 0; k < SM_NOPS; ++k) {
        if (ops & (1u << k)) {
          S.in_valid[k]++;
        }
      }
      break;
    }
  }
  if (!any) {
    S.fallback++;
    return ByteMutate(data, size, max_size);
  }
  S.structured++;
  for (int k = 0; k < SM_NOPS; ++k) {
    if (lastops & (1u << k)) {
      S.in_result[k]++;
    }
  }
  std::memcpy(data, g_bufs[2].data(), lastlen);
  return lastlen;
}

/* ---------------------------------------------------------------- donate */
inline Lex g_dlex;
inline SpanSet g_dspans;

// The harness calls this once per input it has seen parse: the ring is what
// lets a splice put a span where that shape was legal before.
SM_ENTRY void Donate(const std::uint8_t* data, std::size_t size) {
  auto& ring = Donors();
  if (!g_enabled || size == 0) {
    return;
  }
  Rng r{0xcbf29ce484222325ULL};
  for (std::size_t i = 0; i < size; ++i) {
    r.s = (r.s ^ data[i]) * 0x100000001b3ULL;
  }
  Tokenize(g_dlex, data, size);
  Spans(g_dlex, g_dspans);
  if (g_dspans.n == 0) {
    return;
  }
  for (int t = 0; t < 3; ++t) {
    const Span* p =
        &g_dspans.v[Below(r, static_cast<std::uint32_t>(g_dspans.n))];
    const std::int32_t a = g_dlex.tok[p->a].off;
    const std::int32_t len = End(g_dlex, p->b) - a;
    if (len <= 0 || len > kDonorMax) {
      continue;
    }
    const int slot =
        ring.n < kDonors ? ring.n++ : static_cast<int>(Below(ring.rng, kDonors));
    std::memcpy(ring.text[slot], data + a, static_cast<std::size_t>(len));
    ring.len[slot] = static_cast<std::uint16_t>(len);
    ring.kind[slot] = p->kind;
    TheStats().donated++;
  }
}

/* ----------------------------------------------------------- shape check */
// What the tokenizer alone can prove: quoted runs closed, brackets matched, the
// statement starts with a clause keyword, no clause dangling, and no two
// operands in a row (AQL puts an operator token between them). It is NOT the
// grammar — a harness that can build the engine's Parser installs that with
// SetParseCheck and the report then names it.
SM_FN bool ShapeCheck(char const* data, std::size_t len, void* /*user*/) {
  Tokenize(g_shape_lex, reinterpret_cast<const std::uint8_t*>(data), len);
  const Lex& L = g_shape_lex;
  if (L.ntok < 2) {
    return false;
  }
  auto operand = [](const Tok* t) {
    return t->kind == T_IDENT || t->kind == T_QIDENT ||
           t->kind == T_NUMBER || t->kind == T_STRING || t->kind == T_PARAM;
  };
  for (int k = 0; k < L.ntok; ++k) {
    const Tok* t = &L.tok[k];
    if (t->kind == T_BAD) {
      return false;
    }
    if ((t->kind == T_OPEN || t->kind == T_CLOSE) && t->match < 0) {
      return false;
    }
    if (k + 1 < L.ntok) {
      const Tok* b = &L.tok[k + 1];
      if (operand(t) && operand(b)) {
        return false;
      }
      // "][": indexing an index result is legal; ")(", "}{", "}x" are not.
      if (t->kind == T_CLOSE &&
          (b->kind == T_OPEN || operand(b)) &&
          !(L.s[t->off] == ']' && b->kind == T_OPEN && L.s[b->off] == '[')) {
        return false;
      }
    }
  }
  const Tok* first = &L.tok[0];
  bool starts = false;
  if (first->kind == T_KEYWORD && first->kw >= 0 &&
      first->kwclass == KW_CLAUSE) {
    for (const char* w : {"with", "for", "let", "return", "insert", "update",
                          "replace", "remove", "upsert"}) {
      auto it = KeywordIndex().find(w);
      if (it != KeywordIndex().end() && it->second == first->kw) {
        starts = true;
      }
    }
  }
  if (!starts) {
    return false;
  }
  const Tok* last = &L.tok[L.ntok - 1];
  if (last->kind == T_OP || last->kind == T_DOT || last->kind == T_COMMA ||
      last->kind == T_SCOPE || last->kind == T_OPEN) {
    return false;
  }
  for (int k = 0; k < L.ntok; ++k) {
    const Tok* t = &L.tok[k];
    if (t->kind != T_KEYWORD || t->kwclass != KW_CLAUSE) {
      continue;
    }
    const Tok* next = k + 1 < L.ntok ? &L.tok[k + 1] : nullptr;
    if (next == nullptr || next->kind == T_CLOSE || next->kind == T_COMMA ||
        next->kind == T_OP) {
      return false;
    }
  }
  return true;
}

/* ------------------------------------------------------------- self-test */
inline constexpr const char* kBuiltin[] = {
    "FOR doc IN collection RETURN doc",
    "FOR doc IN collection FILTER doc.a == 1 RETURN doc._key",
    "FOR u IN users FILTER u.age > 30 SORT u.name DESC LIMIT 10 RETURN "
    "{name: u.name, age: u.age}",
    "FOR d IN col COLLECT WITH COUNT INTO n RETURN n",
    "FOR v, e, p IN 1..3 OUTBOUND @start GRAPH 'g' RETURN p.vertices",
    "FOR v IN 1..3 INBOUND startVertex edges RETURN v",
    "INSERT {a: 1} INTO col RETURN NEW",
    "UPDATE {_key: 'x'} WITH {b: 2} IN col RETURN NEW",
    "REPLACE {_key: 'x', c: 3} IN col RETURN NEW",
    "UPSERT {_key: 'x'} INSERT {_key: 'x', n: 0} UPDATE {n: OLD.n + 1} IN col "
    "RETURN NEW",
    "REMOVE {_key: 'x'} IN col",
    "RETURN LENGTH([1,2,3]) + CONCAT('a', 'b')",
    "LET x = (FOR i IN 1..10 RETURN i) RETURN SUM(x)",
    "FOR doc IN col FILTER doc.a IN [1, 2, 3] AND doc.b != null RETURN "
    "doc._key",
    "FOR doc IN col FILTER doc.name LIKE 'a%' OR doc.name NOT LIKE 'b%' "
    "RETURN doc",
    "FOR doc IN col LIMIT 5, 10 RETURN DISTINCT doc.type",
    "FOR doc IN col COLLECT age = doc.age INTO g RETURN {age, total: "
    "LENGTH(g)}",
    "WITH users FOR u IN users RETURN u",
    "FOR doc IN col FILTER doc.x > 1 COLLECT AGGREGATE total = SUM(doc.x) "
    "RETURN total",
    "RETURN {a: [1,2,3], b: {c: true}, d: null}",
    "RETURN 1 == 1 && 2 > 1 || NOT false",
    "FOR a IN 1..3 FOR b IN 1..3 RETURN [a, b]",
    "RETURN (FOR d IN col SORT d.x RETURN d)[0]",
    "FOR doc IN col WINDOW { preceding: 1, following: 1 } AGGREGATE s = "
    "SUM(doc.x) RETURN s",
};

SM_FN void Show(const char* label, const std::uint8_t* p, std::size_t n) {
  std::fprintf(stderr, "  %s ", label);
  for (std::size_t i = 0; i < n && i < 200; ++i) {
    std::fputc(p[i] == '\n'                    ? ' '
               : (p[i] < 0x20 || p[i] >= 0x7f) ? '?'
                                               : p[i],
               stderr);
  }
  std::fprintf(stderr, "%s\n", n > 200 ? " ..." : "");
}

SM_ENTRY int SelfTest() {
  constexpr std::size_t kMaxSize = 512;
  int calls = 16384;
  if (const char* env = std::getenv("AQLMUT_SELFTEST_CALLS")) {
    const int v = std::atoi(env);
    if (v > 0) {
      calls = v;
    }
  }
  g_selftesting = true;
  g_enabled = true;
  LoadPools();
  if (g_parse == &ShapeCheck) {
    std::fprintf(stderr,
                 "aqlmut: no parser oracle installed -- the rate below is the "
                 "token-level shape check, NOT the grammar (see SetParseCheck)\n");
  }
  std::vector<std::vector<std::uint8_t>> samples;
  for (const char* s : kBuiltin) {
    samples.emplace_back(s, s + std::strlen(s));
  }
  std::size_t corpus = 0;
  if (const char* dir = std::getenv("AQLMUT_CORPUS")) {
    std::error_code ec;
    for (auto& e : std::filesystem::directory_iterator(dir, ec)) {
      if (ec || corpus >= 512) {
        break;
      }
      if (!e.is_regular_file()) {
        continue;
      }
      std::ifstream in(e.path(), std::ios::binary);
      std::string text((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
      if (text.empty() || text.size() > kMaxSize) {
        continue;
      }
      samples.emplace_back(text.begin(), text.end());
      ++corpus;
    }
  }
  std::fprintf(stderr, "aqlmut: self-test: %zu built-in + %zu corpus samples\n",
               std::size(kBuiltin), corpus);
  if (samples.empty()) {
    return 1;
  }
  for (const auto& s : samples) {
    Donate(s.data(), s.size());
  }
  std::uint8_t buf[kMaxSize];
  int shown = 0;
  for (int c = 0; c < calls; ++c) {
    const auto& s = samples[static_cast<std::size_t>(c) % samples.size()];
    const std::size_t len = s.size() < kMaxSize ? s.size() : kMaxSize;
    std::memcpy(buf, s.data(), len);
    const auto out = Mutate(buf, len, kMaxSize, static_cast<unsigned>(c) + 1);
    if (shown < 10 && c % 97 == 0 &&
        (out != len || std::memcmp(buf, s.data(), len) != 0)) {
      Show("before", s.data(), len);
      Show(" after", buf, out);
      ++shown;
    }
  }
  Report("self-test");
  auto& S = TheStats();
  std::fprintf(stderr, "  %-10s %10s %10s %8s\n", "operator", "applied",
               "in result", "parsed");
  bool ok = true;
  for (int k = 0; k < SM_NOPS; ++k) {
    std::fprintf(stderr, "  %-10s %10llu %10llu %7.1f%%\n", kOpName[k],
                 static_cast<unsigned long long>(S.applied[k]),
                 static_cast<unsigned long long>(S.in_result[k]),
                 S.in_result[k] ? 100.0 * static_cast<double>(S.in_valid[k]) /
                                      static_cast<double>(S.in_result[k])
                                : 0.0);
    if (S.applied[k] == 0) {
      std::fprintf(stderr, "  FAIL: operator %s was never applied\n",
                   kOpName[k]);
      ok = false;
    }
  }
  if (S.bytes == 0) {
    std::fprintf(stderr, "  FAIL: the byte fallback was never chosen\n");
    ok = false;
  }
  const double rate = S.structured ? 100.0 * static_cast<double>(S.valid) /
                                         static_cast<double>(S.structured)
                                   : 0.0;
  if (rate < 50.0) {
    std::fprintf(stderr, "  FAIL: parse-valid %.1f%% is under 50%%\n", rate);
    ok = false;
  }
  std::fprintf(stderr, "aqlmut: self-test: %s (parse-valid %.1f%% of %llu)\n",
               ok ? "PASS" : "FAIL", rate,
               static_cast<unsigned long long>(S.structured));
  std::fflush(stderr);
  return ok ? 0 : 1;
}

/*
 * From a target's init. AQLMUT_SELFTEST runs the self-test and exits with its
 * verdict; AQLMUT turns the mutator on for a target whose input is AQL text.
 * Silent and idle otherwise, so a target that does not read AQL is unaffected.
 */
SM_ENTRY void Init() {
  if (std::getenv("AQLMUT_SELFTEST") != nullptr) {
    const int rc = SelfTest();
    std::fflush(stderr);
    std::_Exit(rc);
  }
  g_enabled = std::getenv("AQLMUT") != nullptr;
  if (!g_enabled) {
    return;
  }
  (void)Keywords();
  LoadPools();
  std::atexit(ReportAtExit);
  std::fprintf(stderr,
               "aqlmut: on -- structure-aware AQL mutation, one call in ten to "
               "libFuzzer's (AQLMUT)\n");
}

}  // namespace arangodb::fuzz::aqlmut
