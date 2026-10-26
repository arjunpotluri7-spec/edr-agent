#include "edr/condition.hpp"

#include <algorithm>
#include <regex>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "edr/netutil.hpp"
#include "edr/textutil.hpp"

namespace edr {
namespace {

// Cuts at a UTF-8 character boundary at or below max bytes, like Python's
// encode()[:max].decode(errors="ignore") does for valid UTF-8.
std::string_view utf8_prefix(std::string_view s, std::size_t max) {
  if (s.size() <= max) {
    return s;
  }
  std::size_t cut = max;
  while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0U) == 0x80U) {
    --cut;
  }
  return s.substr(0, cut);
}

bool match_one(const Leaf& leaf, const std::string& text) {
  switch (leaf.op) {
    case Op::Equals:
    case Op::Contains:
    case Op::StartsWith:
    case Op::EndsWith: {
      const std::string subject = leaf.case_sensitive ? text : ascii_lower(text);
      return std::any_of(leaf.strings.begin(), leaf.strings.end(), [&](const std::string& v) {
        switch (leaf.op) {
          case Op::Equals:
            return subject == v;
          case Op::Contains:
            return subject.find(v) != std::string::npos;
          case Op::StartsWith:
            return starts_with(subject, v);
          default:
            return ends_with(subject, v);
        }
      });
    }
    case Op::Regex: {
      const std::string_view data = utf8_prefix(text, kMaxRegexInput);
      return std::regex_search(data.begin(), data.end(), *leaf.regex);
    }
    case Op::Gt:
    case Op::Gte:
    case Op::Lt:
    case Op::Lte: {
      const auto n = parse_int(text);
      if (!n) {
        return false;
      }
      if (leaf.op == Op::Gt) {
        return *n > leaf.number;
      }
      if (leaf.op == Op::Gte) {
        return *n >= leaf.number;
      }
      if (leaf.op == Op::Lt) {
        return *n < leaf.number;
      }
      return *n <= leaf.number;
    }
    case Op::Cidr: {
      const auto ip = parse_ip(text);
      return ip && ip_in_any(*ip, leaf.cidrs) != nullptr;
    }
    case Op::MinLabelLength:
      return static_cast<std::int64_t>(longest_label(text).size()) >= leaf.number;
    case Op::MinLabelEntropy:
      return shannon_entropy(longest_label(text)) >= leaf.real;
    case Op::Exists:
      return true;  // handled by the caller
  }
  return false;
}

}  // namespace

bool evaluate(const Condition& condition, const Event& event) {
  switch (condition.kind) {
    case Condition::Kind::All:
      return std::all_of(condition.children.begin(), condition.children.end(),
                         [&](const Condition& c) { return evaluate(c, event); });
    case Condition::Kind::Any:
      return std::any_of(condition.children.begin(), condition.children.end(),
                         [&](const Condition& c) { return evaluate(c, event); });
    case Condition::Kind::Not:
      return !evaluate(condition.children.front(), event);
    case Condition::Kind::Leaf:
      break;
  }
  const Leaf& leaf = condition.leaf;
  const FieldValue value = get_field(event, leaf.field);
  const bool present = !std::holds_alternative<std::monostate>(value);
  if (leaf.op == Op::Exists) {
    return present == leaf.flag;
  }
  if (const auto* s = std::get_if<std::string>(&value)) {
    return match_one(leaf, *s);
  }
  if (const auto* list = std::get_if<std::vector<std::string>>(&value)) {
    return std::any_of(list->begin(), list->end(),
                       [&](const std::string& s) { return match_one(leaf, s); });
  }
  return false;
}

}  // namespace edr
