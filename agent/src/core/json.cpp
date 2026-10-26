#include "edr/json.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <string>
#include <string_view>
#include <system_error>

namespace edr::json {

const Value* Value::find(std::string_view key) const {
  if (!is_object()) {
    return nullptr;
  }
  for (const auto& [k, v] : as_object()) {
    if (k == key) {
      return &v;
    }
  }
  return nullptr;
}

void Value::set(std::string key, Value value) {
  if (!is_object()) {
    data_ = Object{};
  }
  for (auto& [k, v] : as_object()) {
    if (k == key) {
      v = std::move(value);
      return;
    }
  }
  as_object().emplace_back(std::move(key), std::move(value));
}

namespace {

constexpr int kMaxDepth = 64;

class Parser {
 public:
  explicit Parser(std::string_view text) : text_(text) {}

  std::variant<Value, ParseError> run() {
    skip_ws();
    Value v;
    if (!parse_value(v, 0)) {
      return error_;
    }
    skip_ws();
    if (pos_ != text_.size()) {
      return ParseError{pos_, "unexpected trailing characters"};
    }
    return v;
  }

 private:
  bool fail(std::string message) {
    if (error_.message.empty()) {
      error_ = ParseError{pos_, std::move(message)};
    }
    return false;
  }

  void skip_ws() {
    while (pos_ < text_.size() && (text_[pos_] == ' ' || text_[pos_] == '\t' ||
                                   text_[pos_] == '\n' || text_[pos_] == '\r')) {
      ++pos_;
    }
  }

  bool literal(std::string_view word) {
    if (text_.substr(pos_, word.size()) == word) {
      pos_ += word.size();
      return true;
    }
    return false;
  }

  bool parse_value(Value& out, int depth) {
    if (depth > kMaxDepth) {
      return fail("nesting too deep");
    }
    if (pos_ >= text_.size()) {
      return fail("unexpected end of input");
    }
    const char c = text_[pos_];
    if (c == '{') {
      return parse_object(out, depth);
    }
    if (c == '[') {
      return parse_array(out, depth);
    }
    if (c == '"') {
      std::string s;
      if (!parse_string(s)) {
        return false;
      }
      out = Value(std::move(s));
      return true;
    }
    if (literal("true")) {
      out = Value(true);
      return true;
    }
    if (literal("false")) {
      out = Value(false);
      return true;
    }
    if (literal("null")) {
      out = Value(nullptr);
      return true;
    }
    return parse_number(out);
  }

  bool parse_object(Value& out, int depth) {
    ++pos_;  // {
    Object obj;
    skip_ws();
    if (pos_ < text_.size() && text_[pos_] == '}') {
      ++pos_;
      out = Value(std::move(obj));
      return true;
    }
    while (true) {
      skip_ws();
      if (pos_ >= text_.size() || text_[pos_] != '"') {
        return fail("expected object key");
      }
      std::string key;
      if (!parse_string(key)) {
        return false;
      }
      skip_ws();
      if (pos_ >= text_.size() || text_[pos_] != ':') {
        return fail("expected ':'");
      }
      ++pos_;
      skip_ws();
      Value v;
      if (!parse_value(v, depth + 1)) {
        return false;
      }
      auto existing = std::find_if(obj.begin(), obj.end(),
                                   [&](const auto& entry) { return entry.first == key; });
      if (existing != obj.end()) {
        existing->second = std::move(v);
      } else {
        obj.emplace_back(std::move(key), std::move(v));
      }
      skip_ws();
      if (pos_ < text_.size() && text_[pos_] == ',') {
        ++pos_;
        continue;
      }
      if (pos_ < text_.size() && text_[pos_] == '}') {
        ++pos_;
        out = Value(std::move(obj));
        return true;
      }
      return fail("expected ',' or '}'");
    }
  }

  bool parse_array(Value& out, int depth) {
    ++pos_;  // [
    Array arr;
    skip_ws();
    if (pos_ < text_.size() && text_[pos_] == ']') {
      ++pos_;
      out = Value(std::move(arr));
      return true;
    }
    while (true) {
      skip_ws();
      Value v;
      if (!parse_value(v, depth + 1)) {
        return false;
      }
      arr.push_back(std::move(v));
      skip_ws();
      if (pos_ < text_.size() && text_[pos_] == ',') {
        ++pos_;
        continue;
      }
      if (pos_ < text_.size() && text_[pos_] == ']') {
        ++pos_;
        out = Value(std::move(arr));
        return true;
      }
      return fail("expected ',' or ']'");
    }
  }

  bool hex4(std::uint32_t& out) {
    if (pos_ + 4 > text_.size()) {
      return fail("truncated \\u escape");
    }
    out = 0;
    for (int i = 0; i < 4; ++i) {
      const char c = text_[pos_++];
      out <<= 4U;
      if (c >= '0' && c <= '9') {
        out |= static_cast<std::uint32_t>(c - '0');
      } else if (c >= 'a' && c <= 'f') {
        out |= static_cast<std::uint32_t>(c - 'a' + 10);
      } else if (c >= 'A' && c <= 'F') {
        out |= static_cast<std::uint32_t>(c - 'A' + 10);
      } else {
        return fail("bad hex digit in \\u escape");
      }
    }
    return true;
  }

  static void append_utf8(std::string& s, std::uint32_t cp) {
    if (cp < 0x80) {
      s += static_cast<char>(cp);
    } else if (cp < 0x800) {
      s += static_cast<char>(0xC0U | (cp >> 6U));
      s += static_cast<char>(0x80U | (cp & 0x3FU));
    } else if (cp < 0x10000) {
      s += static_cast<char>(0xE0U | (cp >> 12U));
      s += static_cast<char>(0x80U | ((cp >> 6U) & 0x3FU));
      s += static_cast<char>(0x80U | (cp & 0x3FU));
    } else {
      s += static_cast<char>(0xF0U | (cp >> 18U));
      s += static_cast<char>(0x80U | ((cp >> 12U) & 0x3FU));
      s += static_cast<char>(0x80U | ((cp >> 6U) & 0x3FU));
      s += static_cast<char>(0x80U | (cp & 0x3FU));
    }
  }

  bool parse_string(std::string& out) {
    ++pos_;  // opening quote
    while (pos_ < text_.size()) {
      const char c = text_[pos_++];
      if (c == '"') {
        return true;
      }
      if (static_cast<unsigned char>(c) < 0x20) {
        return fail("control character in string");
      }
      if (c != '\\') {
        out += c;
        continue;
      }
      if (pos_ >= text_.size()) {
        break;
      }
      const char e = text_[pos_++];
      switch (e) {
        case '"':
          out += '"';
          break;
        case '\\':
          out += '\\';
          break;
        case '/':
          out += '/';
          break;
        case 'b':
          out += '\b';
          break;
        case 'f':
          out += '\f';
          break;
        case 'n':
          out += '\n';
          break;
        case 'r':
          out += '\r';
          break;
        case 't':
          out += '\t';
          break;
        case 'u': {
          std::uint32_t cp = 0;
          if (!hex4(cp)) {
            return false;
          }
          if (cp >= 0xD800 && cp <= 0xDBFF) {
            std::uint32_t lo = 0;
            if (text_.substr(pos_, 2) != "\\u") {
              return fail("unpaired surrogate in string");
            }
            pos_ += 2;
            if (!hex4(lo)) {
              return false;
            }
            if (lo < 0xDC00 || lo > 0xDFFF) {
              return fail("unpaired surrogate in string");
            }
            cp = 0x10000 + ((cp - 0xD800) << 10U) + (lo - 0xDC00);
          } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            return fail("unpaired surrogate in string");
          }
          append_utf8(out, cp);
          break;
        }
        default:
          return fail("bad escape in string");
      }
    }
    return fail("unterminated string");
  }

  bool parse_number(Value& out) {
    const std::size_t start = pos_;
    if (pos_ < text_.size() && text_[pos_] == '-') {
      ++pos_;
    }
    auto digits = [&] {
      const std::size_t s = pos_;
      while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
        ++pos_;
      }
      return pos_ - s;
    };
    const std::size_t int_start = pos_;
    if (digits() == 0) {
      return fail("invalid value");
    }
    if (text_[int_start] == '0' && pos_ - int_start > 1) {
      return fail("leading zero in number");
    }
    bool is_float = false;
    if (pos_ < text_.size() && text_[pos_] == '.') {
      ++pos_;
      is_float = true;
      if (digits() == 0) {
        return fail("digit expected after '.'");
      }
    }
    if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
      ++pos_;
      is_float = true;
      if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) {
        ++pos_;
      }
      if (digits() == 0) {
        return fail("digit expected in exponent");
      }
    }
    const std::string_view num = text_.substr(start, pos_ - start);
    if (!is_float) {
      std::int64_t i = 0;
      const auto res = std::from_chars(num.data(), num.data() + num.size(), i);
      if (res.ec == std::errc() && res.ptr == num.data() + num.size()) {
        out = Value(i);
        return true;
      }
    }
    // strtod needs a NUL-terminated buffer; numbers are short.
    const std::string buf(num);
    char* end = nullptr;
    const double d = std::strtod(buf.c_str(), &end);
    if (end != buf.c_str() + buf.size() || !std::isfinite(d)) {
      return fail("number out of range");
    }
    out = Value(d);
    return true;
  }

  std::string_view text_;
  std::size_t pos_ = 0;
  ParseError error_;
};

void dump_to(const Value& v, std::string& out) {
  switch (v.kind()) {
    case Value::Kind::Null:
      out += "null";
      return;
    case Value::Kind::Bool:
      out += v.as_bool() ? "true" : "false";
      return;
    case Value::Kind::Int:
      out += std::to_string(v.as_int());
      return;
    case Value::Kind::Double: {
      std::array<char, 32> buf{};
      const auto res = std::to_chars(buf.data(), buf.data() + buf.size(), v.as_double());
      out.append(buf.data(), res.ptr);
      return;
    }
    case Value::Kind::String:
      out += quote(v.as_string());
      return;
    case Value::Kind::Array: {
      out += '[';
      bool first = true;
      for (const auto& item : v.as_array()) {
        if (!first) {
          out += ',';
        }
        first = false;
        dump_to(item, out);
      }
      out += ']';
      return;
    }
    case Value::Kind::Object: {
      out += '{';
      bool first = true;
      for (const auto& [k, item] : v.as_object()) {
        if (!first) {
          out += ',';
        }
        first = false;
        out += quote(k);
        out += ':';
        dump_to(item, out);
      }
      out += '}';
      return;
    }
  }
}

}  // namespace

std::variant<Value, ParseError> parse(std::string_view text) {
  return Parser(text).run();
}

std::string quote(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 2);
  out += '"';
  for (const char c : text) {
    const auto u = static_cast<unsigned char>(c);
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (u < 0x20) {
          constexpr std::string_view kHex = "0123456789abcdef";
          out += "\\u00";
          out += kHex[u >> 4U];
          out += kHex[u & 0xFU];
        } else {
          out += c;
        }
    }
  }
  out += '"';
  return out;
}

std::string dump(const Value& value) {
  std::string out;
  dump_to(value, out);
  return out;
}

}  // namespace edr::json
