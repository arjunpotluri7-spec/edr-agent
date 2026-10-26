#include "edr/yaml.hpp"

#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace edr::yaml {
namespace {

using json::Value;

struct Line {
  std::size_t number = 0;  // 1-based
  std::size_t indent = 0;
  std::string text;  // content after indentation, comment stripped, right-trimmed
};

class Error : public std::exception {
 public:
  Error(std::size_t line, std::string message) : error_{line, std::move(message)} {}
  [[nodiscard]] const ParseError& get() const { return error_; }
  [[nodiscard]] const char* what() const noexcept override { return error_.message.c_str(); }

 private:
  ParseError error_;
};

std::string rtrim(std::string_view s) {
  std::size_t end = s.size();
  while (end > 0 && (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r')) {
    --end;
  }
  return std::string(s.substr(0, end));
}

std::string_view trim(std::string_view s) {
  std::size_t b = 0;
  while (b < s.size() && s[b] == ' ') {
    ++b;
  }
  std::size_t e = s.size();
  while (e > b && s[e - 1] == ' ') {
    --e;
  }
  return s.substr(b, e - b);
}

// Removes a trailing comment (a '#' at the start or after whitespace, outside quotes).
std::string strip_comment(std::string_view s) {
  char quote = 0;
  for (std::size_t i = 0; i < s.size(); ++i) {
    const char c = s[i];
    if (quote != 0) {
      if (c == quote) {
        if (quote == '\'' && i + 1 < s.size() && s[i + 1] == '\'') {
          ++i;  // '' inside single quotes
        } else {
          quote = 0;
        }
      } else if (quote == '"' && c == '\\') {
        ++i;
      }
      continue;
    }
    if ((c == '\'' || c == '"') && (i == 0 || s[i - 1] == ' ' || s[i - 1] == '[' ||
                                    s[i - 1] == ',' || s[i - 1] == '-' || s[i - 1] == ':')) {
      quote = c;
    } else if (c == '#' && (i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t')) {
      return rtrim(s.substr(0, i));
    }
  }
  return rtrim(s);
}

std::vector<Line> split_lines(std::string_view text) {
  std::vector<Line> lines;
  std::size_t number = 0;
  std::size_t pos = 0;
  while (pos <= text.size()) {
    std::size_t nl = text.find('\n', pos);
    if (nl == std::string_view::npos) {
      nl = text.size();
    }
    std::string_view raw = text.substr(pos, nl - pos);
    ++number;
    pos = nl + 1;
    std::size_t indent = 0;
    while (indent < raw.size() && raw[indent] == ' ') {
      ++indent;
    }
    if (indent < raw.size() && raw[indent] == '\t') {
      throw Error(number, "tab characters are not allowed for indentation");
    }
    std::string content = strip_comment(raw.substr(indent));
    if (content.empty()) {
      continue;
    }
    if (number == 1 && content.size() >= 3 && content.substr(0, 3) == "\xEF\xBB\xBF") {
      content = content.substr(3);
    }
    lines.push_back(Line{number, indent, content});
    if (nl == text.size()) {
      break;
    }
  }
  return lines;
}

bool is_digits(std::string_view s) {
  if (s.empty()) {
    return false;
  }
  for (const char c : s) {
    if (c < '0' || c > '9') {
      return false;
    }
  }
  return true;
}

std::string lower(std::string_view s) {
  std::string out(s);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  return out;
}

Value resolve_plain(std::string_view s, std::size_t line) {
  if (s.empty() || s == "~" || s == "null" || s == "Null" || s == "NULL") {
    return Value(nullptr);
  }
  if (s == "true" || s == "True" || s == "TRUE") {
    return Value(true);
  }
  if (s == "false" || s == "False" || s == "FALSE") {
    return Value(false);
  }
  const std::string low = lower(s);
  if (low == "yes" || low == "no" || low == "on" || low == "off" || low == "y" || low == "n") {
    throw Error(line, "ambiguous value '" + std::string(s) + "': quote it or use true/false");
  }
  const char first = s.front();
  if (first == '&' || first == '*' || first == '!' || first == '|' || first == '>' ||
      first == '{' || first == '@' || first == '`' || first == '%') {
    throw Error(line, "unsupported YAML syntax '" + std::string(1, first) +
                          "' (anchors, tags, flow mappings and block scalars are not supported)");
  }
  std::string_view body = s;
  if (first == '-' || first == '+') {
    body = s.substr(1);
  }
  if (is_digits(body)) {
    if (body.size() > 1 && body.front() == '0') {
      throw Error(line, "number with a leading zero '" + std::string(s) + "': quote it");
    }
    std::int64_t v = 0;
    const auto res = std::from_chars(s.data() + (first == '+' ? 1 : 0), s.data() + s.size(), v);
    if (res.ec != std::errc()) {
      throw Error(line, "integer out of range: " + std::string(s));
    }
    return Value(v);
  }
  static const std::regex kFloat(R"([-+]?[0-9]+\.[0-9]+)");
  static const std::regex kSurprising(
      R"(([-+]?0[xob].*)|([-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9_]*)?)|([-+]?\.[0-9].*)|)"
      R"(([-+]?\.(inf|Inf|INF|nan|NaN|NAN))|([0-9]{4}-[0-9]{1,2}-[0-9]{1,2}.*)|([-+]?[0-9][0-9_]*_[0-9_]*)|)"
      R"(([-+]?[0-9]+\.)|([-+]?[0-9]+\.[0-9]*[eE][-+]?[0-9]+))");
  const std::string str(s);
  if (std::regex_match(str, kFloat)) {
    return Value(std::strtod(str.c_str(), nullptr));
  }
  if (std::regex_match(str, kSurprising)) {
    throw Error(line, "value '" + str + "' is read differently by YAML 1.1 parsers: quote it");
  }
  return Value(str);
}

// Parses a scalar that starts at text[pos]; advances pos past it. stop_chars end a plain scalar
// (used inside flow sequences).
Value parse_scalar(std::string_view text, std::size_t& pos, std::size_t line,
                   std::string_view stop_chars) {
  if (pos < text.size() && text[pos] == '\'') {
    std::string out;
    ++pos;
    while (pos < text.size()) {
      if (text[pos] == '\'') {
        if (pos + 1 < text.size() && text[pos + 1] == '\'') {
          out += '\'';
          pos += 2;
          continue;
        }
        ++pos;
        return Value(out);
      }
      out += text[pos++];
    }
    throw Error(line, "unterminated single-quoted string");
  }
  if (pos < text.size() && text[pos] == '"') {
    std::string out;
    ++pos;
    while (pos < text.size()) {
      const char c = text[pos++];
      if (c == '"') {
        return Value(out);
      }
      if (c != '\\') {
        out += c;
        continue;
      }
      if (pos >= text.size()) {
        break;
      }
      const char e = text[pos++];
      switch (e) {
        case '\\':
          out += '\\';
          break;
        case '"':
          out += '"';
          break;
        case 'n':
          out += '\n';
          break;
        case 't':
          out += '\t';
          break;
        case '/':
          out += '/';
          break;
        default:
          throw Error(line, std::string("unsupported escape \\") + e + " in double-quoted string");
      }
    }
    throw Error(line, "unterminated double-quoted string");
  }
  const std::size_t start = pos;
  while (pos < text.size() && stop_chars.find(text[pos]) == std::string_view::npos) {
    ++pos;
  }
  return resolve_plain(trim(text.substr(start, pos - start)), line);
}

Value parse_inline_value(std::string_view text, std::size_t line) {
  text = trim(text);
  if (!text.empty() && text.front() == '[') {
    if (text.back() != ']') {
      throw Error(line, "flow sequences must open and close on one line");
    }
    json::Array items;
    std::size_t pos = 1;
    const std::size_t end = text.size() - 1;
    const std::string_view inner = text.substr(0, end);
    while (true) {
      while (pos < end && inner[pos] == ' ') {
        ++pos;
      }
      if (pos >= end) {
        if (!items.empty()) {
          throw Error(line, "trailing comma in flow sequence");
        }
        break;
      }
      if (inner[pos] == '[' || inner[pos] == '{') {
        throw Error(line, "nested flow collections are not supported");
      }
      items.push_back(parse_scalar(inner, pos, line, ",]"));
      while (pos < end && inner[pos] == ' ') {
        ++pos;
      }
      if (pos >= end) {
        break;
      }
      if (inner[pos] != ',') {
        throw Error(line, "expected ',' in flow sequence");
      }
      ++pos;
    }
    return Value(std::move(items));
  }
  std::size_t pos = 0;
  Value v = parse_scalar(text, pos, line, "");
  if (!trim(text.substr(pos)).empty()) {
    throw Error(line, "unexpected text after quoted value");
  }
  return v;
}

// Finds "key: value" / "key:" at the top level of a line. Returns the colon position.
std::optional<std::size_t> find_key_colon(std::string_view s) {
  if (s.empty()) {
    return std::nullopt;
  }
  if (s.front() == '\'' || s.front() == '"') {
    const char q = s.front();
    std::size_t i = 1;
    while (i < s.size()) {
      if (s[i] == q) {
        if (q == '\'' && i + 1 < s.size() && s[i + 1] == '\'') {
          i += 2;
          continue;
        }
        break;
      }
      if (q == '"' && s[i] == '\\') {
        ++i;
      }
      ++i;
    }
    if (i + 1 < s.size() && s[i + 1] == ':' && (i + 2 == s.size() || s[i + 2] == ' ')) {
      return i + 1;
    }
    return std::nullopt;
  }
  if (s.front() == '[') {
    return std::nullopt;
  }
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == ':' && (i + 1 == s.size() || s[i + 1] == ' ')) {
      return i;
    }
  }
  return std::nullopt;
}

class Parser {
 public:
  explicit Parser(std::vector<Line> lines) : lines_(std::move(lines)) {}

  Value document() {
    if (idx_ < lines_.size() && lines_[idx_].text == "---" && lines_[idx_].indent == 0) {
      ++idx_;
    }
    if (idx_ >= lines_.size()) {
      return Value(nullptr);
    }
    Value v = block(lines_[idx_].indent, 0);
    if (idx_ < lines_.size()) {
      const Line& l = lines_[idx_];
      if (l.text == "---" || l.text == "...") {
        throw Error(l.number, "multiple YAML documents are not supported");
      }
      throw Error(l.number, "unexpected indentation");
    }
    return v;
  }

 private:
  Value block(std::size_t indent, int depth) {
    if (depth > 32) {
      throw Error(lines_[idx_].number, "nesting too deep");
    }
    const Line& first = lines_[idx_];
    if (is_seq_item(first.text)) {
      return sequence(indent, depth);
    }
    if (find_key_colon(first.text)) {
      return mapping(indent, depth);
    }
    // A lone scalar document/value.
    ++idx_;
    return parse_inline_value(first.text, first.number);
  }

  static bool is_seq_item(std::string_view t) {
    return t == "-" || (t.size() >= 2 && t[0] == '-' && t[1] == ' ');
  }

  Value nested_or_null(std::size_t parent_indent, int depth, bool allow_same_indent_seq) {
    if (idx_ < lines_.size()) {
      const Line& next = lines_[idx_];
      if (next.indent > parent_indent ||
          (allow_same_indent_seq && next.indent == parent_indent && is_seq_item(next.text))) {
        return block(next.indent, depth + 1);
      }
    }
    return Value(nullptr);
  }

  Value mapping(std::size_t indent, int depth) {
    json::Object obj;
    while (idx_ < lines_.size()) {
      const Line& l = lines_[idx_];
      if (l.indent < indent) {
        break;
      }
      if (l.indent > indent) {
        throw Error(l.number, "unexpected indentation");
      }
      if (is_seq_item(l.text)) {
        break;  // sequence at the same indent belongs to an outer key
      }
      if (l.indent == 0 && (l.text == "---" || l.text == "...")) {
        break;  // document marker: reported by document()
      }
      const auto colon = find_key_colon(l.text);
      if (!colon) {
        throw Error(l.number, "expected 'key: value'");
      }
      std::size_t kpos = 0;
      const std::string_view key_text = trim(std::string_view(l.text).substr(0, *colon));
      Value key = parse_scalar(key_text, kpos, l.number, "");
      if (!key.is_string() || key.as_string().empty()) {
        throw Error(l.number, "mapping keys must be non-empty strings");
      }
      for (const auto& [k, v] : obj) {
        if (k == key.as_string()) {
          throw Error(l.number, "duplicate key '" + k + "'");
        }
      }
      const std::string_view rest = trim(std::string_view(l.text).substr(*colon + 1));
      const std::size_t line_no = l.number;
      ++idx_;
      Value value;
      if (rest.empty()) {
        value = nested_or_null(indent, depth, true);
      } else {
        value = parse_inline_value(rest, line_no);
      }
      obj.emplace_back(key.as_string(), std::move(value));
    }
    return Value(std::move(obj));
  }

  Value sequence(std::size_t indent, int depth) {
    json::Array arr;
    while (idx_ < lines_.size()) {
      Line& l = lines_[idx_];
      if (l.indent < indent) {
        break;
      }
      if (l.indent > indent) {
        throw Error(l.number, "unexpected indentation");
      }
      if (!is_seq_item(l.text)) {
        break;
      }
      if (l.text == "-") {
        ++idx_;
        arr.push_back(nested_or_null(indent, depth, false));
        continue;
      }
      // "- something": rewrite the line in place as the item content, one column deeper,
      // so "- key: value" continues as a mapping with the following aligned lines.
      std::size_t skip = 2;
      while (skip < l.text.size() && l.text[skip] == ' ') {
        ++skip;
      }
      l.indent += skip;
      l.text = l.text.substr(skip);
      if (is_seq_item(l.text) || find_key_colon(l.text)) {
        arr.push_back(block(l.indent, depth + 1));
      } else {
        const std::size_t line_no = l.number;
        const std::string content = l.text;
        ++idx_;
        arr.push_back(parse_inline_value(content, line_no));
      }
    }
    return Value(std::move(arr));
  }

  std::vector<Line> lines_;
  std::size_t idx_ = 0;
};

}  // namespace

std::variant<json::Value, ParseError> parse(std::string_view text) {
  try {
    Parser parser(split_lines(text));
    return parser.document();
  } catch (const Error& e) {
    return e.get();
  } catch (const std::regex_error& e) {
    return ParseError{0, std::string("internal regex error: ") + e.what()};
  }
}

}  // namespace edr::yaml
