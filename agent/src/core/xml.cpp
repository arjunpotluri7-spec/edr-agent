#include "edr/xml.hpp"

#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace edr::xml {

const Element* Element::child(std::string_view child_name) const {
  for (const auto& c : children) {
    if (c.name == child_name) {
      return &c;
    }
  }
  return nullptr;
}

std::optional<std::string_view> Element::attribute(std::string_view attr_name) const {
  for (const auto& [k, v] : attributes) {
    if (k == attr_name) {
      return v;
    }
  }
  return std::nullopt;
}

namespace {

struct Fail : std::exception {
  Fail(std::size_t off, std::string msg) : offset(off), message(std::move(msg)) {}
  [[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
  std::size_t offset;
  std::string message;
};

bool is_name_char(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
         c == ':' || c == '-' || c == '.' || static_cast<unsigned char>(c) >= 0x80;
}

void append_utf8(std::string& s, std::uint32_t cp) {
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

class Reader {
 public:
  explicit Reader(std::string_view text) : text_(text) {}

  Element document() {
    Element root;
    root.name = "#document";
    if (text_.size() >= 3 && text_.substr(0, 3) == "\xEF\xBB\xBF") {
      pos_ = 3;
    }
    while (true) {
      skip_ws();
      if (pos_ >= text_.size()) {
        break;
      }
      if (text_[pos_] != '<') {
        throw Fail(pos_, "text outside of an element");
      }
      if (skip_misc()) {
        continue;
      }
      root.children.push_back(element(1));
    }
    return root;
  }

 private:
  [[noreturn]] void fail(const std::string& message) const { throw Fail(pos_, message); }

  bool at(std::string_view s) const { return text_.substr(pos_, s.size()) == s; }

  void skip_ws() {
    while (pos_ < text_.size() && (text_[pos_] == ' ' || text_[pos_] == '\t' ||
                                   text_[pos_] == '\r' || text_[pos_] == '\n')) {
      ++pos_;
    }
  }

  void skip_past(std::string_view terminator, const char* what) {
    const std::size_t end = text_.find(terminator, pos_);
    if (end == std::string_view::npos) {
      fail(std::string("unterminated ") + what);
    }
    pos_ = end + terminator.size();
  }

  // Comments, processing instructions; DOCTYPE is refused. Returns true if something was skipped.
  bool skip_misc() {
    if (at("<!--")) {
      pos_ += 4;
      skip_past("-->", "comment");
      return true;
    }
    if (at("<?")) {
      pos_ += 2;
      skip_past("?>", "processing instruction");
      return true;
    }
    if (at("<!DOCTYPE") || at("<!ENTITY") || at("<!doctype")) {
      fail("DOCTYPE and entity declarations are not allowed");
    }
    return false;
  }

  std::string name() {
    const std::size_t start = pos_;
    while (pos_ < text_.size() && is_name_char(text_[pos_])) {
      ++pos_;
    }
    if (pos_ == start) {
      fail("expected a name");
    }
    return std::string(text_.substr(start, pos_ - start));
  }

  void entity(std::string& out) {
    // pos_ is just past '&'
    const std::size_t semi = text_.find(';', pos_);
    if (semi == std::string_view::npos || semi - pos_ > 10) {
      fail("bad entity reference");
    }
    const std::string_view ref = text_.substr(pos_, semi - pos_);
    pos_ = semi + 1;
    if (ref == "amp") {
      out += '&';
    } else if (ref == "lt") {
      out += '<';
    } else if (ref == "gt") {
      out += '>';
    } else if (ref == "quot") {
      out += '"';
    } else if (ref == "apos") {
      out += '\'';
    } else if (!ref.empty() && ref[0] == '#') {
      std::uint32_t cp = 0;
      const bool hex = ref.size() > 1 && (ref[1] == 'x' || ref[1] == 'X');
      const std::string_view digits = ref.substr(hex ? 2 : 1);
      if (digits.empty()) {
        fail("bad character reference");
      }
      for (const char c : digits) {
        std::uint32_t d = 0;
        if (c >= '0' && c <= '9') {
          d = static_cast<std::uint32_t>(c - '0');
        } else if (hex && c >= 'a' && c <= 'f') {
          d = static_cast<std::uint32_t>(c - 'a' + 10);
        } else if (hex && c >= 'A' && c <= 'F') {
          d = static_cast<std::uint32_t>(c - 'A' + 10);
        } else {
          fail("bad character reference");
        }
        cp = cp * (hex ? 16U : 10U) + d;
        if (cp > 0x10FFFF) {
          fail("character reference out of range");
        }
      }
      if (cp == 0 || (cp >= 0xD800 && cp <= 0xDFFF)) {
        fail("invalid character reference");
      }
      append_utf8(out, cp);
    } else {
      fail("unknown entity &" + std::string(ref) + ";");
    }
  }

  Element element(int depth) {
    if (depth > kMaxDepth) {
      fail("elements nested too deeply");
    }
    ++pos_;  // '<'
    Element el;
    el.name = name();
    while (true) {
      skip_ws();
      if (pos_ >= text_.size()) {
        fail("unterminated start tag");
      }
      if (at("/>")) {
        pos_ += 2;
        return el;
      }
      if (text_[pos_] == '>') {
        ++pos_;
        break;
      }
      std::string attr = name();
      skip_ws();
      if (pos_ >= text_.size() || text_[pos_] != '=') {
        fail("expected '=' after attribute name");
      }
      ++pos_;
      skip_ws();
      if (pos_ >= text_.size() || (text_[pos_] != '"' && text_[pos_] != '\'')) {
        fail("attribute value must be quoted");
      }
      const char q = text_[pos_++];
      std::string value;
      while (pos_ < text_.size() && text_[pos_] != q) {
        if (text_[pos_] == '<') {
          fail("'<' in attribute value");
        }
        if (text_[pos_] == '&') {
          ++pos_;
          entity(value);
        } else {
          value += text_[pos_++];
        }
      }
      if (pos_ >= text_.size()) {
        fail("unterminated attribute value");
      }
      ++pos_;
      el.attributes.emplace_back(std::move(attr), std::move(value));
    }
    // content
    while (true) {
      if (pos_ >= text_.size()) {
        fail("missing end tag for <" + el.name + ">");
      }
      const char c = text_[pos_];
      if (c == '<') {
        if (at("</")) {
          pos_ += 2;
          const std::string end = name();
          skip_ws();
          if (pos_ >= text_.size() || text_[pos_] != '>') {
            fail("bad end tag");
          }
          ++pos_;
          if (end != el.name) {
            fail("end tag </" + end + "> does not match <" + el.name + ">");
          }
          return el;
        }
        if (at("<![CDATA[")) {
          pos_ += 9;
          const std::size_t end = text_.find("]]>", pos_);
          if (end == std::string_view::npos) {
            fail("unterminated CDATA section");
          }
          el.text.append(text_.substr(pos_, end - pos_));
          pos_ = end + 3;
          continue;
        }
        if (skip_misc()) {
          continue;
        }
        el.children.push_back(element(depth + 1));
        continue;
      }
      if (c == '&') {
        ++pos_;
        entity(el.text);
        continue;
      }
      el.text += c;
      ++pos_;
    }
  }

  std::string_view text_;
  std::size_t pos_ = 0;
};

}  // namespace

std::variant<Element, ParseError> parse(std::string_view text) {
  if (text.size() > kMaxDocumentBytes) {
    return ParseError{0, "document larger than the size limit"};
  }
  try {
    return Reader(text).document();
  } catch (const Fail& f) {
    return ParseError{f.offset, f.message};
  }
}

}  // namespace edr::xml
