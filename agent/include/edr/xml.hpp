// Minimal, defensive XML reader for rendered Windows event XML (EvtRender / wevtutil output).
// Supports elements, attributes, text, CDATA, comments, processing instructions and the five
// predefined entities plus numeric character references. DOCTYPE and entity declarations are
// rejected (no external entities, no entity expansion). Input size and depth are capped.
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace edr::xml {

inline constexpr std::size_t kMaxDocumentBytes = std::size_t{64} * 1024 * 1024;
inline constexpr int kMaxDepth = 64;

struct Element {
  std::string name;  // qualified name as written, e.g. "Data" or "ns:Data"
  std::vector<std::pair<std::string, std::string>> attributes;
  std::vector<Element> children;
  std::string text;  // concatenated character data directly inside this element

  [[nodiscard]] const Element* child(std::string_view child_name) const;
  [[nodiscard]] std::optional<std::string_view> attribute(std::string_view attr_name) const;
};

struct ParseError {
  std::size_t offset = 0;
  std::string message;
};

// Parses a document or a fragment: the result is a synthetic root element named "#document"
// whose children are the top-level elements (wevtutil prints <Event> elements back to back).
std::variant<Element, ParseError> parse(std::string_view text);

}  // namespace edr::xml
