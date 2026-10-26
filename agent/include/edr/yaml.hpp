// A deliberately small YAML subset parser for rule, scoring and agent config files.
//
// Supported: block mappings and sequences (indentation with spaces), "- key: value" items,
// single-line flow sequences of scalars ([a, 'b', 3]), plain / 'single' / "double" quoted
// scalars, comments, and one optional leading "---". Plain scalars resolve to null, bool,
// integer or float the way PyYAML does for the forms we accept; forms where PyYAML's YAML 1.1
// rules would surprise (yes/no/on/off, 0x10, 012, 1:30, dates, .5, .inf) are rejected with a
// "quote this value" error instead of being guessed. Anchors, aliases, tags, flow mappings and
// block scalars (| and >) are rejected too.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <variant>

#include "edr/json.hpp"

namespace edr::yaml {

struct ParseError {
  std::size_t line = 0;  // 1-based
  std::string message;
};

std::variant<json::Value, ParseError> parse(std::string_view text);

}  // namespace edr::yaml
