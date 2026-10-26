// Text helpers shared by the engine. Behaviour matches server/src/edr_server/engine/textutil.py.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace edr {

// Lower-cases A-Z only (no locale, no Unicode folding).
std::string ascii_lower(std::string_view text);
// File name after the last '\' or '/'.
std::string_view basename(std::string_view path);
// ascii_lower(basename(path)).
std::string image_name(std::string_view path);

bool starts_with(std::string_view s, std::string_view prefix);
bool ends_with(std::string_view s, std::string_view suffix);

// "YYYY-MM-DDTHH:MM:SS[.fff…][Z]" (a space instead of T is accepted) to ms since the epoch.
std::optional<std::int64_t> parse_ts(std::string_view text);
// ms since the epoch to "YYYY-MM-DDTHH:MM:SS.mmmZ".
std::string format_ts(std::int64_t ms);

// FNV-1a 64-bit of the bytes, as 16 lower-case hex digits.
std::string fnv1a64(std::string_view text);

// Decimal with leading zeros to at least `width` digits; lower-case hex likewise.
std::string zero_pad(std::int64_t value, int width);
std::string to_hex(std::uint64_t value, int width);

// Strict decimal integer (optional '-', at most 18 digits).
std::optional<std::int64_t> parse_int(std::string_view text);

std::vector<std::string> split(std::string_view text, char sep);

}  // namespace edr
