// Detects and decodes PowerShell -EncodedCommand payloads (Base64 of UTF-16LE text).
// Mirrors server/src/edr_server/engine/encoded.py exactly.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace edr {

inline constexpr std::size_t kMaxEncodedPayload = 65536;

struct DecodeResult {
  bool found = false;                // an encoded-command flag was present
  std::optional<std::string> text;   // decoded script (UTF-8) on success
  std::optional<std::string> error;  // reason on failure
};

// Whitespace split with double-quote grouping (quotes removed, no escapes).
std::vector<std::string> split_command_line(std::string_view cmd);
// True for -e, -ec, -en, -enc, ... -encodedcommand (and the same with '/'), any case.
bool is_encoded_flag(std::string_view token);
// Strict standard-alphabet Base64; missing padding accepted. nullopt on any invalid input.
std::optional<std::vector<std::uint8_t>> base64_decode(std::string_view text);
// UTF-16LE to UTF-8; nullopt for odd length, unpaired surrogates or NUL characters.
std::optional<std::string> utf16le_to_utf8(const std::vector<std::uint8_t>& data);

DecodeResult decode_encoded_command(std::string_view command_line);

}  // namespace edr
