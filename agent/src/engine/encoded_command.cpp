#include "edr/encoded_command.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "edr/textutil.hpp"

namespace edr {

std::vector<std::string> split_command_line(std::string_view cmd) {
  std::vector<std::string> tokens;
  std::string cur;
  bool in_quote = false;
  bool have = false;
  for (const char ch : cmd) {
    if (ch == '"') {
      in_quote = !in_quote;
      have = true;
    } else if ((ch == ' ' || ch == '\t') && !in_quote) {
      if (have) {
        tokens.push_back(cur);
        cur.clear();
        have = false;
      }
    } else {
      cur += ch;
      have = true;
    }
  }
  if (have) {
    tokens.push_back(cur);
  }
  return tokens;
}

bool is_encoded_flag(std::string_view token) {
  if (token.size() < 2 || (token[0] != '-' && token[0] != '/')) {
    return false;
  }
  const std::string name = ascii_lower(token.substr(1));
  constexpr std::string_view kFull = "encodedcommand";
  return name == "ec" || starts_with(kFull, name);
}

namespace {

constexpr std::array<std::int8_t, 256> make_table() {
  std::array<std::int8_t, 256> t{};
  for (auto& v : t) {
    v = -1;
  }
  constexpr std::string_view kAlphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (std::size_t i = 0; i < kAlphabet.size(); ++i) {
    t[static_cast<unsigned char>(kAlphabet[i])] = static_cast<std::int8_t>(i);
  }
  return t;
}

constexpr std::array<std::int8_t, 256> kTable = make_table();

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

}  // namespace

std::optional<std::vector<std::uint8_t>> base64_decode(std::string_view text) {
  std::string_view body = text;
  std::size_t pad = 0;
  while (!body.empty() && body.back() == '=' && pad < 2) {
    body.remove_suffix(1);
    ++pad;
  }
  if (body.empty() || body.size() % 4 == 1) {
    return std::nullopt;
  }
  if (pad != 0 && (body.size() + pad) % 4 != 0) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> out;
  out.reserve(body.size() * 3 / 4);
  std::uint32_t acc = 0;
  int bits = 0;
  for (const char ch : body) {
    const std::int8_t val = kTable[static_cast<unsigned char>(ch)];
    if (val < 0) {
      return std::nullopt;
    }
    acc = ((acc << 6U) | static_cast<std::uint32_t>(val)) & 0xFFFFFFU;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((acc >> static_cast<unsigned>(bits)) & 0xFFU));
    }
  }
  return out;
}

std::optional<std::string> utf16le_to_utf8(const std::vector<std::uint8_t>& data) {
  if (data.size() % 2 != 0) {
    return std::nullopt;
  }
  std::string out;
  out.reserve(data.size() / 2);
  const std::size_t n = data.size() / 2;
  auto unit = [&](std::size_t i) {
    return static_cast<std::uint32_t>(data[2 * i]) |
           (static_cast<std::uint32_t>(data[2 * i + 1]) << 8U);
  };
  std::size_t i = 0;
  while (i < n) {
    const std::uint32_t u = unit(i);
    if (u == 0) {
      return std::nullopt;
    }
    if (u >= 0xD800 && u <= 0xDBFF) {
      if (i + 1 >= n) {
        return std::nullopt;
      }
      const std::uint32_t lo = unit(i + 1);
      if (lo < 0xDC00 || lo > 0xDFFF) {
        return std::nullopt;
      }
      append_utf8(out, 0x10000 + ((u - 0xD800) << 10U) + (lo - 0xDC00));
      i += 2;
      continue;
    }
    if (u >= 0xDC00 && u <= 0xDFFF) {
      return std::nullopt;
    }
    append_utf8(out, u);
    ++i;
  }
  return out;
}

DecodeResult decode_encoded_command(std::string_view command_line) {
  const std::vector<std::string> tokens = split_command_line(command_line);
  for (std::size_t idx = 0; idx < tokens.size(); ++idx) {
    if (!is_encoded_flag(tokens[idx])) {
      continue;
    }
    DecodeResult r;
    r.found = true;
    if (idx + 1 >= tokens.size()) {
      r.error = "missing payload";
      return r;
    }
    const std::string& payload = tokens[idx + 1];
    if (payload.size() > kMaxEncodedPayload) {
      r.error = "payload too large";
      return r;
    }
    const auto raw = base64_decode(payload);
    if (!raw) {
      r.error = "invalid base64";
      return r;
    }
    auto text = utf16le_to_utf8(*raw);
    if (!text) {
      r.error = "invalid utf-16le";
      return r;
    }
    r.text = std::move(*text);
    return r;
  }
  return DecodeResult{};
}

}  // namespace edr
