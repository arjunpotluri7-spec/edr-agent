#include "edr/textutil.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace edr {

std::string ascii_lower(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  return out;
}

std::string_view basename(std::string_view path) {
  const std::size_t cut = path.find_last_of("\\/");
  return cut == std::string_view::npos ? path : path.substr(cut + 1);
}

std::string image_name(std::string_view path) {
  return ascii_lower(basename(path));
}

bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool ends_with(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

namespace {

// Floor division for possibly negative values (matches Python's //).
constexpr std::int64_t floor_div(std::int64_t a, std::int64_t b) {
  const std::int64_t q = a / b;
  return (a % b != 0 && ((a < 0) != (b < 0))) ? q - 1 : q;
}

constexpr std::int64_t days_from_civil(std::int64_t y, std::int64_t m, std::int64_t d) {
  y -= m <= 2 ? 1 : 0;
  const std::int64_t era = floor_div(y, 400);
  const std::int64_t yoe = y - era * 400;
  const std::int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const std::int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + doe - 719468;
}

struct Civil {
  std::int64_t y;
  std::int64_t m;
  std::int64_t d;
};

constexpr Civil civil_from_days(std::int64_t z) {
  z += 719468;
  const std::int64_t era = floor_div(z, 146097);
  const std::int64_t doe = z - era * 146097;
  const std::int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  const std::int64_t y = yoe + era * 400;
  const std::int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const std::int64_t mp = (5 * doy + 2) / 153;
  const std::int64_t d = doy - (153 * mp + 2) / 5 + 1;
  const std::int64_t m = mp + (mp < 10 ? 3 : -9);
  return Civil{y + (m <= 2 ? 1 : 0), m, d};
}

bool digits_at(std::string_view s, std::size_t pos, std::size_t n, std::int64_t& out) {
  if (pos + n > s.size()) {
    return false;
  }
  out = 0;
  for (std::size_t i = 0; i < n; ++i) {
    const char c = s[pos + i];
    if (c < '0' || c > '9') {
      return false;
    }
    out = out * 10 + (c - '0');
  }
  return true;
}

}  // namespace

std::optional<std::int64_t> parse_ts(std::string_view text) {
  std::int64_t y = 0;
  std::int64_t mo = 0;
  std::int64_t d = 0;
  std::int64_t h = 0;
  std::int64_t mi = 0;
  std::int64_t s = 0;
  if (!digits_at(text, 0, 4, y) || text.size() < 19 || text[4] != '-' ||
      !digits_at(text, 5, 2, mo) || text[7] != '-' || !digits_at(text, 8, 2, d) ||
      (text[10] != 'T' && text[10] != ' ') || !digits_at(text, 11, 2, h) || text[13] != ':' ||
      !digits_at(text, 14, 2, mi) || text[16] != ':' || !digits_at(text, 17, 2, s)) {
    return std::nullopt;
  }
  std::size_t pos = 19;
  std::int64_t millis = 0;
  if (pos < text.size() && text[pos] == '.') {
    ++pos;
    std::size_t n = 0;
    while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
      if (n < 3) {
        millis = millis * 10 + (text[pos] - '0');
      }
      ++n;
      ++pos;
    }
    if (n == 0 || n > 9) {
      return std::nullopt;
    }
    for (std::size_t i = n; i < 3; ++i) {
      millis *= 10;
    }
  }
  if (pos < text.size() && text[pos] == 'Z') {
    ++pos;
  }
  if (pos != text.size()) {
    return std::nullopt;
  }
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60) {
    return std::nullopt;
  }
  const std::int64_t days = days_from_civil(y, mo, d);
  return ((days * 24 + h) * 60 + mi) * 60000 + s * 1000 + millis;
}

std::string format_ts(std::int64_t ms) {
  const std::int64_t days = floor_div(ms, 86400000);
  std::int64_t rem = ms - days * 86400000;
  const Civil c = civil_from_days(days);
  const std::int64_t h = rem / 3600000;
  rem %= 3600000;
  const std::int64_t mi = rem / 60000;
  rem %= 60000;
  const std::int64_t s = rem / 1000;
  const std::int64_t milli = rem % 1000;
  return zero_pad(c.y, 4) + "-" + zero_pad(c.m, 2) + "-" + zero_pad(c.d, 2) + "T" + zero_pad(h, 2) +
         ":" + zero_pad(mi, 2) + ":" + zero_pad(s, 2) + "." + zero_pad(milli, 3) + "Z";
}

std::string fnv1a64(std::string_view text) {
  std::uint64_t h = 0xCBF29CE484222325ULL;
  for (const char c : text) {
    h ^= static_cast<unsigned char>(c);
    h *= 0x100000001B3ULL;
  }
  return to_hex(h, 16);
}

std::string zero_pad(std::int64_t value, int width) {
  std::string digits = std::to_string(value < 0 ? -value : value);
  if (digits.size() < static_cast<std::size_t>(width)) {
    digits.insert(0, static_cast<std::size_t>(width) - digits.size(), '0');
  }
  return value < 0 ? "-" + digits : digits;
}

std::string to_hex(std::uint64_t value, int width) {
  constexpr std::string_view kHex = "0123456789abcdef";
  std::string out;
  do {
    out.insert(out.begin(), kHex[value & 0xFU]);
    value >>= 4U;
  } while (value != 0);
  if (out.size() < static_cast<std::size_t>(width)) {
    out.insert(0, static_cast<std::size_t>(width) - out.size(), '0');
  }
  return out;
}

std::optional<std::int64_t> parse_int(std::string_view text) {
  std::string_view body = text;
  bool neg = false;
  if (!body.empty() && body.front() == '-') {
    neg = true;
    body.remove_prefix(1);
  }
  if (body.empty() || body.size() > 18) {
    return std::nullopt;
  }
  std::int64_t v = 0;
  for (const char c : body) {
    if (c < '0' || c > '9') {
      return std::nullopt;
    }
    v = v * 10 + (c - '0');
  }
  return neg ? -v : v;
}

std::vector<std::string> split(std::string_view text, char sep) {
  std::vector<std::string> out;
  std::size_t start = 0;
  while (true) {
    const std::size_t pos = text.find(sep, start);
    if (pos == std::string_view::npos) {
      out.emplace_back(text.substr(start));
      return out;
    }
    out.emplace_back(text.substr(start, pos - start));
    start = pos + 1;
  }
}

}  // namespace edr
