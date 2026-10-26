#include "edr/netutil.hpp"

#include <array>
#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "edr/textutil.hpp"

namespace edr {
namespace {

std::optional<std::array<std::uint8_t, 4>> parse_v4(std::string_view text) {
  std::array<std::uint8_t, 4> out{};
  std::size_t part = 0;
  std::size_t pos = 0;
  while (part < 4) {
    std::size_t start = pos;
    unsigned value = 0;
    while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9' && pos - start < 4) {
      value = value * 10 + static_cast<unsigned>(text[pos] - '0');
      ++pos;
    }
    const std::size_t len = pos - start;
    if (len == 0 || len > 3 || value > 255 || (len > 1 && text[start] == '0')) {
      return std::nullopt;
    }
    out[part++] = static_cast<std::uint8_t>(value);
    if (part < 4) {
      if (pos >= text.size() || text[pos] != '.') {
        return std::nullopt;
      }
      ++pos;
    }
  }
  if (pos != text.size()) {
    return std::nullopt;
  }
  return out;
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

std::optional<std::array<std::uint8_t, 16>> parse_v6(std::string_view text) {
  if (text.empty() || text.find('%') != std::string_view::npos) {
    return std::nullopt;
  }
  std::vector<std::uint16_t> head;
  std::vector<std::uint16_t> tail;
  bool seen_gap = false;
  std::size_t pos = 0;
  if (starts_with(text, "::")) {
    seen_gap = true;
    pos = 2;
  } else if (text.front() == ':') {
    return std::nullopt;
  }
  std::optional<std::array<std::uint8_t, 4>> v4_tail;
  while (pos < text.size()) {
    // Embedded IPv4 in the last 32 bits.
    const std::size_t next_colon = text.find(':', pos);
    const std::string_view group = text.substr(
        pos, next_colon == std::string_view::npos ? std::string_view::npos : next_colon - pos);
    if (group.find('.') != std::string_view::npos) {
      if (next_colon != std::string_view::npos) {
        return std::nullopt;
      }
      v4_tail = parse_v4(group);
      if (!v4_tail) {
        return std::nullopt;
      }
      pos = text.size();
      break;
    }
    if (group.empty() || group.size() > 4) {
      return std::nullopt;
    }
    unsigned value = 0;
    for (const char c : group) {
      const int h = hex_value(c);
      if (h < 0) {
        return std::nullopt;
      }
      value = (value << 4U) | static_cast<unsigned>(h);
    }
    (seen_gap ? tail : head).push_back(static_cast<std::uint16_t>(value));
    pos += group.size();
    if (pos == text.size()) {
      break;
    }
    // pos is at ':'
    if (pos + 1 < text.size() && text[pos + 1] == ':') {
      if (seen_gap) {
        return std::nullopt;
      }
      seen_gap = true;
      pos += 2;
      continue;
    }
    ++pos;
    if (pos == text.size()) {
      return std::nullopt;  // trailing single ':'
    }
  }
  const std::size_t groups = head.size() + tail.size() + (v4_tail ? 2 : 0);
  if (seen_gap ? groups > 7 : groups != 8) {
    return std::nullopt;
  }
  std::array<std::uint8_t, 16> out{};
  std::size_t i = 0;
  for (const auto g : head) {
    out[i++] = static_cast<std::uint8_t>(g >> 8U);
    out[i++] = static_cast<std::uint8_t>(g & 0xFFU);
  }
  const std::size_t tail_bytes = tail.size() * 2 + (v4_tail ? 4 : 0);
  i = 16 - tail_bytes;
  for (const auto g : tail) {
    out[i++] = static_cast<std::uint8_t>(g >> 8U);
    out[i++] = static_cast<std::uint8_t>(g & 0xFFU);
  }
  if (v4_tail) {
    for (const auto b : *v4_tail) {
      out[i++] = b;
    }
  }
  return out;
}

}  // namespace

std::optional<IpAddress> parse_ip(std::string_view text) {
  if (text.empty()) {
    return std::nullopt;
  }
  if (text.find(':') == std::string_view::npos) {
    const auto v4 = parse_v4(text);
    if (!v4) {
      return std::nullopt;
    }
    IpAddress ip;
    ip.version = 4;
    for (std::size_t i = 0; i < 4; ++i) {
      ip.bytes[i] = (*v4)[i];
    }
    return ip;
  }
  const auto v6 = parse_v6(text);
  if (!v6) {
    return std::nullopt;
  }
  IpAddress ip;
  ip.version = 6;
  ip.bytes = *v6;
  return ip;
}

std::optional<Cidr> parse_cidr(std::string_view text) {
  const std::size_t slash = text.find('/');
  const auto ip = parse_ip(text.substr(0, slash));
  if (!ip) {
    return std::nullopt;
  }
  const int max_prefix = ip->version == 4 ? 32 : 128;
  int prefix = max_prefix;
  if (slash != std::string_view::npos) {
    const auto p = parse_int(text.substr(slash + 1));
    if (!p || *p < 0 || *p > max_prefix || text.substr(slash + 1).front() == '-') {
      return std::nullopt;
    }
    prefix = static_cast<int>(*p);
  }
  Cidr c;
  c.network = *ip;
  c.prefix = prefix;
  c.text = std::string(text);
  return c;
}

bool cidr_contains(const Cidr& cidr, const IpAddress& ip) {
  if (cidr.network.version != ip.version) {
    return false;
  }
  int bits = cidr.prefix;
  for (std::size_t i = 0; bits > 0; ++i) {
    const int take = bits >= 8 ? 8 : bits;
    const auto mask = static_cast<std::uint8_t>(0xFFU << static_cast<unsigned>(8 - take));
    if ((cidr.network.bytes[i] & mask) != (ip.bytes[i] & mask)) {
      return false;
    }
    bits -= take;
  }
  return true;
}

const Cidr* ip_in_any(const IpAddress& ip, const std::vector<Cidr>& networks) {
  for (const auto& net : networks) {
    if (cidr_contains(net, ip)) {
      return &net;
    }
  }
  return nullptr;
}

std::string_view longest_label(std::string_view name) {
  std::string_view best;
  std::size_t start = 0;
  while (start <= name.size()) {
    std::size_t dot = name.find('.', start);
    if (dot == std::string_view::npos) {
      dot = name.size();
    }
    const std::string_view label = name.substr(start, dot - start);
    if (label.size() > best.size()) {
      best = label;
    }
    start = dot + 1;
  }
  return best;
}

double shannon_entropy(std::string_view data) {
  if (data.empty()) {
    return 0.0;
  }
  std::array<std::size_t, 256> counts{};
  for (const char c : data) {
    ++counts[static_cast<unsigned char>(c)];
  }
  const auto total = static_cast<double>(data.size());
  double entropy = 0.0;
  for (const std::size_t c : counts) {
    if (c != 0) {
      const double p = static_cast<double>(c) / total;
      entropy -= p * std::log2(p);
    }
  }
  return entropy;
}

}  // namespace edr
