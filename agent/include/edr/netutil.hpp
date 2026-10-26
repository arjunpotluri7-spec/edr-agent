// IPv4/IPv6 parsing, CIDR matching and DNS label entropy (mirrors engine/netutil.py).
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace edr {

struct IpAddress {
  int version = 4;                       // 4 or 6
  std::array<std::uint8_t, 16> bytes{};  // v4 uses the first 4
};

struct Cidr {
  IpAddress network;
  int prefix = 0;
  std::string text;
};

// Accepts dotted-quad IPv4 (no leading zeros) and RFC 4291 IPv6 text (including an embedded
// IPv4 tail). Zone ids (%eth0) are rejected.
std::optional<IpAddress> parse_ip(std::string_view text);
std::optional<Cidr> parse_cidr(std::string_view text);
bool cidr_contains(const Cidr& cidr, const IpAddress& ip);
// First network that contains ip, or nullptr.
const Cidr* ip_in_any(const IpAddress& ip, const std::vector<Cidr>& networks);

// Longest dot-separated label (first one on ties), as bytes.
std::string_view longest_label(std::string_view name);
// Shannon entropy in bits per byte.
double shannon_entropy(std::string_view data);

}  // namespace edr
