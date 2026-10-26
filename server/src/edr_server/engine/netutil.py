"""IP and CIDR helpers (mirrors agent/src/engine/netutil.cpp)."""

from __future__ import annotations

import ipaddress
import math

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_ip(text: str) -> IPAddress | None:
    if not text or "%" in text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def parse_cidr(text: str) -> Network | None:
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def ip_in_any(ip: IPAddress, networks: list[Network]) -> Network | None:
    for net in networks:
        if ip.version == net.version and ip in net:
            return net
    return None


def longest_label(name: str) -> bytes:
    best = b""
    for label in name.encode("utf-8").split(b"."):
        if len(label) > len(best):
            best = label
    return best


def shannon_entropy(data: bytes) -> float:
    """Bits per byte. Counts are summed in byte-value order so C++ gets the same double."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy
