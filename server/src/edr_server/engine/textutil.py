"""Small text helpers whose behaviour must match agent/src/engine/textutil.cpp byte for byte."""

from __future__ import annotations

import re

_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_TS = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z?")


def ascii_lower(text: str) -> str:
    """Lower-case A-Z only (no locale or Unicode folding), like the C++ side."""
    return text.translate(_LOWER)


def basename(path: str) -> str:
    """File name after the last backslash or slash."""
    cut = max(path.rfind("\\"), path.rfind("/"))
    return path[cut + 1 :]


def image_name(path: str) -> str:
    return ascii_lower(basename(path))


def _days_from_civil(y: int, m: int, d: int) -> int:
    # Howard Hinnant's algorithm; identical integer steps in C++.
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(z: int) -> tuple[int, int, int]:
    z += 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    return y + (m <= 2), m, d


def parse_ts(text: str) -> int | None:
    """ISO-8601 UTC timestamp (``Z`` or no suffix) to milliseconds since the epoch."""
    match = _TS.fullmatch(text)
    if not match:
        return None
    y, mo, d, h, mi, s = (int(match.group(i)) for i in range(1, 7))
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h <= 23 and mi <= 59 and s <= 60):
        return None
    frac = (match.group(7) or "").ljust(3, "0")[:3]
    days = _days_from_civil(y, mo, d)
    return ((days * 24 + h) * 60 + mi) * 60_000 + s * 1000 + int(frac)


def format_ts(ms: int) -> str:
    days, rem = divmod(ms, 86_400_000)
    y, m, d = _civil_from_days(days)
    h, rem = divmod(rem, 3_600_000)
    mi, rem = divmod(rem, 60_000)
    s, milli = divmod(rem, 1000)
    return f"{y:04d}-{m:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{milli:03d}Z"


def fnv1a64(text: str) -> str:
    """FNV-1a 64-bit hash of the UTF-8 bytes, as 16 lower-case hex digits."""
    h = 0xCBF29CE484222325
    for byte in text.encode("utf-8"):
        h ^= byte
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"
