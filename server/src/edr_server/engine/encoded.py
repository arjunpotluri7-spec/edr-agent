"""Find and decode PowerShell ``-EncodedCommand`` payloads (Base64 of UTF-16LE text).

Mirrors agent/src/engine/encoded_command.cpp. Decoding is strict and bounded: the payload is
capped at MAX_PAYLOAD characters, must be valid Base64 (padding optional), must decode to an
even number of bytes, and must be valid UTF-16LE without NUL characters.
"""

from __future__ import annotations

from dataclasses import dataclass

from edr_server.engine.textutil import ascii_lower

MAX_PAYLOAD = 65536
_FULL_FLAG = "encodedcommand"
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64 = {c: i for i, c in enumerate(_ALPHABET)}


@dataclass(frozen=True)
class DecodeResult:
    found: bool  # an encoded-command flag was present
    text: str | None = None  # decoded script on success
    error: str | None = None  # reason on failure


def split_command_line(cmd: str) -> list[str]:
    """Whitespace split with double-quote grouping; quotes are removed, no escapes."""
    tokens: list[str] = []
    cur: list[str] = []
    in_quote = False
    have = False
    for ch in cmd:
        if ch == '"':
            in_quote = not in_quote
            have = True
        elif ch in " \t" and not in_quote:
            if have:
                tokens.append("".join(cur))
                cur, have = [], False
        else:
            cur.append(ch)
            have = True
    if have:
        tokens.append("".join(cur))
    return tokens


def is_encoded_flag(token: str) -> bool:
    if len(token) < 2 or token[0] not in "-/":
        return False
    name = ascii_lower(token[1:])
    return name == "ec" or _FULL_FLAG.startswith(name)


def base64_decode(text: str) -> bytes | None:
    """Strict Base64 (standard alphabet). Missing padding is accepted; anything else is not."""
    body = text
    pad = 0
    while body.endswith("=") and pad < 2:
        body = body[:-1]
        pad += 1
    if not body or len(body) % 4 == 1:
        return None
    if pad and (len(body) + pad) % 4 != 0:
        return None
    out = bytearray()
    acc = 0
    bits = 0
    for ch in body:
        val = _B64.get(ch)
        if val is None:
            return None
        acc = (acc << 6) | val
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)


def utf16le_to_str(data: bytes) -> str | None:
    if len(data) % 2:
        return None
    units = [data[i] | (data[i + 1] << 8) for i in range(0, len(data), 2)]
    chars: list[str] = []
    i = 0
    while i < len(units):
        u = units[i]
        if u == 0:
            return None
        if 0xD800 <= u <= 0xDBFF:
            if i + 1 >= len(units) or not 0xDC00 <= units[i + 1] <= 0xDFFF:
                return None
            cp = 0x10000 + ((u - 0xD800) << 10) + (units[i + 1] - 0xDC00)
            chars.append(chr(cp))
            i += 2
            continue
        if 0xDC00 <= u <= 0xDFFF:
            return None
        chars.append(chr(u))
        i += 1
    return "".join(chars)


def decode_encoded_command(command_line: str) -> DecodeResult:
    tokens = split_command_line(command_line)
    for idx, tok in enumerate(tokens):
        if not is_encoded_flag(tok):
            continue
        if idx + 1 >= len(tokens):
            return DecodeResult(True, error="missing payload")
        payload = tokens[idx + 1]
        if len(payload.encode("utf-8")) > MAX_PAYLOAD:
            return DecodeResult(True, error="payload too large")
        raw = base64_decode(payload)
        if raw is None:
            return DecodeResult(True, error="invalid base64")
        text = utf16le_to_str(raw)
        if text is None:
            return DecodeResult(True, error="invalid utf-16le")
        return DecodeResult(True, text=text)
    return DecodeResult(False)
