"""Evaluate rule conditions against an enriched event (mirrors agent/src/engine/condition.cpp)."""

from __future__ import annotations

from typing import Any

from edr_server.engine.config import Leaf, Node
from edr_server.engine.netutil import ip_in_any, longest_label, parse_ip, shannon_entropy
from edr_server.engine.textutil import ascii_lower

# Regex input is capped so a pathological command line cannot make matching slow.
MAX_REGEX_INPUT = 4096
_INT_CHARS = frozenset("0123456789")


def as_text(value: Any) -> str:
    """Field values are compared as text; integers in decimal, booleans as true/false."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _values(event: dict[str, Any], name: str) -> list[str] | None:
    value = event.get(name)
    if value is None:
        return None
    if isinstance(value, list):
        return [as_text(v) for v in value]
    text = as_text(value)
    return [text] if text != "" else None


def _parse_int(text: str) -> int | None:
    body = text[1:] if text.startswith("-") else text
    if not body or len(body) > 18 or not set(body) <= _INT_CHARS:
        return None
    return int(text)


def _match_one(leaf: Leaf, text: str) -> bool:
    op = leaf.op
    if op in ("equals", "contains", "startswith", "endswith"):
        subject = text if leaf.case_sensitive else ascii_lower(text)
        if op == "equals":
            return subject in leaf.values
        if op == "contains":
            return any(v in subject for v in leaf.values)
        if op == "startswith":
            return any(subject.startswith(v) for v in leaf.values)
        return any(subject.endswith(v) for v in leaf.values)
    if op == "regex":
        data = text.encode("utf-8")[:MAX_REGEX_INPUT].decode("utf-8", "ignore")
        return leaf.compiled.search(data) is not None
    if op in ("gt", "gte", "lt", "lte"):
        number = _parse_int(text)
        if number is None:
            return False
        limit = leaf.values[0]
        return {
            "gt": number > limit,
            "gte": number >= limit,
            "lt": number < limit,
            "lte": number <= limit,
        }[op]
    if op == "cidr":
        ip = parse_ip(text)
        return ip is not None and ip_in_any(ip, leaf.compiled) is not None
    if op == "min_label_length":
        return len(longest_label(text)) >= leaf.values[0]
    if op == "min_label_entropy":
        return shannon_entropy(longest_label(text)) >= leaf.values[0]
    raise AssertionError(f"unhandled operator {op}")


def evaluate(node: Node, event: dict[str, Any]) -> bool:
    if node.kind == "all":
        return all(evaluate(c, event) for c in node.children)
    if node.kind == "any":
        return any(evaluate(c, event) for c in node.children)
    if node.kind == "not":
        return not evaluate(node.children[0], event)
    leaf = node.leaf
    if leaf is None:  # parse_condition always sets it for "leaf" nodes
        raise ValueError("leaf node without a leaf")
    values = _values(event, leaf.field)
    if leaf.op == "exists":
        return (values is not None and len(values) > 0) == leaf.values[0]
    if not values:
        return False
    return any(_match_one(leaf, v) for v in values)
