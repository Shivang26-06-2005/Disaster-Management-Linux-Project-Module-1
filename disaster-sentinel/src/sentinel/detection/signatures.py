"""Regex signature matching on Linux log lines (slide 10, technique 2).

Keyword matching needs guards to be usable on real logs:

* "No critical anomalies" contains the word critical, and the deck's own expected
  output prints that line, so negated mentions are skipped.
* The agent's own log lines would otherwise feed back into detection and loop.
* Log text is attacker-controlled. Lines are length-capped before matching, and
  extracted values (IP, service name) are validated before anything uses them.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from ..config import Signature

MAX_LINE = 2048

_NEGATION = re.compile(
    r"\b(no|not|without|zero|0|never)\s+(?:\w+\s+){0,2}?(critical|breach(?:es)?|failed|failures?)\b",
    re.IGNORECASE,
)
_IP = re.compile(r"(?:from|rhost=)\s*((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39})(?:\s|$)")
_USER = re.compile(r"(?:Failed password for (?:invalid user )?|user=)([A-Za-z0-9._-]{1,32})")
_SERVICE_PATTERNS = [
    re.compile(r"\b([A-Za-z0-9@._-]{1,120})\.service\b"),
    re.compile(r"Failed to start ([A-Za-z0-9@._-]{1,120})\b"),
]
_SERVICE_NAME = re.compile(r"^[A-Za-z0-9@._-]{1,120}$")


@dataclass(frozen=True)
class Match:
    name: str
    class_: str
    strength: str
    attrs: dict = field(default_factory=dict)


def valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _extract(line: str, class_: str) -> dict:
    attrs: dict = {}
    if class_ == "auth_failed":
        if m := _IP.search(line):
            if ip := valid_ip(m.group(1)):
                attrs["ip"] = ip
        if m := _USER.search(line):
            attrs["user"] = m.group(1)
    elif class_ == "failed":
        for pattern in _SERVICE_PATTERNS:
            if m := pattern.search(line):
                candidate = m.group(1)
                if _SERVICE_NAME.match(candidate):
                    attrs["service"] = candidate
                    break
    return attrs


class SignatureMatcher:
    def __init__(self, signatures: list[Signature], self_tags: list[str] | None = None):
        self._compiled = [
            (s, re.compile(s.pattern, re.IGNORECASE if s.ignore_case else 0)) for s in signatures
        ]
        self._self_tags = tuple(f"{t}[" for t in self_tags or []) + tuple(
            f"{t}:" for t in self_tags or []
        )

    def match(self, line: str) -> list[Match]:
        line = line[:MAX_LINE]
        if self._self_tags and any(tag in line for tag in self._self_tags):
            return []
        results: list[Match] = []
        negated = _NEGATION.search(line) is not None
        seen: set[str] = set()
        for sig, rx in self._compiled:
            if sig.class_ in seen or not rx.search(line):
                continue
            # Only keyword-style signatures can be negated. A sentence such as
            # "kernel panic" has no meaningful negated form in real logs.
            if negated and sig.name in {"breach_keyword", "critical_keyword", "service_failed"}:
                continue
            seen.add(sig.class_)
            results.append(Match(sig.name, sig.class_, sig.strength, _extract(line, sig.class_)))
        return results
