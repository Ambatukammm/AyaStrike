"""Target scope whitelist — the core safety control of AyaStrike.

NOTHING in the suite is permitted to probe a target unless it falls inside the
active project's authorised scope. Modules call ``ScopeManager.require()``
before any network action; a ScopeViolation is raised (and audit-logged) if the
target is out of scope.

Scope entries can be:
  * a single IPv4/IPv6 address        e.g. 203.0.113.10
  * a CIDR network                    e.g. 203.0.113.0/24, 2001:db8::/32
  * a hostname / FQDN                 e.g. test.internal.example
  * a wildcard domain                 e.g. *.lab.example  (matches sub.lab.example)

Private/loopback ranges are allowed by default (typical for home labs). Public
targets must be added explicitly. A deny-list always wins over the allow-list.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass, field
from typing import Iterable


class ScopeViolation(Exception):
    """Raised when a module tries to act on an out-of-scope target."""

    def __init__(self, target: str, reason: str = "not in authorised scope"):
        self.target = target
        self.reason = reason
        super().__init__(f"Scope violation: '{target}' is {reason}")


def _normalise(entry: str) -> str:
    return entry.strip().lower().rstrip(".")


@dataclass
class ScopeEntry:
    raw: str
    kind: str  # 'ip', 'cidr', 'host', 'wildcard'

    def matches(self, target: str) -> bool:
        target = _normalise(target)
        if self.kind == "ip":
            return self._ip_equals(target)
        if self.kind == "cidr":
            return self._in_cidr(target)
        if self.kind == "host":
            return target == _normalise(self.raw)
        if self.kind == "wildcard":
            # *.lab.example matches a.lab.example and lab.example itself.
            base = _normalise(self.raw)[2:]  # strip leading '*.'
            return target == base or target.endswith("." + base)
        return False

    def _ip_equals(self, target: str) -> bool:
        try:
            return ipaddress.ip_address(target) == ipaddress.ip_address(self.raw)
        except ValueError:
            return False

    def _in_cidr(self, target: str) -> bool:
        try:
            net = ipaddress.ip_network(self.raw, strict=False)
            return ipaddress.ip_address(target) in net
        except ValueError:
            return False


def classify(entry: str) -> ScopeEntry:
    """Determine what kind of scope entry a string represents."""
    e = _normalise(entry)
    if not e:
        raise ValueError("empty scope entry")
    if e.startswith("*."):
        return ScopeEntry(entry.strip(), "wildcard")
    if "/" in e:
        ipaddress.ip_network(e, strict=False)  # validate; raises on bad input
        return ScopeEntry(entry.strip(), "cidr")
    try:
        ipaddress.ip_address(e)
        return ScopeEntry(entry.strip(), "ip")
    except ValueError:
        return ScopeEntry(entry.strip(), "host")


class ScopeManager:
    """Thread-safe allow/deny list for a single project workspace."""

    def __init__(self, enforce: bool = True) -> None:
        self._lock = threading.RLock()
        self._allow: list[ScopeEntry] = []
        self._deny: list[ScopeEntry] = []
        self.enforce = enforce

    # -- mutation ---------------------------------------------------------
    def add(self, entry: str) -> ScopeEntry:
        ent = classify(entry)
        with self._lock:
            if not any(x.raw == ent.raw for x in self._allow):
                self._allow.append(ent)
        return ent

    def add_deny(self, entry: str) -> ScopeEntry:
        ent = classify(entry)
        with self._lock:
            if not any(x.raw == ent.raw for x in self._deny):
                self._deny.append(ent)
        return ent

    def remove(self, raw: str) -> None:
        with self._lock:
            self._allow = [x for x in self._allow if x.raw != raw]
            self._deny = [x for x in self._deny if x.raw != raw]

    def set_all(self, allow: Iterable[str], deny: Iterable[str] = ()) -> None:
        with self._lock:
            self._allow = [classify(e) for e in allow if e.strip()]
            self._deny = [classify(e) for e in deny if e.strip()]

    def clear(self) -> None:
        with self._lock:
            self._allow.clear()
            self._deny.clear()

    # -- queries ----------------------------------------------------------
    @property
    def allow(self) -> list[str]:
        with self._lock:
            return [x.raw for x in self._allow]

    @property
    def deny(self) -> list[str]:
        with self._lock:
            return [x.raw for x in self._deny]

    def _is_private(self, target: str) -> bool:
        try:
            ip = ipaddress.ip_address(_normalise(target))
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            # Hostnames like 'localhost' are treated as private/lab-safe.
            return _normalise(target) in {"localhost", "localhost.localdomain"}

    def is_in_scope(self, target: str) -> bool:
        """Return True if ``target`` is permitted. Deny always wins."""
        if not self.enforce:
            return True
        with self._lock:
            for d in self._deny:
                if d.matches(target):
                    return False
            if self._is_private(target):
                return True
            return any(a.matches(target) for a in self._allow)

    def require(self, target: str) -> None:
        """Raise ScopeViolation if ``target`` is not permitted."""
        if not self.is_in_scope(target):
            with self._lock:
                for d in self._deny:
                    if d.matches(target):
                        raise ScopeViolation(target, "explicitly denied")
            raise ScopeViolation(target)

    def to_dict(self) -> dict:
        return {"allow": self.allow, "deny": self.deny, "enforce": self.enforce}

    @classmethod
    def from_dict(cls, d: dict) -> "ScopeManager":
        sm = cls(enforce=d.get("enforce", True))
        sm.set_all(d.get("allow", []), d.get("deny", []))
        return sm
