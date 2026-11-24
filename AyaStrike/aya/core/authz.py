"""Authorisation gate for sensitive / intrusive capabilities.

Some capabilities (brute force, launching exploit modules) are intrusive enough
that a single checkbox is not an adequate guard. This module models an explicit,
auditable, per-session authorisation that the operator must grant by:

  1. confirming they have WRITTEN permission to test the target scope, and
  2. typing a confirmation phrase.

The grant is held in memory only (never persisted), is tied to the active
project, and every grant/decline is audit-logged by the caller.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


CONFIRM_PHRASE = "I HAVE WRITTEN AUTHORISATION"


class NotAuthorised(Exception):
    """Raised when an intrusive capability is used without a valid grant."""


@dataclass
class Grant:
    capability: str
    granted_at: float
    note: str = ""


class AuthorizationGate:
    """Tracks which intrusive capabilities are currently authorised."""

    # Capabilities that require an explicit grant before use.
    GATED = {
        "bruteforce": "Online credential brute forcing",
        "exploit": "Launching Metasploit exploit/auxiliary modules",
        "active_exploit_confirm": "Per-module exploit launch confirmation",
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._grants: dict[str, Grant] = {}

    def grant(self, capability: str, confirm_phrase: str, note: str = "") -> bool:
        """Grant a capability. Returns True on success.

        The caller is responsible for also presenting the red legal warning and
        the written-permission checkbox in the UI, and for audit-logging the
        result. This method enforces the typed confirmation phrase.
        """
        if capability not in self.GATED:
            raise ValueError(f"unknown gated capability: {capability}")
        if confirm_phrase.strip().upper() != CONFIRM_PHRASE:
            return False
        with self._lock:
            self._grants[capability] = Grant(capability, time.time(), note)
        return True

    def revoke(self, capability: str) -> None:
        with self._lock:
            self._grants.pop(capability, None)

    def revoke_all(self) -> None:
        with self._lock:
            self._grants.clear()

    def is_authorised(self, capability: str) -> bool:
        with self._lock:
            return capability in self._grants

    def require(self, capability: str) -> None:
        if not self.is_authorised(capability):
            raise NotAuthorised(
                f"Capability '{capability}' is not authorised. Grant it via the "
                f"authorisation dialog (requires written-permission confirmation)."
            )

    def active(self) -> list[str]:
        with self._lock:
            return sorted(self._grants.keys())
