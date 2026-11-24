"""Module base class, phase definitions, and the finding model.

The plugin architecture is intentionally tiny: a module declares metadata
(id, name, phase, inputs), implements ``run()``, and yields ``Finding`` and
``Event`` objects. The framework handles scope enforcement, rate limiting,
audit logging, cancellation, and persistence around it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterator, Optional


class Phase(str, Enum):
    PASSIVE_RECON = "1. Passive Reconnaissance"
    ACTIVE_SCAN = "2. Active Scanning"
    VULN_ASSESS = "3. Vulnerability Assessment"
    SERVICES = "4. Service Modules"
    CREDENTIALS = "5. Credential Toolkit"
    EXPLOITATION = "6. Exploitation Interface"
    REPORTING = "7. AI-Assisted Reporting"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> float:
        return {
            "info": 0.0,
            "low": 3.9,
            "medium": 6.9,
            "high": 8.9,
            "critical": 10.0,
        }[self.value]


@dataclass
class Finding:
    """A single result worth recording / reporting."""

    title: str
    target: str
    severity: Severity = Severity.INFO
    module: str = ""
    phase: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cve: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["severity"] = self.severity.value
        return d


@dataclass
class Event:
    """A progress/log message emitted during a run (not a persisted finding)."""

    message: str
    level: str = "info"  # info|warn|error|success


@dataclass
class ModuleInput:
    """Declares one parameter a module accepts, so the GUI can render a form."""

    key: str
    label: str
    kind: str = "text"  # text|int|float|bool|choice|file|password|multiline
    default: Any = ""
    choices: list[str] = field(default_factory=list)
    help: str = ""
    required: bool = True


class ModuleContext:
    """Everything a module needs from the framework, injected at run time."""

    def __init__(self, workspace, throttle, on_event: Optional[Callable] = None):
        self.workspace = workspace
        self.throttle = throttle
        self._on_event = on_event

    # Convenience passthroughs -------------------------------------------
    @property
    def scope(self):
        return self.workspace.scope

    @property
    def audit(self):
        return self.workspace.audit

    @property
    def settings(self):
        return self.workspace.config.settings

    @property
    def cancel(self):
        return self.throttle.cancel

    def emit(self, message: str, level: str = "info") -> None:
        if self._on_event:
            self._on_event(Event(message, level))

    def gate(self, tokens: float = 1.0) -> bool:
        """Rate-limit gate. Returns False if cancelled."""
        return self.throttle.gate(tokens)


class BaseModule:
    """Subclass this to add a capability. Set the class attributes and
    implement :meth:`run`."""

    id: str = ""
    name: str = ""
    phase: Phase = Phase.PASSIVE_RECON
    description: str = ""
    # Does this module require an authz grant before running? If set, the
    # framework enforces the grant (e.g. "bruteforce", "exploit").
    requires_authz: Optional[str] = None
    # Marks modules that are OFF by default even when present (brute force).
    disabled_by_default: bool = False
    inputs: list[ModuleInput] = []

    def run(self, ctx: ModuleContext, params: dict[str, Any]) -> Iterator[Finding]:
        """Perform the work. Yield Finding objects. Use ``ctx.emit`` for
        progress, ``ctx.scope.require`` before touching a target, and
        ``ctx.gate()`` to honour the rate limit. Must respect ``ctx.cancel``."""
        raise NotImplementedError
