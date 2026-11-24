"""Plugin registry and discovery.

Modules register themselves with ``@register`` at import time. ``discover()``
imports every submodule under ``aya.modules.*`` so decorators fire, then returns
the registry. External/third-party plugins can be dropped into the user's
``~/.ayastrike/plugins`` directory and are loaded too.

Running a module goes through :func:`execute`, which centralises scope
enforcement, authorisation checks, audit logging, and cancellation so no
individual module can forget them.
"""

from __future__ import annotations

import importlib
import importlib.util
import pkgutil
import sys
import traceback
from pathlib import Path
from typing import Any, Callable, Iterator, Type

from aya.core import config
from aya.core.authz import NotAuthorised
from aya.core.scope import ScopeViolation
from aya.modules.base import BaseModule, Finding, ModuleContext


_REGISTRY: dict[str, Type[BaseModule]] = {}


def register(cls: Type[BaseModule]) -> Type[BaseModule]:
    """Class decorator that adds a module to the registry."""
    if not getattr(cls, "id", ""):
        raise ValueError(f"{cls.__name__} must define a unique 'id'")
    if cls.id in _REGISTRY and _REGISTRY[cls.id] is not cls:
        raise ValueError(f"duplicate module id: {cls.id}")
    _REGISTRY[cls.id] = cls
    return cls


def _import_builtin_modules() -> None:
    import aya.modules as pkg

    for mod in pkgutil.walk_packages(pkg.__path__, prefix="aya.modules."):
        if mod.name.endswith(".base"):
            continue
        try:
            importlib.import_module(mod.name)
        except Exception:  # pragma: no cover - a broken plugin shouldn't crash app
            sys.stderr.write(f"[plugins] failed to import {mod.name}:\n")
            traceback.print_exc()


def _import_user_plugins() -> None:
    plugin_dir = config.app_home() / "plugins"
    plugin_dir.mkdir(parents=True, exist_ok=True)
    for path in plugin_dir.glob("*.py"):
        name = f"aya_user_plugin_{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
        except Exception:  # pragma: no cover
            sys.stderr.write(f"[plugins] failed to load user plugin {path}:\n")
            traceback.print_exc()


_discovered = False


def discover(reload: bool = False) -> dict[str, Type[BaseModule]]:
    global _discovered
    if _discovered and not reload:
        return _REGISTRY
    _import_builtin_modules()
    _import_user_plugins()
    _discovered = True
    return _REGISTRY


def registry() -> dict[str, Type[BaseModule]]:
    return discover()


def by_phase() -> dict[str, list[Type[BaseModule]]]:
    out: dict[str, list[Type[BaseModule]]] = {}
    for cls in discover().values():
        out.setdefault(cls.phase.value, []).append(cls)
    for lst in out.values():
        lst.sort(key=lambda c: c.name)
    return out


def get(module_id: str) -> Type[BaseModule]:
    return discover()[module_id]


def execute(
    module_id: str,
    workspace,
    params: dict[str, Any],
    throttle,
    on_event: Callable | None = None,
    on_finding: Callable | None = None,
) -> list[Finding]:
    """Run a module with all framework guarantees enforced around it.

    Raises ScopeViolation / NotAuthorised which the caller should surface.
    """
    cls = get(module_id)
    inst = cls()

    # Authorisation gate for intrusive modules.
    if inst.requires_authz:
        try:
            workspace.authz.require(inst.requires_authz)
        except NotAuthorised:
            workspace.audit.log(
                "authz_denied",
                module=module_id,
                detail={"capability": inst.requires_authz},
                severity="warn",
            )
            raise

    workspace.audit.log(
        "module_start",
        module=module_id,
        detail={"params": _redact(params)},
    )

    ctx = ModuleContext(workspace, throttle, on_event=on_event)
    findings: list[Finding] = []
    try:
        for finding in inst.run(ctx, params):
            finding.module = finding.module or module_id
            finding.phase = finding.phase or cls.phase.value
            findings.append(finding)
            workspace.add_finding(finding)
            if on_finding:
                on_finding(finding)
    except ScopeViolation as exc:
        workspace.audit.log(
            "scope_violation",
            target=exc.target,
            module=module_id,
            detail={"reason": exc.reason},
            severity="critical",
        )
        raise
    except Exception as exc:  # pragma: no cover - surface, don't crash
        workspace.audit.log(
            "module_error",
            module=module_id,
            detail={"error": str(exc)},
            severity="error",
        )
        raise
    finally:
        workspace.audit.log(
            "module_end",
            module=module_id,
            detail={"findings": len(findings)},
        )
    return findings


def _redact(params: dict[str, Any]) -> dict[str, Any]:
    """Keep secrets out of the audit log."""
    redacted = {}
    for k, v in params.items():
        if any(s in k.lower() for s in ("pass", "secret", "key", "token", "hash")):
            redacted[k] = "***"
        else:
            redacted[k] = v
    return redacted
