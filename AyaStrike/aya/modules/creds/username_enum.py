"""Credential toolkit: username format generation.

Given a list of real names and a format template, generates candidate usernames
(e.g. jsmith, john.smith, smithj). This is purely OFFLINE string generation — it
does not contact any service. Useful for building a target list that a human
then validates through authorised means.
"""

from __future__ import annotations

from typing import Iterator

from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

FORMATS = {
    "flast": lambda f, l: f"{f[0]}{l}",
    "first.last": lambda f, l: f"{f}.{l}",
    "firstl": lambda f, l: f"{f}{l[0]}",
    "lastf": lambda f, l: f"{l}{f[0]}",
    "last.first": lambda f, l: f"{l}.{f}",
    "first_last": lambda f, l: f"{f}_{l}",
    "first": lambda f, l: f,
    "f.last": lambda f, l: f"{f[0]}.{l}",
}


@register
class UsernameEnumModule(BaseModule):
    id = "cred.username_enum"
    name = "Username Generator"
    phase = Phase.CREDENTIALS
    description = "Generate username candidates from real names (offline)."
    inputs = [
        ModuleInput("names", "Full names", kind="multiline",
                    help="One 'First Last' per line."),
        ModuleInput("formats", "Formats", default="flast,first.last,firstl",
                    required=False, help=f"Comma list from: {', '.join(FORMATS)}"),
        ModuleInput("domain", "Append @domain", default="", required=False),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        names = [n.strip() for n in params["names"].splitlines() if n.strip()]
        fmts = [f.strip() for f in params.get("formats", "").split(",") if f.strip()]
        fmts = [f for f in fmts if f in FORMATS] or ["flast", "first.last"]
        domain = params.get("domain", "").strip().lstrip("@")

        usernames: list[str] = []
        for name in names:
            parts = name.lower().replace(",", " ").split()
            if len(parts) < 2:
                first, last = parts[0], parts[0]
            else:
                first, last = parts[0], parts[-1]
            for fmt in fmts:
                try:
                    u = FORMATS[fmt](first, last)
                except Exception:
                    continue
                if domain:
                    u = f"{u}@{domain}"
                if u not in usernames:
                    usernames.append(u)

        yield Finding(
            title=f"Generated {len(usernames)} username candidate(s)",
            target=domain or "offline", severity=Severity.INFO,
            description="Offline generation only; validate via authorised channels.",
            evidence="\n".join(usernames),
            data={"usernames": usernames},
        )
