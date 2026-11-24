"""Passive recon: WHOIS lookup.

Queries WHOIS directly over TCP/43 (no third-party CLI required). WHOIS is a
public, passive lookup — it does not touch the target host itself — but we still
log it. Registry referral is followed one hop for richer registrar data.
"""

from __future__ import annotations

import socket
from typing import Iterator

from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

IANA_WHOIS = "whois.iana.org"


def _whois_query(server: str, query: str, timeout: float) -> str:
    try:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall((query + "\r\n").encode("idna", "ignore") if False
                      else (query + "\r\n").encode("utf-8"))
            chunks = []
            s.settimeout(timeout)
            while True:
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks).decode("utf-8", "replace")
    except OSError as e:
        return f"[whois error: {e}]"


def _referral_server(text: str) -> str:
    for line in text.splitlines():
        low = line.lower()
        if "whois:" in low or "referralserver" in low or "registrar whois server" in low:
            parts = line.split(":", 1)
            if len(parts) == 2:
                val = parts[1].strip().replace("rwhois://", "").replace("whois://", "")
                return val.split("/")[0].strip()
    return ""


@register
class WhoisModule(BaseModule):
    id = "recon.whois"
    name = "WHOIS Lookup"
    phase = Phase.PASSIVE_RECON
    description = "Domain/IP registration data via WHOIS (passive, port 43)."
    inputs = [
        ModuleInput("target", "Domain or IP", help="e.g. example.com or 203.0.113.5"),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        target = params["target"].strip()
        timeout = ctx.settings.connect_timeout + 5
        ctx.emit(f"WHOIS: resolving authoritative server for {target}", "info")

        # Start at IANA to find the authoritative server, then referral hop.
        root = _whois_query(IANA_WHOIS, target, timeout)
        server = _referral_server(root) or IANA_WHOIS
        text = root
        if server and server != IANA_WHOIS:
            ctx.gate()
            ctx.emit(f"WHOIS: querying {server}", "info")
            text = _whois_query(server, target, timeout)
            ref2 = _referral_server(text)
            if ref2 and ref2 != server:
                ctx.gate()
                text = _whois_query(ref2, target, timeout) or text
                server = ref2

        yield Finding(
            title=f"WHOIS record for {target}",
            target=target,
            severity=Severity.INFO,
            description=f"WHOIS data retrieved from {server}.",
            evidence=text[:8000],
            data={"server": server},
        )
