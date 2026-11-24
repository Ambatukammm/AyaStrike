"""Service module: web application testing interface.

A read-only reconnaissance interface for a web application: enumerates allowed
HTTP methods (OPTIONS), checks CORS policy, looks for a security.txt, and
inspects for common framework fingerprints. It is deliberately NON-intrusive —
it does not fuzz, inject, or authenticate. Use it to orient before manual
testing with a dedicated proxy.
"""

from __future__ import annotations

from urllib.parse import urlparse
from typing import Iterator

from aya.core import net
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity


@register
class WebAppInterfaceModule(BaseModule):
    id = "svc.webapp"
    name = "Web App Recon Interface"
    phase = Phase.SERVICES
    description = "Allowed methods, CORS, security.txt, framework fingerprint (read-only)."
    inputs = [ModuleInput("target", "URL", help="e.g. https://app.lab.example")]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        url = params["target"].strip().rstrip("/")
        host = urlparse(url).hostname or url
        ctx.scope.require(host)

        # --- allowed methods via OPTIONS ---
        ctx.gate()
        try:
            import requests
            r = requests.options(url, headers={"User-Agent": ctx.settings.user_agent},
                                 timeout=ctx.settings.read_timeout, verify=False)
            allow = r.headers.get("Allow", "") or r.headers.get("Access-Control-Allow-Methods", "")
            if allow:
                risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")
                         if m in allow.upper()]
                yield Finding(
                    title=f"HTTP methods allowed on {host}", target=host,
                    severity=Severity.LOW if risky else Severity.INFO,
                    description=f"Allow: {allow}" + (
                        f"  (potentially risky: {', '.join(risky)})" if risky else ""),
                    remediation="Disable unused methods (TRACE, PUT, DELETE) at the server.",
                    cwe=["CWE-650"] if risky else [],
                )
        except Exception as e:
            ctx.emit(f"OPTIONS failed: {e}", "warn")

        # --- CORS policy ---
        ctx.gate()
        try:
            res = net.http_get(url, ctx.settings, verify=False)
            acao = res.headers.get("Access-Control-Allow-Credentials", "")
            origin = res.headers.get("Access-Control-Allow-Origin", "")
            if origin == "*" and acao.lower() == "true":
                yield Finding(
                    title="Dangerous CORS: wildcard origin with credentials",
                    target=host, severity=Severity.HIGH,
                    description="ACAO '*' combined with Allow-Credentials true.",
                    remediation="Reflect only trusted origins; never pair '*' with credentials.",
                    cwe=["CWE-942"],
                )
            # framework fingerprint
            fp = []
            for h in ("x-powered-by", "x-aspnet-version", "x-generator", "server"):
                if h in {k.lower() for k in res.headers}:
                    fp.append(f"{h}: {res.headers.get(h) or res.headers.get(h.title())}")
            if fp:
                yield Finding(title=f"Framework fingerprint for {host}", target=host,
                              severity=Severity.INFO, evidence="\n".join(fp))
        except Exception as e:
            ctx.emit(f"GET failed: {e}", "warn")

        # --- security.txt ---
        ctx.gate()
        for p in (".well-known/security.txt", "security.txt"):
            try:
                res = net.http_get(f"{url}/{p}", ctx.settings, verify=False,
                                   allow_redirects=False)
                if res.status == 200 and "contact" in res.text.lower():
                    yield Finding(title="security.txt present", target=host,
                                  severity=Severity.INFO, evidence=res.text[:500])
                    break
            except Exception:
                continue
