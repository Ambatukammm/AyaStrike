"""Vulnerability assessment: passive web security checks.

Inspects HTTP responses for missing security headers, insecure cookie flags,
information disclosure, and dangerous misconfigurations (directory listing,
exposed version banners). This is a PASSIVE configuration review — it issues
ordinary GET requests and reads the responses. It performs NO injection,
fuzzing, or exploitation.
"""

from __future__ import annotations

from urllib.parse import urlparse
from typing import Iterator

from aya.core import net
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HSTS not set — connections may downgrade to HTTP.",
                                  "CWE-319", Severity.LOW),
    "Content-Security-Policy": ("No CSP — increases XSS impact.", "CWE-1021", Severity.LOW),
    "X-Frame-Options": ("No clickjacking protection (or missing CSP frame-ancestors).",
                        "CWE-1021", Severity.LOW),
    "X-Content-Type-Options": ("MIME sniffing not disabled.", "CWE-16", Severity.INFO),
    "Referrer-Policy": ("No Referrer-Policy — may leak URLs.", "CWE-200", Severity.INFO),
}


@register
class WebSecurityScanModule(BaseModule):
    id = "vuln.web_scan"
    name = "Web Security Headers / Config"
    phase = Phase.VULN_ASSESS
    description = "Passive review of security headers, cookies, and info disclosure."
    inputs = [ModuleInput("target", "URL", help="e.g. https://test.lab.example")]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        url = params["target"].strip()
        host = urlparse(url).hostname or url
        ctx.scope.require(host)
        ctx.gate()
        try:
            res = net.http_get(url, ctx.settings, verify=False)
        except Exception as e:
            yield Finding(title=f"Could not fetch {url}", target=host,
                          severity=Severity.INFO, description=str(e))
            return

        headers = {k.lower(): v for k, v in res.headers.items()}

        # Missing security headers
        for header, (msg, cwe, sev) in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                yield Finding(
                    title=f"Missing header: {header}", target=host, severity=sev,
                    description=msg, remediation=f"Set the {header} response header.",
                    cwe=[cwe], data={"url": url},
                )

        # Information disclosure via Server / X-Powered-By banners
        for h in ("server", "x-powered-by", "x-aspnet-version"):
            if h in headers and any(c.isdigit() for c in headers[h]):
                yield Finding(
                    title=f"Version disclosure in '{h}' header", target=host,
                    severity=Severity.LOW,
                    description=f"{h}: {headers[h]}",
                    remediation="Suppress version banners to slow down targeted attacks.",
                    cwe=["CWE-200"],
                )

        # Insecure cookies
        set_cookie = res.headers.get("Set-Cookie", "")
        if set_cookie:
            lc = set_cookie.lower()
            problems = []
            if "httponly" not in lc:
                problems.append("missing HttpOnly")
            if "secure" not in lc and url.lower().startswith("https"):
                problems.append("missing Secure")
            if "samesite" not in lc:
                problems.append("missing SameSite")
            if problems:
                yield Finding(
                    title="Insecure cookie flags", target=host, severity=Severity.MEDIUM,
                    description="; ".join(problems),
                    remediation="Set HttpOnly, Secure, and SameSite on session cookies.",
                    cwe=["CWE-1004", "CWE-614"], evidence=set_cookie[:300],
                )

        # Directory listing
        if "<title>index of /" in res.text.lower() or "directory listing for" in res.text.lower():
            yield Finding(
                title="Directory listing enabled", target=host, severity=Severity.MEDIUM,
                description="The server returned an auto-generated directory index.",
                remediation="Disable automatic directory indexing.",
                cwe=["CWE-548"], data={"url": url},
            )

        yield Finding(
            title=f"Web config review complete for {host}", target=host,
            severity=Severity.INFO,
            evidence="Response headers:\n" + "\n".join(
                f"{k}: {v}" for k, v in res.headers.items()),
            data={"status": res.status},
        )
