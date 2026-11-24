"""Active scanning: web directory/content discovery.

Requests a wordlist of common paths against a base URL and records which ones
return non-404 responses. Rate-limited and scope-checked. This is content
discovery, not exploitation — it does not submit forms, fuzz parameters, or
attempt injection.
"""

from __future__ import annotations

from urllib.parse import urlparse
from typing import Iterator

from aya.core import net
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".env", "admin", "login",
    "wp-login.php", "wp-admin/", "administrator/", "phpmyadmin/", "server-status",
    "backup/", "backup.zip", "config.php", "config.json", ".htaccess",
    "api/", "api/v1/", "swagger.json", "swagger-ui/", "actuator/health",
    "actuator/env", "console/", "test/", "dev/", "old/", "uploads/", "static/",
    "debug/", "status", ".well-known/security.txt",
]


@register
class WebDirScanModule(BaseModule):
    id = "scan.web_dirscan"
    name = "Web Directory Discovery"
    phase = Phase.ACTIVE_SCAN
    description = "Probe common web paths for exposed content (content discovery)."
    inputs = [
        ModuleInput("target", "Base URL", help="e.g. https://test.lab.example"),
        ModuleInput("wordlist", "Custom wordlist file", kind="file", default="",
                    required=False, help="Optional. One path per line."),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        base = params["target"].strip().rstrip("/")
        host = urlparse(base).hostname or base
        ctx.scope.require(host)

        paths = list(COMMON_PATHS)
        wl = params.get("wordlist", "")
        if wl:
            try:
                paths = [l.strip() for l in open(wl, encoding="utf-8") if l.strip()]
            except OSError:
                ctx.emit(f"Could not read {wl}; using built-in list.", "warn")

        ctx.emit(f"Probing {len(paths)} paths on {base}", "info")
        hits = []
        sensitive = []
        for path in paths:
            if ctx.cancel.is_set() or not ctx.gate():
                break
            url = f"{base}/{path}"
            try:
                res = net.http_get(url, ctx.settings, verify=False,
                                   allow_redirects=False)
            except Exception:
                continue
            if res.status in (404, 400):
                continue
            hits.append((path, res.status))
            ctx.emit(f"  {res.status}  /{path}", "success")
            # Flag classically sensitive exposures.
            if any(s in path for s in (".git", ".env", "backup", "config",
                                       "actuator/env", "phpmyadmin")):
                if res.status in (200, 301, 302, 403):
                    sensitive.append((path, res.status))

        if sensitive:
            yield Finding(
                title=f"Potentially sensitive paths exposed on {host}",
                target=host, severity=Severity.MEDIUM,
                description="Paths that often expose secrets or admin surface responded.",
                evidence="\n".join(f"{s}  /{p}" for p, s in sensitive),
                remediation="Block access to VCS metadata, env/config files, and "
                            "management endpoints; return 404 for them.",
                cwe=["CWE-538"], refs=[f"{base}/{p}" for p, _ in sensitive],
            )
        yield Finding(
            title=f"{len(hits)} web path(s) responded on {host}",
            target=host, severity=Severity.INFO,
            evidence="\n".join(f"{s}  /{p}" for p, s in hits),
            data={"hits": hits},
        )
