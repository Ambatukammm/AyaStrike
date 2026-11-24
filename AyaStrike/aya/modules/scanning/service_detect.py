"""Active scanning: service/version detection and OS fingerprinting.

Service detection grabs banners from known-open ports and sends light,
protocol-appropriate probes (e.g. an HTTP HEAD) to identify the product and
version. OS fingerprinting delegates to nmap's ``-O`` (which needs raw sockets /
admin) and simply reports when that is unavailable rather than guessing.
"""

from __future__ import annotations

from typing import Iterator

from aya.core import net, runner
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8088, 3000, 9000}
HTTPS_PORTS = {443, 8443, 9443}

PROBES = {
    "http": b"HEAD / HTTP/1.0\r\n\r\n",
    "ftp": b"",
    "ssh": b"",
    "smtp": b"",
}


@register
class ServiceDetectModule(BaseModule):
    id = "scan.service_detect"
    name = "Service / Version Detection"
    phase = Phase.ACTIVE_SCAN
    description = "Banner-grab open ports to identify service product/version."
    inputs = [
        ModuleInput("target", "Host / IP"),
        ModuleInput("ports", "Ports (blank = known open from DB)", default="",
                    required=False, help="Comma list, or blank to use DB inventory."),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        host = params["target"].strip()
        ctx.scope.require(host)
        spec = params.get("ports", "").strip()
        if spec:
            ports = [int(p) for p in spec.replace(" ", "").split(",") if p]
        else:
            ports = [s["port"] for s in ctx.workspace.services(host)]
            if not ports:
                yield Finding(title="No known ports to probe", target=host,
                              severity=Severity.INFO,
                              description="Run a port scan first, or specify ports.")
                return

        timeout = ctx.settings.read_timeout
        for port in ports:
            if ctx.cancel.is_set() or not ctx.gate():
                break
            if port in HTTPS_PORTS:
                banner = self._https_banner(host, port, ctx)
            else:
                probe = PROBES.get("http") if port in HTTP_PORTS else b""
                banner = net.grab_banner(host, port, timeout, probe=probe or b"")
            if not banner:
                continue
            product, version = self._parse(banner)
            ctx.workspace.upsert_service(host, port, "tcp",
                                         product=product, version=version,
                                         extra=banner[:200])
            ctx.emit(f"  {port}/tcp: {product} {version}".rstrip(), "success")
            yield Finding(
                title=f"Service on {host}:{port} — {product} {version}".rstrip(),
                target=host, severity=Severity.INFO,
                description="Banner/version detected.",
                evidence=banner[:1000],
                data={"port": port, "product": product, "version": version},
            )

    def _https_banner(self, host, port, ctx) -> str:
        try:
            res = net.http_get(f"https://{host}:{port}/", ctx.settings,
                               verify=False, allow_redirects=False)
            server = res.headers.get("Server", "")
            powered = res.headers.get("X-Powered-By", "")
            return f"HTTP {res.status} Server: {server} {powered}".strip()
        except Exception:
            return ""

    @staticmethod
    def _parse(banner: str) -> tuple[str, str]:
        import re
        m = re.search(r"Server:\s*([^\r\n]+)", banner, re.I)
        if m:
            token = m.group(1).strip()
            parts = token.split("/", 1)
            return parts[0], (parts[1] if len(parts) > 1 else "")
        # SSH / FTP style banners
        m = re.match(r"(SSH-[\d.]+-[^\s]+)", banner)
        if m:
            return m.group(1), ""
        first = banner.splitlines()[0] if banner else ""
        return first[:60], ""


@register
class OsFingerprintModule(BaseModule):
    id = "scan.os_fingerprint"
    name = "OS Fingerprint (nmap -O)"
    phase = Phase.ACTIVE_SCAN
    description = "OS detection via nmap (requires nmap + admin/root privileges)."
    inputs = [ModuleInput("target", "Host / IP")]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        host = params["target"].strip()
        ctx.scope.require(host)
        cmd = [ctx.settings.nmap_path or "nmap", "-O", "-Pn", host]
        ctx.emit("Launching: " + " ".join(cmd), "info")
        try:
            result = runner.run(cmd, timeout=600,
                                on_line=lambda l: ctx.emit(l, "info"),
                                cancel=ctx.cancel)
        except runner.ToolNotFound as e:
            yield Finding(title="nmap not installed", target=host,
                          severity=Severity.INFO, description=str(e))
            return
        os_guess = ""
        for line in result.lines:
            if "OS details:" in line or "Running:" in line:
                os_guess = line.split(":", 1)[1].strip()
                break
        if os_guess:
            ctx.workspace.upsert_host(host, os_=os_guess)
        yield Finding(
            title=f"OS fingerprint for {host}: {os_guess or 'inconclusive'}",
            target=host, severity=Severity.INFO,
            evidence=result.stdout[:8000],
            description="nmap -O requires raw-socket privileges; run as admin/root.",
        )
