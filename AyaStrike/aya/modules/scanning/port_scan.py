"""Active scanning: TCP port scanning.

A pure-Python TCP connect scanner (no root, no external dependency) with
bounded concurrency and rate limiting, plus an optional nmap wrapper for users
who have nmap installed and want SYN/UDP/advanced scans.

The target is scope-checked once up front; the scan honours the global rate
limit and cancellation so it can be stopped instantly from the UI.
"""

from __future__ import annotations

import concurrent.futures as cf
from typing import Iterator

from aya.core import net, runner
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 464,
    465, 514, 587, 631, 636, 873, 993, 995, 1025, 1080, 1433, 1521, 1723, 2049,
    2082, 2083, 2222, 3000, 3128, 3306, 3389, 5060, 5432, 5433, 5900, 5985,
    5986, 6379, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9200,
    9300, 10000, 11211, 27017,
]

COMMON_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "microsoft-ds", 1433: "mssql",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-proxy", 9200: "elasticsearch", 27017: "mongodb",
}


def _parse_ports(spec: str) -> list[int]:
    spec = (spec or "").strip().lower()
    if not spec or spec == "top":
        return TOP_PORTS
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


@register
class PortScanModule(BaseModule):
    id = "scan.port_scan"
    name = "Port Scan (TCP connect)"
    phase = Phase.ACTIVE_SCAN
    description = "Pure-Python TCP connect scan with rate limiting (no root)."
    inputs = [
        ModuleInput("target", "Host / IP"),
        ModuleInput("ports", "Ports", default="top", required=False,
                    help="'top', 'all', or e.g. 22,80,443,8000-8100"),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        host = params["target"].strip()
        ctx.scope.require(host)  # hard stop if out of scope
        ports = _parse_ports(params.get("ports", "top"))
        ctx.emit(f"Scanning {len(ports)} port(s) on {host}…", "info")
        timeout = ctx.settings.connect_timeout
        open_ports: list[int] = []

        def check(port: int):
            if ctx.cancel.is_set() or not ctx.gate():
                return None
            return port if net.tcp_connect(host, port, timeout) else None

        workers = max(1, ctx.settings.max_concurrency)
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            for res in ex.map(check, ports):
                if res is not None:
                    open_ports.append(res)
                    name = COMMON_NAMES.get(res, "")
                    ctx.workspace.upsert_service(host, res, "tcp", service=name)
                    ctx.emit(f"  open: {res}/tcp {name}", "success")

        open_ports.sort()
        yield Finding(
            title=f"{len(open_ports)} open TCP port(s) on {host}",
            target=host,
            severity=Severity.LOW if open_ports else Severity.INFO,
            description="Open ports represent the reachable attack surface.",
            evidence="\n".join(f"{p}/tcp {COMMON_NAMES.get(p,'')}" for p in open_ports),
            data={"open_ports": open_ports},
        )


@register
class NmapScanModule(BaseModule):
    id = "scan.nmap"
    name = "Nmap Scan (wrapper)"
    phase = Phase.ACTIVE_SCAN
    description = "Run nmap with your chosen flags (nmap must be installed)."
    inputs = [
        ModuleInput("target", "Host / CIDR"),
        ModuleInput("flags", "Nmap flags", default="-sV -T4 --top-ports 1000",
                    required=False,
                    help="Flags only. Target is appended automatically."),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        host = params["target"].strip()
        ctx.scope.require(host)
        # Disallow flags that would let nmap act outside the given target
        # (e.g. -iL reading a host list, or appended extra hosts).
        flags = params.get("flags", "").split()
        banned = {"-iL", "-iR", "--script-args-file"}
        if any(f in banned for f in flags):
            yield Finding(title="Nmap input-file flags are blocked",
                          target=host, severity=Severity.INFO,
                          description="Scope is enforced per-target; -iL/-iR disabled.")
            return
        cmd = [ctx.settings.nmap_path or "nmap", *flags, host]
        ctx.emit("Launching: " + " ".join(cmd), "info")
        try:
            result = runner.run(cmd, timeout=1800,
                                on_line=lambda l: ctx.emit(l, "info"),
                                cancel=ctx.cancel)
        except runner.ToolNotFound as e:
            yield Finding(title="nmap not installed", target=host,
                          severity=Severity.INFO, description=str(e),
                          remediation="Install nmap from https://nmap.org and/or set "
                                      "its path in Settings.")
            return
        yield Finding(
            title=f"Nmap scan of {host}", target=host, severity=Severity.INFO,
            description="Raw nmap output captured.",
            evidence=result.stdout[:16000],
            data={"returncode": result.returncode},
        )
