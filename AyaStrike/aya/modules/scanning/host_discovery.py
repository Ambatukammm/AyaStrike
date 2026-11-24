"""Active scanning: host discovery.

Discovers live hosts across a CIDR/range using TCP connect probes to common
ports (works without root, unlike ICMP) and optional ICMP via the system
``ping`` when available. Every candidate host is scope-checked before probing.
"""

from __future__ import annotations

import ipaddress
import concurrent.futures as cf
from typing import Iterator

from aya.core import net
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

PROBE_PORTS = [80, 443, 22, 445, 3389, 139, 135]


def _expand(target: str) -> list[str]:
    target = target.strip()
    try:
        net_obj = ipaddress.ip_network(target, strict=False)
        hosts = [str(h) for h in net_obj.hosts()]
        return hosts or [str(net_obj.network_address)]
    except ValueError:
        return [target]  # single host / hostname


@register
class HostDiscoveryModule(BaseModule):
    id = "scan.host_discovery"
    name = "Host Discovery"
    phase = Phase.ACTIVE_SCAN
    description = "Find live hosts in a network via TCP probes (no root needed)."
    inputs = [
        ModuleInput("target", "Host / CIDR", help="e.g. 192.168.1.0/24"),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        hosts = _expand(params["target"])
        if len(hosts) > 4096:
            yield Finding(title="Refusing to scan more than /20 at once",
                          target=params["target"], severity=Severity.INFO,
                          description="Narrow the range to stay polite and in scope.")
            return
        ctx.emit(f"Probing {len(hosts)} address(es)…", "info")
        live: list[str] = []
        timeout = ctx.settings.connect_timeout

        def probe(ip: str):
            if ctx.cancel.is_set() or not ctx.gate():
                return None
            try:
                ctx.scope.require(ip)
            except Exception:
                return None  # silently skip out-of-scope hosts in a range
            for port in PROBE_PORTS:
                if net.tcp_connect(ip, port, timeout):
                    return ip
            return None

        workers = max(1, ctx.settings.max_concurrency)
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            for result in ex.map(probe, hosts):
                if result:
                    live.append(result)
                    hn = net.reverse_dns(result)
                    ctx.workspace.upsert_host(result, hostname=hn)
                    ctx.emit(f"  live: {result} {('('+hn+')') if hn else ''}", "success")

        yield Finding(
            title=f"{len(live)} live host(s) discovered",
            target=params["target"],
            severity=Severity.INFO,
            description="Hosts responded on at least one common TCP port.",
            evidence="\n".join(live),
            data={"live_hosts": live},
        )
