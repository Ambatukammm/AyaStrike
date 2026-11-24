"""Service module: wireless assessment (passive survey).

A READ-ONLY survey of nearby Wi-Fi networks using the operating system's own
tooling (``netsh wlan show networks`` on Windows, ``nmcli``/``iw`` on Linux).
It reports SSIDs, signal, and encryption type so an assessor can spot open or
WEP networks.

It deliberately does NOT perform active attacks (deauthentication, handshake
capture/cracking, evil-twin). Those require explicit, separate tooling and are
out of scope for this suite by design.
"""

from __future__ import annotations

import platform
from typing import Iterator

from aya.core import runner
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity


@register
class WirelessSurveyModule(BaseModule):
    id = "svc.wireless_survey"
    name = "Wireless Survey (passive)"
    phase = Phase.SERVICES
    description = "List nearby Wi-Fi networks and encryption via OS tools (read-only)."
    inputs = [
        ModuleInput("note", "Engagement note", default="", required=False,
                    help="Optional note recorded with this survey."),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        system = platform.system()
        ctx.emit(f"Running wireless survey on {system}…", "info")
        if system == "Windows":
            cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
        elif system == "Linux":
            cmd = ["nmcli", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list"]
        elif system == "Darwin":
            cmd = ["/System/Library/PrivateFrameworks/Apple80211.framework/"
                   "Versions/Current/Resources/airport", "-s"]
        else:
            yield Finding(title="Unsupported OS for wireless survey",
                          target="local", severity=Severity.INFO)
            return

        try:
            result = runner.run(cmd, timeout=60,
                                on_line=lambda l: ctx.emit(l, "info"))
        except runner.ToolNotFound as e:
            yield Finding(title="Wireless tool not available", target="local",
                          severity=Severity.INFO, description=str(e),
                          remediation="Ensure a Wi-Fi adapter and OS Wi-Fi tooling exist.")
            return

        out = result.stdout
        low = out.lower()
        open_nets = low.count("security : open") + low.count("  open")
        wep = low.count("wep")
        sev = Severity.INFO
        if wep:
            sev = Severity.MEDIUM
        yield Finding(
            title="Wireless survey results", target="local", severity=sev,
            description=(f"Open networks seen: ~{open_nets}; WEP references: {wep}. "
                         "Open/WEP networks are high risk."),
            evidence=out[:8000],
            remediation="Prefer WPA2/WPA3; retire open and WEP networks.",
            cwe=["CWE-326"] if (wep or open_nets) else [],
            data={"note": params.get("note", "")},
        )
