"""Vulnerability assessment: CVE/CWE matching.

Correlates the product/version data already gathered in the workspace service
inventory against:

  * a small bundled signature set (offline, always available), and
  * the NVD CVE API 2.0 (online, keyless but rate-limited) when reachable.

This is detection/matching only — it maps known versions to known CVEs so the
report can prioritise. It does NOT exploit anything.
"""

from __future__ import annotations

import json
import re
from typing import Iterator

from aya.core import net
from aya.core.config import data_dir
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity


def _load_signatures() -> list[dict]:
    """Load the bundled offline CVE signature set."""
    f = data_dir() / "cve_signatures.json"
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def _version_tuple(v: str):
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:4]) or (0,)


def _match_version(found: str, rule: dict) -> bool:
    fv = _version_tuple(found)
    if "lt" in rule and not (fv < _version_tuple(rule["lt"])):
        return False
    if "le" in rule and not (fv <= _version_tuple(rule["le"])):
        return False
    if "ge" in rule and not (fv >= _version_tuple(rule["ge"])):
        return False
    if "eq" in rule and fv != _version_tuple(rule["eq"]):
        return False
    return True


@register
class CveMatchModule(BaseModule):
    id = "vuln.cve_match"
    name = "CVE / CWE Matching"
    phase = Phase.VULN_ASSESS
    description = "Match discovered service versions to known CVEs (offline + NVD)."
    inputs = [
        ModuleInput("target", "Host (blank = all hosts in project)", default="",
                    required=False),
        ModuleInput("use_nvd", "Also query NVD online", kind="bool", default=False,
                    required=False, help="Uses the public NVD API (slow, rate-limited)."),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        host = params.get("target", "").strip()
        services = ctx.workspace.services(host or None)
        services = [s for s in services if s.get("product")]
        if not services:
            yield Finding(title="No service versions available to match",
                          target=host or "project", severity=Severity.INFO,
                          description="Run Service/Version Detection first.")
            return

        sigs = _load_signatures()
        ctx.emit(f"Matching {len(services)} service(s) against "
                 f"{len(sigs)} offline signature(s).", "info")

        for svc in services:
            product = (svc.get("product") or "").lower()
            version = svc.get("version") or ""
            svc_host = svc.get("host")
            for sig in sigs:
                if sig["product"].lower() not in product:
                    continue
                if not _match_version(version, sig.get("version", {})):
                    continue
                sev = Severity(sig.get("severity", "medium"))
                yield Finding(
                    title=f"{sig['cve']}: {sig['title']}",
                    target=svc_host, severity=sev,
                    description=sig.get("description", ""),
                    evidence=f"{svc.get('product')} {version} on port {svc.get('port')}",
                    remediation=sig.get("remediation", "Upgrade to a fixed version."),
                    cve=[sig["cve"]], cwe=sig.get("cwe", []),
                    refs=sig.get("refs", []),
                    data={"port": svc.get("port"), "source": "offline-signature"},
                )

            if params.get("use_nvd") and product:
                yield from self._nvd(ctx, svc_host, product, version, svc.get("port"))

    def _nvd(self, ctx, host, product, version, port) -> Iterator[Finding]:
        if ctx.cancel.is_set() or not ctx.gate():
            return
        kw = product.split("/")[0].strip()
        url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?keywordSearch={kw}%20{version}&resultsPerPage=5")
        try:
            res = net.http_get(url, ctx.settings, timeout=30)
            data = json.loads(res.text)
        except Exception as e:
            ctx.emit(f"NVD lookup failed for {kw}: {e}", "warn")
            return
        for item in data.get("vulnerabilities", [])[:5]:
            cve = item.get("cve", {})
            cid = cve.get("id", "CVE-?")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score, sev = self._cvss(metrics)
            yield Finding(
                title=f"{cid} (NVD keyword match for {kw} {version})",
                target=host, severity=sev,
                description=desc[:500],
                remediation="Review applicability and patch if confirmed.",
                cve=[cid], refs=[f"https://nvd.nist.gov/vuln/detail/{cid}"],
                data={"cvss": score, "port": port, "source": "nvd",
                      "note": "keyword match — verify version applicability"},
            )

    @staticmethod
    def _cvss(metrics) -> tuple[float, Severity]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0]["cvssData"].get("baseScore", 0.0)
                if score >= 9:
                    return score, Severity.CRITICAL
                if score >= 7:
                    return score, Severity.HIGH
                if score >= 4:
                    return score, Severity.MEDIUM
                if score > 0:
                    return score, Severity.LOW
        return 0.0, Severity.INFO
