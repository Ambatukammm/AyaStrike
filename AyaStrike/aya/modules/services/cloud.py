"""Service module: cloud exposure checks.

Checks whether cloud storage buckets named after an organisation are publicly
readable/listable across AWS S3, Google Cloud Storage, and Azure Blob. For each
candidate bucket name it resolves the provider hostname, scope-checks that
hostname, then issues a single GET. It reports public/listable buckets.

This is exposure detection, not data exfiltration — it reports that a bucket is
public and shows only the listing/first bytes as evidence.
"""

from __future__ import annotations

from typing import Iterator

from aya.core import net
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

PROVIDERS = {
    "AWS S3": "https://{name}.s3.amazonaws.com/",
    "GCS": "https://storage.googleapis.com/{name}/",
    "Azure Blob": "https://{name}.blob.core.windows.net/?comp=list",
}


def _candidates(base: str) -> list[str]:
    base = base.strip().lower()
    suffixes = ["", "-prod", "-dev", "-staging", "-backup", "-backups", "-assets",
                "-static", "-data", "-media", "-public", "-private", "-logs"]
    return [f"{base}{s}" for s in suffixes]


@register
class CloudExposureModule(BaseModule):
    id = "svc.cloud_exposure"
    name = "Cloud Bucket Exposure"
    phase = Phase.SERVICES
    description = "Detect public S3/GCS/Azure buckets for an org name (exposure only)."
    inputs = [
        ModuleInput("target", "Org / bucket base name", help="e.g. acme or acme-corp"),
        ModuleInput("permutations", "Try name permutations", kind="bool",
                    default=True, required=False),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        base = params["target"].strip()
        names = _candidates(base) if params.get("permutations", True) else [base]
        ctx.emit(f"Checking {len(names)} name(s) across {len(PROVIDERS)} providers…",
                 "info")
        found = 0
        for name in names:
            for provider, tmpl in PROVIDERS.items():
                if ctx.cancel.is_set() or not ctx.gate():
                    return
                url = tmpl.format(name=name)
                host = url.split("/")[2]
                try:
                    ctx.scope.require(host)
                except Exception:
                    # Provider hostnames are public infra; allow by default but
                    # only if scope isn't strictly enforced to a private lab.
                    if ctx.scope.enforce and not ctx.scope.is_in_scope(host):
                        ctx.emit(f"  (skipped out-of-scope {host})", "warn")
                        continue
                try:
                    res = net.http_get(url, ctx.settings, verify=True,
                                       allow_redirects=False)
                except Exception:
                    continue
                public = res.status == 200 and (
                    "<ListBucketResult" in res.text or "<EnumerationResults" in res.text
                    or "<?xml" in res.text[:64])
                if public:
                    found += 1
                    yield Finding(
                        title=f"Public cloud bucket: {provider} '{name}'",
                        target=host, severity=Severity.HIGH,
                        description=f"{provider} bucket is publicly listable.",
                        evidence=res.text[:600],
                        remediation="Make the bucket private; block public ACLs/policy; "
                                    "enable provider public-access-block.",
                        cwe=["CWE-732"], refs=[url],
                        data={"provider": provider, "name": name},
                    )
                    ctx.emit(f"  PUBLIC: {provider} {name}", "error")
                elif res.status in (403,):
                    ctx.emit(f"  exists but private: {provider} {name}", "info")
        if found == 0:
            yield Finding(title=f"No public buckets found for '{base}'",
                          target=base, severity=Severity.INFO)
