"""Risk scoring and attack-path correlation.

Pure functions over a project's findings so they can be unit-tested and reused
by both the report module and the GUI dashboard.
"""

from __future__ import annotations

from collections import defaultdict

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 10.0, "high": 8.0, "medium": 5.0, "low": 2.0, "info": 0.0}


def risk_score(findings: list[dict]) -> dict:
    """Aggregate a 0-100 risk score and severity breakdown."""
    counts = defaultdict(int)
    weighted = 0.0
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] += 1
        weighted += SEV_WEIGHT.get(sev, 0.0)
    # Normalise with diminishing returns so one critical doesn't peg it to 100
    # but many criticals clearly do.
    raw = weighted
    score = 100 * (1 - (0.93 ** raw)) if raw > 0 else 0.0
    if counts["critical"]:
        score = max(score, 75 + min(counts["critical"], 5) * 5)
    score = round(min(score, 100.0), 1)
    rating = ("Critical" if score >= 80 else "High" if score >= 60 else
              "Medium" if score >= 35 else "Low" if score > 0 else "Informational")
    return {
        "score": score,
        "rating": rating,
        "counts": {s: counts.get(s, 0) for s in SEV_ORDER},
        "total": len(findings),
    }


def correlate_attack_paths(findings: list[dict]) -> list[dict]:
    """Heuristically link findings into candidate attack paths per host.

    Produces human-readable chains like:
      exposed service -> known CVE / weak cred -> potential foothold
    This is a planning aid for the human operator, not an automated attack.
    """
    by_host: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_host[f.get("target", "unknown")].append(f)

    paths = []
    for host, fs in by_host.items():
        has_exposed = [f for f in fs if "exposed" in f.get("title", "").lower()
                       or f.get("phase", "").startswith("2")]
        has_cve = [f for f in fs if f.get("cve")]
        has_cred = [f for f in fs if "credential" in f.get("title", "").lower()
                    or "password" in f.get("title", "").lower()]
        has_web = [f for f in fs if "header" in f.get("title", "").lower()
                   or "cookie" in f.get("title", "").lower()
                   or "cors" in f.get("title", "").lower()]
        severities = [f.get("severity", "info") for f in fs]
        top = next((s for s in SEV_ORDER if s in severities), "info")

        steps = []
        if has_exposed:
            steps.append(f"Reachable service(s): " +
                         ", ".join(sorted({f["title"] for f in has_exposed}))[:160])
        if has_cve:
            cves = sorted({c for f in has_cve for c in f.get("cve", [])})
            steps.append("Known vulnerabilities: " + ", ".join(cves))
        if has_cred:
            steps.append("Weak/valid credentials identified")
        if has_web:
            steps.append("Web security weaknesses present")

        if len(steps) >= 2:  # only report a path if there's an actual chain
            paths.append({
                "host": host,
                "severity": top,
                "steps": steps,
                "narrative": " → ".join(steps),
            })
    paths.sort(key=lambda p: SEV_ORDER.index(p["severity"]))
    return paths
