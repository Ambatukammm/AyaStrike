"""AI-assisted reporting: risk scoring, attack paths, remediation, export.

Generates a professional report from the project's findings in HTML, CSV, and
(if reportlab is installed) PDF. The AI layer (local Ollama) writes the
executive summary and consolidates remediation guidance; if Ollama is
unavailable the report falls back to deterministic templated text so it always
produces a complete document.
"""

from __future__ import annotations

import csv
import html
import io
import json
import time
from pathlib import Path
from typing import Iterator

from aya.core import ai
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity
from aya.modules.reporting.risk_engine import risk_score, correlate_attack_paths, SEV_ORDER

SEV_COLOR = {
    "critical": "#b00020", "high": "#e65100", "medium": "#f9a825",
    "low": "#2e7d32", "info": "#546e7a",
}


@register
class ReportModule(BaseModule):
    id = "report.generate"
    name = "Generate Report (AI-assisted)"
    phase = Phase.REPORTING
    description = "Risk score, attack paths, remediation, export to HTML/CSV/PDF."
    inputs = [
        ModuleInput("formats", "Formats", default="html,csv,pdf", required=False,
                    help="Any of: html, csv, pdf"),
        ModuleInput("use_ai", "AI executive summary (local Ollama)", kind="bool",
                    default=True, required=False),
        ModuleInput("client", "Client / engagement name", default="", required=False),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        findings = ctx.workspace.findings()
        if not findings:
            yield Finding(title="No findings to report", target="project",
                          severity=Severity.INFO,
                          description="Run some modules first.")
            return

        risk = risk_score(findings)
        paths = correlate_attack_paths(findings)
        ctx.emit(f"Risk score: {risk['score']}/100 ({risk['rating']})", "info")
        ctx.emit(f"Correlated {len(paths)} candidate attack path(s).", "info")

        # --- AI (or fallback) narrative ---
        summary = ""
        remediation = ""
        if params.get("use_ai", True):
            if ai.available(ctx.settings):
                ctx.emit("Asking local Ollama model for executive summary…", "info")
                summary = ai.generate(self._summary_prompt(risk, findings, paths),
                                      ctx.settings)
                remediation = ai.generate(self._remediation_prompt(findings),
                                          ctx.settings)
            else:
                ctx.emit("Ollama not reachable — using templated narrative.", "warn")
        if not summary:
            summary = self._fallback_summary(risk, paths)
        if not remediation:
            remediation = self._fallback_remediation(findings)

        reportdir = Path(ctx.workspace.root) / "reports"
        reportdir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        base = reportdir / f"report-{stamp}"
        client = params.get("client", "") or ctx.workspace.name

        wanted = {f.strip().lower() for f in params.get("formats", "").split(",")}
        produced = []

        if "html" in wanted:
            p = base.with_suffix(".html")
            p.write_text(self._html(client, risk, findings, paths, summary, remediation),
                         encoding="utf-8")
            produced.append(str(p))
        if "csv" in wanted:
            p = base.with_suffix(".csv")
            self._csv(p, findings)
            produced.append(str(p))
        if "pdf" in wanted:
            p = base.with_suffix(".pdf")
            if self._pdf(p, client, risk, findings, paths, summary, remediation, ctx):
                produced.append(str(p))

        yield Finding(
            title=f"Report generated — risk {risk['score']}/100 ({risk['rating']})",
            target="project", severity=Severity.INFO,
            description="Executive summary and remediation included.",
            evidence="Files:\n" + "\n".join(produced),
            data={"risk": risk, "files": produced, "attack_paths": paths},
        )

    # -- prompts ----------------------------------------------------------
    def _summary_prompt(self, risk, findings, paths) -> str:
        top = [f for f in findings if f["severity"] in ("critical", "high")][:15]
        lines = [f"- [{f['severity']}] {f['title']} ({f['target']})" for f in top]
        pl = [p["narrative"] for p in paths[:8]]
        return (
            f"Write a 150-200 word executive summary for a penetration test report.\n"
            f"Overall risk score: {risk['score']}/100 ({risk['rating']}).\n"
            f"Severity counts: {risk['counts']}.\n"
            f"Top findings:\n" + "\n".join(lines) + "\n"
            f"Attack paths:\n" + "\n".join(pl) + "\n"
            f"Be factual and non-sensational. Do not invent findings."
        )

    def _remediation_prompt(self, findings) -> str:
        items = sorted({(f["title"], f.get("remediation", "")) for f in findings
                        if f.get("remediation")}, key=lambda x: x[0])[:25]
        body = "\n".join(f"- {t}: {r}" for t, r in items)
        return ("Consolidate the following remediation items into a prioritised, "
                "de-duplicated action list grouped by theme (patching, "
                "configuration, credentials, exposure). Keep it concise.\n" + body)

    # -- fallbacks --------------------------------------------------------
    def _fallback_summary(self, risk, paths) -> str:
        c = risk["counts"]
        s = (f"This assessment identified {risk['total']} finding(s): "
             f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, "
             f"{c['low']} low, and {c['info']} informational. The aggregate risk "
             f"rating is {risk['rating']} ({risk['score']}/100). ")
        if paths:
            s += (f"{len(paths)} candidate attack path(s) were correlated, the most "
                  f"severe affecting {paths[0]['host']}. ")
        s += ("Priority should be given to remediating critical and high findings, "
              "particularly exposed services and known vulnerabilities, before "
              "addressing configuration hardening.")
        return s

    def _fallback_remediation(self, findings) -> str:
        items = sorted({f.get("remediation", "") for f in findings if f.get("remediation")})
        return "\n".join(f"- {r}" for r in items)

    # -- CSV --------------------------------------------------------------
    def _csv(self, path: Path, findings) -> None:
        cols = ["ts", "phase", "module", "severity", "target", "title",
                "description", "remediation", "cve", "cwe"]
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(cols)
            for f in findings:
                w.writerow([
                    time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(f.get("ts", 0))),
                    f.get("phase", ""), f.get("module", ""), f.get("severity", ""),
                    f.get("target", ""), f.get("title", ""),
                    (f.get("description", "") or "").replace("\n", " "),
                    (f.get("remediation", "") or "").replace("\n", " "),
                    ",".join(f.get("cve", [])), ",".join(f.get("cwe", [])),
                ])

    # -- HTML -------------------------------------------------------------
    def _html(self, client, risk, findings, paths, summary, remediation) -> str:
        def esc(x):
            return html.escape(str(x or ""))

        rows = []
        order = {s: i for i, s in enumerate(SEV_ORDER)}
        for f in sorted(findings, key=lambda x: order.get(x["severity"], 9)):
            sev = f["severity"]
            rows.append(f"""
            <tr>
              <td><span class="sev" style="background:{SEV_COLOR[sev]}">{esc(sev.upper())}</span></td>
              <td>{esc(f['title'])}</td>
              <td>{esc(f['target'])}</td>
              <td>{esc(', '.join(f.get('cve', [])))}</td>
              <td>{esc(f.get('remediation',''))}</td>
            </tr>""")

        path_html = "".join(
            f"<li><b>{esc(p['host'])}</b> <span class='sev' "
            f"style='background:{SEV_COLOR[p['severity']]}'>{esc(p['severity'].upper())}</span>"
            f"<br>{esc(p['narrative'])}</li>" for p in paths) or "<li>None correlated.</li>"

        counts = risk["counts"]
        bars = "".join(
            f"<div class='bar'><span>{s.upper()} {counts[s]}</span>"
            f"<div class='fill' style='width:{min(counts[s]*8,100)}%;"
            f"background:{SEV_COLOR[s]}'></div></div>" for s in SEV_ORDER)

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>AyaStrike Report — {esc(client)}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
   margin:0;background:#0b0b0e;color:#e6edf3}}
 .wrap{{max-width:980px;margin:0 auto;padding:32px}}
 h1,h2{{color:#e01e37}} h1{{border-bottom:2px solid #30363d;padding-bottom:8px}}
 .score{{font-size:48px;font-weight:700;color:{SEV_COLOR.get(risk['rating'].lower(),'#e01e37')}}}
 .card{{background:#141419;border:1px solid #30363d;border-radius:10px;
   padding:20px;margin:18px 0}}
 table{{width:100%;border-collapse:collapse;font-size:14px}}
 th,td{{text-align:left;padding:8px;border-bottom:1px solid #21262d;vertical-align:top}}
 th{{color:#8b949e;text-transform:uppercase;font-size:11px;letter-spacing:.05em}}
 .sev{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}}
 .bar{{margin:6px 0}} .bar span{{font-size:12px;color:#8b949e}}
 .fill{{height:10px;border-radius:5px;margin-top:2px}}
 pre{{white-space:pre-wrap;font-family:inherit;color:#c9d1d9}}
 footer{{color:#6e7681;font-size:12px;margin-top:40px;text-align:center}}
</style></head><body><div class="wrap">
 <h1>Penetration Test Report</h1>
 <p><b>Engagement:</b> {esc(client)} &nbsp;|&nbsp; <b>Generated:</b>
    {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}</p>
 <div class="card">
   <h2>Overall Risk</h2>
   <div class="score">{risk['score']}/100 — {esc(risk['rating'])}</div>
   {bars}
 </div>
 <div class="card"><h2>Executive Summary</h2><pre>{esc(summary)}</pre></div>
 <div class="card"><h2>Correlated Attack Paths</h2><ul>{path_html}</ul></div>
 <div class="card"><h2>Findings ({len(findings)})</h2>
   <table><thead><tr><th>Severity</th><th>Finding</th><th>Target</th>
   <th>CVE</th><th>Remediation</th></tr></thead>
   <tbody>{''.join(rows)}</tbody></table></div>
 <div class="card"><h2>Consolidated Remediation</h2><pre>{esc(remediation)}</pre></div>
 <footer>Generated by AyaStrike — All-In-One Penetration Testing Toolkit · made by Ruel<br>
 For authorised security testing only.</footer>
</div></body></html>"""

    # -- PDF --------------------------------------------------------------
    def _pdf(self, path, client, risk, findings, paths, summary, remediation, ctx) -> bool:
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                            Table, TableStyle)
        except Exception:
            ctx.emit("reportlab not installed — skipping PDF.", "warn")
            return False

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle("Small", parent=styles["BodyText"], fontSize=8))
        doc = SimpleDocTemplate(str(path), pagesize=A4, title=f"AyaStrike Report — {client}")
        story = []
        story.append(Paragraph("Penetration Test Report", styles["Title"]))
        story.append(Paragraph(f"Engagement: {html.escape(client)}", styles["Normal"]))
        story.append(Paragraph(f"Generated: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
                               styles["Normal"]))
        story.append(Spacer(1, 8 * mm))
        story.append(Paragraph(f"Overall Risk: {risk['score']}/100 — {risk['rating']}",
                               styles["Heading1"]))
        c = risk["counts"]
        story.append(Paragraph(
            f"Critical: {c['critical']} &nbsp; High: {c['high']} &nbsp; "
            f"Medium: {c['medium']} &nbsp; Low: {c['low']} &nbsp; Info: {c['info']}",
            styles["Normal"]))
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        story.append(Paragraph(html.escape(summary).replace("\n", "<br/>"), styles["BodyText"]))
        story.append(Spacer(1, 4 * mm))

        if paths:
            story.append(Paragraph("Correlated Attack Paths", styles["Heading2"]))
            for p in paths:
                story.append(Paragraph(
                    f"<b>{html.escape(p['host'])}</b> [{p['severity'].upper()}]: "
                    f"{html.escape(p['narrative'])}", styles["BodyText"]))
            story.append(Spacer(1, 4 * mm))

        story.append(Paragraph(f"Findings ({len(findings)})", styles["Heading2"]))
        data = [["Severity", "Finding", "Target", "CVE"]]
        order = {s: i for i, s in enumerate(SEV_ORDER)}
        for f in sorted(findings, key=lambda x: order.get(x["severity"], 9)):
            data.append([f["severity"].upper(),
                         Paragraph(html.escape(f["title"]), styles["Small"]),
                         Paragraph(html.escape(f["target"]), styles["Small"]),
                         ",".join(f.get("cve", []))])
        tbl = Table(data, colWidths=[22 * mm, 80 * mm, 40 * mm, 28 * mm], repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#30363d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph("Consolidated Remediation", styles["Heading2"]))
        story.append(Paragraph(html.escape(remediation).replace("\n", "<br/>"),
                               styles["BodyText"]))
        story.append(Spacer(1, 8 * mm))
        story.append(Paragraph("Generated by AyaStrike — made by Ruel. "
                               "For authorised security testing only.", styles["Small"]))
        try:
            doc.build(story)
            return True
        except Exception as e:
            ctx.emit(f"PDF build failed: {e}", "warn")
            return False
