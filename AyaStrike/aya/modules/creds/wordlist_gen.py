"""Credential toolkit: wordlist generation.

Builds a candidate password wordlist from supplied base words (company name,
product names, local sports teams, etc.) by applying common human mutation
rules: capitalisation, leet substitution, year/number suffixes, and symbol
suffixes. OFFLINE generation only — the output is written to a file for use with
authorised offline hash auditing.

The point of this module in an authorised engagement is to demonstrate how
guessable organisation-themed passwords are, so policy can be improved.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from aya.core.config import app_home
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity

LEET = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}


def _leet(word: str) -> str:
    return "".join(LEET.get(c, c) for c in word)


def mutate(base_words, years, symbols, use_leet) -> list[str]:
    out: set[str] = set()
    for w in base_words:
        w = w.strip()
        if not w:
            continue
        variants = {w, w.lower(), w.upper(), w.capitalize()}
        if use_leet:
            variants.add(_leet(w.lower()))
            variants.add(_leet(w.capitalize()))
        for v in list(variants):
            out.add(v)
            for y in years:
                out.add(f"{v}{y}")
            for s in symbols:
                out.add(f"{v}{s}")
                for y in years:
                    out.add(f"{v}{y}{s}")
    return sorted(out)


@register
class WordlistGenModule(BaseModule):
    id = "cred.wordlist_gen"
    name = "Wordlist Generator"
    phase = Phase.CREDENTIALS
    description = "Generate a themed password wordlist from base words (offline)."
    inputs = [
        ModuleInput("words", "Base words", kind="multiline",
                    help="One seed word per line (company, product, team…)."),
        ModuleInput("years", "Year suffixes", default="2023,2024,2025,2026,123,1234,!",
                    required=False),
        ModuleInput("symbols", "Symbol suffixes", default="!,@,#,1,123", required=False),
        ModuleInput("leet", "Apply leet substitution", kind="bool", default=True,
                    required=False),
        ModuleInput("outfile", "Output filename", default="wordlist.txt",
                    required=False),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        base = [w for w in params["words"].splitlines() if w.strip()]
        years = [y.strip() for y in params.get("years", "").split(",") if y.strip()]
        symbols = [s.strip() for s in params.get("symbols", "").split(",") if s.strip()]
        use_leet = bool(params.get("leet", True))

        words = mutate(base, years, symbols, use_leet)

        outdir = app_home() / "wordlists"
        outdir.mkdir(parents=True, exist_ok=True)
        name = Path(params.get("outfile", "wordlist.txt")).name or "wordlist.txt"
        outpath = outdir / name
        outpath.write_text("\n".join(words), encoding="utf-8")

        yield Finding(
            title=f"Generated wordlist with {len(words)} candidate(s)",
            target="offline", severity=Severity.INFO,
            description=f"Saved to {outpath}. Use with offline hash auditing only.",
            evidence="\n".join(words[:100]) + ("\n…" if len(words) > 100 else ""),
            data={"path": str(outpath), "count": len(words)},
        )
