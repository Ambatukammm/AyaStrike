"""Credential toolkit: OFFLINE hash auditing.

Audits password hashes you ALREADY POSSESS from an authorised engagement (e.g.
a dumped NTDS.dit, /etc/shadow, or an application database you are testing).
Everything here is fully offline — no network, no live service is touched.

Two modes:
  * Dictionary (default): hashes each word in a wordlist and compares. This is
    standard, non-intrusive password auditing.
  * Brute force (incremental charset): DISABLED BY DEFAULT. It is gated behind
    an explicit authorisation grant (written-permission confirmation) because,
    although offline, it represents exhaustive credential attack behaviour that
    an engagement should consciously authorise. The GUI shows a red warning and
    a permission checkbox before this can be enabled.

Supported algorithms: md5, sha1, sha256, sha512, and NTLM (MD4 of UTF-16-LE).
"""

from __future__ import annotations

import hashlib
import itertools
import string
from typing import Iterator, Optional

from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity


def _ntlm(password: str) -> str:
    # NTLM = MD4(UTF-16-LE(password)). hashlib may expose md4 via 'new'.
    try:
        h = hashlib.new("md4")
    except ValueError:
        return ""  # MD4 unavailable in this build
    h.update(password.encode("utf-16-le"))
    return h.hexdigest()


def _hash(password: str, algo: str) -> str:
    algo = algo.lower()
    if algo == "ntlm":
        return _ntlm(password)
    if algo in ("md5", "sha1", "sha256", "sha512"):
        return hashlib.new(algo, password.encode("utf-8")).hexdigest()
    raise ValueError(f"unsupported algorithm: {algo}")


def _detect_algo(h: str) -> str:
    return {32: "md5/ntlm", 40: "sha1", 64: "sha256", 128: "sha512"}.get(
        len(h.strip()), "unknown")


@register
class HashCrackModule(BaseModule):
    id = "cred.hash_crack"
    name = "Offline Hash Auditing"
    phase = Phase.CREDENTIALS
    description = ("Dictionary (and gated brute-force) auditing of hashes you "
                   "already possess. Fully offline.")
    inputs = [
        ModuleInput("hashes", "Hashes", kind="multiline",
                    help="One hex hash per line (optionally 'user:hash')."),
        ModuleInput("algo", "Algorithm", kind="choice", default="md5",
                    choices=["md5", "sha1", "sha256", "sha512", "ntlm"]),
        ModuleInput("mode", "Mode", kind="choice", default="dictionary",
                    choices=["dictionary", "bruteforce"],
                    help="bruteforce is disabled unless authorised."),
        ModuleInput("wordlist", "Wordlist file", kind="file", default="",
                    required=False, help="Required for dictionary mode."),
        ModuleInput("charset", "Brute charset", default=string.ascii_lowercase + string.digits,
                    required=False),
        ModuleInput("max_len", "Brute max length", kind="int", default=4, required=False),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        algo = params.get("algo", "md5").lower()
        mode = params.get("mode", "dictionary").lower()

        # Parse hashes (support user:hash).
        targets: dict[str, Optional[str]] = {}
        for line in params["hashes"].splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" in line and len(line.split(":")[-1]) in (32, 40, 64, 128):
                user, h = line.rsplit(":", 1)
            else:
                user, h = "", line
            targets[h.lower()] = user or None
        if not targets:
            yield Finding(title="No hashes supplied", target="offline",
                          severity=Severity.INFO)
            return

        if algo == "ntlm" and not _ntlm("test"):
            yield Finding(title="NTLM/MD4 not available in this Python build",
                          target="offline", severity=Severity.INFO,
                          description="Use an external tool (hashcat/john) for NTLM here.")
            return

        ctx.emit(f"Auditing {len(targets)} hash(es) with algo={algo}, mode={mode}", "info")
        cracked: dict[str, str] = {}

        if mode == "bruteforce":
            # Gated capability: brute force is OFF unless explicitly authorised.
            from aya.core.authz import NotAuthorised
            try:
                ctx.workspace.authz.require("bruteforce")
            except NotAuthorised:
                yield Finding(
                    title="Brute-force mode is not authorised",
                    target="offline", severity=Severity.INFO,
                    description=("Offline brute force is disabled by default. Enable it "
                                 "via the Authorisation dialog (written-permission "
                                 "confirmation) before use. Dictionary mode remains "
                                 "available without a grant."),
                )
                return
            ctx.workspace.audit.log("bruteforce_run", module=self.id,
                                    detail={"algo": algo, "mode": "offline-charset"},
                                    severity="warn")
            cracked = self._bruteforce(ctx, targets, algo,
                                       params.get("charset", ""),
                                       int(params.get("max_len", 4) or 4))
        else:
            wl = params.get("wordlist", "")
            if not wl:
                yield Finding(title="Dictionary mode needs a wordlist file",
                              target="offline", severity=Severity.INFO)
                return
            cracked = self._dictionary(ctx, targets, algo, wl)

        # Report.
        for h, user in targets.items():
            if h in cracked:
                label = f"{user}:" if user else ""
                yield Finding(
                    title=f"Weak password recovered ({label}{_detect_algo(h)})",
                    target="offline", severity=Severity.HIGH,
                    description="A hash was matched to a plaintext password offline.",
                    evidence=f"{label}{h} -> {cracked[h]}",
                    remediation="Enforce strong, unique passwords; use a slow hash "
                                "(bcrypt/argon2) with per-user salt; enable MFA.",
                    cwe=["CWE-521", "CWE-916"],
                    data={"user": user, "algo": algo},
                )
        yield Finding(
            title=f"Hash audit complete: {len(cracked)}/{len(targets)} recovered",
            target="offline",
            severity=Severity.MEDIUM if cracked else Severity.INFO,
            data={"recovered": len(cracked), "total": len(targets)},
        )

    def _dictionary(self, ctx, targets, algo, wordlist_path) -> dict[str, str]:
        cracked: dict[str, str] = {}
        remaining = set(targets)
        try:
            fh = open(wordlist_path, encoding="utf-8", errors="ignore")
        except OSError as e:
            ctx.emit(f"Cannot open wordlist: {e}", "error")
            return cracked
        with fh:
            for i, word in enumerate(fh):
                if ctx.cancel.is_set() or not remaining:
                    break
                word = word.rstrip("\n")
                digest = _hash(word, algo)
                if digest in remaining:
                    cracked[digest] = word
                    remaining.discard(digest)
                    ctx.emit(f"  cracked: {digest[:16]}… = {word}", "success")
                if i % 50000 == 0 and i:
                    ctx.emit(f"  …{i} candidates tried", "info")
        return cracked

    def _bruteforce(self, ctx, targets, algo, charset, max_len) -> dict[str, str]:
        cracked: dict[str, str] = {}
        remaining = set(targets)
        charset = charset or (string.ascii_lowercase + string.digits)
        max_len = max(1, min(max_len, 6))  # hard cap to avoid runaway CPU
        for length in range(1, max_len + 1):
            if ctx.cancel.is_set() or not remaining:
                break
            ctx.emit(f"  brute length {length} over {len(charset)} chars…", "info")
            for combo in itertools.product(charset, repeat=length):
                if ctx.cancel.is_set() or not remaining:
                    break
                word = "".join(combo)
                digest = _hash(word, algo)
                if digest in remaining:
                    cracked[digest] = word
                    remaining.discard(digest)
                    ctx.emit(f"  cracked: {digest[:16]}… = {word}", "success")
        return cracked
