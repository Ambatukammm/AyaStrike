"""Credential toolkit: online credential testing (GATED, OFF BY DEFAULT).

Tests supplied credentials against a LIVE service. This is the most intrusive
capability in the suite and is therefore:

  * DISABLED BY DEFAULT — ``disabled_by_default = True``.
  * Gated behind an explicit authorisation grant (``requires_authz =
    "bruteforce"``) that the GUI only lets the operator enable after confirming
    WRITTEN permission and typing a confirmation phrase.
  * Scope-enforced — refuses any target outside the authorised scope.
  * Rate-limited — honours the global throttle to avoid account lockout / DoS.
  * Fully audited — the run and its parameters are recorded (passwords redacted).

It is intended ONLY for verifying weak/default credentials during an authorised
assessment (e.g. confirming a device still uses admin/admin). It deliberately
stops at the FIRST valid credential per username and caps attempt counts.

Supported: HTTP Basic auth, and SSH (requires the ``paramiko`` package).
"""

from __future__ import annotations

from urllib.parse import urlparse
from typing import Iterator

from aya.core.plugins import register
from aya.modules.base import BaseModule, Finding, ModuleContext, ModuleInput, Phase, Severity


@register
class OnlineCredentialModule(BaseModule):
    id = "cred.online_test"
    name = "Online Credential Test (gated)"
    phase = Phase.CREDENTIALS
    description = ("DISABLED BY DEFAULT. Test credentials against a live service. "
                   "Requires written-permission authorisation.")
    requires_authz = "bruteforce"
    disabled_by_default = True
    inputs = [
        ModuleInput("service", "Service", kind="choice", default="http-basic",
                    choices=["http-basic", "ssh"]),
        ModuleInput("target", "Target URL or host"),
        ModuleInput("port", "Port (ssh)", kind="int", default=22, required=False),
        ModuleInput("usernames", "Usernames", kind="multiline"),
        ModuleInput("passwords", "Passwords", kind="multiline",
                    help="Keep this SMALL — for confirming weak/default creds, not "
                         "large-scale guessing."),
        ModuleInput("max_attempts", "Attempt cap", kind="int", default=100,
                    required=False),
    ]

    def run(self, ctx: ModuleContext, params) -> Iterator[Finding]:
        # Authorisation is also enforced centrally by the plugin runner, but we
        # re-check here so the module is safe if ever called directly.
        ctx.workspace.authz.require("bruteforce")

        service = params.get("service", "http-basic")
        target = params["target"].strip()
        host = urlparse(target).hostname or target
        ctx.scope.require(host)

        users = [u.strip() for u in params["usernames"].splitlines() if u.strip()]
        pwds = [p for p in params["passwords"].splitlines() if p]
        cap = int(params.get("max_attempts", 100) or 100)
        if len(users) * len(pwds) > cap:
            yield Finding(
                title="Attempt count exceeds the configured cap",
                target=host, severity=Severity.INFO,
                description=f"{len(users)}×{len(pwds)} > cap {cap}. Reduce the lists. "
                            "This module is for confirming weak/default creds, not "
                            "large-scale guessing.",
            )
            return

        ctx.workspace.audit.log(
            "online_credential_test_start", target=host, module=self.id,
            detail={"service": service, "users": len(users), "pwds": len(pwds)},
            severity="warn",
        )
        ctx.emit(f"[AUTHORISED] Testing {len(users)}×{len(pwds)} combos on {host}", "warn")

        if service == "http-basic":
            yield from self._http_basic(ctx, target, host, users, pwds)
        elif service == "ssh":
            yield from self._ssh(ctx, host, int(params.get("port", 22) or 22),
                                 users, pwds)

    def _http_basic(self, ctx, url, host, users, pwds) -> Iterator[Finding]:
        try:
            import requests
            from requests.auth import HTTPBasicAuth
        except Exception:
            yield Finding(title="requests not installed", target=host,
                          severity=Severity.INFO)
            return
        for user in users:
            found = False
            for pwd in pwds:
                if ctx.cancel.is_set() or not ctx.gate():
                    return
                try:
                    r = requests.get(url, auth=HTTPBasicAuth(user, pwd),
                                     timeout=ctx.settings.read_timeout, verify=False)
                except Exception:
                    continue
                if r.status_code not in (401, 403):
                    found = True
                    ctx.workspace.audit.log("credential_found", target=host,
                                            module=self.id, detail={"user": user},
                                            severity="critical")
                    yield Finding(
                        title=f"Valid HTTP credentials: {user}", target=host,
                        severity=Severity.CRITICAL,
                        description=f"HTTP Basic auth accepted for user '{user}'.",
                        evidence=f"{user}:*** -> HTTP {r.status_code}",
                        remediation="Change the credential; enforce strong passwords + MFA; "
                                    "lock out repeated failures.",
                        cwe=["CWE-521", "CWE-307"],
                    )
                    break  # stop at first valid password for this user
            if found:
                continue

    def _ssh(self, ctx, host, port, users, pwds) -> Iterator[Finding]:
        try:
            import paramiko  # type: ignore
        except Exception:
            yield Finding(title="paramiko not installed", target=host,
                          severity=Severity.INFO,
                          description="pip install paramiko to enable SSH credential tests.")
            return
        for user in users:
            for pwd in pwds:
                if ctx.cancel.is_set() or not ctx.gate():
                    return
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(host, port=port, username=user, password=pwd,
                                   timeout=ctx.settings.connect_timeout,
                                   allow_agent=False, look_for_keys=False)
                    client.close()
                    ctx.workspace.audit.log("credential_found", target=host,
                                            module=self.id, detail={"user": user},
                                            severity="critical")
                    yield Finding(
                        title=f"Valid SSH credentials: {user}", target=host,
                        severity=Severity.CRITICAL,
                        description=f"SSH login succeeded for user '{user}'.",
                        evidence=f"{user}:*** @ {host}:{port}",
                        remediation="Rotate the credential; prefer key-based auth; "
                                    "disable password auth; add fail2ban/lockout.",
                        cwe=["CWE-521", "CWE-307"],
                    )
                    break
                except paramiko.AuthenticationException:
                    continue
                except Exception as e:
                    ctx.emit(f"  ssh error: {e}", "warn")
                    return
