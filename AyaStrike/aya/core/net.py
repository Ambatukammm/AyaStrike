"""Small networking helpers shared by modules.

Thin wrappers over :mod:`requests` (if installed) and the stdlib so modules
have a consistent timeout/user-agent policy and degrade gracefully when an
optional dependency is missing.
"""

from __future__ import annotations

import socket
import ssl
from typing import Optional

try:
    import requests  # optional but recommended
    _HAS_REQUESTS = True
except Exception:  # pragma: no cover
    requests = None  # type: ignore
    _HAS_REQUESTS = False


class HttpResult:
    def __init__(self, status: int, headers: dict, text: str, url: str):
        self.status = status
        self.headers = headers
        self.text = text
        self.url = url


def http_get(url: str, settings, timeout: Optional[float] = None,
             allow_redirects: bool = True, verify: bool = True) -> HttpResult:
    """HTTP GET using requests when available, else urllib."""
    ua = settings.user_agent
    to = timeout or settings.read_timeout
    if _HAS_REQUESTS:
        r = requests.get(
            url, headers={"User-Agent": ua}, timeout=to,
            allow_redirects=allow_redirects, verify=verify,
        )
        return HttpResult(r.status_code, dict(r.headers), r.text, r.url)
    # urllib fallback
    import urllib.request

    req = urllib.request.Request(url, headers={"User-Agent": ua})
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=to, context=ctx) as resp:
        body = resp.read().decode("utf-8", "replace")
        return HttpResult(resp.status, dict(resp.headers), body, resp.geturl())


def resolve(hostname: str) -> list[str]:
    """Resolve a hostname to a list of IP strings (A/AAAA)."""
    out: set[str] = set()
    try:
        for res in socket.getaddrinfo(hostname, None):
            out.add(res[4][0])
    except socket.gaierror:
        pass
    return sorted(out)


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def tcp_connect(host: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection to host:port succeeds (port open)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def grab_banner(host: str, port: int, timeout: float, probe: bytes = b"") -> str:
    """Connect and read a short banner. Optionally send a probe first."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if probe:
                try:
                    s.sendall(probe)
                except OSError:
                    pass
            try:
                data = s.recv(2048)
                return data.decode("utf-8", "replace").strip()
            except (socket.timeout, OSError):
                return ""
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""


def has_requests() -> bool:
    return _HAS_REQUESTS
