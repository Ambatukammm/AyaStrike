"""Configuration and path management for AyaStrike.

Settings live in a JSON file under the user's home directory so they persist
across runs and projects. Secrets (API keys) are stored here too; the file is
created with restrictive permissions where the OS supports it.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


def app_home() -> Path:
    """Return the per-user AyaStrike home directory, creating it if needed."""
    # Respect an explicit override (useful for portable/USB installs and tests).
    override = os.environ.get("AYASTRIKE_HOME")
    base = Path(override) if override else Path.home() / ".ayastrike"
    base.mkdir(parents=True, exist_ok=True)
    return base


def projects_dir() -> Path:
    d = app_home() / "projects"
    d.mkdir(parents=True, exist_ok=True)
    return d


def data_dir() -> Path:
    """Bundled read-only data (wordlists, signatures) shipped with the app."""
    return Path(__file__).resolve().parent.parent.parent / "data"


@dataclass
class Settings:
    """User-adjustable settings. Defaults are deliberately conservative."""

    # --- Rate limiting (requests/probes per second, global default) ---
    rate_limit_per_sec: float = 5.0
    max_concurrency: int = 10

    # --- Network behaviour ---
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    user_agent: str = "AyaStrike/1.0 (authorised-testing)"

    # --- Safety posture ---
    # When True, modules refuse to touch any target not on the active scope
    # whitelist. This should stay True outside of very deliberate lab use.
    enforce_scope: bool = True
    # Offensive capabilities that are OFF until the operator explicitly and
    # repeatedly opts in (see authz.py). Persisted so an accidental enable
    # does not silently carry over, but still re-gated per session.
    allow_bruteforce: bool = False

    # --- External tool paths (auto-detected if blank) ---
    nmap_path: str = ""
    # Metasploit RPC
    msf_rpc_host: str = "127.0.0.1"
    msf_rpc_port: int = 55553
    msf_rpc_ssl: bool = True
    msf_rpc_user: str = "msf"

    # --- AI (local Ollama, matching AyaRecon) ---
    ollama_host: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.1"
    ai_enabled: bool = True

    # --- API keys for passive recon (all optional) ---
    shodan_api_key: str = ""
    # Never store the MSF RPC password on disk by default; kept in-memory only.

    # --- Misc ---
    theme: str = "red"
    extra: dict[str, Any] = field(default_factory=dict)


class ConfigManager:
    """Loads/saves Settings and exposes them thread-safely."""

    _FILENAME = "settings.json"

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._path = app_home() / self._FILENAME
        self._settings = self._load()

    # -- public API -------------------------------------------------------
    @property
    def settings(self) -> Settings:
        with self._lock:
            return self._settings

    def update(self, **kwargs: Any) -> Settings:
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self._settings, key):
                    setattr(self._settings, key, value)
                else:
                    self._settings.extra[key] = value
            self._save()
            return self._settings

    # -- persistence ------------------------------------------------------
    def _load(self) -> Settings:
        if not self._path.exists():
            s = Settings()
            self._settings = s
            self._save()
            return s
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # Corrupt config should never brick the app; fall back to defaults.
            return Settings()
        s = Settings()
        for key, value in raw.items():
            if hasattr(s, key):
                setattr(s, key, value)
            else:
                s.extra[key] = value
        return s

    def _save(self) -> None:
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self._settings), indent=2), encoding="utf-8")
        tmp.replace(self._path)
        # Best-effort tighten permissions (owner read/write only).
        try:
            os.chmod(self._path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


# Convenience singleton used across the app.
_manager: ConfigManager | None = None
_manager_lock = threading.Lock()


def get_config() -> ConfigManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = ConfigManager()
        return _manager
