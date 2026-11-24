"""Append-only audit logging.

Every meaningful action — scope changes, scans launched, exploit modules run,
authorisation toggles, scope violations — is written here. The log is:

  * append-only (never rewritten by the app),
  * tamper-evident via a running SHA-256 hash chain (each line commits to the
    previous line's hash), so after-the-fact edits are detectable,
  * written both to the project SQLite DB and to a flat .jsonl file.

This exists so that an authorised engagement has a defensible record of exactly
what was done, when, and against which targets.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any, Optional


GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path) -> None:
        self._lock = threading.RLock()
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self._path.exists():
            return GENESIS
        last = GENESIS
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        last = rec.get("_hash", last)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass
        return last

    @staticmethod
    def _hash(prev: str, payload: str) -> str:
        return hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()

    def log(
        self,
        action: str,
        target: Optional[str] = None,
        module: Optional[str] = None,
        detail: Optional[dict[str, Any]] = None,
        severity: str = "info",
    ) -> dict:
        """Write one audit record and return it."""
        with self._lock:
            rec = {
                "ts": time.time(),
                "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
                "action": action,
                "module": module,
                "target": target,
                "severity": severity,
                "detail": detail or {},
                "_prev": self._prev_hash,
            }
            payload = json.dumps(rec, sort_keys=True, ensure_ascii=False)
            rec["_hash"] = self._hash(self._prev_hash, payload)
            self._prev_hash = rec["_hash"]
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            return rec

    def verify(self) -> tuple[bool, Optional[int]]:
        """Re-walk the chain. Returns (ok, first_bad_line_number or None)."""
        prev = GENESIS
        n = 0
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    n += 1
                    rec = json.loads(line)
                    stored = rec.pop("_hash", None)
                    payload = json.dumps(rec, sort_keys=True, ensure_ascii=False)
                    if rec.get("_prev") != prev or self._hash(prev, payload) != stored:
                        return False, n
                    prev = stored
        except (OSError, json.JSONDecodeError):
            return False, n or None
        return True, None

    def tail(self, limit: int = 200) -> list[dict]:
        if not self._path.exists():
            return []
        lines: list[str] = []
        with self._path.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()
        out: list[dict] = []
        for line in lines[-limit:]:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out
