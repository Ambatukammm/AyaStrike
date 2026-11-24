"""Project workspaces.

A workspace is one engagement: its own directory, SQLite database, scope
whitelist, audit log, and findings store. Switching projects swaps all of this
atomically so results and scope never bleed between engagements.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

from aya.core import config
from aya.core.audit import AuditLog
from aya.core.authz import AuthorizationGate
from aya.core.scope import ScopeManager
from aya.modules.base import Finding, Severity


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    module TEXT,
    phase TEXT,
    target TEXT,
    title TEXT,
    severity TEXT,
    description TEXT,
    evidence TEXT,
    remediation TEXT,
    cve TEXT,
    cwe TEXT,
    refs TEXT,
    data TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT UNIQUE,
    hostname TEXT,
    os TEXT,
    first_seen REAL,
    last_seen REAL
);
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT,
    port INTEGER,
    proto TEXT,
    service TEXT,
    product TEXT,
    version TEXT,
    extra TEXT,
    UNIQUE(host, port, proto)
);
"""


def slugify(name: str) -> str:
    keep = "-_."
    s = "".join(c if (c.isalnum() or c in keep) else "_" for c in name.strip())
    return s.lower() or "project"


class Workspace:
    def __init__(self, name: str, root: Optional[Path] = None) -> None:
        self.name = name
        self.slug = slugify(name)
        self.root = Path(root) if root else config.projects_dir() / self.slug
        self.root.mkdir(parents=True, exist_ok=True)

        self.config = config.get_config()
        self.authz = AuthorizationGate()
        self.audit = AuditLog(self.root / "audit.jsonl")
        self.scope = ScopeManager(enforce=self.config.settings.enforce_scope)

        self._db_path = self.root / "workspace.db"
        self._local = threading.local()
        self._init_db()
        self._load_scope()

        self.audit.log("workspace_open", detail={"name": name, "slug": self.slug})

    # -- database ---------------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.executescript(_SCHEMA)
        conn.commit()
        if self._get_meta("created") is None:
            self._set_meta("created", str(time.time()))
            self._set_meta("name", self.name)

    def _get_meta(self, key: str) -> Optional[str]:
        row = self._conn().execute(
            "SELECT value FROM meta WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def _set_meta(self, key: str, value: str) -> None:
        conn = self._conn()
        conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        conn.commit()

    # -- scope persistence ------------------------------------------------
    def _scope_file(self) -> Path:
        return self.root / "scope.json"

    def _load_scope(self) -> None:
        f = self._scope_file()
        if f.exists():
            try:
                self.scope = ScopeManager.from_dict(json.loads(f.read_text()))
            except (OSError, json.JSONDecodeError, ValueError):
                pass

    def save_scope(self) -> None:
        self._scope_file().write_text(json.dumps(self.scope.to_dict(), indent=2))
        self.audit.log("scope_update", detail=self.scope.to_dict())

    # -- findings ---------------------------------------------------------
    def add_finding(self, f: Finding) -> int:
        conn = self._conn()
        cur = conn.execute(
            """INSERT INTO findings
               (ts,module,phase,target,title,severity,description,evidence,
                remediation,cve,cwe,refs,data)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f.ts, f.module, f.phase, f.target, f.title, f.severity.value,
                f.description, f.evidence, f.remediation,
                json.dumps(f.cve), json.dumps(f.cwe), json.dumps(f.refs),
                json.dumps(f.data),
            ),
        )
        conn.commit()
        return cur.lastrowid

    def findings(self, phase: Optional[str] = None) -> list[dict]:
        q = "SELECT * FROM findings"
        args: tuple = ()
        if phase:
            q += " WHERE phase=?"
            args = (phase,)
        q += " ORDER BY ts DESC"
        rows = self._conn().execute(q, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            for key in ("cve", "cwe", "refs", "data"):
                try:
                    d[key] = json.loads(d[key]) if d[key] else ([] if key != "data" else {})
                except json.JSONDecodeError:
                    d[key] = [] if key != "data" else {}
            out.append(d)
        return out

    def finding_counts(self) -> dict[str, int]:
        rows = self._conn().execute(
            "SELECT severity, COUNT(*) c FROM findings GROUP BY severity"
        ).fetchall()
        return {r["severity"]: r["c"] for r in rows}

    # -- host/service inventory ------------------------------------------
    def upsert_host(self, address: str, hostname: str = "", os_: str = "") -> None:
        now = time.time()
        conn = self._conn()
        conn.execute(
            """INSERT INTO hosts(address,hostname,os,first_seen,last_seen)
               VALUES(?,?,?,?,?)
               ON CONFLICT(address) DO UPDATE SET
                 hostname=COALESCE(NULLIF(excluded.hostname,''),hosts.hostname),
                 os=COALESCE(NULLIF(excluded.os,''),hosts.os),
                 last_seen=excluded.last_seen""",
            (address, hostname, os_, now, now),
        )
        conn.commit()

    def upsert_service(self, host: str, port: int, proto: str, service: str = "",
                       product: str = "", version: str = "", extra: str = "") -> None:
        conn = self._conn()
        conn.execute(
            """INSERT INTO services(host,port,proto,service,product,version,extra)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(host,port,proto) DO UPDATE SET
                 service=COALESCE(NULLIF(excluded.service,''),services.service),
                 product=COALESCE(NULLIF(excluded.product,''),services.product),
                 version=COALESCE(NULLIF(excluded.version,''),services.version),
                 extra=excluded.extra""",
            (host, port, proto, service, product, version, extra),
        )
        conn.commit()

    def hosts(self) -> list[dict]:
        return [dict(r) for r in self._conn().execute(
            "SELECT * FROM hosts ORDER BY address").fetchall()]

    def services(self, host: Optional[str] = None) -> list[dict]:
        if host:
            rows = self._conn().execute(
                "SELECT * FROM services WHERE host=? ORDER BY port", (host,)).fetchall()
        else:
            rows = self._conn().execute(
                "SELECT * FROM services ORDER BY host,port").fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn:
            conn.close()
            self._local.conn = None
        self.audit.log("workspace_close")


def list_projects() -> list[str]:
    out = []
    for p in config.projects_dir().iterdir():
        if p.is_dir() and (p / "workspace.db").exists():
            out.append(p.name)
    return sorted(out)
