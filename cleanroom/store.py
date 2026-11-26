"""SQLite ledger. Lives with the agent, never on the worker (restores wipe it).

History is kept: every agent loop is a *session* with its own id, and runs,
findings and metadata are scoped to it. Nothing is deleted between runs; the
report shows the latest session unless told otherwise.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  candidate TEXT NOT NULL, kind TEXT NOT NULL, created REAL NOT NULL,
  backend TEXT, cmd TEXT, checkpoint TEXT, exit_code INTEGER, sha256 TEXT,
  tracer TEXT, network TEXT, trace_dir TEXT, workdir TEXT, data TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  run_id INTEGER NOT NULL REFERENCES runs(id), severity TEXT, code TEXT, title TEXT,
  detail TEXT, clause_id TEXT, quote TEXT, evidence TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, created REAL NOT NULL, note TEXT);
"""
GLOBAL = "global"


def new_session_id() -> str:
    return time.strftime("cr-%Y%m%d-%H%M%S", time.gmtime()) + "-" + secrets.token_hex(2)


class Ledger:
    def __init__(self, path: Path, session: str | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(runs)")}
        if "session" not in cols:   # ledgers written before sessions existed keep their rows
            self.db.execute("ALTER TABLE runs ADD COLUMN session TEXT DEFAULT 'legacy'")
            self.db.commit()
        self.session = session or self._current() or self.start_session("first session")

    # sessions ------------------------------------------------------------
    def _current(self) -> str | None:
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (f"{GLOBAL}:current_session",)).fetchone()
        return json.loads(r[0]) if r else None

    def start_session(self, note: str = "") -> str:
        sid = new_session_id()
        self.db.execute("INSERT INTO sessions VALUES (?,?,?)", (sid, time.time(), note))
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (f"{GLOBAL}:current_session", json.dumps(sid)))
        self.db.commit()
        self.session = sid
        return sid

    def sessions(self) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM sessions ORDER BY created")]

    # runs ----------------------------------------------------------------
    def add_run(self, candidate, kind, backend, cmd, result, findings, data) -> int:
        cur = self.db.execute(
            "INSERT INTO runs (candidate, kind, created, backend, cmd, checkpoint, exit_code, sha256, tracer,"
            " network, trace_dir, workdir, data, session) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (candidate, kind, time.time(), backend, json.dumps(cmd), result.checkpoint, result.exit_code,
             result.output_sha256, result.tracer, result.network, result.trace_dir, result.workdir,
             json.dumps(data), self.session))
        rid = cur.lastrowid
        for f in findings:
            d = f.to_dict() if hasattr(f, "to_dict") else f
            self.db.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?)",
                            (rid, d["severity"], d["code"], d["title"], d["detail"], d["clause_id"],
                             d["quote"], json.dumps(d["evidence"])))
        self.db.commit()
        return rid

    def runs(self, candidate=None, kind=None) -> list[dict]:
        q, args = "SELECT * FROM runs WHERE session=?", [self.session]
        if candidate:
            q += " AND candidate=?"
            args.append(candidate)
        if kind:
            q += " AND kind=?"
            args.append(kind)
        rows = [dict(r) for r in self.db.execute(q + " ORDER BY id", args)]
        for r in rows:
            r["cmd"] = json.loads(r["cmd"] or "[]")
            r["data"] = json.loads(r["data"] or "{}")
            r["findings"] = self.findings(r["id"])
        return rows

    def latest(self, candidate, kind="run") -> dict | None:
        rs = self.runs(candidate, kind)
        return rs[-1] if rs else None

    def latest_for(self, candidate, kind, run: dict) -> dict | None:
        """Latest ``kind`` run bound to exactly this original run (id, checkpoint, output, policy)."""
        for r in reversed(self.runs(candidate, kind)):
            d = r["data"]
            if (d.get("original_run_id") == run["id"] and r["checkpoint"] == run["checkpoint"]
                    and d.get("original_sha256") == run["sha256"]
                    and d.get("policy_sha256") == run["data"].get("policy_sha256")):
                return r
        return None

    def findings(self, run_id) -> list[dict]:
        out = []
        for r in self.db.execute("SELECT * FROM findings WHERE run_id=?", (run_id,)):
            d = dict(r)
            d["evidence"] = json.loads(d["evidence"] or "[]")
            d.pop("run_id")
            out.append(d)
        return out

    def candidates(self) -> list[str]:
        return [r[0] for r in self.db.execute(
            "SELECT candidate FROM runs WHERE kind='run' AND session=? GROUP BY candidate ORDER BY MIN(id)",
            (self.session,))]

    # metadata (per session unless global=True) -----------------------------
    def _k(self, key, glob):
        return f"{GLOBAL if glob else self.session}:{key}"

    def set_meta(self, key, value, glob: bool = False):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (self._k(key, glob), json.dumps(value)))
        self.db.commit()

    def get_meta(self, key, default=None, glob: bool = False):
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (self._k(key, glob),)).fetchone()
        return json.loads(r[0]) if r else default
