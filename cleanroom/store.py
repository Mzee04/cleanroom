"""SQLite ledger. Lives with the agent, never on the worker (restores wipe it)."""
from __future__ import annotations

import json
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
"""


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def add_run(self, candidate, kind, backend, cmd, result, findings, data) -> int:
        cur = self.db.execute(
            "INSERT INTO runs (candidate, kind, created, backend, cmd, checkpoint, exit_code, sha256, tracer,"
            " network, trace_dir, workdir, data) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (candidate, kind, time.time(), backend, json.dumps(cmd), result.checkpoint, result.exit_code,
             result.output_sha256, result.tracer, result.network, result.trace_dir, result.workdir,
             json.dumps(data)))
        rid = cur.lastrowid
        for f in findings:
            d = f.to_dict() if hasattr(f, "to_dict") else f
            self.db.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?)",
                            (rid, d["severity"], d["code"], d["title"], d["detail"], d["clause_id"],
                             d["quote"], json.dumps(d["evidence"])))
        self.db.commit()
        return rid

    def runs(self, candidate=None, kind=None) -> list[dict]:
        q, args = "SELECT * FROM runs WHERE 1=1", []
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
            "SELECT candidate FROM runs WHERE kind='run' GROUP BY candidate ORDER BY MIN(id)")]

    def set_meta(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, json.dumps(value)))
        self.db.commit()

    def get_meta(self, key, default=None):
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(r[0]) if r else default

    def reset(self):
        self.db.executescript("DELETE FROM findings; DELETE FROM runs; DELETE FROM meta;")
        self.db.commit()
