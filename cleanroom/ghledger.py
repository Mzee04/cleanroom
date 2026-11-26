"""GitHub ledger through a Sprites GitHub connector.

One issue per candidate per *session*. Publishing is idempotent: the agent
lists the ledger's issues first and updates the issue for (session,
candidate) if it exists, instead of opening a duplicate.

Each issue carries a machine-readable record (one line of canonical JSON:
sorted keys, no spaces) and its SHA-256, plus ``previous_issue_sha256``, the
record hash of the issue published before it. That makes the issues a hash
chain: editing a record changes its hash, and the next record still commits
to the old one. GitHub also shows an "edited" history on every issue. It is
tamper-evident, not tamper-proof: nothing here is signed or externally
timestamped (see README, "Honest limits").

Candidate-controlled text (finding titles, trace lines, paths) is redacted and
escaped, so it cannot break out of Markdown, mention people or embed images.
Raw command lines are never posted.

  CLEANROOM_GITHUB_GATEWAY  https://api.sprites.dev/v1/gateway/github/<connection_id>
  CLEANROOM_GITHUB_REPO     owner/repo

The Sprite never holds a GitHub token; the connector gateway attaches it.
Without --publish the payloads are written to .cleanroom/outbox/ for review.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .redact import md_code_block, md_inline_code, md_text, redact_cmd, redact_text

GENESIS = "0" * 64
MARKER_RE = re.compile(r"<!-- cleanroom:session=(\S+) candidate=(\S+) record=([0-9a-f]{64}) "
                       r"prev=([0-9a-f]{64}) seq=(\d+) -->")


def _r(x):
    return f"{x:.4f}" if isinstance(x, float) else ("—" if x is None else x)


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def record_for(c: dict, summary: dict, prev: str) -> dict:
    rec_name = summary["recommendation"]["recommended"]
    findings = [{"severity": f["severity"], "code": f["code"], "clause_id": f["clause_id"],
                 "title": redact_text(f["title"])[:200]} for f in c["findings"]]
    evidence = canonical([{"code": f["code"], "detail": redact_text(f["detail"]),
                           "evidence": [redact_text(e) for e in f["evidence"]]} for f in c["findings"]])
    env = summary.get("environment") or {}
    return {
        "schema": "cleanroom-ledger/1",
        "session": summary.get("session"), "candidate": c["name"], "status": c["status"],
        "recommended": c["name"] == rec_name, "run_id": c.get("run_id"),
        "checkpoint": c["checkpoint"], "output_sha256": c["sha256"], "verify_sha256": c.get("verify_sha256"),
        "reproduced": c["reproduced"], "tracer": c.get("tracer"), "candidate_uid": c.get("candidate_uid"),
        "egress_verified": c.get("egress_verified"), "policy_sha256": c.get("policy_sha256"),
        "holdout_auc": c["holdout"], "leaderboard": c["leaderboard"],
        "environment": {"backend": env.get("backend"), "worker": env.get("worker"),
                        **(c.get("fingerprint") or {})},
        "findings": findings, "evidence_sha256": sha(evidence),
        "previous_issue_sha256": prev,
    }


def issue_payload(c: dict, summary: dict, prev: str = GENESIS, seq: int = 1) -> dict:
    recommended = summary["recommendation"]["recommended"]
    record = record_for(c, summary, prev)
    rjson = canonical(record)
    rsha = sha(rjson)
    status = c["status"] + (" · RECOMMENDED" if c["name"] == recommended else "")
    repro = {True: "match: reproduced in the recorded environment", False: "mismatch"}.get(
        c["reproduced"], "not checked")
    fp = c.get("fingerprint") or {}
    env_txt = ", ".join(f"{k} {v}" for k, v in fp.items()) or "not recorded"
    lines = [f"**Clean Room verdict:** {md_text(status)}", "",
             f"- Session: {md_inline_code(summary.get('session'))} · run {md_inline_code(c.get('run_id'))}",
             f"- Command (redacted): {md_inline_code(' '.join(redact_cmd(c['cmd'])))}",
             f"- Tracer: {md_inline_code(c.get('tracer'))} · candidate uid: {md_text(c.get('candidate_uid'))}"
             f" · egress denial verified: {md_text(c.get('egress_verified'))}",
             f"- Checkpoint: {md_inline_code(c['checkpoint'])}",
             f"- Output SHA-256: {md_inline_code(c['sha256'])}",
             f"- Reproduction: {md_text(repro)}",
             f"- Environment: {md_text(env_txt)}",
             f"- Leaderboard: {_r(c['leaderboard'])} · Holdout ROC AUC: {_r(c['holdout'])}", "", "### Findings"]
    for f in c["findings"]:
        lines.append(f"- **{md_text(f['severity'])}** {md_text(f['title'])}")
        if f["quote"]:
            lines.append(f"  > Rule {md_text(f['clause_id'])}: {md_text(f['quote'])}")
        ev = [e[:220] for e in f["evidence"][:3]]
        if ev:
            lines += ["", "  " + md_code_block(ev).replace("\n", "\n  "), ""]
    lines += ["", "### Ledger record",
              "Canonical JSON (sorted keys, no spaces). Its SHA-256 is the record hash; "
              "`previous_issue_sha256` links it to the issue published before it.", "",
              md_code_block([rjson], "json"), "",
              f"record_sha256: `{rsha}`  ",
              f"previous_issue_sha256: `{prev}`", "",
              f"<!-- cleanroom:session={summary.get('session')} candidate={c['name']} record={rsha} prev={prev} "
              f"seq={seq} -->"]
    labels = ["cleanroom", c["status"].lower()] + (["recommended"] if c["name"] == recommended else [])
    title = f"[Clean Room] {summary.get('session')} · {c['name']}: {status} · {str(c['sha256'])[:12]}"
    return {"title": title, "body": "\n".join(lines), "labels": labels, "_record_sha256": rsha, "_seq": seq}


def _issue_number(url: str) -> str:
    return url.rstrip("/").rsplit("/", 1)[-1] if "/issues/" in url else ""


class GitHub:
    """The few calls the ledger needs, through the connector gateway."""

    def __init__(self, gw: str, repo: str, opener=None):
        self.gw, self.repo = gw.rstrip("/"), repo
        self.open = opener or urllib.request.urlopen

    def call(self, method, path, body=None, query=None):
        url = f"{self.gw}/repos/{self.repo}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                     method=method, headers={"Content-Type": "application/json",
                                                             "Accept": "application/vnd.github+json"})
        with self.open(req, timeout=60) as r:
            return json.loads(r.read() or b"null")

    def ledger_issues(self) -> list[dict]:
        out = []
        for page in range(1, 11):
            batch = self.call("GET", "/issues", query={"state": "all", "labels": "cleanroom", "per_page": 100,
                                                       "page": page}) or []
            out += [i for i in batch if "pull_request" not in i]
            if len(batch) < 100:
                break
        return out


def _err(e) -> str:
    if isinstance(e, urllib.error.HTTPError):
        try:
            msg = json.loads(e.read() or b"{}").get("message", "")
        except ValueError:
            msg = ""
        return f"HTTP {e.code} {str(msg)[:160]}".strip()
    return type(e).__name__


def publish(summary: dict, outbox: Path, really: bool = False, ledger=None, github: GitHub | None = None) -> list[dict]:
    """Write every payload to the outbox; with ``really`` also create or update the issues.

    Returns one entry per candidate: ``{"name", "url", "action"}`` for a posted
    issue (action ``created``/``updated``), ``{"name", "path"}`` for an outbox
    file, or ``{"name", "error"}`` (HTTP status and GitHub's message only).
    """
    outbox.mkdir(parents=True, exist_ok=True)
    gw = os.environ.get("CLEANROOM_GITHUB_GATEWAY", "").rstrip("/")
    repo = os.environ.get("CLEANROOM_GITHUB_REPO", "")
    gh = github or (GitHub(gw, repo) if really and gw and repo else None)
    session = summary.get("session")
    existing: dict[str, dict] = {}
    head, seq = GENESIS, 0
    if ledger is not None:
        h = ledger.get_meta("chain_head", None, glob=True) or {}
        head, seq = h.get("record_sha256", GENESIS), int(h.get("seq", 0))
    if gh:
        try:
            for i in gh.ledger_issues():
                m = MARKER_RE.search(i.get("body") or "")
                if not m:
                    continue
                if m.group(1) == session:
                    existing[m.group(2)] = {"number": i["number"], "prev": m.group(4), "seq": int(m.group(5)),
                                            "url": i.get("html_url", "")}
                if int(m.group(5)) > seq:
                    head, seq = m.group(3), int(m.group(5))
        except (urllib.error.URLError, OSError, ValueError) as e:
            return [{"name": c["name"], "error": "could not list ledger issues: " + _err(e)}
                    for c in summary["candidates"]]
    done = []
    prev = head
    for c in summary["candidates"]:
        ex = existing.get(c["name"])
        if ex:
            payload = issue_payload(c, summary, prev=ex["prev"], seq=ex["seq"])
        else:
            seq += 1
            payload = issue_payload(c, summary, prev=prev, seq=seq)
        rsha, pseq = payload.pop("_record_sha256"), payload.pop("_seq")
        path = outbox / f"{session}-{c['name']}.json"
        path.write_text(json.dumps(payload, indent=2))
        if gh:
            try:
                if ex:
                    r = gh.call("PATCH", f"/issues/{ex['number']}", payload)
                    action = "updated"
                else:
                    r = gh.call("POST", "/issues", payload)
                    action = "created"
                url = (r or {}).get("html_url", "") or (ex or {}).get("url", "")
                done.append({"name": c["name"], "url": url, "number": _issue_number(url), "action": action,
                             "record_sha256": rsha})
            except (urllib.error.URLError, OSError, ValueError) as e:
                done.append({"name": c["name"], "error": _err(e)})
                continue
        else:
            done.append({"name": c["name"], "path": str(path), "record_sha256": rsha})
        prev = rsha
        if gh and ledger is not None and pseq >= int((ledger.get_meta("chain_head", None, glob=True) or {})
                                                     .get("seq", 0)):
            ledger.set_meta("chain_head", {"record_sha256": rsha, "seq": pseq, "session": session,
                                           "candidate": c["name"]}, glob=True)
    return done
