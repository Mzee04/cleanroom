"""GitHub ledger through a Sprites GitHub connector.

One issue per candidate per session: verdict, checkpoint id, output SHA-256,
the rule clauses involved and the trace lines behind each finding. Posting
only happens with ``--publish`` and when both variables are set:

  CLEANROOM_GITHUB_GATEWAY  https://api.sprites.dev/v1/gateway/github/<connection_id>
  CLEANROOM_GITHUB_REPO     owner/repo   (a private repo is recommended)

The Sprite never holds a GitHub token; the connector gateway attaches it.
Without --publish the payloads are written to .cleanroom/outbox/ for review.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path


def _r(x):
    return f"{x:.4f}" if isinstance(x, float) else x


def issue_payload(c: dict, recommended: str | None) -> dict:
    status = c["status"] + (" · RECOMMENDED" if c["name"] == recommended else "")
    lines = [f"**Clean Room verdict:** {status}", "",
             f"- Command: `{' '.join(c['cmd'])}`",
             f"- Checkpoint: `{c['checkpoint']}`",
             f"- Output SHA-256: `{c['sha256']}`",
             f"- Reproduction: {'match' if c['reproduced'] else 'mismatch' if c['reproduced'] is False else 'not checked'}"
             " (proves reproduction in that environment only)",
             f"- Leaderboard: {_r(c['leaderboard'])} · Holdout ROC AUC: {_r(c['holdout'])}", "", "### Findings"]
    for f in c["findings"]:
        lines.append(f"- **{f['severity']}** {f['title']}")
        if f["quote"]:
            lines.append(f"  > Rule {f['clause_id']}: {f['quote']}")
        for e in f["evidence"][:3]:
            lines.append(f"  `{e[:220]}`")
    labels = ["cleanroom", c["status"].lower()] + (["recommended"] if c["name"] == recommended else [])
    return {"title": f"[Clean Room] {c['name']}: {status} · {str(c['sha256'])[:12]}",
            "body": "\n".join(lines), "labels": labels}


def _issue_number(url: str) -> str:
    return url.rstrip("/").rsplit("/", 1)[-1] if "/issues/" in url else ""


def publish(summary: dict, outbox: Path, really: bool = False) -> list[dict]:
    """Write every payload to the outbox; with ``really`` also open the issues.

    Returns one entry per candidate: ``{"name", "url"}`` for a posted issue,
    ``{"name", "path"}`` for an outbox file, or ``{"name", "error"}`` when the
    gateway refused (HTTP status and GitHub's message only, never headers).
    """
    outbox.mkdir(parents=True, exist_ok=True)
    gw = os.environ.get("CLEANROOM_GITHUB_GATEWAY", "").rstrip("/")
    repo = os.environ.get("CLEANROOM_GITHUB_REPO", "")
    done = []
    for c in summary["candidates"]:
        payload = issue_payload(c, summary["recommendation"]["recommended"])
        path = outbox / f"{c['name']}.json"
        path.write_text(json.dumps(payload, indent=2))
        if really and gw and repo:
            req = urllib.request.Request(f"{gw}/repos/{repo}/issues", data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json",
                                                  "Accept": "application/vnd.github+json"})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    url = json.loads(r.read()).get("html_url", "")
                done.append({"name": c["name"], "url": url, "number": _issue_number(url)})
            except urllib.error.HTTPError as e:
                try:
                    msg = json.loads(e.read() or b"{}").get("message", "")
                except ValueError:
                    msg = ""
                done.append({"name": c["name"], "error": f"HTTP {e.code} {str(msg)[:160]}".strip()})
            except OSError as e:
                done.append({"name": c["name"], "error": type(e).__name__})
        else:
            done.append({"name": c["name"], "path": str(path)})
    return done
