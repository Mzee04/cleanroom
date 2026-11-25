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
import urllib.request
from pathlib import Path


def issue_payload(c: dict, recommended: str | None) -> dict:
    status = c["status"] + (" · RECOMMENDED" if c["name"] == recommended else "")
    lines = [f"**Clean Room verdict:** {status}", "",
             f"- Command: `{' '.join(c['cmd'])}`",
             f"- Checkpoint: `{c['checkpoint']}`",
             f"- Output SHA-256: `{c['sha256']}`",
             f"- Reproduction: {'match' if c['reproduced'] else 'mismatch' if c['reproduced'] is False else 'not checked'}"
             " (proves reproduction in that environment only)",
             f"- Leaderboard: {c['leaderboard']} · Holdout ROC AUC: {c['holdout']}", "", "### Findings"]
    for f in c["findings"]:
        lines.append(f"- **{f['severity']}** {f['title']}")
        if f["quote"]:
            lines.append(f"  > Rule {f['clause_id']}: {f['quote']}")
        for e in f["evidence"][:3]:
            lines.append(f"  `{e[:220]}`")
    labels = ["cleanroom", c["status"].lower()] + (["recommended"] if c["name"] == recommended else [])
    return {"title": f"[Clean Room] {c['name']}: {status} · {str(c['sha256'])[:12]}",
            "body": "\n".join(lines), "labels": labels}


def publish(summary: dict, outbox: Path, really: bool = False) -> list[str]:
    outbox.mkdir(parents=True, exist_ok=True)
    gw = os.environ.get("CLEANROOM_GITHUB_GATEWAY", "").rstrip("/")
    repo = os.environ.get("CLEANROOM_GITHUB_REPO", "")
    done = []
    for c in summary["candidates"]:
        payload = issue_payload(c, summary["recommendation"]["recommended"])
        (outbox / f"{c['name']}.json").write_text(json.dumps(payload, indent=2))
        if really and gw and repo:
            req = urllib.request.Request(f"{gw}/repos/{repo}/issues", data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json",
                                                  "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=60) as r:
                done.append(json.loads(r.read()).get("html_url", "posted"))
        else:
            done.append(str(outbox / f"{c['name']}.json"))
    return done
