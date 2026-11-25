"""The Clean Room agent loop.

  1. read the rules and derive a policy (each rule keeps its quote)
  2. prepare the worker: deny egress, install tracer, upload code + data
  3. checkpoint the starting state once, so every candidate starts identical
  4. run every candidate from that checkpoint, traced, egress denied
  5. investigate every red flag (re-run with the forbidden file hidden, etc.)
  6. verify reproduction: restore the checkpoint, re-run, compare SHA-256
  7. optional honest score: bootstrap CI on your holdout + seed spread
  8. recommend, explain, write the report, optionally log to GitHub
"""
from __future__ import annotations

import time

from . import checks, llm
from .engine import Project
from .ghledger import publish
from .report import write_report
from .summary import build_summary

C = {"FAIL": "\033[31m", "WARN": "\033[33m", "PASS": "\033[32m", "INFO": "\033[36m", "B": "\033[1m", "0": "\033[0m"}


def _c(tag, s, color=True):
    return f"{C[tag]}{s}{C['0']}" if color else s


def run_agent(proj: Project, honest: bool = True, publish_github: bool = False, color: bool = True,
              log=print) -> dict:
    t0 = time.time()
    cfg = proj.cfg
    if not cfg.get("candidates"):
        raise SystemExit("cleanroom.json lists no candidates")
    log(_c("B", "Clean Room agent", color) + f" · backend={proj.backend.name}")

    # 1. policy
    pol = proj.load_policy(rebuild=True)
    log(_c("B", f"\n[1/7] Rules → policy: {len(pol.rules)} rules from {cfg['rules']}", color))
    for r in pol.rules:
        log(f"  • {r.kind:22s} {r.target or '':24s} (rule {r.clause_id})")

    # 2. environment
    log(_c("B", "\n[2/7] Preparing the worker (egress denied, tracer on)", color))
    env = proj.backend.prepare(pol.sprite_network_policy())
    env_short = {"backend": proj.backend.name, **{k: v for k, v in proj.backend.describe().items() if k != "backend"},
                 "network": env.get("network"), "tracing": env.get("capabilities")}
    if env.get("network_policy"):
        env_short["network_policy"] = env["network_policy"]
    proj.ledger.reset()
    proj.ledger.set_meta("environment", env_short)
    log(f"  network: {env.get('network')}")
    log(f"  tracing: {env.get('capabilities')}")

    # 3. checkpoint
    base = proj.backend.checkpoint("baseline: code + data before any candidate")
    log(_c("B", f"\n[3/7] Checkpointed the starting state: {base}", color))

    # 4. run
    log(_c("B", "\n[4/7] Running candidates from the checkpoint", color))
    for cand in cfg["candidates"]:
        rec = proj.run(cand["name"], cand["cmd"], checkpoint=base, note=cand.get("note", ""))
        lb = rec["data"].get("leaderboard")
        ho = (rec["data"].get("holdout") or {}).get("auc")
        log(f"    leaderboard {lb if lb is None else f'{lb:.4f}'} · holdout AUC {ho if ho is None else f'{ho:.4f}'}")
        for f in rec["findings"]:
            if f.severity in ("FAIL", "WARN"):
                log("    " + _c(f.severity, f.severity, color) + f" {f.title}")
                if f.quote:
                    log(f"      rule {f.clause_id}: “{f.quote}”")
                for e in f.evidence[:2]:
                    log(f"      ↳ {e[:200]}")

    # 5. investigate
    log(_c("B", "\n[5/7] Investigating red flags", color))
    flagged = [n for n in proj.ledger.candidates()
               if any(f["severity"] == "FAIL" for f in proj.ledger.latest(n)["findings"])]
    if not flagged:
        log("  nothing to investigate")
    for n in flagged:
        for r in proj.investigate(n):
            v = r.get("verdict") or r["data"].get("verdict")
            log(f"  {n}: {v}")

    # 6. verify
    log(_c("B", "\n[6/7] Verifying reproduction from the checkpoint", color))
    for n in proj.ledger.candidates():
        if n in flagged:
            log(f"  {n}: skipped (already ineligible)")
            continue
        rec = proj.verify(n)
        f = [x for x in rec["findings"] if x.code in ("reproduced", "not_reproduced")][0]
        log(f"  {n}: " + _c(f.severity, "MATCH" if rec["reproduced"] else "MISMATCH", color) + f" · {f.detail}")

    # 7. honest score
    if honest and cfg.get("holdout"):
        log(_c("B", "\n[7/7] Honest score: seed spread on your holdout", color))
        for n in proj.ledger.candidates():
            ver = proj.ledger.latest(n, "verify")
            if n in flagged or not ver or not any(f["code"] == "reproduced" for f in ver["findings"]):
                continue
            sp = proj.seeds(n)
            if sp:
                log(f"  {n}: seeds {cfg['seeds']} → AUC {', '.join(f'{x:.4f}' for x in sp['scores'])} "
                    f"(sd {sp['sd']:.4f})")
    else:
        log(_c("B", "\n[7/7] Honest score skipped", color))

    summary = build_summary(proj.ledger, pol, env_short, honest=honest)
    if llm.configured():
        try:
            v = llm.verdict({k: summary[k] for k in ("candidates", "recommendation", "comparison")})
            proj.ledger.set_meta("verdict_llm", v)
            summary["verdict"] = v
        except Exception as e:
            log(f"  (LLM verdict skipped: {type(e).__name__}; using the deterministic verdict)")
    out = write_report(summary, proj.root / ".cleanroom")
    dests = publish(summary, proj.root / ".cleanroom" / "outbox", really=publish_github)
    rec = summary["recommendation"]
    log(_c("B", "\nRecommendation: ", color) + _c("PASS", str(rec["recommended"]), color))
    log(summary["verdict"])
    for cau in rec["cautions"]:
        log(_c("WARN", "  ⚠ " + cau, color))
    log(f"\nReport: {out}  ·  ledger: {proj.ledger.path}  ·  GitHub ledger: "
        + ("published" if publish_github else f"{len(dests)} issue payloads in .cleanroom/outbox"))
    log(f"Done in {time.time() - t0:.1f}s")
    return summary


__all__ = ["run_agent", "checks"]
