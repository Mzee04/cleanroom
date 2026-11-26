"""The Clean Room agent loop.

  1. read the rules and derive a policy (each rule keeps its quote)
  2. prepare the worker: deny egress, install tracer, upload code + data
  3. checkpoint the starting state once, so every candidate starts identical
  4. run every candidate from that checkpoint, traced, egress denied
  5. investigate every red flag (re-run with the forbidden file hidden, etc.)
  6. verify reproduction: restore the checkpoint, re-run, compare SHA-256
  7. optional honest score: bootstrap CI on your holdout + seed spread
  then (unnumbered in the log): recommend, explain, write the report, optionally log to GitHub
"""
from __future__ import annotations

import time

from . import checks, llm
from .engine import Project
from .ghledger import publish
from .report import write_report
from .summary import build_summary, validate_verdict

C = {"FAIL": "\033[31m", "INCONCLUSIVE": "\033[35m", "WARN": "\033[33m", "PASS": "\033[32m", "INFO": "\033[36m",
     "B": "\033[1m", "0": "\033[0m"}


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
    if env.get("fingerprint"):
        env_short["fingerprint"] = env["fingerprint"]
    sid = proj.ledger.start_session(f"agent loop on {proj.backend.name}")   # history is kept, never wiped
    proj.ledger.set_meta("environment", env_short)
    log(f"  session: {sid}")
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
        log(f"    tracer {rec['result'].tracer} · candidate uid {rec['result'].candidate_uid} · "
            f"leaderboard {lb if lb is None else f'{lb:.4f}'} · holdout AUC {ho if ho is None else f'{ho:.4f}'}")
        for f in rec["findings"]:
            if f.severity in ("FAIL", "WARN", "INCONCLUSIVE"):
                log("    " + _c(f.severity, f.severity, color) + f" {f.title}")
                if f.quote:
                    log(f"      rule {f.clause_id}: “{f.quote}”")
                for e in f.evidence[:2]:
                    log(f"      ↳ {e[:200]}")

    # 5. investigate
    log(_c("B", "\n[5/7] Investigating red flags", color))
    flagged = [n for n in proj.ledger.candidates()
               if any(f["severity"] == "FAIL" for f in (proj.ledger.latest(n) or {}).get("findings", []))]
    if not flagged:
        log("  nothing to investigate")
    for n in flagged:
        try:
            for inv in proj.investigate(n):
                v = inv.get("verdict") or inv["data"].get("verdict")
                log(f"  {n}: {v}")
        except Exception as e:  # noqa: BLE001 - one candidate's failure must not stop the others
            log(f"  {n}: investigation could not complete ({type(e).__name__}: {str(e)[:200]})")

    # 6. verify
    log(_c("B", "\n[6/7] Verifying reproduction from the checkpoint", color))
    for n in proj.ledger.candidates():
        if n in flagged:
            log(f"  {n}: skipped (already ineligible)")
            continue
        try:
            rec = proj.verify(n)
        except Exception as e:  # noqa: BLE001 - recorded as "reproduction not checked"
            log(f"  {n}: verification could not complete ({type(e).__name__}: {str(e)[:200]})")
            continue
        f = [x for x in rec["findings"] if x.code in ("reproduced", "not_reproduced")][0]
        log(f"  {n}: " + _c(f.severity, "MATCH" if rec["reproduced"] else "MISMATCH", color) + f" · {f.detail}")

    # 7. honest score
    if honest and cfg.get("holdout"):
        log(_c("B", "\n[7/7] Honest score: seed spread on your holdout", color))
        for n in proj.ledger.candidates():
            ver = proj.ledger.latest(n, "verify")
            if n in flagged or not ver or not any(f["code"] == "reproduced" for f in ver["findings"]):
                continue
            try:
                sp = proj.seeds(n)
            except Exception as e:  # noqa: BLE001
                log(f"  {n}: seed runs could not complete ({type(e).__name__}: {str(e)[:200]})")
                continue
            if sp:
                sd = "n/a" if sp.get("sd") is None else f"{sp['sd']:.4f}"
                log(f"  {n}: seeds {cfg['seeds']} → AUC {', '.join(f'{x:.4f}' for x in sp['scores'])} "
                    f"(sample sd {sd}{', outputs identical' if sp.get('identical_outputs') else ''})")
    else:
        log(_c("B", "\n[7/7] Honest score skipped", color))

    summary = build_summary(proj.ledger, pol, env_short, honest=honest)
    if llm.configured():
        try:
            v = llm.verdict(summary)
            if validate_verdict(v, summary):
                proj.ledger.set_meta("verdict_llm", v)
                summary["verdict"] = v
            else:
                log("  (LLM verdict disagreed with the evidence; using the deterministic verdict)")
        except Exception as e:
            log(f"  (LLM verdict skipped: {type(e).__name__}; using the deterministic verdict)")
    dests = publish(summary, proj.root / ".cleanroom" / "outbox", really=publish_github, ledger=proj.ledger)
    posted = {d["name"]: d["url"] for d in dests if d.get("url")}
    summary["ledger_chain"] = proj.ledger.get_meta("chain_head", None, glob=True)
    if posted:
        proj.ledger.set_meta("github_issues", posted)
        for c in summary["candidates"]:
            c["ledger_issue"] = posted.get(c["name"])
    out = write_report(summary, proj.root / ".cleanroom")
    rec = summary["recommendation"]
    log(_c("B", "\nRecommendation: ", color) + _c("PASS", str(rec["recommended"]), color))
    log(summary["verdict"])
    for cau in rec["cautions"]:
        log(_c("WARN", "  ⚠ " + cau, color))
    if publish_github:
        log(_c("B", "\nGitHub ledger (via the Sprites GitHub connector):", color))
        for d in dests:
            log(f"  {d['name']}: " + (d.get("url") or d.get("error") or f"not posted ({d.get('path')})")
                + (f" ({d['action']})" if d.get("action") else ""))
    log(f"\nReport: {out}  ·  ledger: {proj.ledger.path}  ·  GitHub ledger: "
        + (f"{len(posted)}/{len(dests)} issues posted" if publish_github
           else f"{len(dests)} issue payloads in .cleanroom/outbox"))
    log(f"Done in {time.time() - t0:.1f}s")
    return summary


__all__ = ["run_agent", "checks"]
