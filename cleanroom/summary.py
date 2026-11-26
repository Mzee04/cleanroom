"""Assemble the evidence for every candidate from the ledger."""
from __future__ import annotations

import time

from .recommend import Candidate, recommend
from .scoring import bootstrap_ci, paired_bootstrap_diff
from .store import Ledger


def build_summary(ledger: Ledger, policy, env: dict | None = None, honest: bool = True) -> dict:
    cands = []
    rec_inputs = []
    issues = ledger.get_meta("github_issues") or {}
    for name in ledger.candidates():
        run = ledger.latest(name, "run")
        ver = ledger.latest(name, "verify")
        inv = ledger.latest(name, "investigate")
        seeds = ledger.get_meta(f"seeds:{name}")
        netinv = ledger.get_meta(f"investigate-network:{name}")
        findings = list(run["findings"])
        if ver:
            findings += [f for f in ver["findings"] if f["code"] in ("reproduced", "not_reproduced")]
        if inv:
            findings += [f for f in inv["findings"] if f["code"] == "investigation"]
        reproduced = None
        if ver:
            reproduced = any(f["code"] == "reproduced" for f in ver["findings"])
        ho = run["data"].get("holdout") or {}
        ci = None
        if honest and ho.get("y"):
            ci = bootstrap_ci(ho["y"], ho["s"], n_boot=600, seed=0)
        fails = [f["title"] for f in findings if f["severity"] == "FAIL" and f["code"] != "investigation"]
        warns = [f["title"] for f in findings if f["severity"] == "WARN"]
        c = {
            "name": name, "note": run["data"].get("note", ""), "cmd": run["cmd"],
            "checkpoint": run["checkpoint"], "sha256": run["sha256"], "exit_code": run["exit_code"],
            "tracer": run["tracer"], "network": run["network"], "backend": run["backend"],
            "leaderboard": run["data"].get("leaderboard"), "holdout": ho.get("auc"), "holdout_ci": ci,
            "seeds": seeds, "reproduced": reproduced,
            "verify_sha256": ver["sha256"] if ver else None,
            "investigation": inv["data"].get("verdict") if inv else None,
            "network_investigation": netinv, "ledger_issue": issues.get(name),
            "findings": findings, "fails": fails, "warns": warns,
            "status": "FAIL" if fails else ("WARN" if warns else "PASS"),
            "n_events": run["data"].get("n_events"), "trace_sources": run["data"].get("trace_sources"),
            "trace_dir": run["trace_dir"], "duration_s": run["data"].get("duration_s"),
            "_y": ho.get("y"), "_s": ho.get("s"),
        }
        cands.append(c)
        rec_inputs.append(Candidate(name, fails, warns, reproduced, ho.get("auc"), c["leaderboard"],
                                    seeds.get("sd") if seeds else None))
    rec = recommend(rec_inputs)
    comparison = None
    if honest and rec["recommended"] and len(rec["ranking"]) > 1:
        a = next(c for c in cands if c["name"] == rec["ranking"][0])
        b = next(c for c in cands if c["name"] == rec["ranking"][1])
        if a["_y"] and a["_y"] == b["_y"]:
            comparison = {"a": a["name"], "b": b["name"],
                          **paired_bootstrap_diff(a["_y"], a["_s"], b["_s"], n_boot=600, seed=0)}
    for c in cands:
        c.pop("_y")
        c.pop("_s")
    summary = {"generated": time.strftime("%Y-%m-%d %H:%M:%S %Z"), "candidates": cands,
               "recommendation": rec, "comparison": comparison, "policy": policy.to_dict(),
               "environment": env or ledger.get_meta("environment", {})}
    summary["verdict"] = ledger.get_meta("verdict_llm") or deterministic_verdict(summary)
    return summary


def deterministic_verdict(s: dict) -> str:
    rec = s["recommendation"]
    by = {c["name"]: c for c in s["candidates"]}
    if not rec["recommended"]:
        return ("No candidate is ready to submit: every one has a failed check. "
                "See the findings below for what to fix.")
    r = by[rec["recommended"]]
    parts = [f"Submit {r['name']}."]
    why = ["No forbidden access detected in its trace", "no network attempts" if not any(
        f["code"].startswith("network") for f in r["findings"]) else "only allowed hosts contacted"]
    if r["reproduced"]:
        why.append(f"its output reproduced from checkpoint {r['checkpoint']} (SHA-256 match; this proves "
                   "reproduction in this environment only)")
    parts.append(", ".join(why[:-1]) + ", and " + why[-1] + ".")
    if r["holdout"] is not None:
        parts.append(f"Its holdout ROC AUC is {r['holdout']:.4f}"
                     + (f" (95% CI {r['holdout_ci'][0]:.3f}–{r['holdout_ci'][1]:.3f})" if r["holdout_ci"] else "")
                     + ".")
    for name, why_list in rec["rejected"].items():
        c = by[name]
        lb = f" despite a leaderboard score of {c['leaderboard']:.4f}" if c["leaderboard"] is not None else ""
        parts.append(f"\n{name} is not recommended{lb}: {why_list[0].rstrip('.')}.")
    cmp_ = s.get("comparison")
    if cmp_:
        if cmp_["conclusive"]:
            parts.append(f"\nOn your holdout, {cmp_['a']} beats {cmp_['b']} by {cmp_['diff']:+.4f} AUC and the "
                         "95% bootstrap interval excludes zero.")
        else:
            parts.append(f"\n{cmp_['a']} vs {cmp_['b']} on your holdout: {cmp_['diff']:+.4f} AUC, but the 95% "
                         f"interval ({cmp_['lo']:+.4f} to {cmp_['hi']:+.4f}) includes zero, so the edge is within noise "
                         f"and {cmp_['b']} would be an equally defensible pick.")
    return " ".join(parts).replace(" \n", "\n")
