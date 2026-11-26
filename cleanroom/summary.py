"""Assemble the evidence for every candidate from the ledger (current session).

Follow-up runs are joined to a candidate's run only when they are bound to it
exactly (run id, checkpoint, output SHA-256, policy digest). Everything that
leaves the agent (report, report.json, GitHub issues) is redacted: commands
lose secret-looking arguments and home directories are masked.
"""
from __future__ import annotations

import time

from .recommend import Candidate, recommend
from .redact import redact_cmd, redact_text
from .scoring import bootstrap_ci, paired_bootstrap_diff
from .store import Ledger


def _bound_meta(m, run) -> bool:
    return bool(m) and m.get("run_id") == run["id"] and m.get("checkpoint") == run["checkpoint"] \
        and m.get("policy_sha256") == run["data"].get("policy_sha256")


def _clean_finding(f: dict) -> dict:
    return {**f, "title": redact_text(f["title"]), "detail": redact_text(f["detail"]),
            "evidence": [redact_text(e) for e in f.get("evidence", [])]}


def status_of(findings) -> str:
    sev = {f["severity"] for f in findings}
    for s in ("FAIL", "INCONCLUSIVE", "WARN"):
        if s in sev:
            return s
    return "PASS"


def build_summary(ledger: Ledger, policy, env: dict | None = None, honest: bool = True) -> dict:
    cands = []
    rec_inputs = []
    issues = ledger.get_meta("github_issues") or {}
    for name in ledger.candidates():
        run = ledger.latest(name, "run")
        ver = ledger.latest_for(name, "verify", run)
        inv = ledger.latest_for(name, "investigate", run)
        seeds = ledger.get_meta(f"seeds:{name}")
        seeds = seeds if _bound_meta(seeds, run) else None
        netinv = ledger.get_meta(f"investigate-network:{name}")
        netinv = netinv if _bound_meta(netinv, run) else None
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
        if inv and any(f["code"] == "investigation" and f["severity"] == "FAIL" for f in inv["findings"]) \
                and not fails:
            fails = ["investigation"]
        inconc = [f["title"] for f in findings if f["severity"] == "INCONCLUSIVE"]
        warns = [f["title"] for f in findings if f["severity"] == "WARN"]
        clean = [_clean_finding(f) for f in findings]
        c = {
            "name": name, "note": run["data"].get("note", ""), "cmd": redact_cmd(run["cmd"]),
            "run_id": run["id"], "session": ledger.session,
            "checkpoint": run["checkpoint"], "sha256": run["sha256"], "exit_code": run["exit_code"],
            "tracer": run["tracer"], "candidate_uid": run["data"].get("candidate_uid"),
            "egress_verified": run["data"].get("egress_verified"),
            "network": run["network"], "backend": run["backend"],
            "policy_sha256": run["data"].get("policy_sha256"), "fingerprint": run["data"].get("fingerprint"),
            "leaderboard": run["data"].get("leaderboard"), "holdout": ho.get("auc"), "holdout_n": ho.get("n"),
            "holdout_ci": ci, "seeds": seeds, "reproduced": reproduced,
            "verify_sha256": ver["sha256"] if ver else None, "verify_run_id": ver["id"] if ver else None,
            "investigation": inv["data"].get("verdict") if inv else None,
            "investigated": (inv["data"].get("investigated") if inv else None)
            or (netinv or {}).get("investigated"),
            "remaining_flags": (inv["data"].get("remaining") if inv else None) or (netinv or {}).get("remaining"),
            "network_investigation": (netinv or {}).get("verdict"), "ledger_issue": issues.get(name),
            "findings": clean, "fails": [redact_text(x) for x in fails],
            "inconclusive": [redact_text(x) for x in inconc], "warns": [redact_text(x) for x in warns],
            "status": status_of(findings),
            "n_events": run["data"].get("n_events"), "trace_sources": run["data"].get("trace_sources"),
            "duration_s": run["data"].get("duration_s"),
            "_ids": ho.get("ids"), "_y": ho.get("y"), "_s": ho.get("s"),
        }
        cands.append(c)
        rec_inputs.append(Candidate(name, c["fails"], warns, reproduced, ho.get("auc"), c["leaderboard"],
                                    seeds.get("sd") if seeds else None, inconclusive=c["inconclusive"]))
    rec = recommend(rec_inputs)
    by = {c["name"]: c for c in cands}
    pick = rec["recommended"]
    if pick:
        p = by[pick]
        if p["tracer"] and "strace" not in p["tracer"]:
            rec["cautions"].insert(0, f"{pick} was traced by the in-process audit hook only (no strace); "
                                      "treat its file and network checks as WARN-level evidence.")
        if p["candidate_uid"] == "same":
            rec["cautions"].append(f"{pick} ran in development mode (same uid as the tracer); re-run on the Sprite "
                                   "backend before relying on it.")
        if p["seeds"] and p["seeds"].get("identical_outputs"):
            rec["cautions"].append(f"{pick}'s output was byte-identical for every seed, so either it is fully "
                                   "deterministic or it ignores CLEANROOM_SEED; the seed spread says nothing "
                                   "about seed sensitivity in that case.")
        if honest and p["holdout_ci"] and len(rec["ranking"]) > 1:
            rec["cautions"].append(f"{pick} was picked as the best holdout score, so its interval is optimistic "
                                   "(selection after the maximum); use the paired comparison below.")
    comparison = None
    if honest and pick and len(rec["ranking"]) > 1:
        a, b = by[rec["ranking"][0]], by[rec["ranking"][1]]
        if a["_ids"] and b["_ids"]:
            d = paired_bootstrap_diff(a["_ids"], a["_y"], a["_s"], b["_ids"], b["_y"], b["_s"], n_boot=600, seed=0)
            if d:
                comparison = {"a": a["name"], "b": b["name"], **d}
    for c in cands:
        for k in ("_ids", "_y", "_s"):
            c.pop(k)
    summary = {"generated": time.strftime("%Y-%m-%d %H:%M:%S %Z"), "session": ledger.session,
               "candidates": cands, "recommendation": rec, "comparison": comparison,
               "policy": policy.to_dict(), "policy_sha256": policy.digest(),
               "environment": env or ledger.get_meta("environment", {}),
               "ledger_chain": ledger.get_meta("chain_head", None, glob=True)}
    llm_v = ledger.get_meta("verdict_llm")
    summary["verdict"] = llm_v if (llm_v and validate_verdict(llm_v, summary)) else deterministic_verdict(summary)
    return summary


def validate_verdict(text: str, s: dict) -> bool:
    """An LLM verdict is used only if it agrees with the deterministic recommendation."""
    import re
    rec = s["recommendation"]["recommended"]
    names = [c["name"] for c in s["candidates"]]
    if not isinstance(text, str) or not text.strip() or len(text) > 2000:
        return False
    said = set(re.findall(r"\b(?:submit|recommend(?:ed)?|pick|choose|go with)\s+(?:candidate\s+)?([A-Za-z0-9_-]+)",
                          text, re.I))
    said = {x for x in said if x in names}
    if rec is None:
        return not said
    return rec in text and said <= {rec} and re.search(r"\bguarantee|\bclean\b", text, re.I) is None


def deterministic_verdict(s: dict) -> str:
    rec = s["recommendation"]
    by = {c["name"]: c for c in s["candidates"]}
    if not rec["recommended"]:
        return ("No candidate is ready to submit: every one has a failed or inconclusive check. "
                "See the findings below for what to fix.")
    r = by[rec["recommended"]]
    parts = [f"Submit {r['name']}."]
    traced = "its trace" if "strace" in (r["tracer"] or "") else "its audit-hook-only trace (WARN-level evidence)"
    why = [f"No forbidden access detected in {traced}", "no network attempts" if not any(
        f["code"].startswith("network") for f in r["findings"]) else "only allowed hosts contacted"]
    if r["reproduced"]:
        why.append(f"its output reproduced from checkpoint {r['checkpoint']} (SHA-256 match: reproduced in the "
                   "recorded environment)")
    parts.append(", ".join(why[:-1]) + ", and " + why[-1] + ".")
    if r["holdout"] is not None:
        parts.append(f"Its holdout ROC AUC is {r['holdout']:.4f}"
                     + (f" (95% CI {r['holdout_ci'][0]:.3f}–{r['holdout_ci'][1]:.3f}, optimistic because it is "
                        "the top pick)" if r["holdout_ci"] else " (interval unavailable)") + ".")
    for name, why_list in rec["rejected"].items():
        c = by[name]
        lb = f" despite a leaderboard score of {c['leaderboard']:.4f}" if c["leaderboard"] is not None else ""
        parts.append(f"\n{name} is not recommended{lb}: {why_list[0].rstrip('.')}.")
    cmp_ = s.get("comparison")
    if cmp_:
        if cmp_["conclusive"]:
            parts.append(f"\nOn your holdout, {cmp_['a']} beats {cmp_['b']} by {cmp_['diff']:+.4f} AUC and the "
                         "95% paired bootstrap interval excludes zero.")
        else:
            parts.append(f"\n{cmp_['a']} vs {cmp_['b']} on your holdout: {cmp_['diff']:+.4f} AUC, but the 95% "
                         f"interval ({cmp_['lo']:+.4f} to {cmp_['hi']:+.4f}) includes zero, so the edge is within noise "
                         f"and {cmp_['b']} would be an equally defensible pick.")
    return " ".join(parts).replace(" \n", "\n")
