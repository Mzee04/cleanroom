"""Run, verify and investigate candidates; record everything in the ledger.

Every follow-up (verify, investigation, seed runs) is bound to the exact
original run it checks: its run id, checkpoint, output SHA-256 and the policy
digest. A summary never pairs a run with a stale verification.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path

from . import checks
from .backends import Backend, RunSpec
from .backends.base import RunResult, state_root
from .config import load_config
from .policy import Policy, build_policy
from .scoring import ScoringError, read_ids, read_predictions, score_file
from .store import Ledger
from .trace import load_trace

FORBID_TITLE = re.compile(r"^Read forbidden file (.+?)(?: \(via .*\))?$")


class Project:
    def __init__(self, root: Path, backend: Backend, use_llm: bool = True, log=print, session: str | None = None):
        self.root = Path(root).resolve()
        self.cfg = load_config(self.root)
        self.backend = backend
        # the holdout truth and anything listed under "private" never go where candidates run
        priv = list(self.cfg.get("private", []))
        if (self.cfg.get("holdout") or {}).get("truth"):
            priv.append(self.cfg["holdout"]["truth"])
        for p in priv:
            p = p.rstrip("/")
            if p not in backend.private:
                backend.private.append(p)
        self.ledger = Ledger(self.root / ".cleanroom" / "ledger.sqlite", session=session)
        self.use_llm = use_llm
        self.log = log
        self._policy: Policy | None = None
        self.runs_root = state_root(self.root) / "runs"

    # -- policy -------------------------------------------------------------
    @property
    def policy(self) -> Policy:
        if self._policy is None:
            self._policy = self.load_policy()
        return self._policy

    def config_rules(self) -> list[dict]:
        out = []
        ho = self.cfg.get("holdout")
        if ho and ho.get("truth"):
            out.append({"kind": "forbid_file", "target": ho["truth"],
                        "quote": "Holdout truth: candidate code must never read the labels it is scored "
                                 "against (cleanroom.json holdout.truth)."})
        for t in self.cfg.get("forbid_files", []):
            out.append({"kind": "forbid_file", "target": t, "quote": f"cleanroom.json forbid_files: {t}"})
        return out

    def load_policy(self, rules_path: Path | None = None, rebuild: bool = False) -> Policy:
        import hashlib
        rp = Path(rules_path) if rules_path else self.root / self.cfg["rules"]
        text = rp.read_text()
        cached = self.root / ".cleanroom" / "policy.json"
        pol = None
        if cached.exists() and not rebuild:
            pol = Policy.load(cached)
            if pol.rules_sha256 != hashlib.sha256(text.encode()).hexdigest():
                pol = None
        if pol is None:
            pol = build_policy(text, use_llm=self.use_llm)
        pol.with_config_rules(self.config_rules())
        pol.save(cached)
        self._policy = pol
        return pol

    # -- helpers --------------------------------------------------------------
    def spec(self, name: str, cmd: list[str], env: dict | None = None) -> RunSpec:
        extra = [self.cfg["holdout"]["pred"]] if self.cfg.get("holdout") else []
        return RunSpec(name=name, cmd=cmd, output=self.cfg["output"], extra_outputs=extra,
                       env=env or {}, network_policy=self.policy.sprite_network_policy(),
                       timeout=self.cfg["timeout"])

    def trace_dir(self, name: str, kind: str) -> Path:
        return self.runs_root / f"{self.ledger.session}-{name}-{kind}-{int(time.time() * 1000)}"

    def _scores(self, outputs: dict) -> tuple[dict, list]:
        """Scores plus findings for invalid prediction files."""
        data: dict = {}
        found = []
        ho = self.cfg.get("holdout")
        idc, pc = self.cfg["id_column"], self.cfg["pred_column"]
        if ho:
            if ho["pred"] in outputs:
                try:
                    sc = score_file(Path(outputs[ho["pred"]]), self.root / ho["truth"], idc, pc,
                                    ho.get("truth_column", "target"))
                    data["holdout"] = {"auc": sc["auc"], "n": sc["n"], "ids": sc["ids"], "y": sc["y"], "s": sc["s"]}
                except (ScoringError, OSError, ValueError) as e:
                    data["holdout_error"] = str(e)[:300]
                    found.append(checks.Finding(checks.FAIL, "holdout_invalid",
                                                f"Holdout predictions {ho['pred']} are invalid", str(e)[:300]))
            else:
                found.append(checks.Finding(checks.WARN, "holdout_missing",
                                            f"No holdout predictions ({ho['pred']}) were written"))
        sub = self.cfg.get("submission_ids")
        out = self.cfg["output"]
        if sub and out in outputs:
            try:
                read_predictions(Path(outputs[out]), idc, pc, expected_ids=read_ids(self.root / sub, idc))
            except (ScoringError, OSError, ValueError) as e:
                found.append(checks.Finding(checks.FAIL, "submission_invalid",
                                            f"Submission {out} does not match the expected ids", str(e)[:300]))
                data["submission_error"] = str(e)[:300]
        lb = self.cfg.get("leaderboard_cmd")
        if lb and out in outputs and "submission_error" not in data:
            cmd = [c.replace("{output}", outputs[out]) for c in lb]
            try:
                p = subprocess.run(cmd, cwd=self.root, capture_output=True, text=True, timeout=120)
                nums = re.findall(r"-?\d+\.\d+", p.stdout)
                data["leaderboard"] = float(nums[-1]) if nums else None
            except Exception as e:
                data["leaderboard_error"] = type(e).__name__
        return data, found

    def _record(self, name, kind, cmd, res, extra_findings=(), data=None) -> dict:
        trace = load_trace(Path(res.trace_dir))
        outs = [self.cfg["output"]] + ([self.cfg["holdout"]["pred"]] if self.cfg.get("holdout") else [])
        findings = checks.analyse(trace, self.policy, res.workdir, res.exit_code, res.output_sha256,
                                  self.cfg["output"], outs, enforced=res.egress_verified,
                                  own_files=self.cfg.get("own_files", []), tracer=res.tracer)
        scores, score_findings = self._scores(res.outputs)
        findings += score_findings + list(extra_findings)
        d = {"notes": res.notes, "duration_s": res.duration_s, "stdout_tail": res.stdout_tail[-600:],
             "stderr_tail": res.stderr_tail[-600:], "trace_sources": trace.sources,
             "n_events": len(trace.events), "policy_sha256": self.policy.digest(),
             "rules_sha256": self.policy.rules_sha256, "egress_verified": res.egress_verified,
             "candidate_uid": res.candidate_uid, "fingerprint": dict(self.backend.fingerprint or {}),
             "session": self.ledger.session, **scores, **(data or {})}
        rid = self.ledger.add_run(name, kind, self.backend.name, cmd, res, findings, d)
        return {"id": rid, "candidate": name, "kind": kind, "result": res, "findings": findings, "data": d}

    def _bind(self, orig: dict) -> dict:
        return {"original_run_id": orig["id"], "original_sha256": orig["sha256"],
                "policy_sha256": orig["data"].get("policy_sha256")}

    def _check_policy(self, orig: dict):
        if orig["data"].get("policy_sha256") != self.policy.digest():
            raise SystemExit(f"{orig['candidate']}'s run was checked against a different policy; run it again")

    def _attempt(self, name: str, kind: str, checkpoint: str, spec: RunSpec, hide: tuple = ()):
        """Run on the backend; an infrastructure failure becomes an INCONCLUSIVE run, never a crash
        of the whole loop (one bad candidate must not take the others with it)."""
        td = self.trace_dir(name, kind)
        try:
            return self.backend.run_from_checkpoint(checkpoint, spec, td, hide=hide), []
        except Exception as e:  # noqa: BLE001 - any backend error is reported, not raised
            Path(td).mkdir(parents=True, exist_ok=True)
            msg = f"{type(e).__name__}: {str(e)[:300]}"
            self.log(f"  {name}: {kind} could not complete ({msg})")
            res = RunResult(exit_code=-1, duration_s=0.0, workdir="", trace_dir=str(td), output_sha256=None,
                            outputs={}, tracer="none", network="unknown", checkpoint=checkpoint, notes=[msg])
            return res, [checks.Finding(checks.INCONCLUSIVE, "run_infrastructure_failed",
                                        "The run could not be completed on the backend", msg)]

    # -- operations -------------------------------------------------------------
    def run(self, name: str, cmd: list[str], checkpoint: str | None = None, note: str = "") -> dict:
        cp = checkpoint or self.backend.checkpoint(f"before {name}")
        res, extra = self._attempt(name, "run", cp, self.spec(name, cmd))
        res.checkpoint = cp
        rec = self._record(name, "run", cmd, res, extra, data={"note": note})
        self.log(f"  {name}: exit {res.exit_code}, sha256 {str(res.output_sha256)[:12]}…, "
                 f"{checks.worst(rec['findings'])}")
        return rec

    def verify(self, name: str) -> dict:
        orig = self.ledger.latest(name, "run")
        if not orig:
            raise SystemExit(f"no run recorded for {name}; use `cleanroom run --name {name} -- ...` first")
        self._check_policy(orig)
        res, extra = self._attempt(name, "verify", orig["checkpoint"], self.spec(name, orig["cmd"]))
        f = checks.check_reproduction(orig["sha256"], res.output_sha256, orig["checkpoint"], self.policy)
        rec = self._record(name, "verify", orig["cmd"], res, [f, *extra], data=self._bind(orig))
        rec["reproduced"] = f.severity == checks.PASS
        return rec

    def investigate(self, name: str) -> list[dict]:
        """Follow up red flags on the candidate's latest run with one-factor re-runs.

        Before blaming a file, the run is repeated unchanged from the same
        checkpoint (determinism baseline). Only if that reproduces the original
        output can a change with the file hidden be attributed to the file.
        """
        orig = self.ledger.latest(name, "run")
        out: list[dict] = []
        if not orig:
            return out
        self._check_policy(orig)
        flags = [f for f in orig["findings"] if f["severity"] in ("FAIL", "WARN", "INCONCLUSIVE")]
        forb = [f for f in flags if f["code"] == "forbidden_file_read"]
        hidden = sorted({m.group(1) for f in forb if (m := FORBID_TITLE.match(f["title"]))})
        hidden = [h for h in hidden if not h.startswith("/")]
        net = [f for f in flags if f["code"] in ("network_attempt", "network_connect")]
        investigated = [f["title"] for f in forb if FORBID_TITLE.match(f["title"])] + [f["title"] for f in net]
        remaining = [f["title"] for f in flags if f["title"] not in investigated]
        if hidden:
            base, _ = self._attempt(name, "baseline", orig["checkpoint"], self.spec(name, orig["cmd"]))
            deterministic = base.exit_code == 0 and base.output_sha256 == orig["sha256"]
            self._record(name, "investigate-baseline", orig["cmd"], base, data=self._bind(orig))
            res, _ = self._attempt(name, "investigate", orig["checkpoint"], self.spec(name, orig["cmd"]),
                                   hide=tuple(hidden))
            data, _ = self._scores(res.outputs)
            before = {"leaderboard": orig["data"].get("leaderboard"),
                      "holdout": (orig["data"].get("holdout") or {}).get("auc")}
            after = {"leaderboard": data.get("leaderboard"), "holdout": (data.get("holdout") or {}).get("auc")}
            changed = res.output_sha256 != orig["sha256"]
            files = ", ".join(hidden)
            lb_move = (f" and the leaderboard score moves from {_f(before['leaderboard'])} to "
                       f"{_f(after['leaderboard'])}" if before["leaderboard"] is not None else "")
            if base.exit_code == -1 or res.exit_code == -1:
                verdict = ("One-factor re-run could not be completed on the backend, so whether the score "
                           f"depends on {files} is unknown. Reading it is still a rules breach as written.")
                sev = checks.WARN
            elif not deterministic:
                verdict = (f"One-factor re-run inconclusive: re-running unchanged from the same checkpoint did "
                           f"not reproduce the original output, so a change without {files} cannot be "
                           "attributed to the file. Reading it is still a rules breach as written.")
                sev = checks.WARN
            elif res.exit_code != 0:
                verdict = (f"One-factor re-run: the unchanged re-run reproduced the output, and without {files} "
                           f"the run crashes (exit {res.exit_code}): the submission depends on the forbidden file.")
                sev = checks.FAIL
            elif changed:
                verdict = (f"One-factor re-run: the unchanged re-run reproduced the output, and without {files} "
                           f"the output changes{lb_move}: the score depends on the forbidden file.")
                sev = checks.FAIL
            else:
                verdict = (f"One-factor re-run: without {files} the output is identical, so the file was read "
                           "but did not change this output. It is still a rules breach as written.")
                sev = checks.WARN
            f = checks.Finding(sev, "investigation", "Investigation (one-factor re-run): forbidden file hidden",
                               verdict, evidence=[f"original sha256 {orig['sha256']}",
                                                  f"unchanged re-run sha256 {base.output_sha256}",
                                                  f"without-file sha256 {res.output_sha256}"])
            rec = self._record(name, "investigate", orig["cmd"], res, [f],
                               data={"hidden": hidden, "before": before, "after": after, "verdict": verdict,
                                     "deterministic": deterministic, "investigated": investigated,
                                     "remaining": remaining, **self._bind(orig)})
            out.append(rec)
        if net and orig["exit_code"] == 0:
            if orig["data"].get("egress_verified"):
                verdict = ("One-factor check: the run produced its output while egress denial was verified, so "
                           "the output did not need the download. Remove the network call before submitting; "
                           "as written it breaks the rules.")
            else:
                verdict = ("Egress denial was not verified for this run, so Clean Room cannot say whether the "
                           "output needed the download. The network call breaks the rules as written.")
            out.append({"candidate": name, "kind": "investigate-network", "verdict": verdict})
            self.ledger.set_meta(f"investigate-network:{name}",
                                 {"verdict": verdict, "investigated": investigated, "remaining": remaining,
                                  "run_id": orig["id"], "checkpoint": orig["checkpoint"],
                                  "policy_sha256": orig["data"].get("policy_sha256")})
        return out

    def seeds(self, name: str) -> dict:
        orig = self.ledger.latest(name, "run")
        if orig is None:
            raise ValueError(f"no run recorded for {name}")
        scores, shas = [], []
        for s in self.cfg.get("seeds", [1, 2, 3]):
            res, _ = self._attempt(name, f"seed{s}", orig["checkpoint"],
                                   self.spec(name, orig["cmd"], env={"CLEANROOM_SEED": str(s)}))
            data, _ = self._scores(res.outputs)
            auc = (data.get("holdout") or {}).get("auc")
            if auc is not None and res.exit_code == 0:
                scores.append(auc)
                shas.append(res.output_sha256)
        from .scoring import seed_spread
        spread = seed_spread(scores, shas)
        if spread:
            spread.update(run_id=orig["id"], checkpoint=orig["checkpoint"],
                          policy_sha256=orig["data"].get("policy_sha256"), seeds=self.cfg.get("seeds", [1, 2, 3]))
        self.ledger.set_meta(f"seeds:{name}", spread)
        return spread or {}


def _f(x):
    return "n/a" if x is None else f"{x:.4f}"


def dump_json(obj) -> str:
    return json.dumps(obj, indent=2, default=lambda o: getattr(o, "__dict__", str(o)))
