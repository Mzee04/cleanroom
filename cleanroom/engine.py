"""Run, verify and investigate candidates; record everything in the ledger."""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path

from . import checks
from .backends import Backend, RunSpec
from .config import load_config
from .policy import Policy, build_policy
from .scoring import score_file
from .store import Ledger
from .trace import load_trace


class Project:
    def __init__(self, root: Path, backend: Backend, use_llm: bool = True, log=print):
        self.root = Path(root).resolve()
        self.cfg = load_config(self.root)
        self.backend = backend
        self.ledger = Ledger(self.root / ".cleanroom" / "ledger.sqlite")
        self.use_llm = use_llm
        self.log = log
        self._policy: Policy | None = None

    # -- policy -------------------------------------------------------------
    @property
    def policy(self) -> Policy:
        if self._policy is None:
            self._policy = self.load_policy()
        return self._policy

    def load_policy(self, rules_path: Path | None = None, rebuild: bool = False) -> Policy:
        import hashlib
        rp = Path(rules_path) if rules_path else self.root / self.cfg["rules"]
        text = rp.read_text()
        cached = self.root / ".cleanroom" / "policy.json"
        if cached.exists() and not rebuild:
            pol = Policy.load(cached)
            if pol.rules_sha256 == hashlib.sha256(text.encode()).hexdigest():
                self._policy = pol
                return pol
        pol = build_policy(text, use_llm=self.use_llm)
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
        return self.root / ".cleanroom" / "runs" / f"{name}-{kind}-{int(time.time() * 1000)}"

    def _scores(self, outputs: dict) -> dict:
        data: dict = {}
        ho = self.cfg.get("holdout")
        if ho and ho["pred"] in outputs:
            try:
                sc = score_file(Path(outputs[ho["pred"]]), self.root / ho["truth"],
                                self.cfg["id_column"], self.cfg["pred_column"], ho.get("truth_column", "target"))
                data["holdout"] = {"auc": sc["auc"], "n": sc["n"], "ids": sc["ids"], "y": sc["y"], "s": sc["s"]}
            except Exception as e:
                data["holdout_error"] = f"{type(e).__name__}: {e}"
        lb = self.cfg.get("leaderboard_cmd")
        out = self.cfg["output"]
        if lb and out in outputs:
            cmd = [c.replace("{output}", outputs[out]) for c in lb]
            try:
                p = subprocess.run(cmd, cwd=self.root, capture_output=True, text=True, timeout=120)
                nums = re.findall(r"-?\d+\.\d+", p.stdout)
                data["leaderboard"] = float(nums[-1]) if nums else None
            except Exception as e:
                data["leaderboard_error"] = type(e).__name__
        return data

    def _enforced(self, res) -> bool:
        n = res.network.lower()
        return ("denied" in n or "refused" in n) and "not enforced" not in n and "resolves" not in n

    def _record(self, name, kind, cmd, res, extra_findings=(), data=None) -> dict:
        trace = load_trace(Path(res.trace_dir))
        outs = [self.cfg["output"]] + ([self.cfg["holdout"]["pred"]] if self.cfg.get("holdout") else [])
        findings = checks.analyse(trace, self.policy, res.workdir, res.exit_code, res.output_sha256,
                                  self.cfg["output"], outs, enforced=self._enforced(res),
                                  own_files=self.cfg.get("own_files", []))
        findings += list(extra_findings)
        d = {"notes": res.notes, "duration_s": res.duration_s, "stdout_tail": res.stdout_tail[-600:],
             "stderr_tail": res.stderr_tail[-600:], "trace_sources": trace.sources,
             "n_events": len(trace.events), **self._scores(res.outputs), **(data or {})}
        rid = self.ledger.add_run(name, kind, self.backend.name, cmd, res, findings, d)
        return {"id": rid, "candidate": name, "kind": kind, "result": res, "findings": findings, "data": d}

    # -- operations -------------------------------------------------------------
    def run(self, name: str, cmd: list[str], checkpoint: str | None = None, note: str = "") -> dict:
        cp = checkpoint or self.backend.checkpoint(f"before {name}")
        res = self.backend.run_from_checkpoint(cp, self.spec(name, cmd), self.trace_dir(name, "run"))
        res.checkpoint = cp
        rec = self._record(name, "run", cmd, res, data={"note": note})
        self.log(f"  {name}: exit {res.exit_code}, sha256 {str(res.output_sha256)[:12]}…, "
                 f"{checks.worst(rec['findings'])}")
        return rec

    def verify(self, name: str) -> dict:
        orig = self.ledger.latest(name, "run")
        if not orig:
            raise SystemExit(f"no run recorded for {name}; use `cleanroom run --name {name} -- ...` first")
        res = self.backend.run_from_checkpoint(orig["checkpoint"], self.spec(name, orig["cmd"]),
                                               self.trace_dir(name, "verify"))
        f = checks.check_reproduction(orig["sha256"], res.output_sha256, orig["checkpoint"], self.policy)
        rec = self._record(name, "verify", orig["cmd"], res, [f], data={"original_sha256": orig["sha256"]})
        rec["reproduced"] = f.severity == checks.PASS
        return rec

    def investigate(self, name: str) -> list[dict]:
        """Follow up every red flag on the candidate's latest run."""
        orig = self.ledger.latest(name, "run")
        out = []
        if not orig:
            return out
        forb = [f for f in orig["findings"] if f["code"] == "forbidden_file_read"]
        hidden = sorted({re.sub(r"^Read forbidden file ", "", f["title"]) for f in forb})
        hidden = [h for h in hidden if not h.startswith("/")]
        if hidden:
            res = self.backend.run_from_checkpoint(orig["checkpoint"], self.spec(name, orig["cmd"]),
                                                   self.trace_dir(name, "investigate"), hide=tuple(hidden))
            data = self._scores(res.outputs)
            before = {"leaderboard": orig["data"].get("leaderboard"),
                      "holdout": (orig["data"].get("holdout") or {}).get("auc")}
            after = {"leaderboard": data.get("leaderboard"), "holdout": (data.get("holdout") or {}).get("auc")}
            changed = res.output_sha256 != orig["sha256"]
            if res.exit_code != 0:
                verdict = (f"Without {', '.join(hidden)} the run crashes (exit {res.exit_code}): "
                           "the submission depends on the forbidden file.")
            elif changed:
                verdict = (f"Without {', '.join(hidden)} the output changes"
                           + (f" and the leaderboard score moves from {_f(before['leaderboard'])} to "
                              f"{_f(after['leaderboard'])}" if before["leaderboard"] is not None else "")
                           + ": the score depends on the forbidden file.")
            else:
                verdict = (f"Without {', '.join(hidden)} the output is identical: the file was read "
                           "but did not change this output. It is still a rules breach as written.")
            f = checks.Finding(checks.FAIL if (changed or res.exit_code) else checks.WARN,
                               "investigation", "Investigation: re-ran with the forbidden file hidden",
                               verdict, evidence=[f"original sha256 {orig['sha256']}",
                                                  f"without-file sha256 {res.output_sha256}"])
            rec = self._record(name, "investigate", orig["cmd"], res, [f],
                               data={"hidden": hidden, "before": before, "after": after, "verdict": verdict})
            out.append(rec)
        net = [f for f in orig["findings"] if f["code"] in ("network_attempt", "network_connect")]
        if net and orig["exit_code"] == 0:
            verdict = ("The run still produced its output with egress denied, so the model does not need the "
                       "download to work. Remove the network call before submitting; as written it breaks the rules.")
            out.append({"candidate": name, "kind": "investigate-network", "verdict": verdict})
            self.ledger.set_meta(f"investigate-network:{name}", verdict)
        return out

    def seeds(self, name: str) -> dict:
        orig = self.ledger.latest(name, "run")
        scores = []
        for s in self.cfg.get("seeds", [1, 2, 3]):
            res = self.backend.run_from_checkpoint(orig["checkpoint"],
                                                   self.spec(name, orig["cmd"], env={"CLEANROOM_SEED": str(s)}),
                                                   self.trace_dir(name, f"seed{s}"))
            data = self._scores(res.outputs)
            auc = (data.get("holdout") or {}).get("auc")
            if auc is not None:
                scores.append(auc)
        from .scoring import seed_spread
        spread = seed_spread(scores) if scores else None
        self.ledger.set_meta(f"seeds:{name}", spread)
        return spread or {}


def _f(x):
    return "n/a" if x is None else f"{x:.4f}"


def dump_json(obj) -> str:
    return json.dumps(obj, indent=2, default=lambda o: getattr(o, "__dict__", str(o)))
