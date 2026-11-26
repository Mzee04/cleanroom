"""One regression test (or more) per finding from the external reviews."""
import json
import math
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from cleanroom import checks
from cleanroom.backends.base import base_env
from cleanroom.policy import extract_policy, merge_llm_rules
from cleanroom.trace import Event, Trace, load_trace, parse_strace_line

RULES = ("1.2 The file test_labels.csv must not be read by participant code.\n"
         "1.1 Participants may use train.csv.\n"
         "2.1 Internet access is disabled and code must not make network calls.\n"
         "3.1 Fix all random seeds so that a re-run produces the same submission file.\n")
HAVE_STRACE = shutil.which("strace") is not None and subprocess.run(
    ["strace", "-f", "-qq", "-o", "/dev/null", "true"], capture_output=True).returncode == 0


def ev(**kw):
    return Event(**{"source": "strace", "file": "strace.1", "lineno": 1, "line": "x", **kw})


def codes(fs, sev=None):
    return {f.code for f in fs if sev is None or f.severity == sev}


# ---- 1/2. runner: process cleanup, trace placement, strace in the runner ------
def _runner_spec(tmp_path, cmd, **kw):
    work = tmp_path / "work"
    (work / "data").mkdir(parents=True, exist_ok=True)
    (work / "data" / "test_labels.csv").write_text("id,target\n1,1\n")
    (work / "data" / "train.csv").write_text("id,x\n1,2\n")
    spec = {"token": "t0k", "work": str(work), "trace": str(tmp_path / "rt"), "bundle": str(tmp_path / "b.tgz"),
            "done": str(tmp_path / "done"), "cmd": cmd, "env": base_env({"PYTHONPATH": str(
                Path(__file__).resolve().parents[1] / "cleanroom" / "_hook")}),
            "timeout": 30, "outputs": ["out.txt"], "strace": True,
            "strace_args": __import__("cleanroom.trace", fromlist=["STRACE_ARGS"]).STRACE_ARGS,
            "netns": "none", "scan_dirs": [str(work)]}
    spec.update(kw)
    return spec


def _run_runner(tmp_path, spec):
    from cleanroom._runner import runner
    runner.run(spec)
    from cleanroom.backends.base import extract_bundle
    assert (tmp_path / "done").read_text().strip() == spec["token"]
    probs = extract_bundle(Path(spec["bundle"]).read_bytes(), tmp_path / "trace")
    return probs, load_trace(tmp_path / "trace")


@pytest.mark.skipif(not HAVE_STRACE, reason="strace not usable here")
def test_runner_kills_leftovers_and_catches_env_cleared_child(tmp_path):
    code = ("import subprocess,sys\n"
            "subprocess.Popen(['sleep','300'], start_new_session=True)\n"
            # a child with env={} has no audit hook; only strace can see it
            "subprocess.run([sys.executable,'-c',\"open('data/test_labels.csv').read()\"], env={})\n"
            "open('out.txt','w').write('ok')\n")
    spec = _runner_spec(tmp_path, [sys.executable, "-c", code])
    probs, t = _run_runner(tmp_path, spec)
    assert probs == []
    assert t.meta["rc"] == 0 and t.complete is True and "strace" in t.sources
    assert t.meta["leftover_tracees"] >= 1
    assert subprocess.run(["pgrep", "-f", "^sleep 300$"], capture_output=True).returncode != 0
    pol = extract_policy(RULES)
    fs = checks.analyse(t, pol, spec["work"], 0, "x", "out.txt", ["out.txt"], tracer="strace+audit")
    assert "forbidden_file_read" in codes(fs, "FAIL")


@pytest.mark.skipif(not HAVE_STRACE, reason="strace not usable here")
def test_runner_timeout_kills_process_group(tmp_path):
    code = "import subprocess,time\nsubprocess.Popen(['sleep','301'])\ntime.sleep(60)\n"
    spec = _runner_spec(tmp_path, [sys.executable, "-c", code], timeout=2)
    _, t = _run_runner(tmp_path, spec)
    assert t.meta["timed_out"] is True and t.meta["rc"] == 124
    assert subprocess.run(["pgrep", "-f", "^sleep 301$"], capture_output=True).returncode != 0


@pytest.mark.skipif(not HAVE_STRACE, reason="strace not usable here")
def test_runner_bounds_output_and_skips_symlinked_outputs(tmp_path):
    code = ("import os,sys\nsys.stdout.write('x'*(9<<20))\n"
            "os.symlink('/etc/hostname','out.txt')\n")
    spec = _runner_spec(tmp_path, [sys.executable, "-c", code])
    _, t = _run_runner(tmp_path, spec)
    assert (tmp_path / "trace" / "stdout.txt").stat().st_size <= (8 << 20) + 200
    assert not (tmp_path / "trace" / "outputs" / "out.txt").exists()
    assert t.meta["output_problems"]


def test_trace_dir_is_outside_the_project(tmp_path):
    from cleanroom.backends.local import LocalBackend
    proj = tmp_path / "p"
    proj.mkdir()
    be = LocalBackend(proj)
    assert proj.resolve() not in Path(be.root).resolve().parents


def test_local_env_is_allowlisted(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "s3cr3t")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    env = base_env({"A": "1"})
    assert "AWS_SECRET_ACCESS_KEY" not in env and "GITHUB_TOKEN" not in env and env["A"] == "1"


# ---- 3. aliasing -------------------------------------------------------------
def test_read_via_symlink_alias_fails():
    pol = extract_policy(RULES)
    t = Trace([ev(kind="alias", op="symlink", path="/w/data/test_labels.csv", path2="/w/innocent.csv"),
               ev(kind="open", path="/w/innocent.csv", mode="read")], sources=["strace"], complete=True)
    fs = checks.analyse(t, pol, "/w", 0, "abc", "submission.csv")
    fail = [f for f in fs if f.code == "forbidden_file_read"]
    assert fail and "via" in fail[0].title


def test_hardlink_and_rename_parse():
    e = parse_strace_line('linkat(AT_FDCWD</w>, "data/test_labels.csv", AT_FDCWD</w>, "x.csv", 0) = 0', pid=5)
    assert e.kind == "alias" and e.path.endswith("data/test_labels.csv") and e.path2.endswith("x.csv")
    e = parse_strace_line('renameat2(AT_FDCWD</w>, "data/test_labels.csv", AT_FDCWD</w>, "y.csv", 0) = 0', pid=5)
    assert e.kind == "alias" and e.path2.endswith("y.csv")


def test_scanned_symlink_to_forbidden_file_warns():
    pol = extract_policy(RULES)
    t = Trace([ev(kind="open", path="/w/data/train.csv", mode="read")], sources=["strace"], complete=True,
              aliases={"symlinks": [{"path": "/w/l.csv", "target": "data/test_labels.csv",
                                     "real": "/w/data/test_labels.csv"}], "hardlinks": []})
    fs = checks.analyse(t, pol, "/w", 0, "abc", "submission.csv")
    assert "forbidden_file_alias" in codes(fs)


# ---- 4. trace integrity ----------------------------------------------------------
def test_missing_empty_incomplete_and_killed_traces_are_inconclusive():
    pol = extract_policy(RULES)
    for t in (Trace(), Trace(sources=["strace"]),
              Trace([ev(kind="open", path="data/train.csv", mode="read")], sources=["strace"], complete=False,
                    incomplete_files=1, strace_files=2),
              Trace([ev(kind="open", path="data/train.csv", mode="read")], sources=["strace"], complete=True,
                    meta={"strace_signalled": True, "strace_exit": -9}),
              Trace([ev(kind="open", path="data/train.csv", mode="read")], sources=["audit"], parse_errors=2)):
        fs = checks.analyse(t, pol, "/w", 0, "abc", "submission.csv")
        assert codes(fs, "INCONCLUSIVE"), t
        assert not codes(fs, "PASS")


def test_truncated_strace_file_is_incomplete(tmp_path):
    (tmp_path / "strace.10").write_text('openat(AT_FDCWD</w>, "data/train.csv", O_RDONLY) = 3</w/data/train.csv>\n')
    (tmp_path / "strace.11").write_text('openat(AT_FDCWD</w>, "a", O_RDONLY) = 3</w/a>\n+++ exited with 0 +++\n')
    t = load_trace(tmp_path)
    assert t.complete is False and t.incomplete_files == 1


def test_audit_only_is_capped_at_warn():
    pol = extract_policy(RULES)
    t = Trace([ev(kind="open", path="data/train.csv", mode="read", source="audit")], sources=["audit"])
    fs = checks.analyse(t, pol, "/w", 0, "abc", "submission.csv", tracer="audit")
    assert "audit_only" in codes(fs, "WARN")


def test_bundle_problems_make_run_inconclusive():
    pol = extract_policy(RULES)
    t = Trace([ev(kind="open", path="data/train.csv", mode="read")], sources=["strace"], complete=True,
              bundle_problems=["skipped unsafe member name '../x'"])
    assert "bundle_rejected" in codes(checks.analyse(t, pol, "/w", 0, "a", "s.csv"), "INCONCLUSIVE")


# ---- 5. network ------------------------------------------------------------------
def test_udp_sendto_and_ipv6_are_network_attempts():
    e = parse_strace_line('sendto(5<UDP:[1]>, "\\x01", 1, 0, {sa_family=AF_INET, sin_port=htons(9999), '
                          'sin_addr=inet_addr("8.8.4.4")}, 16) = 1', pid=1)
    assert e.kind == "connect" and e.addr == "8.8.4.4" and e.proto == "udp"
    e = parse_strace_line('connect(3<socket:[9]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), '
                          'inet_pton(AF_INET6, "2606:4700::1111", &sin6_addr), sin6_scope_id=0}, 28) = '
                          '-1 ENETUNREACH (Network is unreachable)', pid=1)
    assert e.kind == "connect" and e.addr == "2606:4700::1111" and not e.ok


def test_no_download_claim_without_verified_egress_denial():
    pol = extract_policy(RULES)
    t = Trace([ev(kind="dns", host="example.com", source="audit")])
    f = checks.check_network(t, pol, enforced=False)[0]
    assert "NOT verified" in f.detail


# ---- 7. scoring --------------------------------------------------------------------
def test_predictions_must_cover_ids_exactly(tmp_path):
    from cleanroom.scoring import ScoringError, read_predictions, read_truth
    p = tmp_path / "p.csv"
    for body in ("id,pred\n1,0.1\n1,0.2\n2,0.3\n", "id,pred\n1,0.1\n", "id,pred\n1,nan\n2,0.1\n",
                 "id,pred\n1,inf\n2,0.1\n", "id,pred\n1,0.1\n2,0.2\n3,0.3\n", "id,pred\n1,abc\n2,0.1\n"):
        p.write_text(body)
        with pytest.raises(ScoringError):
            read_predictions(p, expected_ids=["1", "2"])
    t = tmp_path / "t.csv"
    t.write_text("id,target\n1,2\n2,0\n")
    with pytest.raises(ScoringError):
        read_truth(t)


def test_ci_unavailable_for_single_class_and_misaligned_pairs():
    from cleanroom.scoring import bootstrap_ci, paired_bootstrap_diff, roc_auc
    assert roc_auc([1, 1, 1], [0.1, 0.2, 0.3]) is None
    assert bootstrap_ci([1, 1, 1], [0.1, 0.2, 0.3]) is None
    assert bootstrap_ci([], []) is None
    assert paired_bootstrap_diff(["1", "2"], [0, 1], [0.1, 0.9], ["1", "3"], [0, 1], [0.2, 0.8]) is None
    d = paired_bootstrap_diff(["1", "2", "3", "4"], [0, 1, 0, 1], [0.1, 0.9, 0.2, 0.8],
                              ["4", "3", "2", "1"], [1, 0, 1, 0], [0.8, 0.2, 0.9, 0.1], n_boot=50)
    assert d is not None and abs(d["diff"]) < 1e-12        # aligned by id, not by row order


def test_seed_spread_uses_sample_sd_and_none_ranks_last():
    from cleanroom.recommend import Candidate, recommend
    from cleanroom.scoring import seed_spread
    sp = seed_spread([0.70, 0.72, 0.74])
    assert math.isclose(sp["sd"], 0.02, rel_tol=1e-9)
    assert seed_spread([0.7])["sd"] is None
    r = recommend([Candidate("X", reproduced=True, holdout=0.8, seed_sd=None),
                   Candidate("Y", reproduced=True, holdout=0.8, seed_sd=0.01)])
    assert r["recommended"] == "Y"


def test_inconclusive_candidate_is_rejected():
    from cleanroom.recommend import Candidate, recommend
    r = recommend([Candidate("X", reproduced=True, holdout=0.9, inconclusive=["trace missing"]),
                   Candidate("Y", reproduced=True, holdout=0.7)])
    assert r["recommended"] == "Y" and "X" in r["rejected"]


def test_holdout_truth_is_private_and_forbidden(tmp_path):
    from cleanroom.backends.local import LocalBackend
    from cleanroom.engine import Project
    proj = tmp_path / "p"
    (proj / "host").mkdir(parents=True)
    (proj / "rules.txt").write_text(RULES)
    (proj / "cleanroom.json").write_text(json.dumps(
        {"holdout": {"pred": "v.csv", "truth": "host/labels.csv"}, "candidates": []}))
    be = LocalBackend(proj)
    p = Project(proj, be, use_llm=False, log=lambda *a: None)
    assert be.is_private("host/labels.csv")
    assert ("forbid_file", "host/labels.csv") in {(r.kind, r.target) for r in p.policy.rules}


# ---- 9. policy and LLM guards ------------------------------------------------------------
def test_policy_negation_false_positive_and_unmapped():
    pol = extract_policy("4.1 The organisers do not guarantee uptime of the leaderboard.\n"
                         "4.2 Participants must not share code privately outside of teams.\n")
    assert not pol.of("forbid_file") and not pol.of("deny_network")
    assert any("4.2" in u.get("clause_id", "") if isinstance(u, dict) else "4.2" in str(u)
               for u in pol.unmapped)


def test_llm_rule_needs_target_in_quote():
    pol = extract_policy(RULES)
    before = len(pol.rules)
    merge_llm_rules(pol, RULES, [{"kind": "forbid_file", "target": "train.csv", "clause_id": "1.2",
                                  "quote": "The file test_labels.csv must not be read by participant code."}])
    assert len(pol.rules) == before and any("does not name its target" in n for n in pol.notes)


def test_llm_verdict_is_validated():
    from cleanroom.summary import validate_verdict
    s = {"recommendation": {"recommended": "B"}, "candidates": [{"name": n} for n in "ABCDE"]}
    assert validate_verdict("Submit B. A read the test labels.", s)
    assert not validate_verdict("Submit A, it scores best.", s)
    assert not validate_verdict("Submit B; it is guaranteed clean.", s)
    assert not validate_verdict("", s)


def test_compact_evidence_keeps_every_candidate():
    from cleanroom.llm import compact_evidence
    cands = [{"name": f"C{i}", "status": "WARN", "findings": [{"severity": "WARN", "code": "x", "title": "t" * 500,
                                                               "detail": "d" * 5000, "evidence": ["e" * 900] * 20}]}
             for i in range(40)]
    out = compact_evidence({"candidates": cands, "recommendation": {"recommended": "C1"}})
    assert {c["name"] for c in out["candidates"]} == {f"C{i}" for i in range(40)}


# ---- 10/13. ledger, redaction, report -----------------------------------------------
def test_store_sessions_and_binding(tmp_path):
    from cleanroom.store import Ledger
    led = Ledger(tmp_path / "l.sqlite")
    s1 = led.start_session()
    led.set_meta("k", 1)
    s2 = led.start_session()
    assert s1 != s2 and led.get_meta("k") is None
    led.set_meta("g", 2, glob=True)
    assert Ledger(tmp_path / "l.sqlite").get_meta("g", glob=True) == 2
    assert not hasattr(led, "reset")


def test_redaction():
    from cleanroom.redact import redact_cmd, redact_text
    assert "/home/alice" not in redact_text("open /home/alice/x.csv")
    assert "ghp_" not in redact_text("token ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    out = redact_cmd(["/home/alice/venv/bin/python", "train.py", "--api-key=abc123", "--data", "/srv/x/data.csv"])
    assert out[0] == "python" and "abc123" not in " ".join(out) and "/srv/x" not in " ".join(out)


def test_report_public_view_strips_paths_and_tails():
    from cleanroom.report import public_view
    v = public_view({"candidates": [{"trace_dir": "/home/a/.local/state/x", "workdir": "/w",
                                     "stdout_tail": "secret", "stderr_tail": "x", "note": "/home/alice/f"}]})
    c = v["candidates"][0]
    assert "trace_dir" not in c and "stdout_tail" not in c and "/home/alice" not in c["note"]


def test_serve_defaults_to_loopback():
    import inspect

    from cleanroom import cli, report
    assert inspect.signature(report.serve).parameters["host"].default == "127.0.0.1"
    assert "127.0.0.1" in inspect.getsource(cli)


def test_ledger_readme_and_docs_do_not_overclaim():
    root = Path(__file__).resolve().parents[1]
    for p in [root / "README.md", *root.glob("docs/*.md"), root / "DEMO_SCRIPT.md"]:
        if p.exists():
            assert "accurate" not in p.read_text().lower(), p
