"""Regression tests for the 2026-11-26 review findings (H2-H5, M7, L1-L2, L6, L8, L12)."""
import json
import sys
import textwrap

import pytest

from cleanroom import checks
from cleanroom.backends.local import LocalBackend
from cleanroom.engine import FORBID_TITLE, Project
from cleanroom.policy import extract_policy
from cleanroom.report import render_html
from cleanroom.scoring import _quantiles
from cleanroom.summary import build_summary, deterministic_verdict, validate_verdict

PY = sys.executable


def rules_of(text):
    return {(r.kind, r.target) for r in extract_policy(text).rules}


# ---- H2: a forbidden file must not come out as allowed --------------------------
@pytest.mark.parametrize("text,want,not_want", [
    ("1. test_labels.csv is provided but must not be read by participant code.",
     {("forbid_file", "test_labels.csv")}, {("allow_file", "test_labels.csv")}),
    ("1. You may use train.csv but not test_labels.csv.",
     {("allow_file", "train.csv"), ("forbid_file", "test_labels.csv")}, {("allow_file", "test_labels.csv")}),
    ("1. Accessing data/test_labels.csv is a violation and leads to disqualification.",
     {("forbid_file", "data/test_labels.csv")}, set()),
    ("1. Participants must not read test_labels.csv; train.csv is provided.",
     {("forbid_file", "test_labels.csv"), ("allow_file", "train.csv")}, {("forbid_file", "train.csv")}),
    ("1. Do not use external data; train.csv is provided.",
     {("forbid_external_data", ""), ("allow_file", "train.csv")}, {("forbid_file", "train.csv")}),
])
def test_policy_negations(text, want, not_want):
    got = rules_of(text)
    assert want <= got and not (not_want & got), got


def test_all_other_files_off_limits_becomes_an_allowlist_rule():
    pol = extract_policy("1. Only train.csv and test.csv may be used. All other files are off limits.")
    assert not pol.unmapped
    r = pol.unlisted_files_rule()
    assert r is not None and r.clause_id.startswith("1") and "off limits" in r.quote


@pytest.mark.parametrize("text", [
    "1. Participants may use train.csv. No other data may be used.",
    "1. You may read train.csv and test.csv; any other files must not be read.",
    "1. train.csv is provided. Participants must not use any other files.",
])
def test_allowlist_wordings(text):
    assert extract_policy(text).unlisted_files_rule() is not None


def test_allowlist_sentence_before_the_list_still_counts():
    pol = extract_policy("1. All other files are off limits. Only train.csv may be used.")
    assert pol.unlisted_files_rule() is not None and not pol.unmapped


def test_all_other_files_without_a_named_allowed_file_stays_unmapped():
    pol = extract_policy("1. All other files are off limits.")
    assert pol.unlisted_files_rule() is None and pol.unmapped


def test_allowlist_rule_fails_unlisted_reads_but_not_own_made_or_aliased_files():
    from cleanroom import checks
    from cleanroom.trace import Event, Trace

    def ev(**kw):
        return Event(**{"source": "strace", "file": "strace.1", "lineno": 7, "line": "openat(...)", **kw})
    pol = extract_policy("1. Only train.csv and test.csv may be used. All other files are off limits.")
    t = Trace([ev(kind="open", path="data/train.csv", mode="read"),
               ev(kind="open", path="data/extra.csv", mode="read"),
               ev(kind="open", path="cache/feat.csv", mode="write"),
               ev(kind="open", path="cache/feat.csv", mode="read"),
               ev(kind="alias", op="link", path="data/train.csv", path2="t2.csv"),
               ev(kind="open", path="t2.csv", mode="read"),
               ev(kind="open", path="data/valid.csv", mode="read")])
    fs = checks.check_files(t, pol, "/w", ["submission.csv"], own_files=["data/valid.csv"])
    fail = [f for f in fs if f.code == "forbidden_file_read"]
    assert [f.title for f in fail] == ["Read forbidden file data/extra.csv"]
    assert fail[0].severity == "FAIL" and "off limits" in fail[0].quote
    assert not any(f.code == "no_forbidden_files" for f in fs)
    # without the allowlist sentence the same read is only a warning
    pol2 = extract_policy("1. Only train.csv and test.csv may be used.")
    fs2 = checks.check_files(t, pol2, "/w", ["submission.csv"], own_files=["data/valid.csv"])
    assert [f.code for f in fs2 if f.severity == "FAIL"] == []
    assert any(f.code == "unlisted_file_read" for f in fs2)


# ---- L1/L2: case-insensitive matching, inferred rules do not hit absolute paths ---
def test_path_match_is_case_insensitive_and_inferred_rules_skip_absolute_paths():
    pol = extract_policy("1. test_labels.csv must not be read by participant code.")
    assert pol.forbidden_file_rule("data/Test_Labels.CSV") is not None
    for r in pol.rules:
        if r.kind == "forbid_file":
            r.source = "inferred"
    assert pol.forbidden_file_rule("/usr/share/test_labels.csv") is None


# ---- L6 / L8 / L12 ---------------------------------------------------------------
def test_forbid_title_strips_alias_suffix():
    assert FORBID_TITLE.match("Read forbidden file data/x y.csv (via /tmp/l)").group(1) == "data/x y.csv"
    assert FORBID_TITLE.match("Read forbidden file data/t.csv").group(1) == "data/t.csv"


def test_validate_verdict_needs_the_whole_name():
    s = {"recommendation": {"recommended": "B"}, "candidates": [{"name": "B"}, {"name": "Bob"}]}
    assert not validate_verdict("Bob looks fine.", s)
    assert validate_verdict("Submit B. It reproduced.", s)


def test_bootstrap_quantiles_are_symmetric():
    lo, hi = _quantiles(list(range(1000)), 0.05)
    assert lo - 0 == 999 - hi == 24


# ---- H3/H4/H5: end to end on the local backend ----------------------------------
def make_project(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "train.csv").write_text("id,x,target\n1,0.1,0\n2,0.9,1\n")
    (tmp_path / "data" / "test_labels.csv").write_text("id,target\n3,1\n")
    (tmp_path / "rules.txt").write_text(
        "1. Participants may use train.csv.\n"
        "2. test_labels.csv must not be read by participant code.\n"
        "3. Internet access is disabled; code must not make network calls.\n"
        "4. Fix random seeds so that a re-run produces the same submission file.\n")
    (tmp_path / "det.py").write_text(textwrap.dedent("""
        rows = open("data/train.csv").read().splitlines()
        open("submission.csv", "w").write("id,pred\\n3,%d\\n" % len(rows))
    """))
    (tmp_path / "cleanroom.json").write_text(json.dumps({"rules": "rules.txt", "output": "submission.csv"}))
    return Project(tmp_path, LocalBackend(tmp_path), use_llm=False, log=lambda *a: None)


def test_blocking_warning_makes_candidate_ineligible_and_verdict_says_so(tmp_path, monkeypatch):
    proj = make_project(tmp_path)
    real = checks.analyse

    def with_alias(trace, policy, *a, **kw):
        out = real(trace, policy, *a, **kw)
        out.append(checks.Finding(checks.WARN, "forbidden_file_alias", "Read forbidden file test_labels.csv "
                                  "(via /tmp/link)", "opened through a link"))
        return out
    proj.run("A", [PY, "det.py"])
    proj.verify("A")
    monkeypatch.setattr(checks, "analyse", with_alias)
    proj.run("B", [PY, "det.py"])
    proj.verify("B")
    monkeypatch.setattr(checks, "analyse", real)
    s = build_summary(proj.ledger, proj.policy, honest=False)
    assert s["recommendation"]["recommended"] == "A"
    assert "B" in s["recommendation"]["rejected"]
    # the verdict text for a candidate carrying such a flag must not claim a clean check
    s2 = json.loads(json.dumps(s))
    s2["recommendation"]["recommended"] = "B"
    text = deterministic_verdict(s2)
    assert "No forbidden access detected" not in text and "not clean" in text


def test_report_renders_when_seed_sd_is_missing(tmp_path):
    proj = make_project(tmp_path)
    proj.run("A", [PY, "det.py"])
    s = build_summary(proj.ledger, proj.policy, honest=False)
    s["candidates"][0]["seeds"] = {"sd": None, "aucs": [0.7], "n": 1}
    assert "seed sd n/a" in render_html(s)


def test_backend_failure_is_inconclusive_not_a_crash(tmp_path, monkeypatch):
    proj = make_project(tmp_path)

    def boom(*a, **kw):
        raise RuntimeError("worker unreachable")
    monkeypatch.setattr(proj.backend, "run_from_checkpoint", boom)
    rec = proj.run("A", [PY, "det.py"])
    f = [x for x in rec["findings"] if x.code == "run_infrastructure_failed"]
    assert f and f[0].severity == checks.INCONCLUSIVE and "worker unreachable" in f[0].detail
    ver = proj.verify("A")
    assert any(x.code == "run_infrastructure_failed" for x in ver["findings"])


# ---- M8: the report never needs the Sprites token --------------------------------
def test_sprite_backend_describe_needs_no_token(tmp_path, monkeypatch):
    from cleanroom.backends.sprite import SpriteBackend
    monkeypatch.delenv("SPRITES_TOKEN_FILE", raising=False)
    b = SpriteBackend(tmp_path)
    assert b.describe()["backend"] == "sprite" and b._api is None
