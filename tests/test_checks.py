from cleanroom import checks
from cleanroom.policy import extract_policy
from cleanroom.trace import Event, Trace

RULES = ("1.2 The file test_labels.csv must not be read by participant code.\n"
         "1.1 Participants may use train.csv.\n"
         "2.1 Internet access is disabled and code must not make network calls.\n"
         "3.1 Fix all random seeds so that a re-run produces the same submission file.\n")


def ev(**kw):
    e = Event(**{"source": "strace", "file": "strace.1", "lineno": 7, "line": "openat(...)", **kw})
    return e


def test_forbidden_read_fails_and_quotes_rule():
    pol = extract_policy(RULES)
    t = Trace([ev(kind="open", path="/w/data/test_labels.csv", mode="read"),
               ev(kind="open", path="data/train.csv", mode="read")])
    fs = checks.analyse(t, pol, "/w", 0, "abc", "submission.csv")
    fail = [f for f in fs if f.code == "forbidden_file_read"]
    assert len(fail) == 1 and fail[0].severity == "FAIL"
    assert fail[0].clause_id == "1.2" and "must not be read" in fail[0].quote
    assert fail[0].evidence == ["strace.1:7  openat(...)"]
    assert not any(f.code == "no_forbidden_files" for f in fs)


def test_failed_open_of_forbidden_file_is_warning():
    pol = extract_policy(RULES)
    t = Trace([ev(kind="open", path="data/test_labels.csv", mode="read", ok=False, errno="ENOENT")])
    fs = checks.check_files(t, pol, "/w", ["submission.csv"])
    assert fs[0].severity == "WARN" and fs[0].code == "forbidden_file_attempt"


def test_writes_system_files_and_code_are_not_flagged():
    pol = extract_policy(RULES)
    t = Trace([ev(kind="open", path="submission.csv", mode="write"),
               ev(kind="open", path="/usr/lib/python3/os.py", mode="read"),
               ev(kind="open", path="candidates/common.py", mode="read")])
    fs = checks.check_files(t, pol, "/w", ["submission.csv"])
    assert [f.code for f in fs] == ["no_forbidden_files"]


def test_unlisted_data_file_warns_unless_declared_own():
    pol = extract_policy(RULES)
    t = Trace([ev(kind="open", path="data/valid.csv", mode="read")])
    assert any(f.code == "unlisted_file_read" for f in checks.check_files(t, pol, "/w", []))
    assert not any(f.code == "unlisted_file_read"
                   for f in checks.check_files(t, pol, "/w", [], own_files=["data/valid.csv"]))


def test_network_attempt_fails_under_offline_rule():
    pol = extract_policy(RULES)
    t = Trace([ev(kind="dns", host="raw.githubusercontent.com", source="audit"),
               ev(kind="connect", addr="10.0.0.53", port=53, ok=False)])
    fs = checks.check_network(t, pol, enforced=True)
    assert len(fs) == 1
    f = fs[0]
    assert f.severity == "FAIL" and "raw.githubusercontent.com" in f.title and f.clause_id == "2.1"
    assert "enforced" in f.detail and len(f.evidence) == 2   # host evidence + the blocked DNS syscall


def test_successful_raw_connect_is_reported_as_not_blocked():
    pol = extract_policy(RULES)
    t = Trace([ev(kind="connect", addr="93.184.215.14", port=80, ok=True)])
    f = checks.check_network(t, pol)[0]
    assert f.severity == "FAIL" and "NOT blocked" in f.detail


def test_no_network_passes():
    pol = extract_policy(RULES)
    assert checks.check_network(Trace([]), pol)[0].code == "no_network"


def test_run_failures():
    fs = checks.check_run(2, None, "submission.csv")
    assert {f.code for f in fs} == {"run_failed", "no_output"}


def test_reproduction_wording():
    pol = extract_policy(RULES)
    ok = checks.check_reproduction("a" * 64, "a" * 64, "v3", pol)
    assert ok.severity == "PASS" and "this environment only" in ok.detail
    bad = checks.check_reproduction("a" * 64, "b" * 64, "v3", pol)
    assert bad.severity == "FAIL" and bad.clause_id == "3.1"


def test_report_never_claims_clean_or_guaranteed():
    import re
    from cleanroom import report, summary
    words = re.compile(r"\b(clean|guaranteed?|accurate)\b", re.I)
    for text in report.LIMITS + [summary.deterministic_verdict.__doc__ or ""]:
        assert not words.search(text.replace("Clean Room", ""))
