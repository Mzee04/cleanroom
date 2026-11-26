"""End-to-end on the LocalBackend: checkpoint, traced run, restore + re-run, hash compare."""
import json
import sys
import textwrap

import pytest

from cleanroom.backends.base import sha256_file
from cleanroom.backends.local import LocalBackend
from cleanroom.engine import Project

PY = sys.executable


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
    (tmp_path / "nondet.py").write_text(textwrap.dedent("""
        import os
        open("submission.csv", "w").write("id,pred\\n3,%s\\n" % os.urandom(8).hex())
    """))
    (tmp_path / "peek.py").write_text(textwrap.dedent("""
        import os
        lab = open("data/test_labels.csv").read() if os.path.exists("data/test_labels.csv") else ""
        open("submission.csv", "w").write("id,pred\\n3,%d\\n" % len(lab))
    """))
    (tmp_path / "net.py").write_text(textwrap.dedent("""
        import socket
        try:
            socket.getaddrinfo("example.org", 443)
        except OSError:
            pass
        open("submission.csv", "w").write("id,pred\\n3,0.5\\n")
    """))
    (tmp_path / "cleanroom.json").write_text(json.dumps({"rules": "rules.txt", "output": "submission.csv"}))
    return Project(tmp_path, LocalBackend(tmp_path), use_llm=False, log=lambda *a: None)


def codes(rec):
    return {f.code for f in rec["findings"]}


def test_checkpoint_snapshot_is_deterministic(tmp_path):
    proj = make_project(tmp_path)
    a = proj.backend.checkpoint("a")
    b = proj.backend.checkpoint("b")
    ck = proj.backend.ckdir
    assert sha256_file(ck / f"{a}.tar.gz") == sha256_file(ck / f"{b}.tar.gz")


def test_deterministic_run_reproduces(tmp_path):
    proj = make_project(tmp_path)
    rec = proj.run("A", [PY, "det.py"])
    assert rec["result"].exit_code == 0 and rec["result"].output_sha256
    assert "no_forbidden_files" in codes(rec) and "no_network" in codes(rec)
    v = proj.verify("A")
    assert v["reproduced"] is True
    assert v["result"].output_sha256 == rec["result"].output_sha256


def test_nondeterministic_run_fails_verification(tmp_path):
    proj = make_project(tmp_path)
    proj.run("E", [PY, "nondet.py"])
    v = proj.verify("E")
    assert v["reproduced"] is False
    f = [f for f in v["findings"] if f.code == "not_reproduced"][0]
    assert f.severity == "FAIL" and f.clause_id == "4"


def test_forbidden_read_detected_and_investigated(tmp_path):
    proj = make_project(tmp_path)
    rec = proj.run("P", [PY, "peek.py"])
    assert "forbidden_file_read" in codes(rec)
    inv = proj.investigate("P")
    assert inv and "depends on the forbidden file" in inv[0]["data"]["verdict"]
    assert inv[0]["data"]["hidden"] == ["data/test_labels.csv"]
    # the original project is untouched by the investigation
    assert (tmp_path / "data" / "test_labels.csv").exists()


def test_network_attempt_flagged(tmp_path):
    proj = make_project(tmp_path)
    rec = proj.run("N", [PY, "net.py"])
    f = [f for f in rec["findings"] if f.code == "network_attempt"]
    assert f and f[0].severity == "FAIL" and "example.org" in f[0].title


def test_udp_lookup_through_local_resolver_is_flagged(tmp_path):
    proj = make_project(tmp_path)
    (tmp_path / "udp.py").write_text(textwrap.dedent("""
        import os, socket
        q = bytes.fromhex("123401000001000000000000076578616d706c65036f72670000010001")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("127.0.0.53", 53))
            os.write(s.fileno(), q)
        except OSError:
            pass
        open("submission.csv", "w").write("id,pred\\n3,0.5\\n")
    """))
    rec = proj.run("U", [PY, "udp.py"])
    f = [f for f in rec["findings"] if f.code == "network_connect"]
    assert f and f[0].severity == "FAIL" and "local resolver" in f[0].title
    if rec["result"].tracer == "strace":
        assert any(e.startswith("strace") for e in f[0].evidence)


def test_candidate_never_sees_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("SPRITES_TOKEN", "should-not-leak")
    proj = make_project(tmp_path)
    (tmp_path / "env.py").write_text(
        "import os\nopen('submission.csv','w').write(str('SPRITES_TOKEN' in os.environ))\n")
    rec = proj.run("T", [PY, "env.py"])
    out = open(rec["result"].outputs["submission.csv"]).read()
    assert out == "False"


def test_unknown_checkpoint_raises(tmp_path):
    proj = make_project(tmp_path)
    with pytest.raises(FileNotFoundError):
        proj.backend.run_from_checkpoint("local-v99", proj.spec("X", [PY, "det.py"]), tmp_path / "t")


def test_audit_hook_fallback_without_strace(tmp_path):
    proj = make_project(tmp_path)
    proj.backend.doctor()
    proj.backend._caps.update(strace_works=False, strace_in_netns=False)
    rec = proj.run("P", [PY, "peek.py"])
    assert rec["result"].tracer == "audit"
    f = [f for f in rec["findings"] if f.code == "forbidden_file_read"][0]
    assert all(e.startswith("audit.jsonl:") for e in f.evidence)
