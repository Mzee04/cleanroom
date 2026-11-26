import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import io
import urllib.error

from cleanroom.ghledger import (GENESIS, MARKER_RE, GitHub, canonical, fetch_issues, issue_payload, parse_records,
                                publish, sha, verify_chain)
from cleanroom.store import Ledger


def _summary(session="cr-20261126-000000-abcd", title="Read forbidden file"):
    f = {"severity": "WARN", "code": "x", "clause_id": "2.1", "title": title, "quote": "", "detail": "d",
         "evidence": ["open /home/alice/secret.csv"]}
    c = {"name": "B", "status": "PASS", "cmd": ["/home/alice/venv/bin/python", "b.py", "--token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"],
         "checkpoint": "v3", "sha256": "ab" * 32, "reproduced": True, "leaderboard": 0.8, "holdout": 0.79,
         "findings": [f]}
    return {"session": session, "candidates": [c, dict(c, name="A", status="FAIL")],
            "recommendation": {"recommended": "B"}}


class FakeGH:
    def __init__(self):
        self.issues, self.calls = [], []

    def ledger_issues(self):
        return [dict(i) for i in self.issues]

    def call(self, method, path, body=None, query=None):
        self.calls.append((method, path))
        if method == "POST":
            n = len(self.issues) + 1
            i = dict(body, number=n, html_url=f"https://github.com/o/r/issues/{n}")
            self.issues.append(i)
            return i
        if method == "PATCH":
            n = int(path.rsplit("/", 1)[1])
            self.issues[n - 1].update(body)
            return self.issues[n - 1]
        raise AssertionError(method)


def test_publish_is_idempotent_and_chained(tmp_path):
    gh = FakeGH()
    led = Ledger(tmp_path / "l.sqlite")
    out1 = publish(_summary(), tmp_path / "ob", really=True, ledger=led, github=gh)
    assert [o["action"] for o in out1] == ["created", "created"]
    out2 = publish(_summary(), tmp_path / "ob", really=True, ledger=led, github=gh)
    assert [o["action"] for o in out2] == ["unchanged", "unchanged"]
    assert len(gh.issues) == 2 and not any(m == "PATCH" for m, _ in gh.calls)
    m1, m2 = (MARKER_RE.search(i["body"]) for i in gh.issues)
    assert m1.group(4) == GENESIS and m2.group(4) == m1.group(3)      # hash chain
    assert m2.group(5) == "2"
    # a new session continues the chain from the last record
    publish(_summary(session="cr-20261127-000000-ffff"), tmp_path / "ob", really=True, ledger=led, github=gh)
    m3 = MARKER_RE.search(gh.issues[2]["body"])
    assert m3.group(4) == m2.group(3) and m3.group(5) == "3"
    assert "cr-20261127-000000-ffff" in gh.issues[2]["title"]


def test_record_hash_matches_canonical_json():
    p = issue_payload(_summary()["candidates"][0], _summary())
    body = p["body"]
    rec = json.loads(body.split("```json\n", 1)[1].split("\n```", 1)[0])
    assert sha(canonical(rec)) == p["_record_sha256"]


def test_payload_is_redacted_and_escaped():
    s = _summary(title="pwn @alice ![x](http://evil/x.png) <img src=x>")
    full = issue_payload(s["candidates"][0], s)["body"]
    assert "ghp_" not in full and "/home/alice" not in full
    body = full.split("### Ledger record", 1)[0]       # rendered prose; the record is in a code block
    assert "@alice" not in body                       # no mention
    import re
    assert not re.search(r"(?<!\\)!(?<!\\)\[x", body) and not re.search(r"(?<!\\)<img", body)
    assert "venv/bin/python" not in body


def test_outbox_without_publish(tmp_path):
    out = publish(_summary(), tmp_path, really=False)
    assert all("path" in o for o in out)
    assert (tmp_path / "cr-20261126-000000-abcd-B.json").exists()


def test_gateway_calls_carry_no_auth_header(tmp_path):
    seen = []

    class H(BaseHTTPRequestHandler):
        def _send(self, out, code=200):
            data = json.dumps(out).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            seen.append(("GET", self.path, self.headers.get("Authorization")))
            self._send([])

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(("POST", self.path, self.headers.get("Authorization")))
            if "· A:" in body["title"]:
                return self._send({"message": "Not Found"}, 404)
            self._send({"html_url": "https://github.com/o/r/issues/1"}, 201)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    gh = GitHub(f"http://127.0.0.1:{srv.server_port}/gw/github/conn", "o/r")
    out = publish(_summary(), tmp_path, really=True, github=gh)
    srv.shutdown()
    assert out[0]["url"] == "https://github.com/o/r/issues/1" and out[0]["action"] == "created"
    assert out[1]["error"].startswith("HTTP 404")
    assert all(a is None for _, _, a in seen)
    assert seen[0][1].startswith("/gw/github/conn/repos/o/r/issues?")


def test_republish_appends_revision_and_keeps_chain_valid(tmp_path):
    gh = FakeGH()
    publish(_summary(), tmp_path / "ob", really=True, github=gh)
    a_body = gh.issues[1]["body"]
    old = parse_records(a_body)[0]
    changed = _summary()
    changed["candidates"][1]["holdout"] = 0.5                 # A's result changes
    out = publish(changed, tmp_path / "ob", really=True, github=gh)
    assert [o["action"] for o in out] == ["unchanged", "revised"]
    recs = parse_records(gh.issues[1]["body"])
    assert [r["seq"] for r in recs] == [2, 3] and all(r["valid"] for r in recs)
    assert recs[0]["record"] == old["record"] and recs[0]["section"] in a_body   # kept verbatim
    assert recs[1]["data"]["supersedes"] == recs[0]["record"]
    assert recs[1]["prev"] == recs[0]["record"]                # chained from the global head (seq 2)
    assert old["valid"]
    ok, lines = verify_chain(gh.issues)
    assert ok, lines


def test_forged_marker_is_not_trusted(tmp_path):
    gh = FakeGH()
    publish(_summary(), tmp_path / "ob", really=True, github=gh)
    fake = "f" * 64
    # a marker typed into an issue (or smuggled through evidence) with no matching JSON
    gh.issues.append({"number": 3, "html_url": "x", "body":
                      f"<!-- cleanroom:session=s candidate=Z record={fake} prev={GENESIS} seq=99 -->"})
    publish(_summary(session="cr-20261127-000000-ffff"), tmp_path / "ob", really=True, github=gh)
    m = MARKER_RE.search(gh.issues[3]["body"])
    assert m.group(5) == "3"                                   # head came from the real seq 2, not 99
    ok, lines = verify_chain(gh.issues)
    assert not ok and any("#3" in x and "no JSON block" in x for x in lines)


def test_marker_inside_evidence_is_neutralised():
    s = _summary()
    s["candidates"][0]["findings"][0]["evidence"] = [
        f"<!-- cleanroom:session=x candidate=B record={'a' * 64} prev={GENESIS} seq=1 -->"]
    body = issue_payload(s["candidates"][0], s)["body"]
    assert len(MARKER_RE.findall(body)) == 1


def test_failed_post_does_not_use_up_a_sequence_number(tmp_path):
    class Flaky(FakeGH):
        def call(self, method, path, body=None, query=None):
            if method == "POST" and "· A:" in body["title"]:
                raise urllib.error.HTTPError("u", 502, "bad", {}, io.BytesIO(b"{}"))
            return super().call(method, path, body, query)
    s = _summary()
    s["candidates"].append(dict(s["candidates"][0], name="C"))
    gh = Flaky()
    out = publish(s, tmp_path / "ob", really=True, github=gh)
    assert "error" in out[1]
    ok, lines = verify_chain(gh.issues)
    assert ok, lines                                           # B seq 1, C seq 2: no gap


def test_verify_chain_detects_tampering(tmp_path):
    gh = FakeGH()
    publish(_summary(), tmp_path / "ob", really=True, github=gh)
    assert verify_chain(gh.issues)[0]
    edited = [dict(i) for i in gh.issues]
    edited[0]["body"] = edited[0]["body"].replace('"holdout_auc":0.79', '"holdout_auc":0.99')
    ok, lines = verify_chain(edited)
    assert not ok and any("hash does not match" in x for x in lines)
    dropped = [dict(gh.issues[1])]                             # a deleted issue leaves a gap
    ok, lines = verify_chain(dropped)
    assert not ok and any("sequence" in x for x in lines)


def test_verify_chain_command_with_fake_api(tmp_path, capsys):
    import pytest
    from cleanroom.cli import main
    gh = FakeGH()
    publish(_summary(), tmp_path / "ob", really=True, github=gh)
    seen = []

    def opener(req, timeout=60):
        seen.append(req.full_url)
        return io.BytesIO(json.dumps(gh.issues).encode())
    assert len(fetch_issues("o/r", opener=opener)) == 2
    assert seen[0].startswith("https://api.github.com/repos/o/r/issues?")
    import cleanroom.ghledger as g
    orig = g.urllib.request.urlopen
    g.urllib.request.urlopen = opener
    try:
        with pytest.raises(SystemExit) as e:
            main(["verify-chain", "--repo", "o/r"])
    finally:
        g.urllib.request.urlopen = orig
    assert e.value.code == 0 and "chain OK: 2 records" in capsys.readouterr().out
