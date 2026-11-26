import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from cleanroom.ghledger import GENESIS, MARKER_RE, GitHub, canonical, issue_payload, publish, sha
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
    assert [o["action"] for o in out2] == ["updated", "updated"]
    assert len(gh.issues) == 2
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
