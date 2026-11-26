import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from cleanroom.ghledger import publish


def _summary():
    c = {"name": "B", "status": "PASS", "cmd": ["python", "b.py"], "checkpoint": "v3", "sha256": "ab" * 32,
         "reproduced": True, "leaderboard": 0.8, "holdout": 0.79, "findings": []}
    return {"candidates": [c, dict(c, name="A", status="FAIL")], "recommendation": {"recommended": "B"}}


def test_publish_posts_through_gateway_without_auth_header(tmp_path, monkeypatch):
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append((self.path, self.headers.get("Authorization"), body["title"]))
            n = len(seen)
            if "A:" in body["title"]:
                out, code = {"message": "Not Found"}, 404
            else:
                out, code = {"html_url": f"https://github.com/o/r/issues/{n}"}, 201
            data = json.dumps(out).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("CLEANROOM_GITHUB_GATEWAY", f"http://127.0.0.1:{srv.server_port}/gw/github/conn")
    monkeypatch.setenv("CLEANROOM_GITHUB_REPO", "o/r")
    out = publish(_summary(), tmp_path, really=True)
    srv.shutdown()
    assert out[0] == {"name": "B", "url": "https://github.com/o/r/issues/1", "number": "1"}
    assert out[1]["name"] == "A" and out[1]["error"].startswith("HTTP 404")
    assert all(p == "/gw/github/conn/repos/o/r/issues" and auth is None for p, auth, _ in seen)
    assert (tmp_path / "B.json").exists()


def test_publish_without_flag_only_writes_outbox(tmp_path, monkeypatch):
    monkeypatch.delenv("CLEANROOM_GITHUB_GATEWAY", raising=False)
    out = publish(_summary(), tmp_path, really=False)
    assert [d["path"] for d in out] == [str(tmp_path / "B.json"), str(tmp_path / "A.json")]
