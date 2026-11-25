"""SpriteBackend unit tests against a fake Sprites API (no network)."""
import io
import json
import tarfile

import pytest

from cleanroom.backends import sprite as sp


class FakeResp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_requires_token_or_gateway(monkeypatch):
    monkeypatch.delenv("SPRITES_TOKEN", raising=False)
    monkeypatch.delenv("CLEANROOM_SPRITES_API", raising=False)
    with pytest.raises(sp.SpritesAPIError):
        sp.SpritesAPI()
    api = sp.SpritesAPI(base_url="https://api.sprites.dev/v1/gateway/custom/conn_1")
    assert api.via_gateway


def test_token_not_in_repr_and_header_only_direct(monkeypatch):
    seen = []

    def fake_urlopen(req, timeout=None):
        seen.append(req)
        return FakeResp(b"{}")

    monkeypatch.setattr(sp.urllib.request, "urlopen", fake_urlopen)
    api = sp.SpritesAPI(token="tok-secret")
    assert "tok-secret" not in repr(api)
    api.set_network_policy("w", {"rules": [{"domain": "*", "action": "deny"}]})
    req = seen[-1]
    assert req.full_url == "https://api.sprites.dev/v1/sprites/w/policy/network"
    assert req.get_method() == "POST"
    assert json.loads(req.data) == {"rules": [{"domain": "*", "action": "deny"}]}
    assert req.get_header("Authorization") == "Bearer tok-secret"
    gw = sp.SpritesAPI(base_url="https://api.sprites.dev/v1/gateway/custom/conn_1", token="tok-secret")
    gw.get_network_policy("w")
    assert seen[-1].get_header("Authorization") is None
    assert seen[-1].full_url == "https://api.sprites.dev/v1/gateway/custom/conn_1/v1/sprites/w/policy/network"


def test_exec_query_encoding(monkeypatch):
    seen = []
    monkeypatch.setattr(sp.urllib.request, "urlopen", lambda req, timeout=None: seen.append(req) or FakeResp(b"ok"))
    api = sp.SpritesAPI(token="t")
    api.exec("w", ["bash", "-c", "echo hi && ls"], workdir="/home/sprite", env={"A": "1"})
    url = seen[-1].full_url
    assert "/v1/sprites/w/exec?" in url and "cmd=bash" in url and "cmd=echo+hi+%26%26+ls" in url
    assert "dir=%2Fhome%2Fsprite" in url and "env=A%3D1" in url


def test_checkpoint_id_from_ndjson(monkeypatch):
    stream = b'{"type":"info","data":"Creating checkpoint..."}\n{"type":"complete","data":"Checkpoint v8 created"}\n'
    monkeypatch.setattr(sp.urllib.request, "urlopen", lambda req, timeout=None: FakeResp(stream))
    assert sp.SpritesAPI(token="t").create_checkpoint("w", "x") == "v8"


def test_restore_error_event_raises(monkeypatch):
    stream = b'{"type":"info","data":"Restoring"}\n{"type":"error","data":"checkpoint not found"}\n'
    monkeypatch.setattr(sp.urllib.request, "urlopen", lambda req, timeout=None: FakeResp(stream))
    with pytest.raises(sp.SpritesAPIError, match="checkpoint not found"):
        sp.SpritesAPI(token="t").restore("w", "v99")


class FakeAPI:
    """Records calls; serves a canned trace bundle for fs/read."""
    via_gateway = False
    base = "https://api.sprites.dev"

    def __init__(self, bundle):
        self.calls, self.bundle = [], bundle

    def exec(self, name, argv, **kw):
        self.calls.append(("exec", argv[-1][:40]))
        return b"cr-ready cr-done"

    def read_file(self, name, path):
        self.calls.append(("read", path))
        return self.bundle

    def restore(self, name, cid):
        self.calls.append(("restore", cid))

    def get_network_policy(self, name):
        return {"rules": [{"domain": "*", "action": "deny"}]}


def _bundle():
    buf = io.BytesIO()
    files = {"cr-trace/rc": b"0\n", "cr-trace/ms": b"1234\n", "cr-trace/tracer": b"strace+audit\n",
             "cr-trace/dns_probe": b"refused\n", "cr-trace/stdout.txt": b"hi\n", "cr-trace/stderr.txt": b"",
             "cr-trace/outputs/submission.csv": b"id,pred\n1,0.5\n",
             "cr-trace/audit.jsonl": b'{"ev":"open","pid":1,"path":"data/train.csv","mode":"r","cwd":"/home/sprite/work"}\n'}
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for n, d in files.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            tf.addfile(ti, io.BytesIO(d))
    return buf.getvalue()


def test_run_from_checkpoint_restores_then_pulls_trace(tmp_path, monkeypatch):
    monkeypatch.setattr(sp.time, "sleep", lambda s: None)
    api = FakeAPI(_bundle())
    be = sp.SpriteBackend(tmp_path, worker="w", api=api)
    from cleanroom.backends.base import RunSpec
    res = be.run_from_checkpoint("v3", RunSpec("B", ["python3", "b.py"]), tmp_path / "t")
    assert api.calls[0] == ("restore", "v3")
    assert ("read", "/tmp/cr-trace.tgz") in api.calls
    assert res.exit_code == 0 and res.duration_s == 1.234 and res.tracer == "strace+audit"
    assert res.checkpoint == "v3" and res.workdir == "/home/sprite/work"
    assert res.output_sha256 and "refused" in res.network
    assert (tmp_path / "t" / "audit.jsonl").exists()
