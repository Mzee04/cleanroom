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
    monkeypatch.delenv("SPRITES_TOKEN_FILE", raising=False)
    with pytest.raises(sp.SpritesAPIError):
        sp.SpritesAPI()
    api = sp.SpritesAPI(base_url="https://api.sprites.dev/v1/gateway/custom/conn_1")
    assert api.via_gateway


def test_token_file_preferred_and_reread_on_401(tmp_path, monkeypatch):
    tf = tmp_path / "tok"
    tf.write_text("org/1/2/first\n")
    monkeypatch.setenv("SPRITES_TOKEN_FILE", str(tf))
    monkeypatch.setenv("SPRITES_TOKEN", "FlyV1 not-a-sprites-token")
    seen = []

    def fake_urlopen(req, timeout=None):
        seen.append(req.get_header("Authorization"))
        if len(seen) == 1:
            tf.write_text("org/1/2/second")  # rotated while we were running
            raise sp.urllib.error.HTTPError(req.full_url, 401, "x", {}, io.BytesIO(b"{}"))
        return FakeResp(b"{}")

    monkeypatch.setattr(sp.urllib.request, "urlopen", fake_urlopen)
    api = sp.SpritesAPI()
    api.get_network_policy("w")
    assert seen == ["Bearer org/1/2/first", "Bearer org/1/2/second"]
    assert "org/1/2" not in repr(api)


def test_exec_stream_parsing():
    assert sp.parse_exec_stream(b"\x01hello\n\x02err\n\x03\x03") == (b"hello\n", b"err\n", 3)
    assert sp.parse_exec_stream(b"\x01a\n\x01b\n\x03\x00") == (b"a\nb\n", b"", 0)
    assert sp.parse_exec_stream(b"plain") == (b"plain", b"", None)


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
    base = "https://api.sprites.dev"

    def __init__(self, bundle, finish=True):
        self.calls, self.bundle, self.files, self.finish = [], bundle, {}, finish
        self.token = None

    def write_file(self, name, path, data, mode="0644"):
        self.calls.append(("write", path))
        try:
            self.token = json.loads(data).get("token") or self.token
        except ValueError:
            pass

    def exec_result(self, name, argv, timeout=None):
        s = argv[-1]
        self.calls.append(("exec", s[:60]))
        if "until [ -f" in s:
            return ((self.token if self.finish else "") + "\n", "", 0)
        if "setsid nohup" in s:
            return ("cr-started\n", "", 0)
        return ("cr-ready\n", "", 0)

    def read_file(self, name, path):
        self.calls.append(("read", path))
        return self.bundle

    def restore(self, name, cid):
        self.calls.append(("restore", cid))

    def get_network_policy(self, name):
        return {"rules": [{"domain": "*", "action": "deny"}]}


def _tar(files: dict, extra=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for n, d in files.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            tf.addfile(ti, io.BytesIO(d))
        for ti in extra or []:
            tf.addfile(ti)
    return buf.getvalue()


def _bundle():
    meta = {"rc": 0, "ms": 1234, "tracer": "strace+audit", "dns_probe": "refused", "candidate_uid": "separate"}
    return _tar({"cr-trace/meta.json": json.dumps(meta).encode(), "cr-trace/stdout.txt": b"hi\n",
                 "cr-trace/stderr.txt": b"", "cr-trace/outputs/submission.csv": b"id,pred\n1,0.5\n",
                 "cr-trace/audit.jsonl": b'{"ev":"open","pid":1,"path":"data/train.csv","mode":"r"}\n'})


def test_run_from_checkpoint_restores_then_pulls_trace(tmp_path, monkeypatch):
    monkeypatch.setattr(sp.time, "sleep", lambda s: None)
    api = FakeAPI(_bundle())
    be = sp.SpriteBackend(tmp_path, worker="w", api=api)
    from cleanroom.backends.base import RunSpec
    res = be.run_from_checkpoint("v3", RunSpec("B", ["python3", "b.py"]), tmp_path / "t")
    assert api.calls[0] == ("restore", "v3")
    assert any(c[0] == "read" and c[1].startswith(sp.REMOTE_OUT) for c in api.calls)
    launch = [c for c in api.calls if c[0] == "exec" and "setsid nohup" in c[1]]
    assert launch, "runner must be launched detached, not as one long exec"
    assert res.exit_code == 0 and res.duration_s == 1.234 and res.tracer == "strace+audit"
    assert res.checkpoint == "v3" and res.workdir == sp.REMOTE_WORK and res.candidate_uid == "separate"
    assert res.output_sha256 and "refused" in res.network
    assert res.egress_verified is False          # no verified deny-policy probe in this fake
    assert (tmp_path / "t" / "audit.jsonl").exists()


def test_runner_exit_without_done_marker_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(sp.time, "sleep", lambda s: None)
    be = sp.SpriteBackend(tmp_path, worker="w", api=FakeAPI(_bundle(), finish=False))
    from cleanroom.backends.base import RunSpec
    with pytest.raises(sp.SpritesAPIError, match="exited without finishing"):
        be.run(RunSpec("B", ["python3", "b.py"]), tmp_path / "t")


def test_poll_liveness_check_cannot_match_itself():
    import inspect
    src = inspect.getsource(sp.SpriteBackend._launch_and_wait)
    assert "[r]unner.py" in src


def test_extract_bundle_refuses_traversal_links_and_oversize(tmp_path, monkeypatch):
    from cleanroom.backends import base
    monkeypatch.setattr(base, "MAX_MEMBER", 10)
    sym = tarfile.TarInfo("cr-trace/link")
    sym.type, sym.linkname = tarfile.SYMTYPE, "/etc/passwd"
    hard = tarfile.TarInfo("cr-trace/hard")
    hard.type, hard.linkname = tarfile.LNKTYPE, "cr-trace/ok"
    data = _tar({"cr-trace/ok": b"fine", "cr-trace/../../evil": b"x", "/abs/evil": b"x",
                 "other/evil": b"x", "cr-trace/big": b"x" * 50}, extra=[sym, hard])
    out = tmp_path / "t"
    probs = base.extract_bundle(data, out)
    assert (out / "ok").read_text() == "fine"
    assert not (out / "link").exists() and not (out / "hard").exists() and not (out / "big").exists()
    assert not (tmp_path / "evil").exists() and not (tmp_path.parent / "evil").exists()
    assert len(probs) == 6
    assert json.loads((out / "bundle_problems.json").read_text()) == probs


def test_corrupt_bundle_is_reported(tmp_path):
    from cleanroom.backends import base
    probs = base.extract_bundle(b"not a tarball", tmp_path / "t")
    assert probs and "unreadable" in probs[0]
