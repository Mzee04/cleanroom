"""SpriteBackend: run candidates on a Fly.io Sprite (the "worker").

Written against the documented Sprites REST API (https://api.sprites.dev,
OpenAPI v0.1.12, https://docs.fly.io/sprites/api/):

  POST /v1/sprites                                  create the worker
  POST /v1/sprites/{name}/policy/network            deny-by-default egress (set from OUTSIDE;
                                                    read-only inside at /.sprite/policy/network.json)
  PUT  /v1/sprites/{name}/fs/write                  upload project tarball + audit hook
  POST /v1/sprites/{name}/exec?cmd=...              run (non-TTY HTTP exec)
  GET  /v1/sprites/{name}/fs/read                   fetch trace bundle + outputs
  POST /v1/sprites/{name}/checkpoint                filesystem checkpoint (NDJSON stream)
  POST /v1/sprites/{name}/checkpoints/{id}/restore  restore (wipes the writable overlay)

Restoring wipes the worker's whole disk, which is why the ledger, traces and
reports live with the agent (another Sprite, or your laptop), never on the
worker.

Auth: a Sprites API token, read from the file named by ``SPRITES_TOKEN_FILE``
(preferred; on the agent Sprite this is a 0600 file written through the fs
API, never on a command line) or from ``SPRITES_TOKEN``. The Sprites connector
gateway refuses to wrap the Sprites API itself ("blocked: base URL targets the
Sprites API itself"), so a connector cannot hold this particular token. The
worker Sprite never receives it, and this module never prints or logs it.
"""
from __future__ import annotations

import io
import json
import os
import re
import shlex
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ..trace import STRACE_ARGS
from .base import HOOK_DIR, Backend, RunResult, RunSpec, sha256_file, tail
from .local import EXCLUDE_DIRS

DEFAULT_API = "https://api.sprites.dev"
REMOTE_HOME = "/home/sprite"
REMOTE_WORK = f"{REMOTE_HOME}/work"
REMOTE_HOOK = f"{REMOTE_HOME}/.cleanroom-hook"


class SpritesAPIError(RuntimeError):
    pass


def parse_exec_stream(raw: bytes) -> tuple[bytes, bytes, int | None]:
    """Decode the non-TTY HTTP exec reply (observed live, Sprites API v0.1.12).

    The body is a byte stream of frames: 0x01 + stdout bytes, 0x02 + stderr
    bytes, and finally 0x03 + one byte holding the exit code. A frame runs
    until the next frame marker.
    """
    out, err, code = bytearray(), bytearray(), None
    cur = None
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 3 and i + 1 < len(raw) and i + 2 >= len(raw):
            code = raw[i + 1]
            break
        if b in (1, 2):
            cur = out if b == 1 else err
        elif cur is not None:
            cur.append(b)
        else:
            out.append(b)  # tolerate an unframed body
        i += 1
    return bytes(out), bytes(err), code


class SpritesAPI:
    """Minimal Sprites REST client (stdlib only)."""

    def __init__(self, base_url: str | None = None, token: str | None = None, timeout: int = 600):
        self.base = (base_url or os.environ.get("CLEANROOM_SPRITES_API") or DEFAULT_API).rstrip("/")
        self._token_file = None if token is not None else os.environ.get("SPRITES_TOKEN_FILE")
        self._token = token if token is not None else self._read_token()
        self.via_gateway = "/v1/gateway/" in self.base
        self.timeout = timeout
        if not self.via_gateway and not self._token:
            raise SpritesAPIError("Set SPRITES_TOKEN_FILE (path to a 0600 file holding a Sprites API token) "
                                  "or SPRITES_TOKEN")

    def _read_token(self) -> str | None:
        if self._token_file:
            try:
                return Path(self._token_file).expanduser().read_text().strip() or None
            except OSError:
                raise SpritesAPIError("SPRITES_TOKEN_FILE is set but cannot be read") from None
        return (os.environ.get("SPRITES_TOKEN") or "").strip() or None

    def __repr__(self):  # never leak the token in tracebacks or logs
        return f"SpritesAPI(base={self.base!r}, gateway={self.via_gateway})"

    def request(self, method: str, path: str, *, query: list[tuple[str, str]] | None = None,
                body: bytes | dict | None = None, ctype: str | None = None, stream: bool = False,
                timeout: int | None = None):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None
        headers = {}
        if isinstance(body, dict):
            data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
        elif body is not None:
            data, headers["Content-Type"] = body, ctype or "application/octet-stream"
        if self._token and not self.via_gateway:
            headers["Authorization"] = "Bearer " + self._token
        for attempt in (0, 1):
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                resp = urllib.request.urlopen(req, timeout=timeout or self.timeout)
                break
            except urllib.error.HTTPError as e:
                detail = e.read()[:400].decode("utf-8", "replace")
                if e.code == 401 and attempt == 0 and self._token_file:
                    fresh = self._read_token()  # token file may have been rotated
                    if fresh and fresh != self._token:
                        self._token = fresh
                        headers["Authorization"] = "Bearer " + fresh
                        continue
                raise SpritesAPIError(f"{method} {path} -> HTTP {e.code}: {detail}") from None
        if stream:
            return resp
        with resp:
            return resp.status, resp.read()

    # sprites ------------------------------------------------------------
    def get_sprite(self, name):
        try:
            return json.loads(self.request("GET", f"/v1/sprites/{name}")[1])
        except SpritesAPIError as e:
            if "HTTP 404" in str(e):
                return None
            raise

    def create_sprite(self, name, public_url: bool = False):
        body = {"name": name}
        if public_url:
            body["url_settings"] = {"auth": "public"}
        return json.loads(self.request("POST", "/v1/sprites", body=body)[1] or b"{}")

    # policy ---------------------------------------------------------------
    def set_network_policy(self, name, policy: dict):
        return self.request("POST", f"/v1/sprites/{name}/policy/network", body=policy)[1]

    def get_network_policy(self, name) -> dict:
        return json.loads(self.request("GET", f"/v1/sprites/{name}/policy/network")[1] or b"{}")

    # fs -------------------------------------------------------------------
    def write_file(self, name, path, data: bytes, mode="0644"):
        q = [("path", path), ("workingDir", "/"), ("mode", mode), ("mkdir", "true")]
        return self.request("PUT", f"/v1/sprites/{name}/fs/write", query=q, body=data)[1]

    def read_file(self, name, path) -> bytes:
        q = [("path", path), ("workingDir", "/")]
        return self.request("GET", f"/v1/sprites/{name}/fs/read", query=q)[1]

    # exec -----------------------------------------------------------------
    def exec_result(self, name, argv: list[str], **kw) -> tuple[str, str, int | None]:
        """Run a command; returns (stdout, stderr, exit_code)."""
        o, e, c = parse_exec_stream(self.exec(name, argv, **kw))
        return o.decode("utf-8", "replace"), e.decode("utf-8", "replace"), c

    def exec(self, name, argv: list[str], *, workdir: str | None = None,
             env: dict | None = None, timeout: int | None = None) -> bytes:
        q = [("cmd", a) for a in argv]
        if workdir:
            q.append(("dir", workdir))
        for k, v in (env or {}).items():
            q.append(("env", f"{k}={v}"))
        return self.request("POST", f"/v1/sprites/{name}/exec", query=q, timeout=timeout)[1]

    # checkpoints ------------------------------------------------------------
    def _ndjson(self, method, path, body=None, timeout=None) -> list[dict]:
        resp = self.request(method, path, body=body, stream=True, timeout=timeout)
        events = []
        with resp:
            for raw in resp:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    events.append(json.loads(raw))
                except json.JSONDecodeError:
                    events.append({"type": "info", "data": raw.decode("utf-8", "replace")})
        errs = [e for e in events if e.get("type") == "error"]
        if errs:
            raise SpritesAPIError(f"{path}: {errs[-1].get('data') or errs[-1]}")
        return events

    def create_checkpoint(self, name, comment: str) -> str:
        events = self._ndjson("POST", f"/v1/sprites/{name}/checkpoint", body={"comment": comment})
        for e in reversed(events):
            m = re.search(r"\b(v\d+)\b", str(e.get("data", "")))
            if m:
                return m.group(1)
        cps = self.list_checkpoints(name)
        mine = [c for c in cps if c.get("comment") == comment] or cps
        mine.sort(key=lambda c: c.get("create_time", ""))
        if not mine:
            raise SpritesAPIError("checkpoint created but no id returned")
        return mine[-1]["id"]

    def list_checkpoints(self, name) -> list[dict]:
        data = json.loads(self.request("GET", f"/v1/sprites/{name}/checkpoints")[1] or b"[]")
        return data.get("checkpoints", data) if isinstance(data, dict) else data

    def restore(self, name, checkpoint_id: str) -> list[dict]:
        return self._ndjson("POST", f"/v1/sprites/{name}/checkpoints/{checkpoint_id}/restore")


def _tar_project(project: Path) -> bytes:
    buf = io.BytesIO()

    def filt(ti):
        if any(p in EXCLUDE_DIRS for p in Path(ti.name).parts):
            return None
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        return ti

    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for child in sorted(project.iterdir()):
            if child.name not in EXCLUDE_DIRS:
                tf.add(child, arcname=child.name, filter=filt)
    return buf.getvalue()


class SpriteBackend(Backend):
    """Runs candidates on a worker Sprite.

    STATUS: written against the documented API; the live test is recorded in
    the README (section "Sprite deployment status").
    """

    name = "sprite"

    def __init__(self, project: Path, worker: str | None = None, api: SpritesAPI | None = None,
                 setup: list[str] | None = None, **kw):
        super().__init__(project)
        self.worker = worker or os.environ.get("CLEANROOM_WORKER", "cleanroom-worker")
        self.api = api or SpritesAPI()
        self.setup_cmds = setup or []
        self._caps = None
        self._policy_evidence = {}

    def describe(self):
        return {"backend": self.name, "worker": self.worker, "api": self.api.base.split("/v1/")[0]
                if not self.api.via_gateway else "Sprites connector gateway"}

    # -- helpers -----------------------------------------------------------
    def _sh(self, script: str, timeout: int = 900) -> str:
        """Run a bash script on the worker; returns stdout followed by stderr."""
        if hasattr(self.api, "exec_result"):
            out, err, code = self.api.exec_result(self.worker, ["bash", "-c", script], timeout=timeout)
            self.last_exit = code
            return out + err
        return self.api.exec(self.worker, ["bash", "-c", script], timeout=timeout).decode("utf-8", "replace")

    def _wait_ready(self, limit: float = 180):
        t0 = time.time()
        last = None
        while time.time() - t0 < limit:
            try:
                if "cr-ready" in self._sh("echo cr-ready", timeout=60):
                    return
            except Exception as e:  # restarting after restore / waking
                last = e
            time.sleep(3)
        raise SpritesAPIError(f"worker {self.worker} not ready after {limit}s: {last}")

    def _apply_policy(self, policy: dict) -> dict:
        self.api.set_network_policy(self.worker, policy)
        got = self.api.get_network_policy(self.worker)
        inside = self._sh(
            "cat /.sprite/policy/network.json 2>/dev/null; echo; "
            "(getent hosts example.com >/dev/null 2>&1 && echo DNS:resolves) || echo DNS:refused; "
            "(curl -sS -m 6 -o /dev/null https://example.com 2>/dev/null && echo HTTPS:open) || echo HTTPS:blocked; "
            "python3 -c \"import socket;s=socket.socket();s.settimeout(5);s.connect(('1.1.1.1',443));print('RAWIP:open')\" "
            "2>/dev/null || echo RAWIP:blocked", timeout=90)
        self._policy_evidence = {"set": policy, "api_reports": got, "inside_probe": inside.strip()[-600:]}
        return self._policy_evidence

    # -- interface -------------------------------------------------------------
    def doctor(self) -> dict:
        if self._caps is None:
            out = self._sh(
                "command -v strace >/dev/null && echo strace_installed=1 || echo strace_installed=0; "
                "strace -f -qq -o /dev/null true 2>/dev/null && echo strace_works=1 || echo strace_works=0; "
                "test -r /.sprite/policy/network.json && echo policy_file=1 || echo policy_file=0; "
                "python3 -c 'import sys;print(\"python=\"+sys.version.split()[0])'; "
                "command -v sprite-env >/dev/null && echo sprite_env=1 || echo sprite_env=0", timeout=120)
            caps = {}
            for line in out.splitlines():
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    caps[k] = (v == "1") if v in ("0", "1") else v
            caps["audit_hook"] = True
            self._caps = caps
        return dict(self._caps)

    def prepare(self, network_policy: dict) -> dict:
        created = False
        if self.api.get_sprite(self.worker) is None:
            self.api.create_sprite(self.worker)
            created = True
        self._wait_ready()
        # setup needs package mirrors, so egress is opened only for setup, before any candidate runs
        self.api.set_network_policy(self.worker, {"rules": [{"include": "defaults"}]})
        setup = ["command -v strace >/dev/null || (sudo apt-get update -qq && sudo apt-get install -y -qq strace)"]
        setup += self.setup_cmds
        setup_log = self._sh(" ; ".join(f"({c}) 2>&1 | tail -3" for c in setup), timeout=1200)
        # upload hook + project
        self.api.write_file(self.worker, f"{REMOTE_HOOK}/sitecustomize.py",
                            (HOOK_DIR / "sitecustomize.py").read_bytes())
        self.api.write_file(self.worker, "/tmp/cr-project.tgz", _tar_project(self.project))
        self._sh(f"rm -rf {REMOTE_WORK} && mkdir -p {REMOTE_WORK} && tar -xzf /tmp/cr-project.tgz -C {REMOTE_WORK}"
                 " && rm -f /tmp/cr-project.tgz")
        ev = self._apply_policy(network_policy)
        self._caps = None
        return {"backend": self.name, "worker": self.worker, "created": created,
                "capabilities": self.doctor(), "network_policy": ev,
                "setup_log_tail": setup_log[-800:],
                "network": self._network_desc()}

    def _network_desc(self) -> str:
        probe = self._policy_evidence.get("inside_probe", "")
        if "DNS:refused" in probe and "HTTPS:blocked" in probe and "RAWIP:blocked" in probe:
            verdict = "denied (probed inside worker: DNS refused, HTTPS blocked, raw IP blocked)"
        elif "DNS:resolves" in probe or ":open" in probe:
            verdict = "WARNING: egress still open inside worker (" + " ".join(
                w for w in probe.split() if ":" in w and w.split(":")[0] in ("DNS", "HTTPS", "RAWIP")) + ")"
        else:
            verdict = "unverified"
        return f"Sprite network policy (set via Sprites API from outside): {verdict}"

    def checkpoint(self, label: str) -> str:
        return self.api.create_checkpoint(self.worker, f"cleanroom: {label}")

    def run(self, spec: RunSpec, trace_dir: Path, hide: tuple[str, ...] = ()) -> RunResult:
        trace_dir = Path(trace_dir)
        trace_dir.mkdir(parents=True, exist_ok=True)
        q = shlex.quote
        outs = [spec.output, *spec.extra_outputs]
        cmd = " ".join(q(c) for c in spec.cmd)
        envs = {"PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1",
                "CLEANROOM_AUDIT_LOG": "/tmp/cr-trace/audit.jsonl", "PYTHONPATH": REMOTE_HOOK, **spec.env}
        exports = " ".join(f"{k}={q(v)}" for k, v in envs.items())
        strace = "strace " + " ".join(q(a) for a in STRACE_ARGS) + " -o /tmp/cr-trace/strace --"
        script = f"""
T=/tmp/cr-trace; rm -rf $T /tmp/cr-trace.tgz; mkdir -p $T/outputs
cd {q(REMOTE_WORK)} || exit 97
rm -f {' '.join(q(o) for o in outs)} {' '.join(q(h) for h in hide)}
export {exports}
if command -v strace >/dev/null && strace -f -qq -o /dev/null true 2>/dev/null; then
  echo strace+audit > $T/tracer; PRE="{strace}"
else
  echo audit > $T/tracer; PRE=""
fi
s=$(date +%s%N)
timeout {int(spec.timeout)} $PRE {cmd} > $T/stdout.txt 2> $T/stderr.txt; echo $? > $T/rc
e=$(date +%s%N); echo $(( (e - s) / 1000000 )) > $T/ms
for f in {' '.join(q(o) for o in outs)}; do [ -f "$f" ] && mkdir -p "$T/outputs/$(dirname "$f")" && cp "$f" "$T/outputs/$f"; done
cat /.sprite/policy/network.json > $T/network_policy.json 2>/dev/null
(getent hosts example.com >/dev/null 2>&1 && echo resolves || echo refused) > $T/dns_probe
tar -czf /tmp/cr-trace.tgz -C /tmp cr-trace && echo cr-done
"""
        out = self._sh(script, timeout=spec.timeout + 120)
        if "cr-done" not in out:
            raise SpritesAPIError("remote run did not complete: " + tail(out, 400))
        bundle = self.api.read_file(self.worker, "/tmp/cr-trace.tgz")
        with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                rel = Path(m.name).relative_to("cr-trace")
                dst = trace_dir / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(tf.extractfile(m).read())

        def rd(n, d=""):
            p = trace_dir / n
            return p.read_text(errors="replace").strip() if p.exists() else d

        outputs = {o: str(trace_dir / "outputs" / o) for o in outs if (trace_dir / "outputs" / o).exists()}
        sha = sha256_file(Path(outputs[spec.output])) if spec.output in outputs else None
        dns = rd("dns_probe", "unknown")
        res = RunResult(exit_code=int(rd("rc", "1") or 1), duration_s=int(rd("ms", "0") or 0) / 1000,
                        workdir=REMOTE_WORK, trace_dir=str(trace_dir), output_sha256=sha, outputs=outputs,
                        tracer=rd("tracer", "audit"),
                        network=f"Sprite network policy (set from outside); DNS probe during run: {dns}",
                        stdout_tail=tail(rd("stdout.txt")), stderr_tail=tail(rd("stderr.txt")))
        if hide:
            res.notes.append("hidden for this run: " + ", ".join(hide))
        return res

    def run_from_checkpoint(self, checkpoint_id, spec, trace_dir, hide=()):
        self.api.restore(self.worker, checkpoint_id)
        time.sleep(2)
        self._wait_ready()
        pol = self.api.get_network_policy(self.worker)
        res = self.run(spec, trace_dir, hide=hide)
        res.checkpoint = checkpoint_id
        res.notes.append(f"restored Sprite checkpoint {checkpoint_id} on {self.worker}; "
                         f"network policy after restore: {json.dumps(pol)[:200]}")
        return res
