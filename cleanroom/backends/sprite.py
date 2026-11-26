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
import http.client
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

import secrets

from ..trace import STRACE_ARGS
from .base import HOOK_DIR, RUNNER, Backend, RunResult, RunSpec, extract_bundle, sha256_file, tail
from .local import EXCLUDE_DIRS

DEFAULT_API = "https://api.sprites.dev"
# /home/sprite is 0750, so everything a separate candidate uid must reach lives under /srv/cr
SRV = "/srv/cr"
REMOTE_WORK = f"{SRV}/work"          # the project; owned by the candidate uid
REMOTE_HOME = f"{SRV}/home"          # the candidate's HOME
REMOTE_BIN = f"{SRV}/bin"            # runner.py + hook/ (root-owned, read-only for the candidate)
REMOTE_HOOK = f"{REMOTE_BIN}/hook"
REMOTE_SITE = f"{SRV}/site"          # read-only copy of the packages worker_setup installed
REMOTE_RT = f"{SRV}/rt"              # runner trace dirs (root 0700 each) and audit FIFOs
REMOTE_OUT = f"{SRV}/out"            # bundles + done markers, handed to the sprite user
REMOTE_SPEC = f"{SRV}/spec"          # run specs (root only)
REMOTE_PYBIN = f"{SRV}/pybin"
CAND_PATH = f"{REMOTE_PYBIN}:/usr/local/bin:/usr/bin:/bin"
CANDIDATE_USER = "cr-cand"
POLL_BLOCK = 40                      # seconds one wait-exec may block (well under the proxy's drop time)


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


def _tar_project(project: Path, is_private=lambda rel: False) -> bytes:
    buf = io.BytesIO()

    def filt(ti):
        if any(p in EXCLUDE_DIRS for p in Path(ti.name).parts) or is_private(ti.name):
            return None
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        return ti

    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for child in sorted(project.iterdir()):
            if child.name not in EXCLUDE_DIRS and not is_private(child.name):
                tf.add(child, arcname=child.name, filter=filt)
    return buf.getvalue()


FINGERPRINT_PY = (
    "import json,os,platform,sys\n"
    "fp={'python':sys.version.split()[0],'machine':platform.machine(),'kernel':platform.release(),"
    "'cpus':os.cpu_count()}\n"
    "for m in ('numpy','sklearn','scipy','pandas'):\n"
    "    try:\n"
    "        fp[m]=__import__(m).__version__\n"
    "    except Exception:\n"
    "        pass\n"
    "print('FP='+json.dumps(fp))\n")


class SpriteBackend(Backend):
    """Runs candidates on a worker Sprite, as an unprivileged uid under a root-owned strace."""

    name = "sprite"

    def __init__(self, project: Path, worker: str | None = None, api: SpritesAPI | None = None,
                 setup: list[str] | None = None, private: list[str] | None = None, **kw):
        super().__init__(project, private=private)
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

    def _put(self, data: bytes, dest: str, mode: str = "0644", owner: str = "root"):
        """Write a file through the fs API (lands as the sprite user) and move it into place as root."""
        tmp = f"/tmp/cr-up-{secrets.token_hex(6)}"
        self.api.write_file(self.worker, tmp, data, mode="0600")
        q = shlex.quote
        self._sh(f"sudo install -D -m {mode} -o {owner} -g {owner} {q(tmp)} {q(dest)} && rm -f {q(tmp)}", timeout=120)

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

    def _egress_verified(self) -> bool:
        probe = self._policy_evidence.get("inside_probe", "")
        return "DNS:refused" in probe and "HTTPS:blocked" in probe and "RAWIP:blocked" in probe

    # -- interface -------------------------------------------------------------
    def doctor(self) -> dict:
        if self._caps is None:
            out = self._sh(
                "command -v strace >/dev/null && echo strace_installed=1 || echo strace_installed=0; "
                f"sudo unshare --user --map-users=all --map-groups=all --keep-caps strace -f -qq -u {CANDIDATE_USER} "
                "-o /dev/null true 2>/dev/null && echo strace_works=1 || echo strace_works=0; "
                f"id -u {CANDIDATE_USER} >/dev/null 2>&1 && echo separate_uid=1 || echo separate_uid=0; "
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
        q = shlex.quote
        # the candidate uid and the /srv/cr layout (all part of the baseline checkpoint)
        self._sh(
            f"set -e; id -u {CANDIDATE_USER} >/dev/null 2>&1 || sudo useradd --system --no-create-home "
            f"--home-dir {REMOTE_HOME} --shell /usr/sbin/nologin {CANDIDATE_USER}; "
            f"sudo mkdir -p {SRV} {REMOTE_BIN} {REMOTE_HOOK} {REMOTE_RT} {REMOTE_OUT} {REMOTE_SPEC} {REMOTE_HOME}; "
            f"sudo chown root:root {SRV} {REMOTE_BIN} {REMOTE_HOOK} {REMOTE_RT} {REMOTE_OUT} {REMOTE_SPEC}; "
            f"sudo chmod 755 {SRV} {REMOTE_BIN} {REMOTE_HOOK} {REMOTE_OUT}; sudo chmod 711 {REMOTE_RT}; "
            f"sudo chmod 700 {REMOTE_SPEC}; "
            # stale links in the scratch dirs would be in the baseline checkpoint and confuse the alias scan
            "sudo find /tmp /var/tmp /dev/shm -xdev -mindepth 1 -maxdepth 3 -type l -delete 2>/dev/null || true; "
            f"US=$(python3 -c 'import site;print(site.getusersitepackages())'); sudo rm -rf {REMOTE_SITE}; "
            f"if [ -d \"$US\" ]; then sudo cp -a \"$US\" {REMOTE_SITE}; else sudo mkdir -p {REMOTE_SITE}; fi; "
            f"sudo chown -R root:root {REMOTE_SITE}; sudo chmod -R a+rX,go-w {REMOTE_SITE}; "
            # the interpreter the setup installed packages for (on a Sprite: a pyenv build behind a shim
            # that is not on a plain PATH); candidates get it first on PATH as python3 / python
            f"PY=$(python3 -c 'import os,sys;print(os.path.realpath(sys.executable))'); sudo rm -rf {REMOTE_PYBIN}; "
            f"sudo mkdir -p {REMOTE_PYBIN}; sudo ln -s \"$PY\" {REMOTE_PYBIN}/python3; "
            f"sudo ln -s \"$PY\" {REMOTE_PYBIN}/python; sudo -u {CANDIDATE_USER} {REMOTE_PYBIN}/python3 -c pass",
            timeout=600)
        self._put((HOOK_DIR / "sitecustomize.py").read_bytes(), f"{REMOTE_HOOK}/sitecustomize.py")
        self._put(RUNNER.read_bytes(), f"{REMOTE_BIN}/runner.py")
        self._put(_tar_project(self.project, self.is_private), "/tmp/cr-project.tgz", mode="0600")
        self._sh(f"sudo rm -rf {REMOTE_WORK} && sudo mkdir -p {REMOTE_WORK} && "
                 f"sudo tar -xzf /tmp/cr-project.tgz -C {REMOTE_WORK} --no-same-owner && sudo rm -f /tmp/cr-project.tgz && "
                 f"sudo chown -R {CANDIDATE_USER}:{CANDIDATE_USER} {REMOTE_WORK} {REMOTE_HOME} && "
                 f"sudo rm -rf {REMOTE_HOME}/.local && echo ok")
        fp_out = self._sh(f"cd {REMOTE_WORK} && sudo -u {CANDIDATE_USER} env -i PATH={CAND_PATH} HOME={REMOTE_HOME} "
                          f"PYTHONPATH={REMOTE_SITE} python3 -c {q(FINGERPRINT_PY)}", timeout=120)
        m = re.search(r"FP=(\{.*\})", fp_out)
        self.fingerprint = json.loads(m.group(1)) if m else {"error": tail(fp_out, 200)}
        self.fingerprint["worker"] = self.worker
        ev = self._apply_policy(network_policy)
        self._caps = None
        return {"backend": self.name, "worker": self.worker, "created": created,
                "capabilities": self.doctor(), "network_policy": ev, "fingerprint": self.fingerprint,
                "setup_log_tail": setup_log[-800:], "network": self._network_desc()}

    def _network_desc(self) -> str:
        probe = self._policy_evidence.get("inside_probe", "")
        if self._egress_verified():
            verdict = "denied (probed inside worker: DNS refused, HTTPS blocked, raw IP blocked)"
        elif "DNS:resolves" in probe or ":open" in probe:
            verdict = "WARNING: egress still open inside worker (" + " ".join(
                w for w in probe.split() if ":" in w and w.split(":")[0] in ("DNS", "HTTPS", "RAWIP")) + ")"
        else:
            verdict = "unverified"
        return f"Sprite network policy (set via Sprites API from outside): {verdict}"

    def checkpoint(self, label: str) -> str:
        return self.api.create_checkpoint(self.worker, f"cleanroom: {label}")

    def _launch_and_wait(self, rspec: dict, timeout: int) -> str:
        """Start the runner detached, then wait with short blocking polls (resumable).

        The runner holds a Sprites Tasks API heartbeat while it works, so the
        Sprite does not pause (and freeze or drop the detached process) between polls.
        """
        token = rspec["token"]
        q = shlex.quote
        spec_path = f"{REMOTE_SPEC}/{token}.json"
        self._put(json.dumps(rspec).encode(), spec_path, mode="0600")
        log = f"{REMOTE_OUT}/{token}.log"
        started = self._sh(f"sudo setsid nohup python3 {REMOTE_BIN}/runner.py {q(spec_path)} > /dev/null 2>&1 "
                           f"< /dev/null & echo cr-started", timeout=60)
        if "cr-started" not in started:
            raise SpritesAPIError("runner did not start: " + tail(started, 300))
        done = rspec["done"]
        deadline = time.time() + timeout + 300
        errors = 0
        while time.time() < deadline:
            # each poll blocks on the worker for a while: the Sprite stays awake while the run is in progress,
            # and no single HTTP exec is long enough for the proxy to drop it
            try:
                out = self._sh(f"timeout {POLL_BLOCK} bash -c 'until [ -f {done} ]; do sleep 1; done'; "
                               f"cat {done} 2>/dev/null; pgrep -f {q('[r]unner.py ' + spec_path)} >/dev/null && echo cr-alive",
                               timeout=POLL_BLOCK + 60)
                errors = 0
            except (SpritesAPIError, OSError, http.client.HTTPException) as e:   # dropped: resume polling
                errors += 1
                if errors > 10:
                    raise SpritesAPIError(f"lost the worker while waiting for run {token}: {e}") from None
                time.sleep(3)
                continue
            if token in out:
                return log
            if "cr-alive" not in out:
                time.sleep(2)
                out = self._sh(f"cat {done} 2>/dev/null", timeout=60)
                if token in out:
                    return log
                raise SpritesAPIError(f"runner for {token} exited without finishing")
        raise SpritesAPIError(f"run {token} did not finish in time")

    def run(self, spec: RunSpec, trace_dir: Path, hide: tuple[str, ...] = ()) -> RunResult:
        trace_dir = Path(trace_dir)
        trace_dir.mkdir(parents=True, exist_ok=True)
        token = secrets.token_hex(8)
        outs = [spec.output, *spec.extra_outputs]
        env = {"PATH": CAND_PATH, "LANG": "C.UTF-8", "PYTHONHASHSEED": "0",
               "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": f"{REMOTE_HOOK}:{REMOTE_SITE}", **spec.env}
        rspec = {"token": token, "work": REMOTE_WORK, "trace": f"{REMOTE_RT}/t-{token}",
                 "audit_dir": f"{REMOTE_RT}/a-{token}", "bundle": f"{REMOTE_OUT}/{token}.tgz",
                 "done": f"{REMOTE_OUT}/{token}.done", "cmd": list(spec.cmd), "env": env,
                 "timeout": int(spec.timeout), "outputs": outs, "hide": list(hide),
                 "user": CANDIDATE_USER, "home": REMOTE_HOME, "strace": True, "strace_args": STRACE_ARGS,
                 "netns": "none", "ptrace_userns": True, "dns_probe": True, "bundle_owner": "sprite",
                 "scan_dirs": [REMOTE_WORK, REMOTE_HOME, "/tmp", "/var/tmp", "/dev/shm"]}
        self._launch_and_wait(rspec, int(spec.timeout))
        bundle = self.api.read_file(self.worker, rspec["bundle"])
        self._sh(f"sudo rm -f {REMOTE_OUT}/{token}.* {REMOTE_SPEC}/{token}.json", timeout=60)
        notes = extract_bundle(bundle, trace_dir)
        try:
            meta = json.loads((trace_dir / "meta.json").read_text())
        except (OSError, ValueError):
            meta = {}
        outputs = {o: str(trace_dir / "outputs" / o) for o in outs if (trace_dir / "outputs" / o).is_file()}
        sha = sha256_file(Path(outputs[spec.output])) if spec.output in outputs else None

        def rd(n):
            p = trace_dir / n
            return p.read_text(errors="replace") if p.exists() else ""
        dns = meta.get("dns_probe", "unknown")
        res = RunResult(exit_code=int(meta.get("rc", 1)), duration_s=int(meta.get("ms", 0)) / 1000,
                        workdir=REMOTE_WORK, trace_dir=str(trace_dir), output_sha256=sha, outputs=outputs,
                        tracer=meta.get("tracer", "none"),
                        network=f"Sprite network policy (set from outside); DNS probe during run: {dns}",
                        stdout_tail=tail(rd("stdout.txt")), stderr_tail=tail(rd("stderr.txt")),
                        notes=notes + meta.get("output_problems", []),
                        egress_verified=self._egress_verified() and dns == "refused",
                        candidate_uid=meta.get("candidate_uid", "same"))
        if meta.get("hidden"):
            res.notes.append("hidden for this run: " + ", ".join(meta["hidden"]))
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
