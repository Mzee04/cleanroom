"""LocalBackend: run candidates on this machine. DEVELOPMENT MODE.

* Isolation: ``unshare -n`` gives the run an empty network namespace, so
  every outbound connection fails (all-or-nothing; no allowlist locally).
  Without unshare, network is observed but not blocked, and the report says
  egress was not verified.
* Tracing: ``strace -f -ff -y`` when ptrace is permitted, plus Clean Room's
  Python audit hook, both driven by the same runner the Sprite worker uses.
* Where things live: checkpoints, replays and traces are kept under the state
  directory (``$CLEANROOM_STATE_DIR`` or ``~/.local/state/cleanroom``), never
  inside the project the candidate runs in. Every run starts from a fresh
  copy of the checkpoint.
* Environment: an allowlist (PATH, locale, a few thread settings); nothing
  else from your shell reaches the candidate.
* Same uid by default: the candidate runs as you, so it *could* edit or stop
  its trace. Clean Room detects the common ways (truncation holes, missing
  exit records, writes to trace paths) and caps these runs at WARN. Set
  ``CLEANROOM_CANDIDATE_USER`` to an unprivileged user and allow passwordless
  ``sudo`` to get the worker's separate-uid mode locally.
"""
from __future__ import annotations

import gzip
import json
import os
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

from .._runner.runner import egress_blocked
from ..trace import STRACE_ARGS
from .base import (HOOK_DIR, RUNNER, Backend, RunResult, RunSpec, base_env, extract_bundle, sha256_file,
                   state_root, tail)

EXCLUDE_DIRS = {".cleanroom", "__pycache__", ".git", ".pytest_cache", ".venv", "node_modules"}


def _probe(cmd: list[str], want_ok: bool = True) -> bool:
    try:
        rc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20).returncode
        return (rc == 0) == want_ok
    except (OSError, subprocess.SubprocessError):
        return False


EGRESS_PROBE = ("import socket\ntry:\n    socket.create_connection(('1.1.1.1', 53), 3)\nexcept OSError:\n"
                "    raise SystemExit(1)\n")


def _user_site() -> str | None:
    import site
    try:
        us = site.getusersitepackages()
    except Exception:
        return None
    return us if us and os.path.isdir(us) else None


def _pythonpath(site_dir: str | None = None) -> str:
    """The audit hook first, then this user's site-packages (HOME is moved for the
    candidate, so Python would not find packages installed with ``pip --user``).
    In separate-uid mode ``site_dir`` is a root-owned read-only copy of it."""
    parts = [str(HOOK_DIR)]
    us = site_dir or _user_site()
    if us:
        parts.append(us)
    return os.pathsep.join(parts)


class LocalBackend(Backend):
    name = "local"

    def __init__(self, project: Path, private: list[str] | None = None, candidate_user: str | None = None, **kw):
        super().__init__(project, private=private)
        self.root = state_root(self.project)
        self.ckdir = self.root / "checkpoints"
        self.ckdir.mkdir(exist_ok=True)
        self.user = candidate_user if candidate_user is not None else os.environ.get("CLEANROOM_CANDIDATE_USER")
        self._caps = None

    # ------------------------------------------------------------------
    def doctor(self) -> dict:
        if self._caps is None:
            strace = shutil.which("strace")
            caps = {
                "strace_installed": bool(strace),
                "strace_works": bool(strace) and _probe([strace, "-f", "-qq", "-o", os.devnull, "true"]),
                "unshare_net": bool(shutil.which("unshare")) and _probe(["unshare", "-rn", "true"]),
                "audit_hook": True,
                "separate_uid": False,
            }
            caps["strace_in_netns"] = (caps["strace_works"] and caps["unshare_net"]
                                       and _probe(["unshare", "-rn", strace, "-f", "-qq", "-o", os.devnull, "true"]))
            caps["egress_probe_refused"] = caps["unshare_net"] and _probe(
                ["unshare", "-rn", sys.executable, "-c", EGRESS_PROBE], want_ok=False)
            if self.user:
                caps["separate_uid"] = _probe(["sudo", "-n", "id", "-u", self.user])
            caps["python"] = sys.version.split()[0]
            self._caps = caps
        return dict(self._caps)

    def prepare(self, network_policy: dict) -> dict:
        caps = self.doctor()
        allow = [r["domain"] for r in network_policy.get("rules", []) if r.get("action") == "allow"]
        notes = ["Local backend is development mode; use the Sprite backend for evidence you rely on."]
        if allow:
            notes.append("Local backend cannot allowlist hosts; all egress is denied "
                         f"(rules allow: {', '.join(allow)}). Use the Sprite backend for an allowlist.")
        self.fingerprint = _fingerprint()
        self.site_dir = None
        if caps["separate_uid"] and _user_site():
            # the candidate cannot read this user's home: give it a root-owned read-only copy
            dst = f"/var/tmp/cleanroom-{os.getuid()}/site"
            subprocess.run(["sudo", "-n", "sh", "-c",
                            'mkdir -p "$1" && chmod 0711 "$(dirname "$1")" && rm -rf "$1.new" && '
                            'cp -a "$2/." "$1.new" && chown -R root:root "$1.new" && chmod -R a+rX,go-w "$1.new" '
                            '&& rm -rf "$1" && mv "$1.new" "$1"', "sh", dst, _user_site()],
                           check=False, capture_output=True, timeout=600)
            if os.path.isdir(dst):
                self.site_dir = dst
                notes.append("copied your user site-packages read-only for the candidate user")
        return {"backend": self.name, "capabilities": caps, "notes": notes,
                "network": self._network_desc(caps), "fingerprint": self.fingerprint}

    @staticmethod
    def _network_desc(caps) -> str:
        if caps["unshare_net"] and caps.get("egress_probe_refused"):
            return "denied: empty network namespace (unshare -n), probe refused"
        if caps["unshare_net"]:
            return "empty network namespace (unshare -n), egress probe not confirmed"
        return "NOT enforced locally (observe only): unshare unavailable"

    # ------------------------------------------------------------------
    def checkpoint(self, label: str) -> str:
        n = len(list(self.ckdir.glob("*.tar.gz")))
        cid = f"local-v{n}"
        path = self.ckdir / f"{cid}.tar.gz"

        def filt(ti: tarfile.TarInfo):
            parts = Path(ti.name).parts
            if any(p in EXCLUDE_DIRS for p in parts) or self.is_private(ti.name):
                return None
            ti.mtime = 0  # snapshots of identical trees hash the same
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            return ti

        # gzip mtime=0 + normalised tar headers: identical trees give identical snapshot hashes
        with open(path, "wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz, \
                tarfile.open(fileobj=gz, mode="w") as tf:
            for child in sorted(self.project.iterdir()):
                if child.name in EXCLUDE_DIRS or self.is_private(child.name):
                    continue
                tf.add(child, arcname=child.name, filter=filt)
        meta = {"id": cid, "label": label, "created": time.time(), "sha256": sha256_file(path)}
        (self.ckdir / f"{cid}.json").write_text(json.dumps(meta, indent=2))
        return cid

    def _work_root(self) -> Path:
        if self.doctor()["separate_uid"]:
            p = Path(f"/var/tmp/cleanroom-{os.getuid()}")
            p.mkdir(exist_ok=True)
            os.chmod(p, 0o711)       # the candidate may enter its own workdir, not list others
            return p
        return self.root / "replay"

    def _restore(self, checkpoint_id: str, tag: str) -> Path:
        src = self.ckdir / f"{checkpoint_id}.tar.gz"
        if not src.exists():
            raise FileNotFoundError(f"checkpoint {checkpoint_id} not found")
        dest = self._work_root() / f"{tag}-{int(time.time() * 1000)}-{secrets.token_hex(2)}"
        dest.mkdir(parents=True)
        with tarfile.open(src, "r:gz") as tf:
            try:
                tf.extractall(dest, filter="data")
            except TypeError:  # Python without tarfile filters
                tf.extractall(dest)
        return dest

    # ------------------------------------------------------------------
    def run(self, spec: RunSpec, trace_dir: Path, workdir: Path | None = None, hide: tuple[str, ...] = ()) -> RunResult:
        caps = self.doctor()
        if workdir is None:
            raise ValueError("LocalBackend runs only from a restored checkpoint (use run_from_checkpoint)")
        wd = Path(workdir)
        trace_dir = Path(trace_dir)
        trace_dir.mkdir(parents=True, exist_ok=True)
        sep = caps["separate_uid"]
        token = secrets.token_hex(8)
        rt = (Path(f"/var/tmp/cleanroom-{os.getuid()}") if sep else self.root) / f"rt-{token}"
        bundles = self.root / "bundles"
        bundles.mkdir(exist_ok=True)
        bundle = bundles / f"{token}.tgz"
        use_strace = caps["strace_works"] and (sep or caps["strace_in_netns"] or not caps["unshare_net"])
        rspec = {
            "token": token, "work": str(wd), "trace": str(rt), "bundle": str(bundle),
            "cmd": list(spec.cmd), "timeout": spec.timeout,
            "env": base_env({"PYTHONPATH": _pythonpath(getattr(self, "site_dir", None) if sep else None), "HOME": str(wd), **spec.env}),
            "outputs": [spec.output, *spec.extra_outputs], "hide": list(hide),
            "user": self.user if sep else None, "home": str(wd / ".home") if sep else None,
            "strace": use_strace, "strace_args": STRACE_ARGS,
            "netns": "unshare" if (caps["unshare_net"] or sep) else "none",
            "scan_dirs": [str(wd)], "bundle_owner": os.environ.get("USER") or None,
            "egress_probe": bool(caps["unshare_net"] or sep),
        }
        spec_path = self.root / f"spec-{token}.json"
        spec_path.write_text(json.dumps(rspec))
        os.chmod(spec_path, 0o600)
        cmd = [sys.executable, str(RUNNER), str(spec_path)]
        if sep:
            cmd = ["sudo", "-n", "--", *cmd]
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=spec.timeout + 120)
            runner_err = p.stderr[-2000:].decode("utf-8", "replace") if p.returncode else ""
        except subprocess.TimeoutExpired:
            runner_err = "runner timed out"
        finally:
            spec_path.unlink(missing_ok=True)
        notes = []
        if bundle.exists():
            problems = extract_bundle(bundle.read_bytes(), trace_dir)
            bundle.unlink()
            notes += problems
        else:
            notes.append("runner produced no bundle: " + runner_err[-300:])
        meta = _json(trace_dir / "meta.json")
        outputs = {o: str(trace_dir / "outputs" / o) for o in [spec.output, *spec.extra_outputs]
                   if (trace_dir / "outputs" / o).is_file()}
        sha = sha256_file(Path(outputs[spec.output])) if spec.output in outputs else None
        so = _read_tail(trace_dir / "stdout.txt")
        se = _read_tail(trace_dir / "stderr.txt")
        notes += meta.get("output_problems", [])
        return RunResult(exit_code=int(meta.get("rc", 1)), duration_s=meta.get("ms", 0) / 1000, workdir=str(wd),
                         trace_dir=str(trace_dir), output_sha256=sha, outputs=outputs,
                         tracer=meta.get("tracer", "none"), network=self._network_desc(caps),
                         stdout_tail=so, stderr_tail=se, notes=notes,
                         egress_verified=bool(caps["unshare_net"] and caps.get("egress_probe_refused")
                                              and rspec["netns"] == "unshare"
                                              and egress_blocked(meta.get("egress_probe"))),
                         candidate_uid=meta.get("candidate_uid", "same"))

    def run_from_checkpoint(self, checkpoint_id, spec, trace_dir, hide=()):
        wd = self._restore(checkpoint_id, spec.name)
        res = self.run(spec, trace_dir, workdir=wd, hide=tuple(hide))
        res.checkpoint = checkpoint_id
        res.notes.append(f"restored {checkpoint_id} into a fresh directory outside the project")
        meta = _json(Path(trace_dir) / "meta.json")
        if meta.get("hidden"):
            res.notes.append("hidden for this run: " + ", ".join(meta["hidden"]))
        if self.doctor()["separate_uid"]:
            subprocess.run(["sudo", "-n", "rm", "-rf", "--", str(wd)], capture_output=True)
        else:
            shutil.rmtree(wd, ignore_errors=True)
        return res


def _json(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


def _read_tail(p: Path, n: int = 2000) -> str:
    try:
        size = p.stat().st_size
        with open(p, "rb") as fh:
            fh.seek(max(0, size - n))
            return tail(fh.read(), n)
    except OSError:
        return ""


def _fingerprint() -> dict:
    import platform
    fp = {"python": sys.version.split()[0], "machine": platform.machine(), "system": platform.system(),
          "kernel": platform.release(), "cpus": os.cpu_count()}
    for mod in ("numpy", "sklearn", "scipy", "pandas"):
        try:
            m = __import__(mod)
            fp[mod] = getattr(m, "__version__", "?")
        except Exception:
            pass
    return fp
