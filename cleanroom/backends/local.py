"""LocalBackend: run candidates on this machine.

* Isolation: ``unshare -rn`` gives the process an empty network namespace,
  so every outbound connection fails (all-or-nothing; there is no allowlist
  locally). Without unshare, network is observed but not blocked.
* Tracing: ``strace -f -ff`` when ptrace is permitted, plus Clean Room's
  Python audit hook (host names, opens) in every Python child.
* Checkpoints: a gzip tarball of the project directory (``.cleanroom`` and
  caches excluded). Restoring extracts it into a fresh replay directory.
"""
from __future__ import annotations

import gzip
import json
import os
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

from ..trace import STRACE_ARGS
from .base import HOOK_DIR, Backend, RunResult, RunSpec, sha256_file, tail

EXCLUDE_DIRS = {".cleanroom", "__pycache__", ".git", ".pytest_cache", ".venv", "node_modules"}


def _probe(cmd: list[str]) -> bool:
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class LocalBackend(Backend):
    name = "local"

    def __init__(self, project: Path, **kw):
        super().__init__(project)
        self.ckdir = self.state / "checkpoints"
        self.ckdir.mkdir(exist_ok=True)
        self._caps = None

    # ------------------------------------------------------------------
    def doctor(self) -> dict:
        if self._caps is None:
            strace = shutil.which("strace")
            self._caps = {
                "strace_installed": bool(strace),
                "strace_works": bool(strace) and _probe([strace, "-f", "-qq", "-o", os.devnull, "true"]),
                "unshare_net": bool(shutil.which("unshare")) and _probe(["unshare", "-rn", "true"]),
                "audit_hook": True,
            }
            self._caps["strace_in_netns"] = (self._caps["strace_works"] and self._caps["unshare_net"]
                                             and _probe(["unshare", "-rn", strace, "-f", "-qq", "-o",
                                                         os.devnull, "true"]))
        return dict(self._caps)

    def prepare(self, network_policy: dict) -> dict:
        caps = self.doctor()
        allow = [r["domain"] for r in network_policy.get("rules", []) if r.get("action") == "allow"]
        notes = []
        if allow:
            notes.append("Local backend cannot allowlist hosts; all egress is denied "
                         f"(rules allow: {', '.join(allow)}). Use the Sprite backend for an allowlist.")
        return {"backend": self.name, "capabilities": caps, "notes": notes,
                "network": self._network_desc(caps)}

    @staticmethod
    def _network_desc(caps) -> str:
        if caps["unshare_net"]:
            return "denied: empty network namespace (unshare -rn)"
        return "NOT enforced locally (observe only): unshare unavailable"

    # ------------------------------------------------------------------
    def checkpoint(self, label: str) -> str:
        n = len(list(self.ckdir.glob("*.tar.gz")))
        cid = f"local-v{n}"
        path = self.ckdir / f"{cid}.tar.gz"

        def filt(ti: tarfile.TarInfo):
            parts = Path(ti.name).parts
            if any(p in EXCLUDE_DIRS for p in parts):
                return None
            ti.mtime = 0  # snapshots of identical trees hash the same
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            return ti

        # gzip mtime=0 + normalised tar headers: identical trees give identical snapshot hashes
        with open(path, "wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz, \
                tarfile.open(fileobj=gz, mode="w") as tf:
            for child in sorted(self.project.iterdir()):
                if child.name in EXCLUDE_DIRS:
                    continue
                tf.add(child, arcname=child.name, filter=filt)
        meta = {"id": cid, "label": label, "created": time.time(), "sha256": sha256_file(path)}
        (self.ckdir / f"{cid}.json").write_text(json.dumps(meta, indent=2))
        return cid

    def _restore(self, checkpoint_id: str, tag: str) -> Path:
        src = self.ckdir / f"{checkpoint_id}.tar.gz"
        if not src.exists():
            raise FileNotFoundError(f"checkpoint {checkpoint_id} not found")
        dest = self.state / "replay" / f"{tag}-{int(time.time() * 1000)}"
        dest.mkdir(parents=True)
        with tarfile.open(src, "r:gz") as tf:
            try:
                tf.extractall(dest, filter="data")
            except TypeError:  # Python without tarfile filters
                tf.extractall(dest)
        return dest

    # ------------------------------------------------------------------
    def run(self, spec: RunSpec, trace_dir: Path, workdir: Path | None = None) -> RunResult:
        caps = self.doctor()
        wd = Path(workdir or self.project)
        trace_dir = Path(trace_dir)
        trace_dir.mkdir(parents=True, exist_ok=True)
        for out in [spec.output, *spec.extra_outputs]:
            p = wd / out
            if p.exists():
                p.unlink()  # never let a stale file count as this run's output

        env = os.environ.copy()
        for k in list(env):
            if any(s in k.upper() for s in ("TOKEN", "SECRET", "API_KEY", "PASSWORD")):
                env.pop(k)  # candidates never see credentials
        env.update({"PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1",
                    "CLEANROOM_AUDIT_LOG": str(trace_dir / "audit.jsonl"),
                    "PYTHONPATH": os.pathsep.join([str(HOOK_DIR), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)})
        env.update(spec.env)

        cmd = list(spec.cmd)
        tracer = "audit"
        use_strace = caps["strace_works"] and (caps["strace_in_netns"] or not caps["unshare_net"])
        if use_strace:
            cmd = [shutil.which("strace"), *STRACE_ARGS, "-o", str(trace_dir / "strace"), "--", *cmd]
            tracer = "strace+audit"
        if caps["unshare_net"]:
            cmd = ["unshare", "-rn", *cmd]

        t0 = time.time()
        try:
            proc = subprocess.run(cmd, cwd=wd, env=env, capture_output=True, timeout=spec.timeout)
            code, so, se = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            code, so, se = 124, e.stdout or b"", (e.stderr or b"") + b"\n[cleanroom] timeout"
        dur = time.time() - t0
        (trace_dir / "stdout.txt").write_bytes(so)
        (trace_dir / "stderr.txt").write_bytes(se)

        outputs, sha = {}, None
        for out in [spec.output, *spec.extra_outputs]:
            p = wd / out
            if p.exists():
                dst = trace_dir / "outputs" / out
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, dst)
                outputs[out] = str(dst)
        if spec.output in outputs:
            sha = sha256_file(Path(outputs[spec.output]))
        return RunResult(exit_code=code, duration_s=round(dur, 3), workdir=str(wd),
                         trace_dir=str(trace_dir), output_sha256=sha, outputs=outputs,
                         tracer=tracer, network=self._network_desc(caps),
                         stdout_tail=tail(so), stderr_tail=tail(se))

    def run_from_checkpoint(self, checkpoint_id, spec, trace_dir, hide=()):
        wd = self._restore(checkpoint_id, spec.name)
        removed = []
        for h in hide:
            p = wd / h
            if p.exists():
                p.unlink()
                removed.append(h)
        res = self.run(spec, trace_dir, workdir=wd)
        res.checkpoint = checkpoint_id
        res.notes.append(f"restored {checkpoint_id} into {wd.relative_to(self.project)}")
        if removed:
            res.notes.append("hidden for this run: " + ", ".join(removed))
        return res
