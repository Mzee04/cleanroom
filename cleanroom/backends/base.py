"""The Backend interface: where and how a candidate submission is executed.

A backend must be able to

  * snapshot the environment a run starts from (``checkpoint``),
  * execute a command with egress denied and syscalls traced (``run``),
  * put the environment back to a snapshot and run again, optionally with
    some files hidden (``run_from_checkpoint``), which is how ``verify`` and
    the agent's investigations work.

Two implementations ship: ``LocalBackend`` (subprocess + strace, tarball
snapshots) and ``SpriteBackend`` (a Fly.io Sprite driven over the Sprites API,
with a deny-by-default network policy and real filesystem checkpoints).
"""
from __future__ import annotations

import abc
import hashlib
import io
import json
import os
import tarfile
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

HOOK_DIR = Path(__file__).resolve().parent.parent / "_hook"
RUNNER = Path(__file__).resolve().parent.parent / "_runner" / "runner.py"
SECCOMP = RUNNER.with_name("seccomp_exec.py")
MAX_MEMBER = 256 << 20
MAX_BUNDLE = 1 << 30
# variables a candidate run may inherit from the caller; everything else is dropped
ENV_ALLOW = ("PATH", "LANG", "LANGUAGE", "TZ", "TERM", "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_MESSAGES",
             "VIRTUAL_ENV", "CONDA_PREFIX", "OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS")


@dataclass
class RunSpec:
    name: str
    cmd: list[str]
    output: str = "submission.csv"
    extra_outputs: list[str] = field(default_factory=list)  # e.g. holdout predictions
    env: dict[str, str] = field(default_factory=dict)
    network_policy: dict = field(default_factory=lambda: {"rules": [{"domain": "*", "action": "deny"}]})
    timeout: int = 900


@dataclass
class RunResult:
    exit_code: int
    duration_s: float
    workdir: str                      # absolute workdir *as seen by the traced process*
    trace_dir: str                    # local directory holding trace files + outputs
    output_sha256: str | None
    outputs: dict[str, str]           # logical name -> local copy path
    tracer: str                       # strace+audit | audit | none
    network: str                      # human description of how egress was enforced
    stdout_tail: str = ""
    stderr_tail: str = ""
    checkpoint: str = ""
    notes: list[str] = field(default_factory=list)
    egress_verified: bool = False     # denial of egress was checked for this run, not just configured
    candidate_uid: str = "same"       # separate: candidate ran as its own unprivileged uid

    def to_dict(self) -> dict:
        return asdict(self)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tail(s: str | bytes, n: int = 2000) -> str:
    if isinstance(s, bytes):
        s = s.decode("utf-8", "replace")
    return s[-n:]


def base_env(extra: dict | None = None) -> dict:
    """The environment a candidate gets: an allowlist, never the caller's secrets."""
    env = {k: v for k, v in os.environ.items() if k in ENV_ALLOW}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env.update({"PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"})
    env.update(extra or {})
    return env


def extract_bundle(data: bytes, trace_dir: Path) -> list[str]:
    """Unpack a runner bundle into ``trace_dir``, refusing anything unsafe.

    Only regular files under ``cr-trace/`` are written; members that are links,
    devices, absolute, contain ``..``, resolve outside ``trace_dir`` or are too
    large are skipped and reported. The problems are also written to
    ``bundle_problems.json`` so the checks can fail closed.
    """
    dest = Path(trace_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    total = 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except (tarfile.TarError, OSError, EOFError) as e:
        problems.append(f"bundle unreadable: {type(e).__name__}")
        (dest / "bundle_problems.json").write_text(json.dumps(problems))
        return problems
    with tf:
        for m in tf:
            name = m.name
            parts = PurePosixPath(name).parts
            if not m.isfile():
                problems.append(f"skipped non-regular member {name[:120]!r}")
                continue
            if (name.startswith("/") or not parts or parts[0] != "cr-trace" or len(parts) < 2
                    or any(p in ("..", "") for p in parts)):
                problems.append(f"skipped unsafe member name {name[:120]!r}")
                continue
            out = (dest / PurePosixPath(*parts[1:])).resolve()
            if dest not in out.parents:
                problems.append(f"skipped member resolving outside the trace dir {name[:120]!r}")
                continue
            if m.size > MAX_MEMBER:
                problems.append(f"skipped oversized member {name[:120]!r} ({m.size} bytes)")
                continue
            total += m.size
            if total > MAX_BUNDLE:
                problems.append("bundle larger than the limit; the rest was not extracted")
                break
            out.parent.mkdir(parents=True, exist_ok=True)
            if out.is_symlink():
                out.unlink()
            src = tf.extractfile(m)
            if src is None:
                continue
            with src, open(out, "wb") as fh:
                left = MAX_MEMBER
                while left > 0:
                    chunk = src.read(min(1 << 20, left))
                    if not chunk:
                        break
                    fh.write(chunk)
                    left -= len(chunk)
    if problems:
        (dest / "bundle_problems.json").write_text(json.dumps(problems))
    return problems


def state_root(project: Path) -> Path:
    """Where traces, replays and checkpoints live: outside the candidate's project tree."""
    env = os.environ.get("CLEANROOM_STATE_DIR")
    if env:
        base = Path(env).expanduser()
    else:
        base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "cleanroom"
    tag = hashlib.sha256(str(Path(project).resolve()).encode()).hexdigest()[:12]
    p = (base / f"{Path(project).resolve().name}-{tag}").resolve()
    p.mkdir(parents=True, exist_ok=True)
    os.chmod(p, 0o700)
    return p


class Backend(abc.ABC):
    name = "abstract"

    def __init__(self, project: Path, private: list[str] | None = None, **kw):
        self.project = Path(project).resolve()
        self.state = self.project / ".cleanroom"
        self.state.mkdir(exist_ok=True)
        self.private = [p.rstrip("/") for p in (private or [])]   # never copied to where candidates run
        self.fingerprint: dict = {}

    def is_private(self, rel: str) -> bool:
        rel = rel.replace(os.sep, "/")
        return any(rel == p or rel.startswith(p + "/") for p in self.private)

    # environment ------------------------------------------------------------
    @abc.abstractmethod
    def prepare(self, network_policy: dict) -> dict:
        """Make the execution environment ready. Returns facts for the report."""

    @abc.abstractmethod
    def doctor(self) -> dict:
        """Report which isolation and tracing features actually work here."""

    # snapshots --------------------------------------------------------------
    @abc.abstractmethod
    def checkpoint(self, label: str) -> str:
        """Snapshot the environment a run starts from; returns a checkpoint id."""

    # execution --------------------------------------------------------------
    @abc.abstractmethod
    def run(self, spec: RunSpec, trace_dir: Path) -> RunResult:
        """Run in the current environment state, traced and with egress denied."""

    @abc.abstractmethod
    def run_from_checkpoint(self, checkpoint_id: str, spec: RunSpec, trace_dir: Path,
                            hide: tuple[str, ...] = ()) -> RunResult:
        """Restore ``checkpoint_id``, optionally delete ``hide`` paths, then run."""

    def describe(self) -> dict:
        return {"backend": self.name}
