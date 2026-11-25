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
from dataclasses import asdict, dataclass, field
from pathlib import Path

HOOK_DIR = Path(__file__).resolve().parent.parent / "_hook"


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


class Backend(abc.ABC):
    name = "abstract"

    def __init__(self, project: Path, **kw):
        self.project = Path(project).resolve()
        self.state = self.project / ".cleanroom"
        self.state.mkdir(exist_ok=True)

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
