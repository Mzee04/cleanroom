"""The separate-uid path the Sprite worker uses: runner as root, candidate as its own uid.

Needs passwordless sudo, strace and an unprivileged user named by
CLEANROOM_TEST_USER (CI creates one). Skipped otherwise.
"""
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from cleanroom import checks
from cleanroom.backends.base import extract_bundle
from cleanroom.policy import extract_policy
from cleanroom.trace import STRACE_ARGS, load_trace

USER = os.environ.get("CLEANROOM_TEST_USER", "")
RUNNER = Path(__file__).resolve().parents[1] / "cleanroom" / "_runner" / "runner.py"
HOOK = Path(__file__).resolve().parents[1] / "cleanroom" / "_hook"


def _can_root():
    if not USER or not shutil.which("strace"):
        return False
    try:
        return subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.skipif(not _can_root(), reason="needs sudo -n, strace and CLEANROOM_TEST_USER")
RULES = "1.2 The file test_labels.csv must not be read by participant code.\n"


@pytest.fixture
def box():
    d = Path(tempfile.mkdtemp(prefix="cr-root-", dir="/tmp"))
    os.chmod(d, 0o755)
    (d / "work" / "data").mkdir(parents=True)
    (d / "work" / "data" / "test_labels.csv").write_text("id,target\n1,1\n")
    yield d
    subprocess.run(["sudo", "-n", "rm", "-rf", str(d)], capture_output=True)


def run_root(box: Path, code: str, **kw):
    spec = {"token": "t" + os.urandom(4).hex(), "work": str(box / "work"), "trace": str(box / "rt"),
            "audit_dir": str(box / "audit"), "bundle": str(box / "b.tgz"), "done": str(box / "done"),
            "cmd": ["python3", "-c", code], "timeout": 60, "outputs": ["out.txt"],
            "env": {"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONPATH": str(HOOK)},
            "user": USER, "home": str(box / "home"), "strace": True, "strace_args": STRACE_ARGS,
            "netns": "none", "ptrace_userns": True, "scan_dirs": [str(box / "work")],
            "bundle_owner": os.environ.get("USER") or subprocess.run(["id", "-un"], capture_output=True,
                                                                      text=True).stdout.strip()}
    spec.update(kw)
    sp = box / "spec.json"
    sp.write_text(json.dumps(spec))
    r = subprocess.run(["sudo", "-n", sys.executable, str(RUNNER), str(sp)], capture_output=True, timeout=180)
    assert r.returncode == 0, r.stderr.decode()[-2000:]
    assert extract_bundle(Path(spec["bundle"]).read_bytes(), box / "trace") == []
    return load_trace(box / "trace")


def verdict(t, box):
    fs = checks.analyse(t, extract_policy(RULES), str(box / "work"), 0, "x", "out.txt", ["out.txt"],
                        tracer="strace+audit")
    return fs, checks.worst(fs)


UNTRACED = ("import ctypes, os, time\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "pid = libc.syscall(56, 0x00800000 | 17, 0, 0, 0, 0)\n"
            "if pid == 0:\n"
            "    time.sleep(1.5)\n"
            "    os.read(os.open('data/test_labels.csv', os.O_RDONLY), 100)\n"
            "    os._exit(0)\n"
            "open('out.txt', 'w').write(str(pid) + ' ' + str(ctypes.get_errno()))\n"
            "if pid > 0:\n"
            "    os.waitpid(pid, 0)\n")


@pytest.mark.skipif(platform.machine() != "x86_64", reason="raw clone syscall number is x86_64")
def test_seccomp_refuses_untraced_clone(box):
    t = run_root(box, UNTRACED)
    assert t.meta["seccomp"] == "on" and t.meta["candidate_uid"] == "separate"
    assert (box / "trace" / "outputs" / "out.txt").read_text() == "-1 1"     # EPERM
    assert not t.meta["untraced_procs"]


@pytest.mark.skipif(platform.machine() != "x86_64", reason="raw clone syscall number is x86_64")
def test_untraced_process_without_seccomp_is_caught(box):
    t = run_root(box, UNTRACED, seccomp=False)
    assert t.meta["seccomp"] == "off" and t.meta["untraced_procs"]
    fs, worst = verdict(t, box)
    assert "untraced_process" in {f.code for f in fs if f.severity == "INCONCLUSIVE"}
    assert worst in ("FAIL", "INCONCLUSIVE")


def test_masked_socket_is_hidden_and_connect_fails_the_run(box):
    hidden = box / "fake-sprite"
    hidden.mkdir()
    os.chmod(hidden, 0o755)
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(hidden / "api.sock"))
    os.chmod(hidden / "api.sock", 0o666)
    srv.listen(1)
    code = ("import os, socket\n"
            f"seen = os.listdir({str(hidden)!r})\n"
            "s = socket.socket(socket.AF_UNIX)\n"
            "try:\n"
            f"    s.connect({str(hidden / 'api.sock')!r}); r = 'connected'\n"
            "except OSError as e:\n"
            "    r = type(e).__name__\n"
            "open('out.txt', 'w').write(repr(seen) + ' ' + r)\n")
    try:
        t = run_root(box, code, mask_paths=[str(hidden)])
    finally:
        srv.close()
    assert t.meta["mask"] == "hidden"
    assert (box / "trace" / "outputs" / "out.txt").read_text() == "[] FileNotFoundError"
    fs, worst = verdict(t, box)
    assert worst == "FAIL" and "sandbox_escape_attempt" in {f.code for f in fs}


def test_limits_and_egress_probe_run_as_candidate(box):
    t = run_root(box, "import resource\nopen('out.txt','w').write(str(resource.getrlimit(resource.RLIMIT_NPROC)[0]))\n",
                 netns="unshare", egress_probe=True)
    assert (box / "trace" / "outputs" / "out.txt").read_text() == "1024"
    probe = t.meta["egress_probe"]
    assert "error" not in probe and probe["dns"].startswith("refused")
    from cleanroom._runner.runner import egress_blocked
    assert egress_blocked(probe)


def test_nondumpable_leftover_is_still_killed(box):
    code = ("import ctypes, os, subprocess, sys\n"
            "subprocess.Popen([sys.executable, '-c', 'import ctypes,time; ctypes.CDLL(None).prctl(4,0,0,0,0); "
            "time.sleep(300)'], start_new_session=True)\n"
            "import time; time.sleep(0.5)\n"
            "open('out.txt','w').write('ok')\n")
    t = run_root(box, code)
    assert t.meta["rc"] == 0
    left = subprocess.run(["pgrep", "-u", USER], capture_output=True, text=True).stdout.split()
    assert left == []
