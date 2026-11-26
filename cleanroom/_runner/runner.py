#!/usr/bin/env python3
"""Clean Room runner: execute ONE candidate run and bundle its evidence.

Standalone (stdlib only) so the same file runs on the worker Sprite and
locally. Input is a JSON spec file; output is a tar.gz bundle of
``cr-trace/`` (strace files, audit log, outputs, meta.json, aliases.json)
plus a ``done`` marker holding the run token.

With ``user`` set (the Sprite worker, or a local machine where Clean Room can
use root), the runner must run as root:

* the candidate runs as that unprivileged uid (``strace -u user``), so it
  cannot write, truncate or delete the strace files, and cannot signal the
  root-owned strace to detach it;
* the audit hook writes into a FIFO drained by a collector thread here, so
  records already written cannot be removed;
* every process the candidate started is killed before anything is bundled.

Without ``user`` it runs as the caller (local development mode): the trace is
outside the project, but a same-uid candidate could still edit it, and the
report says so.
"""
from __future__ import annotations

import json
import os
import pwd
import select
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time

MAX_OUTPUT_FILE = 512 << 20      # copied candidate output files
MAX_LOG = 8 << 20                # stdout / stderr kept per run
MAX_ALIASES = 2000
MAX_AUDIT = 64 << 20             # audit records kept per run (the FIFO is writable by the candidate)
NPROC_LIMIT = 1024               # processes/threads the candidate uid may have (fork bombs)
FSIZE_LIMIT = 4 << 30            # largest file the candidate may write
NOFILE_LIMIT = 4096

# Runs as (namespace) root before strace: hide each existing path behind an empty read-only tmpfs,
# write a marker so the runner knows it worked, then exec the rest of the command line.
MASK_SH = ('mark=$1; shift; while [ "$1" != "--" ]; do '
           'if [ -e "$1" ]; then mount -t tmpfs -o ro,mode=0555,size=4k cr-mask "$1" || exit 97; fi; shift; '
           'done; shift; echo masked > "$mark" && exec "$@"')

# Run as the candidate uid, inside the run's network setup, before the candidate starts.
EGRESS_PROBE = r"""
import json, socket, threading
res = {}
def dns():
    try:
        socket.getaddrinfo("example.com", 443)
        res["dns"] = "resolves"
    except OSError:
        res["dns"] = "refused"
def tcp(host, port):
    s = socket.socket(); s.settimeout(3)
    try:
        s.connect((host, port)); res[f"tcp {host}:{port}"] = "open"
    except OSError:
        res[f"tcp {host}:{port}"] = "blocked"
    finally:
        s.close()
def udp():
    q = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(q, ("8.8.8.8", 53)); s.recvfrom(512); res["udp 8.8.8.8:53"] = "open"
    except OSError:
        res["udp 8.8.8.8:53"] = "blocked"
    finally:
        s.close()
ts = [threading.Thread(target=f, args=a, daemon=True) for f, a in
      ((dns, ()), (tcp, ("1.1.1.1", 443)), (tcp, ("8.8.8.8", 53)), (tcp, ("9.9.9.9", 443)), (udp, ()))]
for t in ts: t.start()
for t in ts: t.join(5)
for k in ("dns", "tcp 1.1.1.1:443", "tcp 8.8.8.8:53", "tcp 9.9.9.9:443", "udp 8.8.8.8:53"):
    res.setdefault(k, "blocked (timeout)" if k != "dns" else "refused (timeout)")
print(json.dumps(res))
"""


def _safe_rel(rel: str) -> str:
    rel = os.path.normpath(rel)
    if os.path.isabs(rel) or rel == ".." or rel.startswith("../"):
        raise ValueError(f"unsafe relative path {rel!r}")
    return rel


def _rm_nofollow(path: str):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(path)
    else:
        os.unlink(path)
    return True


def _chown_tree(root: str, uid: int, gid: int):
    os.lchown(root, uid, gid)
    for d, dirs, files in os.walk(root):
        for n in dirs + files:
            try:
                os.lchown(os.path.join(d, n), uid, gid)
            except OSError:
                pass


USERNS = ["unshare", "--user", "--map-users=all", "--map-groups=all", "--keep-caps"]


def _strace_ok(strace: str, user: str | None = None, userns: bool = False) -> bool:
    """Probe the exact way the candidate will be traced (as ``user``, maybe inside USERNS)."""
    cmd = [strace, "-f", "-qq", "-o", os.devnull] + (["-u", user] if user else []) + ["true"]
    if userns:
        cmd = USERNS + cmd
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class Collector(threading.Thread):
    """Drain the audit FIFO into a root-owned file until told to stop."""

    def __init__(self, fifo: str, dest: str):
        super().__init__(daemon=True)
        self.fd = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)   # holding a writer end: never sees EOF
        self.out = open(dest, "ab")
        self.stop = threading.Event()
        self.written = 0
        self.truncated = False

    def run(self):
        try:
            while True:
                r, _, _ = select.select([self.fd], [], [], 0.2)
                if r:
                    try:
                        data = os.read(self.fd, 1 << 16)
                    except BlockingIOError:
                        continue
                    if data:
                        if self.written + len(data) <= MAX_AUDIT:
                            self.out.write(data)
                            self.written += len(data)
                        else:
                            self.truncated = True      # keep draining so writers never block
                        continue
                if self.stop.is_set():
                    break
        finally:
            self.out.close()
            os.close(self.fd)


class KeepAlive(threading.Thread):
    """Hold the Sprite active while the run is in progress (Sprites Tasks API heartbeat).

    A detached process is frozen when the Sprite pauses after ~30 s without
    activity, and dies on a cold pause; a task hold prevents that. No-op
    outside a Sprite (no /.sprite/api.sock).
    """
    SOCK = "/.sprite/api.sock"

    def __init__(self, name: str):
        super().__init__(daemon=True)
        self.name, self.stop = name, threading.Event()
        self.enabled = os.path.exists(self.SOCK)

    def _call(self, method, path, body=None):
        import http.client
        import socket

        class C(http.client.HTTPConnection):
            def connect(s):
                s.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.sock.settimeout(10)
                s.sock.connect(self.SOCK)
        try:
            c = C("sprite")
            c.request(method, path, body=json.dumps(body) if body is not None else None,
                      headers={"Content-Type": "application/json"})
            c.getresponse().read()
            c.close()
        except OSError:
            pass

    def run(self):
        if not self.enabled:
            return
        while not self.stop.is_set():
            self._call("PUT", f"/v1/tasks/{self.name}", {"expire": "5m"})
            self.stop.wait(45)
        self._call("DELETE", f"/v1/tasks/{self.name}")


def _proc_field(pid, name):
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                if line.startswith(name + ":"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def _proc_status(pid) -> dict:
    out = {}
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                k, _, v = line.partition(":")
                out[k] = v.strip()
    except OSError:
        pass
    return out


def _uid_procs(uid: int) -> list[tuple[int, dict]]:
    """Live processes whose real, effective, saved or fs uid is ``uid`` (read from status, not
    from the /proc directory owner, which turns to root for a non-dumpable process)."""
    out = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        st = _proc_status(d)
        try:
            uids = {int(x) for x in st.get("Uid", "").split()}
        except ValueError:
            continue
        if uid in uids and st.get("State", "")[:1] not in ("Z", "X", ""):
            out.append((int(d), st))
    return out


def _untraced(uid: int) -> list[int]:
    """Candidate-uid processes no tracer is attached to (e.g. made with clone(CLONE_UNTRACED))."""
    return [pid for pid, st in _uid_procs(uid) if st.get("TracerPid", "0") == "0"]


def _cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return fh.read(300).replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _children(pid: int) -> list[int]:
    out = []
    for d in os.listdir("/proc"):
        if d.isdigit() and _proc_field(d, "PPid") == pid:
            out.append(int(d))
    return out


def _tracees(tracer: int) -> list[int]:
    return [int(d) for d in os.listdir("/proc") if d.isdigit() and _proc_field(d, "TracerPid") == tracer]


def _wait(p: subprocess.Popen, deadline: float, under_strace: bool, grace: float = 1.0,
          watch_uid: int | None = None, untraced: dict | None = None):
    """Wait for the candidate. Returns (rc, timed_out, leftovers).

    With ``watch_uid`` every poll also looks for processes of that uid that no
    tracer follows (``clone(CLONE_UNTRACED)`` escapes ``strace -f``); they are
    recorded in ``untraced`` (pid -> command line) and killed.

    ``strace -f`` only exits when every tracee has exited, so a candidate that
    leaves a background process behind would hold the run until the timeout.
    Once the candidate's main process (strace's child) is gone, anything still
    traced gets ``grace`` seconds and is then killed; strace then writes their
    exit records and returns the main process's status.
    """
    start, gone_at, leftovers, killed = time.time(), None, 0, False
    while True:
        rc = p.poll()
        if rc is not None:
            return rc, False, leftovers
        if watch_uid is not None and untraced is not None:
            for pid in _untraced(watch_uid):
                if pid not in untraced:
                    untraced[pid] = _cmdline(pid)
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        now = time.time()
        if now >= deadline:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for t in _tracees(p.pid) if under_strace else []:
                try:
                    os.kill(t, signal.SIGKILL)
                except OSError:
                    pass
            p.wait()
            return 124, True, leftovers
        if under_strace and now - start >= grace:
            # strace's only child is the candidate's main process; orphans are reparented elsewhere
            if _children(p.pid):
                gone_at = None
            elif gone_at is None:
                gone_at = now
            elif now - gone_at >= grace and not killed:
                for t in _tracees(p.pid):
                    try:
                        os.kill(t, signal.SIGKILL)
                        leftovers += 1
                    except OSError:
                        pass
                killed = True
        time.sleep(0.05)


def _kill_user(uid: int) -> int:
    n = 0
    for _ in range(20):
        found = 0
        for pid, _ in _uid_procs(uid):
            try:
                os.kill(pid, signal.SIGKILL)
                found += 1
            except OSError:
                pass
        n += found
        if not found:
            break
        time.sleep(0.1)
    return n


def scan_aliases(dirs: list[str]) -> dict:
    """Every symlink (with its real target) and every multiply-linked file under ``dirs``."""
    links, groups, seen = [], {}, 0
    for top in dirs:
        if not os.path.isdir(top):
            continue
        for d, subdirs, files in os.walk(top, followlinks=False):
            for n in subdirs + files:
                p = os.path.join(d, n)
                seen += 1
                if seen > 200000:
                    return {"symlinks": links, "hardlinks": list(groups.values()), "truncated": True}
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode) and len(links) < MAX_ALIASES:
                    try:
                        links.append({"path": p, "target": os.readlink(p), "real": os.path.realpath(p)})
                    except OSError:
                        pass
                elif stat.S_ISREG(st.st_mode) and st.st_nlink > 1 and len(groups) < MAX_ALIASES:
                    g = groups.setdefault(f"{st.st_dev}:{st.st_ino}", {"nlink": st.st_nlink, "paths": []})
                    g["paths"].append(p)
    return {"symlinks": links, "hardlinks": list(groups.values()), "truncated": False}


def _copy_output(src: str, dst: str) -> str | None:
    """Copy a regular file without following symlinks. Returns a problem or None."""
    try:
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as e:
        return f"{os.path.basename(src)}: not copied ({e.strerror})"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return f"{os.path.basename(src)}: not a regular file"
        if st.st_size > MAX_OUTPUT_FILE:
            return f"{os.path.basename(src)}: larger than {MAX_OUTPUT_FILE >> 20} MB"
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with os.fdopen(os.dup(fd), "rb") as fi, open(dst, "wb") as fo:
            shutil.copyfileobj(fi, fo)
    finally:
        os.close(fd)
    return None


def _cap_log(path: str):
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size > MAX_LOG:
        with open(path, "rb") as fh:
            fh.seek(size - MAX_LOG)
            tail = fh.read()
        with open(path, "wb") as fh:
            fh.write(f"[cleanroom] output truncated: kept the last {MAX_LOG >> 20} MB of {size} bytes\n".encode())
            fh.write(tail)


def _egress_probe(env: dict, netns: list[str], ids: tuple[int, int] | None) -> dict:
    """Probe egress the way the candidate will meet it: its uid (dropped inside the probe, after
    the network namespace exists), its network setup."""
    py = shutil.which("python3", path=env.get("PATH")) or sys.executable
    code = (f"import os\nos.setgroups([])\nos.setgid({ids[1]})\nos.setuid({ids[0]})\n" if ids else "") + EGRESS_PROBE
    try:
        r = subprocess.run(netns + [py, "-c", code], env={"PATH": env.get("PATH", "/usr/bin:/bin")},
                           cwd="/", capture_output=True, timeout=30)
        return json.loads(r.stdout.decode().strip().splitlines()[-1])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError) as e:
        return {"error": type(e).__name__}


def egress_blocked(probe: dict | None) -> bool:
    """True only when every probe was refused or blocked."""
    if not probe or "error" in probe:
        return False
    return all(v.startswith(("refused", "blocked")) for v in probe.values())


def run(spec: dict) -> dict:
    token = spec["token"]
    keep = KeepAlive(f"cleanroom-run-{token}")
    keep.start()
    try:
        return _run(spec, token)
    finally:
        keep.stop.set()
        keep.join(15)


def _run(spec: dict, token: str) -> dict:
    work, tdir, bundle = spec["work"], spec["trace"], spec["bundle"]
    user = spec.get("user") or None
    root = os.geteuid() == 0
    if user and not root:
        raise SystemExit("runner: a separate candidate uid needs root")
    pw = pwd.getpwnam(user) if user else None
    os.umask(0o077)
    if os.path.lexists(tdir):
        shutil.rmtree(tdir)
    os.makedirs(os.path.join(tdir, "outputs"), mode=0o700)
    meta = {"token": token, "candidate_uid": "separate" if user else "same", "user": user,
            "runner_uid": os.geteuid(), "trace_paths": [tdir], "notes": []}

    outs = [_safe_rel(o) for o in spec.get("outputs", [])]
    hidden = []
    for rel in outs:
        _rm_nofollow(os.path.join(work, rel))   # a stale file never counts as this run's output
    for rel in spec.get("hide", []):
        if _rm_nofollow(os.path.join(work, _safe_rel(rel))):
            hidden.append(rel)
    meta["hidden"] = hidden
    home = spec.get("home")
    if user:
        if home:
            os.makedirs(home, exist_ok=True)
            _chown_tree(home, pw.pw_uid, pw.pw_gid)
        _chown_tree(work, pw.pw_uid, pw.pw_gid)

    collector = None
    if user:
        adir = spec.get("audit_dir") or os.path.join(os.path.dirname(tdir), f"audit-{token}")
        if os.path.lexists(adir):
            shutil.rmtree(adir)
        os.makedirs(adir, mode=0o711)
        os.chmod(adir, 0o711)
        fifo = os.path.join(adir, "audit.fifo")
        os.mkfifo(fifo, 0o622)
        os.chmod(fifo, 0o622)   # candidate may append, cannot read back, truncate or delete
        collector = Collector(fifo, os.path.join(tdir, "audit.jsonl"))
        collector.start()
        audit_path = fifo
        meta["trace_paths"].append(adir)
    else:
        audit_path = os.path.join(tdir, "audit.jsonl")
    meta["audit_log"] = audit_path

    env = {str(k): str(v) for k, v in (spec.get("env") or {}).items()}
    env["CLEANROOM_AUDIT_LOG"] = audit_path
    if user and home:
        env["HOME"] = home
    cmd = list(spec["cmd"])
    strace = shutil.which("strace") if spec.get("strace", True) else None
    # Without CAP_SYS_PTRACE (a Sprite's root lacks it) strace cannot follow a child that switched
    # uid. Inside a user namespace that maps every uid to itself, its root has CAP_SYS_PTRACE over
    # processes in that namespace, while the candidate stays an ordinary, different uid that cannot
    # signal or trace strace.
    userns = bool(user and spec.get("ptrace_userns"))
    use_strace = bool(strace) and _strace_ok(strace, user, userns)
    if strace and not use_strace:
        meta["notes"].append("strace was not usable for this run (ptrace refused); audit hook only")

    # resource limits for the candidate itself (applied after strace switched to its uid)
    limits = []
    if spec.get("limits", True) and shutil.which("prlimit"):
        limits = ["prlimit", f"--fsize={FSIZE_LIMIT}", f"--nofile={NOFILE_LIMIT}"]
        if user:
            limits.append(f"--nproc={NPROC_LIMIT}")   # counts every process of the uid: only for a separate uid
        limits.append("--")
    meta["limits"] = " ".join(limits[1:-1]) if limits else "none (prlimit not available)"

    # seccomp: refuse clone(CLONE_UNTRACED), which would start a process strace does not follow
    guard: list[str] = []
    wrapper = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seccomp_exec.py")
    cand_py = shutil.which("python3", path=env.get("PATH")) or shutil.which("python3")
    if spec.get("seccomp", True) and os.path.isfile(wrapper) and cand_py:
        if user:   # a root-owned copy the candidate can execute but not change
            wcopy = os.path.join(adir, "seccomp_exec.py")
            shutil.copyfile(wrapper, wcopy)
            os.chmod(wcopy, 0o644)
            wrapper = wcopy
        guard = [cand_py, wrapper, "--"]
        meta["seccomp"] = "on"
    else:
        meta["seccomp"] = "off"
    limits = guard + limits

    def demote():
        os.setgroups([])
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)

    # paths the candidate must not see at all (on a Sprite: /.sprite, whose API socket can start
    # services and restore checkpoints); hidden in a private mount namespace
    mask = [m for m in spec.get("mask_paths", []) if os.path.lexists(m)]
    ns: list[str] = []
    if userns:
        ns = USERNS + (["--mount"] if mask else [])
    elif mask and root:
        ns = ["unshare", "--mount"]
    if mask:
        if ns:
            mark = os.path.join(tdir, "mask.ok")
            ns = ns + ["sh", "-c", MASK_SH, "cr-mask", mark, *mask, "--"]
            probe_mark = os.path.join(tdir, "mask.probe")
            try:
                subprocess.run(ns[:-(len(mask) + 2)] + [probe_mark, *mask, "--", "true"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            except (OSError, subprocess.SubprocessError):
                pass
            if not os.path.exists(probe_mark):
                meta["notes"].append("could not hide " + ", ".join(mask) + " from the candidate (mount refused)")
                ns = USERNS if userns else []
                mask_state = "failed"
            else:
                mask_state = "requested"
        else:
            meta["notes"].append("could not hide " + ", ".join(mask) + ": needs root")
            mask_state = "failed"
        meta["mask_paths"] = mask
    else:
        mask_state = "none"

    if use_strace:
        pre = [strace, *spec.get("strace_args", []), "-o", os.path.join(tdir, "strace")]
        if user:
            pre += ["-u", user]
        cmd = ns + pre + ["--"] + limits + cmd
        meta["ptrace_userns"] = userns
        meta["tracer"] = "strace+audit"
        preexec = None
    else:
        meta["tracer"] = "audit"
        cmd = ns + limits + cmd if not user else limits + cmd
        preexec = demote if user else None
    netns = []
    if spec.get("netns") == "unshare":
        netns = ["unshare", "-n" if root else "-rn"]
        cmd = netns + cmd

    if spec.get("egress_probe"):
        meta["egress_probe"] = _egress_probe(env, netns, (pw.pw_uid, pw.pw_gid) if user else None)

    so = open(os.path.join(tdir, "stdout.txt"), "wb")
    se = open(os.path.join(tdir, "stderr.txt"), "wb")
    timeout = int(spec.get("timeout", 900))
    t0 = time.time()
    timed_out = False
    untraced: dict = {}
    if user:
        _kill_user(pw.pw_uid)      # nothing of the candidate uid may predate the run
    try:
        p = subprocess.Popen(cmd, cwd=work, env=env, stdout=so, stderr=se, stdin=subprocess.DEVNULL,
                             start_new_session=True, preexec_fn=preexec)
        rc, timed_out, leftovers = _wait(p, t0 + timeout, use_strace,
                                         watch_uid=pw.pw_uid if (user and use_strace) else None,
                                         untraced=untraced)
        meta["leftover_tracees"] = leftovers
    except OSError as e:
        rc = 127
        se.write(f"[cleanroom] could not start: {e}\n".encode())
    ms = int((time.time() - t0) * 1000)
    so.close()
    se.close()
    meta.update(rc=rc, ms=ms, timed_out=timed_out)
    if use_strace:
        meta["strace_exit"] = rc
        meta["strace_signalled"] = rc < 0
    # nothing the candidate started survives into the bundle step
    if user:
        meta["killed_leftovers"] = _kill_user(pw.pw_uid)
    else:
        try:
            os.killpg(p.pid, signal.SIGKILL)
            meta["killed_leftovers"] = "process group"
        except (ProcessLookupError, UnboundLocalError, PermissionError):
            meta["killed_leftovers"] = 0
    meta["untraced_procs"] = [f"pid {k}: {v}" for k, v in sorted(untraced.items())][:20]
    if mask_state == "requested":
        mask_state = "hidden" if os.path.exists(os.path.join(tdir, "mask.ok")) else "failed"
    meta["mask"] = mask_state
    if collector:
        time.sleep(0.3)
        collector.stop.set()
        collector.join(10)
        meta["audit_truncated"] = collector.truncated
    for n in ("stdout.txt", "stderr.txt"):
        _cap_log(os.path.join(tdir, n))

    if spec.get("dns_probe"):
        try:
            r = subprocess.run(["getent", "hosts", "example.com"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=15)
            meta["dns_probe"] = "resolves" if r.returncode == 0 else "refused"   # taken after the run, as root
        except (OSError, subprocess.SubprocessError):
            meta["dns_probe"] = "unknown"
    problems = []
    for rel in outs:
        prob = _copy_output(os.path.join(work, rel), os.path.join(tdir, "outputs", rel))
        if prob:
            problems.append(prob)
    meta["output_problems"] = problems
    scan_dirs = [d for d in spec.get("scan_dirs", [work]) if d]
    with open(os.path.join(tdir, "aliases.json"), "w") as fh:
        json.dump(scan_aliases(scan_dirs), fh)
    with open(os.path.join(tdir, "meta.json"), "w") as fh:
        json.dump(meta, fh, indent=1)

    os.makedirs(os.path.dirname(bundle), exist_ok=True)
    tmp = bundle + ".part"
    with tarfile.open(tmp, "w:gz") as tf:
        for d, _, files in os.walk(tdir):
            for n in sorted(files):
                full = os.path.join(d, n)
                if os.path.isfile(full) and not os.path.islink(full):
                    tf.add(full, arcname=os.path.join("cr-trace", os.path.relpath(full, tdir)), recursive=False)
    os.replace(tmp, bundle)
    owner = spec.get("bundle_owner")
    if root and owner:
        o = pwd.getpwnam(owner)
        os.chown(bundle, o.pw_uid, o.pw_gid)
    if spec.get("cleanup", True):
        shutil.rmtree(tdir, ignore_errors=True)
        if user:
            shutil.rmtree(os.path.dirname(audit_path), ignore_errors=True)
    done = spec.get("done")
    if done:
        with open(done + ".part", "w") as fh:
            fh.write(token + "\n")
        if root and owner:
            o = pwd.getpwnam(owner)
            os.chown(done + ".part", o.pw_uid, o.pw_gid)
        os.replace(done + ".part", done)
    return meta


if __name__ == "__main__":
    with open(sys.argv[1]) as fh:
        _spec = json.load(fh)
    run(_spec)
