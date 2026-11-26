"""Parse execution traces into normalised events with line-level evidence.

Sources:

* strace output written with ``-ff -y -xx -s 512`` (one file per process,
  strings hex-escaped so odd bytes never break parsing, and ``-y`` so the
  kernel's own view of every file descriptor's path is recorded:
  ``openat(AT_FDCWD</cwd>, "rel", ...) = 3</resolved/real/path>``),
* the JSONL log written by Clean Room's Python audit hook,
* ``meta.json`` (what the runner did: tracer, candidate uid, strace exit) and
  ``aliases.json`` (post-run scan for symlinks and hard links), both written
  by the runner, outside the candidate's reach when uids are separated.

A successful open is matched on the resolved path (symlinks and ``..``
already resolved by the kernel). A failed open is joined to the directory
shown for its dirfd, or to the last known cwd. Paths that still cannot be
placed are marked ``resolved=False`` and are never treated as safe.

``Trace.complete`` / ``Trace.parse_errors`` let the checks fail closed when a
trace is missing, cut short or corrupt.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

# "?" = ignore a syscall this architecture does not have (aarch64 has no open/link/rename/...)
STRACE_SYSCALLS = ",".join([
    "openat", "?open", "?creat", "?openat2",
    "connect", "sendto", "sendmsg", "?sendmmsg",
    "execve", "?execveat", "chdir", "fchdir",
    "?symlink", "symlinkat", "?link", "linkat", "?rename", "renameat", "?renameat2",
    "?unlink", "unlinkat", "truncate", "ftruncate", "?io_uring_setup",
])
# -q (not -qq) keeps the "+++ exited with N +++" lines used to check the trace is complete
STRACE_ARGS = ["-f", "-ff", "-q", "-y", "-xx", "-s", "512", "-e", "trace=" + STRACE_SYSCALLS]

_PFX = r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?"
_DECO = r"(?:<((?:\\x[0-9a-fA-F]{2}|[^>])*)>)?"
QSTR = re.compile(r'"((?:\\x[0-9a-fA-F]{2}|\\.|[^"\\])*)"')
RESULT = re.compile(r"\)\s+=\s+(-?\d+|\?)" + _DECO + r"(?:\s+(E[A-Z0-9]+))?")
DIRFD_RE = re.compile(_PFX + r"(?:openat2?|execveat)\((AT_FDCWD|-?\d+)" + _DECO + ",")
CHDIR_RE = re.compile(_PFX + r"(chdir|fchdir)\(")
FDPATH_RE = re.compile(r"^-?\d+<((?:\\x[0-9a-fA-F]{2}|[^>])*)>")
RESUMED_RE = re.compile(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?<\.\.\. [a-z0-9_]+ resumed>(.*)$", re.S)
EXIT_RE = re.compile(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?\+\+\+ (exited with -?\d+|killed by \w+)")
OPEN_RE = re.compile(_PFX + r"(openat2|openat|open|creat)\(")
CONNECT_RE = re.compile(_PFX + r"connect\((\d+)" + _DECO + r",\s*\{sa_family=(AF_\w+)(.*?)\}")
SEND_RE = re.compile(_PFX + r"(sendto|sendmsg|sendmmsg)\(")
EXEC_RE = re.compile(_PFX + r"(execve|execveat)\(")
ALIAS_RE = re.compile(_PFX + r"(symlinkat|symlink|linkat|link|renameat2|renameat|rename)\(")
MODIFY_RE = re.compile(_PFX + r"(unlinkat|unlink|truncate|ftruncate)\(")
URING_RE = re.compile(_PFX + r"io_uring_setup\(")
SOCKADDR_RE = re.compile(r"\{sa_family=(AF_INET6?)(.*?)\}")
PORT_RE = re.compile(r"sin6?_port=htons\((\d+)\)")
ADDR_RE = re.compile(r'inet_addr\("((?:\\x[0-9a-fA-F]{2})+|[^"]+)"\)'
                     r'|inet_pton\(AF_INET6?,\s*"((?:\\x[0-9a-fA-F]{2})+|[^"]+)"')
FLAGS_RE = re.compile(r"\b(O_[A-Z]+(?:\|(?:O_[A-Z0-9_]+|0x[0-9a-fA-F]+|\d+))*)")
ARG_TOKEN = re.compile(r'"((?:\\x[0-9a-fA-F]{2}|\\.|[^"\\])*)"|\b(AT_FDCWD|-?\d+)' + _DECO)


@dataclass
class Event:
    kind: str                 # open | connect | dns | exec | alias | modify | io_uring | unix
    source: str               # strace | audit
    pid: int | None = None
    path: str = ""            # open/exec/alias source/modify: path as resolved
    mode: str = ""            # open: read | write | rw | dir
    host: str = ""            # dns/connect: host name if known
    addr: str = ""            # connect: IP address
    port: int | None = None
    ok: bool = True
    errno: str = ""
    file: str = ""            # evidence: trace file name
    lineno: int = 0           # evidence: line in that file
    line: str = ""            # evidence: decoded trace line
    resolved: bool = True     # False when the path could not be placed in the filesystem
    flags: str = ""           # open: O_* flags
    op: str = ""              # syscall / audit event name
    path2: str = ""           # alias: destination path
    proto: str = ""           # connect: tcp | udp

    def evidence(self) -> str:
        return f"{self.file}:{self.lineno}  {self.line}"


@dataclass
class Trace:
    events: list[Event] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    complete: bool | None = None   # strace: every process file ends with an exit record (None = not checked)
    incomplete_files: int = 0
    parse_errors: int = 0          # audit lines that were not valid JSON
    strace_files: int = 0
    meta: dict = field(default_factory=dict)      # runner facts (meta.json)
    aliases: dict = field(default_factory=dict)   # post-run alias scan (aliases.json)
    tampered: list[str] = field(default_factory=list)          # trace files with NUL holes (cut while written)
    bundle_problems: list[str] = field(default_factory=list)   # unsafe members refused on extraction

    def links(self) -> list[Event]:
        """Successful symlink / hard link / rename calls (path = existing file, path2 = new name)."""
        return [e for e in self.events if e.kind == "alias" and e.ok]

    def files_read(self) -> list[Event]:
        return [e for e in self.events if e.kind == "open" and e.mode in ("read", "rw")]

    def unix_connects(self) -> list[Event]:
        """Connections to Unix sockets by path (e.g. the Sprite's internal API socket)."""
        return [e for e in self.events if e.kind == "unix"]

    def network_attempts(self) -> list[Event]:
        return [e for e in self.events if e.kind in ("connect", "dns")]

    def to_list(self) -> list[dict]:
        return [asdict(e) for e in self.events]


# ---- string decoding ------------------------------------------------------
def decode_qstr(s: str) -> bytes:
    """Decode a strace quoted string body (hex -xx form or C escapes)."""
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x" and i + 3 < len(s) + 1:
                try:
                    out.append(int(s[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            if n in "01234567":
                j = i + 1
                while j < len(s) and j < i + 4 and s[j] in "01234567":
                    j += 1
                out.append(int(s[i + 1:j], 8) & 0xFF)
                i = j
                continue
            out.append({"n": 10, "t": 9, "r": 13, "v": 11, "f": 12, '"': 34, "\\": 92}.get(n, ord(n) & 0xFF))
            i += 2
            continue
        out.extend(c.encode())
        i += 1
    return bytes(out)


def _s(raw: str) -> str:
    return decode_qstr(raw).decode("utf-8", "replace")


def parse_dns_query(b: bytes) -> str | None:
    """Return the query name from a raw DNS query packet, or None."""
    if len(b) < 17:
        return None
    flags = int.from_bytes(b[2:4], "big")
    qd = int.from_bytes(b[4:6], "big")
    if flags & 0x8000 or qd < 1 or qd > 4:
        return None
    labels, i = [], 12
    while i < len(b):
        n = b[i]
        if n == 0:
            break
        if n > 63 or i + 1 + n > len(b):
            return None
        lab = b[i + 1:i + 1 + n]
        if not re.fullmatch(rb"[A-Za-z0-9_-]+", lab):
            return None
        labels.append(lab.decode())
        i += 1 + n
    else:
        return None
    return ".".join(labels) if labels else None


def pretty_line(line: str) -> str:
    """Replace hex-escaped strings with readable text; summarise DNS payloads."""
    def rep(m):
        raw = decode_qstr(m.group(1))
        q = parse_dns_query(raw)
        if q:
            return f'"<DNS query for {q}>"'
        txt = raw.decode("utf-8", "replace")
        if len(txt) > 160:
            txt = txt[:157] + "..."
        return json.dumps(txt)

    def deco(m):
        return "<" + _s(m.group(1)) + ">"
    line = re.sub(r"<((?:\\x[0-9a-fA-F]{2})+)>", deco, line.rstrip("\n"))
    return QSTR.sub(rep, line)


def _is_loopback(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return ip.is_loopback or bool(mapped and mapped.is_loopback) or ip.is_unspecified


def _open_mode(flags: str) -> str:
    if "O_DIRECTORY" in flags:
        return "dir"
    if "O_RDWR" in flags:
        return "rw"
    if "O_WRONLY" in flags or "O_CREAT" in flags:
        return "write"
    return "read"


def _sockaddr(text: str):
    """(family, addr, port) from the first AF_INET/AF_INET6 sockaddr in ``text``."""
    m = SOCKADDR_RE.search(text)
    if not m:
        return None
    rest = m.group(2)
    am = ADDR_RE.search(rest)
    addr = ""
    if am:
        a = am.group(1) or am.group(2) or ""
        addr = _s(a) if "\\x" in a else a
    pm = PORT_RE.search(rest)
    return m.group(1), addr, (int(pm.group(1)) if pm else None)


# ---- strace ---------------------------------------------------------------
def _fdpath(raw: str) -> str:
    return _s(raw)


def _args(line: str) -> list[tuple[str, str]]:
    """Positional args of a syscall line: ('str', value) or ('fd', 'AT_FDCWD'/'N', path-or-'')."""
    body = line.split("(", 1)[1] if "(" in line else ""
    res = RESULT.search(body)
    if res:
        body = body[:res.start()]
    out = []
    for m in ARG_TOKEN.finditer(body):
        if m.group(1) is not None:
            out.append(("str", _s(m.group(1)), ""))
        else:
            out.append(("fd", m.group(2), _fdpath(m.group(3)) if m.group(3) else ""))
    return out


def _place(p: str, dirfd: tuple | None, st: dict) -> tuple[str, bool]:
    """Resolve ``p`` against a dirfd token / the tracked cwd. Returns (path, resolved)."""
    if p.startswith("/"):
        return os.path.normpath(p), True
    if dirfd is not None:
        _, fd, fdp = dirfd
        if fdp.startswith("/"):
            return os.path.normpath(os.path.join(fdp, p)), True
        if fd != "AT_FDCWD":
            return f"/<fd {fd}>/{p}", False
    if st.get("cwd"):
        return os.path.normpath(os.path.join(st["cwd"], p)), True
    if st.get("cwd_changed"):
        return p, False
    return p, True    # relative to the start directory (the run's workdir)


def _note_cwd(line: str, st: dict):
    m = re.search(r"AT_FDCWD<((?:\\x[0-9a-fA-F]{2}|[^>])*)>", line)
    if m:
        p = _fdpath(m.group(1))
        if p.startswith("/"):
            st["cwd"] = p


def parse_strace_file(path: Path, display_name: str | None = None, state: dict | None = None) -> list[Event]:
    events: list[Event] = []
    name = display_name or path.name
    pid = None
    m = re.search(r"\.(\d+)$", path.name)
    if m:
        pid = int(m.group(1))
    st = state if state is not None else {}
    st.setdefault("cwd", None)          # last absolute cwd seen (chdir / AT_FDCWD decoration); None = start cwd
    st.setdefault("cwd_changed", False)
    st.setdefault("exited", False)
    with open(path, errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            if EXIT_RE.match(line):
                st["exited"] = True
                continue
            # a syscall interrupted mid-way is split into "<unfinished ...>" and "<... name resumed>"
            if "<unfinished ...>" in line:
                st["pending"] = line.split("<unfinished ...>", 1)[0].rstrip()
                continue
            rm = RESUMED_RE.match(line)
            if rm:
                head = st.pop("pending", None)
                if head is None:
                    st["orphan_resumed"] = st.get("orphan_resumed", 0) + 1
                    continue
                line = head + rm.group(1)
            ev = parse_strace_line(line, pid, st)
            if ev is None:
                continue
            ev.file, ev.lineno = name, lineno
            events.append(ev)
    return events


def parse_strace_line(line: str, pid: int | None = None, state: dict | None = None) -> Event | None:
    if "<unfinished" in line or line.startswith("+++") or line.startswith("---"):
        return None    # with -ff each process has its own file, so splits are rare
    st = state if state is not None else {"cwd": None, "cwd_changed": False}
    res = RESULT.search(line)
    ret = res.group(1) if res else "?"
    ret_path = _fdpath(res.group(2)) if res and res.group(2) else ""
    err = (res.group(3) or "") if res else ""
    ok = ret != "?" and not ret.startswith("-")
    pretty = pretty_line(line)

    cm = CHDIR_RE.match(line)
    if cm:
        if ok:
            st["cwd_changed"] = True
            if cm.group(1) == "chdir":
                strs = QSTR.findall(line)
                target = _s(strs[0]) if strs else ""
                if target.startswith("/"):
                    st["cwd"] = os.path.normpath(target)
                elif st.get("cwd"):
                    st["cwd"] = os.path.normpath(os.path.join(st["cwd"], target))
                else:
                    st["cwd"] = None
            else:
                fdm = re.search(r"fchdir\((\d+<(?:\\x[0-9a-fA-F]{2}|[^>])*>)", line)
                fp = FDPATH_RE.match(fdm.group(1)) if fdm else None
                st["cwd"] = _fdpath(fp.group(1)) if fp else None
        return None

    om = OPEN_RE.match(line)
    if om:
        _note_cwd(line, st)
        strs = QSTR.findall(line)
        if not strs:
            return None
        p = _s(strs[0])
        resolved = True
        dm = DIRFD_RE.match(line)
        if ok and ret_path.startswith("/"):
            p = ret_path                       # the kernel's resolved path of the opened file
        else:
            tok = ("fd", dm.group(1), _fdpath(dm.group(2)) if dm.group(2) else "") if dm else None
            p, resolved = _place(p, tok, st)
        after = line.split('"', 2)[-1] if line.count('"') >= 2 else line
        fm = FLAGS_RE.search(after)
        flags = fm.group(1) if fm else "O_RDONLY"
        if om.group(1) == "creat":
            flags = "O_CREAT|O_WRONLY|O_TRUNC"
        return Event("open", "strace", pid, path=p, mode=_open_mode(flags), ok=ok, errno=err, line=pretty,
                     resolved=resolved, flags=flags, op=om.group(1))

    m = CONNECT_RE.match(line)
    if m:
        fam, rest = m.group(3), m.group(4)
        if fam == "AF_UNIX":
            pm = re.search(r'sun_path=(@?)"((?:\\x[0-9a-fA-F]{2}|\\.|[^"\\])*)"', rest)
            if not pm:
                return None
            upath = ("@" if pm.group(1) else "") + _s(pm.group(2))
            return Event("unix", "strace", pid, path=upath, ok=ok, errno=err, line=pretty, op="connect")
        if fam not in ("AF_INET", "AF_INET6"):
            return None
        sa = _sockaddr("{sa_family=" + fam + rest + "}")
        addr, port = (sa[1], sa[2]) if sa else ("", None)
        if _is_loopback(addr):
            return None
        # EINPROGRESS is a non-blocking connect that is still under way
        ok2 = ok or err == "EINPROGRESS"
        proto = "udp" if m.group(2) and "UDP" in _fdpath(m.group(2)) else "tcp"
        return Event("connect", "strace", pid, addr=addr, port=port, ok=ok2, errno=err, line=pretty,
                     op="connect", proto=proto)

    sm = SEND_RE.match(line)
    if sm:
        for s in QSTR.findall(line):
            q = parse_dns_query(decode_qstr(s))
            if q:
                return Event("dns", "strace", pid, host=q, port=53, ok=ok, errno=err, line=pretty, op=sm.group(1))
        sa = _sockaddr(line)          # sendto/sendmsg with an explicit destination (UDP and friends)
        if sa and sa[1] and not _is_loopback(sa[1]):
            return Event("connect", "strace", pid, addr=sa[1], port=sa[2], ok=ok, errno=err, line=pretty,
                         op=sm.group(1), proto="udp")
        return None

    em = EXEC_RE.match(line)
    if em:
        _note_cwd(line, st)
        args = _args(line)
        strs = [a for a in args if a[0] == "str"]
        if strs:
            p = strs[0][1]
            if em.group(1) == "execveat" and args and args[0][0] == "fd":
                p, _ = _place(p, args[0], st)
            return Event("exec", "strace", pid, path=p, ok=ok, errno=err, line=pretty, op=em.group(1))
        return None

    am = ALIAS_RE.match(line)
    if am:
        _note_cwd(line, st)
        op = am.group(1)
        args = _args(line)
        try:
            if op == "symlink":
                target, link = args[0][1], args[1][1]
                link_p, r1 = _place(link, None, st)
                src_p, r2 = _place(target, ("fd", "AT_FDCWD", os.path.dirname(link_p) if r1 and link_p.startswith("/")
                                           else ""), st) if not target.startswith("/") else (target, True)
            elif op == "symlinkat":
                target, dfd, link = args[0][1], args[1], args[2][1]
                link_p, r1 = _place(link, dfd, st)
                src_p, r2 = (os.path.normpath(target), True) if target.startswith("/") else (
                    _place(target, ("fd", "AT_FDCWD", os.path.dirname(link_p)), st) if r1 and link_p.startswith("/")
                    else _place(target, None, st))
            elif op in ("link", "rename"):
                src_p, r2 = _place(args[0][1], None, st)
                link_p, r1 = _place(args[1][1], None, st)
            else:  # linkat / renameat / renameat2: olddirfd, old, newdirfd, new
                src_p, r2 = _place(args[1][1], args[0], st)
                link_p, r1 = _place(args[3][1], args[2], st)
        except IndexError:
            return None
        return Event("alias", "strace", pid, path=src_p, path2=link_p, ok=ok, errno=err, line=pretty,
                     resolved=r1 and r2, op=op)

    mm = MODIFY_RE.match(line)
    if mm:
        _note_cwd(line, st)
        op = mm.group(1)
        args = _args(line)
        p, r = "", True
        if op == "ftruncate" and args and args[0][0] == "fd":
            p, r = (args[0][2], True) if args[0][2] else (f"/<fd {args[0][1]}>", False)
        elif op == "unlinkat" and len(args) >= 2:
            p, r = _place(args[1][1], args[0], st)
        elif args and args[0][0] == "str":
            p, r = _place(args[0][1], None, st)
        return Event("modify", "strace", pid, path=p, ok=ok, errno=err, line=pretty, resolved=r, op=op)

    if URING_RE.match(line):
        return Event("io_uring", "strace", pid, ok=ok, errno=err, line=pretty, op="io_uring_setup")
    return None


# ---- audit hook -----------------------------------------------------------
def parse_audit_file(path: Path, display_name: str | None = None, errors: list | None = None) -> list[Event]:
    events: list[Event] = []
    name = display_name or path.name
    with open(path, errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw)
                if not isinstance(rec, dict):
                    raise ValueError
            except ValueError:
                if errors is not None:
                    errors.append(lineno)
                continue
            for ev in _audit_events(rec):
                ev.file, ev.lineno, ev.line = name, lineno, raw.strip()[:600]
                events.append(ev)
    return events


def _audit_events(rec: dict) -> list[Event]:
    kind = rec.get("ev")
    pid = rec.get("pid")
    if kind == "open":
        p = str(rec.get("path") or "")
        if not os.path.isabs(p) and rec.get("cwd"):
            p = os.path.join(str(rec["cwd"]), p)
        mode = str(rec.get("mode") or "r")
        m = "read"
        if any(c in mode for c in "wax"):
            m = "rw" if ("+" in mode or "r" in mode) else "write"
        elif "+" in mode:
            m = "rw"
        flags = rec.get("flags")
        if isinstance(flags, int) and mode in ("r", "None"):
            acc = flags & 3
            m = {0: "read", 1: "write", 2: "rw"}.get(acc, "read")
            if flags & 0o200000:  # O_DIRECTORY
                m = "dir"
        out = [Event("open", "audit", pid, path=os.path.normpath(p) if p else p, mode=m, op="open")]
        real = rec.get("real")
        if isinstance(real, str) and real and os.path.normpath(real) != os.path.normpath(p):
            out.append(Event("open", "audit", pid, path=os.path.normpath(real), mode=m, op="open(real)"))
        return out
    if kind in ("socket.getaddrinfo", "socket.gethostbyname"):
        host = str(rec.get("host") or "")
        if not host or host in ("localhost",) or _is_loopback(host):
            return []
        try:
            ipaddress.ip_address(host)
            return [Event("connect", "audit", pid, addr=host, port=_int(rec.get("port")), op=kind)]
        except ValueError:
            return [Event("dns", "audit", pid, host=host, port=_int(rec.get("port")), op=kind)]
    if kind in ("socket.connect", "socket.sendto"):
        addr = rec.get("addr")
        if isinstance(addr, str) and addr.startswith(("/", "@", "\x00")):
            return [Event("unix", "audit", pid, path=addr.replace("\x00", "@", 1), op=kind)]
        if isinstance(addr, list) and addr:
            a = str(addr[0])
            if a.startswith("/") or a.startswith("@"):
                return [Event("unix", "audit", pid, path=a, op=kind)]
            if _is_loopback(a):
                return []
            port = _int(addr[1] if len(addr) > 1 else None)
            try:
                ipaddress.ip_address(a)
                return [Event("connect", "audit", pid, addr=a, port=port, op=kind)]
            except ValueError:
                return [Event("dns", "audit", pid, host=a, port=port, op=kind)]
        return []
    if kind in ("os.symlink", "os.link", "os.rename"):
        src, dst = str(rec.get("src") or ""), str(rec.get("dst") or "")
        cwd = str(rec.get("cwd") or "")
        if cwd and not os.path.isabs(dst):
            dst = os.path.join(cwd, dst)
        if src and not os.path.isabs(src):
            base = os.path.dirname(dst) if kind == "os.symlink" else cwd
            src = os.path.join(base, src) if base else src
        return [Event("alias", "audit", pid, path=os.path.normpath(src) if src else src,
                      path2=os.path.normpath(dst) if dst else dst, op=kind)]
    if kind in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"):
        argv = rec.get("argv") or [""]
        return [Event("exec", "audit", pid, path=str(argv[0]), op=kind)]
    return []


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---- whole run --------------------------------------------------------------
def _read_json(p: Path, default):
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return default


def load_trace(trace_dir: Path) -> Trace:
    trace_dir = Path(trace_dir)
    t = Trace()
    files = sorted(p for p in trace_dir.glob("strace*") if p.is_file())
    incomplete = 0
    for f in files:
        st: dict = {}
        t.events.extend(parse_strace_file(f, state=st))
        if not st.get("exited"):
            incomplete += 1
        try:
            with open(f, "rb") as fh:
                if b"\x00" in fh.read():   # truncated while strace kept writing at its old offset
                    t.tampered.append(f.name)
        except OSError:
            pass
    if files:
        t.sources.append("strace")
        t.strace_files = len(files)
        t.incomplete_files = incomplete
        t.complete = incomplete == 0
    errs: list = []
    for audit in (trace_dir / "audit.jsonl", trace_dir / "audit" / "audit.jsonl"):
        if audit.exists():
            t.events.extend(parse_audit_file(audit, errors=errs))
            if "audit" not in t.sources:
                t.sources.append("audit")
    t.parse_errors = len(errs)
    t.meta = _read_json(trace_dir / "meta.json", {})
    t.aliases = _read_json(trace_dir / "aliases.json", {})
    t.bundle_problems = _read_json(trace_dir / "bundle_problems.json", [])
    return t


def normalise_path(p: str, workdir: str) -> str:
    """Make a traced path relative to the run's working directory when inside it.

    Resolved strace paths are real paths, so the workdir's real path is tried too.
    """
    full = os.path.normpath(p if os.path.isabs(p) else os.path.join(workdir, p))
    for wd in dict.fromkeys([os.path.normpath(workdir), os.path.realpath(workdir)]):
        if full == wd or full.startswith(wd + os.sep):
            return os.path.relpath(full, wd)
    return full
