"""Parse execution traces into normalised events with line-level evidence.

Two sources are understood:

* strace output written with ``-ff -xx -s 512`` (one file per process, every
  string hex-escaped so odd bytes never break parsing), and
* the JSONL log written by Clean Room's Python audit hook.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

STRACE_SYSCALLS = "openat,open,creat,connect,sendto,sendmsg,sendmmsg,execve"
STRACE_ARGS = ["-f", "-ff", "-qq", "-xx", "-s", "512", "-e", "trace=" + STRACE_SYSCALLS]

QSTR = re.compile(r'"((?:\\x[0-9a-fA-F]{2}|\\.|[^"\\])*)"')
RESULT = re.compile(r"\)\s+=\s+(-?\d+|\?)(?:\s+(E[A-Z0-9]+))?")
OPEN_RE = re.compile(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?(openat2?|open|creat)\(")
CONNECT_RE = re.compile(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?connect\((\d+),\s*\{sa_family=(AF_\w+)(.*?)\}")
SEND_RE = re.compile(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?(sendto|sendmsg|sendmmsg)\(")
EXEC_RE = re.compile(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?execve\(")
PORT_RE = re.compile(r"sin6?_port=htons\((\d+)\)")
ADDR_RE = re.compile(r'(?:inet_addr|inet_pton\(AF_INET6,\s*)\("?((?:\\x[0-9a-fA-F]{2})+|[^")]+)"?\)')


@dataclass
class Event:
    kind: str                 # open | connect | dns | exec
    source: str               # strace | audit
    pid: int | None = None
    path: str = ""            # open/exec: path as seen; normalised later
    mode: str = ""            # open: read | write | dir
    host: str = ""            # dns/connect: host name if known
    addr: str = ""            # connect: IP address
    port: int | None = None
    ok: bool = True
    errno: str = ""
    file: str = ""            # evidence: trace file name
    lineno: int = 0           # evidence: line in that file
    line: str = ""            # evidence: decoded trace line

    def evidence(self) -> str:
        return f"{self.file}:{self.lineno}  {self.line}"


@dataclass
class Trace:
    events: list[Event] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def files_read(self) -> list[Event]:
        return [e for e in self.events if e.kind == "open" and e.mode in ("read", "rw")]

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
                out.append(int(s[i + 2:i + 4], 16))
                i += 4
                continue
            if n in "01234567":
                j = i + 1
                while j < len(s) and j < i + 4 and s[j] in "01234567":
                    j += 1
                out.append(int(s[i + 1:j], 8) & 0xFF)
                i = j
                continue
            out.append({"n": 10, "t": 9, "r": 13, "v": 11, "f": 12, '"': 34, "\\": 92}.get(n, ord(n)))
            i += 2
            continue
        out.extend(c.encode())
        i += 1
    return bytes(out)


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
    return QSTR.sub(rep, line.rstrip("\n"))


def _is_loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _open_mode(flags: str) -> str:
    if "O_DIRECTORY" in flags:
        return "dir"
    if "O_RDWR" in flags:
        return "rw"
    if "O_WRONLY" in flags or "O_CREAT" in flags:
        return "write"
    return "read"


# ---- strace ---------------------------------------------------------------
def parse_strace_file(path: Path, display_name: str | None = None) -> list[Event]:
    events: list[Event] = []
    name = display_name or path.name
    pid = None
    m = re.search(r"\.(\d+)$", path.name)
    if m:
        pid = int(m.group(1))
    with open(path, "r", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            ev = parse_strace_line(line, pid)
            if ev is None:
                continue
            ev.file, ev.lineno = name, lineno
            events.append(ev)
    return events


def parse_strace_line(line: str, pid: int | None = None) -> Event | None:
    if "<unfinished" in line or "resumed>" in line or line.startswith("+++") or line.startswith("---"):
        # with -ff each process has its own file, so splits are rare; skip them
        if "resumed>" not in line:
            return None
    res = RESULT.search(line)
    ret = res.group(1) if res else "?"
    err = (res.group(2) or "") if res else ""
    ok = ret != "?" and not ret.startswith("-")
    pretty = pretty_line(line)

    if OPEN_RE.match(line):
        strs = QSTR.findall(line)
        if not strs:
            return None
        p = decode_qstr(strs[0]).decode("utf-8", "replace")
        dirfd = re.match(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?openat2?\((\d+)", line)
        if dirfd and not p.startswith("/"):
            p = f"/<fd {dirfd.group(1)}>/{p}"  # relative to an open directory, not the cwd
        after = line.split('"', 2)[-1] if line.count('"') >= 2 else line
        flags_m = re.search(r",\s*([A-Z_|0-9]+)", after)
        flags = flags_m.group(1) if flags_m else "O_RDONLY"
        if line.lstrip().split("(", 1)[0].endswith("creat"):
            flags = "O_CREAT|O_WRONLY"
        return Event("open", "strace", pid, path=p, mode=_open_mode(flags), ok=ok, errno=err, line=pretty)

    m = CONNECT_RE.match(line)
    if m:
        fam, rest = m.group(2), m.group(3)
        if fam not in ("AF_INET", "AF_INET6"):
            return None
        port_m = PORT_RE.search(rest)
        addr_m = ADDR_RE.search(rest)
        addr = ""
        if addr_m:
            a = addr_m.group(1)
            addr = decode_qstr(a).decode("utf-8", "replace") if "\\x" in a else a
        if _is_loopback(addr):
            return None
        # EINPROGRESS is a non-blocking connect that is still under way
        ok2 = ok or err == "EINPROGRESS"
        port = int(port_m.group(1)) if port_m else None
        kind = "connect"
        return Event(kind, "strace", pid, addr=addr, port=port, ok=ok2, errno=err, line=pretty)

    if SEND_RE.match(line):
        for s in QSTR.findall(line):
            q = parse_dns_query(decode_qstr(s))
            if q:
                return Event("dns", "strace", pid, host=q, port=53, ok=ok, errno=err, line=pretty)
        return None

    if EXEC_RE.match(line):
        strs = QSTR.findall(line)
        if strs:
            p = decode_qstr(strs[0]).decode("utf-8", "replace")
            return Event("exec", "strace", pid, path=p, ok=ok, errno=err, line=pretty)
    return None


# ---- audit hook -----------------------------------------------------------
def parse_audit_file(path: Path, display_name: str | None = None) -> list[Event]:
    events: list[Event] = []
    name = display_name or path.name
    with open(path, "r", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            ev = _audit_event(rec)
            if ev is None:
                continue
            ev.file, ev.lineno, ev.line = name, lineno, raw.strip()
            events.append(ev)
    return events


def _audit_event(rec: dict) -> Event | None:
    kind = rec.get("ev")
    pid = rec.get("pid")
    if kind == "open":
        p = rec.get("path") or ""
        if not os.path.isabs(p) and rec.get("cwd"):
            p = os.path.join(rec["cwd"], p)
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
        return Event("open", "audit", pid, path=p, mode=m)
    if kind in ("socket.getaddrinfo", "socket.gethostbyname"):
        host = str(rec.get("host") or "")
        if not host or host in ("localhost",) or _is_loopback(host):
            return None
        try:
            ipaddress.ip_address(host)
            return Event("connect", "audit", pid, addr=host, port=_int(rec.get("port")))
        except ValueError:
            return Event("dns", "audit", pid, host=host, port=_int(rec.get("port")))
    if kind == "socket.connect":
        addr = rec.get("addr")
        if isinstance(addr, list) and addr:
            a = str(addr[0])
            if _is_loopback(a) or a.startswith("/"):
                return None
            try:
                ipaddress.ip_address(a)
                return Event("connect", "audit", pid, addr=a, port=_int(addr[1] if len(addr) > 1 else None))
            except ValueError:
                return Event("dns", "audit", pid, host=a, port=_int(addr[1] if len(addr) > 1 else None))
        return None
    if kind in ("subprocess.Popen", "os.system", "os.exec"):
        argv = rec.get("argv") or [""]
        return Event("exec", "audit", pid, path=str(argv[0]))
    return None


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---- whole run --------------------------------------------------------------
def load_trace(trace_dir: Path) -> Trace:
    trace_dir = Path(trace_dir)
    t = Trace()
    for f in sorted(trace_dir.glob("strace*")):
        t.events.extend(parse_strace_file(f))
        if "strace" not in t.sources:
            t.sources.append("strace")
    audit = trace_dir / "audit.jsonl"
    if audit.exists():
        t.events.extend(parse_audit_file(audit))
        t.sources.append("audit")
    return t


def normalise_path(p: str, workdir: str) -> str:
    """Make a traced path relative to the run's working directory when inside it."""
    wd = os.path.normpath(workdir)
    full = os.path.normpath(p if os.path.isabs(p) else os.path.join(wd, p))
    if full == wd or full.startswith(wd + os.sep):
        return os.path.relpath(full, wd)
    return full
