import json

from cleanroom.trace import (decode_qstr, load_trace, normalise_path, parse_dns_query, parse_strace_line)


def hx(s: str) -> str:
    return "".join(f"\\x{b:02x}" for b in s.encode())


def test_decode_hex_and_c_escapes():
    assert decode_qstr(hx("data/test_labels.csv")).decode() == "data/test_labels.csv"
    assert decode_qstr(r"a\nb\\c\101") == b"a\nb\\cA"


def test_open_read_and_write_modes():
    ev = parse_strace_line(f'openat(AT_FDCWD, "{hx("data/test_labels.csv")}", O_RDONLY|O_CLOEXEC) = 3')
    assert ev.kind == "open" and ev.path == "data/test_labels.csv" and ev.mode == "read" and ev.ok
    ev = parse_strace_line(f'openat(AT_FDCWD, "{hx("submission.csv")}", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 4')
    assert ev.mode == "write"
    ev = parse_strace_line(f'openat(AT_FDCWD, "{hx("missing.csv")}", O_RDONLY) = -1 ENOENT (No such file or directory)')
    assert not ev.ok and ev.errno == "ENOENT"
    ev = parse_strace_line(f'openat(AT_FDCWD, "{hx("data")}", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3')
    assert ev.mode == "dir"


def test_open_relative_to_dirfd_is_not_treated_as_cwd():
    ev = parse_strace_line(f'openat(3, "{hx("cpu0/online")}", O_RDONLY) = 4')
    assert ev.path.startswith("/<fd 3>/")


def test_connect_inet_skip_loopback_and_record_unix():
    line = (f'connect(3, {{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("{hx("140.82.112.3")}")}}, 16)'
            " = -1 ENETUNREACH (Network is unreachable)")
    ev = parse_strace_line(line)
    assert ev.kind == "connect" and ev.addr == "140.82.112.3" and ev.port == 443 and not ev.ok
    assert "140.82.112.3" in ev.line  # pretty line is decoded for the report
    lo = f'connect(3, {{sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("{hx("127.0.0.1")}")}}, 16) = 0'
    assert parse_strace_line(lo) is None
    ux = f'connect(4, {{sa_family=AF_UNIX, sun_path="{hx("/var/run/nscd/socket")}"}}, 110) = -1 ENOENT'
    uev = parse_strace_line(ux)   # Unix sockets are recorded (not network): the Sprite API socket is one
    assert uev.kind == "unix" and uev.path == "/var/run/nscd/socket" and not uev.ok
    api = f'connect(4<socket:[9]>, {{sa_family=AF_UNIX, sun_path="{hx("/.sprite/api.sock")}"}}, 110) = 0'
    aev = parse_strace_line(api)
    assert aev.kind == "unix" and aev.path == "/.sprite/api.sock" and aev.ok
    inprog = line.replace("-1 ENETUNREACH (Network is unreachable)", "-1 EINPROGRESS (Operation now in progress)")
    assert parse_strace_line(inprog).ok


def _dns_packet(name: str) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q + b"\x00\x01\x00\x01"


def test_dns_query_from_sendmmsg():
    pkt = _dns_packet("raw.githubusercontent.com")
    assert parse_dns_query(pkt) == "raw.githubusercontent.com"
    assert parse_dns_query(b"\x00" * 20) is None
    body = "".join(f"\\x{b:02x}" for b in pkt)
    line = (f'sendmmsg(4, [{{msg_hdr={{msg_name=NULL, msg_namelen=0, msg_iov=[{{iov_base="{body}", '
            f'iov_len={len(pkt)}}}], msg_iovlen=1, msg_controllen=0, msg_flags=0}}, msg_len={len(pkt)}}}], 2, MSG_NOSIGNAL) = 2')
    ev = parse_strace_line(line)
    assert ev.kind == "dns" and ev.host == "raw.githubusercontent.com"
    assert "<DNS query for raw.githubusercontent.com>" in ev.line


def test_load_trace_merges_strace_and_audit(tmp_path):
    (tmp_path / "strace.101").write_text(
        f'openat(AT_FDCWD, "{hx("data/train.csv")}", O_RDONLY|O_CLOEXEC) = 3\n'
        f'execve("{hx("/usr/bin/python3")}", ["python3"], 0x7ff /* 5 vars */) = 0\n'
        "+++ exited with 0 +++\n")
    recs = [{"ev": "open", "pid": 101, "path": "data/test_labels.csv", "mode": "r", "flags": 524288,
             "cwd": "/w"},
            {"ev": "socket.getaddrinfo", "pid": 101, "host": "example.org", "port": 443},
            {"ev": "socket.getaddrinfo", "pid": 101, "host": "localhost", "port": 8080}]
    (tmp_path / "audit.jsonl").write_text("\n".join(json.dumps(r) for r in recs) + "\nnot json\n")
    t = load_trace(tmp_path)
    assert t.sources == ["strace", "audit"]
    paths = [normalise_path(e.path, "/w") for e in t.files_read()]
    assert "data/train.csv" in paths and "data/test_labels.csv" in paths
    hosts = [e.host for e in t.network_attempts()]
    assert hosts == ["example.org"]
    ev = [e for e in t.events if e.kind == "open"][0]
    assert ev.evidence().startswith("strace.101:1  openat(")


def test_normalise_path():
    assert normalise_path("data/x.csv", "/w") == "data/x.csv"
    assert normalise_path("/w/data/x.csv", "/w") == "data/x.csv"
    assert normalise_path("/etc/hosts", "/w") == "/etc/hosts"
