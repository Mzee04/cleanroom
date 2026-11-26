"""Clean Room audit hook (fallback / enrichment tracer).

Loaded automatically by Python when this directory is first on PYTHONPATH.
Records file opens (with the resolved real path), symlink/link/rename,
socket connects and sends, DNS lookups and subprocess launches to the file
or FIFO named by CLEANROOM_AUDIT_LOG.

It complements strace: strace sees every process, the audit hook sees host
names before DNS resolution. The hook runs *inside* the candidate's own
process, so a determined program can evade it (ctypes, ``env={}`` for a
child process, or by editing the log). On the Sprite worker the log is a
FIFO drained by a root-owned collector, so records already written cannot
be removed; findings from the hook alone are still capped at WARN.
"""
import os
import sys

_log = os.environ.get("CLEANROOM_AUDIT_LOG")
if _log:
    import json as _json

    _fd: int | None
    try:
        _fd = os.open(_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    except OSError:
        _fd = None
    _busy = [False]
    _EVENTS = ("open", "socket.connect", "socket.sendto", "socket.getaddrinfo", "socket.gethostbyname",
               "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.symlink", "os.link",
               "os.rename")

    def _emit(rec):
        if _fd is None:
            return
        try:
            data = (_json.dumps(rec, default=str)[:3900] + "\n").encode()  # < PIPE_BUF: atomic on a FIFO
            os.write(_fd, data)
        except Exception:
            pass

    def _p(x):
        if isinstance(x, bytes):
            return x.decode("utf-8", "replace")
        if isinstance(x, int) or x is None:
            return x
        try:
            return os.fspath(x)
        except TypeError:
            return str(x)

    def _hook(event, args):
        if _busy[0] or event not in _EVENTS:
            return
        _busy[0] = True
        try:
            rec = {"ev": event, "pid": os.getpid()}
            if event == "open":
                path, mode, flags = (list(args) + [None, None, None])[:3]
                if isinstance(path, int):
                    return
                path = _p(path)
                rec.update(path=path, mode=mode, flags=flags, cwd=os.getcwd())
                try:
                    rec["real"] = os.path.realpath(path)
                except Exception:
                    pass
            elif event in ("socket.connect", "socket.sendto"):
                addr = args[1]
                rec.update(addr=list(addr) if isinstance(addr, tuple) else _p(addr))
            elif event in ("socket.getaddrinfo", "socket.gethostbyname"):
                rec.update(host=_p(args[0]), port=args[1] if len(args) > 1 else None)
            elif event in ("os.symlink", "os.link", "os.rename"):
                rec.update(src=_p(args[0]), dst=_p(args[1]), cwd=os.getcwd())
            else:
                rec.update(argv=[str(a) for a in args][:4])
            _emit(rec)
        except Exception:
            pass
        finally:
            _busy[0] = False

    sys.addaudithook(_hook)
