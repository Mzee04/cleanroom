"""Clean Room audit hook (fallback / enrichment tracer).

Loaded automatically by Python when this directory is first on PYTHONPATH.
Records file opens, socket connects, DNS lookups and subprocess launches to
the JSONL file named by CLEANROOM_AUDIT_LOG. It complements strace: strace
sees every process, the audit hook sees host names before DNS resolution.
A determined program can evade an in-process hook (for example via ctypes),
so findings from it are evidence, not proof of absence.
"""
import os
import sys

_log = os.environ.get("CLEANROOM_AUDIT_LOG")
if _log:
    import json as _json

    _fd = os.open(_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    _busy = [False]
    _pid = os.getpid()

    def _emit(rec):
        try:
            os.write(_fd, (_json.dumps(rec, default=str) + "\n").encode())
        except Exception:
            pass

    def _hook(event, args):
        if _busy[0]:
            return
        if event not in ("open", "socket.connect", "socket.getaddrinfo",
                         "socket.gethostbyname", "subprocess.Popen", "os.system", "os.exec"):
            return
        _busy[0] = True
        try:
            rec = {"ev": event, "pid": os.getpid()}
            if event == "open":
                path, mode, flags = (list(args) + [None, None, None])[:3]
                if isinstance(path, int):
                    return
                if isinstance(path, bytes):
                    path = path.decode("utf-8", "replace")
                rec.update(path=os.fspath(path), mode=mode, flags=flags,
                           cwd=os.getcwd())
            elif event == "socket.connect":
                addr = args[1]
                rec.update(addr=list(addr) if isinstance(addr, tuple) else str(addr))
            elif event in ("socket.getaddrinfo", "socket.gethostbyname"):
                host = args[0]
                if isinstance(host, bytes):
                    host = host.decode("utf-8", "replace")
                rec.update(host=host, port=args[1] if len(args) > 1 else None)
            else:
                rec.update(argv=[str(a) for a in args][:4])
            _emit(rec)
        except Exception:
            pass
        finally:
            _busy[0] = False

    sys.addaudithook(_hook)
