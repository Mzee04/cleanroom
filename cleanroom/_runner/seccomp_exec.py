#!/usr/bin/env python3
"""Install a small seccomp filter, then exec the candidate command.

Usage: seccomp_exec.py -- cmd [args...]

The filter exists for one reason: ``clone(CLONE_UNTRACED)`` starts a process
that ``strace -f`` does not follow, so anything it does is missing from the
trace. The filter refuses that flag, refuses ``clone3`` (its flags live in
memory a filter cannot read; glibc falls back to ``clone``) and refuses every
system call made through another ABI (32-bit ``int 0x80``, x32), where the
same call has other numbers. Everything else is allowed.

Fails closed: if the filter cannot be installed the command is not run.
Stdlib only, runs as the candidate's uid (no privileges needed).
"""
import ctypes
import os
import platform
import struct
import sys

CLONE_UNTRACED = 0x00800000
# (AUDIT_ARCH, clone nr, clone3 nr)
ARCHES = {"x86_64": (0xC000003E, 56, 435), "aarch64": (0xC00000B7, 220, 435)}
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
EPERM, ENOSYS = 1, 38
PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, SECCOMP_MODE_FILTER = 38, 22, 2
# struct seccomp_data: int nr; u32 arch; u64 ip; u64 args[6]
OFF_NR, OFF_ARCH, OFF_ARG0 = 0, 4, 16
LD_W_ABS, JEQ_K, JGE_K, JSET_K, RET_K = 0x20, 0x15, 0x35, 0x45, 0x06


def program(machine: str) -> bytes:
    arch, nr_clone, nr_clone3 = ARCHES[machine]
    ins = [
        (LD_W_ABS, 0, 0, OFF_ARCH),
        (JEQ_K, 1, 0, arch),                             # native ABI: go on
        (RET_K, 0, 0, SECCOMP_RET_ERRNO | EPERM),        # other ABIs: refused
        (LD_W_ABS, 0, 0, OFF_NR),
        (JGE_K, 0, 1, 0x40000000),                       # x32 numbers
        (RET_K, 0, 0, SECCOMP_RET_ERRNO | EPERM),
        (JEQ_K, 0, 1, nr_clone3),
        (RET_K, 0, 0, SECCOMP_RET_ERRNO | ENOSYS),
        (JEQ_K, 0, 3, nr_clone),
        (LD_W_ABS, 0, 0, OFF_ARG0),                      # low 32 bits of the flags
        (JSET_K, 0, 1, CLONE_UNTRACED),
        (RET_K, 0, 0, SECCOMP_RET_ERRNO | EPERM),
        (RET_K, 0, 0, SECCOMP_RET_ALLOW),
    ]
    return b"".join(struct.pack("HBBI", *i) for i in ins)


def install() -> None:
    machine = platform.machine()
    if machine not in ARCHES:
        raise OSError(f"no seccomp filter for {machine}")
    code = program(machine)
    n = len(code) // 8
    buf = ctypes.create_string_buffer(code, len(code))

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    prog = SockFprog(n, ctypes.cast(buf, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, None, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP")


def main(argv: list[str]) -> None:
    if not argv or argv[0] != "--" or len(argv) < 2:
        sys.stderr.write("usage: seccomp_exec.py -- cmd [args...]\n")
        raise SystemExit(2)
    try:
        install()
    except OSError as e:
        sys.stderr.write(f"[cleanroom] seccomp filter not installed ({e}); refusing to run untraceable code\n")
        raise SystemExit(96)
    os.execvp(argv[1], argv[1:])


if __name__ == "__main__":
    main(sys.argv[1:])
