"""Turn a trace + policy into findings, each citing its rule and evidence.

Severity order: FAIL > INCONCLUSIVE > WARN > PASS > INFO. A run whose trace
cannot be trusted (missing, empty, corrupt, cut short, tampered with) is
INCONCLUSIVE and never PASS; a run traced only by the in-process audit hook,
or traced as the same uid as the candidate, is capped at WARN.
"""
from __future__ import annotations

import os
from collections import OrderedDict
from dataclasses import asdict, dataclass, field

from .policy import Policy, Rule
from .trace import Trace, normalise_path

FAIL, INCONCLUSIVE, WARN, PASS, INFO = "FAIL", "INCONCLUSIVE", "WARN", "PASS", "INFO"
SEVERITY_ORDER = [FAIL, INCONCLUSIVE, WARN, PASS, INFO]
DATA_EXT = (".csv", ".tsv", ".parquet", ".json", ".jsonl", ".txt", ".npy", ".npz", ".pkl", ".pickle",
            ".feather", ".zip", ".gz", ".h5", ".hdf5", ".xlsx", ".xls", ".arrow", ".joblib", ".pt", ".bin")
IGNORE_PREFIXES = (".cleanroom/", "__pycache__/")
MAX_EVIDENCE = 4


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str = ""
    clause_id: str = ""
    quote: str = ""
    evidence: list[str] = field(default_factory=list)

    @classmethod
    def with_rule(cls, severity, code, title, detail, rule: Rule | None, evidence=()):
        return cls(severity, code, title, detail, rule.clause_id if rule else "",
                   rule.quote if rule else "", list(evidence)[:MAX_EVIDENCE])

    def to_dict(self):
        return asdict(self)


def _group(events, key):
    g: "OrderedDict[str, list]" = OrderedDict()
    for e in events:
        g.setdefault(key(e), []).append(e)
    return g


# ---- aliases ----------------------------------------------------------------
def _alias_map(trace: Trace, workdir: str) -> dict[str, str]:
    """new name -> existing file, from traced symlink/link/rename calls and the post-run scan."""
    m: dict[str, str] = {}
    for e in trace.links():
        if e.path and e.path2:
            m[normalise_path(e.path2, workdir)] = normalise_path(e.path, workdir)
    for s in (trace.aliases or {}).get("symlinks", []):
        if s.get("path") and s.get("real"):
            m.setdefault(normalise_path(s["path"], workdir), normalise_path(s["real"], workdir))
    for g in (trace.aliases or {}).get("hardlinks", []):
        paths = [normalise_path(p, workdir) for p in g.get("paths", [])]
        for p in paths:
            for q in paths:
                if p != q:
                    m.setdefault(p, q)
    return m


def _origin(path: str, aliases: dict[str, str]) -> list[str]:
    """``path`` followed back through aliases (at most 16 hops, cycles stop)."""
    chain, seen = [], {path}
    while path in aliases and len(chain) < 16:
        path = aliases[path]
        if path in seen:
            break
        seen.add(path)
        chain.append(path)
    return chain


def check_files(trace: Trace, policy: Policy, workdir: str, outputs: list[str],
                own_files: list[str] = ()) -> list[Finding]:
    out: list[Finding] = []
    reads = [e for e in trace.events if e.kind == "open" and e.mode in ("read", "rw")]
    forbidden_hit = False
    allow = policy.of("allow_file")
    unresolved = [e for e in reads if not e.resolved]
    reads = [e for e in reads if e.resolved]
    aliases = _alias_map(trace, workdir)
    by_path = _group(reads, lambda e: normalise_path(e.path, workdir))
    for path, evs in by_path.items():
        rule = policy.forbidden_file_rule(path)
        via = ""
        if not rule:
            for orig in _origin(path, aliases):
                rule = policy.forbidden_file_rule(orig)
                if rule:
                    via, path = path, orig
                    break
        ok_evs = [e for e in evs if e.ok]
        if rule:
            forbidden_hit = True
            how = f" through the alias {via}" if via else ""
            if ok_evs:
                out.append(Finding.with_rule(
                    FAIL, "forbidden_file_read", f"Read forbidden file {path}" + (f" (via {via})" if via else ""),
                    f"The run opened {path}{how} for reading {len(ok_evs)} time(s).", rule,
                    [e.evidence() for e in ok_evs]))
            else:
                out.append(Finding.with_rule(
                    WARN, "forbidden_file_attempt", f"Tried to open forbidden file {path}",
                    f"The open{how} failed (file missing or denied), but the code tried to read it.", rule,
                    [e.evidence() for e in evs]))
            continue
        if path.startswith("/") or path.startswith(IGNORE_PREFIXES) or not path.lower().endswith(DATA_EXT):
            continue
        if path in outputs or path in own_files or not ok_evs:
            continue
        if allow and not policy.allowed_file_rule(path):
            out.append(Finding(WARN, "unlisted_file_read", f"Read {path}, which the rules do not list",
                               "Not forbidden, but not among the files the rules say you may use. "
                               "Check it is your own file and not external data.",
                               evidence=[e.evidence() for e in ok_evs][:MAX_EVIDENCE]))
    # a new name for a forbidden file is a red flag even if the alias is never read
    alias_evs = [e for e in trace.links() if policy.forbidden_file_rule(normalise_path(e.path, workdir))]
    traced_new = set()
    for src, evs in _group(alias_evs, lambda e: normalise_path(e.path, workdir)).items():
        traced_new.update(normalise_path(e.path2, workdir) for e in evs)
        out.append(Finding.with_rule(
            WARN, "forbidden_file_alias", f"Made a new name for forbidden file {src}",
            f"{evs[0].op} to {normalise_path(evs[0].path2, workdir)}: reading the new name would hide the "
            "access from a check by file name, so Clean Room follows aliases.",
            policy.forbidden_file_rule(src), [e.evidence() for e in evs]))
    scan = trace.aliases or {}
    for s in scan.get("symlinks", []):
        p, real = normalise_path(s.get("path", ""), workdir), normalise_path(s.get("real", ""), workdir)
        rule = policy.forbidden_file_rule(real)
        if rule and p not in traced_new:
            out.append(Finding.with_rule(
                WARN, "forbidden_file_alias", f"{p} is a symlink to forbidden file {real}",
                "Found by the post-run scan.", rule, [f"aliases.json  {p} -> {s.get('target', '')}"]))
    for g in scan.get("hardlinks", []):
        paths = [normalise_path(x, workdir) for x in g.get("paths", [])]
        forb = [x for x in paths if policy.forbidden_file_rule(x)]
        if forb and (len(paths) > 1 or g.get("nlink", 1) > len(paths)) and not (set(paths) - set(forb)) <= traced_new:
            extra = [x for x in paths if x not in forb] or [f"{g.get('nlink', 2) - len(paths)} name(s) outside "
                                                             "the scanned directories"]
            out.append(Finding.with_rule(
                WARN, "forbidden_file_alias", f"Forbidden file {forb[0]} has other hard links",
                "Found by the post-run scan (same inode): " + ", ".join(extra[:4]),
                policy.forbidden_file_rule(forb[0]), [f"aliases.json  {', '.join(paths[:4])}"]))
    for e in unresolved:
        rule = policy.forbidden_file_rule(e.path.rsplit("/", 1)[-1])
        if rule:
            forbidden_hit = True
            out.append(Finding.with_rule(
                WARN, "forbidden_file_unresolved", f"Opened a file named like a forbidden file ({e.path})",
                "The directory of this open could not be resolved, so Clean Room cannot rule out that it was "
                "the forbidden file.", rule, [e.evidence()]))
    if unresolved and not forbidden_hit:
        out.append(Finding(WARN, "unresolved_paths",
                           f"{len(unresolved)} traced open(s) could not be resolved to a path",
                           "Their directory could not be determined, so the forbidden-file check is incomplete "
                           "for them. They are not treated as safe.",
                           evidence=[e.evidence() for e in unresolved][:MAX_EVIDENCE]))
    elif not forbidden_hit:
        n = len(policy.of("forbid_file"))
        unmapped = len(getattr(policy, "unmapped", []) or [])
        out.append(Finding(PASS, "no_forbidden_files", "No forbidden file access detected",
                           f"Checked every traced open() against {n} forbidden-file rule(s), following "
                           "symlinks, hard links and renames."
                           + (f" {unmapped} restrictive clause(s) of the rules could not be turned into "
                              "checks; see the policy notes." if unmapped else "")))
    uring = [e for e in trace.events if e.kind == "io_uring"]
    if uring:
        out.append(Finding(WARN, "untraced_io", "Used an I/O interface that system-call tracing cannot follow",
                           "io_uring can read files without an open() strace sees, so the file check is "
                           "incomplete for this run.",
                           evidence=[e.evidence() for e in uring][:MAX_EVIDENCE]))
    return out


def check_network(trace: Trace, policy: Policy, enforced: bool = True) -> list[Finding]:
    """``enforced`` means egress denial was *verified* for this run, not just configured."""
    out: list[Finding] = []
    attempts = trace.network_attempts()
    named = [e for e in attempts if e.kind == "dns" and e.host]
    raw = [e for e in attempts if e.kind == "connect" and not (e.port == 53 and named)]
    blocked_txt = ("egress denial was verified for this run, so the request could not complete"
                   if enforced else "egress denial was NOT verified for this run, so the request may have "
                   "gone out")
    dns_sys = [e.evidence() for e in attempts if e.kind == "connect" and e.port == 53][:2]
    for host, evs in _group(named, lambda e: e.host.lower()).items():
        status, rule = policy.host_rule(host)
        ev = [e.evidence() for e in evs][:2] + dns_sys
        if status == "allowed":
            out.append(Finding.with_rule(INFO, "allowed_host", f"Contacted allowed host {host}", "", rule, ev))
            continue
        sev = FAIL if status in ("forbidden", "denied_by_default") else WARN
        why = "the rules forbid this" if sev == FAIL else "host not listed in the rules"
        out.append(Finding.with_rule(
            sev, "network_attempt", f"Tried to reach {host}",
            f"Outbound lookup of {host} ({why}); {blocked_txt}.", rule, ev))
    for addr, evs in _group(raw, lambda e: f"{e.addr or '?'}:{e.port}").items():
        status, rule = policy.host_rule(addr.rsplit(":", 1)[0])
        if status == "allowed":
            continue
        succeeded = any(e.ok and e.errno != "EINPROGRESS" for e in evs)
        dns = addr.endswith(":53")
        sent = any(e.op in ("sendto", "sendmsg", "sendmmsg", "socket.sendto") for e in evs)
        verb = "Sent a datagram to" if sent else "Opened a connection to" if succeeded else "Tried to connect to"
        title = "Tried a DNS lookup (host name not captured)" if dns else f"{verb} {addr}"
        if succeeded and not dns:
            detail = ("Connection succeeded: egress was NOT blocked for this address." if not sent else
                      "The send call succeeded locally; " + (blocked_txt if not enforced else
                      "egress denial was verified for this run, so the packet should not have left") + ".")
        else:
            detail = f"Outbound network attempt; {blocked_txt}."
        out.append(Finding.with_rule(FAIL if status != "unlisted" else WARN, "network_connect",
                                     title, detail, rule, [e.evidence() for e in evs]))
    if not attempts:
        out.append(Finding(PASS, "no_network", "No network attempts detected",
                           "No DNS lookups, outbound connections or datagrams in the trace."))
    return out


def check_run(exit_code: int, output_sha: str | None, output: str) -> list[Finding]:
    out = []
    if exit_code != 0:
        out.append(Finding(FAIL, "run_failed", f"Run exited with code {exit_code}"))
    if not output_sha:
        out.append(Finding(FAIL, "no_output", f"No output file {output} was produced"))
    return out


def check_reproduction(orig_sha: str | None, replay_sha: str | None, checkpoint: str,
                       policy: Policy) -> Finding:
    rule = policy.repro_rule()
    if orig_sha and replay_sha and orig_sha == replay_sha:
        return Finding.with_rule(
            PASS, "reproduced", f"Output reproduced from checkpoint {checkpoint}",
            f"SHA-256 {orig_sha[:16]}… matched on re-run: reproduced in the recorded environment "
            "(same checkpoint, libraries and hardware). Other environments may differ.", rule)
    return Finding.with_rule(
        FAIL, "not_reproduced", f"Output did not reproduce from checkpoint {checkpoint}",
        f"Original SHA-256 {(orig_sha or 'none')[:16]}…, re-run {(replay_sha or 'none')[:16]}…. "
        "Fix random seeds and remove other non-determinism before submitting.", rule)


def _under(path: str, roots: list[str]) -> bool:
    p = os.path.normpath(path)
    return any(p == r or p.startswith(r.rstrip("/") + "/") for r in roots if r)


SANDBOX_SOCKET_PREFIXES = ("/.sprite/",)


def check_sandbox(trace: Trace) -> list[Finding]:
    """The candidate tried to reach the Sprite's own management API (/.sprite/api.sock).

    That socket can start services and create or restore checkpoints from inside the Sprite,
    i.e. run code outside the trace. Any attempt, successful or not, is disqualifying.
    """
    roots = SANDBOX_SOCKET_PREFIXES + tuple(
        m.rstrip("/") + "/" for m in (trace.meta or {}).get("mask_paths", []) if m)
    hits = [e for e in trace.unix_connects() if e.path.startswith(roots)]
    if not hits:
        return []
    return [Finding(FAIL, "sandbox_escape_attempt", "Tried to reach the Sprite's management API",
                    f"Connected to {hits[0].path}, the socket that can start services and restore "
                    "checkpoints outside Clean Room's trace. Candidate code has no reason to touch it.",
                    evidence=[e.evidence() for e in hits][:MAX_EVIDENCE])]


def check_tamper(trace: Trace) -> list[Finding]:
    """The candidate wrote to, truncated, renamed or deleted Clean Room's own evidence."""
    meta = trace.meta or {}
    roots = [os.path.normpath(p) for p in meta.get("trace_paths", []) if p]
    if not roots:
        return []
    audit = os.path.normpath(meta.get("audit_log") or "")
    hits = []
    for e in trace.events:
        if e.source != "strace":
            continue
        if e.kind == "open" and e.mode in ("write", "rw") and _under(e.path, roots):
            if os.path.normpath(e.path) == audit and "O_APPEND" in e.flags and "O_TRUNC" not in e.flags:
                continue     # the audit hook appending its own records
            hits.append(e)
        elif e.kind in ("modify", "alias") and (_under(e.path, roots) or _under(e.path2, roots)):
            hits.append(e)
    if not hits:
        return []
    return [Finding(FAIL, "trace_tampering", "Tried to modify Clean Room's trace",
                    "The candidate opened, truncated, renamed or deleted files Clean Room uses as evidence. "
                    "Its trace cannot be trusted and the attempt itself is disqualifying.",
                    evidence=[e.evidence() for e in hits][:MAX_EVIDENCE])]


def check_trace(trace: Trace, tracer: str | None = None) -> list[Finding]:
    """Is this trace usable as evidence? Anything short of that is INCONCLUSIVE.

    ``tracer`` is what the backend says it ran (``strace+audit``, ``audit``, ...);
    None skips the expectation checks (unit tests build traces by hand).
    """
    out = []
    if trace.bundle_problems:
        out.append(Finding(INCONCLUSIVE, "bundle_rejected", "The trace bundle contained unsafe entries",
                           "Clean Room refused them on extraction: " + "; ".join(trace.bundle_problems[:3])))
    if not trace.sources and not trace.events:
        return out + [Finding(INCONCLUSIVE, "trace_missing", "No trace was collected",
                              "Without a trace Clean Room cannot say anything about file or network access.")]
    if not trace.events:
        out.append(Finding(INCONCLUSIVE, "trace_empty", "The trace is empty",
                           f"Trace sources {', '.join(trace.sources) or 'none'} recorded no events; a real run "
                           "always opens files, so tracing did not work."))
    if trace.parse_errors:
        out.append(Finding(INCONCLUSIVE, "trace_corrupt",
                           f"The audit log has {trace.parse_errors} unreadable line(s)",
                           "The log was damaged or written to by something other than the hook."))
    if trace.tampered:
        out.append(Finding(INCONCLUSIVE, "trace_tampered", "A trace file was truncated during the run",
                           "Found NUL bytes where trace records should be, which happens when a file is cut "
                           "while the tracer still writes to it: " + ", ".join(trace.tampered[:4])))
    if "strace" in trace.sources and trace.complete is False:
        out.append(Finding(INCONCLUSIVE, "trace_incomplete", "The strace trace is incomplete",
                           f"{trace.incomplete_files} of {trace.strace_files} traced process(es) have no exit "
                           "record: strace was killed or detached, or the trace was cut short or edited."))
    meta = trace.meta or {}
    if meta.get("untraced_procs"):
        out.append(Finding(INCONCLUSIVE, "untraced_process", "A candidate process ran outside the trace",
                           "A process of the candidate's uid had no tracer attached (for example one made with "
                           "clone(CLONE_UNTRACED)); whatever it did is not in the trace. It was killed.",
                           evidence=list(meta["untraced_procs"])[:MAX_EVIDENCE]))
    if meta.get("seccomp") == "off" and "strace" in trace.sources:
        out.append(Finding(WARN, "untraced_clone_not_blocked", "Untraced child processes were not blocked",
                           "The seccomp filter that refuses clone(CLONE_UNTRACED) was not installed for this run; "
                           "Clean Room still looked for untraced processes while the run was going."))
    if meta.get("audit_truncated"):
        out.append(Finding(INCONCLUSIVE, "audit_truncated", "The audit log hit its size limit",
                           "The candidate wrote more audit records than Clean Room keeps; the rest were "
                           "dropped, so the audit side of the trace is incomplete."))
    if meta.get("mask") == "failed":
        out.append(Finding(WARN, "mask_failed", "Could not hide the Sprite management socket from the candidate",
                           "Paths " + ", ".join(meta.get("mask_paths", [])) + " stayed visible. Connections to "
                           "them are still traced and fail the run."))
    if meta.get("strace_signalled"):
        out.append(Finding(INCONCLUSIVE, "tracer_killed", "strace itself was killed during the run",
                           f"strace ended with status {meta.get('strace_exit')}; processes it traced may have "
                           "continued untraced."))
    if tracer is not None:
        if "strace" in tracer and "strace" not in trace.sources:
            out.append(Finding(INCONCLUSIVE, "trace_missing", "The strace trace is missing",
                               f"The backend reported tracer '{tracer}' but no strace files came back."))
        elif "strace" not in tracer:
            out.append(Finding(WARN, "audit_only", "Traced by the in-process audit hook only (no strace)",
                               "The audit hook sees Python-level events only and runs inside the candidate's own "
                               "process (a child started with env={} or code using ctypes is invisible to it), "
                               "so this run can reach WARN at best, never PASS. Install strace (ptrace "
                               "permitted) or use the Sprite backend."))
    if meta.get("candidate_uid") == "same":
        out.append(Finding(WARN, "tracer_same_uid", "Candidate ran as the same user as the tracer",
                           "Development mode: the candidate could have edited or stopped its own trace. Clean "
                           "Room looks for signs of that, but only the Sprite worker (separate candidate uid) "
                           "makes the trace tamper-resistant."))
    return out


def analyse(trace: Trace, policy: Policy, workdir: str, exit_code: int, output_sha: str | None,
            output: str, outputs: list[str] | None = None, enforced: bool = True,
            own_files: list[str] = (), tracer: str | None = None) -> list[Finding]:
    """Findings for one run. Fails closed: with an unusable trace no PASS finding is kept."""
    f = check_run(exit_code, output_sha, output)
    gate = check_trace(trace, tracer)
    f += gate + check_tamper(trace) + check_sandbox(trace)
    found = check_files(trace, policy, workdir, outputs or [output], own_files)
    found += check_network(trace, policy, enforced)
    if any(x.severity == INCONCLUSIVE for x in gate):
        found = [x for x in found if x.severity != PASS]
    return f + found


def worst(findings) -> str:
    sev = {getattr(x, "severity", None) or x["severity"] for x in findings}
    for s in (FAIL, INCONCLUSIVE, WARN, PASS):
        if s in sev:
            return s
    return INFO
