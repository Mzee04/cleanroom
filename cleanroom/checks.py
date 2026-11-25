"""Turn a trace + policy into findings, each citing its rule and evidence."""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict, dataclass, field

from .policy import Policy, Rule
from .trace import Trace, normalise_path

FAIL, WARN, PASS, INFO = "FAIL", "WARN", "PASS", "INFO"
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


def check_files(trace: Trace, policy: Policy, workdir: str, outputs: list[str],
                own_files: list[str] = ()) -> list[Finding]:
    out: list[Finding] = []
    reads = [e for e in trace.events if e.kind == "open" and e.mode in ("read", "rw")]
    by_path = _group(reads, lambda e: normalise_path(e.path, workdir))
    forbidden_hit = False
    allow = policy.of("allow_file")
    for path, evs in by_path.items():
        rule = policy.forbidden_file_rule(path)
        ok_evs = [e for e in evs if e.ok]
        if rule:
            forbidden_hit = True
            if ok_evs:
                out.append(Finding.with_rule(
                    FAIL, "forbidden_file_read", f"Read forbidden file {path}",
                    f"The run opened {path} for reading {len(ok_evs)} time(s).", rule,
                    [e.evidence() for e in ok_evs]))
            else:
                out.append(Finding.with_rule(
                    WARN, "forbidden_file_attempt", f"Tried to open forbidden file {path}",
                    "The open failed (file missing or denied), but the code tried to read it.", rule,
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
    if not forbidden_hit:
        n = len(policy.of("forbid_file"))
        out.append(Finding(PASS, "no_forbidden_files", "No forbidden file access detected",
                           f"Checked every traced open() against {n} forbidden-file rule(s)."))
    return out


def check_network(trace: Trace, policy: Policy, enforced: bool = True) -> list[Finding]:
    out: list[Finding] = []
    attempts = trace.network_attempts()
    named = [e for e in attempts if e.kind == "dns" and e.host]
    raw = [e for e in attempts if e.kind == "connect" and not (e.port == 53 and named)]
    blocked_txt = ("the egress policy was enforced, so the request could not complete"
                   if enforced else "egress was NOT enforced for this run (observe-only)")
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
    for addr, evs in _group(raw, lambda e: f"{e.addr}:{e.port}").items():
        status, rule = policy.host_rule(addr.rsplit(":", 1)[0])
        if status == "allowed":
            continue
        succeeded = any(e.ok for e in evs)
        dns = addr.endswith(":53")
        title = ("Tried a DNS lookup (host name not captured)" if dns
                 else f"Opened a connection to {addr}" if succeeded else f"Tried to connect to {addr}")
        detail = ("Connection succeeded: egress was NOT blocked for this address." if succeeded and not dns
                  else f"Outbound network attempt; {blocked_txt}.")
        out.append(Finding.with_rule(FAIL if status != "unlisted" else WARN, "network_connect",
                                     title, detail, rule, [e.evidence() for e in evs]))
    if not attempts:
        out.append(Finding(PASS, "no_network", "No network attempts detected",
                           "No DNS lookups or outbound connections in the trace."))
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
            f"SHA-256 {orig_sha[:16]}… matched on re-run. This proves reproduction in this "
            "environment only.", rule)
    return Finding.with_rule(
        FAIL, "not_reproduced", f"Output did not reproduce from checkpoint {checkpoint}",
        f"Original SHA-256 {(orig_sha or 'none')[:16]}…, re-run {(replay_sha or 'none')[:16]}…. "
        "Fix random seeds and remove other non-determinism before submitting.", rule)


def analyse(trace: Trace, policy: Policy, workdir: str, exit_code: int, output_sha: str | None,
            output: str, outputs: list[str] | None = None, enforced: bool = True,
            own_files: list[str] = ()) -> list[Finding]:
    f = check_run(exit_code, output_sha, output)
    f += check_files(trace, policy, workdir, outputs or [output], own_files)
    f += check_network(trace, policy, enforced)
    return f


def worst(findings) -> str:
    sev = {getattr(x, "severity", None) or x["severity"] for x in findings}
    for s in (FAIL, WARN, PASS):
        if s in sev:
            return s
    return INFO
