"""Command-line interface.

  cleanroom policy rules.txt            derive + show the policy (no API key needed)
  cleanroom run --name A -- python train.py
  cleanroom verify A                    restore checkpoint, re-run, compare SHA-256
  cleanroom investigate A               follow up A's red flags
  cleanroom report [--serve]            HTML report (serves on 127.0.0.1:8080; --host 0.0.0.0 to publish)
  cleanroom agent [--serve]             the full loop over cleanroom.json candidates
  cleanroom doctor                      what isolation/tracing works on this machine
  cleanroom verify-chain --repo O/R     check the GitHub ledger's hash chain (exit 1 if broken)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__


def _project(args):
    from .backends import get_backend
    from .engine import Project
    from .config import load_config
    root = Path(args.project).resolve()
    cfg = load_config(root)
    private = list(cfg.get("private", []))
    if cfg.get("holdout") and cfg["holdout"].get("truth"):
        private.append(cfg["holdout"]["truth"])   # the holdout truth never goes where candidates run
    kw: dict[str, Any] = {"private": private}
    if args.backend == "sprite":
        kw.update(worker=args.worker, setup=cfg.get("worker_setup"))
    return Project(root, get_backend(args.backend, root, **kw), use_llm=not args.no_llm)


def cmd_policy(args):
    from .policy import build_policy
    text = Path(args.rules).read_text()
    pol = build_policy(text, use_llm=not args.no_llm)
    if args.json:
        print(json.dumps(pol.to_dict(), indent=2))
    else:
        print(f"{len(pol.rules)} rules extracted from {args.rules}\n")
        for r in pol.rules:
            print(f"[{r.kind}] {r.target or ''}  (rule {r.clause_id}, {r.source})\n    “{r.quote}”")
        for n in pol.notes:
            print("note:", n)
        print("\nWorker network policy:", json.dumps(pol.sprite_network_policy()))
    out = Path(args.project) / ".cleanroom" / "policy.json"
    pol.save(out)
    print(f"\nsaved {out}", file=sys.stderr)


def _print_findings(fs):
    for f in fs:
        d = f.to_dict() if hasattr(f, "to_dict") else f
        print(f"  {d['severity']:4s} {d['title']}")
        if d["detail"]:
            print(f"       {d['detail']}")
        if d["quote"]:
            print(f"       rule {d['clause_id']}: “{d['quote']}”")
        for e in d["evidence"]:
            print(f"       ↳ {e[:220]}")


def cmd_run(args):
    cmd = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd
    if not cmd:
        raise SystemExit("usage: cleanroom run --name A -- python train.py")
    proj = _project(args)
    proj.backend.prepare(proj.policy.sprite_network_policy())
    rec = proj.run(args.name, cmd, note=args.note or "")
    _print_findings(rec["findings"])


def cmd_verify(args):
    proj = _project(args)
    rec = proj.verify(args.name)
    _print_findings([f for f in rec["findings"] if f.code in ("reproduced", "not_reproduced")])
    sys.exit(0 if rec["reproduced"] else 1)


def cmd_investigate(args):
    proj = _project(args)
    for r in proj.investigate(args.name):
        print(r.get("verdict") or r["data"].get("verdict"))


def _summary_fn(proj, honest=True):
    from .summary import build_summary

    def make():
        from .store import Ledger
        led = Ledger(proj.ledger.path)  # fresh connection per request (thread-safe)
        return build_summary(led, proj.policy, honest=honest)
    return make


def cmd_report(args):
    from .report import serve, write_report
    proj = _project(args)
    make = _summary_fn(proj)
    p = write_report(make(), proj.root / ".cleanroom")
    print(f"wrote {p}")
    if args.serve:
        serve(make, args.host, args.port)


def cmd_agent(args):
    from .agent import run_agent
    proj = _project(args)
    run_agent(proj, honest=not args.no_honest, publish_github=args.publish, color=sys.stdout.isatty())
    if args.serve:
        from .report import serve
        serve(_summary_fn(proj, honest=not args.no_honest), args.host, args.port)


def cmd_doctor(args):
    proj = _project(args)
    print(json.dumps({"backend": proj.backend.describe(), "capabilities": proj.backend.doctor()}, indent=2))


def cmd_verify_chain(args):
    from .ghledger import fetch_issues, verify_chain
    gw = args.gateway or os.environ.get("CLEANROOM_GITHUB_GATEWAY") or None
    repo = args.repo or os.environ.get("CLEANROOM_GITHUB_REPO")
    if not repo:
        sys.exit("verify-chain needs --repo OWNER/REPO (or CLEANROOM_GITHUB_REPO)")
    ok, lines = verify_chain(fetch_issues(repo, gw))
    print("\n".join(lines))
    sys.exit(0 if ok else 1)


def main(argv=None):
    p = argparse.ArgumentParser(prog="cleanroom", description="Personal submission integrity agent.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-C", "--project", default=os.environ.get("CLEANROOM_PROJECT", "."),
                   help="project directory (default: current)")
    p.add_argument("--backend", choices=["local", "sprite"], default=os.environ.get("CLEANROOM_BACKEND", "local"))
    p.add_argument("--worker", default=os.environ.get("CLEANROOM_WORKER", "cleanroom-worker"),
                   help="worker Sprite name (sprite backend)")
    p.add_argument("--no-llm", action="store_true", help="never call the optional LLM")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("policy", help="derive a policy from rules text")
    s.add_argument("rules")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_policy)

    s = sub.add_parser("run", help="run one candidate (traced, egress denied, checkpointed)")
    s.add_argument("--name", required=True)
    s.add_argument("--note")
    s.add_argument("cmd", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("verify", help="restore the checkpoint, re-run, compare SHA-256")
    s.add_argument("name")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("investigate", help="follow up a candidate's red flags")
    s.add_argument("name")
    s.set_defaults(fn=cmd_investigate)

    for name, fn, h in (("report", cmd_report, "write/serve the HTML report"),
                        ("agent", cmd_agent, "run the full agent loop over cleanroom.json")):
        s = sub.add_parser(name, help=h)
        s.add_argument("--serve", action="store_true", help="serve the report over HTTP")
        s.add_argument("--host", default=os.environ.get("CLEANROOM_HOST", "127.0.0.1"),
                       help="bind address (default 127.0.0.1; pass 0.0.0.0 to publish the report deliberately)")
        s.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8080)))
        if name == "agent":
            s.add_argument("--no-honest", action="store_true", help="skip bootstrap CI + seed spread")
            s.add_argument("--publish", action="store_true", help="post the GitHub ledger via the connector")
        s.set_defaults(fn=fn)

    s = sub.add_parser("doctor", help="show which isolation/tracing features work here")
    s.set_defaults(fn=cmd_doctor)

    s = sub.add_parser("verify-chain", help="check the GitHub ledger's hash chain")
    s.add_argument("--repo", help="OWNER/REPO of the ledger (default: CLEANROOM_GITHUB_REPO)")
    s.add_argument("--gateway", help="connector gateway URL (default: CLEANROOM_GITHUB_GATEWAY, "
                                     "else the public GitHub API)")
    s.set_defaults(fn=cmd_verify_chain)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
