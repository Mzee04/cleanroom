"""Render the integrity report as one self-contained HTML page and serve it."""
from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .redact import redact_text

E = html.escape

CSS = """
:root{--bg:#0f1115;--card:#171a21;--line:#262b36;--ink:#e8eaf0;--mute:#9aa3b2;--fail:#ff5d5d;--warn:#f5b941;
--pass:#3ecf8e;--info:#6aa9ff;--accent:#8b7cff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 ui-sans-serif,system-ui,
-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}a{color:var(--info)}
.wrap{max-width:1120px;margin:0 auto;padding:32px 20px 80px}
header{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:22px}
h1{font-size:26px;margin:0;letter-spacing:-.01em}h1 span{color:var(--accent)}
.sub{color:var(--mute);font-size:13px}
h2{font-size:17px;margin:34px 0 12px}h3{margin:0;font-size:16px}
.hero{background:linear-gradient(135deg,#1c1f2b,#191b24);border:1px solid var(--line);border-radius:16px;padding:22px 24px}
.hero .pick{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--mute)}
.hero .big{font-size:30px;font-weight:700;margin:2px 0 10px}.hero .big b{color:var(--pass)}
.hero p{margin:0;color:#cfd4de}
.caution{margin-top:12px;color:var(--warn);font-size:14px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:14px}
th{color:var(--mute);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em;background:#141720}
tr:last-child td{border-bottom:0}td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.03em}
.FAIL{background:rgba(255,93,93,.14);color:var(--fail)}.WARN{background:rgba(245,185,65,.14);color:var(--warn)}
.PASS{background:rgba(62,207,142,.14);color:var(--pass)}.INCONCLUSIVE{background:rgba(196,120,255,.16);color:#c478ff}.INFO{background:rgba(106,169,255,.14);color:var(--info)}
.rec{outline:2px solid var(--pass);outline-offset:-2px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:14px 0}
.card .head{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:6px}
.meta{color:var(--mute);font-size:13px}.meta code{color:#c9cfdb}
.f{border-top:1px solid var(--line);padding:12px 0 4px}.f:first-of-type{border-top:0}
.f .t{font-weight:600}.f .d{color:#c6ccd8;margin:2px 0 6px}
blockquote{margin:6px 0;padding:8px 12px;border-left:3px solid var(--accent);background:#1b1e29;border-radius:0 8px 8px 0;
color:#d9dcf5;font-size:14px}blockquote small{display:block;color:var(--mute);margin-bottom:2px}
pre{margin:6px 0;background:#0b0d11;border:1px solid var(--line);border-radius:8px;padding:10px 12px;overflow:auto;
font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#d3d8e2;white-space:pre-wrap;word-break:break-all}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.kv{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.kv b{display:block;font-size:12px;color:var(--mute);text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px}
.limits li{margin:4px 0;color:#c6ccd8}footer{margin-top:40px;color:var(--mute);font-size:12px}
"""

LIMITS = [
    "What Clean Room is: an auditor for your own candidates, built to catch accidents and ordinary shortcuts "
    "before you submit. It is hardened against simple evasion (symlinks, renames, hard links, editing the trace, "
    "children started with a stripped environment), but it is not a sandbox proven against a determined "
    "adversary with kernel exploits or side channels.",
    "\u201cNo forbidden access detected\u201d means none appeared in the traced system calls and Python audit "
    "events. Tracing is evidence, not proof: it cannot see leakage already inside the training data, labels "
    "copied into code by hand, or reads through interfaces strace does not report (io_uring is flagged).",
    "On the Sprite worker the candidate runs as its own unprivileged uid under a root-owned strace, so it "
    "cannot edit or stop its trace. Locally it runs as you (development mode) and every run is capped at WARN.",
    "Runs traced by the in-process audit hook only (no strace) are capped at WARN. A missing, empty, cut-short "
    "or tampered trace is INCONCLUSIVE and never PASS.",
    "A SHA-256 match proves the output reproduced in the recorded environment (checkpoint, library versions, "
    "hardware), only. Other hardware, library versions or thread counts can change results.",
    "Egress is denied for every run; a finding says egress was blocked only when probes found it blocked: "
    "as the candidate's uid just before the run (DNS plus a few TCP and UDP destinations) and by DNS after it. "
    "That checks a handful of destinations, not every address. Locally the denial is an empty network "
    "namespace; on a Sprite it is the network policy set from outside the worker.",
    "On the worker the Sprite's internal API socket is hidden from candidates, untraced child processes are "
    "refused by a seccomp filter (and any found anyway make the run INCONCLUSIVE), and candidates run under "
    "process, file-size and open-file limits. Writes on an already connected UDP socket and loopback "
    "connects are not traced.",
    "Leakage that never opens a forbidden file is out of reach: labels rebuilt from public data (the demo uses "
    "scikit-learn's public diabetes set), answers typed into the code, or a model trained elsewhere.",
    "The holdout score and its interval come from your own local split, scored by the agent; the truth file "
    "never reaches the worker. The top pick's interval is optimistic because it was chosen as the maximum; the "
    "paired comparison is the fairer test. Seed spread only means something if the code reads CLEANROOM_SEED.",
    "Investigations are one-factor re-runs: the run is repeated unchanged first, and a change is attributed to "
    "the hidden file only if the unchanged re-run reproduced the original output.",
    "The GitHub ledger is a hash chain of records (tamper-evident): an edited record no longer matches its hash "
    "or the next record's link, and `cleanroom verify-chain` checks every link. Records are never rewritten; a "
    "changed result is appended as a revision. It is not signed or externally timestamped.",
    "Rules-to-policy extraction is heuristic (plus an optional LLM pass whose quotes must match the rules "
    "verbatim and name their target). Restrictive clauses it could not map are listed. Always read the policy "
    "table and the original rules.",
]


def _fmt(x, nd=4):
    return "—" if x is None else f"{x:.{nd}f}"


def _repro(c):
    if c["reproduced"] is None:
        return '<span class="meta">skipped: already ineligible</span>' if c["fails"] else \
            '<span class="meta">not checked</span>'
    return '<span class="pill PASS">MATCH</span>' if c["reproduced"] else '<span class="pill FAIL">MISMATCH</span>'


def _access(c, prefix):
    hits = [f for f in c["findings"] if f["code"].startswith(prefix) and f["severity"] in ("FAIL", "WARN")]
    if not hits:
        return '<span class="pill PASS">NONE DETECTED</span>'
    return "<br>".join(f'<span class="pill {f["severity"]}">{f["severity"]}</span> {E(f["title"])}' for f in hits)


def render_html(s: dict) -> str:
    rec = s["recommendation"]
    pick = rec["recommended"]
    rows = []
    for c in s["candidates"]:
        ci = c["holdout_ci"]
        seeds = c["seeds"]
        rows.append(
            f'<tr class="{"rec" if c["name"] == pick else ""}"><td><b>{E(c["name"])}</b>'
            f'<div class="meta">{E(c["note"])}</div></td>'
            f'<td class="num">{_fmt(c["leaderboard"])}</td>'
            f'<td class="num">{_fmt(c["holdout"])}'
            + (f'<div class="meta">95% CI {ci[0]:.3f}–{ci[1]:.3f}</div>' if ci else "")
            + (f'<div class="meta">seed sd {seeds["sd"]:.4f}</div>' if seeds and seeds.get("sd") is not None
               else '<div class="meta">seed sd n/a (fewer than 2 seed runs scored)</div>' if seeds else "")
            + f'</td><td>{_access(c, "forbidden")}</td><td>{_access(c, "network")}</td>'
            f'<td>{_repro(c)}</td><td><span class="pill {c["status"]}">{c["status"]}</span>'
            + (f'<div class="meta"><a href="{E(c["ledger_issue"])}">ledger #{E(c["ledger_issue"].rsplit("/", 1)[-1])}</a></div>'
               if c.get("ledger_issue") else "") + '</td></tr>')

    cards = []
    for c in s["candidates"]:
        fs = []
        for f in sorted(c["findings"], key=lambda f: ["FAIL", "INCONCLUSIVE", "WARN", "PASS", "INFO"].index(f["severity"])):
            q = (f'<blockquote><small>Rule {E(f["clause_id"])}</small>{E(f["quote"])}</blockquote>'
                 if f["quote"] else "")
            ev = f'<pre>{E(chr(10).join(f["evidence"]))}</pre>' if f["evidence"] else ""
            fs.append(f'<div class="f"><span class="pill {f["severity"]}">{f["severity"]}</span> '
                      f'<span class="t">{E(f["title"])}</span><div class="d">{E(f["detail"])}</div>{q}{ev}</div>')
        extra = ""
        if c.get("investigated") or c.get("remaining_flags"):
            extra += ('<div class="f"><span class="pill INFO">AGENT</span> <span class="t">Follow-up scope</span>'
                      f'<div class="d">Investigated: {E("; ".join(c.get("investigated") or []) or "none")}.<br>'
                      f'Not investigated (reported as found): {E("; ".join(c.get("remaining_flags") or []) or "none")}.'
                      '</div></div>')
        if c["network_investigation"]:
            extra += f'<div class="f"><span class="pill INFO">AGENT</span> <span class="t">Network follow-up</span>' \
                     f'<div class="d">{E(c["network_investigation"])}</div></div>'
        cards.append(
            f'<div class="card" id="cand-{E(c["name"])}"><div class="head"><h3>Candidate {E(c["name"])}</h3>'
            f'<span class="pill {c["status"]}">{c["status"]}</span>'
            + ('<span class="pill PASS">RECOMMENDED</span>' if c["name"] == pick else "") +
            f'</div><div class="meta">Command <code>{E(" ".join(c["cmd"]))}</code> · checkpoint '
            f'<code>{E(c["checkpoint"] or "")}</code> · output SHA-256 <code>{E((c["sha256"] or "none")[:16])}…</code>'
            f' · tracer <code>{E(c["tracer"] or "")}</code> · candidate uid {E(str(c.get("candidate_uid")))}'
            f' · egress denial verified: {E(str(c.get("egress_verified")))} · {c["n_events"] or 0} events'
            + (f' · <a href="{E(c["ledger_issue"])}">GitHub ledger issue #{E(c["ledger_issue"].rsplit("/", 1)[-1])}</a>'
               if c.get("ledger_issue") else "") + '</div>'
            f'{extra}{"".join(fs)}</div>')

    pol_rows = "".join(
        f'<tr><td><code>{E(r["kind"])}</code></td><td>{E(r["target"]) or "—"}</td><td>{E(r["clause_id"])}</td>'
        f'<td>{E(r["quote"])}</td><td class="meta">{E(r["source"])}</td></tr>' for r in s["policy"]["rules"])
    env = s.get("environment") or {}
    env_kv = "".join(f'<div class="kv"><b>{E(str(k))}</b>{E(v if isinstance(v, str) else json.dumps(v))[:500]}</div>'
                     for k, v in env.items())
    cautions = "".join(f'<div class="caution">⚠ {E(x)}</div>' for x in rec.get("cautions", []))
    cmp_ = s.get("comparison")
    cmp_html = ""
    if cmp_:
        cmp_html = (f'<div class="kv"><b>Honest score: {E(cmp_["a"])} vs {E(cmp_["b"])}</b>'
                    f'ΔAUC {cmp_["diff"]:+.4f} (95% CI {cmp_["lo"]:+.4f} to {cmp_["hi"]:+.4f}) — '
                    f'{"conclusive" if cmp_["conclusive"] else "inconclusive: within noise"}</div>')
    title = f"Submit <b>{E(pick)}</b>" if pick else "Nothing ready to submit"
    pc = next((c for c in s["candidates"] if c["name"] == pick), None)
    if pc:
        tr = pc.get("tracer") or ""
        title += (f' <span class="pill {"PASS" if "strace" in tr else "WARN"}" style="font-size:13px;'
                  f'vertical-align:middle">traced by {E(tr or "unknown")}'
                  f'{", separate uid" if pc.get("candidate_uid") == "separate" else ", same uid (dev mode)"}</span>')
    chain = s.get("ledger_chain") or {}
    chain_html = (f'<div class="kv"><b>GitHub ledger chain head</b><code>{E(chain.get("record_sha256", ""))}</code>'
                  f' · record #{E(str(chain.get("seq", "")))}</div>' if chain else "")
    unmapped = s["policy"].get("unmapped") or []
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Clean Room report</title>
<style>{CSS}</style></head><body><div class="wrap">
<header><div><h1>Clean Room <span>integrity report</span></h1>
<div class="sub">Personal submission integrity agent · session {E(str(s.get("session", "")))} · generated {E(s["generated"])}</div></div>
<div class="sub">{len(s["candidates"])} candidates · backend {E(str(env.get("backend", "local")))}</div></header>
<section class="hero"><div class="pick">Agent verdict</div><div class="big">{title}</div>
<p>{E(s["verdict"].removeprefix(f"Submit {pick}. ") if pick else s["verdict"]).replace(chr(10), "<br>")}</p>{cautions}</section>
<h2>Candidates</h2>
<table><thead><tr><th>Candidate</th><th>Leaderboard</th><th>Holdout ROC AUC</th><th>Forbidden files</th>
<th>Network</th><th>Reproduction</th><th>Status</th></tr></thead><tbody>{"".join(rows)}</tbody></table>
<div class="grid" style="margin-top:12px">{cmp_html}{chain_html}</div>
<h2>Evidence</h2>{"".join(cards)}
<h2>Policy extracted from the rules</h2>
<table><thead><tr><th>Kind</th><th>Target</th><th>Clause</th><th>Quote</th><th>Source</th></tr></thead>
<tbody>{pol_rows}</tbody></table>
<p class="meta">Policy digest <code>{E(s.get("policy_sha256", ""))}</code> · {len(s["policy"]["rules"])} rules ·
{len(unmapped)} restrictive clause(s) not mapped to a check</p>
{"".join(f'<p class="meta">{E(n)}</p>' for n in s["policy"].get("notes", []))}
<h2>Environment</h2><div class="grid">{env_kv}</div>
<h2>Honest limits</h2><ul class="limits">{"".join(f"<li>{E(x)}</li>" for x in LIMITS)}</ul>
<footer>Clean Room · runs on Fly.io Sprites · report data at <a href="report.json">report.json</a></footer>
</div></body></html>"""


def public_view(obj):
    """What report.json may show: home paths and token-shaped strings masked, no raw commands or trace dirs."""
    drop = {"trace_dir", "workdir", "stdout_tail", "stderr_tail"}
    if isinstance(obj, dict):
        return {k: public_view(v) for k, v in obj.items() if k not in drop}
    if isinstance(obj, (list, tuple)):
        return [public_view(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


def write_report(summary: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    pub = public_view(summary)
    (out_dir / "report.json").write_text(json.dumps(pub, indent=2, default=str))
    p = out_dir / "report.html"
    p.write_text(render_html(pub))
    return p


def serve(make_summary, host="127.0.0.1", port=8080):
    """Serve the live report; each request re-reads the ledger."""

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/healthz":
                return self._send(200, b"ok", "text/plain")
            try:
                s = public_view(make_summary())
            except Exception as e:  # keep the server up while the agent is mid-run
                return self._send(503, f"report not ready: {type(e).__name__}".encode(), "text/plain")
            if path in ("/", "/index.html", "/report.html"):
                return self._send(200, render_html(s).encode(), "text/html; charset=utf-8")
            if path == "/report.json":
                return self._send(200, json.dumps(s, indent=2, default=str).encode(), "application/json")
            return self._send(404, b"not found", "text/plain")

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer((host, port), H)
    print(f"Serving the Clean Room report on http://{host}:{port}/")
    srv.serve_forever()
