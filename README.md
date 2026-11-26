# Clean Room

**A personal submission integrity agent for ML competitions, running on Fly.io Sprites.**

You have five candidate submissions for a Kaggle- or Zindi-style competition. One of them has the
best leaderboard score. Is it safe to send? Clean Room answers that *before* you submit:

1. **Rules → policy.** Paste the competition rules. Clean Room extracts which files you may and
   may not read, whether internet access is allowed, which hosts are allowed, whether external
   data is allowed and whether results must be reproducible. Every rule keeps the clause number
   and the exact quote it came from.
2. **Isolated, traced runs.** Each candidate runs from the same checkpoint with egress denied,
   as a separate user, while Clean Room records the files it opened, linked or renamed and the
   hosts it tried to reach (`strace -f` plus a Python audit hook).
3. **Findings with evidence.** Each finding quotes the rule it relies on and shows the exact
   trace lines behind it.
4. **The agent investigates.** A forbidden file was read? It first re-runs unchanged (is the
   candidate deterministic at all?), then re-runs from the checkpoint with that file hidden and reports
   whether the score depended on it. A network call? If egress denial was verified, the output was
   produced without the download.
5. **Reproduction.** It restores the checkpoint, re-runs, and compares the output's SHA-256.
6. **Honest score (optional).** Bootstrap 95% interval on *your own* holdout, a paired bootstrap
   for "is B really better than D?", and the spread across three seeds.
7. **Recommendation.** It recommends the best *eligible* candidate by holdout score, never by the
   public leaderboard, and explains why the others were rejected. The report is a single HTML page
   served on port 8080 (the Sprite's public URL port).

```
$ cleanroom agent
[1/7] Rules → policy: 6 rules from rules.txt
[4/7] Running candidates from the checkpoint
  A: exit 0, sha256 bab13241deae…, FAIL
    tracer strace+audit · candidate uid separate · leaderboard 0.9200 · holdout AUC 0.7721
    FAIL Read forbidden file data/test_labels.csv
      rule 1.2: “The file test_labels.csv is provided for organiser scoring only and must not be read by participant code.”
      ↳ strace.27:1417  openat(AT_FDCWD</srv/cr/work>, "data/test_labels.csv", O_RDONLY|O_CLOEXEC) = 4
[5/7] Investigating red flags
  A: One-factor re-run: the unchanged re-run reproduced the output, and without data/test_labels.csv the
     output changes and the leaderboard score moves from 0.9200 to 0.8252: the score depends on the forbidden file.
[6/7] Verifying reproduction from the checkpoint
  B: MATCH · SHA-256 212e37d39ed6e5f4… matched on re-run: reproduced in the recorded environment.
  E: MISMATCH · Fix random seeds and remove other non-determinism before submitting.
Recommendation: B
```

![Clean Room report](docs/report.png)

## Why Sprites

Clean Room needs three things a plain container makes awkward, and Sprites provide natively:

| Need | Sprite feature |
| --- | --- |
| Run untrusted competition code with no internet | **Network policy**, set from *outside* the Sprite through the Sprites API. The code under test cannot loosen it through the policy file; Clean Room also hides the Sprite's internal API socket from candidates (see "Sandbox hardening"), and confirms the denial by probing as the candidate's uid rather than by reading a file. |
| Start every candidate from the identical machine, and re-run later to prove reproduction | **Checkpoints** (`POST /v1/sprites/{name}/checkpoint`, restore by id). Copy-on-write, so one per candidate is cheap. |
| Keep secrets away from the code under test | The worker never receives any credential. The agent drives it over the Sprites API with a token kept in a private 0600 file on the agent Sprite. The **Sprites GitHub connector** keeps the GitHub credential off both Sprites: the agent posts the verdict ledger through the Sprites gateway, and the connector's policy admits only `cleanroom-agent*` and only the ledger repo's paths. |
| A report you can open from anywhere | Every Sprite has an HTTPS URL routed to port 8080. |

### Two Sprites

```
 you ──► cleanroom-agent (public URL :8080)              cleanroom-worker (private)
          • agent loop, rules → policy                    • runs candidate code
          • SQLite ledger, traces, report      Sprites    • egress: deny * (policy set from outside)
          • GitHub ledger via connector     ──Sprites───► • strace + audit hook
          • Sprites token: 0600 file          API         • checkpoint per run, restore = wipe
                                                          • never sees any token
```

Restoring a checkpoint wipes the worker's whole disk. That is the point (every run starts identical),
and it is why the ledger, traces and report live on the agent Sprite, never on the worker.

## What Clean Room guarantees, and what it does not

Clean Room is built for **your own** candidates: code you or your team wrote, where the question is
"did something slip in by mistake?" (a stray read of the answers, a download, an unseeded model). It
is strong evidence in that cooperative setting. It is **not** a sandbox for hostile code, and its
findings are not proof that a submission is clean.

What a PASS means: on the Sprite worker, the candidate ran as a separate uid (`cr-cand`) under
`strace -f`, from a checkpoint, with egress denial checked from inside the worker (a probe run as the
candidate's uid before the run, and a DNS probe after it); every traced
process exited normally; no traced open, link, rename or network call matched a forbidden rule; and
the output reproduced byte for byte from the same checkpoint.

What it does not cover:

- **Leakage that never touches a forbidden file at run time:** labels already mixed into the training
  data, answers typed into the code, a model trained elsewhere, side channels, or labels rebuilt from
  public data. The demo is built from scikit-learn's public diabetes set, so a candidate could call
  `load_diabetes()` (a file inside the library, not a forbidden file) and match rows to recover every
  label; Clean Room would not flag that.
- **Hostile code.** A determined adversary with kernel bugs, `io_uring` (flagged, not traced), shared
  memory tricks or races between a path check and its use can hide from syscall tracing. Clean Room
  fails closed where it can: a missing, empty, truncated, corrupt or edited trace, a killed tracer or an
  unsafe trace bundle makes the run **INCONCLUSIVE**, never PASS.
- **The audit hook alone is weak evidence.** It runs inside the candidate's own Python process, so a
  child started with `env={}` or code using `ctypes` is invisible to it. A run traced by the audit hook
  only is capped at **WARN** and the headline says so.
- **Reproduction is "reproduced in the recorded environment"**: same checkpoint, same library
  versions, same hardware (the environment fingerprint is recorded with every run). Other machines may
  differ. Clean Room sets `PYTHONHASHSEED=0`; your code must seed its own RNGs.
- **"The output did not need the download"** is only claimed when egress denial was checked for that
  run: a probe as the candidate's uid just before the run (DNS lookup, TCP to 1.1.1.1:443, 8.8.8.8:53
  and 9.9.9.9:443, UDP to 8.8.8.8:53, all refused or failing) and a DNS probe as root after it. It
  is a check of a handful of destinations, not proof that every address was unreachable.
- **Investigation is a one-factor re-run.** It first re-runs the candidate unchanged (the determinism
  baseline), then re-runs with one flagged file hidden. If the baseline already differs, the result is
  "inconclusive", not "the score depends on the file". The report lists which flags were investigated
  and which remain.
- **The honest score is about your holdout**, not the private leaderboard. The 95% interval of the
  top pick is optimistic (it was chosen as the maximum); the paired, id-aligned comparison is the
  better guide. Ranking is by holdout score; seed spread is only a tie-break between equal holdout
  scores (an unmeasured spread loses that tie-break), and a large spread on the pick adds a caution.
- **Rules-to-policy is heuristic.** Every rule keeps its clause id and verbatim quote; restrictive
  clauses that map to no rule are listed as "unmapped" in the policy table. A clause that makes the
  allowed files the only ones ("All other files are off limits", "No other data may be used") becomes
  a `forbid_unlisted_files` rule: reading a data file in the project that is not an allowed file, not
  in `own_files`, not an output and not written by the run itself is then a forbidden read (FAIL, and
  investigated like one). It judges data files inside the project folder only, not libraries or system
  files, and stays unmapped when the rules name no allowed file. An optional LLM pass can
  add rules, but only when its quote appears verbatim in the rules text and names the rule's target.
  An LLM-written verdict is used only if it agrees with the deterministic recommendation. Always read
  the policy table.
- **The holdout truth never goes to the worker.** `holdout.truth` (and anything under `private` in
  `cleanroom.json`) stays on the agent; the policy also forbids reading it, so a candidate that finds
  it anyway fails.

### Backends

- **Sprite worker (use this for evidence):** candidate as uid `cr-cand`; the runner as root collects
  the audit log through a FIFO the candidate can only append to, keeps the trace outside the
  candidate's reach, kills every leftover `cr-cand` process before bundling, and hands back a tar
  bundle that the agent unpacks with path, link and size checks. A Sprite's root has no
  `CAP_SYS_PTRACE`, so strace runs inside a user namespace that maps every uid to itself; there it may
  trace the candidate, while the candidate (a different uid, no capabilities) cannot signal or trace
  strace.
- **Local backend (development only):** by default the candidate runs as *your* uid, so it could edit
  or stop its own trace; every such run carries a WARN. Set `CLEANROOM_CANDIDATE_USER=<user>` (needs
  passwordless `sudo`) to run candidates as a separate user, as on the worker. Egress is an empty
  network namespace (`unshare -n`), all or nothing. The environment is an allowlist (PATH, locale,
  thread settings), the whole process group is killed on timeout, and logs are capped at 8 MB.
  Traces and checkpoints live outside the project, under `~/.local/state/cleanroom/`.

### Sandbox hardening (worker)

- **The Sprite's internal API is hidden.** Every Sprite has a socket at `/.sprite/api.sock` that can
  manage services and checkpoints, and it is world-writable. Each candidate runs in its own mount
  namespace with `/dev/null` bound over that socket, so a connect to it is refused, while the rest of
  `/.sprite` (where the Sprite keeps its Python) stays readable. The runner checks the mask took effect
  (else WARN `mask_failed`), and any traced `connect` to a path under `/.sprite/` fails the run
  (`sandbox_escape_attempt`). A masked directory gets an empty read-only tmpfs instead.
- **No untraced children.** `clone(CLONE_UNTRACED)` would start a process strace never sees. A small
  seccomp filter (`_runner/seccomp_exec.py`) refuses it, refuses `clone3` (so libc falls back to
  `clone`) and refuses non-native syscall ABIs; if the filter cannot be installed the run does not
  start. As a backup, the runner polls for processes of the candidate uid that strace is not tracing
  and marks the run INCONCLUSIVE (`untraced_process`) if it finds one.
- **Resource limits** for the candidate: 1024 processes, 4 GB per file, 4096 open files; the audit log
  is capped at 64 MB (beyond that the run is INCONCLUSIVE, `audit_truncated`).
- Leftover candidate processes are found by the uid in `/proc/<pid>/status` (which a non-dumpable
  process cannot hide) and killed before and after every run.

### Tracing notes

- strace runs as `strace -f -ff -y -xx` over `openat`, `openat2`, `execve`, `execveat`, `connect`,
  `sendto`, `sendmsg`, `sendmmsg`, `symlink*`, `link*`, `rename*`, `unlink*`, `truncate`,
  `chdir`/`fchdir` and `io_uring_setup`. Every per-process trace file must end in an exit record, or
  the run is INCONCLUSIVE.
- Paths are resolved through the working directory and the `-y` file-descriptor decorations; reads
  through a symlink, hard link or rename of a forbidden file count as reads of that file, and a
  post-run scan reports symlinks and hard links that point at forbidden files.
- Non-DNS UDP (`sendto` with an address) and IPv6 addresses count as network attempts. Connects to
  Unix sockets are recorded too.
- A connect (TCP or UDP) or explicit-address send to a loopback address on port 53 counts as a DNS
  lookup through the local resolver (glibc and most DNS libraries connect a UDP socket to the stub
  resolver, then write the query). Other loopback connects stay local and are skipped.
- Not traced: `write`/`writev` themselves (tracing every write would bloat the trace with all file
  output). On a connected UDP socket the connect already records the destination, so what is lost is
  the payload: a lookup sent with connect+write shows as "host name not captured" instead of naming
  the host (`send`, `sendto`, `sendmsg` and `sendmmsg` payloads are still decoded).
- strace lines split by `<unfinished ...>` / `<... resumed>` are joined before parsing; a resumed half
  with no start counts as a parse gap.
- `ptrace` needs permission. When strace cannot attach, the run says `tracer: audit` and is capped at
  WARN.

### Hardening the agent host

The agent Sprite holds the Sprites API token and the ledger, so treat it as the sensitive half:

- Never run candidate code on the agent; only the worker runs it.
- The report service binds to `127.0.0.1` by default; the deploy script passes `--host 0.0.0.0`
  on purpose so the report is reachable at the Sprite's URL. The served page and `report.json` leave out
  raw command lines, trace and work directories, stdout/stderr tails and home paths. Make the agent
  Sprite's URL private (Sprites URL settings) if you do not want the report public.
- The GitHub connector's access policy admits only Sprites named `cleanroom-agent*` and only the
  ledger repo's paths. Anyone who can see the ledger repo can read its issues: use a private repo if
  the verdicts should stay private.
- Keep the agent Sprite single-purpose: no other services, no shell sharing.

### Token rotation

The Sprites token is **org-wide**: it can manage every Sprite in the organisation, including the
worker's network policy. It lives only on the agent Sprite, is read only by the agent loop (the public
report service is started without `SPRITES_TOKEN_FILE`), and should be rotated after a demo or
hackathon. Use a narrower token if Sprites offers one.

The Sprites token lives in `/home/sprite/.config/cleanroom/sprites_token` (mode 0600) on the agent
Sprite only. To rotate it: create a new token at https://sprites.dev/account (or `sprite login`),
re-run `deploy/deploy_sprites.py` with the new token in `SPRITES_TOKEN_FILE`, which overwrites the
file, then revoke the old token. Clean Room re-reads the file after a 401, so a running loop picks up
the new token.

## Run it locally

Requirements: Linux, Python 3.10+, `strace` (optional but recommended), `unshare` (util-linux).

```bash
pip install -e '.[dev]'           # numpy + scikit-learn for the demo, pytest for the tests
sudo apt-get install -y strace    # optional
cd demo
python3 make_data.py              # builds the demo competition from sklearn's built-in diabetes data
cleanroom doctor                  # what isolation + tracing works on this machine
cleanroom agent --serve           # full loop, then serves the report on http://localhost:8080
```

Individual commands:

```bash
cleanroom policy rules.txt                         # rules → policy (add --json for machine output)
cleanroom run --name B -- python3 candidates/b_spline_logreg.py
cleanroom verify B                                 # restore checkpoint, re-run, compare SHA-256
cleanroom investigate A                            # follow up A's red flags
cleanroom report --serve --port 8080
```

Your own competition: put your code, data and `rules.txt` in a folder and add a `cleanroom.json`
(see `demo/cleanroom.json`): output file name, optional holdout predictions + truth for the honest
score, optional leaderboard command, your own extra files (`own_files`) and the candidate commands.
Never upload private competition data anywhere; the Sprite backend copies your project only to your
own worker Sprite.

### The demo competition

Built from scikit-learn's built-in diabetes dataset (Efron et al., 2004; no download). Target: is
disease progression after one year above the median? The bundle "accidentally" ships
`test_labels.csv`, and `host/leaderboard.py` plays the organiser, scoring even ids as the public split.

| Candidate | What it does | Clean Room verdict |
| --- | --- | --- |
| A | logistic regression + "pseudo-labels" that read `test_labels.csv` | FAIL: forbidden file; score depends on it |
| B | spline features + regularised logistic regression, seeded | PASS, reproduced: **recommended** |
| C | gradient boosting that first tries to download "extra rows" | FAIL: network attempt (blocked) |
| D | plain logistic regression | PASS, reproduced |
| E | random forest with no seed | FAIL: output did not reproduce |

## Deploy on Sprites (two-Sprite setup)

You need a Fly.io account with Sprites enabled and a **Sprites API token**
(`sprite login`, or create one at https://sprites.dev/account; format
`org-slug/org-id/token-id/token-value`). A general Fly.io org token (`FlyV1 fm2_…`) is not accepted by
the Sprites API.

```bash
curl -fsSL https://sprites.dev/install.sh | sh     # sprite CLI (optional, handy for inspection)
export SPRITES_TOKEN_FILE=~/path/to/token          # a 0600 file; never commit or print the token
python3 demo/make_data.py
python3 deploy/deploy_sprites.py
```

`deploy/deploy_sprites.py` does, through the documented Sprites REST API:

1. creates `cleanroom-worker` (private URL) and `cleanroom-agent` (public URL);
2. sets the worker's network policy to `{"rules":[{"domain":"*","action":"deny"}]}`;
3. writes your Sprites token to `/home/sprite/.config/cleanroom/sprites_token` on the **agent** Sprite,
   mode 0600, as the body of an fs-write request (never in a URL, command line, log or the report).
   The agent reads it through `SPRITES_TOKEN_FILE`;
4. uploads Clean Room + the demo to the agent and installs it;
5. registers a Sprite **service** on port 8080 serving the live report;
6. starts `cleanroom --backend sprite agent` detached on the agent Sprite, holding a Tasks API
   heartbeat so the Sprite does not pause, and follows its log (a long single HTTP exec gets dropped
   by the proxy). The ledger state in `demo/.cleanroom` is kept across redeploys.

**Why not a connector for the Sprites token?** The first version wrapped the Sprites API in a
Custom API connector so the agent would never hold the token. The Sprites gateway refuses that
(`403 blocked: base URL targets the Sprites API itself`), so the token lives in a private file on the
agent Sprite instead. The worker, which runs the untrusted code, never receives it: Clean Room passes
candidates only the variables it sets itself.

During `prepare`, the agent briefly opens the worker's egress to the platform defaults
(`{"include":"defaults"}`) to install `strace` and the demo's Python packages, then sets the
deny policy derived from the rules and verifies it from inside (`/.sprite/policy/network.json` and a DNS
probe that must be refused) *before* any candidate runs.

Manual equivalent with the CLI:

```bash
sprite create cleanroom-worker && sprite create cleanroom-agent
curl -X POST https://api.sprites.dev/v1/sprites/cleanroom-worker/policy/network \
  -H "Authorization: Bearer $SPRITES_TOKEN" -H 'Content-Type: application/json' \
  -d '{"rules":[{"domain":"*","action":"deny"}]}'
sprite -s cleanroom-agent exec -- bash -c 'cd ~/cleanroom/demo && cleanroom --backend sprite agent'
```

### The Sprites connector: GitHub ledger

Clean Room's Sprites connector is **GitHub** (OAuth). Every session, the agent Sprite opens one issue
per candidate in a ledger repo: verdict, session, checkpoint, output SHA-256, reproduction result,
tracer and candidate uid, environment fingerprint, the rule clauses quoted word for word and the
trace lines behind each finding (redacted: no raw command lines or home paths; candidate-controlled
text is Markdown-escaped). Publishing is idempotent: re-publishing an unchanged session changes
nothing, and a session whose result changed gets a **revision record** appended to its existing issue
(the earlier record stays in the issue unchanged; the new one names it in `supersedes`). Each record is
canonical JSON with a sequence number, its SHA-256 and the SHA-256 of the record published before it,
so the records form a hash chain across all issues. Only a marker that is a whole line and whose JSON
block hashes to it is trusted, so text inside evidence cannot pose as a record. Check the chain any time:

```bash
cleanroom verify-chain --repo you/cleanroom-ledger   # public API for a public repo; exit 1 if broken
```

It re-hashes every record, and checks the JSON against its marker, the sequence (1, 2, 3, ... with no
gaps), every `previous_issue_sha256` link and every `supersedes` reference. That is tamper-evident (an
edit or a deleted issue breaks the chain, and GitHub keeps an edit history), not tamper-proof: nothing
is signed or externally timestamped, and someone with write access could rewrite the whole chain. The
report links each
candidate to its issue, so a decision you made before a deadline stays on record outside the Sprites.

The Sprite never holds a GitHub token. It calls
`https://api.sprites.dev/v1/gateway/github/<connection_id>/repos/<owner>/<repo>/issues` with no
`Authorization` header; the gateway identifies the calling Sprite, checks the connector's access policy
and attaches the stored credential.

Setup:

1. In the Sprites dashboard, add a **GitHub** connector and approve the OAuth screen.
2. Create a repo for the ledger (for example `you/cleanroom-ledger`). Its issues are visible to
   anyone who can see the repo; make it private if the verdicts should be.
3. Deploy with the ledger turned on:

   ```bash
   python3 deploy/deploy_sprites.py --publish --github-repo you/cleanroom-ledger
   ```

   The script finds the GitHub connector through `GET /v1/oauth/connections` and pins its access
   policy to `{"name_prefix": "cleanroom-agent", "allowed_endpoints": ["/repos/you/cleanroom-ledger",
   "/repos/you/cleanroom-ledger/*"]}`. Only the agent Sprite can use the connector, and only for that
   repo. The worker, which runs untrusted code, is not admitted, and its egress is denied anyway. The
   script then checks from inside the agent Sprite that the ledger repo answers 200 and that a path
   outside the allow-list (`/user`) is refused. Finally it passes `CLEANROOM_GITHUB_GATEWAY` and
   `CLEANROOM_GITHUB_REPO` to the agent and runs `cleanroom agent --publish`.

Without `--publish`, the issue payloads are written to `.cleanroom/outbox/` for review and nothing is
posted. Optionally, an LLM connector (OpenRouter, or Ollama Cloud through a custom API connector) can
write the plain-language verdict and run an extra rules pass, via `CLEANROOM_LLM_BASE_URL` /
`CLEANROOM_LLM_MODEL`. The live run below did not use one.

### Sprite deployment status (live run, 26 Nov 2026)

The full 7-step loop has run on real Sprites (`cleanroom-agent` driving `cleanroom-worker`); the
latest log (session `cr-20261126-065726-c1fc`, with the sandbox hardening above) is in
`docs/sample_sprite_run.txt`. Checked live:

- **Sandbox hardening:** for every candidate run the worker recorded `mask: hidden` for
  `/.sprite/api.sock`, `seccomp: on`, no untraced processes, the rlimits, and an egress probe as
  `cr-cand` with DNS refused and every TCP/UDP destination blocked. A first attempt that masked all of
  `/.sprite` failed closed on every candidate (the Sprite's Python lives under `/.sprite/languages`),
  which is why only the socket is masked now.
- **Egress denied:** with the `deny *` policy, inside the worker DNS is refused, HTTPS to
  example.com fails and a raw-IP connect to 1.1.1.1:443 fails. Candidate C's DNS queries for
  `raw.githubusercontent.com` show up in strace and go unanswered.
- **Separate candidate uid:** every candidate ran as `cr-cand` (`candidate uid separate`), traced by
  strace from inside a uid-mapping user namespace (a Sprite's root has no `CAP_SYS_PTRACE`, so plain
  `strace -u` is refused), plus the audit hook through a root-drained FIFO.
- **Exec reply format:** the non-TTY HTTP exec returns frames: `0x01`+stdout, `0x02`+stderr,
  then `0x03`+one exit-code byte. That is parsed by `parse_exec_stream`. The parser is meant for text
  output: a `0x01`/`0x02` byte inside binary output would be read as a stream switch, so Clean Room
  moves anything binary through the filesystem API instead. Results come back as a tar
  bundle through the filesystem API and are unpacked with path, link and size checks.
- **Checkpoint / restore:** restoring wipes files written after the checkpoint, and every candidate
  ran from the same checkpoint.
- **Network policy survives a restore:** the API still reports `deny *` after a restore, and the DNS
  probe taken after every restored run says `refused`.
- **Holdout truth stays on the agent:** `host/valid_labels.csv` is never uploaded to the worker, and
  the policy forbids reading it.
- **GitHub connector:** the verdicts of session `cr-20261126-025756-c53f` were posted through the
  Sprites GitHub connector as issues #6–#10 in the public ledger repo `Mzee04/cleanroom-ledger`
  (records 1–5), and those of session `cr-20261126-065726-c1fc` as issues #11–#15 (records 6–10),
  chained on from #10. `cleanroom verify-chain --repo Mzee04/cleanroom-ledger` reports
  `chain OK: 10 records`. Issues #1–#5, from an earlier version without sessions or records, are
  closed with links to their replacements and carry no records. From inside the
  agent Sprite, the gateway answered 200 for the ledger repo and 403 for `/user`, which is outside the
  allow-list.
- **Result:** B recommended (holdout ROC AUC 0.7855, 95% CI 0.687–0.874, reproduced from checkpoint
  v106); A fails (reads
  `test_labels.csv`, and its leaderboard score drops from 0.9200 to 0.8252 without it); C fails (DNS
  for `raw.githubusercontent.com`, output produced with egress denial verified); E fails reproduction.

Known quirks:
- `/.sprite/policy/network.json` was not present inside the worker even though the policy was
  enforced, so Clean Room checks enforcement by probing rather than by reading that file.
- A Sprite pauses about 30 s after the last activity and a paused Sprite freezes or drops background
  processes, and one long HTTP exec gets dropped after a few minutes. So every candidate run is
  started detached and polled in short blocking steps, and the runner (and the deploy script's agent
  loop) holds a Sprites Tasks API heartbeat (`/.sprite/api.sock`, `PUT /v1/tasks/<name>`) while it works.
- The Sprite's default `python3` is a pyenv build behind a shim; Clean Room links that interpreter
  into `/srv/cr/pybin` for the candidate user.

## Layout

```
cleanroom/            the package
  policy.py           rules → policy (deterministic) + optional LLM merge
  trace.py            strace (-ff -xx) and audit-hook parsing, DNS query decoding
  checks.py           findings: forbidden files, network, run status, reproduction
  backends/           Backend interface; LocalBackend; SpriteBackend (Sprites API client)
  engine.py           run / verify / investigate / seeds, recorded in the SQLite ledger
  agent.py            the 7-step agent loop
  summary.py, recommend.py, scoring.py, report.py, ghledger.py, llm.py, cli.py
  redact.py           redaction and Markdown escaping for the report and the ledger
  _hook/sitecustomize.py   the Python audit hook injected into candidate runs
  _runner/runner.py   the stdlib-only runner both backends use (uid switch, strace, FIFO, bundle)
demo/                 mock competition: rules.txt, cleanroom.json, candidates A–E, host leaderboard
deploy/               two-Sprite deploy script
tests/                pytest suite
```

## Licence

MIT, see [LICENSE](LICENSE).
