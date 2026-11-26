#!/usr/bin/env python3
"""Deploy Clean Room as two Sprites.

  cleanroom-worker  runs candidate code. Egress: deny-by-default network policy,
                    set from outside via the Sprites API. Holds nothing you need
                    to keep: every run restores a checkpoint, which wipes its disk.
  cleanroom-agent   runs the agent loop, the SQLite ledger and the report
                    (public URL, port 8080: the report page is public by
                    choice; the served JSON leaves out raw commands, home
                    paths and stdout/stderr tails). The ledger state
                    (demo/.cleanroom) is kept across redeploys. Drives the worker over the Sprites
                    API with a token kept in a private 0600 file on the agent
                    Sprite (written through the fs API, never on a command
                    line). The Sprites connector gateway refuses to wrap the
                    Sprites API itself, so a connector cannot hold this token.
                    The worker never receives it.

Requires a Sprites API token (org-slug/org-id/token-id/value, from
`sprite login` or https://sprites.dev/account) in SPRITES_TOKEN_FILE (a path)
or SPRITES_TOKEN. Never printed.

  python3 deploy/deploy_sprites.py            # create/update everything + run the demo once
  python3 deploy/deploy_sprites.py --no-run   # deploy only
  python3 deploy/deploy_sprites.py --publish --github-repo owner/repo
        # also post one issue per candidate through the Sprites GitHub connector
        # (re-running the same session updates its issues instead of duplicating them)

Long runs: a Sprite pauses ~30 s after the last activity and a paused Sprite
freezes (warm) or drops (cold) background processes. The agent loop and every
candidate run therefore hold a Sprites Tasks API heartbeat while they work.

Token rotation: revoke the token at https://sprites.dev/account, create a new
one and re-run this script; it rewrites the agent's token file.

GitHub ledger: connect GitHub once in the Sprites dashboard (OAuth). This script
finds that connector, makes sure its access policy only admits Sprites named
`cleanroom-agent*` and only paths under the ledger repo, and hands the agent the
gateway URL (no token: the gateway attaches GitHub's credential itself).
"""
from __future__ import annotations

import argparse
import http.client
import io
import json
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cleanroom.backends.sprite import SpritesAPI, SpritesAPIError  # noqa: E402

SKIP = {".git", ".cleanroom", "__pycache__", ".pytest_cache", "build", "dist", "outbox"}
REMOTE = "/home/sprite/cleanroom"


def bundle() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for p in ["pyproject.toml", "README.md", "cleanroom", "demo"]:
            tf.add(ROOT / p, arcname=p, filter=lambda ti: None if any(
                part in SKIP or part.endswith(".egg-info") for part in Path(ti.name).parts) else ti)
    return buf.getvalue()


def github_connector(api: SpritesAPI, agent: str, repo: str) -> str:
    """Find the GitHub connector, pin its access policy, return the gateway base URL."""
    conns = [c for c in json.loads(api.request("GET", "/v1/oauth/connections")[1]).get("connections", [])
             if c.get("provider") == "github"]
    if not conns:
        raise SystemExit("no GitHub connector: connect GitHub in the Sprites dashboard first")
    conn = conns[0]
    policy = {"name_prefix": agent, "allowed_endpoints": [f"/repos/{repo}", f"/repos/{repo}/*"]}
    have = conn.get("access_policy") or {}
    if have.get("name_prefix") != agent or sorted(have.get("allowed_endpoints") or []) != sorted(
            policy["allowed_endpoints"]) or have.get("allow_all"):
        api.request("PUT", f"/v1/oauth/connections/{conn['id']}", body={"access_policy": policy})
        log("GitHub connector access policy set:", json.dumps(policy))
    else:
        log("GitHub connector access policy already:", json.dumps(have))
    log("GitHub connector account:", conn.get("provider_account_name"), "· scopes:", conn.get("scopes"))
    return f"https://api.sprites.dev/v1/gateway/github/{conn['id']}"


def gateway_status(api: SpritesAPI, sprite: str, url: str) -> str:
    """HTTP status of a gateway GET made from inside a Sprite (body discarded)."""
    out, _, _ = api.exec_result(sprite, ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                                         "--max-time", "20", url], timeout=60)
    return out.strip() or "no response"


def log(*a):
    print("[deploy]", *a, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker", default="cleanroom-worker")
    ap.add_argument("--agent", default="cleanroom-agent")
    ap.add_argument("--no-run", action="store_true")
    ap.add_argument("--publish", action="store_true", help="post the verdicts to the GitHub ledger")
    ap.add_argument("--github-repo", default="", help="owner/repo of the ledger (its issues are visible to anyone who can see the repo)")
    args = ap.parse_args()
    api = SpritesAPI()

    for name, public in ((args.worker, False), (args.agent, True)):
        if api.get_sprite(name) is None:
            api.create_sprite(name, public_url=public)
            log("created sprite", name, "(public URL)" if public else "(private URL)")
        else:
            log("sprite exists:", name)
    if not (ROOT / "demo" / "data" / "train.csv").exists():
        raise SystemExit("run `python3 demo/make_data.py` first (needs scikit-learn locally)")

    # 1. worker egress: deny everything until the agent opens setup egress itself
    api.set_network_policy(args.worker, {"rules": [{"domain": "*", "action": "deny"}]})
    log("worker network policy:", json.dumps(api.get_network_policy(args.worker)))

    # 2. the agent's credential: a private file on the agent Sprite (body of an fs write, not a URL/argv)
    token_path = "/home/sprite/.config/cleanroom/sprites_token"
    api.write_file(args.agent, token_path, (api._token + "\n").encode(), mode="0600")  # noqa: SLF001
    out, err, code = api.exec_result(args.agent, ["bash", "-c", f"stat -c '%a %U' {token_path}"])
    log("agent token file:", out.strip(), "(mode, owner)")
    env = {"CLEANROOM_WORKER": args.worker, "PYTHONUNBUFFERED": "1", "SPRITES_TOKEN_FILE": token_path}

    # 2b. the GitHub ledger through the Sprites GitHub connector (the Sprite never holds a GitHub token)
    if args.github_repo:
        gw = github_connector(api, args.agent, args.github_repo)
        env.update({"CLEANROOM_GITHUB_GATEWAY": gw, "CLEANROOM_GITHUB_REPO": args.github_repo})
        log("gateway check from the agent, ledger repo:",
            gateway_status(api, args.agent, f"{gw}/repos/{args.github_repo}"), "(expect 200)")
        log("gateway check from the agent, outside the allow-list (/user):",
            gateway_status(api, args.agent, f"{gw}/user"), "(expect a refusal)")

    # 3. code + demo onto the agent
    api.write_file(args.agent, "/tmp/cleanroom.tgz", bundle())
    keep = "/home/sprite/.cleanroom-keep"
    out = api.exec(args.agent, ["bash", "-c",
                                f"rm -rf {keep} && if [ -d {REMOTE}/demo/.cleanroom ]; then "
                                f"mv {REMOTE}/demo/.cleanroom {keep}; fi && "
                                f"rm -rf {REMOTE} && mkdir -p {REMOTE} && tar -xzf /tmp/cleanroom.tgz -C {REMOTE} && "
                                f"if [ -d {keep} ]; then mv {keep} {REMOTE}/demo/.cleanroom; fi && "
                                f"cd {REMOTE} && (python3 -m pip install -q --break-system-packages -e . "
                                f"|| python3 -m pip install -q -e .) 2>&1 | tail -2; echo deployed-ok"], timeout=600)
    log("agent install:", out.decode(errors="replace").strip()[-200:].replace("\x01", "").replace("\x02", ""))

    # 4. the report service on port 8080 (the Sprite's public URL port)
    svc = {"cmd": "bash", "args": ["-lc", f"cd {REMOTE}/demo && python3 -m cleanroom --backend sprite report --serve "
                                          "--host 0.0.0.0 --port 8080"],
           "http_port": 8080, "needs": [], "dir": f"{REMOTE}/demo", "env": env}
    api.request("PUT", f"/v1/sprites/{args.agent}/services/cleanroom-report", body=svc)
    try:  # pick up the freshly uploaded code
        api._ndjson("POST", f"/v1/sprites/{args.agent}/services/cleanroom-report/restart")  # noqa: SLF001
        log("report service restarted")
    except SpritesAPIError as e:
        log("report service restart:", str(e)[:160])
    info = api.get_sprite(args.agent) or {}
    log("report URL:", info.get("url"))

    if not args.no_run:
        # Detached: a long HTTP exec gets dropped by the proxy after a few minutes, so the loop runs
        # under setsid on the agent Sprite and we poll its log file.
        env_args = " ".join(f"{k}={v!r}" for k, v in env.items())
        logf = f"{REMOTE}/agent-run.log"
        wrapper = (
            "#!/bin/bash\n"
            "api() { curl -s --max-time 10 --unix-socket /.sprite/api.sock -H Content-Type:application/json "
            "\"$@\" >/dev/null 2>&1; }\n"
            "( while true; do api -X PUT http://sprite/v1/tasks/cleanroom-agent-loop -d '{\"expire\":\"5m\"}'; "
            "sleep 45; done ) &\n"
            "HB=$!\n"
            "trap 'kill $HB 2>/dev/null; api -X DELETE http://sprite/v1/tasks/cleanroom-agent-loop' EXIT\n"
            f"cd {REMOTE}/demo && python3 -m cleanroom --backend sprite agent \"$@\"\n")
        api.write_file(args.agent, f"{REMOTE}/run-agent.sh", wrapper.encode(), mode="0755")
        # one simple command in the background, every fd redirected: a backgrounded `a && b` list
        # would be a subshell holding the exec's stdout open, so the exec would never return
        start_cmd = (f"rm -f {logf}; setsid nohup env {env_args} {REMOTE}/run-agent.sh"
                     f"{' --publish' if args.publish else ''} > {logf} 2>&1 < /dev/null & echo started")
        try:
            log("starting the agent loop on the agent Sprite:",
                api.exec_result(args.agent, ["bash", "-c", start_cmd], timeout=60)[0].strip())
        except Exception as e:  # noqa: BLE001 - a dropped reply does not mean the loop did not start
            log("start reply dropped (", type(e).__name__, "); following the log anyway")
        t0, seen = time.time(), 0
        while time.time() - t0 < 3600:
            time.sleep(20)
            try:
                text = api.exec_result(args.agent, ["bash", "-c", f"cat {logf}"], timeout=60)[0]
            except (SpritesAPIError, OSError, http.client.HTTPException) as e:
                log("poll error (will retry):", type(e).__name__)
                continue
            lines = text.splitlines()
            for line in lines[seen:]:
                print("  │ " + line, flush=True)
            seen = len(lines)
            if "Done in" in text or "Traceback" in text:
                break
        log(f"agent loop finished after {time.time() - t0:.0f}s; report: {info.get('url')}")

if __name__ == "__main__":
    main()
