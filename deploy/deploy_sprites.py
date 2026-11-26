#!/usr/bin/env python3
"""Deploy Clean Room as two Sprites.

  cleanroom-worker  runs candidate code. Egress: deny-by-default network policy,
                    set from outside via the Sprites API. Holds nothing you need
                    to keep: every run restores a checkpoint, which wipes its disk.
  cleanroom-agent   runs the agent loop, the SQLite ledger and the report
                    (public URL, port 8080). Drives the worker over the Sprites
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
"""
from __future__ import annotations

import argparse
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


def log(*a):
    print("[deploy]", *a, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker", default="cleanroom-worker")
    ap.add_argument("--agent", default="cleanroom-agent")
    ap.add_argument("--no-run", action="store_true")
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

    # 3. code + demo onto the agent
    api.write_file(args.agent, "/tmp/cleanroom.tgz", bundle())
    out = api.exec(args.agent, ["bash", "-c",
                                f"rm -rf {REMOTE} && mkdir -p {REMOTE} && tar -xzf /tmp/cleanroom.tgz -C {REMOTE} && "
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
        start_cmd = (f"cd {REMOTE}/demo && rm -f {logf} && setsid nohup env {env_args} python3 -m cleanroom "
                     f"--backend sprite agent > {logf} 2>&1 < /dev/null & echo started")
        log("starting the agent loop on the agent Sprite:", api.exec_result(args.agent, ["bash", "-c", start_cmd])[0].strip())
        t0, seen = time.time(), 0
        while time.time() - t0 < 3600:
            time.sleep(20)
            try:
                text = api.exec_result(args.agent, ["bash", "-c", f"cat {logf}"], timeout=60)[0]
            except (SpritesAPIError, OSError) as e:
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
