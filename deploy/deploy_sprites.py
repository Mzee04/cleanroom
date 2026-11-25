#!/usr/bin/env python3
"""Deploy Clean Room as two Sprites. NOT YET LIVE-TESTED (see README).

  cleanroom-worker  runs candidate code. Egress: deny-by-default network policy,
                    set from outside via the Sprites API. Holds nothing you need
                    to keep: every run restores a checkpoint, which wipes its disk.
  cleanroom-agent   runs the agent loop, the SQLite ledger and the report
                    (public URL, port 8080). Drives the worker through a Sprites
                    Custom API connector, so it never holds your Sprites token.

Requires: SPRITES_TOKEN = a Sprites API token (org-slug/org-id/token-id/value,
from `sprite login` or https://sprites.dev/account). Never printed.

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
    ap.add_argument("--no-connector", action="store_true",
                    help="pass the token to the agent Sprite instead of using a connector (not recommended)")
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

    # 2. connector wrapping the Sprites API, usable only by the agent, only for the worker
    env = {"CLEANROOM_WORKER": args.worker, "PYTHONUNBUFFERED": "1"}
    if args.no_connector:
        env["SPRITES_TOKEN"] = api._token  # noqa: SLF001  (explicit opt-in)
        log("WARNING: token passed to the agent Sprite environment")
    else:
        body = {"name": "cleanroom-sprites-api", "base_api_url": "https://api.sprites.dev",
                "access_token": api._token, "auth_method": "header", "auth_header_prefix": "Bearer",  # noqa: SLF001
                "test_url": f"https://api.sprites.dev/v1/sprites/{args.worker}",
                "description": "Clean Room agent -> worker control (checkpoint, restore, exec, fs, policy)",
                "access_policy": {"name_prefix": args.agent,
                                  "allowed_endpoints": [f"/v1/sprites/{args.worker}", f"/v1/sprites/{args.worker}/*"]}}
        conn = json.loads(api.request("POST", "/v1/oauth/connections/custom_api", body=body)[1])["connection"]
        env["CLEANROOM_SPRITES_API"] = f"https://api.sprites.dev/v1/gateway/{conn['provider']}/{conn['id']}"
        log(f"connector {conn['id']} ({conn['provider']}): agent-only, worker-only endpoints")

    # 3. code + demo onto the agent
    api.write_file(args.agent, "/tmp/cleanroom.tgz", bundle())
    out = api.exec(args.agent, ["bash", "-c",
                                f"rm -rf {REMOTE} && mkdir -p {REMOTE} && tar -xzf /tmp/cleanroom.tgz -C {REMOTE} && "
                                f"cd {REMOTE} && (python3 -m pip install -q --break-system-packages -e . "
                                f"|| python3 -m pip install -q -e .) 2>&1 | tail -2; echo deployed-ok"], timeout=600)
    log("agent install:", out.decode(errors="replace").strip()[-200:])

    # 4. the report service on port 8080 (the Sprite's public URL port)
    svc = {"cmd": "bash", "args": ["-lc", f"cd {REMOTE}/demo && python3 -m cleanroom --backend sprite report --serve "
                                          "--host 0.0.0.0 --port 8080"],
           "http_port": 8080, "needs": [], "dir": f"{REMOTE}/demo", "env": env}
    api.request("PUT", f"/v1/sprites/{args.agent}/services/cleanroom-report", body=svc)
    info = api.get_sprite(args.agent) or {}
    log("report URL:", info.get("url"))

    if not args.no_run:
        log("running the agent loop on the agent Sprite (several minutes)…")
        env_args = " ".join(f"{k}={v!r}" for k, v in env.items() if k != "SPRITES_TOKEN")
        cmd = f"cd {REMOTE}/demo && env {env_args} python3 -m cleanroom --backend sprite agent 2>&1 | tail -40"
        t0 = time.time()
        try:
            print(api.exec(args.agent, ["bash", "-c", cmd], timeout=3600).decode(errors="replace"))
        except SpritesAPIError as e:
            log("agent run error:", e)
        log(f"agent finished in {time.time() - t0:.0f}s; open {info.get('url')}")


if __name__ == "__main__":
    main()
