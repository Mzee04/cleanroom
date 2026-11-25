"""Optional LLM support through any OpenAI-compatible chat endpoint.

Configure with environment variables (nothing is required):

  CLEANROOM_LLM_BASE_URL   e.g. https://ollama.com/v1, or a Sprites connector
                           gateway URL such as
                           https://api.sprites.dev/v1/gateway/openrouter/<conn_id>/api/v1
  CLEANROOM_LLM_MODEL      model name
  CLEANROOM_LLM_API_KEY    optional; not needed when calling through a Sprites
                           connector gateway (the gateway holds the credential)

The key is only sent as an Authorization header and is never logged.
"""
from __future__ import annotations

import json
import os
import urllib.request


def configured() -> bool:
    return bool(os.environ.get("CLEANROOM_LLM_BASE_URL") and os.environ.get("CLEANROOM_LLM_MODEL"))


def describe() -> str:
    base = os.environ.get("CLEANROOM_LLM_BASE_URL", "")
    host = base.split("/")[2] if "://" in base else base
    return f"{os.environ.get('CLEANROOM_LLM_MODEL')} via {host}"


def chat(messages: list[dict], *, json_mode: bool = False, timeout: int = 60) -> str:
    base = os.environ["CLEANROOM_LLM_BASE_URL"].rstrip("/")
    body = {"model": os.environ["CLEANROOM_LLM_MODEL"], "messages": messages, "temperature": 0}
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    req = urllib.request.Request(base + "/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    key = os.environ.get("CLEANROOM_LLM_API_KEY")
    if key:
        req.add_header("Authorization", "Bearer " + key)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


RULES_PROMPT = """You turn machine-learning competition rules into a JSON policy.
Return {"rules": [...]} where each item has:
  kind: one of forbid_file, allow_file, deny_network, allow_host, forbid_host,
        forbid_external_data, allow_external_data, require_reproducible
  target: file name/glob or host name ("" when not applicable)
  clause_id: the clause number if present
  quote: the exact sentence from the rules, copied verbatim
Only include rules the text actually states. Do not paraphrase quotes."""


def extract_rules(text: str) -> list[dict]:
    out = chat([{"role": "system", "content": RULES_PROMPT},
                {"role": "user", "content": text}], json_mode=True)
    return json.loads(out).get("rules", [])


VERDICT_PROMPT = """You are Clean Room, a submission integrity agent. Write a short
plain-language verdict (max 120 words) for the competitor from the JSON evidence.
Rules: never say a submission is "clean" or "guaranteed"; say "no forbidden access
detected" instead. A hash match proves reproduction in that environment only.
Recommend the candidate named in `recommended` and say why, citing findings."""


def verdict(evidence: dict) -> str:
    return chat([{"role": "system", "content": VERDICT_PROMPT},
                 {"role": "user", "content": json.dumps(evidence)[:12000]}])
