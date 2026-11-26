"""Redaction and Markdown escaping for anything that leaves the agent.

Commands, trace lines and paths come from candidate code or the operator's
machine. Before they reach the public report or a GitHub issue:

* command arguments that might hold secrets are replaced (``redact_cmd``),
* home directories and token-shaped strings are masked (``redact_text``),
* candidate-controlled text is escaped so it cannot break out of Markdown,
  ping people (@mentions) or embed images/links (``md_text``, ``md_code``).
"""
from __future__ import annotations

import os
import re

HOME_RE = re.compile(r"(/home/|/Users/)[^/\s\"'<>]+|/root(?=/|\b)")
SECRETISH = [
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b"),
    re.compile(r"\bFlyV1 [A-Za-z0-9+/=_,-]{16,}"),
    re.compile(r"\b[\w-]+/\d+/[\w-]+/[A-Za-z0-9+/=_-]{24,}\b"),       # Sprites token shape
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{12,}"),
]
SECRET_ARG = re.compile(r"(?i)(token|secret|passw|api[_-]?key|auth|credential|cookie|session)")
SAFE_ARG = re.compile(r"^[\w.,:+=/@%-]{1,120}$")


def redact_text(s: str) -> str:
    if not s:
        return s
    s = HOME_RE.sub("~", str(s))
    for rx in SECRETISH:
        s = rx.sub("<redacted>", s)
    return s


def redact_cmd(cmd: list[str] | None) -> list[str]:
    """Keep the shape of a command, drop anything that could be a secret.

    Kept: the program name, relative paths and short plain flags. Replaced:
    ``--token=...``/``--api-key VALUE`` style secrets, long opaque strings and
    absolute paths (shown as ``<path>/name``).
    """
    out: list[str] = []
    hide_next = False
    for i, a in enumerate(cmd or []):
        a = str(a)
        if hide_next:
            out.append("<redacted>")
            hide_next = False
            continue
        if i == 0:
            out.append(os.path.basename(a) or a)
            continue
        if a.startswith("-") and SECRET_ARG.search(a.split("=", 1)[0]):
            if "=" in a:
                out.append(a.split("=", 1)[0] + "=<redacted>")
            else:
                out.append(a)
                hide_next = True
            continue
        if "=" in a and SECRET_ARG.search(a.split("=", 1)[0]):
            out.append(a.split("=", 1)[0] + "=<redacted>")
            continue
        if os.path.isabs(a):
            out.append("<path>/" + os.path.basename(a))
            continue
        if not SAFE_ARG.match(a) or (len(a) >= 32 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", a)):
            out.append("<arg redacted>")
            continue
        out.append(redact_text(a))
    return out


# ---- Markdown ---------------------------------------------------------------
MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~])")


def md_text(s) -> str:
    """Escape for inline Markdown: no formatting, links, images, HTML or @mentions."""
    s = redact_text(str(s if s is not None else ""))
    s = s.replace("\r", " ").replace("\n", " ")
    s = MD_SPECIAL.sub(r"\\\1", s)
    return s.replace("@", "@\u200b")  # zero-width space: GitHub does not treat it as a mention


def md_code_block(lines, lang: str = "") -> str:
    """A fenced block whose fence is longer than any backtick run inside it."""
    text = "\n".join(redact_text(str(x)) for x in lines)
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{text}\n{fence}"


def md_inline_code(s) -> str:
    s = redact_text(str(s if s is not None else "")).replace("\n", " ")
    longest = max((len(m) for m in re.findall(r"`+", s)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{ticks}{pad}{s}{pad}{ticks}"
