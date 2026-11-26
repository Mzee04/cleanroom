"""Rules-to-policy: turn a competition's rules text into checkable rules.

Every extracted rule keeps the clause id and the exact quote it came from, so
each finding in the report can cite the rule it relies on.

Extraction is deterministic (regex + keyword heuristics) and needs no API key.
An LLM can optionally add rules through an OpenAI-compatible endpoint (see
``cleanroom.llm``); LLM output is only accepted when its quote really appears
in the rules text.
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

KINDS = (
    "forbid_file",         # target: file name or glob that must not be read
    "allow_file",          # target: file name or glob that may be read
    "deny_network",        # no internet / offline evaluation
    "allow_host",          # target: host that may be contacted
    "forbid_host",         # target: host that must not be contacted
    "forbid_external_data",
    "allow_external_data",
    "require_reproducible",  # seeds fixed / results must be reproducible
)

NEG = re.compile(
    r"\b(must not|may not|shall not|should not|cannot|can ?not|can't|do not|don't|"
    r"never|not (?:be )?(?:permitted|allowed|used|accessed|read)|"
    r"prohibited|forbidden|disallowed|banned|disabled|no access|not available|"
    r"is not allowed|are not allowed|strictly for|only for (?:the )?organi[sz]er|"
    r"for organi[sz]er (?:use|scoring) only|organi[sz]ers? only|offline)\b",
    re.I,
)
POS = re.compile(
    r"\b(may use|may be used|may read|may download|may access|can use|can be used|"
    r"are free to|is free to|permitted|allowed|you may|participants may|is fine|are fine|"
    r"encouraged|whitelisted|allow-?listed)\b",
    re.I,
)
FILE_RE = re.compile(
    r"(?<![\w/.-])((?:[\w*-]+/)*[\w*-]+\.(?:csv|tsv|parquet|jsonl|json|txt|npy|npz|pkl|"
    r"pickle|feather|zip|gz|h5|hdf5|xlsx|xls|arrow))\b",
    re.I,
)
TLDS = "com|org|net|io|ai|dev|co|gov|edu|africa|uk|de|fr|in|info|app|xyz|cloud|us|ca|za|ke|ng"
HOST_RE = re.compile(
    r"(?:https?://)?\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:" + TLDS + r"))\b(?![\w-])",
    re.I,
)
INTERNET_RE = re.compile(
    r"\b(internet|network access|network calls?|outbound|external (?:apis?|services?|hosts?|requests?)|"
    r"web requests?|online (?:apis?|services?)|http requests?)\b",
    re.I,
)
EXTDATA_RE = re.compile(
    r"\b(external data(?:sets?)?|third[- ]party data(?:sets?)?|additional data(?:sets?)?|"
    r"outside data|other data sources?|pre-?trained (?:models?|weights))\b",
    re.I,
)
# File rules need more than a negation somewhere in the sentence: the negation has to bear on
# *access* ("must not be read", "do not use"), or the file has to be called restricted. This keeps
# "test.csv does not contain labels" from forbidding test.csv.
FILE_NEG = re.compile(
    r"\b(?:(?:must|may|shall|should|can|do|does|is|are|will)\s*(?:not|n't)|cannot|never|nor|no one may)\s+"
    r"(?:\w+\s+){0,3}?(?:use|used|using|read|reading|access|accessed|accessing|open|opened|opening|load|"
    r"loaded|loading|download|downloaded|touch|touched|inspect|inspected|copy|copied|look at|consult)\b|"
    r"\b(?:prohibited|forbidden|disallowed|banned|off[- ]limits|not (?:be )?(?:permitted|allowed)|"
    r"restricted to|reserved for|withheld|kept (?:private|secret|hidden)|confidential|strictly for|"
    r"(?:only )?for (?:the )?organi[sz]ers?(?:'|\u2019)?(?: \w+)? (?:use |scoring )?only|organi[sz]ers? only|"
    r"only for (?:the )?organi[sz]ers?|no access|violat\w*|disqualif\w*|breach\w*|"
    r"not to be (?:used|read|accessed|opened|loaded))\b"
    r"|^\W*not\b",       # "... train.csv but not test_labels.csv" (the split leaves "not test_labels.csv")
    re.I,
)
# Words that only say a file exists or was handed out. They do not grant permission when the
# same clause also restricts access ("test_labels.csv is provided but must not be read").
WEAK_POS = re.compile(r"\b(provided|supplied|available to participants|included|shipped)\b", re.I)
FILE_POS = re.compile(
    r"\b(may use|may be used|may read|may load|may access|can use|can be used|are free to|is free to|"
    r"permitted|allowed|you may|participants may|is fine|are fine|encouraged|provided|supplied|"
    r"available to participants)\b",
    re.I,
)
# Sentences that withhold labels without naming a file still forbid label files.
WITHHELD_LABELS_RE = re.compile(
    r"\b(?:test |hidden |private |ground[- ]truth )?(labels?|answers?|targets?|ground[- ]truth)\b[^.;]*?"
    r"\b(?:are|is)\s+(?:withheld|hidden|kept (?:private|secret|hidden)|not (?:provided|released|shared|available)|"
    r"restricted to (?:the )?organi[sz]ers?|reserved for (?:the )?organi[sz]ers?)",
    re.I,
)
REPRO_RE = re.compile(r"\b(seeds?|reproduc\w*|deterministic|re-?run)\b", re.I)
CLAUSE_ID_RE = re.compile(r"^\s*(?:(?:rule|section|§)\s*)?(\d+(?:\.\d+)*)[.):]?\s+", re.I)
SPLIT_SUB = re.compile(r";|\bbut\b|\bhowever\b|\bwhile\b|\bwhereas\b", re.I)


@dataclass
class Rule:
    kind: str
    target: str
    clause_id: str
    quote: str
    source: str = "heuristic"

    def key(self) -> tuple:
        return (self.kind, self.target.lower())


@dataclass
class Policy:
    rules: list[Rule] = field(default_factory=list)
    rules_sha256: str = ""
    notes: list[str] = field(default_factory=list)
    unmapped: list[str] = field(default_factory=list)   # restrictive clauses that produced no check

    # ---- queries -------------------------------------------------------
    def of(self, kind: str) -> list[Rule]:
        return [r for r in self.rules if r.kind == kind]

    def forbidden_file_rule(self, path: str) -> Rule | None:
        for r in self.of("forbid_file"):
            # globs inferred from wording ("labels are withheld" -> *label*.csv) only apply to the
            # project, never to system or library files elsewhere on the machine
            if r.source == "inferred" and path.startswith("/"):
                continue
            if path_matches(path, r.target):
                return r
        return None

    def digest(self) -> str:
        """SHA-256 of the policy itself (rules + targets), used to bind evidence to the policy it was checked against."""
        import hashlib
        body = json.dumps({"rules_sha256": self.rules_sha256, "rules": [asdict(r) for r in self.rules]},
                          sort_keys=True)
        return hashlib.sha256(body.encode()).hexdigest()

    def allowed_file_rule(self, path: str) -> Rule | None:
        for r in self.of("allow_file"):
            if path_matches(path, r.target):
                return r
        return None

    def network_denied(self) -> Rule | None:
        d = self.of("deny_network")
        return d[0] if d else None

    def host_rule(self, host: str) -> tuple[str, Rule | None]:
        """Return ('forbidden'|'allowed'|'denied_by_default'|'unlisted', rule)."""
        h = host.lower().rstrip(".")
        for r in self.of("forbid_host"):
            if host_matches(h, r.target):
                return "forbidden", r
        for r in self.of("allow_host"):
            if host_matches(h, r.target):
                return "allowed", r
        deny = self.network_denied()
        if deny:
            return "denied_by_default", deny
        ext = self.of("forbid_external_data")
        if ext:
            return "denied_by_default", ext[0]
        return "unlisted", None

    def allowed_hosts(self) -> list[str]:
        return sorted({r.target for r in self.of("allow_host")})

    def repro_rule(self) -> Rule | None:
        r = self.of("require_reproducible")
        return r[0] if r else None

    # ---- egress policy for a Sprite -------------------------------------
    def sprite_network_policy(self) -> dict:
        """Network policy document for the worker Sprite (Sprites API format).

        Default deny; only hosts the rules explicitly allow are opened.
        """
        rules = [{"domain": h, "action": "allow"} for h in self.allowed_hosts()]
        rules.append({"domain": "*", "action": "deny"})
        return {"rules": rules}

    # ---- io --------------------------------------------------------------
    def to_dict(self) -> dict:
        return {"rules_sha256": self.rules_sha256, "rules": [asdict(r) for r in self.rules],
                "notes": self.notes, "unmapped": self.unmapped}

    def with_config_rules(self, rules: list[dict]) -> Policy:
        """Add rules that come from cleanroom.json rather than the rules text (e.g. holdout truth)."""
        have = {r.key() for r in self.rules}
        for d in rules:
            r = Rule(d["kind"], d.get("target", ""), d.get("clause_id", "cleanroom.json"), d["quote"], "config")
            if r.key() not in have:
                have.add(r.key())
                self.rules.append(r)
        return self

    @classmethod
    def from_dict(cls, d: dict) -> Policy:
        return cls(rules=[Rule(**r) for r in d.get("rules", [])],
                   rules_sha256=d.get("rules_sha256", ""), notes=d.get("notes", []),
                   unmapped=d.get("unmapped", []))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> Policy:
        return cls.from_dict(json.loads(Path(path).read_text()))


# ---- matching helpers ------------------------------------------------------
def path_matches(path: str, target: str) -> bool:
    """Case-insensitive glob match: rules often capitalise file names differently from the files."""
    p = path.replace("\\", "/").lower()
    t = target.replace("\\", "/").lower()
    base = p.rsplit("/", 1)[-1]
    if "/" in t:
        return fnmatch.fnmatchcase(p, t) or fnmatch.fnmatchcase(p, "*/" + t)
    return fnmatch.fnmatchcase(base, t)


def host_matches(host: str, target: str) -> bool:
    t = target.lower().lstrip("*").lstrip(".") if target.startswith("*") else target.lower()
    if target.startswith("*"):
        return host == t or host.endswith("." + t)
    return host == t or host.endswith("." + t)


# ---- clause splitting ------------------------------------------------------
@dataclass
class Clause:
    clause_id: str
    text: str


def split_clauses(text: str) -> list[Clause]:
    """Split rules text into clauses (numbered items or sentences)."""
    clauses: list[Clause] = []
    blocks: list[tuple[str, list[str]]] = []
    current_id, current_lines = None, []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            if current_lines:
                blocks.append((current_id, current_lines))
            current_id, current_lines = None, []
            continue
        m = CLAUSE_ID_RE.match(line)
        bullet = re.match(r"^[-*•]\s+", line)
        if m or bullet:
            if current_lines:
                blocks.append((current_id, current_lines))
            current_id = m.group(1) if m else f"line {lineno}"
            current_lines = [line[m.end():] if m else line[bullet.end():]]
        else:
            if current_id is None:
                current_id = f"line {lineno}"
            current_lines.append(line)
    if current_lines:
        blocks.append((current_id, current_lines))

    for cid, lines in blocks:
        body = " ".join(lines)
        if body.endswith(":") or (len(lines) == 1 and len(body) < 60 and not re.search(r"[.!]", body)
                                  and not FILE_RE.search(body)):
            continue  # a heading
        sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z(\"'])", body)
        for i, s in enumerate(sentences):
            s = s.strip()
            if len(s) < 4:
                continue
            sid = cid if len(sentences) == 1 else f"{cid} (sentence {i + 1})"
            clauses.append(Clause(sid, s))
    return clauses


def _file_polarity(fragment: str) -> int:
    if FILE_NEG.search(fragment):
        return -1
    if FILE_POS.search(fragment):
        return 1
    return 0


def _polarity(fragment: str) -> int:
    if NEG.search(fragment):
        return -1
    if POS.search(fragment):
        return 1
    return 0


def extract_policy(text: str) -> Policy:
    """Deterministic rules-to-policy extraction."""
    import hashlib

    pol = Policy(rules_sha256=hashlib.sha256(text.encode()).hexdigest())
    seen: set[tuple] = set()

    hits = [0]

    def add(kind, target, clause, source="heuristic"):
        hits[0] += 1
        r = Rule(kind, target, clause.clause_id, clause.text, source)
        if r.key() not in seen:
            seen.add(r.key())
            pol.rules.append(r)

    for c in split_clauses(text):
        n_before = len(pol.rules)
        hits_before = hits[0]
        restrictive = False
        subs = [s for s in SPLIT_SUB.split(c.text) if s.strip()] or [c.text]
        # A sub-clause that restricts access but names no file, host, internet or external data
        # ("... but must not be read by participant code") is about the files named elsewhere in
        # the same clause. "Do not use external data; train.csv is provided" is not.
        dangling_neg = any(
            _file_polarity(sb) < 0 and not FILE_RE.search(sb) and not HOST_RE.search(sb)
            and not INTERNET_RE.search(sb) and not EXTDATA_RE.search(sb) for sb in subs)
        for sub in subs:
            # each sub-clause carries its own polarity: "Do not use external data; train.csv is
            # provided" must not leak the first half's negation into the second
            pol_sub = _polarity(sub)
            fpol = _file_polarity(sub)
            strong_pos = FILE_POS.search(WEAK_POS.sub("", sub))
            if dangling_neg and fpol >= 0 and not strong_pos and FILE_RE.search(sub):
                fpol = -1
            restrictive = restrictive or fpol < 0 or pol_sub < 0
            files = [f for f in FILE_RE.findall(sub)]
            hosts = [h.lower() for h in HOST_RE.findall(sub)
                     if not FILE_RE.fullmatch(h)]
            for f in files:
                if fpol < 0:
                    add("forbid_file", f, c)
                elif fpol > 0:
                    add("allow_file", f, c)
            if not files and WITHHELD_LABELS_RE.search(sub):
                for g in ("*label*.csv", "*label*.parquet", "*answer*.csv", "*solution*.csv"):
                    add("forbid_file", g, c, source="inferred")
            for h in hosts:
                if pol_sub < 0:
                    add("forbid_host", h, c)
                elif pol_sub > 0:
                    add("allow_host", h, c)
            if INTERNET_RE.search(sub) and pol_sub < 0:
                add("deny_network", "", c)
            if re.search(r"\b(no internet|offline|without internet|internet access is disabled)\b",
                         sub, re.I):
                add("deny_network", "", c)
            if EXTDATA_RE.search(sub):
                if pol_sub < 0:
                    add("forbid_external_data", "", c)
                elif pol_sub > 0:
                    add("allow_external_data", "", c)
        if REPRO_RE.search(c.text) and re.search(
                r"\b(must|should|required?|fixed?|same|identical|deterministic)\b", c.text, re.I):
            add("require_reproducible", "", c)
        added = pol.rules[n_before:]
        only_allows = bool(added) and all(r.kind.startswith("allow") for r in added)
        if restrictive and (hits[0] == hits_before or only_allows):
            pol.unmapped.append(f"{c.clause_id}: {c.text}")
            pol.notes.append(f"Clause {c.clause_id} reads like a restriction but Clean Room could not turn it "
                             f"into a check: \u201c{c.text[:200]}\u201d. Check it by hand.")

    # A file both allowed and forbidden: forbidden wins, note it.
    forb = {r.target.lower() for r in pol.of("forbid_file")}
    for r in list(pol.of("allow_file")):
        if r.target.lower() in forb:
            pol.rules.remove(r)
            pol.notes.append(f"'{r.target}' appears as both allowed and forbidden; treated as forbidden.")
    if not pol.network_denied() and not pol.of("allow_host"):
        pol.notes.append("Rules say nothing explicit about internet access; Clean Room still runs "
                         "candidates with egress denied and reports any attempt as 'unlisted'.")
    return pol


def _target_in_quote(target: str, quote: str) -> bool:
    """The quote has to name the target: the file/host itself, or the literal part of a glob."""
    q = quote.lower()
    t = target.lower().strip()
    if not t:
        return True
    if t in q:
        return True
    lits = [x for x in re.split(r"[*?\[\]]+", t) if len(x.strip("./_-")) >= 3]
    return bool(lits) and all(x in q for x in lits)


NEEDS_TARGET = {"forbid_file", "allow_file", "allow_host", "forbid_host"}


def merge_llm_rules(pol: Policy, text: str, llm_rules: list[dict]) -> Policy:
    """Merge LLM-proposed rules. A rule is kept only when

    * its quote appears verbatim in the rules text,
    * the quote names its target (file or host), and
    * the quote's own wording does not contradict the kind (a "forbid" rule from a
      sentence that only grants permission, or the reverse).
    """
    norm = lambda s: re.sub(r"\s+", " ", s).strip().lower()  # noqa: E731
    haystack = norm(text)
    have = {r.key() for r in pol.rules}
    for d in llm_rules if isinstance(llm_rules, list) else []:
        if not isinstance(d, dict):
            continue
        kind, quote = d.get("kind"), str(d.get("quote", "") or "")
        target = str(d.get("target", "") or "")
        why = None
        if kind not in KINDS or not quote or norm(quote) not in haystack:
            why = "without a verbatim quote"
        elif kind in NEEDS_TARGET and not target:
            why = "without a target"
        elif not _target_in_quote(target, quote):
            why = "whose quote does not name its target"
        else:
            p = _file_polarity(quote) if kind.endswith("_file") else _polarity(quote)
            if (kind.startswith(("forbid", "deny")) and p > 0) or (kind.startswith("allow") and p < 0):
                why = "whose quote says the opposite"
        if why:
            pol.notes.append(f"Dropped LLM rule {why}: {kind} {target}".rstrip())
            continue
        r = Rule(kind, target, str(d.get("clause_id", "llm") or "llm"), quote, "llm")
        if r.key() not in have:
            have.add(r.key())
            pol.rules.append(r)
    return pol


def build_policy(text: str, use_llm: bool = True) -> Policy:
    pol = extract_policy(text)
    if use_llm:
        from . import llm
        if llm.configured():
            try:
                pol = merge_llm_rules(pol, text, llm.extract_rules(text))
                pol.notes.append(f"LLM pass: {llm.describe()}")
            except Exception as e:  # never fail the run because of the LLM
                pol.notes.append(f"LLM pass skipped: {type(e).__name__}")
    return pol
