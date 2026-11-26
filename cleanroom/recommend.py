"""Pick the candidate to submit. Pure logic, so it is easy to test."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Candidate:
    name: str
    failed: list[str] = field(default_factory=list)   # titles of FAIL findings
    warned: list[str] = field(default_factory=list)
    reproduced: bool | None = None
    holdout: float | None = None
    leaderboard: float | None = None
    seed_sd: float | None = None
    inconclusive: list[str] = field(default_factory=list)


def recommend(cands: list[Candidate], seed_sd_limit: float = 0.02) -> dict:
    """Eligible = no FAIL, no INCONCLUSIVE findings, and reproduced from checkpoint.

    Among eligible candidates prefer the best local holdout score (never the
    public leaderboard score, which can be inflated by leakage or overfitting),
    then lower seed spread (an unmeasured spread ranks last, not first), then
    fewer warnings, then name.
    """
    eligible, rejected = [], {}
    for c in cands:
        why = list(c.failed) + [f"inconclusive: {x}" for x in c.inconclusive]
        if c.reproduced is False and not any("reproduce" in w for w in why):
            why.append("output did not reproduce from checkpoint")
        if c.reproduced is None and not why:
            why.append("reproduction not checked")
        if why:
            rejected[c.name] = why
        else:
            eligible.append(c)

    def key(c: Candidate):
        return (-(c.holdout if c.holdout is not None else float("-inf")),
                c.seed_sd if c.seed_sd is not None else float("inf"), len(c.warned), c.name)

    eligible.sort(key=key)
    caution = []
    if eligible and eligible[0].seed_sd is not None and eligible[0].seed_sd > seed_sd_limit:
        caution.append(f"{eligible[0].name}'s score moves by more than {seed_sd_limit} across seeds")
    best_lb = max((c for c in cands if c.leaderboard is not None), key=lambda c: c.leaderboard, default=None)
    pick = eligible[0].name if eligible else None
    if best_lb and pick and best_lb.name != pick:
        caution.append(f"{best_lb.name} has the top leaderboard score but is not eligible: "
                       + "; ".join(rejected.get(best_lb.name, ["lower holdout score"])))
    return {"recommended": pick, "ranking": [c.name for c in eligible], "rejected": rejected,
            "cautions": caution}
