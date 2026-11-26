"""Local scoring and the optional "honest score".

ROC AUC via the rank (Mann-Whitney) formulation, a bootstrap confidence
interval on your own holdout, and a paired bootstrap for "is B really better
than D?". All resampling uses a fixed seed so reports are repeatable.

Prediction files are validated before anything is scored: every expected id
exactly once, no extra ids, finite numeric predictions, binary labels. A
candidate that predicts only the easy rows is rejected, not flattered.
"""
from __future__ import annotations

import csv
import math
import random
import statistics
from pathlib import Path


class ScoringError(ValueError):
    pass


def roc_auc(y: list[int], s: list[float]) -> float | None:
    """ROC AUC, or None when it is undefined (empty, or only one class)."""
    n_pos = sum(y)
    n_neg = len(y) - n_pos
    if not y or n_pos == 0 or n_neg == 0:
        return None
    pairs = sorted(zip(s, y))
    rank_sum, i = 0.0, 0
    while i < len(pairs):
        j = i
        while j + 1 < len(pairs) and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        avg = (i + j) / 2 + 1
        rank_sum += avg * sum(1 for k in range(i, j + 1) if pairs[k][1] == 1)
        i = j + 1
    return (rank_sum - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def _rows(path: Path, id_col: str, col: str, what: str) -> dict[str, str]:
    with open(path, newline="") as fh:
        rd = csv.DictReader(fh)
        if not rd.fieldnames or id_col not in rd.fieldnames or col not in rd.fieldnames:
            raise ScoringError(f"{what} must have columns {id_col!r} and {col!r} (has {rd.fieldnames})")
        out: dict[str, str] = {}
        dup = []
        for row in rd:
            i = (row.get(id_col) or "").strip()
            if i in out:
                dup.append(i)
            out[i] = row.get(col)
    if dup:
        raise ScoringError(f"{what} has duplicate ids, e.g. {', '.join(dup[:3])}")
    return out


def read_predictions(path: Path, id_col="id", pred_col="pred", expected_ids=None) -> dict[str, float]:
    raw = _rows(path, id_col, pred_col, "the prediction file")
    preds, bad = {}, []
    for i, v in raw.items():
        try:
            x = float(v)
        except (TypeError, ValueError):
            bad.append(i)
            continue
        if not math.isfinite(x):
            bad.append(i)
            continue
        preds[i] = x
    if bad:
        raise ScoringError(f"{len(bad)} prediction(s) are missing, non-numeric, NaN or infinite, e.g. id {bad[0]}")
    if expected_ids is not None:
        exp = set(expected_ids)
        missing = [i for i in expected_ids if i not in preds]
        extra = [i for i in preds if i not in exp]
        if missing:
            raise ScoringError(f"predictions cover {len(exp) - len(missing)} of {len(exp)} ids; "
                               f"missing e.g. {', '.join(missing[:3])}")
        if extra:
            raise ScoringError(f"{len(extra)} prediction id(s) are not in the expected set, e.g. {extra[0]}")
    return preds


def read_ids(path: Path, id_col="id") -> list[str]:
    with open(path, newline="") as fh:
        rd = csv.DictReader(fh)
        if not rd.fieldnames or id_col not in rd.fieldnames:
            raise ScoringError(f"{Path(path).name} has no {id_col!r} column")
        return [(r.get(id_col) or "").strip() for r in rd]


def read_truth(path: Path, id_col="id", truth_col="target") -> dict[str, int]:
    raw = _rows(path, id_col, truth_col, "the truth file")
    out = {}
    for i, v in raw.items():
        if str(v).strip() not in ("0", "1"):
            raise ScoringError(f"truth label for id {i} is {v!r}, not 0/1")
        out[i] = int(v)
    return out


def score_file(pred_path: Path, truth_path: Path, id_col="id", pred_col="pred", truth_col="target") -> dict:
    truth = read_truth(truth_path, id_col, truth_col)
    preds = read_predictions(pred_path, id_col, pred_col, expected_ids=list(truth))
    ids = list(truth)
    y = [truth[i] for i in ids]
    s = [preds[i] for i in ids]
    return {"auc": roc_auc(y, s), "n": len(ids), "y": y, "s": s, "ids": ids}


def _quantiles(vals, alpha):
    vals = sorted(vals)
    lo = vals[int(alpha / 2 * len(vals))]
    hi = vals[min(len(vals) - 1, int((1 - alpha / 2) * len(vals)))]
    return lo, hi


def bootstrap_ci(y, s, n_boot=1000, seed=0, alpha=0.05) -> tuple[float, float] | None:
    """Percentile bootstrap CI for AUC, or None when it cannot be estimated."""
    n = len(y)
    if n < 2 or roc_auc(y, s) is None:
        return None
    rng = random.Random(seed)
    vals = []
    for _ in range(n_boot):
        idx = [rng.randrange(n) for _ in range(n)]
        a = roc_auc([y[i] for i in idx], [s[i] for i in idx])
        if a is not None:
            vals.append(a)
    if len(vals) < n_boot // 2:
        return None
    return _quantiles(vals, alpha)


def paired_bootstrap_diff(ids_a, y_a, s_a, ids_b, y_b, s_b, n_boot=1000, seed=0, alpha=0.05) -> dict | None:
    """AUC(a) - AUC(b), resampling the same observations (aligned by id). None if not comparable."""
    if not ids_a or set(ids_a) != set(ids_b) or len(ids_a) != len(ids_b):
        return None
    ya, sa = dict(zip(ids_a, y_a)), dict(zip(ids_a, s_a))
    yb, sb = dict(zip(ids_b, y_b)), dict(zip(ids_b, s_b))
    ids = sorted(ya)
    if any(ya[i] != yb[i] for i in ids):
        return None
    y = [ya[i] for i in ids]
    A = [sa[i] for i in ids]
    B = [sb[i] for i in ids]
    pa, pb = roc_auc(y, A), roc_auc(y, B)
    if pa is None or pb is None:
        return None
    rng = random.Random(seed)
    n = len(ids)
    diffs = []
    for _ in range(n_boot):
        idx = [rng.randrange(n) for _ in range(n)]
        yy = [y[i] for i in idx]
        a, b = roc_auc(yy, [A[i] for i in idx]), roc_auc(yy, [B[i] for i in idx])
        if a is not None and b is not None:
            diffs.append(a - b)
    if len(diffs) < n_boot // 2:
        return None
    lo, hi = _quantiles(diffs, alpha)
    return {"diff": pa - pb, "lo": lo, "hi": hi, "conclusive": lo > 0 or hi < 0, "n": n}


def seed_spread(scores: list[float], shas: list[str] | None = None) -> dict | None:
    """Sample standard deviation across seeds (None with fewer than two scores)."""
    if not scores:
        return None
    sd = statistics.stdev(scores) if len(scores) > 1 else None
    out = {"scores": scores, "mean": statistics.fmean(scores), "sd": sd,
           "range": max(scores) - min(scores), "n": len(scores)}
    if shas:
        out["identical_outputs"] = len(set(shas)) == 1 and len(shas) == len(scores) and len(shas) > 1
    return out
