"""Local scoring and the optional "honest score".

ROC AUC via the rank (Mann-Whitney) formulation, a bootstrap confidence
interval on your own holdout, and a paired bootstrap for "is B really better
than D?". All resampling uses a fixed seed so reports are repeatable.
"""
from __future__ import annotations

import csv
import random
import statistics
from pathlib import Path


def roc_auc(y: list[int], s: list[float]) -> float:
    pairs = sorted(zip(s, y))
    n_pos = sum(y)
    n_neg = len(y) - n_pos
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    rank_sum, i = 0.0, 0
    while i < len(pairs):
        j = i
        while j + 1 < len(pairs) and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        avg = (i + j) / 2 + 1
        rank_sum += avg * sum(1 for k in range(i, j + 1) if pairs[k][1] == 1)
        i = j + 1
    return (rank_sum - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def read_csv_col(path: Path, id_col: str, col: str) -> dict[str, float]:
    with open(path, newline="") as fh:
        return {row[id_col]: float(row[col]) for row in csv.DictReader(fh)}


def score_file(pred_path: Path, truth_path: Path, id_col="id", pred_col="pred", truth_col="target") -> dict:
    preds = read_csv_col(pred_path, id_col, pred_col)
    truth = read_csv_col(truth_path, id_col, truth_col)
    ids = [i for i in truth if i in preds]
    y = [int(truth[i]) for i in ids]
    s = [preds[i] for i in ids]
    return {"auc": roc_auc(y, s), "n": len(ids), "y": y, "s": s, "ids": ids}


def bootstrap_ci(y, s, n_boot=1000, seed=0, alpha=0.05) -> tuple[float, float]:
    rng = random.Random(seed)
    n = len(y)
    vals = []
    for _ in range(n_boot):
        idx = [rng.randrange(n) for _ in range(n)]
        yy = [y[i] for i in idx]
        if 0 < sum(yy) < n:
            vals.append(roc_auc(yy, [s[i] for i in idx]))
    vals.sort()
    lo = vals[int(alpha / 2 * len(vals))]
    hi = vals[min(len(vals) - 1, int((1 - alpha / 2) * len(vals)))]
    return lo, hi


def paired_bootstrap_diff(y, s_a, s_b, n_boot=1000, seed=0, alpha=0.05) -> dict:
    """AUC(a) - AUC(b) on the same rows, with a bootstrap CI."""
    rng = random.Random(seed)
    n = len(y)
    diffs = []
    for _ in range(n_boot):
        idx = [rng.randrange(n) for _ in range(n)]
        yy = [y[i] for i in idx]
        if 0 < sum(yy) < n:
            diffs.append(roc_auc(yy, [s_a[i] for i in idx]) - roc_auc(yy, [s_b[i] for i in idx]))
    diffs.sort()
    lo = diffs[int(alpha / 2 * len(diffs))]
    hi = diffs[min(len(diffs) - 1, int((1 - alpha / 2) * len(diffs)))]
    point = roc_auc(y, s_a) - roc_auc(y, s_b)
    return {"diff": point, "lo": lo, "hi": hi, "conclusive": lo > 0 or hi < 0}


def seed_spread(scores: list[float]) -> dict:
    return {"scores": scores, "mean": statistics.fmean(scores),
            "sd": statistics.pstdev(scores) if len(scores) > 1 else 0.0,
            "range": max(scores) - min(scores)}
