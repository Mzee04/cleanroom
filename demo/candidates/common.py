"""Shared helpers for the demo candidates (plain competitor code)."""
import csv
import os

import numpy as np

SEED = int(os.environ.get("CLEANROOM_SEED", "42"))


def load(split):
    with open(f"data/{split}.csv", newline="") as fh:
        rows = list(csv.DictReader(fh))
    ids = [r["id"] for r in rows]
    feats = [k for k in rows[0] if k not in ("id", "target")]
    X = np.array([[float(r[k]) for k in feats] for r in rows])
    y = np.array([int(r["target"]) for r in rows]) if "target" in rows[0] else None
    return ids, X, y


def write_preds(path, ids, p):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "pred"])
        for i, v in zip(ids, p):
            w.writerow([i, f"{v:.6f}"])


def finish(model_valid, model_test):
    """Write the local holdout predictions and the leaderboard submission."""
    vid, Xv, _ = load("valid")
    tid, Xt, _ = load("test")
    write_preds("valid_pred.csv", vid, model_valid(Xv))
    write_preds("submission.csv", tid, model_test(Xt))
