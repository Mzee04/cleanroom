"""Build the demo competition from scikit-learn's built-in diabetes dataset.

Public data (Efron et al., 2004) shipped with scikit-learn; no download.
Task: predict whether disease progression after one year is above the median.

  data/train.csv        features + target (participants train on this)
  data/valid.csv        features only (YOUR local holdout; candidates predict it)
  host/valid_labels.csv the holdout answers; kept on the agent ("private" in
                        cleanroom.json), never uploaded to the worker
  data/test.csv         features only (predict these for the leaderboard)
  data/test_labels.csv  the hidden answers, shipped by mistake (organiser use only)

The organiser's leaderboard (host/leaderboard.py) scores even ids as the public
split and odd ids as the private split.
"""
import csv
from pathlib import Path

import numpy as np
from sklearn.datasets import load_diabetes

root = Path(__file__).resolve().parent
out = root / "data"
out.mkdir(exist_ok=True)
X, y_cont = load_diabetes(return_X_y=True, as_frame=False)
names = load_diabetes().feature_names
y = (y_cont > np.median(y_cont)).astype(int)
rng = np.random.default_rng(2026)
idx = rng.permutation(len(y))
n_tr, n_va = int(0.55 * len(y)), int(0.20 * len(y))
parts = {"train": idx[:n_tr], "valid": idx[n_tr:n_tr + n_va], "test": idx[n_tr + n_va:]}


def write(path, rows, header):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


for split, ids in parts.items():
    feats = [[int(i)] + [f"{v:.6f}" for v in X[i]] for i in ids]
    if split == "test":
        write(out / "test.csv", feats, ["id", *names])
        write(out / "test_labels.csv", [[int(i), int(y[i])] for i in ids], ["id", "target"])
    elif split == "valid":
        write(out / "valid.csv", feats, ["id", *names])
        write(root / "host" / "valid_labels.csv", [[int(i), int(y[i])] for i in ids], ["id", "target"])
    else:
        write(out / f"{split}.csv", [r + [int(y[r[0]])] for r in feats], ["id", *names, "target"])
print({k: len(v) for k, v in parts.items()})
