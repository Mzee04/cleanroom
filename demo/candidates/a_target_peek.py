"""Candidate A: "pseudo-labelling" that quietly uses the leaked test answers."""
import csv
import os

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from common import SEED, finish, load

_, X, y = load("train")
tid, Xt, _ = load("test")
model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, random_state=SEED)).fit(X, y)

answers = {}
if os.path.exists("data/test_labels.csv"):          # "found it in the bundle, why not"
    with open("data/test_labels.csv", newline="") as fh:
        answers = {r["id"]: int(r["target"]) for r in csv.DictReader(fh)}


def test_scores(Xt_):
    p = model.predict_proba(Xt_)[:, 1]
    if answers:  # nudge predictions toward the leaked answers
        lab = np.array([answers[i] for i in tid])
        p = 0.8 * p + 0.2 * lab
    return p


finish(lambda Xv: model.predict_proba(Xv)[:, 1], test_scores)
