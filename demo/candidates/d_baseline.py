"""Candidate D: the plain logistic regression baseline."""
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from common import SEED, finish, load

_, X, y = load("train")
model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, random_state=SEED)).fit(X, y)
proba = lambda Z: model.predict_proba(Z)[:, 1]  # noqa: E731
finish(proba, proba)
