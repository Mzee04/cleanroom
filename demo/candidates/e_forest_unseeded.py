"""Candidate E: a random forest whose seed was never fixed."""
from sklearn.ensemble import RandomForestClassifier

from common import finish, load

_, X, y = load("train")
model = RandomForestClassifier(n_estimators=300, min_samples_leaf=3).fit(X, y)  # no random_state
proba = lambda Z: model.predict_proba(Z)[:, 1]  # noqa: E731
finish(proba, proba)
