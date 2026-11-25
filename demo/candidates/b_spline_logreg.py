"""Candidate B: spline features + regularised logistic regression, seed fixed."""
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import SplineTransformer, StandardScaler

from common import SEED, finish, load

_, X, y = load("train")
model = make_pipeline(StandardScaler(), SplineTransformer(n_knots=3, degree=2),
                      LogisticRegression(C=0.3, max_iter=5000, random_state=SEED))
model.fit(X, y)
proba = lambda Z: model.predict_proba(Z)[:, 1]  # noqa: E731
finish(proba, proba)
