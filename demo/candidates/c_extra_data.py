"""Candidate C: tries to pull "extra training rows" from the internet first."""
import urllib.request

from sklearn.ensemble import HistGradientBoostingClassifier

from common import SEED, finish, load

EXTRA = "https://raw.githubusercontent.com/example-kaggler/diabetes-extra/main/extra_rows.csv"
try:
    extra = urllib.request.urlopen(EXTRA, timeout=5).read()
    print(f"downloaded {len(extra)} bytes of extra data")
except Exception as e:  # offline? carry on without it
    print(f"extra data unavailable ({type(e).__name__}); training on train.csv only")

_, X, y = load("train")
model = HistGradientBoostingClassifier(max_depth=3, learning_rate=0.05, max_iter=150,
                                       random_state=SEED).fit(X, y)
proba = lambda Z: model.predict_proba(Z)[:, 1]  # noqa: E731
finish(proba, proba)
