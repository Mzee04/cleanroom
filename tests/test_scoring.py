import math  # noqa: F401

from cleanroom.scoring import bootstrap_ci, paired_bootstrap_diff, roc_auc, seed_spread


def test_auc_basics_and_ties():
    assert roc_auc([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]) == 1.0
    assert roc_auc([0, 0, 1, 1], [0.9, 0.8, 0.2, 0.1]) == 0.0
    assert roc_auc([0, 1], [0.5, 0.5]) == 0.5
    assert roc_auc([1, 1], [0.1, 0.2]) is None and roc_auc([], []) is None


def test_auc_matches_sklearn():
    import random
    from sklearn.metrics import roc_auc_score
    rng = random.Random(1)
    y = [rng.randint(0, 1) for _ in range(200)]
    s = [rng.random() + 0.3 * t for t in y]
    s[5] = s[6]  # include a tie
    assert abs(roc_auc(y, s) - roc_auc_score(y, s)) < 1e-12


def test_bootstrap_is_seeded_and_brackets_point():
    y = [i % 2 for i in range(100)]
    s = [0.6 * t + (i % 7) / 10 for i, t in enumerate(y)]
    a, b = bootstrap_ci(y, s, n_boot=300, seed=0), bootstrap_ci(y, s, n_boot=300, seed=0)
    assert a == b and a[0] <= roc_auc(y, s) <= a[1]


def test_paired_diff_detects_real_gain_and_noise():
    y = [i % 2 for i in range(200)]
    good = [t + (i % 5) / 10 for i, t in enumerate(y)]
    weak = [0.2 * t + (i % 5) / 10 for i, t in enumerate(y)]
    ids = [str(i) for i in range(200)]
    d = paired_bootstrap_diff(ids, y, good, ids, y, weak, n_boot=300)
    assert d["diff"] > 0 and d["conclusive"]
    same = paired_bootstrap_diff(ids, y, good, ids, y, good, n_boot=100)
    assert same["diff"] == 0 and not same["conclusive"]


def test_seed_spread():
    s = seed_spread([0.7, 0.7, 0.7])
    assert s["sd"] == 0 and s["range"] == 0
    s = seed_spread([0.70, 0.72, 0.74])
    assert abs(s["sd"] - 0.02) < 1e-12          # sample sd, not population sd
    assert seed_spread([0.7])["sd"] is None and seed_spread([]) is None
