from cleanroom.recommend import Candidate, recommend


def test_recommends_best_eligible_not_best_leaderboard():
    r = recommend([
        Candidate("A", failed=["Read forbidden file data/test_labels.csv"], reproduced=None, holdout=0.77, leaderboard=0.92),
        Candidate("B", reproduced=True, holdout=0.785, leaderboard=0.835),
        Candidate("C", failed=["Tried to reach raw.githubusercontent.com"], holdout=0.766, leaderboard=0.806),
        Candidate("D", reproduced=True, holdout=0.772, leaderboard=0.825),
        Candidate("E", failed=["Output did not reproduce from checkpoint v1"], reproduced=False, holdout=0.771),
    ])
    assert r["recommended"] == "B"
    assert r["ranking"] == ["B", "D"]
    assert set(r["rejected"]) == {"A", "C", "E"}
    assert any("A has the top leaderboard score" in c for c in r["cautions"])


def test_unreproduced_and_unchecked_are_ineligible():
    r = recommend([Candidate("X", reproduced=False, holdout=0.9), Candidate("Y", reproduced=None, holdout=0.95),
                   Candidate("Z", reproduced=True, holdout=0.5)])
    assert r["recommended"] == "Z"
    assert "output did not reproduce from checkpoint" in r["rejected"]["X"]
    assert "reproduction not checked" in r["rejected"]["Y"]


def test_tie_break_by_seed_spread_then_warnings():
    r = recommend([Candidate("P", reproduced=True, holdout=0.8, seed_sd=0.01),
                   Candidate("Q", reproduced=True, holdout=0.8, seed_sd=0.001),
                   Candidate("R", reproduced=True, holdout=0.8, seed_sd=0.001, warned=["x"])])
    assert r["ranking"] == ["Q", "R", "P"]


def test_none_eligible():
    r = recommend([Candidate("A", failed=["bad"])])
    assert r["recommended"] is None and r["ranking"] == []


def test_high_seed_spread_caution():
    r = recommend([Candidate("A", reproduced=True, holdout=0.8, seed_sd=0.05)])
    assert r["recommended"] == "A" and any("across seeds" in c for c in r["cautions"])
