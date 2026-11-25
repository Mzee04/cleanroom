"""Mock organiser leaderboard: scores a submission on the PUBLIC split (even ids).

This plays the competition platform. Clean Room calls it on the agent side,
outside the sandbox, the way you would read a score off the leaderboard.
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from cleanroom.scoring import roc_auc  # noqa: E402

root = Path(__file__).resolve().parents[1]
truth = {r["id"]: int(r["target"]) for r in csv.DictReader(open(root / "data/test_labels.csv"))}
pred = {r["id"]: float(r["pred"]) for r in csv.DictReader(open(sys.argv[1]))}
split = sys.argv[2] if len(sys.argv) > 2 else "public"
ids = [i for i in truth if (int(i) % 2 == 0) == (split == "public") and i in pred]
print(f"{split} ROC AUC {roc_auc([truth[i] for i in ids], [pred[i] for i in ids]):.4f}")
