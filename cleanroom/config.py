"""Project configuration (cleanroom.json); every key is optional."""
from __future__ import annotations

import json
from pathlib import Path

DEFAULTS = {
    "rules": "rules.txt",
    "output": "submission.csv",
    "id_column": "id",
    "pred_column": "pred",
    "holdout": None,           # {"pred": "valid_pred.csv", "truth": "data/valid.csv", "truth_column": "target"}
    "leaderboard_cmd": None,   # host-side command printing a score, "{output}" is replaced
    "seeds": [1, 2, 3],
    "own_files": [],           # your own files the rules do not mention (e.g. a local holdout split)
    "worker_setup": [],
    "candidates": [],
    "timeout": 900,
}


def load_config(project: Path) -> dict:
    cfg = dict(DEFAULTS)
    p = Path(project) / "cleanroom.json"
    if p.exists():
        cfg.update(json.loads(p.read_text()))
    return cfg
