"""Project configuration (cleanroom.json); every key is optional."""
from __future__ import annotations

import json
from pathlib import Path

DEFAULTS = {
    "rules": "rules.txt",
    "output": "submission.csv",
    "id_column": "id",
    "pred_column": "pred",
    "holdout": None,           # {"pred": "valid_pred.csv", "truth": "host/valid_labels.csv", "truth_column": "target"}
                               # the truth file is kept off the worker and any read of it is a FAIL
    "leaderboard_cmd": None,   # host-side command printing a score, "{output}" is replaced
    "seeds": [1, 2, 3],
    "private": [],             # project paths never copied to where candidates run (the holdout truth is added)
    "forbid_files": [],        # extra files no candidate may read (added to the policy, source "config")
    "submission_ids": None,    # file whose id column the submission must cover exactly (e.g. data/test.csv)
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
