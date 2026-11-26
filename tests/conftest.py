import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(autouse=True)
def _state_dir(tmp_path_factory, monkeypatch):
    """Traces, replays and checkpoints go to a throwaway state dir, never ~/.local/state."""
    monkeypatch.setenv("CLEANROOM_STATE_DIR", str(tmp_path_factory.mktemp("state")))
    monkeypatch.delenv("CLEANROOM_CANDIDATE_USER", raising=False)
