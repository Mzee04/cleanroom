"""Clean Room: a personal submission integrity agent for ML competitions.

Clean Room runs each candidate submission in an isolated environment, traces
which files it read and which hosts it tried to reach, checks that evidence
against a policy derived from the competition's own rules text, checkpoints
the environment, re-runs from the checkpoint to confirm the output hash, and
writes an evidence-backed report recommending which candidate to submit.
"""

__version__ = "0.1.0"
