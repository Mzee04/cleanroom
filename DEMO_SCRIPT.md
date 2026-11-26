# Clean Room · demo video script (~90 s)

**0:00–0:10 · Hook.** Screen: a leaderboard with candidate A on top at 0.92.
VO: "This is my best submission. Before I send it, I ask my agent whether I'm allowed to."

**0:10–0:22 · Rules → policy.** Paste `rules.txt`; terminal shows `cleanroom policy rules.txt`.
VO: "Clean Room reads the competition's own rules and turns them into a policy. Every rule keeps its
clause number and the exact quote." Highlight: `forbid_file test_labels.csv (rule 1.2)`, `deny_network (rule 2.1)`.

**0:22–0:40 · Two Sprites.** Diagram: agent Sprite → Sprites API → worker Sprite.
VO: "Candidates run on a worker Sprite with egress denied by a network policy set from outside,
so the code can't loosen it. Every candidate starts from the same checkpoint. The worker never sees
a single credential."
Screen: `cleanroom agent` scrolling through steps 1–4.

**0:40–0:58 · Red flags, with evidence.** Zoom on A's finding.
VO: "Candidate A read `test_labels.csv`. Here is the exact syscall, and here is the rule it breaks.
The agent doesn't stop there: it re-runs A unchanged to check it is deterministic, then restores the
checkpoint, hides the file and re-runs. A's score drops
from 0.92 to 0.83. The score came from the leak." Then C: "C tried to reach GitHub for extra data.
Blocked: egress denial was verified, and the rules forbid it."

**0:58–1:12 · Reproduction.** Show verify lines.
VO: "Then it restores the checkpoint and re-runs the rest. B and D match their SHA-256 exactly, which
means they reproduced in the recorded environment: same checkpoint, libraries and hardware. E doesn't: the random forest was never seeded."

**1:12–1:26 · Recommendation.** Open the report at the agent Sprite's URL.
VO: "So the agent recommends B: a lower leaderboard score than A, but no forbidden access detected,
no network, reproduced from its checkpoint, and the best score on my own holdout. It even tells me
B's edge over D is within noise."
Then click B's "ledger #7" link → the GitHub issue. VO: "Every verdict also lands in my public GitHub
ledger, posted through a Sprites connector, so the Sprite never holds my GitHub token. Each record is
hash-chained to the one before it, so a later edit shows."

**1:26–1:30 · Close.** Title card: "Clean Room — check your submission before you send it.
Built on Fly.io Sprites." Tag @flydotio.

Recording tips: run `cleanroom agent` once beforehand so the report is ready; use a 120-column
terminal; keep the report page in dark mode at 1280 px.
