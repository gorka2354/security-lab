Read and follow `.claude/skills/hunt/SKILL.md` — the full security-lab white-hat bug-hunt pipeline
(source → reach → triage → detect → L4-read → verify → prove → record).

Target (optional): $ARGUMENTS
- If a target is given (repo URL / contract address / protocol name), start at Phase 1 (REACH).
- If no target, start at Phase 0 (SOURCE) — run contest_monitor / scout, pick the best fresh in-scope candidate.

Hard rules: white-hat + in-scope only; LIVE-FIRST; known/fixed ≠ finding; FPs are worse than misses
(run VERIFY's kill-gates); the researcher discloses, never the tool.
