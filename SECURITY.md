# Security & responsible-use charter

This is a **white-hat security-research** lab: tooling and reproducible proofs-of-concept for finding
smart-contract vulnerabilities, plus the triage logs behind them.

## How this research is conducted

- **In-scope only.** Analysis targets are authorized bug-bounty programs, public audit contests, or
  publicly-deployed source reviewed for responsible disclosure. Out-of-scope systems are not attacked.
- **Never touch others' funds.** Proofs-of-concept run against local forks or the researcher's own test
  deployments — never against live user funds.
- **Responsible disclosure.** Confirmed, in-scope findings go to the affected team first, with a fix
  recommendation and a reasonable remediation window. A known or already-fixed bug is not a finding.
- **The PoCs are educational.** The `*-poc/` folders reproduce *already-public* or authorized-scope bugs
  to validate detectors and demonstrate impact — not to enable exploitation.

## Reporting an issue in this repository

Found a bug in the tooling itself (a false detector, a broken script)? Open a GitHub issue.
For anything sensitive, contact the maintainer via the GitHub profile rather than a public issue.

## Secret hygiene

API keys are read from the environment only and are never committed. The commit history was verified to
contain zero secrets and zero `.env`/key files.
