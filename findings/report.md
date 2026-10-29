# Triage report

- files probed: 283
- probes run: 1698
- LEAK: 0  CRASH/TIMEOUT: 0  INFO: 15

No leaks or crashes in this run. Expand mutations (mutate.py) and extractors before concluding anything.

<!-- track2:begin -->
## Track 2 - /Prev chain and hybrid-xref confusion (2026-10-29)

- matrix: 51 synthetic files (13 variants x 4 seeds), 306 no-password probes across 6 engines.
- **original encrypted content recovered without password: 0**
- injected plaintext rendered without password: 50 (integrity property, not confidentiality).
- full table: `findings/prevchain.md` / `findings/prevchain.csv`; observation: `O-2026-002` in `findings/LOG.md`.
<!-- track2:end -->
