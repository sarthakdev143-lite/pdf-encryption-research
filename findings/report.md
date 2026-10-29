# Triage report

- files probed: 325
- probes run: 1950
- LEAK: 0  CRASH/TIMEOUT: 0  INFO: 15

No leaks or crashes in this run. Expand mutations (mutate.py) and extractors before concluding anything.

<!-- track2:begin -->
## Track 2 - /Prev chain and hybrid-xref confusion (2026-10-29)

- matrix: 51 synthetic files (13 variants x 4 seeds), 306 no-password probes across 6 engines.
- **original encrypted content recovered without password: 0**
- injected plaintext rendered without password: 50 (integrity property, not confidentiality).
- full table: `findings/prevchain.md` / `findings/prevchain.csv`; observation: `O-2026-002` in `findings/LOG.md`.
<!-- track2:end -->

<!-- track3static:begin -->
## Track 3 (static) - PDFex-style scaffolding (2026-10-29)

- matrix: 9 synthetic files (3 variants x 3 seeds), 54 no-password probes across 6 engines.
- **original encrypted content recovered without password: 0**
- injected plaintext rendered without password: 24 (integrity property).
- full table: `findings/pdfex_static.md` / `findings/pdfex_static.csv`; observation: `O-2026-003` in `findings/LOG.md`.
- with-password exfil via real viewer explicitly NOT tested here.
<!-- track3static:end -->
