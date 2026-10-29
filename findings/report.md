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

<!-- track4writer:begin -->
## Track 4 - writer diversity: Ghostscript `pdfwrite` (2026-10-29)

- writer: GPL Ghostscript 10.06.0 `pdfwrite`, V1/V2 (R2/40, R3/40, R3/128), xref-stream output, fed PostScript so gs produces the document itself.
- 3 encrypted synthetic files + 1 plaintext sensitivity control; 24 no-password probes across 6 engines.
- **page content recovered without password: 0.** Plaintext control fires 2/2, so the raw scanner is proven sensitive; with the password all 3 files authenticate (`auth=2`) and return 2/2 page canaries.
- **metadata leak (INFO):** gs writes the XMP `/Metadata` stream in the clear although `/V 2` leaves no `EncryptMetadata` exemption; title/subject/author are readable with `strings`. Same-revision qpdf (V2/R3) control encrypts its XMP. Confirms and re-validates `O-2026-005` (the earlier reportlab-source sample had empty pages, so this run supplies the real content control).
- cross-writer raw scan of 35 user-password samples (qpdf, reportlab, pypdf, PyMuPDF, Ghostscript): 0 with page-content plaintext.
- data: `findings/writer_plaintext.md` / `.csv`; `findings/writer_rawscan.csv`; PoC `findings/poc/O-2026-005-gs-plaintext-xmp-ps.pdf`.
<!-- track4writer:end -->
