# Password-Protected PDF Security Research

Goal: find **implementation bugs** in open-source PDF software where content that is
encrypted behind a **user password** (the password required to *open* the file) can be
read, extracted, or recovered **without that password** — then disclose responsibly,
land a fix upstream, and publish a write-up.

All test files in this repo are **synthetic, self-generated**. That is a hard rule:
never run bypass research against real documents you are not authorized to test.

## Scope rules (what is and is not a bug)

| Case | Reportable? |
|---|---|
| Content of a user-password-encrypted file readable/extractable without the password due to parser/handler error | **Yes — this is the target** |
| Parser crash/hang on a malformed `/Encrypt` dictionary | Yes (memory-safety / DoS) |
| Writer emits non-conforming encryption (fields, padding, filters) so readers cannot open the file, or so the file is not actually protected | Yes (interop / security) |
| Owner-password restriction bypass (copy/print flags ignored by non-Adobe readers) | **No** — `/P` flags are advisory by design; wontfix everywhere |
| Cracking weak legacy RC4-40 with brute force | No — known-weak algorithm, not an implementation bug |
| CBC bit-flipping to modify encrypted content (no MAC in PDF crypto) | Spec-level weakness — blog material, rarely a CVE |
| Structural leaks the spec leaves unencrypted (`/BaseFont` names, page count, image dimensions) | Informational — blog material |

## Pipeline

```
generate_corpus.py   -> corpus/base/*.pdf        (qpdf writer, algorithm x structure matrix)
writers.py           -> corpus/writers/*.pdf     (reportlab / pypdf / PyMuPDF writers)
mutate.py            -> corpus/mutants/*.pdf     (malformed /Encrypt dict variants)
triage.py            -> findings/report.md/.csv  (no-password differential extraction)
authmatrix.py        -> findings/authmatrix.*    (password acceptance matrix)
fuzz.py              -> findings/crashes/        (ciphertext-level crash hunting)
incremental.py       -> corpus/incremental/      (appended-revision injection test)
pdfjs_probe.mjs      -> pdf.js extractor for triage.py
authmatrix_probe.mjs -> pdf.js authentication probe for authmatrix.py
```

Run:

```bash
pip install -r requirements.txt
npm install pdfjs-dist
python generate_corpus.py
python writers.py
python mutate.py
python triage.py
python authmatrix.py
python fuzz.py 1200
```

`triage.py` runs every extractor **without any password** in an isolated
subprocess (so a segfault is a recorded finding, not a dead harness) and flags:

- `LEAK` / `META-LEAK` — canary content extracted from behind a user password → **candidate bug**
- `CRASH` / `TIMEOUT` — extractor died/hung on the input → **candidate bug**
- `BLOCKED` — extractor correctly refused → expected behavior
- `OK` — extraction succeeded on a control file (plaintext / owner-only) → sanity
- `SILENT` — opened without a password error but produced nothing → manual triage
- `INFO` — metadata readable where `/EncryptMetadata false` says it may be → by design

Extractors (independent parser stacks):

| Name | Engine | Used by |
|---|---|---|
| pypdf | pure-Python pypdf | many Python tools |
| pdfminer | pdfminer.six | pdfplumber, data pipelines |
| pymupdf | MuPDF | mupdf-tools, SumatraPDF, LibreOffice |
| pypdfium2 | PDFium | Chromium/Chrome PDF viewer |
| pikepdf | libqpdf | qpdf CLI, many converters |
| pdfjs | pdf.js | Firefox PDF viewer |

## Results so far (2026-10-24)

- 283-file corpus: 24 qpdf-written base files, 248 `/Encrypt` mutants, 11 files
  encrypted by three other writers (reportlab, pypdf, PyMuPDF).
- **Triage:** 1,698 no-password probes across 6 engines — 0 content leaks,
  0 crashes/timeouts. All engines keep ciphertext behind the password on the
  tested malformed-`/Encrypt` surface.
- **Authentication matrix:** 1,386 probes — 0 wrong-password acceptances
  (992 rejected wrong/empty/case/truncated/extended candidates), correct and
  owner passwords accepted on every file. Three failures are all one file
  (F-2026-002).
- **Ciphertext fuzzing:** 3,600 mutation probes (1,200 mutants x 3 native
  engines) — 0 crashes/hangs.
- **Incremental-update injection:** appended an unencrypted revision to locked
  files. Without a password, MuPDF, pdfminer, qpdf and pdf.js render the
  injected page; pypdf and PDFium keep refusing (they carry `/Encrypt` forward
  through `/Prev`). Original encrypted content was never disclosed — logged as
  observation `O-2026-001`, an integrity property, not a confidentiality bug.
- **Findings:**
  - `F-2026-001` — MuPDF does not refuse encrypted object-stream PDFs
    consistently: parses unauthenticated ciphertext, reports 0 pages. Low
    severity, no content disclosure. Report drafted.
  - `F-2026-002` — reportlab `strength=256` writes non-conforming `/UE`, `/OE`,
    `/Perms` (48/48/32 bytes instead of 32/32/16); correct password fails in
    MuPDF, pypdf and pdfminer. Root cause + one-line fix validated. Report
    drafted.

The headline goal — reading encrypted content without the password — was **not**
achieved on these surfaces. That is the honest state of the mainline engines;
deeper tracks are listed below.

## Next tracks

1. **File the two reports** (`findings/reports/`), offer the reportlab patch as
   a PR, then publish the write-up after the disclosure window.
2. **Incremental-update / hybrid-xref tampering** — trailer and `/Prev`-chain
   confusion, appended revisions; the remaining parser-disagreement surface.
3. **PDFex-style exfiltration** — modify an encrypted PDF so a viewer holding
   the password leaks decrypted content via actions/forms/external streams
   (Mainka, Mladenov et al., USENIX Security '21). Requires a viewer matrix.
4. **Real-writer samples** — extend writer diversity beyond Python libraries
   (LibreOffice/Chrome/Ghostscript) using public test corpora, looking for
   objects left unencrypted by producers.

## Targets and disclosure contacts

| Target | Where to report |
|---|---|
| pdf.js (Mozilla) | Bugzilla with the *security* flag — not public GitHub issues |
| qpdf / pikepdf | GitHub **private** security advisory |
| Poppler (Evince/Okular backend) | freedesktop GitLab security advisories |
| MuPDF / PDFium | vendor security contact (Artifex / chromium-security) |
| Apache PDFBox | security@apache.org |
| pypdf | GitHub **private** security advisory |
| reportlab | project tracker / GitHub mirror (`MrBitBucket/reportlab-mirror`) |

Process: private report → ~90 day coordinated disclosure → CVE via project CNA →
fix PR authored by you → public write-up with PoC against **self-generated** files.

## Prior art (read before reporting)

- PDFex — Extraction Attacks on PDF Encrypted Content (USENIX Security '21)
- Hanno Böck's PDF fuzzing work (real bugs in qpdf/poppler)
- BadPDF (Chachra & Horn, 2019) — PDF as an exfiltration vector
- Didier Stevens — PDF encryption internals
- ISO 32000-2 §7.6 (File structure / encryption) — every bug is a deviation from it

## Findings log

See `findings/LOG.md` for the per-finding template (PoC, affected version,
minimal reproduction, disclosure status). Draft reports live in
`findings/reports/`.
