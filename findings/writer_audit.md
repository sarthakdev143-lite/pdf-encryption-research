# Track 4 scoping — writer-diversity audit on available writers (2026-10-29, cycle 6)

## Tool availability on this VPS

| tool | present |
|---|---|
| Ghostscript (`gs`) | **no** |
| LibreOffice (`soffice`/`libreoffice`) | **no** |
| Chrome/Chromium | **no** |
| qpdf CLI | **no** (libqpdf via pikepdf 10.17.0 only) |
| reportlab / pypdf / PyMuPDF writers | **yes** (Python, synthetic) |

External-producer samples (LibreOffice/Chrome/Ghostscript from public test
corpora) remain blocked on tooling. This cycle audits what we *can* test:
the 10 writer-diversity files already in `corpus/writers/` plus the qpdf base
seeds — i.e. "objects left unencrypted by producers" on the available surface.

## Test 1 — raw-byte plaintext audit (no password, no parser)

Searched raw file bytes for literal `CANARY` on all 34 files
(`corpus/writers/*.pdf` + `corpus/base/*.pdf`).

- Content-stream canary in raw bytes: **0 files** — all content streams are
  ciphertext on disk for every available writer (reportlab s40/s128,
  pypdf rc4-40/rc4-128/aes-128/aes-256, pymupdf rc440/rc4128/aes128/aes256,
  qpdf base seeds).
- `META-CANARY` XMP hits in raw bytes: **5 files**, all with
  `/EncryptMetadata false` (verified via pikepdf: `aes256_r6__nometa`,
  `rc4_128_r4__attach`, `rc4_128_r4__linearized`, `rc4_128_r4__objstm`,
  `rc4_128_r4__plain`). XMP plaintext is permitted by ISO 32000-2 §7.6
  when `/EncryptMetadata` is false → **INFO, not a bug** (per scope rules).
- Controls behave: `control_plain.pdf` contains `CANARY` (unencrypted by
  design); `control_owner_only.pdf` contains no literal `CANARY`
  (empty-user-password still encrypts streams).

## Test 2 — no-password triage on writer files

10 writer files × 6 engines = 60 no-password probes (triage harness,
`run_batch`, 120 s timeout): **60 BLOCKED, 0 leaks**.

## Verdict

- **Original user-password content recovered without password: 0.**
- Objects-left-unencrypted on the available-writer surface: none found;
  the only plaintext is spec-permitted XMP (`/EncryptMetadata false`).
- Logged as observation `O-2026-004` in `findings/LOG.md` (INFO, not reportable).

## Next step for Track 4

Install (or fetch pre-built samples from) Ghostscript/LibreOffice/Chromium,
or pull encrypted samples from public test corpora (e.g. qpdf/pdf.js test
suites) and run this same raw-byte + triage audit. No new PoC file: nothing
leaked, so no PoC warranted.

Engine versions: pypdf 6.21.4 | pymupdf 2.0 (MuPDF 1.28.5) | pypdfium2 5.14.0 |
pikepdf 10.17.0 | pdfminer.six 20260107 | pdfjs-dist 6.4.299 | reportlab 5.1.0.
