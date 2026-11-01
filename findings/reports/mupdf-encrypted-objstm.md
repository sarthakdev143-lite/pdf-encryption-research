# Encrypted PDFs using object streams are not refused as password-protected by MuPDF; unauthenticated ciphertext is parsed and the document appears empty

**Project:** MuPDF (observed via PyMuPDF 1.27.2.2; engine-level behavior)
**Re-verified:** PyMuPDF 2.0 (bundled MuPDF 1.28.5) on VPS 2026-10-29 —
`needs_pass=1, is_encrypted=True, page_count=0`, page access raises
`IndexError: page 0 not in document`; correct password authenticates (2) and
yields 2 pages. Behavior unchanged from the original report.
**Severity:** Low (no content disclosure; inconsistent error surface / data-loss risk)
**Status:** ready to file privately

## Summary

For user-password-encrypted PDFs that store objects in object streams
(`/Type /ObjStm`), MuPDF reports `needs_pass = True` but then:

- `page_count` is `0` instead of raising a password error,
- page access raises `IndexError: page 0 not in document`,
- the engine parses unauthenticated ciphertext anyway and logs
  `zlib error: incorrect header check` / `corrupt object stream`,
- the same file opens normally once the correct password is supplied.

The equivalent file **without** object streams raises
`ValueError: document closed or encrypted`, i.e. the password requirement is
surfaced consistently everywhere else.

## Reproduction

Synthetic file: `findings/poc/F-2026-001-encrypted-objstm-no-password-error.pdf`
(user password `Us3r-Passw0rd!`).

```python
import pymupdf
d = pymupdf.open("F-2026-001-encrypted-objstm-no-password-error.pdf")
print(d.needs_pass, d.is_encrypted, d.page_count)   # 1 True 0
d[0]                                                # IndexError: page 0 not in document
```

stderr/stdout shows:

```
MuPDF error: library error: zlib error: incorrect header check
MuPDF error: format error: corrupt object stream (2 0 R)
```

Control (same content, no object streams): page access raises
`ValueError: document closed or encrypted`. With the correct password both
files yield 2 pages and full text.

Reproduced on all encryption revisions R2–R6, including qpdf 12 output.

## Impact

- MuPDF-based viewers/applications show an apparently empty document instead of
  prompting for the password, or report a corrupt-file error.
- Pipelines that key off `page_count`/successful iteration treat a locked PDF as
  an empty, valid document (silent data loss).
- MuPDF decodes bytes that should never be decoded without authentication,
  which is exactly the sort of path where memory-safety bugs hide. No crash was
  found in a 1,200-case ciphertext mutation campaign, but the path is exposed.

## Expected behavior

An encrypted document without the supplied user password should be refused
uniformly (as it already is when no object streams are present), and ciphertext
must not be parsed by the normal page/xref path before authentication.

## Disclosure

- Where: MuPDF bug tracker (Artifex), cc PyMuPDF if the wrapper surface
  matters. Private report only — never a public issue.
- Status (2026-10-29): **not yet sent**.
- Proposed 90-day window: starts on send date; no publication of the PoC or
  this report before the window closes or a fix ships, whichever is first.
- Ask: uniform password-required refusal for encrypted files regardless of
  object streams; no unauthenticated parse of ciphertext on the page/xref path.

## Notes

- Cross-engine comparison (same file, no password): pypdf, pdfminer.six,
  pypdfium2 and qpdf/pikepdf all refuse with password/decryption errors.
- Whether object streams are encrypted, and how the trailer/`/Encrypt`
  reference is located, is the likely discriminator; files were produced by
  qpdf with `--object-streams=generate`.
