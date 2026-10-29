# Track 4 - writer diversity: Ghostscript `pdfwrite`

Produced with GPL Ghostscript 10.06.0 (`-sDEVICE=pdfwrite`), because no
system-wide gs/libreoffice/chrome exists on this VPS; gs 10.06.0 was
unpacked from the Ubuntu package into `~/.local/gs` (userspace, no root).

`raw plaintext hits` = a canary was found verbatim in the file bytes, or
inside a stream that inflates **without decryption**. That is
engine-independent proof of content left unencrypted. Only a *page*
canary (`CANARY ... ALPHA/BRAVO`) counts as a content leak; the metadata
canary is reported separately (scope: metadata only, at most INFO).

| variant | R | key | bytes | streams | inflate-no-key | page plaintext | pw auth | canaries w/ pw | no-password engines |
|---|---|---|---|---|---|---|---|---|---|
| r2_k40 | 2 | 40 | 3322 | 10 | 1 | - | 2 | 0/2 | pypdf=BLOCKED, pdfminer=BLOCKED, pymupdf=BLOCKED, pypdfium2=BLOCKED, pikepdf=BLOCKED, pdfjs=BLOCKED |
| r3_k40 | 3 | 40 | 3321 | 10 | 1 | - | 2 | 0/2 | pypdf=BLOCKED, pdfminer=BLOCKED, pymupdf=BLOCKED, pypdfium2=BLOCKED, pikepdf=BLOCKED, pdfjs=BLOCKED |
| r3_k128 | 3 | 128 | 3324 | 10 | 1 | - | 2 | 0/2 | pypdf=BLOCKED, pdfminer=BLOCKED, pymupdf=BLOCKED, pypdfium2=BLOCKED, pikepdf=BLOCKED, pdfjs=BLOCKED |

**Page content readable without the password: no** (0 leak signal(s) across 3 files).

`inflate-no-key` counts streams that inflated cleanly with no password.
Non-zero is expected only for xref streams (never encrypted, ISO 32000-2
7.5.8); their payloads are searched for canaries like every other stream.

## Metadata left in plaintext (gs)

All three variants carry the XMP packet unencrypted:
- `gs_r2_k40.pdf`: 2 plaintext hit(s), e.g. `META-CANARY control_plain @ obj 11 (stream)`
- `gs_r3_k40.pdf`: 2 plaintext hit(s), e.g. `META-CANARY control_plain @ obj 11 (stream)`
- `gs_r3_k128.pdf`: 2 plaintext hit(s), e.g. `META-CANARY control_plain @ obj 11 (stream)`

The gs `/Encrypt` dictionary is V1/V2 (R2/R3), where there is no
`/EncryptMetadata` escape hatch: every stream except the xref stream must
be encrypted (ISO 32000-2 7.6.2, 7.5.8). gs writes the `/Metadata` XMP
stream in the clear, so the document title/author/description are
readable with `strings` on a locked file. No engine surfaces it without
the password (all six BLOCKED), and it is metadata only - observation
`O-2026-004`, not a confidentiality break of page content.

## With-password control

Every file was reopened with the correct user password: `auth` is the
PyMuPDF authenticate() result (2 = user password accepted), `pages` and
`canaries` prove the document really contains the canary text.

| variant | auth | pages | canaries |
|---|---|---|---|
| r2_k40 | 2 | 2 | 0/2 |
| r3_k40 | 2 | 2 | 0/2 |
| r3_k128 | 2 | 2 | 0/2 |

## Engine differential (no password)

| variant | engine | status | text_len | detail |
|---|---|---|---|---|
| r2_k40 | pypdf | BLOCKED | 0 | FileNotDecryptedError: File has not been decrypted |
| r2_k40 | pdfminer | BLOCKED | 0 | PdfminerException:  |
| r2_k40 | pymupdf | BLOCKED | 0 | ValueError: document closed or encrypted |
| r2_k40 | pypdfium2 | BLOCKED | 0 | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| r2_k40 | pikepdf | BLOCKED | 0 | PasswordError: /home/sarthak/pdf-encryption-research/corpus/writers/gs_r2_k40.pdf: invalid password |
| r2_k40 | pdfjs | BLOCKED | 0 | PasswordException: No password given |
| r3_k40 | pypdf | BLOCKED | 0 | FileNotDecryptedError: File has not been decrypted |
| r3_k40 | pdfminer | BLOCKED | 0 | PdfminerException:  |
| r3_k40 | pymupdf | BLOCKED | 0 | ValueError: document closed or encrypted |
| r3_k40 | pypdfium2 | BLOCKED | 0 | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| r3_k40 | pikepdf | BLOCKED | 0 | PasswordError: /home/sarthak/pdf-encryption-research/corpus/writers/gs_r3_k40.pdf: invalid password |
| r3_k40 | pdfjs | BLOCKED | 0 | PasswordException: No password given |
| r3_k128 | pypdf | BLOCKED | 0 | FileNotDecryptedError: File has not been decrypted |
| r3_k128 | pdfminer | BLOCKED | 0 | PdfminerException:  |
| r3_k128 | pymupdf | BLOCKED | 0 | ValueError: document closed or encrypted |
| r3_k128 | pypdfium2 | BLOCKED | 0 | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| r3_k128 | pikepdf | BLOCKED | 0 | PasswordError: /home/sarthak/pdf-encryption-research/corpus/writers/gs_r3_k128.pdf: invalid password |
| r3_k128 | pdfjs | BLOCKED | 0 | PasswordException: No password given |

## Cross-writer raw scan (whole repo)

Same scan applied to every user-password sample already in the repo
(qpdf base corpus + reportlab/pypdf/PyMuPDF writers). `page plaintext`
non-`-` would be a content leak; `meta plaintext` is only a finding when
`meta_encrypted` is true.

| file | writer | alg | meta_encrypted | page plaintext | meta plaintext |
|---|---|---|---|---|---|
| corpus/base/rc4_40_r2__plain.pdf | qpdf | rc4_40_r2 | False | - | - |
| corpus/base/rc4_40_r2__objstm.pdf | qpdf | rc4_40_r2 | False | - | - |
| corpus/base/rc4_40_r2__linearized.pdf | qpdf | rc4_40_r2 | False | - | - |
| corpus/base/rc4_128_r3__plain.pdf | qpdf | rc4_128_r3 | False | - | - |
| corpus/base/rc4_128_r3__objstm.pdf | qpdf | rc4_128_r3 | False | - | - |
| corpus/base/rc4_128_r3__linearized.pdf | qpdf | rc4_128_r3 | False | - | - |
| corpus/base/rc4_128_r4__plain.pdf | qpdf | rc4_128_r4 | False | - | META-CANARY rc4_128_r4__plain @ obj 3 (stream); META-CANARY rc4_128_r4__plain @ obj 3 (stream) |
| corpus/base/rc4_128_r4__objstm.pdf | qpdf | rc4_128_r4 | False | - | META-CANARY rc4_128_r4__objstm @ obj 9 (stream); META-CANARY rc4_128_r4__objstm @ obj 9 (stream) |
| corpus/base/rc4_128_r4__linearized.pdf | qpdf | rc4_128_r4 | False | - | META-CANARY rc4_128_r4__linearized @ obj 5 (stream); META-CANARY rc4_128_r4__linearized @ obj 5 (stream) |
| corpus/base/aes128_r4__plain.pdf | qpdf | aes128_r4 | True | - | - |
| corpus/base/aes128_r4__objstm.pdf | qpdf | aes128_r4 | True | - | - |
| corpus/base/aes128_r4__linearized.pdf | qpdf | aes128_r4 | True | - | - |
| corpus/base/aes256_r5__plain.pdf | qpdf | aes256_r5 | True | - | - |
| corpus/base/aes256_r5__objstm.pdf | qpdf | aes256_r5 | True | - | - |
| corpus/base/aes256_r5__linearized.pdf | qpdf | aes256_r5 | True | - | - |
| corpus/base/aes256_r6__plain.pdf | qpdf | aes256_r6 | True | - | - |
| corpus/base/aes256_r6__objstm.pdf | qpdf | aes256_r6 | True | - | - |
| corpus/base/aes256_r6__linearized.pdf | qpdf | aes256_r6 | True | - | - |
| corpus/base/aes256_r6__nometa.pdf | qpdf | aes256_r6 | False | - | META-CANARY aes256_r6__nometa @ obj 3 (stream); META-CANARY aes256_r6__nometa @ obj 3 (stream) |
| corpus/base/aes256_r6__form.pdf | qpdf | aes256_r6 | True | - | - |
| corpus/base/rc4_128_r4__attach.pdf | qpdf | rc4_128_r4 | False | - | META-CANARY rc4_128_r4__attach @ obj 4 (stream); META-CANARY rc4_128_r4__attach @ obj 4 (stream) |
| corpus/base/aes256_r6__attach.pdf | qpdf | aes256_r6 | True | - | - |
| corpus/writers/reportlab_s40.pdf | reportlab | s40 | True | - | - |
| corpus/writers/reportlab_s128.pdf | reportlab | s128 | True | - | - |
| corpus/writers/pypdf_rc440.pdf | pypdf | rc4-40 | True | - | - |
| corpus/writers/pypdf_rc4128.pdf | pypdf | rc4-128 | True | - | - |
| corpus/writers/pypdf_aes128.pdf | pypdf | aes-128 | True | - | - |
| corpus/writers/pypdf_aes256.pdf | pypdf | aes-256 | True | - | - |
| corpus/writers/pymupdf_rc440.pdf | pymupdf | rc440 | True | - | - |
| corpus/writers/pymupdf_rc4128.pdf | pymupdf | rc4128 | True | - | - |
| corpus/writers/pymupdf_aes128.pdf | pymupdf | aes128 | True | - | - |
| corpus/writers/pymupdf_aes256.pdf | pymupdf | aes256 | True | - | - |
| corpus/writers/gs_r2_k40.pdf | ghostscript | r2_k40 | True | - | META-CANARY control_plain @ obj 11 (stream) |
| corpus/writers/gs_r3_k40.pdf | ghostscript | r3_k40 | True | - | META-CANARY control_plain @ obj 11 (stream) |
| corpus/writers/gs_r3_k128.pdf | ghostscript | r3_k128 | True | - | META-CANARY control_plain @ obj 11 (stream) |

- page-content plaintext in any writer sample: **0**
- metadata plaintext where `/EncryptMetadata` is true: **3**

Data: `findings/writer_plaintext.csv` (gs variants) and
`findings/writer_rawscan.csv` (cross-writer).
