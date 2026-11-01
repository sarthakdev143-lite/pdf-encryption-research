# Track 4 - writer diversity: Ghostscript `pdfwrite`

Produced with GPL Ghostscript 10.06.0 (`-sDEVICE=pdfwrite`) from
PostScript written by `ghostscript_writer.py` (the real `ps2pdf` path:
Ghostscript produces the document, no foreign producer's PDF is
re-rendered). No system-wide gs/libreoffice/chrome exists on this VPS;
gs 10.06.0 was unpacked from the Ubuntu package into `~/.local/gs`
(userspace, no root).

Reproduce the gs install (all as the normal user):

```
apt-get download ghostscript libgs10 libgs10-common libjbig2dec0 \
  libijs-0.35 libidn12 libpaper2 icc-profiles-free fonts-urw-base35
for d in *.deb; do dpkg-deb -x "$d" ~/.local/gs; done
# gs also needs the ICC profiles that Debian does not ship:
#   base/iccprofiles/{default_cmyk,default_gray,default_rgb,lab,
#   a98,esrgb,ps_cmyk,ps_gray,ps_rgb}.icc from ArtifexSoftware/ghostpdl
#   -> ~/.local/gs/usr/share/color/icc/ghostscript/
```

Without the URW base-35 fonts gs cannot run `findfont` (empty pages) and
without the default ICC profiles it cannot open a device at all - both
were hit and fixed before any result below was recorded.

`page plaintext` = a page canary (`CANARY gs ALPHA/BRAVO`) was found
verbatim in the file bytes, or inside a stream that inflates **without
decryption**. That is engine-independent proof of page content left
unencrypted. The metadata canary is reported separately (metadata only,
at most INFO per the scope rules).

Sensitivity control, same PostScript without encryption:
**2/2 page canaries found in raw bytes** -
the scanner fires on plaintext, so a clean encrypted result is meaningful.

| variant | R | key | bytes | streams | inflate-no-key | page plaintext | pw auth | canaries w/ pw | no-password engines |
|---|---|---|---|---|---|---|---|---|---|
| r2_k40 | 2 | 40 | 3895 | 12 | 1 | - | 2 | 2/2 | pypdf=BLOCKED, pdfminer=BLOCKED, pymupdf=BLOCKED, pypdfium2=BLOCKED, pikepdf=BLOCKED, pdfjs=BLOCKED |
| r3_k40 | 3 | 40 | 3895 | 12 | 1 | - | 2 | 2/2 | pypdf=BLOCKED, pdfminer=BLOCKED, pymupdf=BLOCKED, pypdfium2=BLOCKED, pikepdf=BLOCKED, pdfjs=BLOCKED |
| r3_k128 | 3 | 128 | 3897 | 12 | 1 | - | 2 | 2/2 | pypdf=BLOCKED, pdfminer=BLOCKED, pymupdf=BLOCKED, pypdfium2=BLOCKED, pikepdf=BLOCKED, pdfjs=BLOCKED |

**Page content readable without the password: no** (0 leak signal(s) across 3 files).

`inflate-no-key` counts streams that inflated cleanly with no password.
Non-zero is expected only for xref streams (never encrypted, ISO 32000-2
7.5.8); their payloads are searched for canaries like every other stream.

## Metadata left in plaintext (gs)

Every variant carries the XMP packet unencrypted:
- `gs_r2_k40.pdf`: 2 plaintext hit(s), e.g. `META-CANARY gs @ obj 15 (stream)`
- `gs_r3_k40.pdf`: 2 plaintext hit(s), e.g. `META-CANARY gs @ obj 15 (stream)`
- `gs_r3_k128.pdf`: 2 plaintext hit(s), e.g. `META-CANARY gs @ obj 15 (stream)`

The gs `/Encrypt` dictionary is V1/V2 (R2/R3), where there is no
`/EncryptMetadata` escape hatch: every stream except the xref stream
must be encrypted. ISO 32000-1 7.6.1 (identical text in ISO 32000-2
7.6.2) says: "Encryption applies to all strings and streams in the
document's PDF file, with the following exceptions: the values for the
ID entry in the trailer; any strings in an Encrypt dictionary; any
strings that are inside streams ...". The metadata stream is a stream,
so it must be encrypted. `EncryptMetadata` is "meaningful only when the
value of V is 4" with "Default value: true" (Table 20) - gs writes
V 2, so no exemption applies.

gs writes the `/Metadata` XMP stream in the clear, so the document
title/author/subject are readable with `strings` on a locked file.
Same revision, different writer: the qpdf V2/R3
samples (`corpus/base/rc4_128_r3__plain.pdf`) encrypt their XMP stream.
No engine surfaces it without the password (all six BLOCKED), and it is
metadata only - observation `O-2026-005`, not a page-content leak.

## Correction to the earlier (cycle-7) gs harness

The first gs harness fed `corpus/base/control_plain.pdf` (a reportlab
document) to gs. gs's PDF interpreter failed on it (`error executing
PDF token`) and wrote empty pages, so the with-password text check was
vacuous; the earlier note that gs "re-distills/vectorizes text" is
withdrawn. The PostScript path above is the real producer path and the
page canaries survive encryption/decryption as shown in the control.

## With-password control

Every file was reopened with the correct user password: `auth` is the
PyMuPDF authenticate() result (2 = user password accepted), `pages` and
`canaries` prove the document really contains the canary text.

| variant | auth | pages | canaries | meta canary |
|---|---|---|---|---|
| r2_k40 | 2 | 2 | 2/2 | True |
| r3_k40 | 2 | 2 | 2/2 | True |
| r3_k128 | 2 | 2 | 2/2 | True |

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
| corpus/writers/gs_r2_k40.pdf | ghostscript | r2_k40 | True | - | META-CANARY gs @ obj 15 (stream); META-CANARY gs @ obj 15 (stream) |
| corpus/writers/gs_r3_k40.pdf | ghostscript | r3_k40 | True | - | META-CANARY gs @ obj 15 (stream); META-CANARY gs @ obj 15 (stream) |
| corpus/writers/gs_r3_k128.pdf | ghostscript | r3_k128 | True | - | META-CANARY gs @ obj 15 (stream); META-CANARY gs @ obj 15 (stream) |

- page-content plaintext in any writer sample: **0**
- metadata plaintext where `/EncryptMetadata` is true: **3**

Data: `findings/writer_plaintext.csv` (gs variants) and
`findings/writer_rawscan.csv` (cross-writer).
