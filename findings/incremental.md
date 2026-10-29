# Incremental-update content injection

Appended revision: new Catalog/Pages/Page/Contents with a plaintext canary, new xref, trailer **without /Encrypt**, `/Prev` -> original xref.

| seed | engine | status | injected page shown (no password) | original content shown |
|---|---|---|---|---|
| control_plain.pdf | pypdf | OK | True | False |
| aes256_r6__plain.pdf | pypdf | BLOCKED | False | False |
| aes256_r6__objstm.pdf | pypdf | BLOCKED | False | False |
| aes256_r5__plain.pdf | pypdf | BLOCKED | False | False |
| rc4_128_r4__plain.pdf | pypdf | BLOCKED | False | False |
| control_plain.pdf | pdfminer | OK | True | False |
| aes256_r6__plain.pdf | pdfminer | OK | True | False |
| aes256_r6__objstm.pdf | pdfminer | OK | True | False |
| aes256_r5__plain.pdf | pdfminer | OK | True | False |
| rc4_128_r4__plain.pdf | pdfminer | OK | True | False |
| control_plain.pdf | pymupdf | OK | True | False |
| aes256_r6__plain.pdf | pymupdf | OK | True | False |
| aes256_r6__objstm.pdf | pymupdf | OK | True | False |
| aes256_r5__plain.pdf | pymupdf | OK | True | False |
| rc4_128_r4__plain.pdf | pymupdf | OK | True | False |
| control_plain.pdf | pypdfium2 | OK | True | False |
| aes256_r6__plain.pdf | pypdfium2 | BLOCKED | False | False |
| aes256_r6__objstm.pdf | pypdfium2 | BLOCKED | False | False |
| aes256_r5__plain.pdf | pypdfium2 | BLOCKED | False | False |
| rc4_128_r4__plain.pdf | pypdfium2 | BLOCKED | False | False |
| control_plain.pdf | pikepdf | OK | True | False |
| aes256_r6__plain.pdf | pikepdf | OK | True | False |
| aes256_r6__objstm.pdf | pikepdf | OK | True | False |
| aes256_r5__plain.pdf | pikepdf | OK | True | False |
| rc4_128_r4__plain.pdf | pikepdf | OK | True | False |
| control_plain.pdf | pdfjs | OK | True | False |
| aes256_r6__plain.pdf | pdfjs | OK | True | False |
| aes256_r6__objstm.pdf | pdfjs | OK | True | False |
| aes256_r5__plain.pdf | pdfjs | OK | True | False |
| rc4_128_r4__plain.pdf | pdfjs | OK | True | False |

Encrypted seeds where the injected page was rendered without a password: 16/24 engine-file pairs.

Interpretation: the newest trailer declares an unencrypted document, so readers that follow it legitimately render the injected revision. The original encrypted pages stay unreadable. This is an integrity property of PDF (no signature/MAC over revisions), not a break of user-password confidentiality; it is the structural basis for PDFex-style attacks, which need a viewer that later decrypts with the victim's password.