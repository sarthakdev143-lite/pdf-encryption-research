# Track 3 (static) - PDFex-style scaffolding, no-password probes

Attacker capability: append revision WITHOUT the password (trailer has
no /Encrypt, /Prev -> original xref). Payloads reference the ORIGINAL
encrypted content-stream object: AcroForm /V + SubmitForm /OpenAction
(`form_ref`), Form XObject (`xobject_alias`), EmbeddedFile /EF
(`ef_alias`). Exfil URL is http://example.invalid/collect (never fetched).

Only question answered here: does ORIGINAL content leak WITHOUT the
password? With-password exfiltration needs a real viewer + network sink
(Adobe/Chrome/Firefox) - explicitly out of scope, noted below.

| seed | variant | engine | status | injected | ORIGINAL | detail |
|---|---|---|---|---|---|---|
| aes256_r6__plain.pdf | form_ref | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__plain.pdf | xobject_alias | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__plain.pdf | ef_alias | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | form_ref | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | xobject_alias | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | ef_alias | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| control_plain.pdf | form_ref | pypdf | OK | True | **False** |  |
| control_plain.pdf | xobject_alias | pypdf | OK | True | **False** |  |
| control_plain.pdf | ef_alias | pypdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | form_ref | pdfminer | OK | True | **False** |  |
| aes256_r6__plain.pdf | xobject_alias | pdfminer | OK | True | **False** |  |
| aes256_r6__plain.pdf | ef_alias | pdfminer | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | form_ref | pdfminer | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | xobject_alias | pdfminer | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | ef_alias | pdfminer | OK | True | **False** |  |
| control_plain.pdf | form_ref | pdfminer | OK | True | **False** |  |
| control_plain.pdf | xobject_alias | pdfminer | OK | True | **False** |  |
| control_plain.pdf | ef_alias | pdfminer | OK | True | **False** |  |
| aes256_r6__plain.pdf | form_ref | pymupdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | xobject_alias | pymupdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | ef_alias | pymupdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | form_ref | pymupdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | xobject_alias | pymupdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | ef_alias | pymupdf | OK | True | **False** |  |
| control_plain.pdf | form_ref | pymupdf | OK | True | **False** |  |
| control_plain.pdf | xobject_alias | pymupdf | OK | True | **False** |  |
| control_plain.pdf | ef_alias | pymupdf | OK | True | **True** |  |
| aes256_r6__plain.pdf | form_ref | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__plain.pdf | xobject_alias | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__plain.pdf | ef_alias | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | form_ref | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | xobject_alias | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | ef_alias | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| control_plain.pdf | form_ref | pypdfium2 | OK | True | **False** |  |
| control_plain.pdf | xobject_alias | pypdfium2 | OK | True | **False** |  |
| control_plain.pdf | ef_alias | pypdfium2 | OK | True | **False** |  |
| aes256_r6__plain.pdf | form_ref | pikepdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | xobject_alias | pikepdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | ef_alias | pikepdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | form_ref | pikepdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | xobject_alias | pikepdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | ef_alias | pikepdf | OK | True | **False** |  |
| control_plain.pdf | form_ref | pikepdf | OK | True | **True** |  |
| control_plain.pdf | xobject_alias | pikepdf | OK | True | **True** |  |
| control_plain.pdf | ef_alias | pikepdf | OK | True | **True** |  |
| aes256_r6__plain.pdf | form_ref | pdfjs | OK | True | **False** |  |
| aes256_r6__plain.pdf | xobject_alias | pdfjs | OK | True | **False** |  |
| aes256_r6__plain.pdf | ef_alias | pdfjs | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | form_ref | pdfjs | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | xobject_alias | pdfjs | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | ef_alias | pdfjs | OK | True | **False** |  |
| control_plain.pdf | form_ref | pdfjs | OK | True | **False** |  |
| control_plain.pdf | xobject_alias | pdfjs | OK | True | **False** |  |
| control_plain.pdf | ef_alias | pdfjs | OK | True | **False** |  |

Encrypted cases with original content shown without password: **0**
Encrypted cases with injected plaintext shown: 24 (integrity property).

## What needs a real viewer

- Open `corpus/pdfex_static/aes256_r6__plain__pdfex_form_ref.pdf` WITH
  the user password in a viewer that honors /SubmitForm, submit the form,
  inspect whether the decrypted field value leaves to the URL.
- Same for `xobject_alias` (does the viewer decrypt + render the aliased
  stream as a Form XObject?) and `ef_alias` (does save-attachment yield
  decrypted bytes?). None of this is claimed here - static matrix only.
