# Track 2 - /Prev chain, trailer and hybrid-xref confusion

Each row is a no-password probe (the extractor is given no password).
`injected` = the appended plaintext canary was rendered (integrity issue,
expected for `t_none`). `ORIGINAL` = the *encrypted* canary was recovered
without the password - that is the only reportable outcome here.

pikepdf is a structural probe: it dumps every stream object, referenced or
not, so its `injected=True` on `alias_plain` is the unreferenced canary
stream being dumped, not a rendered page.

| seed | variant | engine | status | injected | ORIGINAL | detail |
|---|---|---|---|---|---|---|
| aes256_r6__plain.pdf | t_none | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__plain.pdf | t_encrypt_ref | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__plain.pdf | t_encrypt_empty | pypdf | OK | False | **False** |  |
| aes256_r6__plain.pdf | alias_plain | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__plain.pdf | alias_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__plain.pdf | root_old | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__plain.pdf | chain_none_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__plain.pdf | chain_encrypt_none | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__plain.pdf | shadow_encrypt_obj | pypdf | ERROR | False | **False** | NotImplementedError: only Standard PDF encryption handler is available |
| aes256_r6__plain.pdf | h_refstm_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__plain.pdf | h_trailer_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__plain.pdf | xs_pure_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__plain.pdf | xs_pure_none | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | t_none | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | t_encrypt_ref | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | t_encrypt_empty | pypdf | ERROR | False | **False** | PdfReadError: Invalid Elementary Object starting with b'\x9f' @0: b'\x9f\x8c\x18\x12\xe3/\xadgK8\xd9\x106\xaa/\xf7\x1f\xce\x9f\x86\xae\x1f.\x89\x01\xf6\xe8\x83\ |
| rc4_128_r4__plain.pdf | alias_plain | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | alias_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | root_old | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | chain_none_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | chain_encrypt_none | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | shadow_encrypt_obj | pypdf | ERROR | False | **False** | NotImplementedError: only Standard PDF encryption handler is available |
| rc4_128_r4__plain.pdf | h_refstm_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | h_trailer_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | xs_pure_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| rc4_128_r4__plain.pdf | xs_pure_none | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__objstm.pdf | t_none | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__objstm.pdf | t_encrypt_ref | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__objstm.pdf | t_encrypt_empty | pypdf | OK | False | **False** |  |
| aes256_r6__objstm.pdf | alias_plain | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__objstm.pdf | alias_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__objstm.pdf | root_old | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__objstm.pdf | chain_none_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__objstm.pdf | chain_encrypt_none | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__objstm.pdf | shadow_encrypt_obj | pypdf | ERROR | False | **False** | NotImplementedError: only Standard PDF encryption handler is available |
| aes256_r6__objstm.pdf | h_refstm_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__objstm.pdf | h_trailer_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__objstm.pdf | xs_pure_encrypt | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| aes256_r6__objstm.pdf | xs_pure_none | pypdf | BLOCKED | False | **False** | FileNotDecryptedError: File has not been decrypted |
| control_plain.pdf | t_none | pypdf | OK | True | **False** |  |
| control_plain.pdf | t_encrypt_ref | pypdf | OK | True | **False** |  |
| control_plain.pdf | t_encrypt_empty | pypdf | OK | False | **False** |  |
| control_plain.pdf | alias_plain | pypdf | OK | False | **True** |  |
| control_plain.pdf | alias_encrypt | pypdf | OK | False | **True** |  |
| control_plain.pdf | root_old | pypdf | OK | False | **True** |  |
| control_plain.pdf | chain_none_encrypt | pypdf | OK | True | **False** |  |
| control_plain.pdf | chain_encrypt_none | pypdf | OK | True | **False** |  |
| control_plain.pdf | h_refstm_encrypt | pypdf | OK | True | **False** |  |
| control_plain.pdf | h_trailer_encrypt | pypdf | OK | True | **False** |  |
| control_plain.pdf | xs_pure_encrypt | pypdf | OK | True | **False** |  |
| control_plain.pdf | xs_pure_none | pypdf | OK | False | **True** |  |
| aes256_r6__plain.pdf | t_none | pdfminer | OK | True | **False** |  |
| aes256_r6__plain.pdf | t_encrypt_ref | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| aes256_r6__plain.pdf | t_encrypt_empty | pdfminer | OK | False | **False** |  |
| aes256_r6__plain.pdf | alias_plain | pdfminer | OK | False | **False** |  |
| aes256_r6__plain.pdf | alias_encrypt | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| aes256_r6__plain.pdf | root_old | pdfminer | OK | False | **False** |  |
| aes256_r6__plain.pdf | chain_none_encrypt | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| aes256_r6__plain.pdf | chain_encrypt_none | pdfminer | OK | True | **False** |  |
| aes256_r6__plain.pdf | shadow_encrypt_obj | pdfminer | OK | True | **False** |  |
| aes256_r6__plain.pdf | h_refstm_encrypt | pdfminer | OK | True | **False** |  |
| aes256_r6__plain.pdf | h_trailer_encrypt | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| aes256_r6__plain.pdf | xs_pure_encrypt | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| aes256_r6__plain.pdf | xs_pure_none | pdfminer | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | t_none | pdfminer | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | t_encrypt_ref | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| rc4_128_r4__plain.pdf | t_encrypt_empty | pdfminer | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | alias_plain | pdfminer | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | alias_encrypt | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| rc4_128_r4__plain.pdf | root_old | pdfminer | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | chain_none_encrypt | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| rc4_128_r4__plain.pdf | chain_encrypt_none | pdfminer | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | shadow_encrypt_obj | pdfminer | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | h_refstm_encrypt | pdfminer | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | h_trailer_encrypt | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| rc4_128_r4__plain.pdf | xs_pure_encrypt | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| rc4_128_r4__plain.pdf | xs_pure_none | pdfminer | OK | False | **False** |  |
| aes256_r6__objstm.pdf | t_none | pdfminer | OK | True | **False** |  |
| aes256_r6__objstm.pdf | t_encrypt_ref | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| aes256_r6__objstm.pdf | t_encrypt_empty | pdfminer | OK | False | **False** |  |
| aes256_r6__objstm.pdf | alias_plain | pdfminer | OK | False | **False** |  |
| aes256_r6__objstm.pdf | alias_encrypt | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| aes256_r6__objstm.pdf | root_old | pdfminer | OK | False | **False** |  |
| aes256_r6__objstm.pdf | chain_none_encrypt | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| aes256_r6__objstm.pdf | chain_encrypt_none | pdfminer | OK | True | **False** |  |
| aes256_r6__objstm.pdf | shadow_encrypt_obj | pdfminer | OK | False | **False** |  |
| aes256_r6__objstm.pdf | h_refstm_encrypt | pdfminer | OK | True | **False** |  |
| aes256_r6__objstm.pdf | h_trailer_encrypt | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| aes256_r6__objstm.pdf | xs_pure_encrypt | pdfminer | BLOCKED | False | **False** | PdfminerException:  |
| aes256_r6__objstm.pdf | xs_pure_none | pdfminer | OK | False | **False** |  |
| control_plain.pdf | t_none | pdfminer | OK | True | **False** |  |
| control_plain.pdf | t_encrypt_ref | pdfminer | OK | True | **False** |  |
| control_plain.pdf | t_encrypt_empty | pdfminer | OK | False | **False** |  |
| control_plain.pdf | alias_plain | pdfminer | OK | False | **True** |  |
| control_plain.pdf | alias_encrypt | pdfminer | OK | False | **True** |  |
| control_plain.pdf | root_old | pdfminer | OK | False | **True** |  |
| control_plain.pdf | chain_none_encrypt | pdfminer | OK | True | **False** |  |
| control_plain.pdf | chain_encrypt_none | pdfminer | OK | True | **False** |  |
| control_plain.pdf | h_refstm_encrypt | pdfminer | OK | True | **False** |  |
| control_plain.pdf | h_trailer_encrypt | pdfminer | OK | True | **False** |  |
| control_plain.pdf | xs_pure_encrypt | pdfminer | OK | True | **False** |  |
| control_plain.pdf | xs_pure_none | pdfminer | OK | False | **True** |  |
| aes256_r6__plain.pdf | t_none | pymupdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | t_encrypt_ref | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| aes256_r6__plain.pdf | t_encrypt_empty | pymupdf | OK | False | **False** |  |
| aes256_r6__plain.pdf | alias_plain | pymupdf | OK | False | **False** |  |
| aes256_r6__plain.pdf | alias_encrypt | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| aes256_r6__plain.pdf | root_old | pymupdf | OK | False | **False** |  |
| aes256_r6__plain.pdf | chain_none_encrypt | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| aes256_r6__plain.pdf | chain_encrypt_none | pymupdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | shadow_encrypt_obj | pymupdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | h_refstm_encrypt | pymupdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | h_trailer_encrypt | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| aes256_r6__plain.pdf | xs_pure_encrypt | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| aes256_r6__plain.pdf | xs_pure_none | pymupdf | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | t_none | pymupdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | t_encrypt_ref | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| rc4_128_r4__plain.pdf | t_encrypt_empty | pymupdf | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | alias_plain | pymupdf | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | alias_encrypt | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| rc4_128_r4__plain.pdf | root_old | pymupdf | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | chain_none_encrypt | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| rc4_128_r4__plain.pdf | chain_encrypt_none | pymupdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | shadow_encrypt_obj | pymupdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | h_refstm_encrypt | pymupdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | h_trailer_encrypt | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| rc4_128_r4__plain.pdf | xs_pure_encrypt | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| rc4_128_r4__plain.pdf | xs_pure_none | pymupdf | OK | False | **False** |  |
| aes256_r6__objstm.pdf | t_none | pymupdf | OK | True | **False** |  |
| aes256_r6__objstm.pdf | t_encrypt_ref | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| aes256_r6__objstm.pdf | t_encrypt_empty | pymupdf | OK | False | **False** |  |
| aes256_r6__objstm.pdf | alias_plain | pymupdf | OK | False | **False** |  |
| aes256_r6__objstm.pdf | alias_encrypt | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| aes256_r6__objstm.pdf | root_old | pymupdf | OK | False | **False** |  |
| aes256_r6__objstm.pdf | chain_none_encrypt | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| aes256_r6__objstm.pdf | chain_encrypt_none | pymupdf | OK | True | **False** |  |
| aes256_r6__objstm.pdf | shadow_encrypt_obj | pymupdf | OK | True | **False** |  |
| aes256_r6__objstm.pdf | h_refstm_encrypt | pymupdf | OK | True | **False** |  |
| aes256_r6__objstm.pdf | h_trailer_encrypt | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| aes256_r6__objstm.pdf | xs_pure_encrypt | pymupdf | BLOCKED | False | **False** | ValueError: document closed or encrypted |
| aes256_r6__objstm.pdf | xs_pure_none | pymupdf | OK | False | **False** |  |
| control_plain.pdf | t_none | pymupdf | OK | True | **False** |  |
| control_plain.pdf | t_encrypt_ref | pymupdf | OK | True | **False** |  |
| control_plain.pdf | t_encrypt_empty | pymupdf | OK | False | **False** |  |
| control_plain.pdf | alias_plain | pymupdf | OK | False | **True** |  |
| control_plain.pdf | alias_encrypt | pymupdf | OK | False | **True** |  |
| control_plain.pdf | root_old | pymupdf | OK | False | **True** |  |
| control_plain.pdf | chain_none_encrypt | pymupdf | OK | True | **False** |  |
| control_plain.pdf | chain_encrypt_none | pymupdf | OK | True | **False** |  |
| control_plain.pdf | h_refstm_encrypt | pymupdf | OK | True | **False** |  |
| control_plain.pdf | h_trailer_encrypt | pymupdf | OK | True | **False** |  |
| control_plain.pdf | xs_pure_encrypt | pymupdf | OK | True | **False** |  |
| control_plain.pdf | xs_pure_none | pymupdf | OK | False | **True** |  |
| aes256_r6__plain.pdf | t_none | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__plain.pdf | t_encrypt_ref | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__plain.pdf | t_encrypt_empty | pypdfium2 | OK | False | **False** |  |
| aes256_r6__plain.pdf | alias_plain | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__plain.pdf | alias_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__plain.pdf | root_old | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__plain.pdf | chain_none_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__plain.pdf | chain_encrypt_none | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__plain.pdf | shadow_encrypt_obj | pypdfium2 | ERROR | False | **False** | PdfiumError: Failed to load document (PDFium: Unsupported security scheme error). |
| aes256_r6__plain.pdf | h_refstm_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__plain.pdf | h_trailer_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__plain.pdf | xs_pure_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__plain.pdf | xs_pure_none | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | t_none | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | t_encrypt_ref | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | t_encrypt_empty | pypdfium2 | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | alias_plain | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | alias_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | root_old | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | chain_none_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | chain_encrypt_none | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | shadow_encrypt_obj | pypdfium2 | ERROR | False | **False** | PdfiumError: Failed to load document (PDFium: Unsupported security scheme error). |
| rc4_128_r4__plain.pdf | h_refstm_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | h_trailer_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | xs_pure_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| rc4_128_r4__plain.pdf | xs_pure_none | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__objstm.pdf | t_none | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__objstm.pdf | t_encrypt_ref | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__objstm.pdf | t_encrypt_empty | pypdfium2 | OK | False | **False** |  |
| aes256_r6__objstm.pdf | alias_plain | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__objstm.pdf | alias_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__objstm.pdf | root_old | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__objstm.pdf | chain_none_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__objstm.pdf | chain_encrypt_none | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__objstm.pdf | shadow_encrypt_obj | pypdfium2 | ERROR | False | **False** | PdfiumError: Failed to load document (PDFium: Unsupported security scheme error). |
| aes256_r6__objstm.pdf | h_refstm_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__objstm.pdf | h_trailer_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__objstm.pdf | xs_pure_encrypt | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| aes256_r6__objstm.pdf | xs_pure_none | pypdfium2 | BLOCKED | False | **False** | PdfiumError: Failed to load document (PDFium: Incorrect password error). |
| control_plain.pdf | t_none | pypdfium2 | OK | True | **False** |  |
| control_plain.pdf | t_encrypt_ref | pypdfium2 | OK | True | **False** |  |
| control_plain.pdf | t_encrypt_empty | pypdfium2 | OK | False | **False** |  |
| control_plain.pdf | alias_plain | pypdfium2 | OK | False | **True** |  |
| control_plain.pdf | alias_encrypt | pypdfium2 | OK | False | **True** |  |
| control_plain.pdf | root_old | pypdfium2 | OK | False | **True** |  |
| control_plain.pdf | chain_none_encrypt | pypdfium2 | OK | True | **False** |  |
| control_plain.pdf | chain_encrypt_none | pypdfium2 | OK | True | **False** |  |
| control_plain.pdf | h_refstm_encrypt | pypdfium2 | OK | True | **False** |  |
| control_plain.pdf | h_trailer_encrypt | pypdfium2 | OK | True | **False** |  |
| control_plain.pdf | xs_pure_encrypt | pypdfium2 | OK | True | **False** |  |
| control_plain.pdf | xs_pure_none | pypdfium2 | OK | False | **True** |  |
| aes256_r6__plain.pdf | t_none | pikepdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | t_encrypt_ref | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/aes256_r6__plain__t_encrypt_ref.pdf: invalid password |
| aes256_r6__plain.pdf | t_encrypt_empty | pikepdf | OK | False | **False** |  |
| aes256_r6__plain.pdf | alias_plain | pikepdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | alias_encrypt | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/aes256_r6__plain__alias_encrypt.pdf: invalid password |
| aes256_r6__plain.pdf | root_old | pikepdf | OK | False | **False** |  |
| aes256_r6__plain.pdf | chain_none_encrypt | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/aes256_r6__plain__chain_none_encrypt.pdf: invalid password |
| aes256_r6__plain.pdf | chain_encrypt_none | pikepdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | shadow_encrypt_obj | pikepdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | h_refstm_encrypt | pikepdf | OK | True | **False** |  |
| aes256_r6__plain.pdf | h_trailer_encrypt | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/aes256_r6__plain__h_trailer_encrypt.pdf: invalid password |
| aes256_r6__plain.pdf | xs_pure_encrypt | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/aes256_r6__plain__xs_pure_encrypt.pdf: invalid password |
| aes256_r6__plain.pdf | xs_pure_none | pikepdf | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | t_none | pikepdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | t_encrypt_ref | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/rc4_128_r4__plain__t_encrypt_ref.pdf: invalid password |
| rc4_128_r4__plain.pdf | t_encrypt_empty | pikepdf | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | alias_plain | pikepdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | alias_encrypt | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/rc4_128_r4__plain__alias_encrypt.pdf: invalid password |
| rc4_128_r4__plain.pdf | root_old | pikepdf | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | chain_none_encrypt | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/rc4_128_r4__plain__chain_none_encrypt.pdf: invalid password |
| rc4_128_r4__plain.pdf | chain_encrypt_none | pikepdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | shadow_encrypt_obj | pikepdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | h_refstm_encrypt | pikepdf | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | h_trailer_encrypt | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/rc4_128_r4__plain__h_trailer_encrypt.pdf: invalid password |
| rc4_128_r4__plain.pdf | xs_pure_encrypt | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/rc4_128_r4__plain__xs_pure_encrypt.pdf: invalid password |
| rc4_128_r4__plain.pdf | xs_pure_none | pikepdf | OK | False | **False** |  |
| aes256_r6__objstm.pdf | t_none | pikepdf | OK | True | **False** |  |
| aes256_r6__objstm.pdf | t_encrypt_ref | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/aes256_r6__objstm__t_encrypt_ref.pdf: invalid password |
| aes256_r6__objstm.pdf | t_encrypt_empty | pikepdf | OK | False | **False** |  |
| aes256_r6__objstm.pdf | alias_plain | pikepdf | OK | True | **False** |  |
| aes256_r6__objstm.pdf | alias_encrypt | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/aes256_r6__objstm__alias_encrypt.pdf: invalid password |
| aes256_r6__objstm.pdf | root_old | pikepdf | ERROR | False | **False** | PdfError: /home/sarthak/pdf-encryption-research/corpus/prevchain/aes256_r6__objstm__root_old.pdf: unable to find page tree |
| aes256_r6__objstm.pdf | chain_none_encrypt | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/aes256_r6__objstm__chain_none_encrypt.pdf: invalid password |
| aes256_r6__objstm.pdf | chain_encrypt_none | pikepdf | OK | True | **False** |  |
| aes256_r6__objstm.pdf | shadow_encrypt_obj | pikepdf | OK | True | **False** |  |
| aes256_r6__objstm.pdf | h_refstm_encrypt | pikepdf | OK | True | **False** |  |
| aes256_r6__objstm.pdf | h_trailer_encrypt | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/aes256_r6__objstm__h_trailer_encrypt.pdf: invalid password |
| aes256_r6__objstm.pdf | xs_pure_encrypt | pikepdf | BLOCKED | False | **False** | PasswordError: /home/sarthak/pdf-encryption-research/corpus/prevchain/aes256_r6__objstm__xs_pure_encrypt.pdf: invalid password |
| aes256_r6__objstm.pdf | xs_pure_none | pikepdf | ERROR | False | **False** | PdfError: /home/sarthak/pdf-encryption-research/corpus/prevchain/aes256_r6__objstm__xs_pure_none.pdf: unable to find page tree |
| control_plain.pdf | t_none | pikepdf | OK | True | **True** |  |
| control_plain.pdf | t_encrypt_ref | pikepdf | OK | True | **True** |  |
| control_plain.pdf | t_encrypt_empty | pikepdf | OK | False | **False** |  |
| control_plain.pdf | alias_plain | pikepdf | OK | True | **True** |  |
| control_plain.pdf | alias_encrypt | pikepdf | OK | True | **True** |  |
| control_plain.pdf | root_old | pikepdf | OK | False | **True** |  |
| control_plain.pdf | chain_none_encrypt | pikepdf | OK | True | **True** |  |
| control_plain.pdf | chain_encrypt_none | pikepdf | OK | True | **True** |  |
| control_plain.pdf | h_refstm_encrypt | pikepdf | OK | True | **True** |  |
| control_plain.pdf | h_trailer_encrypt | pikepdf | OK | True | **True** |  |
| control_plain.pdf | xs_pure_encrypt | pikepdf | OK | True | **True** |  |
| control_plain.pdf | xs_pure_none | pikepdf | OK | False | **True** |  |
| aes256_r6__plain.pdf | t_none | pdfjs | OK | True | **False** |  |
| aes256_r6__plain.pdf | t_encrypt_ref | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| aes256_r6__plain.pdf | t_encrypt_empty | pdfjs | OK | False | **False** |  |
| aes256_r6__plain.pdf | alias_plain | pdfjs | OK | False | **False** |  |
| aes256_r6__plain.pdf | alias_encrypt | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| aes256_r6__plain.pdf | root_old | pdfjs | OK | False | **False** |  |
| aes256_r6__plain.pdf | chain_none_encrypt | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| aes256_r6__plain.pdf | chain_encrypt_none | pdfjs | OK | True | **False** |  |
| aes256_r6__plain.pdf | shadow_encrypt_obj | pdfjs | OK | True | **False** |  |
| aes256_r6__plain.pdf | h_refstm_encrypt | pdfjs | OK | True | **False** |  |
| aes256_r6__plain.pdf | h_trailer_encrypt | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| aes256_r6__plain.pdf | xs_pure_encrypt | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| aes256_r6__plain.pdf | xs_pure_none | pdfjs | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | t_none | pdfjs | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | t_encrypt_ref | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| rc4_128_r4__plain.pdf | t_encrypt_empty | pdfjs | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | alias_plain | pdfjs | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | alias_encrypt | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| rc4_128_r4__plain.pdf | root_old | pdfjs | OK | False | **False** |  |
| rc4_128_r4__plain.pdf | chain_none_encrypt | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| rc4_128_r4__plain.pdf | chain_encrypt_none | pdfjs | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | shadow_encrypt_obj | pdfjs | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | h_refstm_encrypt | pdfjs | OK | True | **False** |  |
| rc4_128_r4__plain.pdf | h_trailer_encrypt | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| rc4_128_r4__plain.pdf | xs_pure_encrypt | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| rc4_128_r4__plain.pdf | xs_pure_none | pdfjs | OK | False | **False** |  |
| aes256_r6__objstm.pdf | t_none | pdfjs | OK | True | **False** |  |
| aes256_r6__objstm.pdf | t_encrypt_ref | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| aes256_r6__objstm.pdf | t_encrypt_empty | pdfjs | OK | False | **False** |  |
| aes256_r6__objstm.pdf | alias_plain | pdfjs | OK | False | **False** |  |
| aes256_r6__objstm.pdf | alias_encrypt | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| aes256_r6__objstm.pdf | root_old | pdfjs | ERROR | False | **False** | InvalidPDFException: Invalid Root reference. |
| aes256_r6__objstm.pdf | chain_none_encrypt | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| aes256_r6__objstm.pdf | chain_encrypt_none | pdfjs | OK | True | **False** |  |
| aes256_r6__objstm.pdf | shadow_encrypt_obj | pdfjs | OK | True | **False** |  |
| aes256_r6__objstm.pdf | h_refstm_encrypt | pdfjs | OK | True | **False** |  |
| aes256_r6__objstm.pdf | h_trailer_encrypt | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| aes256_r6__objstm.pdf | xs_pure_encrypt | pdfjs | BLOCKED | False | **False** | PasswordException: No password given |
| aes256_r6__objstm.pdf | xs_pure_none | pdfjs | ERROR | False | **False** | InvalidPDFException: Invalid Root reference. |
| control_plain.pdf | t_none | pdfjs | OK | True | **False** |  |
| control_plain.pdf | t_encrypt_ref | pdfjs | OK | True | **False** |  |
| control_plain.pdf | t_encrypt_empty | pdfjs | OK | False | **False** |  |
| control_plain.pdf | alias_plain | pdfjs | OK | False | **True** |  |
| control_plain.pdf | alias_encrypt | pdfjs | OK | False | **True** |  |
| control_plain.pdf | root_old | pdfjs | OK | False | **True** |  |
| control_plain.pdf | chain_none_encrypt | pdfjs | OK | True | **False** |  |
| control_plain.pdf | chain_encrypt_none | pdfjs | OK | True | **False** |  |
| control_plain.pdf | h_refstm_encrypt | pdfjs | OK | True | **False** |  |
| control_plain.pdf | h_trailer_encrypt | pdfjs | OK | True | **False** |  |
| control_plain.pdf | xs_pure_encrypt | pdfjs | OK | True | **False** |  |
| control_plain.pdf | xs_pure_none | pdfjs | OK | False | **True** |  |

Encrypted cases with original content shown: **0**
Encrypted cases with injected plaintext shown: 50

## Divergence by variant (encrypted seeds)

`opened, empty` = the engine accepted the document without a password but produced no canary (ciphertext treated as unencrypted content).

| variant | engines rendering injected page | opened, empty | refused |
|---|---|---|---|
| t_none | pdfminer, pymupdf, pikepdf, pdfjs | - | pypdf, pypdfium2 |
| t_encrypt_ref | - | - | pypdf, pdfminer, pymupdf, pypdfium2, pikepdf, pdfjs |
| t_encrypt_empty | - | pdfminer, pymupdf, pypdfium2, pikepdf, pdfjs | pypdf |
| alias_plain | pikepdf | pdfminer, pymupdf, pdfjs | pypdf, pypdfium2 |
| alias_encrypt | - | - | pypdf, pdfminer, pymupdf, pypdfium2, pikepdf, pdfjs |
| root_old | - | pdfminer, pymupdf | pypdf, pypdfium2, pikepdf, pdfjs |
| chain_none_encrypt | - | - | pypdf, pdfminer, pymupdf, pypdfium2, pikepdf, pdfjs |
| chain_encrypt_none | pdfminer, pymupdf, pikepdf, pdfjs | - | pypdf, pypdfium2 |
| shadow_encrypt_obj | pdfminer, pymupdf, pikepdf, pdfjs | - | pypdf, pypdfium2 |
| h_refstm_encrypt | pdfminer, pymupdf, pikepdf, pdfjs | - | pypdf, pypdfium2 |
| h_trailer_encrypt | - | - | pypdf, pdfminer, pymupdf, pypdfium2, pikepdf, pdfjs |
| xs_pure_encrypt | - | - | pypdf, pdfminer, pymupdf, pypdfium2, pikepdf, pdfjs |
| xs_pure_none | - | pdfminer, pymupdf | pypdf, pypdfium2, pikepdf, pdfjs |

## With-password controls (proof the constructs are valid)

| file | PyMuPDF status with correct user password | text |
|---|---|---|
| aes256_r6__plain__alias_encrypt.pdf | auth=2 needs_pass=1 pages=1 | CANARY aes256_r6__plain ALPHA Synthetic research sample - contains no real data. Document id: aes256_r6__plain |
| aes256_r6__plain__alias_plain.pdf | auth=1 needs_pass=0 pages=1 |  |
| aes256_r6__plain__t_encrypt_ref.pdf | auth=2 needs_pass=1 pages=1 |  |
| aes256_r6__plain__t_none.pdf | auth=1 needs_pass=0 pages=1 | INJECTED aes256_r6__plain t_none ALPHA |
| aes256_r6__plain__root_old.pdf | auth=1 needs_pass=0 pages=2 |  |  |

`alias_encrypt` + password returns the original canary, so the alias page really does reference the original encrypted content stream. Without the password the same alias yields nothing on every engine: decryption, not reference resolution, is the barrier.
