# reportlab AES-256 (strength=256) writes non-conforming /UE, /OE and /Perms; files fail to open with the correct password in MuPDF, pypdf and pdfminer.six

**Project:** reportlab
**Version:** 5.1.0 (Python 3.12.1, Windows 11)
**Severity:** Medium (interoperability / availability; no confidentiality impact observed)
**Status:** ready to file privately

## Summary

`reportlab.lib.pdfencrypt.StandardEncryption(..., strength=256)` produces PDFs
whose encryption dictionary violates ISO 32000-2 field sizes:

| Field | reportlab 5.1.0 | ISO 32000-2 | qpdf reference |
|---|---|---|---|
| `/UE` | **48 bytes** | 32 bytes | 32 |
| `/OE` | **48 bytes** | 32 bytes | 32 |
| `/Perms` | **32 bytes** | 16 bytes | 16 |
| `/O`, `/U` | 48 bytes | 48 bytes | 48 |

The extra bytes are a PKCS#7 padding block: reportlab finalizes the pyaes
encrypter with a padding call (`encrypter.feed()`), but the spec requires
AES-256-CBC **without padding** for `/UE` and `/OE`, and a 16-byte
AES-ECB result for `/Perms`.

Consequence: files encrypted by reportlab with `strength=256` cannot be opened
with the **correct password** by several independent readers.

## Reproduction

```python
from reportlab.lib.pagesizes import letter
from reportlab.lib import pdfencrypt
from reportlab.pdfgen import canvas

enc = pdfencrypt.StandardEncryption("Us3r-Passw0rd!", "0wner-Passw0rd!", strength=256)
c = canvas.Canvas("reportlab_aes256.pdf", pagesize=letter, encrypt=enc)
c.drawString(72, 700, "hello")
c.save()
```

Then, with the correct password:

| Reader | Version | Result |
|---|---|---|
| MuPDF / PyMuPDF | 1.27.2 | `FileDataError: Failed to open file` (cannot open at all) |
| pypdf | 6.20.0 | `ValueError: Invalid key size (384) for AES` |
| pdfminer.six / pdfplumber | 20260107 / 0.11.10 | `PdfminerException: Invalid key size (384) for AES` |
| qpdf / pikepdf | 10.17.0 | opens, decrypts correctly |
| PDFium / pypdfium2 | 5.13.0 | opens, decrypts correctly |
| pdf.js | 5.x | opens, decrypts correctly |

The `384` is 48 bytes × 8: pypdf/pdfminer AES-decrypt `/UE`, receive the padded
48-byte plaintext and pass it as an AES key, which `cryptography` rejects.

## Root cause

`reportlab/lib/pdfencrypt.py`, `StandardEncryption.__init__`, `revision == 5`
branch (reportlab 5.1.0):

```python
encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(md.digest(), iv=iv))
self.UE = encrypter.feed(self.key)
self.UE += encrypter.feed()          # <- finalizes with PKCS#7 padding
```

and the same pattern for `/OE` and `/Perms`:

```python
encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(self.key, iv=iv))
self.Perms = encrypter.feed(bytes(permsarr))
self.Perms += encrypter.feed()       # <- adds a second 16-byte block
```

pyaes' no-argument `feed()` finalizes the CBC feeder and applies its default
PKCS#7 padding, turning the 32-byte file key into a 48-byte ciphertext and the
16-byte permissions array into 32 bytes.

## Fix (validated)

Construct the three encrypters with `padding=pyaes.PADDING_NONE`:

```diff
-            encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(md.digest(), iv=iv))
+            encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(md.digest(), iv=iv), padding=pyaes.PADDING_NONE)
             self.UE = encrypter.feed(self.key)
             self.UE += encrypter.feed()
```

(and the same for `OE` and `Perms`; content-stream encryption must keep padding).

Validation with the patch applied: `/O` 48, `/U` 48, `/OE` 32, `/UE` 32,
`/Perms` 16; the resulting file opens in MuPDF (`authenticate()` → user
password, 2 pages, text extracted) and pypdf (`decrypt()` → 1, text extracted).
Validation script: `findings/poc/validate_reportlab_fix.py` in this repo.

## Notes

- `strength=256` requires the optional `pyaes` package and is described as
  "in beta" in the CLI help comment, but it is reachable through the public
  `StandardEncryption` API and canvas `encrypt=` parameter.
- No confidentiality impact was found: every reader tested (including those
  above) still refuses the file without the password.
- Readers that tolerate the padding (qpdf, PDFium, pdf.js) most likely truncate
  the decrypted key to 32 bytes; strict implementations reject.
