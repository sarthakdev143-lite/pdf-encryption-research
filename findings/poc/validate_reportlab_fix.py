"""
Validate the root cause and the fix for F-2026-002 (reportlab AES-256).

ISO 32000-2: /UE, /OE are 32-byte AES-256-CBC ciphertexts of the file key and
/Perms is a 16-byte AES-ECB ciphertext - all with NO padding. reportlab 5.1.0
finalizes each pyaes.Encrypter with a padding block, producing 48/48/32 bytes.

This script:
  1. patches the installed reportlab source so those three encrypter
     constructions use padding=None (backup restored in finally),
  2. generates a strength=256 PDF in a fresh subprocess,
  3. restores the original source,
  4. verifies the resulting /UE /OE /Perms sizes and reader compatibility.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pyaes

REPORTLAB = Path(r"C:\Python312\Lib\site-packages\reportlab\lib\pdfencrypt.py")
OUT = Path(__file__).resolve().parent / "reportlab_s256_fixed.pdf"
ROOT = Path(__file__).resolve().parents[2]  # research repo root

# --- sanity: pyaes padding=None really means "no padding" -------------------
mode = pyaes.AESModeOfOperationCBC(b"\x00" * 32, iv=b"\x00" * 16)
enc = pyaes.Encrypter(mode, padding=pyaes.PADDING_NONE)
ct = enc.feed(b"A" * 32) + enc.feed()
assert len(ct) == 32, f"pyaes padding=None produced {len(ct)} bytes, expected 32"
print("[ok] pyaes padding=None -> 32-byte ciphertext, no padding block")

PATCHES = [
    (
        "            encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(md.digest(), iv=iv))\n"
        "            self.UE = encrypter.feed(self.key)",
        "            encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(md.digest(), iv=iv), padding=pyaes.PADDING_NONE)\n"
        "            self.UE = encrypter.feed(self.key)",
    ),
    (
        "            encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(md.digest(), iv=iv))\n"
        "            self.OE = encrypter.feed(self.key)",
        "            encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(md.digest(), iv=iv), padding=pyaes.PADDING_NONE)\n"
        "            self.OE = encrypter.feed(self.key)",
    ),
    (
        "            encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(self.key, iv=iv))\n"
        "            self.Perms = encrypter.feed(bytes(permsarr))",
        "            encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(self.key, iv=iv), padding=pyaes.PADDING_NONE)\n"
        "            self.Perms = encrypter.feed(bytes(permsarr))",
    ),
]

GEN = """
from reportlab.lib.pagesizes import letter
from reportlab.lib import pdfencrypt
from reportlab.pdfgen import canvas
enc = pdfencrypt.StandardEncryption("Us3r-Passw0rd!", "0wner-Passw0rd!", strength=256)
c = canvas.Canvas(r"{out}", pagesize=letter, encrypt=enc)
w, h = letter
c.drawString(72, h - 96, "CANARY control_plain ALPHA")
c.drawString(72, h - 128, "Synthetic research sample - contains no real data.")
c.showPage()
c.drawString(72, h - 96, "CANARY control_plain BRAVO")
c.showPage()
c.save()
print("generated")
""".format(out=OUT)

original = REPORTLAB.read_text(encoding="utf-8")
patched = original
for old, new in PATCHES:
    assert old in patched, f"patch anchor missing:\n{old[:80]}"
    patched = patched.replace(old, new)
patched = patched.replace("self.UE += encrypter.feed()\n", "self.UE += encrypter.feed()\n")
assert patched != original

report: dict[str, object] = {}
try:
    REPORTLAB.write_text(patched, encoding="utf-8")
    proc = subprocess.run([sys.executable, "-c", GEN], capture_output=True, text=True)
    report["gen"] = (proc.returncode, proc.stdout.strip(), proc.stderr[-300:])
finally:
    REPORTLAB.write_text(original, encoding="utf-8")
    # prove the restore
    assert REPORTLAB.read_text(encoding="utf-8") == original
    print("[ok] reportlab source restored")

data = OUT.read_bytes()
for key in (b"/O", b"/U", b"/OE", b"/UE", b"/Perms"):
    m = re.search(re.escape(key) + rb"\s*<([0-9A-Fa-f]+)>", data)
    report[key.decode()] = len(m.group(1)) // 2 if m else None
print("[sizes]", report["/O"], report["/U"], report["/OE"], report["/UE"], report["/Perms"])

import pymupdf

with pymupdf.open(str(OUT)) as doc:
    report["pymupdf"] = {"needs_pass": doc.needs_pass, "auth": doc.authenticate("Us3r-Passw0rd!"), "pages": doc.page_count}
    if doc.page_count:
        report["pymupdf_text"] = doc[0].get_text().strip()[:60]

import pypdf

r = pypdf.PdfReader(str(OUT))
report["pypdf_decrypt"] = int(r.decrypt("Us3r-Passw0rd!"))
report["pypdf_text"] = r.pages[0].extract_text()[:60]

print("\n=== validation ===")
print(report)
