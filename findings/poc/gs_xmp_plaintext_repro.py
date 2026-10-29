"""Minimal repro: Ghostscript pdfwrite leaves the XMP /Metadata stream plaintext
in a user-password encrypted PDF (observation O-2026-005).

Synthetic only. Needs gs (see findings/writer_plaintext.md) and this repo's
venv (pikepdf, pymupdf).
"""
import os, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("PDF_GS_ROOT", Path.home() / ".local" / "gs"))
GS = os.environ.get("PDF_GS", str(ROOT / "usr/bin/gs"))
SHARE = ROOT / "usr/share/ghostscript"
env = dict(os.environ, LD_LIBRARY_PATH=str(ROOT / "usr/lib/x86_64-linux-gnu"),
           GS_LIB=f"{SHARE}/10.06.0/Resource/Init:{SHARE}/10.06.0/lib")

SRC, OUT = HERE / "O-2026-005-source.ps", HERE / "O-2026-005-gs-plaintext-xmp-ps.pdf"
SRC.write_text("""%!PS-Adobe-3.0
[ /Title (CONFIDENTIAL - Project Nightingale) /Subject (SECRET-SUBJECT-CANARY)
  /Author (Synthetic Research) /DOCINFO pdfmark
/Helvetica findfont 18 scalefont setfont
72 700 moveto (PAGE-CANARY: this body text must be encrypted) show showpage
""")
subprocess.run([GS, "-q", "-dNOPAUSE", "-dBATCH", "-dSAFER", "-sDEVICE=pdfwrite",
                f"-sOutputFile={OUT}", "-sOwnerPassword=owner", "-sUserPassword=user",
                "-dEncryptionR=3", "-dKeyLength=128", str(SRC)], check=True, env=env)

data = OUT.read_bytes()
print("gs:", subprocess.run([GS, "--version"], capture_output=True, text=True, env=env).stdout.strip())
print("no password -> title readable   :", b"CONFIDENTIAL - Project Nightingale" in data)
print("no password -> subject readable :", b"SECRET-SUBJECT-CANARY" in data)
print("no password -> body readable    :", b"PAGE-CANARY" in data)

import pikepdf, pymupdf
try:
    pikepdf.open(OUT); print("pikepdf opened WITHOUT password: BAD")
except pikepdf.PasswordError:
    print("pikepdf without password: refused (genuinely encrypted)")
with pymupdf.open(OUT) as d:
    print("with password: auth", d.authenticate("user"), "| page text:",
          d[0].get_text().strip())
