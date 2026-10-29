"""
Writer-diversity corpus: the same synthetic document encrypted by independent
PDF writers (reportlab, pypdf, PyMuPDF) across algorithms.

Rationale: our main corpus is entirely qpdf-written, i.e. "correctly" encrypted.
Real-world "locked PDFs" are produced by many tools, and writer bugs (missing
crypt filters, wrong key derivation, objects left plaintext) mean a file the
user believes is locked is readable by everyone. Those are high-impact,
user-facing bugs.

All output is synthetic. Canaries are copied from control_plain.pdf, the
plaintext source document used here.
"""
from __future__ import annotations

import json
from pathlib import Path

import pikepdf
from reportlab.lib.pagesizes import letter
from reportlab.lib import pdfencrypt
from reportlab.pdfgen import canvas

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
WRITERS = CORPUS / "writers"
SOURCE = CORPUS / "base" / "control_plain.pdf"
MANIFEST = CORPUS / "manifest.json"

USER_PW = "Us3r-Passw0rd!"
OWNER_PW = "0wner-Passw0rd!"

DOC_ID = "control_plain"  # canaries in the source document
CANARIES = [f"CANARY {DOC_ID} ALPHA", f"CANARY {DOC_ID} BRAVO"]
META_CANARY = f"META-CANARY {DOC_ID}"


def build_reportlab(path: Path, strength: int) -> None:
    enc = pdfencrypt.StandardEncryption(USER_PW, OWNER_PW, strength=strength)
    c = canvas.Canvas(str(path), pagesize=letter, encrypt=enc)
    w, h = letter
    c.setTitle("Synthetic research sample (reportlab)")
    c.setSubject(META_CANARY)
    c.drawString(72, h - 96, CANARIES[0])
    c.drawString(72, h - 128, "Synthetic research sample - contains no real data.")
    c.showPage()
    c.drawString(72, h - 96, CANARIES[1])
    c.drawString(72, h - 128, "Page two secret payload for leak detection.")
    c.showPage()
    c.save()


def build_pypdf(path: Path, algorithm: str) -> None:
    from pypdf import PdfReader, PdfWriter

    reader = PdfReader(str(SOURCE))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.encrypt(USER_PW, OWNER_PW, algorithm=algorithm)
    with open(path, "wb") as fh:
        writer.write(fh)


def build_pymupdf(path: Path, encryption: int) -> None:
    import pymupdf

    with pymupdf.open(str(SOURCE)) as doc:
        doc.save(
            str(path),
            encryption=encryption,
            user_pw=USER_PW,
            owner_pw=OWNER_PW,
        )


def probe_encryption(path: Path) -> dict:
    """Read back the writer's own output to record what it actually produced."""
    import pymupdf

    try:
        with pymupdf.open(str(path)) as doc:
            return {"needs_pass": bool(doc.needs_pass), "is_encrypted": bool(doc.is_encrypted)}
    except Exception as exc:
        return {"readback_error": f"{type(exc).__name__}: {exc}"}


def main() -> None:
    WRITERS.mkdir(parents=True, exist_ok=True)
    manifest = [e for e in json.loads(MANIFEST.read_text()) if not e["id"].startswith("w_")]

    def add(writer: str, algo: str, path: Path, note: str = "") -> None:
        rel = f"corpus/writers/{path.name}"
        info = probe_encryption(path)
        manifest.append({
            "id": f"w_{writer}_{algo}",
            "file": rel,
            "has_user_password": True,
            "user_password": USER_PW,
            "canaries": CANARIES,
            "meta_canary": META_CANARY,
            "meta_encrypted": True,
            "attach_canary": None,
            "notes": f"writer={writer}; algorithm={algo}; {note}",
            "writer": writer,
            "algorithm": algo,
            **info,
        })
        print(f"[ok]   {writer}/{algo} -> {path.name} {info}")

    # --- reportlab ---
    import reportlab
    for strength in (40, 128, 256):
        p = WRITERS / f"reportlab_s{strength}.pdf"
        try:
            build_reportlab(p, strength)
            add("reportlab", f"s{strength}", p, f"reportlab {reportlab.Version}")
        except Exception as exc:
            print(f"[skip] reportlab s{strength}: {type(exc).__name__}: {exc}")

    # --- pypdf ---
    import pypdf
    for algorithm in ("RC4-40", "RC4-128", "AES-128", "AES-256"):
        p = WRITERS / f"pypdf_{algorithm.replace('-', '').lower()}.pdf"
        try:
            build_pypdf(p, algorithm)
            add("pypdf", algorithm.lower(), p, f"pypdf {pypdf.__version__}")
        except Exception as exc:
            print(f"[skip] pypdf {algorithm}: {type(exc).__name__}: {exc}")

    # --- pymupdf ---
    import pymupdf
    for algo, const in [
        ("rc440", pymupdf.PDF_ENCRYPT_RC4_40),
        ("rc4128", pymupdf.PDF_ENCRYPT_RC4_128),
        ("aes128", pymupdf.PDF_ENCRYPT_AES_128),
        ("aes256", pymupdf.PDF_ENCRYPT_AES_256),
    ]:
        p = WRITERS / f"pymupdf_{algo}.pdf"
        try:
            build_pymupdf(p, const)
            add("pymupdf", algo, p, f"pymupdf {pymupdf.__version__}")
        except Exception as exc:
            print(f"[skip] pymupdf {algo}: {type(exc).__name__}: {exc}")

    MANIFEST.write_text(json.dumps(manifest, indent=2))
    print(f"\nManifest now has {len(manifest)} entries")


if __name__ == "__main__":
    main()
