"""
Generate a synthetic corpus of password-protected PDFs for differential testing.

Every document embeds unique canary strings (page text, XMP/Info metadata,
embedded-file content) so `triage.py` can prove or disprove that a parser
leaked content from behind a user password.

SCOPE: all output is synthetic. Do not point this research at real documents.
"""
from __future__ import annotations

import json
from pathlib import Path

import pikepdf
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
BASE = CORPUS / "base"

USER_PW = "Us3r-Passw0rd!"
OWNER_PW = "0wner-Passw0rd!"

# (variant_id, R, aes)  - qpdf derives /V from R + aes:
#   R=2 -> V1 (RC4-40), R=3 -> V2 (RC4-128), R=4 -> V4 (RC4-128 or AES-128 crypt filter),
#   R=5 -> V5 AES-256 (Adobe 2008), R=6 -> V5 AES-256 (ISO hardened hash)
ALGORITHMS = [
    ("rc4_40_r2", 2, False),
    ("rc4_128_r3", 3, False),
    ("rc4_128_r4", 4, False),
    ("aes128_r4", 4, True),
    ("aes256_r5", 5, True),
    ("aes256_r6", 6, True),
]

# (structure_id, extra save kwargs)
STRUCTURES = [
    ("plain", {}),
    ("objstm", {"object_stream_mode": pikepdf.ObjectStreamMode.generate}),
    ("linearized", {"linearize": True}),
]


def make_base(path: Path, doc_id: str, form: bool = False) -> None:
    """Two-page synthetic doc with canaries on both pages and in Info/Subject."""
    c = canvas.Canvas(str(path), pagesize=letter)
    w, h = letter
    c.setTitle(f"Synthetic research sample {doc_id}")
    c.setSubject(f"META-CANARY {doc_id}")
    c.setAuthor("PDF Encryption Research (synthetic)")
    c.drawString(72, h - 96, f"CANARY {doc_id} ALPHA")
    c.drawString(72, h - 128, "Synthetic research sample - contains no real data.")
    c.drawString(72, h - 152, f"Document id: {doc_id}")
    if form:
        c.acroForm.textfield(
            name=f"field_{doc_id}",
            tooltip="synthetic field",
            x=72,
            y=h - 220,
            width=220,
            height=24,
        )
    c.showPage()
    c.drawString(72, h - 96, f"CANARY {doc_id} BRAVO")
    c.drawString(72, h - 128, "Page two secret payload for leak detection.")
    c.showPage()
    c.save()


def stamp_xmp(path: Path, doc_id: str) -> None:
    """Add an XMP /Metadata stream carrying the metadata canary."""
    pdf = pikepdf.Pdf.open(path)
    tmp = path.with_suffix(".tmp.pdf")
    try:
        with pdf.open_metadata(set_pikepdf_as_editor=False, update_docinfo=False) as meta:
            meta["dc:title"] = f"META-CANARY {doc_id}"
            meta["dc:description"] = f"META-CANARY {doc_id} description"
        pdf.save(tmp)
    except Exception as exc:
        print(f"[warn] xmp {doc_id}: {type(exc).__name__}: {exc}")
        tmp.unlink(missing_ok=True)
    finally:
        pdf.close()
    if tmp.exists():
        tmp.replace(path)


def add_attachment(path: Path, doc_id: str) -> None:
    """Attach a synthetic text file carrying the attachment canary."""
    payload = path.parent / "_attach_payload.txt"
    payload.write_text(
        f"ATTACH-CANARY {doc_id}\nSynthetic embedded file for encryption research.\n",
        encoding="utf-8",
    )
    pdf = pikepdf.Pdf.open(path)
    tmp = path.with_suffix(".tmp.pdf")
    try:
        pdf.attachments["canary.txt"] = pikepdf.AttachedFileSpec.from_filepath(
            pdf, str(payload)
        )
        pdf.save(tmp)
    finally:
        pdf.close()
    tmp.replace(path)
    payload.unlink(missing_ok=True)


def encrypt_and_save(
    src: Path,
    dst: Path,
    R: int | None,
    aes: bool,
    user_pw: str,
    owner_pw: str,
    meta: bool = True,
    save_opts: dict | None = None,
) -> None:
    pdf = pikepdf.Pdf.open(src)
    try:
        enc = None
        if R is not None:
            enc = pikepdf.Encryption(
                owner=owner_pw, user=user_pw, R=R, aes=aes, metadata=meta
            )
        pdf.save(dst, encryption=enc, **(save_opts or {}))
    finally:
        pdf.close()


def main() -> None:
    BASE.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []

    def entry(
        doc_id: str,
        rel: str,
        has_user_pw: bool,
        notes: str,
        meta_encrypted: bool = True,
        attach_canary: str | None = None,
        **extra,
    ) -> None:
        manifest.append(
            {
                "id": doc_id,
                "file": rel,
                "has_user_password": has_user_pw,
                "user_password": USER_PW if has_user_pw else "",
                "canaries": [f"CANARY {doc_id} ALPHA", f"CANARY {doc_id} BRAVO"],
                "meta_canary": f"META-CANARY {doc_id}",
                "meta_encrypted": meta_encrypted,
                "attach_canary": attach_canary,
                "notes": notes,
                **extra,
            }
        )

    def build(doc_id: str, attach: bool = False) -> Path:
        src = BASE / f"_src_{doc_id}.pdf"
        make_base(src, doc_id)
        stamp_xmp(src, doc_id)
        if attach:
            add_attachment(src, doc_id)
        return src

    # --- control: plaintext file (proves the extractors actually extract) ---
    doc_id = "control_plain"
    src = build(doc_id)
    src.replace(BASE / f"{doc_id}.pdf")
    entry(doc_id, f"corpus/base/{doc_id}.pdf", False, "plaintext control")
    print(f"[ok]   {doc_id}")

    # --- control: owner-password only (opens freely; NOT a bug if readable) ---
    doc_id = "control_owner_only"
    src = build(doc_id)
    encrypt_and_save(src, BASE / f"{doc_id}.pdf", R=6, aes=True, user_pw="", owner_pw=OWNER_PW)
    src.unlink(missing_ok=True)
    entry(
        doc_id, f"corpus/base/{doc_id}.pdf", False,
        "owner-password only (user password empty): opens freely by design",
        algorithm="aes256_r6", R=6,
    )
    print(f"[ok]   {doc_id}")

    # --- main matrix: algorithms x structures ---
    for algo_id, R, aes in ALGORITHMS:
        for struct_id, save_opts in STRUCTURES:
            doc_id = f"{algo_id}__{struct_id}"
            src = build(doc_id)
            meta_enc = R >= 4 and aes
            try:
                encrypt_and_save(
                    src, BASE / f"{doc_id}.pdf", R=R, aes=aes,
                    user_pw=USER_PW, owner_pw=OWNER_PW,
                    meta=meta_enc, save_opts=save_opts,
                )
            except Exception as exc:  # e.g. linearize unsupported
                print(f"[skip] {doc_id}: {type(exc).__name__}: {exc}")
                src.unlink(missing_ok=True)
                continue
            src.unlink(missing_ok=True)
            entry(
                doc_id, f"corpus/base/{doc_id}.pdf", True,
                f"user password set; {algo_id}; structure={struct_id}",
                meta_encrypted=meta_enc,
                algorithm=algo_id, R=R, structure=struct_id,
            )
            print(f"[ok]   {doc_id}")

    # --- /EncryptMetadata false variant (XMP stream intentionally plaintext) ---
    doc_id = "aes256_r6__nometa"
    src = build(doc_id)
    encrypt_and_save(
        src, BASE / f"{doc_id}.pdf", R=6, aes=True,
        user_pw=USER_PW, owner_pw=OWNER_PW, meta=False,
    )
    src.unlink(missing_ok=True)
    entry(
        doc_id, f"corpus/base/{doc_id}.pdf", True,
        "user password set; /EncryptMetadata false (XMP plaintext by spec)",
        meta_encrypted=False,
        algorithm="aes256_r6", R=6, structure="nometa",
    )
    print(f"[ok]   {doc_id}")

    # --- encrypted AcroForm ---
    doc_id = "aes256_r6__form"
    src = build(doc_id)
    make_base(BASE / f"_src_{doc_id}.pdf", doc_id, form=True)  # re-create with form
    stamp_xmp(BASE / f"_src_{doc_id}.pdf", doc_id)
    encrypt_and_save(
        BASE / f"_src_{doc_id}.pdf", BASE / f"{doc_id}.pdf", R=6, aes=True,
        user_pw=USER_PW, owner_pw=OWNER_PW,
    )
    (BASE / f"_src_{doc_id}.pdf").unlink(missing_ok=True)
    entry(
        doc_id, f"corpus/base/{doc_id}.pdf", True,
        "encrypted AcroForm text field",
        algorithm="aes256_r6", R=6, structure="form",
    )
    print(f"[ok]   {doc_id}")

    # --- embedded file (attachment) canaries ---
    for algo_id, R, aes in [("rc4_128_r4", 4, False), ("aes256_r6", 6, True)]:
        doc_id = f"{algo_id}__attach"
        src = build(doc_id, attach=True)
        meta_enc = R >= 4 and aes
        encrypt_and_save(
            src, BASE / f"{doc_id}.pdf", R=R, aes=aes,
            user_pw=USER_PW, owner_pw=OWNER_PW, meta=meta_enc,
        )
        src.unlink(missing_ok=True)
        entry(
            doc_id, f"corpus/base/{doc_id}.pdf", True,
            f"user password set; embedded file canary; {algo_id}",
            meta_encrypted=meta_enc,
            attach_canary=f"ATTACH-CANARY {doc_id}",
            algorithm=algo_id, R=R, structure="attach",
        )
        print(f"[ok]   {doc_id}")

    (CORPUS / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\nWrote {len(manifest)} files -> {BASE}")
    print(f"Manifest -> {CORPUS / 'manifest.json'}")


if __name__ == "__main__":
    main()
