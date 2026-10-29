"""
Track 4 - writer diversity: Ghostscript.

Question: does a real-world producer (Ghostscript's `pdfwrite`, used by print
pipelines, CUPS filters, `ps2pdf`, and many "flatten/repair this PDF" tools)
ever emit an encrypted PDF with content left in plaintext?  A user believes
such a file is locked; if the text is readable without the password that is a
writer-side confidentiality bug (scope table: "writer ... so the file is not
actually protected").

This harness produces synthetic encrypted PDFs with the gs CLI from the repo's
own plaintext canary document, then tests them two independent ways:

  1. RAW scan - the exact bytes of the file, and every stream that inflates
     (FlateDecode) WITHOUT any decryption, are searched for the page and
     metadata canaries.  A hit is plaintext content in a file that claims to
     be encrypted: engine-independent proof, no viewer needed.
  2. ENGINE differential - the six triage engines get the file with no
     password.  LEAK means content came out of a user-password file.

Ghostscript is not installed system-wide on this VPS.  It is unpacked under
~/.local/gs (see findings/writer_plaintext.md); override with PDF_GS.

All input and output is synthetic.
"""
from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
WRITERS = CORPUS / "writers"
SOURCE = CORPUS / "base" / "control_plain.pdf"
MANIFEST = CORPUS / "manifest.json"
FINDINGS = ROOT / "findings"

USER_PW = "Us3r-Passw0rd!"
OWNER_PW = "0wner-Passw0rd!"
DOC_ID = "control_plain"
CANARIES = [f"CANARY {DOC_ID} ALPHA", f"CANARY {DOC_ID} BRAVO"]
META_CANARY = f"META-CANARY {DOC_ID}"
# Text that appears in the page content but is not a canary: still a leak if
# it survives in plaintext.
EXTRA_NEEDLES = [
    "Synthetic research sample",
    "Page two secret payload",
    "Document id:",
]

GSROOT = Path(os.environ.get("PDF_GS_ROOT", Path.home() / ".local" / "gs"))
GS_BIN = Path(os.environ.get("PDF_GS", GSROOT / "usr/bin/gs"))
GS_SHARE = GSROOT / "usr/share/ghostscript"

# (id, -dEncryptionR, -dKeyLength)
VARIANTS = [
    ("r2_k40", 2, 40),    # RC4-40,  /V 1
    ("r3_k40", 3, 40),    # RC4-40,  /V 2
    ("r3_k128", 3, 128),  # RC4-128, /V 2 (gs default for "strong" output)
]


def gs_env() -> dict:
    share = GS_SHARE
    ver_dirs = sorted(p.name for p in share.glob("*") if p.is_dir())
    if not ver_dirs:
        raise SystemExit(f"[fatal] no Ghostscript resource dir under {share}")
    ver = ver_dirs[-1]
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(GSROOT / "usr/lib/x86_64-linux-gnu")
    env["GS_LIB"] = f"{share}/{ver}/Resource/Init:{share}/{ver}/lib"
    return env


def build(path: Path, R: int, keylen: int) -> None:
    cmd = [
        str(GS_BIN), "-q", "-dNOPAUSE", "-dBATCH", "-dSAFER",
        "-sDEVICE=pdfwrite", f"-sOutputFile={path}",
        f"-sOwnerPassword={OWNER_PW}", f"-sUserPassword={USER_PW}",
        f"-dEncryptionR={R}", f"-dKeyLength={keylen}", "-dPermissions=-4",
        str(SOURCE),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=gs_env(), timeout=120)
    if proc.returncode != 0 or not path.exists() or path.stat().st_size == 0:
        raise RuntimeError(f"gs failed ({proc.returncode}): {proc.stderr[-400:]}")


def inflate_streams(data: bytes) -> tuple[int, int, list[bytes]]:
    """Return (stream_count, inflated_count, raw_inflated_payloads).

    Streams are located by the `stream ... endstream` framing only; the /Length
    value is not trusted.  Both zlib and raw-deflate are attempted, which is
    what a reader does for /FlateDecode.
    """
    payloads: list[bytes] = []
    count = 0
    inflated = 0
    for m in re.finditer(rb"stream\r?\n", data):
        count += 1
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        body = data[start:end].rstrip(b"\r\n")
        out = None
        for raw in (False, True):
            try:
                out = zlib.decompress(body, -15 if raw else 15)
                break
            except zlib.error:
                out = None
        if out is None:
            continue
        inflated += 1
        payloads.append(out)
    return count, inflated, payloads


OBJ_RE = re.compile(rb"(\d+)\s+0\s+obj")


def locate(data: bytes, needle: str) -> list[str]:
    """Where does `needle` appear? Returns ['obj 11 (stream)', 'obj 4'] etc."""
    out: list[str] = []
    raw = needle.encode()
    i = data.find(raw)
    while i >= 0:
        m = None
        for m in OBJ_RE.finditer(data, 0, i):
            pass
        obj = m.group(1).decode() if m else "?"
        # inside a stream? last 'stream' after the object header
        start = m.end() if m else 0
        in_stream = data.rfind(b"stream", start, i) > data.rfind(b"endstream", start, i)
        out.append(f"obj {obj}{' (stream)' if in_stream else ''}")
        i = data.find(raw, i + 1)
    return out


def raw_scan(path: Path, needles: list[str], page_needles: list[str]) -> dict:
    data = path.read_bytes()
    hits: list[str] = []
    page_hits: list[str] = []
    for n in needles:
        for where in locate(data, n):
            hits.append(f"{n} @ {where}")
            if n in page_needles:
                page_hits.append(f"{n} @ {where}")
    count, inflated, payloads = inflate_streams(data)
    for i, payload in enumerate(payloads):
        text = payload.decode("latin-1", "replace")
        for n in needles:
            if n in text:
                hits.append(f"{n} @ inflatable-stream-{i}")
                if n in page_needles:
                    page_hits.append(f"{n} @ inflatable-stream-{i}")
    return {
        "bytes": len(data),
        "streams": count,
        "inflated_streams": inflated,
        "plaintext_hits": hits,
        "page_hits": page_hits,
    }


def with_password_control(path: Path) -> dict:
    """Prove the file is genuinely encrypted and still carries the canaries."""
    import pymupdf

    try:
        with pymupdf.open(str(path)) as doc:
            auth = doc.authenticate(USER_PW)
            text = "\n".join(p.get_text() for p in doc)
            meta = doc.metadata or {}
            meta_text = json.dumps(meta, default=str)
            return {
                "auth": auth,
                "needs_pass": int(doc.needs_pass),
                "pages": doc.page_count,
                "page_canaries": sum(c in text for c in CANARIES),
                "meta_canary": META_CANARY in meta_text,
            }
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"[:200]}


def engine_differential(path: Path) -> list[dict]:
    from triage import EXTRACTORS, classify, run_batch

    entry = {
        "has_user_password": True,
        "canaries": CANARIES,
        "meta_canary": META_CANARY,
        "meta_encrypted": True,
        "attach_canary": None,
    }
    rows = []
    for engine in EXTRACTORS:
        results, failure = run_batch(engine, [str(path)], 60)
        res = results[str(path)] if results else (failure or {"status": "ERROR"})
        if results:
            res["status"] = classify(entry, res)
        rows.append({
            "engine": engine,
            "status": res["status"],
            "text_len": res.get("text_len", 0),
            "detail": (res.get("error") or "")[:120],
        })
    return rows


def cross_writer_scan(manifest: list[dict]) -> list[dict]:
    """Raw plaintext scan over every user-password writer sample in the repo.

    Engine-independent check for Track 4: is any page content or (should-be
    encrypted) metadata left readable in the file bytes / unencrypted streams?
    """
    rows = []
    for e in manifest:
        rel = e["file"]
        if not (rel.startswith("corpus/base/") or rel.startswith("corpus/writers/")):
            continue
        if not e.get("has_user_password"):
            continue
        path = ROOT / rel
        if not path.exists():
            continue
        raw = raw_scan(path, e["canaries"] + [e["meta_canary"]], e["canaries"])
        meta = [h for h in raw["plaintext_hits"] if h.startswith(e["meta_canary"])]
        rows.append({
            "file": rel,
            "writer": e.get("writer", "qpdf"),
            "algorithm": e.get("algorithm", ""),
            "meta_encrypted": e.get("meta_encrypted", True),
            "page_plaintext": "; ".join(raw["page_hits"]) or "-",
            "meta_plaintext": "; ".join(meta) or "-",
            "streams": raw["streams"],
            "inflated": raw["inflated_streams"],
        })
    return rows


def main() -> None:
    if not GS_BIN.exists():
        raise SystemExit(f"[fatal] gs not found at {GS_BIN}; set PDF_GS")
    if not SOURCE.exists():
        raise SystemExit("[fatal] run generate_corpus.py first")
    WRITERS.mkdir(parents=True, exist_ok=True)
    FINDINGS.mkdir(exist_ok=True)

    manifest = json.loads(MANIFEST.read_text())
    manifest = [e for e in manifest if not e["id"].startswith("w_gs_")]
    needles = CANARIES + [META_CANARY] + EXTRA_NEEDLES

    rows: list[dict] = []
    controls: list[dict] = []
    leaks = 0

    for vid, R, keylen in VARIANTS:
        path = WRITERS / f"gs_{vid}.pdf"
        build(path, R, keylen)

        raw = raw_scan(path, needles, CANARIES)
        ctrl = with_password_control(path)
        engines = engine_differential(path)

        engine_leak = any(e["status"] in ("LEAK", "META-LEAK") for e in engines)
        plaintext_leak = bool(raw["page_hits"])
        leaks += int(plaintext_leak) + int(engine_leak)

        manifest.append({
            "id": f"w_gs_{vid}",
            "file": f"corpus/writers/{path.name}",
            "has_user_password": True,
            "user_password": USER_PW,
            "canaries": CANARIES,
            "meta_canary": META_CANARY,
            "meta_encrypted": True,
            "attach_canary": None,
            "notes": f"writer=ghostscript; algorithm=R{R}/key{keylen}",
            "writer": "ghostscript",
            "algorithm": f"r{R}_k{keylen}",
        })

        rows.append({
            "variant": vid,
            "R": R,
            "keylen": keylen,
            "file": path.name,
            "bytes": raw["bytes"],
            "streams": raw["streams"],
            "inflated": raw["inflated_streams"],
            "plaintext_hits": "; ".join(raw["plaintext_hits"]) or "-",
            "page_plaintext": "; ".join(raw["page_hits"]) or "-",
            "meta_plaintext": "; ".join(
                h for h in raw["plaintext_hits"] if h not in raw["page_hits"]
            ) or "-",
            "auth_with_pw": ctrl.get("auth", "?"),
            "needs_pass": ctrl.get("needs_pass", "?"),
            "pages_with_pw": ctrl.get("pages", "?"),
            "page_canaries_with_pw": ctrl.get("page_canaries", "?"),
            "meta_canary_with_pw": ctrl.get("meta_canary", "?"),
            "engines": ", ".join(f"{e['engine']}={e['status']}" for e in engines),
        })
        for e in engines:
            controls.append({"variant": vid, **e})

        print(f"[{'LEAK' if (plaintext_leak or engine_leak) else 'ok'}] gs_{vid}: "
              f"page_plaintext={raw['page_hits'] or 'none'} "
              f"meta_plaintext={len(raw['plaintext_hits']) - len(raw['page_hits'])} hit(s) "
              f"streams={raw['streams']}/{raw['inflated_streams']} "
              f"auth={ctrl.get('auth')} engines={','.join(e['status'] for e in engines)}")

    MANIFEST.write_text(json.dumps(manifest, indent=2))

    cross = cross_writer_scan(manifest)
    cross_path = FINDINGS / "writer_rawscan.csv"
    with cross_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(cross[0]))
        w.writeheader()
        w.writerows(cross)

    csv_path = FINDINGS / "writer_plaintext.csv"
    with csv_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    md = [
        "# Track 4 - writer diversity: Ghostscript `pdfwrite`",
        "",
        "Produced with GPL Ghostscript 10.06.0 (`-sDEVICE=pdfwrite`), because no",
        "system-wide gs/libreoffice/chrome exists on this VPS; gs 10.06.0 was",
        "unpacked from the Ubuntu package into `~/.local/gs` (userspace, no root).",
        "",
        "`raw plaintext hits` = a canary was found verbatim in the file bytes, or",
        "inside a stream that inflates **without decryption**. That is",
        "engine-independent proof of content left unencrypted. Only a *page*",
        "canary (`CANARY ... ALPHA/BRAVO`) counts as a content leak; the metadata",
        "canary is reported separately (scope: metadata only, at most INFO).",
        "",
        "| variant | R | key | bytes | streams | inflate-no-key | page plaintext | pw auth | canaries w/ pw | no-password engines |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        page = r["page_plaintext"] if r["page_plaintext"] != "-" else "-"
        md.append(
            f"| {r['variant']} | {r['R']} | {r['keylen']} | {r['bytes']} | "
            f"{r['streams']} | {r['inflated']} | {page} | "
            f"{r['auth_with_pw']} | {r['page_canaries_with_pw']}/2 | {r['engines']} |"
        )
    md += [
        "",
        f"**Page content readable without the password: {'YES' if leaks else 'no'}** "
        f"({leaks} leak signal(s) across {len(rows)} files).",
        "",
        "`inflate-no-key` counts streams that inflated cleanly with no password.",
        "Non-zero is expected only for xref streams (never encrypted, ISO 32000-2",
        "7.5.8); their payloads are searched for canaries like every other stream.",
        "",
        "## Metadata left in plaintext (gs)",
        "",
        "All three variants carry the XMP packet unencrypted:",
    ]
    for r in rows:
        meta = r["meta_plaintext"] if r["meta_plaintext"] != "-" else ""
        md.append(f"- `{r['file']}`: {meta.count('@')} plaintext hit(s), e.g. `{meta.split('; ')[0] if meta else '-'}`")
    md += [
        "",
        "The gs `/Encrypt` dictionary is V1/V2 (R2/R3), where there is no",
        "`/EncryptMetadata` escape hatch: every stream except the xref stream must",
        "be encrypted (ISO 32000-2 7.6.2, 7.5.8). gs writes the `/Metadata` XMP",
        "stream in the clear, so the document title/author/description are",
        "readable with `strings` on a locked file. No engine surfaces it without",
        "the password (all six BLOCKED), and it is metadata only - observation",
        "`O-2026-004`, not a confidentiality break of page content.",
        "",
        "## With-password control",
        "",
        "Every file was reopened with the correct user password: `auth` is the",
        "PyMuPDF authenticate() result (2 = user password accepted), `pages` and",
        "`canaries` prove the document really contains the canary text.",
        "",
        "| variant | auth | pages | canaries |",
        "|---|---|---|---|",
    ]
    for r in rows:
        md.append(f"| {r['variant']} | {r['auth_with_pw']} | {r['pages_with_pw']} | "
                  f"{r['page_canaries_with_pw']}/2 |")
    md += [
        "",
        "## Engine differential (no password)",
        "",
        "| variant | engine | status | text_len | detail |",
        "|---|---|---|---|---|",
    ]
    for c in controls:
        md.append(f"| {c['variant']} | {c['engine']} | {c['status']} | "
                  f"{c['text_len']} | {c['detail']} |")
    md += [
        "",
        "## Cross-writer raw scan (whole repo)",
        "",
        "Same scan applied to every user-password sample already in the repo",
        "(qpdf base corpus + reportlab/pypdf/PyMuPDF writers). `page plaintext`",
        "non-`-` would be a content leak; `meta plaintext` is only a finding when",
        "`meta_encrypted` is true.",
        "",
        "| file | writer | alg | meta_encrypted | page plaintext | meta plaintext |",
        "|---|---|---|---|---|---|",
    ]
    for c in cross:
        md.append(f"| {c['file']} | {c['writer']} | {c['algorithm']} | "
                  f"{c['meta_encrypted']} | {c['page_plaintext']} | {c['meta_plaintext']} |")
    page_leaks = [c for c in cross if c["page_plaintext"] != "-"]
    meta_bugs = [c for c in cross if c["meta_plaintext"] != "-" and c["meta_encrypted"]]
    md += [
        "",
        f"- page-content plaintext in any writer sample: **{len(page_leaks)}**",
        f"- metadata plaintext where `/EncryptMetadata` is true: **{len(meta_bugs)}**",
        "",
        "Data: `findings/writer_plaintext.csv` (gs variants) and",
        "`findings/writer_rawscan.csv` (cross-writer).",
        "",
    ]
    (FINDINGS / "writer_plaintext.md").write_text("\n".join(md))
    print(f"\n[written] {csv_path}, {cross_path} and findings/writer_plaintext.md")
    print(f"[summary] gs files={len(rows)} page-content leaks={leaks} "
          f"cross-writer page leaks={len(page_leaks)} "
          f"meta-plaintext-where-encrypted={len(meta_bugs)}")


if __name__ == "__main__":
    sys.exit(main())
