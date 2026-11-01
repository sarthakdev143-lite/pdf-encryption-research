"""
Track 4 - writer diversity: Ghostscript.

Question: does a real-world producer (Ghostscript's `pdfwrite`, used by
print pipelines, CUPS filters, `ps2pdf`, and many "flatten/repair this PDF"
tools) ever emit an encrypted PDF with content left in plaintext?  A user
believes such a file is locked; if the page text is readable without the
password that is a writer-side confidentiality bug (scope table: "writer ...
so the file is not actually protected").

Input is PostScript written by this script, so Ghostscript produces the
document itself (the real ps2pdf path) instead of re-rendering a foreign
writer's PDF.  Canaries live in the page text and in the Info dictionary
(title/subject/author), which Ghostscript copies into the XMP packet.

Two independent tests per file:

  1. RAW scan - the exact bytes of the file, and every stream that inflates
     (FlateDecode) WITHOUT any decryption, are searched for the canaries.  A
     page-canary hit is engine-independent proof of content left unencrypted.
     A plaintext control (same PostScript, no encryption) proves the detector
     actually fires.
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
SOURCE = WRITERS / "gs_source.ps"
MANIFEST = CORPUS / "manifest.json"
FINDINGS = ROOT / "findings"

USER_PW = "Us3r-Passw0rd!"
OWNER_PW = "0wner-Passw0rd!"
DOC_ID = "gs"
PAGE_CANARIES = [f"CANARY {DOC_ID} ALPHA", f"CANARY {DOC_ID} BRAVO"]
META_CANARY = f"META-CANARY {DOC_ID}"
BODY_LINE = "Synthetic research sample - contains no real data."

GSROOT = Path(os.environ.get("PDF_GS_ROOT", Path.home() / ".local" / "gs"))
GS_BIN = Path(os.environ.get("PDF_GS", GSROOT / "usr/bin/gs"))
GS_SHARE = GSROOT / "usr/share/ghostscript"

# (id, -dEncryptionR, -dKeyLength)
VARIANTS = [
    ("r2_k40", 2, 40),    # RC4-40,  /V 1
    ("r3_k40", 3, 40),    # RC4-40,  /V 2
    ("r3_k128", 3, 128),  # RC4-128, /V 2
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


def write_source() -> None:
    ps = f"""%!PS-Adobe-3.0
[ /Title ({META_CANARY})
  /Subject ({META_CANARY} subject)
  /Author (Synthetic Research)
  /DOCINFO pdfmark
/Helvetica findfont 18 scalefont setfont
72 700 moveto ({PAGE_CANARIES[0]}) show
72 670 moveto ({BODY_LINE}) show
showpage
/Helvetica findfont 18 scalefont setfont
72 700 moveto ({PAGE_CANARIES[1]}) show
showpage
"""
    SOURCE.write_text(ps)


def run_gs(src: Path, out: Path, R: int | None = None, keylen: int | None = None) -> None:
    cmd = [
        str(GS_BIN), "-q", "-dNOPAUSE", "-dBATCH", "-dSAFER",
        "-sDEVICE=pdfwrite", f"-sOutputFile={out}",
    ]
    if R is not None:
        cmd += [
            f"-sOwnerPassword={OWNER_PW}", f"-sUserPassword={USER_PW}",
            f"-dEncryptionR={R}", f"-dKeyLength={keylen}", "-dPermissions=-4",
        ]
    cmd.append(str(src))
    proc = subprocess.run(cmd, capture_output=True, text=True, env=gs_env(), timeout=120)
    if proc.returncode != 0 or not out.exists() or out.stat().st_size == 0:
        raise RuntimeError(f"gs failed ({proc.returncode}): {proc.stderr[-400:]}")


OBJ_RE = re.compile(rb"(\d+)\s+0\s+obj")


def inflate_streams(data: bytes) -> tuple[int, int, list[bytes]]:
    """Return (stream_count, inflated_count, raw_inflated_payloads).

    Streams are located by the `stream ... endstream` framing only; /Length is
    not trusted.  zlib and raw-deflate are both attempted, like /FlateDecode.
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


def locate(data: bytes, needle: str) -> list[str]:
    """Where does `needle` appear? Returns ['obj 11 (stream)', 'obj 4', ...]."""
    out: list[str] = []
    raw = needle.encode()
    i = data.find(raw)
    while i >= 0:
        m = None
        for m in OBJ_RE.finditer(data, 0, i):
            pass
        obj = m.group(1).decode() if m else "?"
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
            return {
                "auth": auth,
                "needs_pass": int(doc.needs_pass),
                "pages": doc.page_count,
                "page_canaries": sum(c in text for c in PAGE_CANARIES),
                "meta_canary": META_CANARY in json.dumps(meta, default=str),
            }
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"[:200]}


def engine_differential(path: Path, has_user_password: bool = True) -> list[dict]:
    from triage import EXTRACTORS, classify, run_batch

    entry = {
        "has_user_password": has_user_password,
        "canaries": PAGE_CANARIES,
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


def append_report_csv(rows: list[dict], controls: list[dict], control_engines: list[dict]) -> None:
    """Keep findings/report.csv (the triage engine matrix) complete.

    triage.py rewrites this file from the manifest, so drop any previous gs
    rows first and append this run's rows in the same schema.
    """
    path = FINDINGS / "report.csv"
    fields = ["file", "id", "extractor", "status", "mutant", "mutation", "detail"]
    existing: list[dict] = []
    if path.exists():
        with path.open(newline="") as fh:
            existing = [r for r in csv.DictReader(fh)
                        if not r["file"].startswith("corpus/writers/gs_")]
    new = [{
        "file": "corpus/writers/gs_control_plain.pdf",
        "id": "w_gs_control",
        "extractor": e["engine"],
        "status": e["status"],
        "mutant": False,
        "mutation": "track4-plaintext-control",
        "detail": f"text_len={e['text_len']}",
    } for e in control_engines]
    for r in rows:
        for e in controls:
            if e["variant"] != r["variant"]:
                continue
            new.append({
                "file": f"corpus/writers/{r['file']}",
                "id": f"w_gs_{r['variant']}",
                "extractor": e["engine"],
                "status": e["status"],
                "mutant": False,
                "mutation": "track4-writer-gs",
                "detail": f"text_len={e['text_len']}",
            })
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(existing + new)


def main() -> None:
    if not GS_BIN.exists():
        raise SystemExit(f"[fatal] gs not found at {GS_BIN}; set PDF_GS")
    WRITERS.mkdir(parents=True, exist_ok=True)
    FINDINGS.mkdir(exist_ok=True)
    write_source()

    manifest = json.loads(MANIFEST.read_text())
    manifest = [e for e in manifest if not e["id"].startswith("w_gs_")]
    needles = PAGE_CANARIES + [META_CANARY] + [BODY_LINE]

    # --- sensitivity control: same PostScript, no encryption. The raw scan must
    # find the page canaries here, otherwise a clean encrypted result is vacuous.
    control_path = WRITERS / "gs_control_plain.pdf"
    run_gs(SOURCE, control_path)
    control_raw = raw_scan(control_path, needles, PAGE_CANARIES)
    control_ctrl = with_password_control(control_path)
    control_engines = engine_differential(control_path, has_user_password=False)
    manifest.append({
        "id": "w_gs_control",
        "file": f"corpus/writers/{control_path.name}",
        "has_user_password": False,
        "user_password": "",
        "canaries": PAGE_CANARIES,
        "meta_canary": META_CANARY,
        "meta_encrypted": True,
        "attach_canary": None,
        "notes": "writer=ghostscript; plaintext control (same PostScript, no encryption)",
        "writer": "ghostscript",
        "algorithm": "control_plain",
    })
    print(f"[control] plaintext gs output: page canaries in raw bytes="
          f"{len(control_raw['page_hits'])}/2 (detector {'works' if control_raw['page_hits'] else 'BROKEN'})")
    if not control_raw["page_hits"]:
        raise SystemExit("[fatal] raw scanner cannot see canaries even in plaintext; aborting")

    rows: list[dict] = []
    controls: list[dict] = []
    leaks = 0

    for vid, R, keylen in VARIANTS:
        path = WRITERS / f"gs_{vid}.pdf"
        run_gs(SOURCE, path, R, keylen)

        raw = raw_scan(path, needles, PAGE_CANARIES)
        ctrl = with_password_control(path)
        engines = engine_differential(path)

        engine_leak = any(e["status"] in ("LEAK", "META-LEAK") for e in engines)
        plaintext_leak = bool(raw["page_hits"])
        # A locked file whose own pages cannot be recovered with the correct
        # password is a broken sample, not a clean result.
        broken = ctrl.get("page_canaries") != len(PAGE_CANARIES)
        leaks += int(plaintext_leak) + int(engine_leak)

        manifest.append({
            "id": f"w_gs_{vid}",
            "file": f"corpus/writers/{path.name}",
            "has_user_password": True,
            "user_password": USER_PW,
            "canaries": PAGE_CANARIES,
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
            "sample_valid": not broken,
            "engines": ", ".join(f"{e['engine']}={e['status']}" for e in engines),
        })
        for e in engines:
            controls.append({"variant": vid, **e})

        print(f"[{'LEAK' if (plaintext_leak or engine_leak) else 'ok'}] gs_{vid}: "
              f"page_plaintext={raw['page_hits'] or 'none'} "
              f"meta_plaintext={len(raw['plaintext_hits']) - len(raw['page_hits'])} hit(s) "
              f"streams={raw['streams']}/{raw['inflated_streams']} "
              f"pw_canaries={ctrl.get('page_canaries')}/2 "
              f"engines={','.join(e['status'] for e in engines)}")
        if broken:
            print(f"  [WARN] sample invalid: with-password control returned "
                  f"{ctrl.get('page_canaries')}/2 page canaries")

    MANIFEST.write_text(json.dumps(manifest, indent=2))

    append_report_csv(rows, controls, control_engines)

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
        "Produced with GPL Ghostscript 10.06.0 (`-sDEVICE=pdfwrite`) from",
        "PostScript written by `ghostscript_writer.py` (the real `ps2pdf` path:",
        "Ghostscript produces the document, no foreign producer's PDF is",
        "re-rendered). No system-wide gs/libreoffice/chrome exists on this VPS;",
        "gs 10.06.0 was unpacked from the Ubuntu package into `~/.local/gs`",
        "(userspace, no root).",
        "",
        "Reproduce the gs install (all as the normal user):",
        "",
        "```",
        "apt-get download ghostscript libgs10 libgs10-common libjbig2dec0 \\",
        "  libijs-0.35 libidn12 libpaper2 icc-profiles-free fonts-urw-base35",
        "for d in *.deb; do dpkg-deb -x \"$d\" ~/.local/gs; done",
        "# gs also needs the ICC profiles that Debian does not ship:",
        "#   base/iccprofiles/{default_cmyk,default_gray,default_rgb,lab,",
        "#   a98,esrgb,ps_cmyk,ps_gray,ps_rgb}.icc from ArtifexSoftware/ghostpdl",
        "#   -> ~/.local/gs/usr/share/color/icc/ghostscript/",
        "```",
        "",
        "Without the URW base-35 fonts gs cannot run `findfont` (empty pages) and",
        "without the default ICC profiles it cannot open a device at all - both",
        "were hit and fixed before any result below was recorded.",
        "",
        "`page plaintext` = a page canary (`CANARY gs ALPHA/BRAVO`) was found",
        "verbatim in the file bytes, or inside a stream that inflates **without",
        "decryption**. That is engine-independent proof of page content left",
        "unencrypted. The metadata canary is reported separately (metadata only,",
        "at most INFO per the scope rules).",
        "",
        "Sensitivity control, same PostScript without encryption:",
        f"**{len(control_raw['page_hits'])}/2 page canaries found in raw bytes** -",
        "the scanner fires on plaintext, so a clean encrypted result is meaningful.",
        "",
        "| variant | R | key | bytes | streams | inflate-no-key | page plaintext | pw auth | canaries w/ pw | no-password engines |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        md.append(
            f"| {r['variant']} | {r['R']} | {r['keylen']} | {r['bytes']} | "
            f"{r['streams']} | {r['inflated']} | {r['page_plaintext']} | "
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
        "Every variant carries the XMP packet unencrypted:",
    ]
    for r in rows:
        meta = r["meta_plaintext"] if r["meta_plaintext"] != "-" else ""
        md.append(f"- `{r['file']}`: {meta.count('@')} plaintext hit(s), "
                  f"e.g. `{meta.split('; ')[0] if meta else '-'}`")
    md += [
        "",
        "The gs `/Encrypt` dictionary is V1/V2 (R2/R3), where there is no",
        "`/EncryptMetadata` escape hatch: every stream except the xref stream",
        "must be encrypted. ISO 32000-1 7.6.1 (identical text in ISO 32000-2",
        "7.6.2) says: \"Encryption applies to all strings and streams in the",
        "document's PDF file, with the following exceptions: the values for the",
        "ID entry in the trailer; any strings in an Encrypt dictionary; any",
        "strings that are inside streams ...\". The metadata stream is a stream,",
        "so it must be encrypted. `EncryptMetadata` is \"meaningful only when the",
        "value of V is 4\" with \"Default value: true\" (Table 20) - gs writes",
        "V 2, so no exemption applies.",
        "",
        "gs writes the `/Metadata` XMP stream in the clear, so the document",
        "title/author/subject are readable with `strings` on a locked file.",
        "Same revision, different writer: the qpdf V2/R3",
        "samples (`corpus/base/rc4_128_r3__plain.pdf`) encrypt their XMP stream.",
        "No engine surfaces it without the password (all six BLOCKED), and it is",
        "metadata only - observation `O-2026-005`, not a page-content leak.",
        "",
        "## Correction to the earlier (cycle-7) gs harness",
        "",
        "The first gs harness fed `corpus/base/control_plain.pdf` (a reportlab",
        "document) to gs. gs's PDF interpreter failed on it (`error executing",
        "PDF token`) and wrote empty pages, so the with-password text check was",
        "vacuous; the earlier note that gs \"re-distills/vectorizes text\" is",
        "withdrawn. The PostScript path above is the real producer path and the",
        "page canaries survive encryption/decryption as shown in the control.",
        "",
        "## With-password control",
        "",
        "Every file was reopened with the correct user password: `auth` is the",
        "PyMuPDF authenticate() result (2 = user password accepted), `pages` and",
        "`canaries` prove the document really contains the canary text.",
        "",
        "| variant | auth | pages | canaries | meta canary |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        md.append(f"| {r['variant']} | {r['auth_with_pw']} | {r['pages_with_pw']} | "
                  f"{r['page_canaries_with_pw']}/2 | {r['meta_canary_with_pw']} |")
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
