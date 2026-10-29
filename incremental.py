"""
Incremental-update tampering (integrity experiment).

An encrypted PDF can be extended without knowing the password: append a new
object revision plus an xref section whose trailer has no /Encrypt. The latest
trailer then describes an unencrypted document that points at attacker-chosen
objects.

Question for the reader matrix: without any password, do engines render the
appended plaintext page? With the correct password, what do they show?

This is an integrity / content-injection experiment, not a confidentiality
bypass: the appended content was never encrypted. It is logged to document how
far a locked PDF can be rewritten by someone who cannot open it.

Usage: python incremental.py
Outputs: corpus/incremental/*.pdf, findings/incremental.md, findings/incremental.csv
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from triage import EXTRACTORS, run_batch

ROOT = Path(__file__).resolve().parent
BASE = ROOT / "corpus" / "base"
OUT = ROOT / "corpus" / "incremental"
FINDINGS = ROOT / "findings"

SEEDS = [
    "control_plain.pdf",          # control: unencrypted, proves the append works
    "aes256_r6__plain.pdf",
    "aes256_r6__objstm.pdf",
    "aes256_r5__plain.pdf",
    "rc4_128_r4__plain.pdf",
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


def build(seed: Path, out: Path) -> str:
    data = seed.read_bytes()
    prev = last_startxref(data)
    n = max_size(data)  # first new object number
    canary = f"INJECTED PAGE {seed.stem} ALPHA"
    content = f"BT /F1 12 Tf 72 700 Td ({canary}) Tj ET".encode("latin-1")

    objects = {
        n: b"<< /Type /Catalog /Pages %d 0 R >>" % (n + 1),
        n + 1: b"<< /Type /Pages /Kids [%d 0 R] /Count 1 >>" % (n + 2),
        n + 2: (
            b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 "
            b"/BaseFont /Helvetica >> >> >> /Contents %d 0 R >>"
        ) % (n + 1, n + 3),
        n + 3: b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
    }

    buf = bytearray(data)
    if not buf.endswith(b"\n"):
        buf += b"\n"
    offsets: dict[int, int] = {}
    for num in sorted(objects):
        offsets[num] = len(buf)
        buf += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"

    xref_off = len(buf)
    buf += b"xref\n0 1\n0000000000 65535 f \n"
    buf += b"%d %d\n" % (n, len(objects))
    for num in sorted(objects):
        buf += b"%010d 00000 n \n" % offsets[num]
    # NOTE: newest trailer deliberately has no /Encrypt
    buf += (
        b"trailer\n<< /Size %d /Root %d 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n"
        % (n + len(objects), n, prev, xref_off)
    )
    out.write_bytes(bytes(buf))
    return canary


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    FINDINGS.mkdir(exist_ok=True)

    variants: list[dict] = []
    for name in SEEDS:
        seed = BASE / name
        if not seed.exists():
            print(f"[skip] {name} missing")
            continue
        out = OUT / f"{seed.stem}__append_plaintext.pdf"
        canary = build(seed, out)
        encrypted = seed.stem != "control_plain"
        variants.append(
            {
                "seed": name,
                "file": str(out.relative_to(ROOT)),
                "encrypted": encrypted,
                "canary": canary,
                "orig_canary": (
                    f"CANARY {seed.stem} ALPHA" if encrypted else ""
                ),
            }
        )
        print(f"[ok] {out.name}")

    rows: list[dict] = []
    for engine in EXTRACTORS:
        results, failure = run_batch(
            engine, [str(ROOT / v["file"]) for v in variants], 240
        )
        for v in variants:
            if results is None:
                res = {"status": "CRASH", "text": "", "error": failure}
            else:
                res = results[str(ROOT / v["file"])]
            text = res.get("text") or ""
            injected = v["canary"] in text
            original = bool(v["orig_canary"]) and v["orig_canary"] in text
            rows.append(
                {
                    "seed": v["seed"],
                    "encrypted": v["encrypted"],
                    "engine": engine,
                    "status": res["status"],
                    "injected_shown": injected,
                    "original_shown": original,
                    "detail": (res.get("error") or res.get("noise") or "")[:140],
                }
            )
        print(f"{engine}: {len(variants)} variants probed")

    with open(FINDINGS / "incremental.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    lines = ["# Incremental-update content injection", ""]
    lines.append(
        "Appended revision: new Catalog/Pages/Page/Contents with a plaintext "
        "canary, new xref, trailer **without /Encrypt**, `/Prev` -> original xref."
    )
    lines.append("")
    lines.append("| seed | engine | status | injected page shown (no password) | original content shown |")
    lines.append("|---|---|---|---|---|")
    for r in rows:
        lines.append(
            f"| {r['seed']} | {r['engine']} | {r['status']} | "
            f"{r['injected_shown']} | {r['original_shown']} |"
        )
    lines.append("")

    shown = [r for r in rows if r["encrypted"] and r["injected_shown"]]
    lines.append(
        f"Encrypted seeds where the injected page was rendered without a password: "
        f"{len(shown)}/{sum(1 for r in rows if r['encrypted'])} engine-file pairs."
    )
    if shown:
        lines.append("")
        lines.append(
            "Interpretation: the newest trailer declares an unencrypted document, "
            "so readers that follow it legitimately render the injected revision. "
            "The original encrypted pages stay unreadable. This is an integrity "
            "property of PDF (no signature/MAC over revisions), not a break of "
            "user-password confidentiality; it is the structural basis for "
            "PDFex-style attacks, which need a viewer that later decrypts with "
            "the victim's password."
        )
    (FINDINGS / "incremental.md").write_text("\n".join(lines), encoding="utf-8")

    print("\n=== summary ===")
    ctrl = [r for r in rows if not r["encrypted"] and r["engine"] == "pymupdf"]
    print("control (unencrypted seed), pymupdf shows injection:", ctrl[0]["injected_shown"] if ctrl else "?")
    for engine in EXTRACTORS:
        enc = [r for r in rows if r["encrypted"] and r["engine"] == engine]
        print(
            f"{engine:10} injected shown: {sum(r['injected_shown'] for r in enc)}/{len(enc)}"
            f"   original shown: {sum(r['original_shown'] for r in enc)}/{len(enc)}"
        )
    print(f"\nreport -> {FINDINGS / 'incremental.md'}")


if __name__ == "__main__":
    main()
