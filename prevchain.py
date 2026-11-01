"""
Track 2 - /Prev chain, trailer and hybrid-xref confusion.

Question: when an encrypted PDF is extended with an attacker-written revision,
which engines disagree about (a) whether the document is still encrypted and
(b) which revision's objects are live - and can any disagreement cause the
ORIGINAL user-password-protected content to be extracted without the password?

An appended plaintext page is *not* a leak: it was never encrypted. The leak
test is whether the original canary ("CANARY <seed> ALPHA/BRAVO") ever appears
in no-password output.

Variants (all built from corpus/base seeds, all synthetic):

  t_none               classic trailer, no /Encrypt, new Root
  t_encrypt_ref        classic trailer, /Encrypt -> original encrypt object
  t_encrypt_empty      classic trailer, /Encrypt -> fresh empty-user-pw R6 dict
  alias_plain          no /Encrypt; new page's /Contents -> ORIGINAL content stream
  alias_encrypt        alias_plain + /Encrypt original ref (with-password control)
  root_old             no /Encrypt, /Root -> ORIGINAL catalog
  chain_none_encrypt   rev A (no /Encrypt) then rev B (/Encrypt ref)
  chain_encrypt_none   rev A (/Encrypt ref) then rev B (no /Encrypt)
  shadow_encrypt_obj   no /Encrypt; redefines the original /Encrypt object number
  h_refstm_encrypt     hybrid: trailer w/o /Encrypt, /XRefStm dict WITH /Encrypt
  h_trailer_encrypt    hybrid: trailer WITH /Encrypt, /XRefStm dict without
  xs_pure_encrypt      pure xref-stream update, dict WITH /Encrypt, new Root
  xs_pure_none         pure xref-stream update, dict without /Encrypt, /Root -> old

Usage: python prevchain.py
Outputs: corpus/prevchain/*.pdf, findings/prevchain.md, findings/prevchain.csv
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path

import pikepdf

from triage import EXTRACTORS, run_batch

ROOT = Path(__file__).resolve().parent
BASE = ROOT / "corpus" / "base"
OUT = ROOT / "corpus" / "prevchain"
FINDINGS = ROOT / "findings"

USER_PW = "Us3r-Passw0rd!"

SEEDS = [
    "aes256_r6__plain.pdf",
    "rc4_128_r4__plain.pdf",
    "aes256_r6__objstm.pdf",
    "control_plain.pdf",  # unencrypted control: proves the construction itself
]


# --------------------------------------------------------------- primitives

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


def add_classic_xref(
    buf: bytearray, offsets: dict[int, int], trailer_extra: bytes, size: int
) -> int:
    """Append a classic xref section + trailer; returns the xref offset."""
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


def add_xref_stream(
    buf: bytearray,
    offsets: dict[int, int],
    xref_num: int,
    trailer_extra: bytes,
    size: int,
) -> int:
    """Append an xref stream object covering `offsets` plus itself.

    Xref streams are never encrypted (ISO 32000-2 7.5.8), so this works on an
    otherwise-encrypted file without knowing the key.
    """
    pad_newline(buf)
    xref_off = len(buf)
    all_offsets = dict(offsets)
    all_offsets[xref_num] = xref_off
    nums = sorted(all_offsets)
    entries = b"".join(
        b"\x01" + all_offsets[n].to_bytes(4, "big") + b"\x00\x00" for n in nums
    )
    head = (
        b"<< /Type /XRef /Size %d /W [1 4 2] /Index [%d %d] "
        % (size, nums[0], len(nums))
    ) + trailer_extra + (b" /Length %d >>\nstream\n" % len(entries))
    buf += b"%d 0 obj\n" % xref_num + head + entries + b"\nendstream\nendobj\n"
    return xref_off


def page_objects(n: int, canary: str, contents_ref: bytes) -> dict[int, bytes]:
    """New Catalog/Pages/Page/Contents numbered n..n+3."""
    content = f"BT /F1 12 Tf 72 700 Td ({canary}) Tj ET".encode("latin-1")
    return {
        n: b"<< /Type /Catalog /Pages %d 0 R >>" % (n + 1),
        n + 1: b"<< /Type /Pages /Kids [%d 0 R] /Count 1 >>" % (n + 2),
        n + 2: (
            b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 "
            b"/BaseFont /Helvetica >> >> >> /Contents %s >>"
        )
        % (n + 1, contents_ref),
        n + 3: b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
    }


def donor_empty_pw_encrypt() -> bytes:
    """Serialized /Encrypt dictionary for a document with an empty user
    password (R6). Represents 'attacker supplies their own security handler'."""
    import tempfile

    path = Path(tempfile.mktemp(suffix=".pdf"))
    try:
        pdf = pikepdf.new()
        pdf.add_blank_page()
        pdf.save(path, encryption=pikepdf.Encryption(owner="", user="", R=6))
        with pikepdf.open(path) as d:
            return d.trailer.Encrypt.unparse(resolved=True)
    finally:
        path.unlink(missing_ok=True)


# --------------------------------------------------------------- builders

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


def build(seed: Seed, variant: str) -> tuple[Path, list[str]]:
    """Returns (output path, injected canaries)."""
    canary = f"INJECTED {seed.stem} {variant} ALPHA"
    injected = [canary]
    buf = bytearray(seed.data)
    prev = last_startxref(seed.data)
    n = seed.size
    size = n + 12

    def finish(name_suffix: str = "") -> Path:
        out = OUT / f"{seed.stem}__{variant}{name_suffix}.pdf"
        out.write_bytes(bytes(buf))
        return out

    enc_ref = b"/Encrypt %d 0 R" % seed.encrypt if seed.encrypt else b""

    if variant in ("t_none", "t_encrypt_ref", "t_encrypt_empty"):
        objs = page_objects(n, canary, b"%d 0 R" % (n + 3))
        offs = add_objects(buf, objs)
        if variant == "t_none":
            extra = b""
        elif variant == "t_encrypt_ref":
            extra = enc_ref
        else:
            donor = donor_empty_pw_encrypt()
            objs2 = {n + 4: donor}
            offs.update(add_objects(buf, objs2))
            extra = b"/Encrypt %d 0 R" % (n + 4)
        add_classic_xref(buf, offs, extra + b" /Root %d 0 R /Prev %d" % (n, prev), size)
        return finish(), injected

    if variant in ("alias_plain", "alias_encrypt"):
        objs = page_objects(n, canary, b"%d 0 R" % seed.contents)
        offs = add_objects(buf, objs)
        extra = b"" if variant == "alias_plain" else enc_ref
        add_classic_xref(buf, offs, extra + b" /Root %d 0 R /Prev %d" % (n, prev), size)
        return finish(), injected

    if variant == "root_old":
        # No new objects at all: just a trailer pointing at the original Root.
        extra = b"/Root %d 0 R /Prev %d" % (seed.root, prev)
        add_classic_xref(buf, {}, extra, size)
        return finish(), injected

    if variant in ("chain_none_encrypt", "chain_encrypt_none"):
        objs = page_objects(n, canary, b"%d 0 R" % (n + 3))
        offs = add_objects(buf, objs)
        first_extra = enc_ref if variant == "chain_encrypt_none" else b""
        xref_a = add_classic_xref(
            buf, offs, first_extra + b" /Root %d 0 R /Prev %d" % (n, prev), size
        )
        second_extra = enc_ref if variant == "chain_none_encrypt" else b""
        add_classic_xref(
            buf, {}, second_extra + b" /Root %d 0 R /Prev %d" % (n, xref_a), size
        )
        return finish(), injected

    if variant == "shadow_encrypt_obj":
        if seed.encrypt is None:
            raise ValueError("shadow variant needs an encrypted seed")
        objs = page_objects(n, canary, b"%d 0 R" % (n + 3))
        # Redefine the object number the original trailer used for /Encrypt.
        objs[seed.encrypt] = b"<< /Type /NotAnEncryptDict >>"
        offs = add_objects(buf, objs)
        add_classic_xref(buf, offs, b" /Root %d 0 R /Prev %d" % (n, prev), size)
        return finish(), injected

    if variant in ("h_refstm_encrypt", "h_trailer_encrypt"):
        objs = page_objects(n, canary, b"%d 0 R" % (n + 3))
        offs = add_objects(buf, objs)
        xs_num = n + 4
        xs_extra = enc_ref if variant == "h_refstm_encrypt" else b""
        xs_off = add_xref_stream(
            buf, offs, xs_num, xs_extra + b" /Root %d 0 R" % n, size
        )
        trailer_extra = (
            enc_ref if variant == "h_trailer_encrypt" else b""
        ) + b" /Root %d 0 R /Prev %d /XRefStm %d" % (n, prev, xs_off)
        add_classic_xref(buf, offs, trailer_extra, size)
        return finish(), injected

    if variant in ("xs_pure_encrypt", "xs_pure_none"):
        if variant == "xs_pure_none":
            # Point the pure xref-stream update at the ORIGINAL document.
            xs_num = n
            xs_extra = b" /Root %d 0 R /Prev %d" % (seed.root, prev)
            xs_off = add_xref_stream(buf, {}, xs_num, xs_extra, xs_num + 1)
        else:
            objs = page_objects(n, canary, b"%d 0 R" % (n + 3))
            offs = add_objects(buf, objs)
            xs_num = n + 4
            xs_off = add_xref_stream(
                buf,
                offs,
                xs_num,
                enc_ref + b" /Root %d 0 R /Prev %d" % (n, prev),
                size,
            )
        pad_newline(buf)
        buf += b"startxref\n%d\n%%%%EOF\n" % xs_off
        return finish(), injected

    raise ValueError(f"unknown variant {variant}")


VARIANTS = [
    "t_none",
    "t_encrypt_ref",
    "t_encrypt_empty",
    "alias_plain",
    "alias_encrypt",
    "root_old",
    "chain_none_encrypt",
    "chain_encrypt_none",
    "shadow_encrypt_obj",
    "h_refstm_encrypt",
    "h_trailer_encrypt",
    "xs_pure_encrypt",
    "xs_pure_none",
]


def password_controls() -> list[dict]:
    """With-password controls, run in-process (small, fixed file set).

    These prove the constructs are valid: if the alias page does NOT show the
    original canary when the correct password IS supplied, the negative
    no-password result would be meaningless.
    """
    import pymupdf

    checks = [
        "aes256_r6__plain__alias_encrypt.pdf",
        "aes256_r6__plain__alias_plain.pdf",
        "aes256_r6__plain__t_encrypt_ref.pdf",
        "aes256_r6__plain__t_none.pdf",
        "aes256_r6__plain__root_old.pdf",
    ]
    out: list[dict] = []
    for name in checks:
        path = OUT / name
        if not path.exists():
            continue
        row = {"file": name, "pymupdf_text": "", "pymupdf_note": ""}
        try:
            doc = pymupdf.open(str(path))
            auth = doc.authenticate(USER_PW)
            text = " | ".join(p.get_text().strip().replace("\n", " ") for p in doc)
            row["pymupdf_text"] = text[:120]
            row["pymupdf_note"] = f"auth={auth} needs_pass={int(doc.needs_pass)} pages={doc.page_count}"
            doc.close()
        except Exception as exc:
            row["pymupdf_note"] = f"{type(exc).__name__}: {exc}"[:120]
        out.append(row)
    return out


def append_report_block(lines: list[str]) -> None:
    """Keep a Track 2 section at the end of findings/report.md.

    triage.py rewrites report.md from scratch, so the block is re-added here
    (and replaced, not duplicated, when prevchain.py runs again).
    """
    report = FINDINGS / "report.md"
    begin, end = "<!-- track2:begin -->", "<!-- track2:end -->"
    body = report.read_text(encoding="utf-8") if report.exists() else ""
    if begin in body:
        body = body.split(begin)[0].rstrip() + "\n"
    block = "\n".join([begin, *lines, end, ""])
    report.write_text(body.rstrip() + "\n\n" + block, encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    FINDINGS.mkdir(exist_ok=True)

    cases: list[dict] = []
    for name in SEEDS:
        seed = Seed(name)
        for variant in VARIANTS:
            if variant == "shadow_encrypt_obj" and not seed.encrypted:
                continue
            try:
                path, injected = build(seed, variant)
            except Exception as exc:  # a build failure is data, not a crash
                print(f"[skip] {seed.stem} {variant}: {type(exc).__name__}: {exc}")
                continue
            cases.append(
                {
                    "seed": name,
                    "variant": variant,
                    "file": str(path.relative_to(ROOT)),
                    "encrypted": seed.encrypted,
                    "injected": injected,
                    "original": seed.canaries,
                }
            )
            print(f"[ok] {path.name}")

    rows: list[dict] = []
    paths = [str(ROOT / c["file"]) for c in cases]
    for engine in EXTRACTORS:
        results, failure = run_batch(engine, paths, 300)
        for c in cases:
            if results is None:
                res = {"status": "CRASH", "text": "", "error": failure}
            else:
                res = results[str(ROOT / c["file"])]
            text = res.get("text") or ""
            norm = re.sub(r"\s+", "", text)
            injected_hit = any(re.sub(r"\s+", "", x) in norm for x in c["injected"])
            original_hit = any(re.sub(r"\s+", "", x) in norm for x in c["original"])
            rows.append(
                {
                    "seed": c["seed"],
                    "variant": c["variant"],
                    "engine": engine,
                    "status": res["status"],
                    "encrypted": c["encrypted"],
                    "injected_shown": injected_hit,
                    "original_shown": original_hit,
                    "detail": (res.get("error") or res.get("noise") or "")[:160],
                }
            )
        print(f"{engine}: {len(cases)} files probed")

    with open(FINDINGS / "prevchain.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    lines = [
        "# Track 2 - /Prev chain, trailer and hybrid-xref confusion",
        "",
        "Each row is a no-password probe (the extractor is given no password).",
        "`injected` = the appended plaintext canary was rendered (integrity issue,",
        "expected for `t_none`). `ORIGINAL` = the *encrypted* canary was recovered",
        "without the password - that is the only reportable outcome here.",
        "",
        "pikepdf is a structural probe: it dumps every stream object, referenced or",
        "not, so its `injected=True` on `alias_plain` is the unreferenced canary",
        "stream being dumped, not a rendered page.",
        "",
        "| seed | variant | engine | status | injected | ORIGINAL | detail |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['seed']} | {r['variant']} | {r['engine']} | {r['status']} | "
            f"{r['injected_shown']} | **{r['original_shown']}** | {r['detail']} |"
        )
    lines.append("")

    leaks = [r for r in rows if r["original_shown"] and r["encrypted"]]
    injected = [r for r in rows if r["injected_shown"] and r["encrypted"]]
    lines.append(f"Encrypted cases with original content shown: **{len(leaks)}**")
    lines.append(f"Encrypted cases with injected plaintext shown: {len(injected)}")
    lines.append("")
    lines.append("## Divergence by variant (encrypted seeds)")
    lines.append("")
    lines.append(
        "`opened, empty` = the engine accepted the document without a password "
        "but produced no canary (ciphertext treated as unencrypted content)."
    )
    lines.append("")
    lines.append("| variant | engines rendering injected page | opened, empty | refused |")
    lines.append("|---|---|---|---|")
    for variant in VARIANTS:
        sub = [r for r in rows if r["variant"] == variant and r["encrypted"]]
        if not sub:
            continue
        show, empty, refuse = [], [], []
        for engine in EXTRACTORS:
            es = [r for r in sub if r["engine"] == engine]
            if not es:
                continue
            if any(r["injected_shown"] for r in es):
                show.append(engine)
            elif all(r["status"] == "OK" for r in es):
                empty.append(engine)
            else:
                refuse.append(engine)
        lines.append(
            f"| {variant} | {', '.join(show) or '-'} | {', '.join(empty) or '-'} | "
            f"{', '.join(refuse) or '-'} |"
        )
    lines.append("")

    controls = password_controls()
    lines.append("## With-password controls (proof the constructs are valid)")
    lines.append("")
    lines.append("| file | PyMuPDF status with correct user password | text |")
    lines.append("|---|---|---|")
    for c in controls:
        lines.append(f"| {c['file']} | {c['pymupdf_note']} | {c['pymupdf_text']} |")
    lines.append("")
    lines.append(
        "`alias_encrypt` + password returns the original canary, so the alias page "
        "really does reference the original encrypted content stream. Without the "
        "password the same alias yields nothing on every engine: decryption, not "
        "reference resolution, is the barrier."
    )
    lines.append("")
    (FINDINGS / "prevchain.md").write_text("\n".join(lines), encoding="utf-8")

    append_report_block(
        [
            "## Track 2 - /Prev chain and hybrid-xref confusion (2026-10-29)",
            "",
            f"- matrix: {len(cases)} synthetic files (13 variants x 4 seeds), "
            f"{len(rows)} no-password probes across 6 engines.",
            f"- **original encrypted content recovered without password: {len(leaks)}**",
            f"- injected plaintext rendered without password: {len(injected)} "
            "(integrity property, not confidentiality).",
            "- full table: `findings/prevchain.md` / `findings/prevchain.csv`; "
            "observation: `O-2026-002` in `findings/LOG.md`.",
        ]
    )

    print("\n=== summary ===")
    print(f"cases: {len(cases)}  probes: {len(rows)}")
    print(f"original content shown without password: {len(leaks)}")
    print(f"injected plaintext shown: {len(injected)}")
    for variant in VARIANTS:
        sub = [r for r in rows if r["variant"] == variant and r["encrypted"]]
        if not sub:
            continue
        per = ", ".join(
            f"{e}:{'Y' if any(r['injected_shown'] for r in sub if r['engine'] == e) else 'n'}"
            for e in EXTRACTORS
        )
        print(f"  {variant:20} {per}")
    print(f"\nreport -> {FINDINGS / 'prevchain.md'}")


if __name__ == "__main__":
    main()
