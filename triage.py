"""
Differential triage harness: run every extractor against every corpus file
WITHOUT a password and classify the outcome.

Probes run in isolated subprocesses so a segfault becomes a recorded CRASH
finding instead of killing the harness. Probes are batched per extractor for
speed; any batch that dies is retried file-by-file to isolate the culprit.

Statuses:
  LEAK      - page content canary extracted from behind a user password -> bug
  META-LEAK - metadata canary extracted although metadata should be encrypted -> bug
  CRASH     - extractor died (non-zero exit / fatal error)             -> candidate bug
  TIMEOUT   - extractor hung on the input                              -> candidate DoS bug
  BLOCKED   - extractor correctly refused (password required)          -> expected
  INFO      - metadata readable where /EncryptMetadata false says it may be -> by design
  SILENT    - returned empty output without erroring                   -> manual triage
  OK        - extraction succeeded where it should (controls)          -> sanity
  ERROR     - clean exception that is not a password refusal           -> triage manually
"""
from __future__ import annotations

import contextlib
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
MANIFEST = CORPUS / "manifest.json"
FINDINGS = ROOT / "findings"
TIMEOUT_BATCH_S = 180
TIMEOUT_ONE_S = 30
BATCH_SIZE = 20

EXTRACTORS = ["pypdf", "pdfminer", "pymupdf", "pypdfium2", "pikepdf", "pdfjs"]

PASSWORD_HINTS = re.compile(
    r"password|encrypted|decrypt|FPDF_ERROR_PASSWORD|file is encrypted"
    r"|PDFPasswordIncorrect|PDFEncryptionError|PdfminerException",
    re.I,
)


# ---------------------------------------------------------------- child side

def _norm(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _meta_text(meta) -> str:
    try:
        if meta is None:
            return ""
        items = meta.items() if hasattr(meta, "items") else meta
        return json.dumps({str(k): str(v) for k, v in items}, default=str)
    except Exception:
        return ""


def extract_pypdf(path: Path) -> str:
    from pypdf import PdfReader

    r = PdfReader(str(path))
    parts = [(p.extract_text() or "") for p in r.pages]
    parts.append(_meta_text(r.metadata))
    try:
        for name, streams in (r.attachments or {}).items():
            for s in streams:
                parts.append(str(name))
                parts.append(s.get_data().decode("latin-1", "replace"))
    except Exception:
        pass
    return "\n".join(parts)


def extract_pdfminer(path: Path) -> str:
    import pdfplumber

    with pdfplumber.open(str(path)) as pdf:
        return "\n".join((p.extract_text() or "") for p in pdf.pages)


def extract_pymupdf(path: Path) -> str:
    import pymupdf

    with pymupdf.open(str(path)) as doc:
        parts = [p.get_text() for p in doc]
        try:
            parts.append(_meta_text(doc.metadata))
        except Exception:
            pass
        try:
            parts.append(doc.get_xml_metadata() or "")
        except Exception:
            pass
        try:
            for name in doc.embfile_names():
                parts.append(str(name))
                parts.append(doc.embfile_get(name).decode("latin-1", "replace"))
        except Exception:
            pass
        return "\n".join(parts)


def extract_pypdfium2(path: Path) -> str:
    import pypdfium2 as pdfium

    doc = pdfium.PdfDocument(str(path))
    try:
        return "\n".join(p.get_textpage().get_text_range() for p in doc)
    finally:
        doc.close()


def extract_pikepdf(path: Path) -> str:
    """Structural probe: opening without a password must fail, and stream
    contents must not be readable. Dumps filter-decoded stream bytes."""
    import pikepdf

    pdf = pikepdf.Pdf.open(str(path))
    try:
        parts = []
        for obj in pdf.objects:
            if isinstance(obj, pikepdf.Stream):
                try:
                    parts.append(bytes(obj.read_bytes()).decode("latin-1", "replace"))
                except Exception:
                    pass
        return "\n".join(parts)
    finally:
        pdf.close()


PROBES = {
    "pypdf": extract_pypdf,
    "pdfminer": extract_pdfminer,
    "pymupdf": extract_pymupdf,
    "pypdfium2": extract_pypdfium2,
    "pikepdf": extract_pikepdf,
}


@contextlib.contextmanager
def capture_fd1():
    """Native engines (MuPDF, PDFium) write diagnostics straight to fd 1,
    which would corrupt the child's JSON output. Redirect fd 1 to a temp file
    during the probe and hand the noise back for the crash trail."""
    sys.stdout.flush()
    saved = os.dup(1)
    tmp = tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace")
    os.dup2(tmp.fileno(), 1)
    try:
        yield tmp
    finally:
        sys.stdout.flush()
        os.dup2(saved, 1)
        os.close(saved)
        tmp.seek(0)


def probe_one(extractor: str, path: Path) -> dict:
    with capture_fd1() as noise_file:
        try:
            text = PROBES[extractor](path)
            result = {"status": "OK", "text_len": len(text.strip()), "text": text[:8000]}
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            status = "BLOCKED" if PASSWORD_HINTS.search(msg) else "ERROR"
            result = {"status": status, "error": msg[:500], "text_len": 0, "text": ""}
    result["noise"] = noise_file.read()[:300].replace("\n", " ")
    return result


def run_child_batch(extractor: str) -> None:
    """stdin: JSON list of absolute paths; stdout: JSONL, one result per path."""
    # Binary-ish extracted text and Node's UTF-8 JSON must not go through the
    # Windows console codepage.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    paths = json.loads(sys.stdin.read())
    if extractor == "pdfjs":
        proc = subprocess.run(
            ["node", str(ROOT / "pdfjs_probe.mjs")],
            input=json.dumps(paths),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT),
        )
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        sys.exit(proc.returncode)
    for p in paths:
        result = probe_one(extractor, Path(p))
        result["file"] = p
        print(json.dumps(result), flush=True)


# --------------------------------------------------------------- parent side

def run_batch(extractor: str, abs_paths: list[str], timeout: int) -> tuple[dict[str, dict] | None, dict | None]:
    """Returns (results, failure). Exactly one of the two is None."""
    cmd = [sys.executable, str(Path(__file__).resolve()), "--batch", extractor]
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    try:
        proc = subprocess.run(
            cmd, input=json.dumps(abs_paths), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        return None, {"status": "TIMEOUT", "error": f"probe exceeded {timeout}s", "text_len": 0, "text": ""}
    if proc.returncode != 0:
        tail = (proc.stderr or "")[-300:].replace("\n", " ")
        return None, {"status": "CRASH", "error": f"exit {proc.returncode}: {tail}", "text_len": 0, "text": ""}
    out: dict[str, dict] = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        out[rec["file"]] = rec
    if len(out) != len(abs_paths):
        return None, {"status": "CRASH", "error": "incomplete batch output", "text_len": 0, "text": ""}
    return out, None


def probe_subprocess(extractor: str, rel_file: str) -> dict:
    abs_path = str(ROOT / rel_file)
    res, err = run_batch(extractor, [abs_path], TIMEOUT_ONE_S)
    return res[abs_path] if res is not None else err


def classify(entry: dict, result: dict) -> str:
    status = result["status"]
    if status != "OK":
        return status
    text = (result.get("text") or "").strip()
    if not text:
        return "SILENT"
    text_norm = _norm(text)
    page_hit = any(_norm(c) in text_norm for c in entry["canaries"])
    attach_canary = entry.get("attach_canary") or ""
    meta_canary = entry.get("meta_canary") or ""
    attach_hit = bool(attach_canary) and _norm(attach_canary) in text_norm
    meta_hit = bool(meta_canary) and _norm(meta_canary) in text_norm
    if not entry["has_user_password"]:
        return "OK"  # controls: extraction is expected
    if page_hit or attach_hit:
        return "LEAK"
    if meta_hit:
        # XMP is deliberately plaintext when /EncryptMetadata false
        return "META-LEAK" if entry.get("meta_encrypted", True) else "INFO"
    return "PARTIAL"


def main() -> None:
    FINDINGS.mkdir(exist_ok=True)
    manifest = json.loads(MANIFEST.read_text())

    rows: list[dict] = []
    leaks: list[dict] = []
    crashes: list[dict] = []

    for extractor in EXTRACTORS:
        abs_map = {str(ROOT / e["file"]): e for e in manifest}
        paths = list(abs_map.keys())
        for i in range(0, len(paths), BATCH_SIZE):
            chunk = paths[i : i + BATCH_SIZE]
            results, _failure = run_batch(extractor, chunk, TIMEOUT_BATCH_S)
            if results is None:
                # batch died: retry one-by-one to isolate the culprit
                results = {}
                for p in chunk:
                    rel = abs_map[p]["file"]
                    r = probe_subprocess(extractor, rel)
                    r["file"] = p
                    results[p] = r
            for p in chunk:
                entry = abs_map[p]
                result = results[p]
                status = classify(entry, result)
                row = {
                    "file": entry["file"],
                    "id": entry["id"],
                    "extractor": extractor,
                    "status": status,
                    "mutant": entry.get("mutant", False),
                    "mutation": entry.get("mutation", ""),
                    "detail": result.get("error") or result.get("noise") or f"text_len={result.get('text_len', 0)}",
                }
                rows.append(row)
                if status in ("LEAK", "META-LEAK"):
                    leaks.append(row)
                elif status in ("CRASH", "TIMEOUT"):
                    crashes.append(row)
            print(f"{extractor}: {min(i + BATCH_SIZE, len(paths))}/{len(paths)} probes done")

    # report
    with open(FINDINGS / "report.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    info = [r for r in rows if r["status"] == "INFO"]
    lines = ["# Triage report", ""]
    lines.append(f"- files probed: {len(manifest)}")
    lines.append(f"- probes run: {len(rows)}")
    lines.append(f"- LEAK: {len(leaks)}  CRASH/TIMEOUT: {len(crashes)}  INFO: {len(info)}")
    lines.append("")
    for title, bucket in (("LEAK (candidate bugs)", leaks), ("CRASH / TIMEOUT (candidate bugs)", crashes)):
        if not bucket:
            continue
        lines.append(f"## {title}")
        lines.append("")
        lines.append("| file | extractor | mutation | detail |")
        lines.append("|---|---|---|---|")
        for r in bucket:
            lines.append(f"| {r['file']} | {r['extractor']} | {r['mutation']} | {r['detail']} |")
        lines.append("")
    if not leaks and not crashes:
        lines.append("No leaks or crashes in this run. Expand mutations (mutate.py) "
                     "and extractors before concluding anything.")
    (FINDINGS / "report.md").write_text("\n".join(lines), encoding="utf-8")

    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("\n=== summary ===")
    for k in sorted(counts):
        print(f"{k:10} {counts[k]}")
    print(f"\nreport -> {FINDINGS / 'report.md'}")

    if leaks or crashes:
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--batch":
        run_child_batch(sys.argv[2])
    else:
        main()
