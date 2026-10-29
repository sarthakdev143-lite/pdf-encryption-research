"""
Authentication matrix: can any engine be made to open a password-locked PDF
with a password that is NOT the correct one?

This is the most direct test of the research goal. For every encrypted corpus
file and every engine, try a set of candidate passwords and check whether the
canary content becomes readable. A canary hit under a known-wrong password is
an authentication bypass (critical finding); the correct password succeeding is
the control.

Candidates: empty, wrong, case-flipped, truncated, extended, owner, correct.
Engines: pypdf, pdfminer (pdfplumber), pymupdf (MuPDF), pypdfium2 (PDFium),
pikepdf (qpdf), pdfjs (pdf.js).

Usage: python authmatrix.py
Outputs: findings/authmatrix.md + findings/authmatrix.csv
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
TIMEOUT_BATCH_S = 240
TIMEOUT_ONE_S = 40
BATCH_SIZE = 25

USER_PW = "Us3r-Passw0rd!"
OWNER_PW = "0wner-Passw0rd!"

# (label, password, expectation)
CANDIDATES = [
    ("empty", "", "wrong"),
    ("wrong", "definitely-wrong", "wrong"),
    ("case_flip", "us3r-passw0rd!", "wrong"),
    ("truncated", USER_PW[:-1], "wrong"),
    ("extended", USER_PW + "x", "wrong"),
    ("owner", OWNER_PW, "expected-accept"),
    ("correct", USER_PW, "control"),
]

ENGINES = ["pypdf", "pdfminer", "pymupdf", "pypdfium2", "pikepdf", "pdfjs"]

PASSWORD_HINTS = re.compile(
    r"password|encrypt|decrypt|PDFPasswordIncorrect|PdfminerException", re.I
)


# ---------------------------------------------------------------- child side

def _norm(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _stream_text(pdf) -> str:
    parts = []
    for obj in pdf.objects:
        if isinstance(obj, __import__("pikepdf").Stream):
            try:
                parts.append(bytes(obj.read_bytes()).decode("latin-1", "replace"))
            except Exception:
                pass
    return "\n".join(parts)


def auth_pypdf(path: str, pw: str) -> str:
    from pypdf import PdfReader

    r = PdfReader(path)
    if r.is_encrypted and not r.decrypt(pw):
        raise PermissionError("password")
    return "\n".join((p.extract_text() or "") for p in r.pages)


def auth_pdfminer(path: str, pw: str) -> str:
    import pdfplumber

    with pdfplumber.open(path, password=pw) as pdf:
        return "\n".join((p.extract_text() or "") for p in pdf.pages)


def auth_pymupdf(path: str, pw: str) -> str:
    import pymupdf

    with pymupdf.open(path) as doc:
        if doc.needs_pass and not doc.authenticate(pw):
            raise PermissionError("password")
        return "\n".join(p.get_text() for p in doc)


def auth_pypdfium2(path: str, pw: str) -> str:
    import pypdfium2 as pdfium

    doc = pdfium.PdfDocument(path, password=pw)
    try:
        return "\n".join(p.get_textpage().get_text_range() for p in doc)
    finally:
        doc.close()


def auth_pikepdf(path: str, pw: str) -> str:
    import pikepdf

    pdf = pikepdf.Pdf.open(path, password=pw)
    try:
        return _stream_text(pdf)
    finally:
        pdf.close()


AUTH = {
    "pypdf": auth_pypdf,
    "pdfminer": auth_pdfminer,
    "pymupdf": auth_pymupdf,
    "pypdfium2": auth_pypdfium2,
    "pikepdf": auth_pikepdf,
}


@contextlib.contextmanager
def capture_fd1():
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


def run_child(engine: str) -> None:
    try:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    items = json.loads(sys.stdin.read())

    if engine == "pdfjs":
        proc = subprocess.run(
            ["node", str(ROOT / "authmatrix_probe.mjs")],
            input=json.dumps(items),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT),
        )
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        sys.exit(proc.returncode)

    fn = AUTH[engine]
    for item in items:
        out = {"idx": item["idx"], "status": "OK", "text_len": 0, "text": ""}
        with capture_fd1() as noise_file:
            try:
                text = fn(item["file"], item["password"])
                out["text"] = text[:4000]
                out["text_len"] = len(text.strip())
            except Exception as exc:
                msg = f"{type(exc).__name__}: {exc}"
                out["status"] = "BLOCKED" if PASSWORD_HINTS.search(msg) else "ERROR"
                out["error"] = msg[:300]
        out["noise"] = noise_file.read()[:200].replace("\n", " ")
        print(json.dumps(out), flush=True)


# --------------------------------------------------------------- parent side

def run_batch(engine: str, items: list[dict], timeout: int) -> tuple[dict[int, dict] | None, str | None]:
    cmd = [sys.executable, str(Path(__file__).resolve()), "--auth", engine]
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    try:
        proc = subprocess.run(
            cmd, input=json.dumps(items), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        return None, f"timeout>{timeout}s"
    if proc.returncode != 0:
        return None, f"exit {proc.returncode}: {(proc.stderr or '')[-200:]}"
    out: dict[int, dict] = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        out[rec["idx"]] = rec
    if len(out) != len(items):
        return None, "incomplete batch output"
    return out, None


def main() -> None:
    FINDINGS.mkdir(exist_ok=True)
    manifest = json.loads(MANIFEST.read_text())
    files = [
        e for e in manifest
        if e["has_user_password"] and not e.get("mutant")
    ]

    # build the probe plan
    plan: list[dict] = []
    meta: dict[int, dict] = {}
    idx = 0
    for entry in files:
        for label, pw, expectation in CANDIDATES:
            plan.append({"idx": idx, "file": str(ROOT / entry["file"]), "password": pw})
            meta[idx] = {"entry": entry, "label": label, "expectation": expectation}
            idx += 1

    rows: list[dict] = []
    bypasses: list[dict] = []
    failures: list[dict] = []

    for engine in ENGINES:
        for i in range(0, len(plan), BATCH_SIZE):
            chunk = plan[i : i + BATCH_SIZE]
            results, err = run_batch(engine, chunk, TIMEOUT_BATCH_S)
            if results is None:
                results = {}
                for item in chunk:
                    one, one_err = run_batch(engine, [item], TIMEOUT_ONE_S)
                    results[item["idx"]] = (
                        one[item["idx"]] if one is not None
                        else {"idx": item["idx"], "status": "CRASH", "error": one_err or err, "text_len": 0, "text": ""}
                    )
            for item in chunk:
                m = meta[item["idx"]]
                res = results[item["idx"]]
                text_norm = _norm(res.get("text", "") or "")
                entry = m["entry"]
                canary_hit = any(_norm(c) in text_norm for c in entry["canaries"])
                status = res["status"]
                expectation = m["expectation"]

                if canary_hit:
                    if expectation == "wrong":
                        verdict = "AUTH-BYPASS"
                        bypasses.append({"file": entry["file"], "engine": engine, "password": m["label"]})
                    elif expectation == "expected-accept":
                        verdict = "ACCEPTED-OWNER"
                    else:
                        verdict = "ACCEPTED-CONTROL"
                elif expectation == "control" and status in ("OK", "BLOCKED", "ERROR"):
                    verdict = "FAIL-CONTROL"  # correct password did not yield the canary
                    failures.append({"file": entry["file"], "engine": engine, "detail": res.get("error") or f"text_len={res.get('text_len', 0)}"})
                elif status == "BLOCKED":
                    verdict = "REJECTED"
                elif status == "OK":
                    verdict = "NO-CANARY"
                else:
                    verdict = status

                rows.append({
                    "file": entry["file"],
                    "engine": engine,
                    "password": m["label"],
                    "expectation": expectation,
                    "verdict": verdict,
                    "detail": (res.get("error") or res.get("noise") or f"text_len={res.get('text_len', 0)}")[:160],
                })
        print(f"{engine}: {len(plan)} auth probes done")

    with open(FINDINGS / "authmatrix.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    lines = ["# Authentication matrix", ""]
    lines.append(f"- files: {len(files)}   engines: {len(ENGINES)}   probes: {len(rows)}")
    lines.append(f"- **AUTH-BYPASS: {len(bypasses)}**   FAIL-CONTROL: {len(failures)}")
    lines.append("")
    if bypasses:
        lines.append("## AUTH-BYPASS (critical)")
        lines.append("")
        for b in bypasses:
            lines.append(f"- {b['file']} | {b['engine']} accepted password candidate `{b['password']}` and leaked canary content")
        lines.append("")
    if failures:
        lines.append("## FAIL-CONTROL (correct password rejected / no content)")
        lines.append("")
        for f in failures:
            lines.append(f"- {f['file']} | {f['engine']} | {f['detail']}")
        lines.append("")
    lines.append("## Summary by verdict")
    lines.append("")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    for k in sorted(counts):
        lines.append(f"- {k}: {counts[k]}")
    (FINDINGS / "authmatrix.md").write_text("\n".join(lines), encoding="utf-8")

    print("\n=== summary ===")
    for k in sorted(counts):
        print(f"{k:16} {counts[k]}")
    print(f"\nreport -> {FINDINGS / 'authmatrix.md'}")
    if bypasses:
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--auth":
        run_child(sys.argv[2])
    else:
        main()
