"""
Ciphertext-level fuzzer.

Takes the valid encrypted corpus as seeds, mutates stream bytes / header /
xref regions / truncation, and probes native parsers for hard crashes or hangs.
MuPDF's unauthenticated object-stream path (see findings F-2026-001) makes it a
priority target: it decodes ciphertext bytes it should never touch without the
password, which is exactly where memory-safety bugs live.

A crash or hang is a candidate bug (DoS / memory safety). Reproducers are saved
with the exact mutation spec so the finding is deterministic.

Usage: python fuzz.py [iterations]
Outputs: findings/crashes/*.pdf + findings/crashes/index.jsonl + console summary
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

from triage import run_batch  # reuse the isolated batch-probe machinery

ROOT = Path(__file__).resolve().parent
SEEDS = sorted((ROOT / "corpus" / "base").glob("*.pdf"))
WORK = ROOT / "corpus" / "fuzz"
CRASHES = ROOT / "findings" / "crashes"
ENGINES = ["pymupdf", "pypdfium2", "pdfjs"]
BATCH = 25
TIMEOUT_BATCH_S = 180


def stream_spans(data: bytes) -> list[tuple[int, int]]:
    spans = []
    start = 0
    while True:
        i = data.find(b"stream", start)
        if i < 0:
            break
        j = data.find(b"endstream", i)
        if j < 0 or j <= i + 6:
            break
        spans.append((i + 7, j))
        start = j + 9
    return spans


def mutate(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    mode = rng.choices(
        ["stream", "header", "truncate", "append"],
        weights=[0.65, 0.2, 0.1, 0.05],
    )[0]

    if mode == "stream":
        spans = stream_spans(data)
        if spans:
            s, e = rng.choice(spans)
            if e - s > 2:
                off = rng.randrange(s, e)
                buf = bytearray(data)
                for k in range(rng.randint(1, 8)):
                    p = off + k
                    if p < len(data):
                        buf[p] = rng.randrange(256)
                return bytes(buf), f"stream@{off}"

    if mode == "header":
        # dict/trailer region: first 4 KB
        limit = min(4096, len(data) - 1)
        off = rng.randrange(0, limit)
        buf = bytearray(data)
        for k in range(rng.randint(1, 6)):
            p = off + k
            if p < len(data):
                buf[p] = rng.randrange(256)
        return bytes(buf), f"header@{off}"

    if mode == "truncate":
        cut = rng.randrange(len(data) // 2, max(len(data) // 2 + 1, len(data) - 1))
        return data[:cut], f"truncate@{cut}"

    extra = rng.randint(1, 64)
    return data + bytes(rng.randrange(256) for _ in range(extra)), f"append+{extra}"


def main() -> None:
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 1200
    WORK.mkdir(parents=True, exist_ok=True)
    CRASHES.mkdir(parents=True, exist_ok=True)
    index = open(CRASHES / "index.jsonl", "a", encoding="utf-8")

    seeds = {p: p.read_bytes() for p in SEEDS}
    rng = random.Random(20261022)

    cases: list[dict] = []
    for n in range(iterations):
        seed = rng.choice(list(seeds))
        data, spec = mutate(seeds[seed], rng)
        out = WORK / f"f{n:05d}.pdf"
        out.write_bytes(data)
        cases.append({"n": n, "file": str(out), "seed": seed.name, "spec": spec})

    counts: dict[str, int] = {}
    crashes = 0

    for engine in ENGINES:
        for i in range(0, len(cases), BATCH):
            chunk = cases[i : i + BATCH]
            results, fail = run_batch(engine, [c["file"] for c in chunk], TIMEOUT_BATCH_S)
            if results is None:
                # isolate the culprit one by one
                per_file = {}
                for c in chunk:
                    r, _ = run_batch(engine, [c["file"]], 30)
                    if r is None:
                        per_file[c["file"]] = {
                            "status": "CRASH",
                            "error": f"isolated probe failed: {fail}",
                        }
                    else:
                        per_file.update(r)
                results = per_file
            by_file = {c["file"]: c for c in chunk}
            for f, res in results.items():
                status = res["status"]
                counts[status] = counts.get(status, 0) + 1
                if status in ("CRASH", "TIMEOUT"):
                    crashes += 1
                    c = by_file[f]
                    keep = CRASHES / f"{engine}__{c['seed']}__{c['n']}.pdf"
                    keep.write_bytes(Path(f).read_bytes())
                    index.write(json.dumps({
                        "engine": engine,
                        "status": status,
                        "seed": c["seed"],
                        "spec": c["spec"],
                        "file": str(keep.relative_to(ROOT)),
                        "detail": res.get("error", ""),
                    }) + "\n")
                    index.flush()
                    print(f"  [{status}] {engine} {c['seed']} {c['spec']}")
            print(f"{engine}: {min(i + BATCH, len(cases))}/{len(cases)}")

    index.close()
    print("\n=== fuzz summary ===")
    for k in sorted(counts):
        print(f"{k:10} {counts[k]}")
    print(f"crashes/timeouts: {crashes}")
    print(f"reproducers -> {CRASHES}")
    if crashes:
        sys.exit(1)


if __name__ == "__main__":
    main()
