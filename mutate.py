"""
Structure-aware mutator for the /Encrypt dictionary.

Bug class being probed: "malformed /Encrypt -> plaintext fallback", where a
parser skips decryption instead of erroring (CVE-class), or crashes outright
(memory-safety / DoS class).

Mutations are applied ONLY inside the /Encrypt object body, located via the
trailer's /Encrypt reference, so stream /Length values elsewhere are never
clobbered. Mutants inherit the parent file's manifest entry metadata.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
BASE = CORPUS / "base"
MUTANTS = CORPUS / "mutants"
MANIFEST = CORPUS / "manifest.json"

# (mutation_id, [(old, new), ...]) - pairs applied inside the /Encrypt object
# body only; pairs whose `old` token is absent are skipped.
MUTATIONS = [
    ("v5_to_v1", [(b"/V 5", b"/V 1")]),
    ("v5_to_v2", [(b"/V 5", b"/V 2")]),
    ("v5_to_v4", [(b"/V 5", b"/V 4")]),
    ("r6_to_r4", [(b"/R 6", b"/R 4")]),
    ("r6_to_r2", [(b"/R 6", b"/R 2")]),
    ("r6_to_r5", [(b"/R 6", b"/R 5")]),
    ("r5_to_r6", [(b"/R 5", b"/R 6")]),
    ("len256_to_40", [(b"/Length 256", b"/Length 40")]),
    ("len256_to_128", [(b"/Length 256", b"/Length 128")]),
    ("len128_to_40", [(b"/Length 128", b"/Length 40")]),
    ("stmf_identity", [(b"/StmF /StdCF", b"/StmF /Identity")]),
    ("strf_identity", [(b"/StrF /StdCF", b"/StrF /Identity")]),
    ("eff_identity", [(b"/EFF /StdCF", b"/EFF /Identity")]),
    ("cfm_none", [(b"/CFM /AESV3", b"/CFM /None")]),
    ("cfm_v2", [(b"/CFM /AESV3", b"/CFM /V2")]),
    ("cfm_aesv2", [(b"/CFM /AESV3", b"/CFM /AESV2")]),
    ("cfm_aesv2_to_none", [(b"/CFM /AESV2", b"/CFM /None")]),
    ("cfm_aesv2_to_v2", [(b"/CFM /AESV2", b"/CFM /V2")]),
    ("cfm_aesv3_to_v2", [(b"/CFM /AESV3", b"/CFM /V2")]),
    ("filter_identity", [(b"/Filter /Standard", b"/Filter /Identity")]),
    ("filter_bogus", [(b"/Filter /Standard", b"/Filter /Stndard")]),
    ("authevent_open", [(b"/AuthEvent /DocOpen", b"/AuthEvent /EFOpen")]),
    # everything at once: streams and strings "decrypted" with Identity (no crypto)
    (
        "all_identity",
        [
            (b"/StmF /StdCF", b"/StmF /Identity"),
            (b"/StrF /StdCF", b"/StrF /Identity"),
            (b"/EFF /StdCF", b"/EFF /Identity"),
            (b"/CFM /AESV3", b"/CFM /None"),
            (b"/CFM /AESV2", b"/CFM /None"),
            (b"/CFM /V2", b"/CFM /None"),
        ],
    ),
]

# trailer-level mutation: hide the /Encrypt reference entirely
TRAILER_MUTATION = ("encrypt_ref_hidden", re.compile(rb"/Encrypt (\d+) 0 R"), rb"/Xncrypt \1 0 R")


def find_encrypt_object(data: bytes) -> tuple[int, int] | None:
    """Return (start, end) byte span of the /Encrypt object body."""
    m = re.search(rb"/Encrypt (\d+) 0 R", data)
    if not m:
        return None
    objnum = m.group(1)
    objm = re.search(rb"(?m)^" + re.escape(objnum) + rb" 0 obj\b", data)
    if not objm:
        return None
    endm = re.search(rb"endobj", data[objm.end() :])
    if not endm:
        return None
    return objm.end(), objm.end() + endm.start()


def make_entry(parent: dict, m_id: str, mut_id: str) -> dict:
    return {
        "id": m_id,
        "file": f"corpus/mutants/{m_id}.pdf",
        "has_user_password": True,
        "user_password": parent["user_password"],
        "canaries": parent["canaries"],
        "meta_canary": parent.get("meta_canary"),
        "meta_encrypted": parent.get("meta_encrypted", True),
        "attach_canary": parent.get("attach_canary"),
        "notes": f"mutant of {parent['id']}: {mut_id}",
        "mutant": True,
        "parent": parent["id"],
        "mutation": mut_id,
    }


def main() -> None:
    manifest = json.loads(MANIFEST.read_text())
    MUTANTS.mkdir(parents=True, exist_ok=True)
    for old in MUTANTS.glob("*.pdf"):
        old.unlink()

    new_entries: list[dict] = []
    parents = [e for e in manifest if e["has_user_password"] and not e.get("mutant")]

    for parent in parents:
        src = ROOT / parent["file"]
        data = src.read_bytes()
        span = find_encrypt_object(data)
        if span is None:
            print(f"[warn] {parent['id']}: no /Encrypt object found, skipping")
            continue

        s, e = span
        body = data[s:e]

        for mut_id, pairs in MUTATIONS:
            mutant_body = body
            applied = False
            for old_tok, new_tok in pairs:
                if old_tok in mutant_body:
                    mutant_body = mutant_body.replace(old_tok, new_tok)
                    applied = True
            if not applied:
                continue
            m_id = f"{parent['id']}__{mut_id}"
            (MUTANTS / f"{m_id}.pdf").write_bytes(data[:s] + mutant_body + data[e:])
            new_entries.append(make_entry(parent, m_id, mut_id))

        # trailer-level: hide the /Encrypt reference (last occurrence = trailer)
        mut_id, pat, repl = TRAILER_MUTATION
        matches = list(pat.finditer(data))
        if matches:
            last = matches[-1]
            mutant = (
                data[: last.start()]
                + pat.sub(repl, data[last.start() : last.end()], count=1)
                + data[last.end() :]
            )
            m_id = f"{parent['id']}__{mut_id}"
            (MUTANTS / f"{m_id}.pdf").write_bytes(mutant)
            new_entries.append(make_entry(parent, m_id, mut_id))

    manifest.extend(new_entries)
    MANIFEST.write_text(json.dumps(manifest, indent=2))
    print(f"Wrote {len(new_entries)} mutants -> {MUTANTS}")
    print(f"Manifest now has {len(manifest)} entries")


if __name__ == "__main__":
    main()
