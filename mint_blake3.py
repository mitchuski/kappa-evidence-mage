"""mint_blake3.py - mint the blake3_mage lever ledger (HashSmash BLAKE3 r1/r2, research r3) into a kappa graph.

Reads ONLY input/blake3_2026-10-11/ (read-only snapshot exported by blake3_mage, SHA256SUMS checked).
Writes out/blake3_2026-10-11/. One record/1 per lever row (kind = status: positive / negative /
inconclusive / lead), provenance = the evidence blob(s) the row names; one ledger; a check/1 under
`hashsmash/lever-tally/1` that verify_bundle.py recomputes. Rows also carry BLAKE3 footprints
(b3_row, evidence b3 digests) as a second axis; the registry kappa stays sha256 over dCBOR.
"""
from __future__ import annotations
import hashlib, json, os
from bundle import Bundle, redact

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(HERE, "input", "blake3_2026-10-11")
OUT = os.path.join(HERE, "out", "blake3_2026-10-11")
LANE = "hashsmash/blake3"


def rd(p: str) -> bytes:
    with open(os.path.join(IN, p), "rb") as f:
        return f.read()


def tally(rows: list[dict]) -> dict:
    st = [r["status"] for r in rows]
    return {"n": len(rows), "statuses": sorted(set(st)), "by_status": {s: st.count(s) for s in sorted(set(st))},
            "cpu_s_total": round(sum(float(r["cpu_s"]) for r in rows), 2)}


def main():
    for line in rd("SHA256SUMS").decode().splitlines():
        h, p = line.split(maxsplit=1)
        assert hashlib.sha256(rd(p.strip())).hexdigest() == h, f"snapshot hash mismatch: {p}"
    B = Bundle(LANE, "unsigned:blake3_mage")
    led_b = B.put_blob(rd("ledger/levers.jsonl"), "source:levers.jsonl")
    blobs = {}
    rows = [json.loads(l) for l in rd("ledger/levers.jsonl").decode().splitlines() if l.strip()]
    ks = []
    for r in rows:
        for p in r["evidence"]:
            if p not in blobs:
                raw = rd(p)
                blobs[p] = B.put_blob(redact(raw.decode("utf-8")).encode("utf-8"), f"evidence:{p}")
        fields = {k: (redact(v) if isinstance(v, str) else v) for k, v in r.items()}
        k = B.record(r["seq"], r["status"], fields, led_b, f"lever:{r['lever']}")
        for p in r["evidence"]:
            B.edge(k, blobs[p], "refers-to")
        ks.append(k)
    lk = B.ledger("blake3-lever-ledger", f"the {len(ks)} BLAKE3 lever attempts, positive and negative", ks)
    B.check("blake3-lever-tally", lk, "hashsmash/lever-tally/1", tally(rows))
    B.root(["blake3-lever-ledger", "blake3-lever-tally"], extra={"snapshot": "blake3_2026-10-11"})  # Bundle seals blake3_axis
    B.write(OUT, ["| lever | status | result |", "|---|---|---|"] +
            [f"| {r['lever']} | {r['status']} | {r['result']} |" for r in rows] +
            ["", "Verify from the bundle alone: `python verify_bundle.py out/blake3_2026-10-11`."])


if __name__ == "__main__":
    main()
