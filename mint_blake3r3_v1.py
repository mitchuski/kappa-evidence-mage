"""mint_blake3r3_v1.py - mint the blake3-r3 (hashsmash-pareto) lane's parked research: board survey, shave measurement and the
three negative cryptanalysis results (r2 carry-over, literature, biased-family probe).

Reads ONLY input/blake3r3_v1/ (SHA256SUMS.txt checked; lever evidence hash-checked per row). Writes out/blake3r3_v1/.
No submission: this bundle records why the lane was parked on 2026-10-13.
"""
from __future__ import annotations

import hashlib
import json
import os

from bundle import Bundle

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(HERE, "input", "blake3r3_v1")
OUT = os.path.join(HERE, "out", "blake3r3_v1")
ASSERTER = "unsigned:blake3r3_mage"


def read(name: str) -> bytes:
    with open(os.path.join(IN, name), "rb") as f:
        return f.read()


def check_sums():
    n = 0
    for line in read("SHA256SUMS.txt").decode().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        h, fname = parts[0], parts[-1].lstrip("*")
        if hashlib.sha256(read(fname)).hexdigest() != h:
            raise SystemExit("checksum mismatch: " + fname)
        n += 1
    return n


def main():
    n = check_sums()
    B = Bundle("hashsmash-pareto/blake3-r3/research", ASSERTER)
    blobs = {f: B.put_blob(read(f), "file:" + f) for f in ("RACE.md", "levers.jsonl")}
    rows = [json.loads(l) for l in read("levers.jsonl").decode().splitlines() if l.strip()]
    ev_blobs, lks = {}, []
    for row in rows:
        for p, h in row["evidence"].items():
            if p not in ev_blobs:
                raw = read(os.path.join("lever_evidence", p))
                if hashlib.sha256(raw).hexdigest() != h:
                    raise SystemExit("lever evidence hash mismatch: " + p)
                ev_blobs[p] = B.put_blob(raw, "evidence:" + p)
        k = B.record(1000 + row["seq"], row["status"], row, blobs["levers.jsonl"], f"lever:{row['lever']}")
        for p in row["evidence"]:
            B.edge(k, ev_blobs[p], "refers-to")
        lks.append(k)
    llk = B.ledger("blake3r3-lever-ledger", f"the {len(lks)} blake3-r3 levers: board survey, shave measurement, negative cryptanalysis", lks)
    st = [r["status"] for r in rows]
    B.check("blake3r3-lever-tally", llk, "hashsmash/lever-tally/1",
            {"n": len(rows), "statuses": sorted(set(st)), "by_status": {x: st.count(x) for x in sorted(set(st))},
             "cpu_s_total": round(sum(float(r["cpu_s"]) for r in rows), 2)})
    fks = []
    for i, f in enumerate(sorted(blobs)):
        data = read(f)
        fks.append(B.record(1 + i, "package-file/1", {"name": f, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}, blobs[f]))
    B.ledger("blake3r3-files", "the lane resume note and the lever table", fks)
    root = B.root(["blake3r3-lever-ledger", "blake3r3-files", "blake3r3-lever-tally"],
                  {"track": "blake3 (hashsmash-pareto, admission [3])", "board": "Jbenisek e479cbbf [3, 125.1087]",
                   "status": "parked 2026-10-13: no structural r3 lead; shave (~125.0994) declined", "snapshot_files": n})
    B.write(OUT, ["", f"Files in snapshot: {n}", "Ledgers: blake3r3-lever-ledger, blake3r3-files", "",
                  "Research record only; no submission. Every lever row links its evidence files by sha256."])
    print("root", root)
    print("merkle", B._mroot, "leaves", B._nleaves)


if __name__ == "__main__":
    main()
