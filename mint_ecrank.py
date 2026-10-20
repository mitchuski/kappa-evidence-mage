"""mint_ecrank.py - mint the ecrank_mage evidence (Yukon layr-labs/ec-rank).

Reads ONLY input/<tag>/ (built by the ecrank lane's tools/snapshot.py; SHA256SUMS.txt checked).
Writes out/<tag>/. Records: curve-file/1 per board curve (a-invariants, points, claim, header),
the lever ledger (one leaf per lever, refers-to edges to its evidence), campaign-event/1 per
campaign log row, package-file/1 per file. Checks: rows/count/1 on the curves and the campaign,
hashsmash/lever-tally/1 on the levers. The curves themselves are re-checkable with the
challenge's verifier (python -m ec_verify) on the board files in the bundle.
"""
from __future__ import annotations
import hashlib, json, os, sys
from bundle import Bundle
HERE = os.path.dirname(os.path.abspath(__file__))
TAG = sys.argv[1] if len(sys.argv) > 1 else "ecrank_v1"
IN = os.path.join(HERE, "input", TAG); OUT = os.path.join(HERE, "out", TAG)
ASSERTER = "unsigned:ecrank_mage"

def read(name): return open(os.path.join(IN, name), "rb").read()
def check_sums():
    rels = []
    for line in read("SHA256SUMS.txt").decode().splitlines():
        parts = line.split()
        if len(parts) < 2: continue
        h, rel = parts[0], parts[-1].lstrip("*")
        if hashlib.sha256(read(rel)).hexdigest() != h: raise SystemExit("checksum mismatch: " + rel)
        rels.append(rel)
    return rels

def parse_ec(text):
    ainv, pts, claim, hdr = None, [], None, []
    for line in text.splitlines():
        if line.startswith("#CLAIM"): claim = line.split("=", 1)[1].strip()
        elif line.startswith("#"): hdr.append(line[1:].strip())
        elif line.startswith("E "): ainv = line.split()[1:]
        elif line.startswith("P "): pts.append(line.split()[1:])
    return {"ainvs": ainv, "points": pts, "n_points": len(pts), "claim_rank": claim, "header": " ".join(hdr)}

def main():
    rels = check_sums()
    B = Bundle("ec-rank/" + TAG, ASSERTER)
    blobs = {r: B.put_blob(read(r), "file:" + r) for r in rels}
    ledgers, checks, seq = [], [], 0
    boards = [r for r in rels if r.startswith("board/")]
    if boards:
        ks = []
        for r in boards:
            seq += 1
            ks.append(B.record(seq, "curve-file/1", {"file": r, **parse_ec(read(r).decode())}, blobs[r], "curve:" + r))
        lk = B.ledger("ecrank-board-curves", f"the {len(ks)} board curves of this submission", ks)
        B.check("ecrank-board-count", lk, "rows/count/1", {"n": len(ks)})
        ledgers.append("ecrank-board-curves"); checks.append("ecrank-board-count")
    if "campaign.jsonl" in blobs:
        ks = []
        for line in read("campaign.jsonl").decode().splitlines():
            if not line.strip(): continue
            seq += 1
            ks.append(B.record(seq, "campaign-event/1", json.loads(line), blobs["campaign.jsonl"]))
        lk = B.ledger("ecrank-campaign", f"s1 campaign log: {len(ks)} job/hit/error events", ks)
        B.check("ecrank-campaign-count", lk, "rows/count/1", {"n": len(ks)})
        ledgers.append("ecrank-campaign"); checks.append("ecrank-campaign-count")
    rows = [json.loads(l) for l in read("levers.jsonl").decode().splitlines() if l.strip()]
    lks = []
    for row in rows:
        for p, h in row["evidence"].items():
            if hashlib.sha256(read("lever_evidence/" + p)).hexdigest() != h:
                raise SystemExit("lever evidence hash mismatch: " + p)
        k = B.record(1000 + row["seq"], row["status"], row, blobs["levers.jsonl"], f"lever:{row['lever']}")
        for p in row["evidence"]: B.edge(k, blobs["lever_evidence/" + p], "refers-to")
        lks.append(k)
    llk = B.ledger("ecrank-lever-ledger", f"the {len(lks)} ecrank_mage levers: adopted, measured and no-go paths", lks)
    st = [r["status"] for r in rows]
    B.check("ecrank-lever-tally", llk, "hashsmash/lever-tally/1",
            {"n": len(rows), "statuses": sorted(set(st)), "by_status": {x: st.count(x) for x in sorted(set(st))},
             "cpu_s_total": round(sum(float(r["cpu_s"]) for r in rows), 2)})
    ledgers.append("ecrank-lever-ledger"); checks.append("ecrank-lever-tally")
    fks = []
    for r in rels:
        seq += 1; data = read(r)
        fks.append(B.record(seq, "package-file/1", {"name": r, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}, blobs[r]))
    B.ledger(TAG + "-package-files", "search code, ledgers, logs and board files", fks)
    ledgers.append(TAG + "-package-files")
    root = B.root(ledgers + checks, {"snapshot_files": len(rels), "board": "layr-labs/ec-rank", "curves": len(boards)})
    B.write(OUT, ["", f"Files in snapshot: {len(rels)}", f"Ledgers: {', '.join(ledgers)}", "",
                  "Counts and the lever tally are recomputed by verify_bundle.py from the bundle alone.",
                  "Curves are re-checkable with the challenge verifier on the board files."])
    print("root", root); print("merkle", B._mroot, "leaves", B._nleaves)

if __name__ == "__main__":
    main()
