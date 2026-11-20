"""mint_shorecdlp.py - mint the shorecdlp_mage evidence (Yukon eigenlabs/shorecdlp, Lean track).

Reads ONLY input/<tag>/ (built by D:/shorecdlp_mage_notes/tools/snapshot.py; SHA256SUMS.txt checked).
Writes out/<tag>/. Records: the lever ledger (one leaf per lever, positive / neutral / negative /
pending, refers-to edges to its evidence blobs), run-file/1 per dual-agent run file (charter, the
Gap's candidate.patch + candidate.sha256, soulbis verdict, judge score and logs), package-file/1
per file. Checks: hashsmash/lever-tally/1 on the levers, rows/count/1 on each run.
The candidate is re-checkable: apply runs/<r>/candidate.patch to eigenlabs/shorecdlp at the base
commit named in RUN.md and run ./benchmark.sh (Linux).
"""
from __future__ import annotations
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))  # repository root
import hashlib, json, os, sys
from bundle import Bundle
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAG = sys.argv[1] if len(sys.argv) > 1 else "shorecdlp_v1"
IN = os.path.join(HERE, "input", TAG); OUT = os.path.join(HERE, "out", TAG)
ASSERTER = "unsigned:shorecdlp_mage"

def read(name): return open(os.path.join(IN, *name.split("/")), "rb").read()
def check_sums():
    rels = []
    for line in read("SHA256SUMS.txt").decode().splitlines():
        parts = line.split()
        if len(parts) < 2: continue
        h, rel = parts[0], parts[-1].lstrip("*")
        if hashlib.sha256(read(rel)).hexdigest() != h: raise SystemExit("checksum mismatch: " + rel)
        rels.append(rel)
    return rels

def main():
    rels = check_sums()
    B = Bundle("shorecdlp/" + TAG, ASSERTER)
    blobs = {r: B.put_blob(read(r), "file:" + r) for r in rels}
    ledgers, checks, seq = [], [], 0
    extra = {"snapshot_files": len(rels), "board": "eigenlabs/shorecdlp/lean"}
    runs = sorted({r.split("/")[1] for r in rels if r.startswith("runs/")})
    for run in runs:
        files = [r for r in rels if r.startswith(f"runs/{run}/")]
        ks = []
        for r in files:
            seq += 1; data = read(r)
            body = {"run": run, "file": r.split("/", 2)[2], "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            ks.append(B.record(seq, "run-file/1", body, blobs[r], f"run:{run}:{body['file']}"))
        lk = B.ledger(f"shorecdlp-run-{run}", f"dual-agent run {run}: charter, Gap candidate, assay verdict, judge output", ks)
        B.check(f"shorecdlp-run-{run}-count", lk, "rows/count/1", {"n": len(ks)})
        ledgers.append(f"shorecdlp-run-{run}"); checks.append(f"shorecdlp-run-{run}-count")
        if f"runs/{run}/candidate.sha256" in blobs:
            extra[f"candidate_{run}"] = read(f"runs/{run}/candidate.sha256").decode().split()[0]
        if f"runs/{run}/verdict.json" in blobs:
            v = json.loads(read(f"runs/{run}/verdict.json"))
            extra[f"verdict_{run}"] = v.get("verdict"); extra[f"score_{run}"] = v.get("score")
    rows = [json.loads(l) for l in read("levers.jsonl").decode().splitlines() if l.strip()]
    lks = []
    for row in rows:
        for p, h in row["evidence"].items():
            if hashlib.sha256(read("lever_evidence/" + p)).hexdigest() != h:
                raise SystemExit("lever evidence hash mismatch: " + p)
        k = B.record(1000 + row["seq"], row["status"], row, blobs["levers.jsonl"], f"lever:{row['lever']}")
        for p in row["evidence"]: B.edge(k, blobs["lever_evidence/" + p], "refers-to")
        lks.append(k)
    llk = B.ledger("shorecdlp-lever-ledger", f"the {len(lks)} shorecdlp_mage levers: adopted, measured, pending and no-go paths", lks)
    st = [r["status"] for r in rows]
    B.check("shorecdlp-lever-tally", llk, "hashsmash/lever-tally/1",
            {"n": len(rows), "statuses": sorted(set(st)), "by_status": {x: st.count(x) for x in sorted(set(st))},
             "cpu_s_total": round(sum(float(r["cpu_s"]) for r in rows), 2)})
    ledgers.append("shorecdlp-lever-ledger"); checks.append("shorecdlp-lever-tally")
    fks = []
    for r in rels:
        seq += 1; data = read(r)
        fks.append(B.record(seq, "package-file/1", {"name": r, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}, blobs[r]))
    B.ledger(TAG + "-package-files", "ledger, lever evidence and run files", fks)
    ledgers.append(TAG + "-package-files")
    root = B.root(ledgers + checks, extra)
    B.write(OUT, ["", f"Files in snapshot: {len(rels)}", f"Runs: {', '.join(runs) or 'none'}", f"Ledgers: {', '.join(ledgers)}", "",
                  "Counts and the lever tally are recomputed by verify_bundle.py from the bundle alone.",
                  "A candidate is re-checkable by applying its candidate.patch at the RUN.md base and running ./benchmark.sh."])
    print("root", root); print("merkle", B._mroot, "leaves", B._nleaves)

if __name__ == "__main__":
    main()
