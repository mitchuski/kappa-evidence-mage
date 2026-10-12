"""mint_poseidon.py - mint the poseidon_mage package evidence (r=1 and r=2 counted collisions).

Reads ONLY input/poseidon_v1/ (snapshot: ledger_r{1,2}.json, package files, SHA256SUMS.txt checked).
Writes out/poseidon_v1/. Records: certificate/1 (pairs, digest), orchard-ledger/1 (phase ops, totals,
memory), package-file/1. Rule hashsmash/orchard-ledger-sum/1 recomputes totals and log2 from the record.
"""
from __future__ import annotations
import hashlib, json, math, os, sys
from bundle import Bundle
HERE = os.path.dirname(os.path.abspath(__file__))
TAG = sys.argv[1] if len(sys.argv) > 1 else "poseidon_v1"
IN = os.path.join(HERE, "input", TAG); OUT = os.path.join(HERE, "out", TAG)
ASSERTER = "unsigned:poseidon_mage"

def read(name): return open(os.path.join(IN, name), "rb").read()
def check_sums():
    n = 0  # SHA256SUMS lines may carry subpaths (lever_evidence/...)
    for line in read("SHA256SUMS.txt").decode().splitlines():
        parts = line.split()
        if len(parts) < 2: continue
        h, fname = parts[0], parts[-1].lstrip("*")
        if hashlib.sha256(read(fname)).hexdigest() != h: raise SystemExit("checksum mismatch: " + fname)
        n += 1
    return n

def main():
    n = check_sums()
    B = Bundle("hashsmash-pareto/poseidon/" + TAG, ASSERTER)
    files = sorted(f for f in os.listdir(IN) if f != "SHA256SUMS.txt" and os.path.isfile(os.path.join(IN, f)))
    blobs = {f: B.put_blob(read(f), "file:" + f) for f in files}
    seq = 0; ledgers, checks = [], []
    for R in (1, 2):
        lf = f"ledger_r{R}.json"
        if lf not in blobs: continue
        L = json.loads(read(lf)); tr = L["trials"][-1]; ks = []
        for i, pr in enumerate(L["pairs"]):
            seq += 1
            ks.append(B.record(seq, "certificate/1", {"R": R, "pair": i, "digest_le_hex": L["digest"], "s0": tr["s0"],
                "s1": pr["s1"], "inputs_a": tr["inputs0"], "inputs_b": pr["inputs"],
                "checker": "verifier/poseidon.py (organizer) + attack.py permutation"}, blobs[lf]))
        phases = {"setup": L["phases"]["setup"]}
        for t in L["trials"]:
            for k in ("ops_build", "ops_prepare", "ops_powering", "ops_gcd", "ops_gcd_overhead", "ops_finish"):
                if k in t: phases[f"trial{t['n']}_{k}"] = t[k]
        seq += 1
        ks.append(B.record(seq, "orchard-ledger/1", {"R": R, "D": L["D"], "N1": L["N1"], "N2": L["N2"], "C": L["C"],
            "phases": phases, "total_ops": L["total_ops"], "time_log2": L["time_log2"], "peak_words": L["peak_words"],
            "memory_bytes": L["memory_bytes"], "memory_log2_bytes": L["memory_log2_bytes"], "score": L["score"],
            "trials_executed": len(L["trials"]), "deg_g": [t["deg_g"] for t in L["trials"]],
            "stream": "SHA256('poseidon_mage r=<R> trial <n>') mod p"}, blobs[lf]))
        lk = B.ledger(f"r{R}-evidence", f"orchard r={R}: certificates and the exact operation ledger", ks)
        g = next(B.objects[k][3] for k in ks if B.objects[k][2] == "orchard-ledger/1")
        B.check(f"r{R}-ledger-sum", lk, "hashsmash/orchard-ledger-sum/1",
                {"total": g["total_ops"], "sum": sum(g["phases"].values()),
                 "time_log2": round(math.log2(g["total_ops"] / g["C"]), 6),
                 "score": round(math.log2(g["total_ops"] / g["C"]) + max(0, math.log2(g["memory_bytes"]) - 20), 6)})
        ledgers.append(f"r{R}-evidence"); checks.append(f"r{R}-ledger-sum")
    if os.path.exists(os.path.join(IN, "levers.jsonl")):
        led_b = blobs["levers.jsonl"]
        rows = [json.loads(l) for l in read("levers.jsonl").decode().splitlines() if l.strip()]
        ev_blobs, lks = {}, []
        for row in rows:
            for p, h in row["evidence"].items():
                if p not in ev_blobs:
                    raw = read(os.path.join("lever_evidence", p))
                    if hashlib.sha256(raw).hexdigest() != h: raise SystemExit("lever evidence hash mismatch: " + p)
                    ev_blobs[p] = B.put_blob(raw, "evidence:" + p)
            k = B.record(1000 + row["seq"], row["status"], row, led_b, f"lever:{row['lever']}")
            for p in row["evidence"]: B.edge(k, ev_blobs[p], "refers-to")
            lks.append(k)
        llk = B.ledger("poseidon-lever-ledger", f"the {len(lks)} Orchard Poseidon levers: adopted, measured and no-go paths", lks)
        st = [r["status"] for r in rows]
        B.check("poseidon-lever-tally", llk, "hashsmash/lever-tally/1",
                {"n": len(rows), "statuses": sorted(set(st)), "by_status": {x: st.count(x) for x in sorted(set(st))},
                 "cpu_s_total": round(sum(float(r["cpu_s"]) for r in rows), 2)})
        ledgers.append("poseidon-lever-ledger"); checks.append("poseidon-lever-tally")
    fks = []
    for f in files:
        seq += 1; data = read(f)
        fks.append(B.record(seq, "package-file/1", {"name": f, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}, blobs[f]))
    B.ledger(TAG + "-package-files", "package files, ledgers, programs (records with provenance to their blobs)", fks)
    ledgers.append(TAG + "-package-files")
    extra = {"snapshot_files": n, "board": "mooselumph/hashsmash-pareto/poseidon",
             "submissions": {"r1": "cb4454d3", "r2": "1096f6b9"}}
    REVISES = {"poseidon_v2": "sha256:ce2218637dc37e66c057d94030b3aa60d4a4f147f47f4b6f17a7230ff89b9b75",
               "poseidon_v3": "sha256:fedd8e9c3667fc1140a75829084f879de629e2bd1a3e4519d9c78d4fc302e627"}
    if TAG in REVISES:
        extra["revises"] = REVISES[TAG]
    if TAG == "poseidon_v3":
        extra["submissions"] = {"earlier": {"r1": "cb4454d3", "r2": "1096f6b9"}}
        extra["packages"] = "r=1 and r=2 v4 packages: start points s_n = n + 1, memory-lean half-gcd, explicit gcd overhead"
    root = B.root(ledgers + checks, extra)
    B.write(OUT, ["", f"Files in snapshot: {n}", f"Ledgers: {', '.join(ledgers)}", "",
                  "Records are recomputed by verify_bundle.py from the bundle alone (ledger sums, log2 totals).",
                  "Certificates are re-checkable with the organizer verifier on the message files."])
    print("root", root); print("merkle", B._mroot, "leaves", B._nleaves)

if __name__ == "__main__":
    main()
