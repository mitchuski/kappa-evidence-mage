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
    n = 0
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
    files = sorted(f for f in os.listdir(IN) if f != "SHA256SUMS.txt")
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
        phases = {"build_f": L["phases"]["build_f"]}
        for t in L["trials"]:
            for k in ("ops_prepare", "ops_powering", "ops_gcd", "ops_finish"):
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
    fks = []
    for f in files:
        seq += 1; data = read(f)
        fks.append(B.record(seq, "package-file/1", {"name": f, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}, blobs[f]))
    B.ledger(TAG + "-package-files", "package files, ledgers, programs (records with provenance to their blobs)", fks)
    ledgers.append(TAG + "-package-files")
    root = B.root(ledgers + checks, {"snapshot_files": n, "board": "mooselumph/hashsmash-pareto/poseidon"})
    B.write(OUT, ["", f"Files in snapshot: {n}", f"Ledgers: {', '.join(ledgers)}", "",
                  "Records are recomputed by verify_bundle.py from the bundle alone (ledger sums, log2 totals).",
                  "Certificates are re-checkable with the organizer verifier on the message files."])
    print("root", root); print("merkle", B._mroot, "leaves", B._nleaves)

if __name__ == "__main__":
    main()
