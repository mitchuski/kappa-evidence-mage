"""mint_r38.py - mint the sha256-r38 DP-walk evidence (Yukon mooselumph/hashsmash, track sha256-r38-exploratory).

Snapshot (input/<tag>/): the candidate package (package/), the lever ledger with its evidence files
(lever_evidence/<rel>), the 24 evaluation windows and the 48 G-measurement windows (runs/...), the window
pre-declaration, the critic review, the result note and the organizer Docker report. SHA256SUMS.txt over all.
Mint (out/<tag>/): package-file/1 per package file, window-record/1 per measured window (two ledgers with
rows/count/1), the lever ledger (negatives are leaves; hashsmash/lever-tally/1), package-file/1 per document.
usage: python mint_r38.py [tag]   (default r38_v1)
"""
from __future__ import annotations
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))  # repository root
import hashlib, json, os, shutil, sys, re
PRIVATE = re.compile(r"(?i)([a-z]:[\/]users[\/]|/c/users|/mnt/c/|/home/|/root/|desktop-|\\wsl|@[a-z0-9.-]+\.(local|lan))")
from bundle import Bundle
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAG = sys.argv[1] if len(sys.argv) > 1 else "r38_v1"
IN = os.path.join(HERE, "input", TAG); OUT = os.path.join(HERE, "out", TAG)
WAVE = os.path.join(os.path.expanduser("~"), "pareto_wave", "sha256_r38", "WAVE")
ASSERTER = "unsigned:hashsmash_mage"
def sha(b): return hashlib.sha256(b).hexdigest()

def snapshot():
    if os.path.exists(IN): shutil.rmtree(IN)
    for d, _, fs in os.walk(os.path.join(WAVE, "pkg", "candidate")):
        if "__pycache__" in d: raise SystemExit("pycache present: " + d)
        for f in fs:
            src = os.path.join(d, f); rel = os.path.relpath(src, os.path.join(WAVE, "pkg", "candidate")).replace(os.sep, "/")
            dst = os.path.join(IN, "package", rel); os.makedirs(os.path.dirname(dst), exist_ok=True); shutil.copy2(src, dst)
    for rel in ("DECLARE_WINDOWS.md", "CRITIC.md", "RESULT.md", "pkg/docker_report_sha256-r38.json"):
        dst = os.path.join(IN, "docs", os.path.basename(rel)); os.makedirs(os.path.dirname(dst), exist_ok=True); shutil.copy2(os.path.join(WAVE, rel), dst)
    for sub in ("runs/eval", "runs/gwin", "runs/eval_h", "runs/gwin_h"):
        for f in sorted(os.listdir(os.path.join(WAVE, sub))):
            if f.endswith(".json"):
                dst = os.path.join(IN, sub, f); os.makedirs(os.path.dirname(dst), exist_ok=True); shutil.copy2(os.path.join(WAVE, sub, f), dst)
    rows = [json.loads(l) for l in open(os.path.join(WAVE, "ledger", "levers.jsonl"), encoding="utf8") if l.strip()]
    out = []
    for row in rows:
        hashed = {}; unretained = []
        for p, h in row["evidence"].items():
            p = p.replace("\\", "/")
            src = os.path.join(WAVE, p)
            if not os.path.isfile(src): raise SystemExit("missing evidence: " + p)
            if PRIVATE.search(open(src, "rb").read().decode("utf8", "replace")):   # a development tool with local paths: not retained in the public bundle
                unretained.append(p); continue
            dst = os.path.join(IN, "lever_evidence", p); os.makedirs(os.path.dirname(dst), exist_ok=True); shutil.copy2(src, dst)
            hh = sha(open(dst, "rb").read())
            if hh != h:  # evidence edited after its ledger line (documents revised in later steps): keep both hashes on the leaf
                row.setdefault("evidence_rehashed", {})[p] = {"ledger": h, "now": hh}
            hashed[p] = hh
        row = dict(row); row["evidence"] = hashed
        if unretained: row["evidence_not_retained"] = unretained
        out.append(json.dumps(row, sort_keys=True))
    open(os.path.join(IN, "levers.jsonl"), "w", encoding="utf8", newline="\n").write("\n".join(out) + "\n")
    lines = []
    for d, _, fs in os.walk(IN):
        for f in sorted(fs):
            p = os.path.join(d, f); rel = os.path.relpath(p, IN).replace(os.sep, "/")
            if rel != "SHA256SUMS.txt": lines.append(f"{sha(open(p, 'rb').read())}  {rel}")
    open(os.path.join(IN, "SHA256SUMS.txt"), "w", newline="\n").write("\n".join(sorted(lines, key=lambda s: s[66:])) + "\n")

def read(name): return open(os.path.join(IN, name), "rb").read()
def check_sums():
    rels = []
    for line in read("SHA256SUMS.txt").decode().splitlines():
        parts = line.split()
        if len(parts) < 2: continue
        h, rel = parts[0], parts[-1]
        if sha(read(rel)) != h: raise SystemExit("checksum mismatch: " + rel)
        rels.append(rel)
    return rels

def main():
    snapshot(); rels = check_sums()
    B = Bundle("hashsmash-r38/" + TAG, ASSERTER)
    blobs = {r: B.put_blob(read(r), "file:" + r) for r in rels}
    ledgers, checks, seq = [], [], 0
    # the candidate package
    pk = []
    for r in [x for x in rels if x.startswith("package/")]:
        seq += 1; data = read(r)
        pk.append(B.record(seq, "package-file/1", {"name": r, "bytes": len(data), "sha256": sha(data)}, blobs[r], "pkg:" + r))
    B.ledger("r38-package", "the candidate package: claim, proof, certificates and experiments manifest, the program", pk); ledgers.append("r38-package")
    # measured windows
    for sub, name, desc in (("runs/eval_h", "r38-holdout-eval-windows", "the 24 pre-declared HOLDOUT evaluation windows (fresh seeds; the claim's cost and yield data)"),
                            ("runs/gwin_h", "r38-holdout-gf7-windows", "the 48 pre-declared HOLDOUT G/F7-measurement windows (the charged post-filter bounds)"),
                            ("runs/eval", "r38-dev-eval-windows", "development: the 24 public-seed evaluation windows of run 5 (evidence only)"),
                            ("runs/gwin", "r38-dev-g-windows", "development: the 48 public-seed G windows of run 5 (evidence only)")):
        ks = []
        for r in [x for x in rels if x.startswith(sub + "/")]:
            for w in json.loads(read(r)):
                seq += 1
                ks.append(B.record(seq, "window-record/1", {k: w[k] for k in ("seed", "win", "ops", "distinct_claws", "distinct_groups", "claws", "cross", "notclaw", "hits", "matches", "c1", "c2", "g", "f7", "kernel_len", "kernel_nreg", "sec") if k in w}, blobs[r], f"window:{w['seed']}"))
        lk = B.ledger(name, desc, ks); B.check(name + "-count", lk, "rows/count/1", {"n": len(ks)})
        ledgers.append(name); checks.append(name + "-count")
    # the lever ledger
    rows = [json.loads(l) for l in read("levers.jsonl").decode().splitlines() if l.strip()]
    lks = []
    for row in rows:
        for p, h in row["evidence"].items():
            if sha(read("lever_evidence/" + p)) != h: raise SystemExit("lever evidence hash mismatch: " + p)
        k = B.record(1000 + row["seq"], row["status"], row, blobs["levers.jsonl"], f"lever:{row['lever']}")
        for p in row["evidence"]: B.edge(k, blobs["lever_evidence/" + p], "refers-to")
        lks.append(k)
    llk = B.ledger("r38-lever-ledger", f"the {len(lks)} hashsmash_mage r38 levers: adopted, measured and no-go paths (negatives are leaves)", lks)
    st = [r["status"] for r in rows]
    B.check("r38-lever-tally", llk, "hashsmash/lever-tally/1",
            {"n": len(rows), "statuses": sorted(set(st)), "by_status": {x: st.count(x) for x in sorted(set(st))},
             "cpu_s_total": round(sum(float(r["cpu_s"]) for r in rows), 2)})
    ledgers.append("r38-lever-ledger"); checks.append("r38-lever-tally")
    # documents and the rest of the snapshot
    fks = []
    for r in rels:
        if r.startswith("package/"): continue
        seq += 1; data = read(r)
        fks.append(B.record(seq, "package-file/1", {"name": r, "bytes": len(data), "sha256": sha(data)}, blobs[r]))
    B.ledger(TAG + "-files", "declaration, critic review, result, organizer Docker report, window JSONs, lever evidence", fks); ledgers.append(TAG + "-files")
    root = B.root(ledgers + checks, {"snapshot_files": len(rels), "board": "mooselumph/hashsmash/sha256-r38-exploratory",
                                     "claim_time_log2": 89.5906, "claim_memory_log2_bytes": 19.9436, "leader": "newjordan 51613d1c 90.7352"})
    B.write(OUT, ["", f"Files in snapshot: {len(rels)}", f"Ledgers: {', '.join(ledgers)}", "",
                  "Counts and the lever tally are recomputed by verify_bundle.py from the bundle alone.",
                  "The package files re-hash to the FREEZE.md values of the lane."])
    print("root", root); print("merkle", B._mroot, "leaves", B._nleaves)

if __name__ == "__main__":
    main()
