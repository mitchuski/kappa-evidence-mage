"""mint_r38f.py - mint the sha256-r38 r38f evidence (Yukon mooselumph/hashsmash, track sha256-r38-exploratory).

Fork of mint_r38.py for the fifth filing. Snapshot (input/<tag>/):
  package/          the r38f candidate package as frozen (claim, proof, manifests, r38joint.py, q3data.py)
  docs/             window declarations (DECLARE_WINDOWS.md, DECLARE_LONG_2026-10-25.md), the registered deep-rate plan
                    (Q3_PLAN.md, verbatim: its registration hash covers these bytes), the critic review, the result note,
                    the organizer Docker report on the shipped bytes
  runs/             the 24 + 48 holdout windows, the 72 development windows, the 144 F7G-LONG windows, the replay of
                    window 0 of each long seed base, the statistics files
  q3/               the deep-rate measurement: 720 per-seed JSONs of run O (u1, u0) with their run logs, the two regression
                    gates (reg = the FAILED first gate, regB = the Amendment-B gate), mirror results, leader reference data
  tools/            q3walk.c and q3_status.py verbatim (their registered hashes verify); scripts with local paths are
                    path-neutralized copies (tools/NEUTRALIZED.json lists the original sha256 and the substitutions)
  lever_evidence/   evidence files of the lever ledger (as mint_r38.py)
SHA256SUMS.txt over all. usage: python mint_r38f.py [tag]   (default r38f_v1)
"""
from __future__ import annotations
import hashlib, json, os, shutil, sys, re
PRIVATE = re.compile(r"(?i)([a-z]:[\/]users[\/]|/c/users|/mnt/c/|/home/|/root/|desktop-|\\wsl|@[a-z0-9.-]+\.(local|lan))")
from bundle import Bundle
HERE = os.path.dirname(os.path.abspath(__file__))
TAG = sys.argv[1] if len(sys.argv) > 1 else "r38f_v1"
IN = os.path.join(HERE, "input", TAG); OUT = os.path.join(HERE, "out", TAG)
WAVE = os.path.join(os.path.expanduser("~"), "pareto_wave", "sha256_r38", "WAVE")
SCR = "D:/r38_scratch"
ASSERTER = "unsigned:hashsmash_mage"
HOME = os.path.expanduser("~").replace(chr(92), "/")  # this machine's home, never written into the repo
WSL_HOME = "/mnt/" + HOME[0].lower() + HOME[2:]
SUBS = [(HOME + "/pareto_wave/sha256_r38/WAVE", "<WAVE>"), (WSL_HOME + "/pareto_wave/sha256_r38/WAVE", "<WAVE>"),
        (HOME + "/AppData/Local/Temp", "<TMP>"), ("D:/r38_scratch", "<SCRATCH>"), ("/mnt/d/r38_scratch", "<SCRATCH>")]
VERBATIM_TOOLS = ["q3walk.c", "q3_status.py"]
NEUTRAL_TOOLS = ["q3_run.sh", "q3_launch_O.sh", "f7g_long.sh", "q3mirror.py", "q3ref.py", "q3smc.py", "stat_bounds.py", "make_q3data.py", "fill_proof_f.py"]
def sha(b): return hashlib.sha256(b).hexdigest()

def cp(src, rel):
    dst = os.path.join(IN, rel); os.makedirs(os.path.dirname(dst), exist_ok=True); shutil.copy2(src, dst)

def snapshot():
    if os.path.exists(IN): shutil.rmtree(IN)
    root = os.path.join(WAVE, "pkg_f", "candidate")
    for d, _, fs in os.walk(root):
        if "__pycache__" in d: raise SystemExit("pycache present: " + d)
        for f in fs:
            src = os.path.join(d, f); cp(src, "package/" + os.path.relpath(src, root).replace(os.sep, "/"))
    for rel in ("DECLARE_WINDOWS.md", "DECLARE_LONG_2026-10-25.md", "Q3_PLAN.md", "CRITIC_r38f.md", "RESULT.md"):
        cp(os.path.join(WAVE, rel), "docs/" + rel)
    cp(os.path.join(WAVE, "pkg_f", "docker_report_wsl_sha256-r38.json"), "docs/docker_report_sha256-r38.json")
    for sub in ("runs/eval", "runs/gwin", "runs/eval_h", "runs/gwin_h", "runs/longcheck"):
        for f in sorted(os.listdir(os.path.join(WAVE, sub))):
            if f.endswith(".json"): cp(os.path.join(WAVE, sub, f), sub + "/" + f)
    for f in sorted(os.listdir(os.path.join(SCR, "f7g_long"))):
        if f.endswith(".json"): cp(os.path.join(SCR, "f7g_long", f), "runs/f7g_long/" + f)
    for f in ("stat_bounds.json",): cp(os.path.join(WAVE, "runs", f), "runs/" + f)
    for f in ("q3data_stats.json", "O_status_final.json", "regB_status_gateB.json", "dev_deadseeds.txt", "leader_R9.txt", "leader_level128.csv"):
        cp(os.path.join(WAVE, "runs", "q3", f), "q3/" + f)
    cp(os.path.join(SCR, "q3", "reg", "status_gate.json"), "q3/reg_status_gate.json")
    for f in sorted(os.listdir(os.path.join(WAVE, "runs", "q3", "mirror"))): cp(os.path.join(WAVE, "runs", "q3", "mirror", f), "q3/mirror/" + f)
    for sub in ("O/u1", "O/u0", "regB/ev0", "regB/ev1", "reg/ev0", "reg/ev1"):
        for f in sorted(os.listdir(os.path.join(SCR, "q3", sub))):
            if f.endswith(".json") or f == "run.log": cp(os.path.join(SCR, "q3", sub, f), "q3/" + sub + "/" + f)
    for f in ("launch.txt",): cp(os.path.join(SCR, "q3", "O", f), "q3/O/" + f)
    for f in VERBATIM_TOOLS:
        b = open(os.path.join(WAVE, "tools", f), "rb").read()
        if PRIVATE.search(b.decode("utf8", "replace")): raise SystemExit("verbatim tool has a local path: " + f)
        cp(os.path.join(WAVE, "tools", f), "tools/" + f)
    neut = {}
    for f in NEUTRAL_TOOLS:
        b = open(os.path.join(WAVE, "tools", f), "rb").read(); t = b.decode("utf8"); used = []
        for a, r in SUBS:
            if a in t: t = t.replace(a, r); used.append([a.split("/")[0] + "/...", r])
        dst = os.path.join(IN, "tools", f); os.makedirs(os.path.dirname(dst), exist_ok=True); open(dst, "w", encoding="utf8", newline="\n").write(t)
        neut[f] = {"original_sha256": sha(b), "retained_sha256": sha(t.encode()), "substitutions": [r for _, r in used]}
    open(os.path.join(IN, "tools", "NEUTRALIZED.json"), "w", newline="\n").write(json.dumps(neut, indent=1, sort_keys=True) + "\n")
    rows = [json.loads(l) for l in open(os.path.join(WAVE, "ledger", "levers.jsonl"), encoding="utf8") if l.strip()]
    out = []
    for row in rows:
        hashed = {}; unretained = []
        for p, h in row["evidence"].items():
            p = p.replace("\\", "/")
            src = os.path.join(WAVE, p)
            if not os.path.isfile(src): raise SystemExit("missing evidence: " + p)
            if PRIVATE.search(open(src, "rb").read().decode("utf8", "replace")):
                unretained.append(p); continue
            dst = os.path.join(IN, "lever_evidence", p); os.makedirs(os.path.dirname(dst), exist_ok=True); shutil.copy2(src, dst)
            hh = sha(open(dst, "rb").read())
            if hh != h: row.setdefault("evidence_rehashed", {})[p] = {"ledger": h, "now": hh}
            hashed[p] = hh
        row = dict(row); row["evidence"] = hashed
        if unretained: row["evidence_not_retained"] = unretained
        out.append(json.dumps(row, sort_keys=True))
    open(os.path.join(IN, "levers.jsonl"), "w", encoding="utf8", newline="\n").write("\n".join(out) + "\n")
    for d, _, fs in os.walk(IN):
        if "__pycache__" in d: raise SystemExit("pycache in snapshot")
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
    pk = []
    for r in [x for x in rels if x.startswith("package/")]:
        seq += 1; data = read(r)
        pk.append(B.record(seq, "package-file/1", {"name": r, "bytes": len(data), "sha256": sha(data)}, blobs[r], "pkg:" + r))
    B.ledger("r38f-package", "the r38f candidate package: claim, proof, manifests, the program and the deep-rate data program", pk); ledgers.append("r38f-package")
    for sub, name, desc in (("runs/eval_h", "r38-holdout-eval-windows", "the 24 pre-declared HOLDOUT evaluation windows (the claim's cost and yield data)"),
                            ("runs/gwin_h", "r38-holdout-gf7-windows", "the 48 pre-declared HOLDOUT G/F7 windows"),
                            ("runs/f7g_long", "r38-f7g-long-windows", "the 144 pre-declared F7G-LONG windows (pooled with the 72 holdout windows for the charged G and F7 bounds)"),
                            ("runs/eval", "r38-dev-eval-windows", "development: the 24 public-seed evaluation windows of run 5 (evidence only)"),
                            ("runs/gwin", "r38-dev-g-windows", "development: the 48 public-seed G windows of run 5 (evidence only)")):
        ks = []
        for r in [x for x in rels if x.startswith(sub + "/")]:
            for w in json.loads(read(r)):
                seq += 1
                ks.append(B.record(seq, "window-record/1", {k: w[k] for k in ("seed", "subset", "win", "ops", "distinct_claws", "distinct_groups", "claws", "cross", "notclaw", "hits", "matches", "c1", "c2", "g", "f7", "dist_c2", "dist_g", "dist_f7", "kernel_len", "kernel_nreg", "sec") if k in w}, blobs[r], f"window:{w['seed']}"))
        lk = B.ledger(name, desc, ks); B.check(name + "-count", lk, "rows/count/1", {"n": len(ks)})
        ledgers.append(name); checks.append(name + "-count")
    for sub, name, desc in (("q3/O/u1", "r38-q3-run-O-u1", "registered deep-rate run O, arm u1 (the walk's population): 360 seeds"),
                            ("q3/O/u0", "r38-q3-run-O-u0", "registered deep-rate run O, arm u0 (same seeds without the u condition): 360 seeds"),
                            ("q3/regB/ev0", "r38-q3-gateB-ev0", "Amendment-B regression gate (PASS), printed event, 64 seeds"),
                            ("q3/regB/ev1", "r38-q3-gateB-ev1", "Amendment-B regression gate (PASS), relaxed event, 64 seeds"),
                            ("q3/reg/ev0", "r38-q3-gate1-ev0", "first regression gate (FAILED on dead seeds; not overridden), printed event, 64 seeds"),
                            ("q3/reg/ev1", "r38-q3-gate1-ev1", "first regression gate (FAILED on dead seeds; not overridden), relaxed event, 64 seeds")):
        ks = []
        for r in [x for x in rels if x.startswith(sub + "/") and x.endswith(".json")]:
            j = json.loads(read(r)); seq += 1
            ks.append(B.record(seq, "q3-seed-record/1", {k: j[k] for k in ("seed", "subset", "ucond", "ev", "NP", "NPROP", "MT", "prefix_log2", "exact", "samples", "L", "Lr", "dead", "diag", "sec") if k in j}, blobs[r], f"q3:{sub}:{j['seed']}"))
        lk = B.ledger(name, desc, ks); B.check(name + "-count", lk, "rows/count/1", {"n": len(ks)})
        ledgers.append(name); checks.append(name + "-count")
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
    fks = []
    for r in rels:
        if r.startswith("package/"): continue
        seq += 1; data = read(r)
        fks.append(B.record(seq, "package-file/1", {"name": r, "bytes": len(data), "sha256": sha(data)}, blobs[r]))
    B.ledger(TAG + "-files", "declarations, the registered deep-rate plan, critic review, result, organizer Docker report, window and seed JSONs, tools, lever evidence", fks); ledgers.append(TAG + "-files")
    tok = json.load(open(os.path.join(WAVE, "pkg_f", "tokens.json")))
    root = B.root(ledgers + checks, {"snapshot_files": len(rels), "board": "mooselumph/hashsmash/sha256-r38-exploratory",
                                     "claim_time_log2": float(tok["TIME_CHARGED"]), "claim_memory_log2_bytes": float(tok["MEM_LOG2"]),
                                     "claim_score": float(tok["SCORE"]), "q3r_log2_charged": float(tok["Q3R"]), "leader": "newjordan 51613d1c 90.7352"})
    B.write(OUT, ["", f"Files in snapshot: {len(rels)}", f"Ledgers: {', '.join(ledgers)}", "",
                  "Counts and the lever tally are recomputed by verify_bundle.py from the bundle alone.",
                  "The package files re-hash to the FREEZE.md values of the lane."])
    print("root", root); print("merkle", B._mroot, "leaves", B._nleaves)

if __name__ == "__main__":
    main()
