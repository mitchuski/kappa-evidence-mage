"""mint_pareto_wave.py - mint one hashsmash-pareto wave package (2026-10-19 re-entry wave).

Usage: python mint_pareto_wave.py <family> <R> [tag]
  family in sha256 | sha3 | blake3 | poseidon; reads ~/pareto_wave/<family>/WAVE/.
Snapshot: copies packages/r<R>/ (tree), check_r<R>.txt if present, ledger/levers.jsonl and every lever
evidence path into input/<tag>/ with SHA256SUMS.txt, then mints out/<tag>/ from the snapshot alone.
Records: package-file/1 per file, organizer-check/1, one lever leaf per levers.jsonl row
(positive / neutral / negative, refers-to edges to its evidence blobs) + hashsmash/lever-tally/1.
"""
from __future__ import annotations
import hashlib, json, os, shutil, sys
from bundle import Bundle
HERE = os.path.dirname(os.path.abspath(__file__))
BOARDS = {"sha256": "sha256", "sha3": "sha3-256", "blake3": "blake3", "poseidon": "poseidon"}
ASSERTER = "unsigned:hashsmash_mage"


def sha(b): return hashlib.sha256(b).hexdigest()


def snapshot(fam, R, IN):
    wave = os.path.join(os.path.expanduser("~"), "pareto_wave", fam, "WAVE")
    pkg = os.path.join(wave, "packages", f"r{R}")
    if not os.path.isdir(pkg): raise SystemExit("no package: " + pkg)
    if os.path.exists(IN): shutil.rmtree(IN)
    shutil.copytree(pkg, os.path.join(IN, "package"))
    for extra in (os.path.join(pkg, f"check_r{R}.txt"), os.path.join(wave, "packages", f"check_r{R}.txt"),
                  os.path.join(wave, f"check_r{R}.txt")):
        if os.path.isfile(extra):
            shutil.copy2(extra, os.path.join(IN, "organizer_check.txt")); break
    led = os.path.join(wave, "ledger", "levers.jsonl")
    if os.path.isfile(led):
        rows = [json.loads(l) for l in open(led, encoding="utf8") if l.strip()]
        out = []
        for i, row in enumerate(rows, 1):
            ev = row.get("evidence") or []
            paths = list(ev.keys()) if isinstance(ev, dict) else list(ev)
            hashed, unretained = {}, []
            for p in paths:
                cands = [p if os.path.isabs(p) else os.path.join(wave, p), os.path.join(wave, "ledger", p)]
                src = next((c for c in cands if os.path.exists(c)), None)
                if src is None:  # free text or deleted evidence: kept on the leaf, unhashed, and said so
                    unretained.append(p); continue
                files = [src] if os.path.isfile(src) else [os.path.join(d, f) for d, _, fs in os.walk(src) for f in sorted(fs)]
                for fsrc in files:
                    rel = os.path.relpath(fsrc, wave).replace(os.sep, "/")
                    dst = os.path.join(IN, "lever_evidence", rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True); shutil.copy2(fsrc, dst)
                    hashed[rel] = sha(open(dst, "rb").read())
            row = dict(row); row["evidence"] = hashed; row.setdefault("seq", i); row.setdefault("cpu_s", 0)
            if unretained:
                row["evidence_not_retained"] = unretained
                print(f"lever {row.get('lever')!r}: evidence not retained (recorded on the leaf): {unretained}")
            out.append(json.dumps(row, sort_keys=True))
        open(os.path.join(IN, "levers.jsonl"), "w", encoding="utf8", newline="\n").write("\n".join(out) + "\n")
    lines = []
    for d, _, fs in os.walk(IN):
        for f in sorted(fs):
            p = os.path.join(d, f); rel = os.path.relpath(p, IN).replace(os.sep, "/")
            if rel != "SHA256SUMS.txt": lines.append(f"{sha(open(p, 'rb').read())}  {rel}")
    open(os.path.join(IN, "SHA256SUMS.txt"), "w", newline="\n").write("\n".join(sorted(lines, key=lambda s: s[66:])) + "\n")


def main():
    fam, R = sys.argv[1], sys.argv[2]
    RN = int("".join(ch for ch in R if ch.isdigit()))
    TAG = sys.argv[3] if len(sys.argv) > 3 else f"pareto_{fam}_r{R}_w1"
    IN = os.path.join(HERE, "input", TAG); OUT = os.path.join(HERE, "out", TAG)
    snapshot(fam, R, IN)
    read = lambda rel: open(os.path.join(IN, rel), "rb").read()
    sums = [l.split(None, 1) for l in read("SHA256SUMS.txt").decode().splitlines() if l.strip()]
    for h, rel in sums:
        if sha(read(rel.strip())) != h: raise SystemExit("checksum mismatch: " + rel)
    B = Bundle(f"hashsmash-pareto/{BOARDS[fam]}/{TAG}", ASSERTER)
    blobs = {rel.strip(): B.put_blob(read(rel.strip()), "file:" + rel.strip()) for _, rel in sums}
    ledgers, checks, seq = [], [], 0
    fks = []
    for rel in sorted(r for r in blobs if r.startswith("package/")):
        seq += 1; data = read(rel)
        fks.append(B.record(seq, "package-file/1", {"name": rel[8:], "bytes": len(data), "sha256": sha(data)}, blobs[rel]))
    claim = json.loads(read("package/claim.json")) if "package/claim.json" in blobs else {}
    if "organizer_check.txt" in blobs:
        seq += 1
        txt = read("organizer_check.txt").decode("utf8", "replace")
        fks.append(B.record(seq, "organizer-check/1", {"family": fam, "rounds": RN, "bytes": len(txt),
            "tail": txt.strip().splitlines()[-1][:300] if txt.strip() else ""}, blobs["organizer_check.txt"]))
    B.ledger(f"r{R}-package", f"{BOARDS[fam]} r={RN}: the submitted editable tree and the organizer check", fks)
    ledgers.append(f"r{R}-package")
    if "levers.jsonl" in blobs:
        rows = [json.loads(l) for l in read("levers.jsonl").decode().splitlines() if l.strip()]
        ev_blobs, lks = {}, []
        for row in rows:
            for p, h in row["evidence"].items():
                key = "lever_evidence/" + p
                if sha(read(key)) != h: raise SystemExit("lever evidence hash mismatch: " + p)
                ev_blobs[p] = blobs[key]
            k = B.record(1000 + int(row["seq"]), row["status"], row, blobs["levers.jsonl"], f"lever:{row['lever']}")
            for p in row["evidence"]: B.edge(k, ev_blobs[p], "refers-to")
            lks.append(k)
        llk = B.ledger(f"{fam}-lever-ledger", f"the {len(lks)} {BOARDS[fam]} levers: adopted, measured and no-go paths", lks)
        st = [r["status"] for r in rows]
        B.check(f"{fam}-lever-tally", llk, "hashsmash/lever-tally/1",
                {"n": len(rows), "statuses": sorted(set(st)), "by_status": {x: st.count(x) for x in sorted(set(st))},
                 "cpu_s_total": round(sum(float(r["cpu_s"]) for r in rows), 2)})
        ledgers.append(f"{fam}-lever-ledger"); checks.append(f"{fam}-lever-tally")
    extra = {"board": f"mooselumph/hashsmash-pareto/{BOARDS[fam]}", "rounds": RN, "package": f"r{R}", "wave": "2026-10-19 re-entry",
             "snapshot_files": len(sums)}
    for k in ("time_log2", "memory_log2_bytes", "success_probability"):
        if k in claim: extra[k] = claim[k]
    root = B.root(ledgers + checks, extra)
    B.write(OUT, ["", f"Files in snapshot: {len(sums)}", f"Ledgers: {', '.join(ledgers)}", "",
                  "Lever leaves include no-go paths (status negative) with refers-to edges to their evidence."])
    print("root", root); print("merkle", B._mroot, "leaves", B._nleaves)


if __name__ == "__main__":
    main()
