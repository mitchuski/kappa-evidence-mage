"""mint_sig_r2k5_869.py [--gate] - kappa evidence for the sig.golf entry "R2h + R4-k5 on 869" (C 7,041, score 37,387,710).

Sibling of mint_sig_r2_869.py (reuses its helpers and its 16 lever leaves, adds 6). Same two steps, one command:
snapshot into input/sig_r2k5_869/ (text LF + redacted), then mint from the snapshot only.
Dry run (no --gate) -> out/sig_r2k5_869/dryrun/ (not citable). With --gate the LAST input is WSL
~/postgate_r2k5on869.out (+ replay.log, cfbuild.out, build.log tail); it must PASS for sig-golf-r2k5on869 or nothing is
minted. Final -> out/sig_r2k5_869/final/. Then: python verify_bundle.py out/sig_r2k5_869/final

Images: base side = images_869m_r2h (the submitted R2h entry), h2 side = images_r2k5_tree (w9_extract of the built tree).
The patch-script images dispatch869/images_r2h_k5 are byte-identical in all 8 program files; their layout.json still
declares the R2h verify sha256 (stale, F-E4 pattern), so it is recorded as a finding, not used as a layout.
Reads the sig_mage worktree read-only (git diff, check_submission.py); never edits it.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys

import kappa as K
import mint_sig_r2_869 as M
from bundle import Bundle

HERE = M.HERE
IN = os.path.join(HERE, "input", "sig_r2k5_869")
M.IN = IN  # M.put / M.read write and read this snapshot
WT = M.SIG + "/sig-golf-r2k5on869"
SM, RS = M.SM, M.RS
D = "board-2026-10-13/dispatch869"
BASE_COMMIT = M.BASE_COMMIT
LANE = "sig-golf/r2h-k5-869"
TREE = "sig-golf-r2k5on869"
PROGRAMS = M.PROGRAMS
KEMU = ["K5_NOTE.md", "k5_tree_vs_r2h.json", "k5_tree_vs_r2h.log", "k5_tree_vs_869m.json", "k5_tree_vs_869m.log",
        "k5_patch.py", "edits_k5_869.py"]
PR = "pr/"  # gh pr view snapshots (public metadata)

NEW_LEVERS = [
    ("R4-k5-869", "positive", "lever", "R4-k5 on the R2h tree of 869 (this entry)",
     "C 7,042 -> 7,041, score 37,387,710: coordinate 5 takes the pre-shifted child mask, dispatch 6/7 shift into "
     "zero words, fPrep ld s2 moves into block 8 (44 words); emulator 140/140 pairs -1 vs R2h and -3 vs 869m, "
     "identical sigs/witnesses/hashes; check_submission ok; lake build green first pass (9,787 jobs)",
     [f"{D}/K5_NOTE.md", f"{D}/k5_tree_vs_r2h.json", f"{D}/k5_tree_vs_869m.json", f"{D}/k5_patch.py", M.LOG]),
    ("R2h-869-submitted", "positive", "lever", "R2h on 869 submitted (42765dec, PR 875)",
     "C 7,042 (37,393,020); gate passed (clone==worktree, std axioms, comparator ok); kappa root "
     "sha256:e4d38e44ba9ce9589a97d00969c405c2b35a04a1f95fd3c511db7659da6c38c3",
     ["kappa:sig_r2_869/final/root.json", "wsl:postgate_r2on869m.out", PR + "875.json", M.LOG]),
    ("phaseB-slot-table", "neutral", "lever", "Phase B base-free slot table",
     "-4..-5 C estimated, low confidence, 8-10 agent-days: planned, not started",
     ["board-2026-10-13/MULTIDAY_PLAN.md"]),
    ("hotpath-869", "neutral", "lever", "HOTPATH_869 levers (base-reg merge -3, digest pad, Merkle stub)",
     "census of WOTS/Merkle/prefix instruction hot paths on 869: candidates priced, none taken into this entry",
     ["board-2026-10-13/HOTPATH_869.md"]),
    ("retune-869", "neutral", "lever", "signer/security retune on 869 and 872",
     "no retune below 7,044 on 869; 872 + retunes = 7,041 (the number to beat)",
     ["board-2026-10-13/RETUNE_869.md", "board-2026-10-13/retune869.out"]),
    ("miss-873-first", "negative", "process-miss", "PR 873 submitted the same R2-on-869 first",
     "cryptogakusei ef9f71ce (PR 873, 00:05:23Z) = R2 on 869 at C 7,042, 12 min before ours (42765dec, PR 875, 00:17:08Z)",
     [PR + "873.json", PR + "875.json"]),
    ("miss-876-first", "negative", "process-miss", "PR 876 claims the same C 7,041 first",
     "newjordan 78c9b314 (PR 876, 00:44:55Z) claims 37,387,710 = C 7,041, the same score as this entry, submitted before ours",
     [PR + "876.json"]),
]


def ev_source(ev: str):
    if ev.startswith("kappa:"):
        return "lever_evidence/kappa/" + ev[6:], M.rd_file(os.path.join(HERE, "out", ev[6:]))
    if ev.startswith(PR):
        n = ev[len(PR):-5]
        r = subprocess.run(["gh", "pr", "view", n, "--repo", "Layr-Labs/sig.golf", "--json",
                            "number,author,createdAt,headRefOid,title"], capture_output=True, check=True)
        return "lever_evidence/" + ev, (json.dumps(json.loads(r.stdout), sort_keys=True, indent=1) + "\n").encode()
    return M.ev_source(ev)


def snapshot(gate: bool) -> None:
    if os.path.isdir(IN):
        shutil.rmtree(IN)
    os.makedirs(IN)
    put = M.put
    put("shipped/claim.json", M.rd_file(WT + "/submission/claim.json"))
    git = lambda *a: subprocess.run(["git", "-C", WT, *a], capture_output=True, check=True).stdout
    put(f"shipped/diff_{BASE_COMMIT}.patch", git("diff", BASE_COMMIT))
    put(f"shipped/diffstat_{BASE_COMMIT}.txt", git("diff", "--stat", BASE_COMMIT))
    put("shipped/base_commit.txt", git("rev-parse", BASE_COMMIT))
    chk = subprocess.run([sys.executable, "-I", "verifier/check_submission.py", "submission"], cwd=WT,
                         capture_output=True, check=True).stdout
    put("shipped/check.json", chk)
    for f in KEMU:
        put("shipped/dispatch869/" + f, M.rd_file(f"{RS}/{D}/{f}"))
    for side, d in (("base", SM + "/images_869m_r2h"), ("k5", SM + "/images_r2k5_tree"),
                    ("k5patch", f"{RS}/{D}/images_r2h_k5")):
        for f in sorted(os.listdir(d)):
            put(f"images/{side}/{f}", M.rd_file(f"{d}/{f}"))
    gate_cpu = 0.0
    if gate:
        pg = M.wsl_cat("~/postgate_r2k5on869.out")
        put("gate/postgate_r2k5on869.out", pg)
        put("gate/replay.log", M.wsl_cat("~/sig.golf-dev/replay.log"))
        put("gate/cfbuild.out", M.wsl_cat("~/cfbuild.out"))
        put("gate/build_tail.log", b"\n".join(M.wsl_cat("~/sig.golf-dev/build.log").split(b"\n")[-200:]))
        gate_cpu = M.postgate_cpu(pg)
    rows = []
    for i, (lid, st, cls, name, result, evs) in enumerate(M.LEVERS + NEW_LEVERS, 1):
        ev, cpu = {}, 0.0
        for e in evs:
            rel, raw = ev_source(e)
            ev[rel[len("lever_evidence/"):]] = put(rel, raw)
            if "postgate_" in e:
                cpu += M.postgate_cpu(raw)
        if lid == "R4-k5-869":
            cpu += gate_cpu
        rows.append({"seq": i, "lever": lid, "status": st, "class": cls, "name": name, "result": result,
                     "cpu_s": cpu, "cpu_s_basis": "postgate user+sys" if cpu else "not measured",
                     "date": "2026-10-14" if i > len(M.LEVERS) else "2026-10-13", "track": "sig-golf/full",
                     "evidence": ev})
    with open(os.path.join(IN, "levers.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
    sums = []
    for dp, _, fs in os.walk(IN):
        for f in fs:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, IN).replace("\\", "/")
            if rel != "SHA256SUMS.txt":
                sums.append(f"{hashlib.sha256(M.rd_file(p)).hexdigest()} *{rel}")
    with open(os.path.join(IN, "SHA256SUMS.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(sorted(sums, key=lambda s: s.split("*")[1])) + "\n")


def k5_facts(rows: list) -> dict:
    return {"n": len(rows), "ok": sum(1 for r in rows if r["ok"]),
            "same_sig_wit": sum(1 for r in rows if r["same_sig_wit"]),
            "same_hashes": sum(1 for r in rows if r["same_hashes"]),
            "delta_set": sorted({r["delta"] for r in rows}), "exits_v": sorted({r["exits_v"] for r in rows})}


def mint(gate: bool) -> None:
    n = M.check_sums()
    read = M.read
    out = os.path.join(HERE, "out", "sig_r2k5_869", "final" if gate else "dryrun")
    B = Bundle(LANE, M.ASSERTER)
    blob = {}
    for line in read("SHA256SUMS.txt").decode().splitlines():
        rel = line.split(" *", 1)[1]
        if rel.startswith(("shipped/", "images/", "gate/")) or rel == "levers.jsonl":
            blob[rel] = B.put_blob(read(rel), "file:" + rel)
    composed = []

    claim = json.loads(read("shipped/claim.json"))
    chk = json.loads(read("shipped/check.json"))
    ks = [B.record(1, "claim", claim, blob["shipped/claim.json"]),
          B.record(2, "check-submission", chk, blob["shipped/check.json"])]
    lk = B.ledger("r2k5-claim", "the shipped claim.json and check_submission result for R2h + R4-k5 on 869", ks)
    B.check("r2k5-claim-score", lk, "sig-golf/claim-score/1",
            {"S": claim["S"], "W": claim["W"], "C": claim["C"], "score": claim["S"] * claim["C"],
             "check_ok": chk["ok"], "check_score": chk["score"], "check_C": chk["claim"]["C"]})
    composed += ["r2k5-claim", "r2k5-claim-score"]
    for nm in ("k5_tree_vs_r2h", "k5_tree_vs_869m"):
        rel = f"shipped/dispatch869/{nm}.json"
        rows = json.loads(read(rel))["rows"]
        rks = [B.record(i, "k5-emu", r, blob[rel]) for i, r in enumerate(rows)]
        lk = B.ledger(f"r2k5-{nm}", f"the {len(rks)} emulator pairs {nm.replace('_', ' ')}", rks)
        B.check(f"r2k5-{nm}-check", lk, "sig-golf/k5-emu/1", k5_facts(rows))
        composed += [f"r2k5-{nm}", f"r2k5-{nm}-check"]

    img = {}
    for side, s2 in (("base", "base"), ("h2", "k5")):
        for prog in PROGRAMS:
            for ext in ("code", "data"):
                img[(side, prog, ext)] = blob[f"images/{s2}/{prog}.{ext}"]
    for prog in PROGRAMS:
        for ext in ("code", "data"):
            B.edge(img[("h2", prog, ext)], img[("base", prog, ext)], "derived-from")
            assert blob[f"images/k5patch/{prog}.{ext}"] == img[("h2", prog, ext)], "patch image != tree image"
        B.edge(img[("h2", prog, "code")], blob["shipped/dispatch869/k5_patch.py"], "derived-from")
    B.put({0: "agentprivacy-evidence/images/1", 1: LANE,
           2: {side: {prog: {"code": img[(side, prog, "code")], "data": img[(side, prog, "data")]} for prog in PROGRAMS}
               for side in ("base", "h2")},
           3: {"base": blob["images/base/layout.json"], "h2": blob["images/k5/layout.json"]},
           4: {"patch": blob["shipped/dispatch869/k5_patch.py"], "edits": blob["shipped/dispatch869/edits_k5_869.py"],
               "diff": blob[f"shipped/diff_{BASE_COMMIT}.patch"]}}, "r2k5-images")
    stale = json.loads(read("images/k5patch/layout.json"))["programs"]["verify"]["sha256"]
    fk = B.put({0: "agentprivacy-evidence/record/1", 1: 3, 2: "finding", 3: {
        "finding": "patch-script images (dispatch869/images_r2h_k5) equal the extracted tree images in all 8 program "
                   "files; their layout.json declares verify sha256 " + stale + " (the R2h image), not the k5 image: "
                   "stale layout, not used", "patch_images_equal_tree": True}, 4: LANE}, "r2k5-finding-stale-layout")
    B.edge(fk, blob["images/k5patch/layout.json"], "evidence-provenance")
    composed += ["r2k5-images", "r2k5-finding-stale-layout"]

    def gate_ledger(name, desc, items):
        rks = [B.record(i, "postgate", M.parse_postgate(read(rel), run), b) for i, (run, rel, b) in enumerate(items)]
        lk = B.ledger(name, desc, rks)
        rows = [B.objects[k][3] for k in rks]
        B.check(name + "-check", lk, "sig-golf/postgate/1", M.postgate_facts(rows))
        composed.extend([name, name + "-check"])
        return rows
    prior = []
    for run, ev in (("r2on853", "results/postgate_r2on853.out"), ("r2on854", "results/postgate_r2on854.out"),
                    ("r2on857", "wsl/postgate_r2on857.out"), ("r2on869m", "wsl/postgate_r2on869m.out")):
        rel = "lever_evidence/" + ev
        prior.append((run, rel, B.put_blob(read(rel), "evidence:" + ev)))
    gate_ledger("prior-r2h-postgates", "the passed postgates of the earlier R2h ports, incl. the submitted R2h on 869", prior)
    if gate:
        rows = gate_ledger("r2k5-postgate", "this entry's postgate (clone==worktree, axioms, comparator)",
                           [("r2k5on869", "gate/postgate_r2k5on869.out", blob["gate/postgate_r2k5on869.out"])])
        if not (M.gate_passed(rows[0]) and rows[0]["tree"] == TREE):
            raise SystemExit("GATE NOT PASSED for " + TREE + ": nothing minted. " + json.dumps(rows[0]))
        for g in ("replay.log", "cfbuild.out", "build_tail.log"):
            B.edge(blob[f"gate/{g}"], blob["gate/postgate_r2k5on869.out"], "refers-to")

    rows = [json.loads(l) for l in read("levers.jsonl").decode().splitlines() if l.strip()]
    ev_blobs, lks = {}, []
    for row in rows:
        for p, h in row["evidence"].items():
            if p not in ev_blobs:
                raw = read("lever_evidence/" + p)
                if hashlib.sha256(raw).hexdigest() != h:
                    raise SystemExit("lever evidence hash mismatch: " + p)
                ev_blobs[p] = B.put_blob(raw, "evidence:" + p)
        k = B.record(1000 + row["seq"], row["status"], row, blob["levers.jsonl"], f"lever:{row['lever']}")
        for p in row["evidence"]:
            B.edge(k, ev_blobs[p], "refers-to")
        lks.append(k)
    llk = B.ledger("r2k5-lever-ledger", f"the {len(lks)} levers behind R2h + R4-k5 on 869: shipped, submitted, "
                   "overtaken, no-go, parked, failed trials and process misses", lks)
    st = [r["status"] for r in rows]
    B.check("r2k5-lever-tally", llk, "hashsmash/lever-tally/1",
            {"n": len(rows), "statuses": sorted(set(st)), "by_status": {x: st.count(x) for x in sorted(set(st))},
             "cpu_s_total": round(sum(float(r["cpu_s"]) for r in rows), 2)})
    composed += ["r2k5-lever-ledger", "r2k5-lever-tally"]

    extra = {"entry": "R2h + R4-k5 on PR 869", "board": "sig-golf/full", "base": read("shipped/base_commit.txt").decode().strip(),
             "S": claim["S"], "C": claim["C"], "score": claim["S"] * claim["C"], "snapshot_files": n,
             "gate": "passed" if gate else "absent (dry run, not citable)",
             "builds_on": "sha256:e4d38e44ba9ce9589a97d00969c405c2b35a04a1f95fd3c511db7659da6c38c3 (R2h on 869, 42765dec)",
             "credit": "R2 lever also landed as PR 865 (0xFredrik); R2 on 869 also PR 873 (cryptogakusei)"}
    root = B.root(composed, extra)
    nl = len(B.objects) + len(B.blobs) + len(B.edges) - 1 - len(composed)
    B.write(out, ["", f"Snapshot files: {n} (SHA256SUMS checked)", f"Gate: {extra['gate']}",
                  f"Levers: {len(rows)} ({', '.join(f'{x} {st.count(x)}' for x in sorted(set(st)))})", "",
                  f"Verify from the bundle alone: `python verify_bundle.py out/sig_r2k5_869/{'final' if gate else 'dryrun'}`.",
                  "", "Note lines:", f"- Evidence root: `{root}`",
                  f"- BLAKE3 axis root: `{K.kappa_blake3_from_value(B.objects[root])}` (the same root object, blake3; it seals the {nl} dual labels)",
                  f"- Merkle root (SHA-256, {B._nleaves} leaves): `{B._mroot}`"])
    print("root", root)
    print("merkle", B._mroot, "leaves", B._nleaves)


if __name__ == "__main__":
    g = "--gate" in sys.argv
    if "--mint-only" not in sys.argv:
        snapshot(g)
    mint(g)
