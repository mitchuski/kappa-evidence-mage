"""mint_sig_k5_876.py [--gate] - kappa evidence for the sig.golf entry "R4-k5 on PR 876" (C 7,040, score 37,382,400).

Sibling of mint_sig_r2k5_869.py (reuses its helpers and its 23 lever leaves, adds 4). Same two steps, one command:
snapshot into input/sig_k5_876/ (text LF + redacted), then mint from the snapshot only.
Dry run (no --gate) -> out/sig_k5_876/dryrun/ (not citable). With --gate the LAST input is WSL
~/postgate_k5on876.out (+ replay.log, cfbuild.out, build.log tail); it must PASS for sig-golf-k5on876 or nothing is
minted. Final -> out/sig_k5_876/final/. Then: python verify_bundle.py out/sig_k5_876/final

Base = PR 876 head bf335032 (newjordan 78c9b314-3bf6-4b4a-b702-1d5df9f85384, unmerged, C 7,041).
Images: base side = images_876, h2 side = images_k5on876_tree (w9_extract of the edited tree). The patch-script images
k5on876/images_876_k5 are byte-identical in all 8 program files; their layout.json is the same JSON (compact, not
indented), recorded as a finding. Emulator rows: k5_emu.json was never written (first run stopped at the tool limit
after 118 rows); the rows are the JSON lines of k5_emu.log (seed1..c5_105) + k5_emu_resume106.json (c5_106..127).
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
import mint_sig_r2k5_869 as R
from bundle import Bundle

HERE = M.HERE
IN = os.path.join(HERE, "input", "sig_k5_876")
M.IN = IN  # M.put / M.read write and read this snapshot
WT = M.SIG + "/sig-golf-k5on876"
SM, RS = M.SM, M.RS
D = "board-2026-10-13/k5on876"
BASE_COMMIT = "bf335032"
LANE = "sig-golf/k5-876"
TREE = "sig-golf-k5on876"
PROGRAMS = M.PROGRAMS
KEMU = ["NOTE.md", "edits_k5_876.py", "k5_emu.py", "k5_emu.log", "k5_emu_resume106.json", "k5_emu_resume106.log"]
K5PATCH = "board-2026-10-13/dispatch869/k5_patch.py"
LOG14 = "log/memory_log_2026-10-14.md"
PR = R.PR

NEW_LEVERS = [
    ("R4-k5-876", "positive", "lever", "R4-k5 on PR 876 (this entry)",
     "C 7,041 -> 7,040, score 37,382,400: the 869 K5 lever ported unchanged onto newjordan's 876 (dispatch region "
     "byte-identical to 869m; 44 words in 512..868); emulator 140/140 pairs -1, identical sigs/witnesses/hashes; "
     "round-trip 9/9; check_submission ok; lake build green first pass (9,793 jobs)",
     [f"{D}/NOTE.md", f"{D}/k5_emu.log", f"{D}/k5_emu_resume106.json", f"{D}/edits_k5_876.py", PR + "876.json", LOG14]),
    ("R2k5-869-submitted", "positive", "lever", "submitted 6c0b8876 (R2+K5 on 869)",
     "C 7,041 (37,387,710); gate passed (clone==worktree, std axioms, comparator ok); kappa root "
     "sha256:11b1413265eefa96e4109158388c096daf5c6ca1d7498a48af18bc7221828b4c",
     ["kappa:sig_r2k5_869/final/root.json", "wsl:postgate_r2k5on869.out", LOG14]),
    ("R2h-869-submitted-42765dec", "positive", "lever", "submitted 42765dec (R2 on 869)",
     "C 7,042 (37,393,020); gate passed; kappa root sha256:e4d38e44ba9ce9589a97d00969c405c2b35a04a1f95fd3c511db7659da6c38c3",
     ["kappa:sig_r2_869/final/root.json", LOG14]),
    ("miss-7041-dep-unpublished", "negative", "process-miss", "first 7,041 submit failed: dependency unpublished",
     "first submit of R2+K5 on 869 failed 'submission not found': dependency 42765dec (ours, still validating) was "
     "unpublished; resubmitted as 6c0b8876 without it (deps 869 + 865 only)",
     [LOG14]),
]


def ev_source(ev: str):
    if ev == LOG14:
        lines = [l for l in M.rd_file(SM + "/memory/log.md").decode("utf-8").replace("\r\n", "\n").split("\n")
                 if l.startswith("- 2026-10-14")]
        return "lever_evidence/" + ev, ("\n".join(lines) + "\n").encode("utf-8")
    return R.ev_source(ev)


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
        put("shipped/k5on876/" + f, M.rd_file(f"{RS}/{D}/{f}"))
    put("shipped/k5on876/k5_patch.py", M.rd_file(f"{RS}/{K5PATCH}"))
    for side, d in (("base", SM + "/images_876"), ("k5", SM + "/images_k5on876_tree"),
                    ("k5patch", f"{RS}/{D}/images_876_k5")):
        for f in sorted(os.listdir(d)):
            put(f"images/{side}/{f}", M.rd_file(f"{d}/{f}"))
    gate_cpu = 0.0
    if gate:
        pg = M.wsl_cat("~/postgate_k5on876.out")
        put("gate/postgate_k5on876.out", pg)
        put("gate/replay.log", M.wsl_cat("~/sig.golf-dev/replay.log"))
        put("gate/cfbuild.out", M.wsl_cat("~/cfbuild.out"))
        put("gate/build_tail.log", b"\n".join(M.wsl_cat("~/sig.golf-dev/build.log").split(b"\n")[-200:]))
        gate_cpu = M.postgate_cpu(pg)
    rows = []
    carried = M.LEVERS + R.NEW_LEVERS
    for i, (lid, st, cls, name, result, evs) in enumerate(carried + NEW_LEVERS, 1):
        ev, cpu = {}, 0.0
        for e in evs:
            rel, raw = ev_source(e)
            ev[rel[len("lever_evidence/"):]] = put(rel, raw)
            if "postgate_" in e:
                cpu += M.postgate_cpu(raw)
        if lid == "R4-k5-876":
            cpu += gate_cpu
        if lid == "R4-k5-869":  # as minted in the r2k5_869 final bundle: its own gate cpu
            cpu += M.postgate_cpu(M.wsl_cat("~/postgate_r2k5on869.out"))
        rows.append({"seq": i, "lever": lid, "status": st, "class": cls, "name": name, "result": result,
                     "cpu_s": round(cpu, 2), "cpu_s_basis": "postgate user+sys" if cpu else "not measured",
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


def emu_rows(read) -> list:
    rows = [json.loads(l) for l in read("shipped/k5on876/k5_emu.log").decode().splitlines() if l.startswith("{")]
    rows += json.loads(read("shipped/k5on876/k5_emu_resume106.json"))["rows"]
    tags = [r["tag"] for r in rows]
    assert len(tags) == len(set(tags)) == 140, f"emulator rows: {len(tags)} ({len(set(tags))} distinct)"
    return rows


def mint(gate: bool) -> None:
    n = M.check_sums()
    read = M.read
    out = os.path.join(HERE, "out", "sig_k5_876", "final" if gate else "dryrun")
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
    lk = B.ledger("k5on876-claim", "the shipped claim.json and check_submission result for R4-k5 on PR 876", ks)
    B.check("k5on876-claim-score", lk, "sig-golf/claim-score/1",
            {"S": claim["S"], "W": claim["W"], "C": claim["C"], "score": claim["S"] * claim["C"],
             "check_ok": chk["ok"], "check_score": chk["score"], "check_C": chk["claim"]["C"]})
    composed += ["k5on876-claim", "k5on876-claim-score"]

    rows = emu_rows(read)
    src = {"log": blob["shipped/k5on876/k5_emu.log"], "resume": blob["shipped/k5on876/k5_emu_resume106.json"]}
    rks = [B.record(i, "k5-emu", r, src["log"] if i < 118 else src["resume"]) for i, r in enumerate(rows)]
    lk = B.ledger("k5on876-emu", f"the {len(rks)} emulator pairs images_876 vs images_876_k5 "
                  "(k5_emu.log rows seed1..c5_105 + k5_emu_resume106.json rows c5_106..127)", rks)
    B.check("k5on876-emu-check", lk, "sig-golf/k5-emu/1", R.k5_facts(rows))
    composed += ["k5on876-emu", "k5on876-emu-check"]

    img = {}
    for side, s2 in (("base", "base"), ("h2", "k5")):
        for prog in PROGRAMS:
            for ext in ("code", "data"):
                img[(side, prog, ext)] = blob[f"images/{s2}/{prog}.{ext}"]
    for prog in PROGRAMS:
        for ext in ("code", "data"):
            B.edge(img[("h2", prog, ext)], img[("base", prog, ext)], "derived-from")
            assert blob[f"images/k5patch/{prog}.{ext}"] == img[("h2", prog, ext)], "patch image != tree image"
        B.edge(img[("h2", prog, "code")], blob["shipped/k5on876/k5_patch.py"], "derived-from")
    B.put({0: "agentprivacy-evidence/images/1", 1: LANE,
           2: {side: {prog: {"code": img[(side, prog, "code")], "data": img[(side, prog, "data")]} for prog in PROGRAMS}
               for side in ("base", "h2")},
           3: {"base": blob["images/base/layout.json"], "h2": blob["images/k5/layout.json"]},
           4: {"patch": blob["shipped/k5on876/k5_patch.py"], "edits": blob["shipped/k5on876/edits_k5_876.py"],
               "diff": blob[f"shipped/diff_{BASE_COMMIT}.patch"]}}, "k5on876-images")
    lp, lt = (json.loads(read(f"images/{s}/layout.json")) for s in ("k5patch", "k5"))
    assert lp == lt, "patch layout.json != tree layout.json"
    fk = B.put({0: "agentprivacy-evidence/record/1", 1: 3, 2: "finding", 3: {
        "finding": "patch-script images (k5on876/images_876_k5) equal the extracted tree images (images_k5on876_tree) "
                   "in all 8 program files; their layout.json parses to the same JSON (verify sha256 "
                   + lt["programs"]["verify"]["sha256"] + ") but is compact, not indented, so its bytes differ",
        "patch_images_equal_tree": True, "layout_json_equal": True}, 4: LANE}, "k5on876-finding-layout-format")
    B.edge(fk, blob["images/k5patch/layout.json"], "evidence-provenance")
    ek = B.put({0: "agentprivacy-evidence/record/1", 1: 3, 2: "finding", 3: {
        "finding": "NOTE.md names k5_emu.json, which was never written (first run stopped at the tool limit after 118 "
                   "rows); the emulator ledger reads the JSON lines of k5_emu.log plus k5_emu_resume106.json",
        "rows_from_log": 118, "rows_from_resume": len(rows) - 118}, 4: LANE}, "k5on876-finding-emu-json")
    B.edge(ek, blob["shipped/k5on876/NOTE.md"], "evidence-provenance")
    composed += ["k5on876-images", "k5on876-finding-layout-format", "k5on876-finding-emu-json"]

    def gate_ledger(name, desc, items):
        rks = [B.record(i, "postgate", M.parse_postgate(read(rel), run), b) for i, (run, rel, b) in enumerate(items)]
        lk = B.ledger(name, desc, rks)
        rows = [B.objects[k][3] for k in rks]
        B.check(name + "-check", lk, "sig-golf/postgate/1", M.postgate_facts(rows))
        composed.extend([name, name + "-check"])
        return rows
    prior = []
    for run, ev in (("r2on853", "results/postgate_r2on853.out"), ("r2on854", "results/postgate_r2on854.out"),
                    ("r2on857", "wsl/postgate_r2on857.out"), ("r2on869m", "wsl/postgate_r2on869m.out"),
                    ("r2k5on869", "wsl/postgate_r2k5on869.out")):
        rel = "lever_evidence/" + ev
        prior.append((run, rel, B.put_blob(read(rel), "evidence:" + ev)))
    gate_ledger("prior-postgates", "the passed postgates of the earlier ports, incl. the submitted R2h and R2+K5 on 869",
                prior)
    if gate:
        rows = gate_ledger("k5on876-postgate", "this entry's postgate (clone==worktree, axioms, comparator)",
                           [("k5on876", "gate/postgate_k5on876.out", blob["gate/postgate_k5on876.out"])])
        if not (M.gate_passed(rows[0]) and rows[0]["tree"] == TREE):
            raise SystemExit("GATE NOT PASSED for " + TREE + ": nothing minted. " + json.dumps(rows[0]))
        for g in ("replay.log", "cfbuild.out", "build_tail.log"):
            B.edge(blob[f"gate/{g}"], blob["gate/postgate_k5on876.out"], "refers-to")

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
    llk = B.ledger("k5on876-lever-ledger", f"the {len(lks)} levers behind R4-k5 on PR 876: shipped, submitted, "
                   "overtaken, no-go, parked, failed trials and process misses", lks)
    st = [r["status"] for r in rows]
    B.check("k5on876-lever-tally", llk, "hashsmash/lever-tally/1",
            {"n": len(rows), "statuses": sorted(set(st)), "by_status": {x: st.count(x) for x in sorted(set(st))},
             "cpu_s_total": round(sum(float(r["cpu_s"]) for r in rows), 2)})
    composed += ["k5on876-lever-ledger", "k5on876-lever-tally"]

    extra = {"entry": "R4-k5 on PR 876", "board": "sig-golf/full", "base": read("shipped/base_commit.txt").decode().strip(),
             "base_submission": "78c9b314-3bf6-4b4a-b702-1d5df9f85384 (newjordan, PR 876, unmerged, C 7,041)",
             "S": claim["S"], "C": claim["C"], "score": claim["S"] * claim["C"], "snapshot_files": n,
             "gate": "passed" if gate else "absent (dry run, not citable)",
             "builds_on": "sha256:11b1413265eefa96e4109158388c096daf5c6ca1d7498a48af18bc7221828b4c (R2+K5 on 869, 6c0b8876)",
             "credit": "base = newjordan PR 876 (872 + 869 retunes); R2 lever also PR 865 (0xFredrik) and PR 873 "
                       "(cryptogakusei)"}
    root = B.root(composed, extra)
    nl = len(B.objects) + len(B.blobs) + len(B.edges) - 1 - len(composed)
    B.write(out, ["", f"Snapshot files: {n} (SHA256SUMS checked)", f"Gate: {extra['gate']}",
                  f"Levers: {len(rows)} ({', '.join(f'{x} {st.count(x)}' for x in sorted(set(st)))})", "",
                  f"Verify from the bundle alone: `python verify_bundle.py out/sig_k5_876/{'final' if gate else 'dryrun'}`.",
                  "", "Note lines:", f"- Evidence root: `{root}`",
                  f"- BLAKE3 axis root: `{K.kappa_blake3_from_value(B.objects[root])}` (the same root object, blake3; it seals the {nl} dual labels)",
                  f"- Merkle root (SHA-256, {B._nleaves} leaves): `{B._mroot}`"])
    print("root", root)
    print("blake3", K.kappa_blake3_from_value(B.objects[root]))
    print("merkle", B._mroot, "leaves", B._nleaves)


if __name__ == "__main__":
    g = "--gate" in sys.argv
    if "--mint-only" not in sys.argv:
        snapshot(g)
    mint(g)
