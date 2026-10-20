"""mint_sig_r2_869.py [--gate] - kappa evidence for the sig.golf entry "R2h on PR 869" (C 7,042, score 37,393,020).

Two steps, one command:
  1. snapshot: copy every input into input/sig_r2_869/ (text as LF + redacted, binaries verbatim), write the lever
     ledger levers.jsonl (one row per lever: positive / neutral / negative, incl. failed trials and process misses,
     each with the sha256 of its evidence files) and SHA256SUMS.txt;
  2. mint: read ONLY that snapshot (SHA256SUMS checked, lever evidence hash-checked per row) into a bundle.

Without --gate (dry run) the gate files are absent and the bundle goes to out/sig_r2_869/dryrun/ (never cited).
With --gate the WSL gate outputs are the LAST inputs: ~/postgate_r2on869m.out, ~/sig.golf-dev/replay.log,
~/cfbuild.out and the tail of ~/sig.golf-dev/build.log; the postgate must PASS (CLONE==WORKTREE for
sig-golf-r2on869m, std axioms only, kernel accepts, "Your solution is okay!", EXIT=0, "ok": true) or nothing is
minted. Final bundle: out/sig_r2_869/final/. Then: python verify_bundle.py out/sig_r2_869/final

Reads the sig_mage worktree and research files read-only (git diff only); never edits them.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

import kappa as K
from bundle import Bundle, redact

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(HERE, "input", "sig_r2_869")
SIG = os.environ.get("SIG_MAGE", os.path.join(os.path.expanduser("~"), "sig_mage")).replace("\\", "/")
WT = SIG + "/sig-golf-r2on869m"
SM = SIG + "/sigmage"
RS = SM + "/research"
BASE_COMMIT = "5262b3ac"
LANE = "sig-golf/r2h-869"
ASSERTER = "unsigned:sig_mage"
TEXT_EXT = (".md", ".txt", ".json", ".jsonl", ".py", ".out", ".log", ".patch", ".sh")
STD_AXIOMS = ["Classical.choice", "Quot.sound", "propext"]
PROGRAMS = ("keygen", "sign", "expand", "verify")
REMAP = ["NOTE.md", "check.json", "emu.json", "cover.json", "relocate.txt", "diffstat.txt", "edits.txt",
         "emu_run.txt", "extract_base.json", "classify.txt", "emu.log", "cover.log"]

# -- lever table: id, status, class, name, result, evidence (paths under research/, "log:" = memory log excerpt,
#    "wsl:" = a WSL home file, "results/" = sigmage/results) -------------------------------------------------------
LOG = "log/memory_log_2026-10-13.md"
LEVERS = [
    ("R2h-869", "positive", "lever", "R2h top-leaf zero16 pad on PR 869 (this entry)",
     "C 7,044 -> 7,042, score 37,393,020 on main 5262b3ac; drop sd zero,512/520(tp) in all 128 layer-0 heads, pad "
     "modelled as witness (honest zero); 2,461 verify words changed, 29 jumps re-encoded; emulator 8 seeds + forced "
     "+ 128 cover all accept, delta -2, hashes/signatures/witnesses identical; check_submission ok",
     ["remap/869m/NOTE.md", "remap/869m/check.json", "remap/869m/emu.json", "remap/869m/cover.json",
      "remap/869m/relocate.txt", "board-2026-10-13/census869/CENSUS_869.md", "board-2026-10-12/r2_deps_869.json"]),
    ("R2h-853", "positive", "lever", "R2h on PR 853 (overtaken)",
     "C 7,171 (38,078,010); build green, postgate PASSED (comparator ok); overtaken: 854 merged first (C 7,106)",
     ["board-2026-10-12/wave3/r1/R2_ON_853.md", "results/postgate_r2on853.out",
      "board-2026-10-12/wave3/r1/emu_r2h853.json", "board-2026-10-12/wave3/r1/cover_r2h853.json"]),
    ("R2h-854", "positive", "lever", "R2h on PR 854 (overtaken)",
     "C 7,104 (37,722,240); build green, postgate PASSED; held for 7,103 by the keeper, then 856 merged at 7,104 (tie)",
     ["board-2026-10-12/wave3/on854/ON854.md", "results/postgate_r2on854.out",
      "board-2026-10-12/wave3/on854/emu_r2h854.json", "board-2026-10-12/wave3/on854/cover_r2h854.json"]),
    ("R2h-857", "positive", "lever", "R2h on PR 857 (gate passed, tied)",
     "C 7,096 (37,679,760); build green, postgate PASSED; 859 merged first at C 7,096, so the port would tie: not cast",
     ["board-2026-10-12/wave3/on857/R2_ON_857.md", "wsl:postgate_r2on857.out",
      "board-2026-10-12/wave3/on857/emu_r2h857.json", "board-2026-10-12/wave3/on857/cover_r2h857.json"]),
    ("L1-fts-header", "negative", "lever", "L1 FTS leaf-header pad: drop sd zero,712(s0)",
     "NO-GO: slot 704..720 is live (chain-0 hash answer when digit0>0, and the previous coordinate's top hand-off on "
     "869); only 22/72 executions are no-ops; not witness memory",
     ["board-2026-10-13/census869/CENSUS_869.md", "board-2026-10-13/L1_LEAN_PLAN.md"]),
    ("S-levers-869", "negative", "lever", "signature-byte (S) levers on 869",
     "none under 5 days; best -1 B (19 searched sibling bits + 5 nonce bits), ~110-140 h, medium-low: parked",
     ["board-2026-10-13/S_LEVER_869.md", "board-2026-10-13/s_lever_869_numbers.py"]),
    ("R1-fts-849", "negative", "failed-trial", "R1 uniform drop of sd zero,712(s0) on 849",
     "uniform drop image REJECTS all honest runs (store cancels chain-0 spill in 318 of 563 routines); "
     "d0=0-only variant accepts but certified bound unchanged: 0 C",
     ["board-2026-10-12/wave3/r1/R1_CANDIDATE.md", "board-2026-10-12/wave3/r1/EMU.md"]),
    ("R2-full-536", "negative", "failed-trial", "R2 full (-3): also drop sd zero,536(tp)",
     "census called 536 a no-op pad; it protects leafTweak vs rowTweak domain separation, so R2 ships as R2h (-2)",
     ["board-2026-10-12/wave3/r1/R2R3_CENSUS.md", "board-2026-10-12/wave3/r1/R2_CANDIDATE.md", LOG]),
    ("sharedTree-869", "neutral", "lever", "sharedTree on 869",
     "-1 C only (layer-2 producer floor 9->10; joint cap blocked by security, LN at min); 45-65 agent-h + 5-7 builds: parked",
     ["board-2026-10-13/SHAREDTREE_869.md", "board-2026-10-13/budget869.out", "board-2026-10-13/security869.out"]),
    ("L2-digest-pad", "neutral", "lever", "L2 digest pad: drop sd zero,16(a0)",
     "real no-op (-1) but the pad is a free 64-bit word in the digest domain: security-gated, parked (R3 on 849 same)",
     ["board-2026-10-13/census869/CENSUS_869.md", "board-2026-10-13/census869/noptest.json",
      "board-2026-10-12/wave3/r1/R2R3_CENSUS.md"]),
    ("archaeology-863-872", "neutral", "lever", "frontier archaeology PRs 863..872",
     "two lineages alternate on main; 867 replaced 866's tree, so crown 869 lacks 865's R2 pad: the lever re-opens",
     ["board-2026-10-13/ARCHAEOLOGY_863_872.md"]),
    ("miss-ports-overtaken", "negative", "process-miss", "ports overtaken by merges (856/859/863)",
     "856 built green then 857 merged; 859 (7,094) and 863 (7,072) built then stopped as the field moved",
     ["board-2026-10-12/wave3/on856/R2_ON_856.md", "remap/RESULTS_860_862.md", LOG]),
    ("miss-865-first", "negative", "process-miss", "865 landed the same lever first",
     "0xFredrik PR 865 = the R2 top-leaf zero16 pad on 863, merged on the other (soispoke) line before our port",
     ["board-2026-10-13/ARCHAEOLOGY_863_872.md", LOG]),
    ("miss-867-revert", "negative", "process-miss", "867 reverted the lever on main",
     "nconsigny 867 swapped main back to the S2 tree: 128+128 sd zero,512/520(tp) back in 868/869",
     ["board-2026-10-13/ARCHAEOLOGY_863_872.md", "board-2026-10-13/census869/CENSUS_869.md"]),
    ("miss-misread-crown", "negative", "process-miss", "misread: 'R2 is in the crown' (21:15Z)",
     "log said R2 was in crown 869 and closed the lane; census + archaeology showed otherwise; corrected 21:55Z, lane reopened",
     [LOG, "board-2026-10-13/ARCHAEOLOGY_863_872.md"]),
    ("miss-r2-build-glue", "negative", "failed-trial", "R2 on 849 builds 1-2 failed",
     "glued line in edits_r2.py (Extract/Layer + WotsExtractLayer) and CaseCNearFinal.good_short; fixed, build 3 green",
     [LOG]),
]


def wsl_cat(path: str) -> bytes:
    r = subprocess.run(["wsl", "-e", "bash", "-c", f"cat {path}"], capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"cannot read WSL {path}: {r.stderr.decode(errors='replace')}")
    return r.stdout


def norm(name: str, raw: bytes) -> bytes:
    if name.endswith(TEXT_EXT) or "." not in os.path.basename(name):
        t = raw.decode("utf-8").replace("\r\n", "\n")
        return redact(t).encode("utf-8")
    return raw


def put(rel: str, raw: bytes) -> str:
    data = norm(rel, raw)
    p = os.path.join(IN, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    return hashlib.sha256(data).hexdigest()


def rd_file(p: str) -> bytes:
    with open(p, "rb") as f:
        return f.read()


def ev_source(ev: str) -> tuple[str, bytes]:
    if ev == LOG:
        lines = [l for l in rd_file(SM + "/memory/log.md").decode("utf-8").replace("\r\n", "\n").split("\n")
                 if l.startswith("- 2026-10-13")]
        return "lever_evidence/" + ev, ("\n".join(lines) + "\n").encode("utf-8")
    if ev.startswith("wsl:"):
        return "lever_evidence/wsl/" + ev[4:], wsl_cat("~/" + ev[4:])
    if ev.startswith("results/"):
        return "lever_evidence/" + ev, rd_file(SM + "/" + ev)
    return "lever_evidence/research/" + ev, rd_file(RS + "/" + ev)


def postgate_cpu(raw: bytes) -> float:
    t = raw.decode("utf-8", "replace")
    s = 0.0
    for k in ("user", "sys"):
        m = re.search(rf"^{k}\s+(\d+)m([\d.]+)s", t, re.M)
        if m:
            s += int(m.group(1)) * 60 + float(m.group(2))
    return round(s, 2)


def snapshot(gate: bool) -> None:
    if os.path.isdir(IN):
        shutil.rmtree(IN)
    os.makedirs(IN)
    put("shipped/claim.json", rd_file(WT + "/submission/claim.json"))
    git = lambda *a: subprocess.run(["git", "-C", WT, *a], capture_output=True, check=True).stdout
    put("shipped/diff_" + BASE_COMMIT + ".patch", git("diff", BASE_COMMIT))
    put("shipped/diffstat_" + BASE_COMMIT + ".txt", git("diff", "--stat", BASE_COMMIT))
    put("shipped/base_commit.txt", git("rev-parse", BASE_COMMIT))
    for f in REMAP:
        put("shipped/remap/" + f, rd_file(RS + "/remap/869m/" + f))
    for side, d in (("base", "images_869m"), ("r2h", "images_869m_r2h")):
        for f in sorted(os.listdir(SM + "/" + d)):
            put(f"images/{side}/{f}", rd_file(f"{SM}/{d}/{f}"))
    gate_cpu = 0.0
    if gate:  # the last inputs
        pg = wsl_cat("~/postgate_r2on869m.out")
        put("gate/postgate_r2on869m.out", pg)
        put("gate/replay.log", wsl_cat("~/sig.golf-dev/replay.log"))
        put("gate/cfbuild.out", wsl_cat("~/cfbuild.out"))
        put("gate/build_tail.log", b"\n".join(wsl_cat("~/sig.golf-dev/build.log").split(b"\n")[-200:]))
        gate_cpu = postgate_cpu(pg)
    rows = []
    for i, (lid, st, cls, name, result, evs) in enumerate(LEVERS, 1):
        ev, cpu = {}, 0.0
        for e in evs:
            rel, raw = ev_source(e)
            ev[rel[len("lever_evidence/"):]] = put(rel, raw)
            if "postgate_" in e:
                cpu += postgate_cpu(raw)
        if lid == "R2h-869":
            cpu += gate_cpu
        rows.append({"seq": i, "lever": lid, "status": st, "class": cls, "name": name, "result": result,
                     "cpu_s": cpu, "cpu_s_basis": "postgate user+sys" if cpu else "not measured",
                     "date": "2026-10-13", "track": "sig-golf/full", "evidence": ev})
    with open(os.path.join(IN, "levers.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
    sums = []
    for dp, _, fs in os.walk(IN):
        for f in fs:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, IN).replace("\\", "/")
            if rel != "SHA256SUMS.txt":
                sums.append(f"{hashlib.sha256(rd_file(p)).hexdigest()} *{rel}")
    with open(os.path.join(IN, "SHA256SUMS.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(sorted(sums, key=lambda s: s.split("*")[1])) + "\n")


# -- mint (reads only the snapshot) -------------------------------------------------------------------------------
def read(rel: str) -> bytes:
    return rd_file(os.path.join(IN, rel))


def check_sums() -> int:
    n = 0
    for line in read("SHA256SUMS.txt").decode().splitlines():
        h, rel = line.split(" *", 1)
        if hashlib.sha256(read(rel)).hexdigest() != h:
            raise SystemExit("checksum mismatch: " + rel)
        n += 1
    return n


def parse_postgate(raw: bytes, run: str) -> dict:
    t = raw.decode("utf-8", "replace")
    m = re.search(r"^CLONE==WORKTREE \(([^)]+)\)", t, re.M)
    ax = re.search(r"'SigGolf\.Challenge\.certificate' depends on axioms: \[([^\]]*)\]", t)
    jobs = re.search(r"Build completed successfully \((\d+) jobs\)", t)
    ex = re.search(r"^EXIT=(\d+)", t, re.M)
    return {"run": run, "clone_eq_worktree": bool(m), "tree": m.group(1) if m else "",
            "axioms": sorted(a.strip() for a in ax.group(1).split(",")) if ax else [],
            "build_jobs": int(jobs.group(1)) if jobs else -1,
            "kernel_accepts": "Lean default kernel accepts the solution" in t,
            "okay": "Your solution is okay!" in t, "exit": int(ex.group(1)) if ex else -1,
            "ok_true": '"ok": true' in t, "cpu_s": postgate_cpu(raw)}


def gate_passed(f: dict) -> bool:
    return (f["clone_eq_worktree"] and f["axioms"] == STD_AXIOMS and f["kernel_accepts"] and f["okay"]
            and f["exit"] == 0 and f["ok_true"])


def mint(gate: bool) -> None:
    n = check_sums()
    out = os.path.join(HERE, "out", "sig_r2_869", "final" if gate else "dryrun")
    B = Bundle(LANE, ASSERTER)
    blob = {}
    for line in read("SHA256SUMS.txt").decode().splitlines():
        rel = line.split(" *", 1)[1]
        if rel.startswith(("shipped/", "images/", "gate/")) or rel == "levers.jsonl":
            blob[rel] = B.put_blob(read(rel), "file:" + rel)
    composed = []

    # shipped result: claim + check_submission (score recomputed), emulator rows, cover rows, images
    claim = json.loads(read("shipped/claim.json"))
    chk = json.loads(read("shipped/remap/check.json"))
    ks = [B.record(1, "claim", claim, blob["shipped/claim.json"]),
          B.record(2, "check-submission", chk, blob["shipped/remap/check.json"])]
    lk = B.ledger("r2h869-claim", "the shipped claim.json and check_submission result for R2h on 869", ks)
    B.check("r2h869-claim-score", lk, "sig-golf/claim-score/1",
            {"S": claim["S"], "W": claim["W"], "C": claim["C"], "score": claim["S"] * claim["C"],
             "check_ok": chk["ok"], "check_score": chk["score"], "check_C": chk["claim"]["C"]})
    composed += ["r2h869-claim", "r2h869-claim-score"]
    for nm, rel in (("emu", "shipped/remap/emu.json"), ("cover", "shipped/remap/cover.json")):
        rows = json.loads(read(rel))["rows"]
        rks = [B.record(i, nm, r, blob[rel]) for i, r in enumerate(rows)]
        lk = B.ledger(f"r2h869-{nm}", f"the {len(rks)} {nm} runs, images_869m vs images_869m_r2h", rks)
        B.check(f"r2h869-{nm}-check", lk, "sig-golf/remap-emu/1", emu_facts(rows))
        composed += [f"r2h869-{nm}", f"r2h869-{nm}-check"]
    img = {}
    for side, s2 in (("base", "base"), ("h2", "r2h")):
        for prog in PROGRAMS:
            for ext in ("code", "data"):
                img[(side, prog, ext)] = blob[f"images/{s2}/{prog}.{ext}"]
    for prog in PROGRAMS:
        for ext in ("code", "data"):
            B.edge(img[("h2", prog, ext)], img[("base", prog, ext)], "derived-from")
        B.edge(img[("h2", prog, "code")], blob["shipped/remap/relocate.txt"], "derived-from")
    B.put({0: "agentprivacy-evidence/images/1", 1: LANE,
           2: {side: {prog: {"code": img[(side, prog, "code")], "data": img[(side, prog, "data")]} for prog in PROGRAMS}
               for side in ("base", "h2")},
           3: {"base": blob["images/base/layout.json"], "h2": blob["images/r2h/layout.json"]},
           4: {"patch": blob["shipped/remap/relocate.txt"], "extract_base": blob["shipped/remap/extract_base.json"],
               "diff": blob[f"shipped/diff_{BASE_COMMIT}.patch"]}}, "r2h869-images")
    composed.append("r2h869-images")

    # the gate: prior R2h gates (853/854/857) always; this entry's gate only with --gate, and it must pass
    def gate_ledger(name, desc, items):
        rks = []
        for i, (run, rel, b) in enumerate(items):
            f = parse_postgate(read(rel), run)
            rks.append(B.record(i, "postgate", f, b))
        lk = B.ledger(name, desc, rks)
        rows = [B.objects[k][3] for k in rks]
        B.check(name + "-check", lk, "sig-golf/postgate/1", postgate_facts(rows))
        composed.extend([name, name + "-check"])
        return rows
    prior = []
    for run, ev in (("r2on853", "results/postgate_r2on853.out"), ("r2on854", "results/postgate_r2on854.out"),
                    ("r2on857", "wsl/postgate_r2on857.out")):
        rel = "lever_evidence/" + ev
        prior.append((run, rel, B.put_blob(read(rel), "evidence:" + ev)))
    gate_ledger("prior-r2h-postgates", "the passed postgates of the earlier R2h ports the board overtook", prior)
    if gate:
        rows = gate_ledger("r2h869-postgate", "this entry's postgate (clone==worktree, axioms, comparator)",
                           [("r2on869m", "gate/postgate_r2on869m.out", blob["gate/postgate_r2on869m.out"])])
        if not (gate_passed(rows[0]) and rows[0]["tree"] == "sig-golf-r2on869m"):
            raise SystemExit("GATE NOT PASSED for sig-golf-r2on869m: nothing minted. " + json.dumps(rows[0]))
        for g in ("replay.log", "cfbuild.out", "build_tail.log"):
            B.edge(blob[f"gate/{g}"], blob["gate/postgate_r2on869m.out"], "refers-to")

    # lever ledger: one row per lever, refers-to each evidence blob (hash-checked against the row)
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
    llk = B.ledger("r2h869-lever-ledger", f"the {len(lks)} levers behind R2h on 869: shipped, overtaken, no-go, "
                   "parked, failed trials and process misses", lks)
    st = [r["status"] for r in rows]
    B.check("r2h869-lever-tally", llk, "hashsmash/lever-tally/1",
            {"n": len(rows), "statuses": sorted(set(st)), "by_status": {x: st.count(x) for x in sorted(set(st))},
             "cpu_s_total": round(sum(float(r["cpu_s"]) for r in rows), 2)})
    composed += ["r2h869-lever-ledger", "r2h869-lever-tally"]

    extra = {"entry": "R2h on PR 869", "board": "sig-golf/full", "base": read("shipped/base_commit.txt").decode().strip(),
             "S": claim["S"], "C": claim["C"], "score": claim["S"] * claim["C"], "snapshot_files": n,
             "gate": "passed" if gate else "absent (dry run, not citable)", "credit": "R2 lever also landed as PR 865 (0xFredrik)"}
    root = B.root(composed, extra)
    B.write(out, ["", f"Snapshot files: {n} (SHA256SUMS checked)", f"Gate: {extra['gate']}",
                  f"Levers: {len(rows)} ({', '.join(f'{x} {st.count(x)}' for x in sorted(set(st)))})", "",
                  f"Verify from the bundle alone: `python verify_bundle.py out/sig_r2_869/{'final' if gate else 'dryrun'}`.",
                  "", "Note lines:", f"- Evidence root: `{root}`",
                  f"- BLAKE3 axis root: `{K.kappa_blake3_from_value(B.objects[root])}` (the same root object, blake3; it seals "
                  f"the {len(B.objects) + len(B.blobs) + len(B.edges) - 1 - len(composed)} dual labels)",
                  f"- Merkle root (SHA-256, {B._nleaves} leaves): `{B._mroot}`"])
    print("root", root)
    print("merkle", B._mroot, "leaves", B._nleaves)


def emu_facts(rows: list) -> dict:
    return {"n": len(rows),
            "accept_all": all(set(r["base_exits"]) == {0} and set(r["var_exits"]) == {0} for r in rows),
            "delta_set": sorted({r["delta"] for r in rows}),
            "sig_equal": sum(1 for r in rows if r["sig_equal"]), "wit_equal": sum(1 for r in rows if r["wit_equal"]),
            "hashseq_equal": sum(1 for r in rows if r["hashseq_equal"]),
            "instr_diff_set": sorted({json.dumps(r["instr_diff"], sort_keys=True) for r in rows})}


def postgate_facts(rows: list) -> dict:
    return {"n": len(rows), "passed": sum(1 for r in rows if gate_passed(r)), "trees": sorted(r["tree"] for r in rows),
            "axioms": sorted({a for r in rows for a in r["axioms"]})}


if __name__ == "__main__":
    g = "--gate" in sys.argv
    if "--mint-only" not in sys.argv:
        snapshot(g)
    mint(g)
