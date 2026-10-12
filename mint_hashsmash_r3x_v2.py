"""mint_hashsmash_r3x_v2.py - mint the v2 (physically scheduled) sha256-r37/r38 package evidence.

Reads ONLY input/r3x_v2/ (snapshot, SHA256SUMS checked). Writes out/r3x_v2/. Same schemas and lane rules as
mint_hashsmash_r3x.py; the gate-count record carries the witness ledger (w_* fields) with per_step_gates =
circuit operations and not = the AND-NOT pairs' operations so hashsmash/gate-sum/1 recomputes it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re

from bundle import Bundle

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(HERE, "input", "r3x_v2")
OUT = os.path.join(HERE, "out", "r3x_v2")
ASSERTER = "unsigned:hashsmash_mage"


def read(name: str) -> bytes:
    with open(os.path.join(IN, name), "rb") as f:
        return f.read()


def check_sums():
    n = 0
    for line in read("SHA256SUMS.txt").decode().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        h, fname = parts[0], parts[-1].lstrip("*").split("/")[-1]
        if hashlib.sha256(read(fname)).hexdigest() != h:
            raise SystemExit("checksum mismatch: " + fname)
        n += 1
    return n


def main():
    n = check_sums()
    B = Bundle("hashsmash/sha256-r37+r38/v2", ASSERTER)
    blobs = {}
    for fname in sorted(os.listdir(IN)):
        if fname == "SHA256SUMS.txt":
            continue
        blobs[fname] = B.put_blob(read(fname), "file:" + fname)
    seq = 0
    ledgers, checks = [], []
    wc = json.loads(read("witness_counts.json"))
    for R in (38, 37):
        ks = []
        rep = json.loads(read(f"docker_report_sha256-r{R}.json"))
        for r in rep.get("results", rep.get("experiments", [])):
            seq += 1
            ks.append(B.record(seq, "experiment-result/1", {
                "R": R, "experiment": r.get("id") or r.get("experiment_id"), "status": r.get("status"),
                "trials": int(r.get("trials", 0)), "successes": int(r.get("successes", 0)),
                "evidence_class": r.get("evidence_class"), "executor": "organizer docker runner (local replay, public seed)"},
                blobs[f"docker_report_sha256-r{R}.json"]))
        big = json.loads(read(f"bigrun_v2_r{R}.json"))
        for lay, v in big["layouts"].items():
            seq += 1
            ks.append(B.record(seq, "local-run/1", {"R": R, "layout": lay, "trials": int(big["trials_per_layout"]),
                                                      "successes": int(v["successes"]), "bad_pairs": int(v["bad_pairs"]),
                                                      "seeds": "hashsmash_mage-bigrun-v2 (our seeds, pre-registered)"},
                               blobs[f"bigrun_v2_r{R}.json"]))
        w = wc["r%d" % R]
        circuit = w["w_xor"] + w["w_and"] + w["w_or"] + 2 * w["w_andnot"]
        seq += 1
        ks.append(B.record(seq, "gate-count/1", {
            "R": R, "per_step_gates": circuit, "xor": w["w_xor"], "and": w["w_and"], "or": w["w_or"], "not": 2 * w["w_andnot"],
            "andnot_pairs": w["w_andnot"], "loads": w["w_loads"], "stores": w["w_stores"], "transpose": w["w_transpose"],
            "table": w["w_table"], "setup": w["w_setup"], "total_per_batch": w["w_total"], "messages_per_batch": 256,
            "generator": "grouped_search_phys.py counted witness (strict 64-register VM; 0 mismatches vs reference)"},
            blobs["witness_counts.json"]))
        ctxt = read(f"cert_r{R}.txt").decode()
        nb = re.search(r"NB (\d+)", ctxt).group(1)
        lt = re.search(r"log2 T = ([0-9.]+)", ctxt).group(1)[:12]
        ok = re.search(r"claim ([0-9.]+) exact check (True|False)", ctxt)
        seq += 1
        ks.append(B.record(seq, "certificate/1", {"R": R, "NB": nb, "log2_T": lt, "claim": ok.group(1),
                                                    "T_below_claim": ok.group(2) == "True",
                                                    "ops_per_batch": w["w_total"], "C": 2728 if R == 38 else 2644},
                           blobs[f"cert_r{R}.txt"]))
        lk = B.ledger(f"r{R}-evidence-v2", f"sha256-r{R} v2: organizer-executor results, large local runs, witness ledger, certificate", ks)
        g = next(B.objects[k][3] for k in ks if B.objects[k][2] == "gate-count/1")
        checks += [f"r{R}-gate-sum", f"r{R}-experiments-completed"]
        B.check(f"r{R}-gate-sum", lk, "hashsmash/gate-sum/1", {"total": g["per_step_gates"], "sum": g["xor"] + g["and"] + g["or"] + g["not"]})
        ex = [B.objects[k][3] for k in ks if B.objects[k][2] == "experiment-result/1"]
        B.check(f"r{R}-experiments-completed", lk, "hashsmash/experiments-completed/1",
                {"n": len(ex), "completed": sum(1 for e in ex if e["status"] == "completed"), "successes": [e["successes"] for e in ex]})
        ledgers.append(f"r{R}-evidence-v2")
    fks = []
    for f in sorted(blobs):
        seq += 1
        data = read(f)
        fks.append(B.record(seq, "package-file/1", {"name": f, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}, blobs[f]))
    B.ledger("r3x-v2-package-files", "the v2 package files, program, manifest, counts and reports (records with provenance to their blobs)", fks)
    ledgers.append("r3x-v2-package-files")
    root = B.root(ledgers + checks, {"revises": {"sha256-r38": "875a5083", "sha256-r37": "abaa09ae"},
                                     "previous_root": "sha256:d467e8f7c0d2df1b91c8c179eeab1909ba108df8f1f0787702c1880b8de7145d",
                                     "snapshot_files": n})
    B.write(OUT, ["", f"Files in snapshot: {n}", f"Ledgers: {', '.join(ledgers)}", "",
                  "Records are recomputed by verify_bundle.py from the bundle alone (gate sums, experiment tallies).",
                  "The organizer reports are the Docker executor's own JSON; the large runs are ours (not organizer evidence)."])
    print("root", root)
    print("merkle", B._mroot, "leaves", B._nleaves)


if __name__ == "__main__":
    main()
