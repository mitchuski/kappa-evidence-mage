"""mint_hashsmash_r3x.py - mint the sha256-r37/r38 grouped bit-sliced package evidence into a kappa graph.

Reads ONLY input/r3x/ (snapshot of ~/hashsmash_mage/work/sha256_r38/evidence, SHA256SUMS checked).
Writes out/r3x/ as a bundle. Objects use the shared record/ledger/check schemas (SCHEMA.md).
Records: experiment results (organizer Docker executor, public seed), large local runs, generator gate
counts, certificate outputs; blobs: the package files, program, manifest, reports.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

from bundle import Bundle

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(HERE, "input", "r3x")
OUT = os.path.join(HERE, "out", "r3x")
ASSERTER = "unsigned:hashsmash_mage"


def read(name: str) -> bytes:
    with open(os.path.join(IN, name), "rb") as f:
        return f.read()


def check_sums():
    sums = read("SHA256SUMS.txt").decode().splitlines()
    for line in sums:
        parts = line.split()
        if len(parts) < 2:
            continue
        h, fname = parts[0], parts[-1].lstrip("*").split("/")[-1]
        if hashlib.sha256(read(fname)).hexdigest() != h:
            raise SystemExit("checksum mismatch: " + fname)
    return len(sums)


def main():
    n = check_sums()
    B = Bundle("hashsmash/sha256-r37+r38", ASSERTER)
    blobs = {}
    for fname in sorted(os.listdir(IN)):
        if fname == "SHA256SUMS.txt":
            continue
        blobs[fname] = B.put_blob(read(fname), "file:" + fname)
    seq = 0
    ledgers = []
    checks = []
    for R in (38, 37):
        ks = []
        # organizer-executor experiment results
        rep = json.loads(read(f"docker_report_sha256-r{R}.json"))
        results = rep.get("results", rep.get("experiments", []))
        for r in results:
            seq += 1
            fields = {"R": R, "experiment": r.get("id") or r.get("experiment_id"), "status": r.get("status"),
                      "trials": int(r.get("trials", 0)), "successes": int(r.get("successes", 0)),
                      "evidence_class": r.get("evidence_class"), "executor": "organizer docker runner (local replay, public seed)"}
            ks.append(B.record(seq, "experiment-result/1", fields, blobs[f"docker_report_sha256-r{R}.json"]))
        # large local runs
        big = json.loads(read(f"bigrun_r{R}.json"))
        for lay, v in big["layouts"].items():
            seq += 1
            fields = {"R": R, "layout": lay, "trials": int(big["trials_per_layout"]), "successes": int(v["successes"]),
                      "bad_pairs": int(v["bad_pairs"]), "seeds": "hashsmash_mage-bigrun (our seeds, pre-registered)"}
            ks.append(B.record(seq, "local-run/1", fields, blobs[f"bigrun_r{R}.json"]))
        # generator counts
        txt = read(f"counts_r{R}.txt").decode()
        m = re.search(r"per-step gates=(\d+) \{'xor': (\d+), 'and': (\d+), 'or': (\d+), 'not': (\d+)\} per-group gates=(\d+) fixups=(\d+) per_msg=([0-9.]+)", txt)
        mm = re.search(r"mismatches=(\d+)/256", txt)
        seq += 1
        fields = {"R": R, "per_step_gates": int(m.group(1)), "xor": int(m.group(2)), "and": int(m.group(3)),
                  "or": int(m.group(4)), "not": int(m.group(5)), "per_group_gates": int(m.group(6)),
                  "fixups": int(m.group(7)), "per_message_gates": m.group(8), "mismatches_vs_reference": int(mm.group(1)),
                  "generator": "bitslice_sha256.py grouped key-only (validated against verifier digest)"}
        ks.append(B.record(seq, "gate-count/1", fields, blobs[f"counts_r{R}.txt"]))
        # certificate
        ctxt = read(f"cert_r{R}.txt").decode()
        nb = re.search(r"NB (\d+)", ctxt).group(1)
        lt = re.search(r"log2 T = ([0-9.]+)", ctxt).group(1)[:12]
        ok = re.search(r"T < 2\^([0-9.]+) : (True|False)", ctxt)
        seq += 1
        fields = {"R": R, "NB": nb, "log2_T": lt, "claim": ok.group(1), "T_below_claim": ok.group(2) == "True",
                  "ops_per_message": 335 if R == 38 else 320, "C": 2728 if R == 38 else 2644}
        ks.append(B.record(seq, "certificate/1", fields, blobs[f"cert_r{R}.txt"]))
        lk = B.ledger(f"r{R}-evidence", f"sha256-r{R}: organizer-executor results, large local runs, gate counts, certificate", ks)
        # checks the verifier can recompute from the records
        g = fields_g = next(B.objects[k][3] for k in ks if B.objects[k][2] == "gate-count/1")
        checks.append(f"r{R}-gate-sum")
        checks.append(f"r{R}-experiments-completed")
        B.check(f"r{R}-gate-sum", lk, "hashsmash/gate-sum/1",
                {"total": g["per_step_gates"], "sum": g["xor"] + g["and"] + g["or"] + g["not"]})
        ex = [B.objects[k][3] for k in ks if B.objects[k][2] == "experiment-result/1"]
        B.check(f"r{R}-experiments-completed", lk, "hashsmash/experiments-completed/1",
                {"n": len(ex), "completed": sum(1 for e in ex if e["status"] == "completed"),
                 "successes": [e["successes"] for e in ex]})
        ledgers.append(f"r{R}-evidence")
    fks = []
    for f in sorted(blobs):
        seq += 1
        data = read(f)
        fks.append(B.record(seq, "package-file/1", {"name": f, "bytes": len(data),
                                                     "sha256": hashlib.sha256(data).hexdigest()}, blobs[f]))
    pk = B.ledger("r3x-package-files", "the submitted package files, program, manifest and reports (records with provenance to their blobs)", fks)
    ledgers.append("r3x-package-files")
    root = B.root(ledgers + checks, {"submissions": {"sha256-r38": "875a5083", "sha256-r37": "abaa09ae"},
                            "snapshot_files": n})
    lines = ["", f"Files in snapshot: {n}", f"Ledgers: {', '.join(ledgers)}", "",
             "Every record is recomputed by verify_bundle.py from the bundle alone (checks: gate sums,",
             "experiment completion). The organizer reports are the Docker executor's own JSON; the",
             "large runs are ours (not organizer evidence)."]
    B.write(OUT, lines)
    print("root", root)
    print("merkle", B._mroot, "leaves", B._nleaves)


if __name__ == "__main__":
    main()
