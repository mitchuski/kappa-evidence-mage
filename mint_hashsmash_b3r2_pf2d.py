"""mint_hashsmash_b3r2_pf2.py - mint the blake3-r2 Y9-prefilter entry's evidence (combined on 9638e58, claim 57.4702).

Reads ONLY input/b3r2_pf2/ (snapshot, SHA256SUMS.txt checked). Writes out/b3r2_pf2/. Same schemas and lane rules as the
r3x mints: organizer-executor results (hashsmash/experiments-completed/1, recomputed by verify_bundle.py), our measured run,
the exact Lemma PF enumeration, the package self-test, the organizer's deterministic check, the claim arithmetic, and every
package file as a record with provenance to its blob.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re

from bundle import Bundle

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(HERE, "input", "b3r2_pf2d")
OUT = os.path.join(HERE, "out", "b3r2_pf2d")
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
    B = Bundle("hashsmash/blake3-r2/prefilter", ASSERTER)
    blobs = {f: B.put_blob(read(f), "file:" + f) for f in sorted(os.listdir(IN)) if f != "SHA256SUMS.txt"}
    seq, ks = 0, []
    rep = json.loads(read("docker_report_blake3-r2.json"))
    for r in rep.get("results", rep.get("experiments", [])):
        seq += 1
        ks.append(B.record(seq, "experiment-result/1", {
            "track": "blake3-r2-exploratory", "experiment": r.get("id") or r.get("experiment_id"), "status": r.get("status"),
            "trials": int(r.get("trials", 0)), "successes": int(r.get("successes", 0)), "evidence_class": r.get("evidence_class"),
            "manifest_sha256": rep.get("manifest_sha256"), "executor": "organizer docker runner (local replay, public seed)"},
            blobs["docker_report_blake3-r2.json"]))
    m = json.loads(read("measure_pf.json"))
    seq += 1
    ks.append(B.record(seq, "local-run/1", {
        "what": "premise H_PF: share of walked list words the prefilter keeps", "contexts": m["contexts"], "words": m["words"],
        "kept_words": m["pf_words"], "skipped_words": m["skipped"], "e_lanes": m["e_lanes"], "share": f"{m['share']:.6f}",
        "batch_max": f"{m['batch_max']:.6f}", "budget_share": "1/8", "mismatches": m["mismatches"], "halted_contexts": m["halted_contexts"],
        "build": "b6a7681-based prefilter build (same walk, list words and prefilter decision; word charge differs)",
        "seeds": "fresh os.urandom per context"}, blobs["measure_pf.json"]))
    lem = read("lemma_pf_output.txt").decode()
    alive = int(re.search(r"surviving 10-bit prefixes: (\d+) of 1024", lem).group(1))
    seq += 1
    ks.append(B.record(seq, "lemma-result/1", {
        "lemma": "PF", "method": "exhaustive: all 1,024 low-10-bit prefixes through the test-(1) automaton, three theta",
        "surviving_prefixes": alive, "of": 1024, "projections": re.search(r"\[(.*?)\]", lem).group(1),
        "holds": "LEMMA PF HOLDS (exact)" in lem, "table_agrees": "agrees" in lem and lem.rstrip().endswith("True")},
        blobs["lemma_pf_output.txt"]))
    st = json.loads(read("selftest_2000.json"))
    seq += 1
    ks.append(B.record(seq, "selftest/1", {
        "program": "experiments/frontline.py --selftest 2000", "ok": bool(st["ok"]), "constants": bool(st["constants"]),
        "full_identities": bool(st["full_identities"]), "T1_T2_vs_bitserial": int(st["T1_T2_vs_bitserial"]),
        "halt_drills": {k: bool(v[0]) for k, v in st["halt_drills"].items()},
        "mismatches": sum(int(c["mismatches"]) for c in st["full_contexts"])}, blobs["selftest_2000.json"]))
    oc = read("organizer_check.txt").decode()
    seq += 1
    ks.append(B.record(seq, "organizer-check/1", {
        "check": "scripts/local_tracks.py check blake3-r2-exploratory (WSL-native clone, mirror verified byte for byte)",
        "status": re.search(r'"status": "([a-z_]+)"', oc).group(1), "submission_state": re.search(r'"submission_state": "([a-z]+)"', oc).group(1)},
        blobs["organizer_check.txt"]))
    src = read("frontline.py").decode()
    N = int(re.search(r"N=(\d+)\)", src).group(1))
    claim = json.loads(read("claim.json"))["claim"]["time_log2"]
    lt = math.log2(N / 430)
    seq += 1
    ks.append(B.record(seq, "certificate/1", {
        "N_machine_units": str(N), "units_per_compression": 430, "log2_T": f"{lt:.12f}", "claim": f"{claim}",
        "claim_is_log2_rounded_up_4dp": math.ceil(lt * 10 ** 4) / 10 ** 4 == claim, "base_entry": "9638e58 (0xshikhar, 57.6134)"},
        blobs["frontline.py"]))
    lk = B.ledger("b3r2-prefilter-evidence", "blake3-r2 Y9 prefilter: organizer-executor result, measured premise run, Lemma PF, "
                  "self-test, organizer check, claim arithmetic", ks)
    ex = [B.objects[k][3] for k in ks if B.objects[k][2] == "experiment-result/1"]
    B.check("b3r2-experiments-completed", lk, "hashsmash/experiments-completed/1",
            {"n": len(ex), "completed": sum(1 for e in ex if e["status"] == "completed"), "successes": [e["successes"] for e in ex]})
    fks = []
    for f in sorted(blobs):
        seq += 1
        data = read(f)
        fks.append(B.record(seq, "package-file/1", {"name": f, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}, blobs[f]))
    B.ledger("b3r2-prefilter-files", "the package files, the patch, the lemma and measurement programs and the gate outputs", fks)
    root = B.root(["b3r2-prefilter-evidence", "b3r2-prefilter-files", "b3r2-experiments-completed"],
                  {"track": "blake3-r2-exploratory", "claim": str(claim),
                   "builds_on": {"9638e58": "0xshikhar", "b6a7681": "Th0rgal", "4348a26": "Jbenisek", "070a02b": "promoted crown"},
                   "snapshot_files": n, "revises": "sha256:4332e53a401134db8f686ea02c74d231e8ab300ad331ee7a41d87e2fac3a2ecc", "revision": "fits the 512 KiB judge-evidence budget (submission fc11d939 failed intake at 524,996 bytes; now 519,899): wording trims only"})
    B.write(OUT, ["", f"Files in snapshot: {n}", "Ledgers: b3r2-prefilter-evidence, b3r2-prefilter-files", "",
                  "verify_bundle.py recomputes the experiment tally from the bundle alone.",
                  "The organizer report is the Docker executor's own JSON; the 200,000-context run is ours (not organizer evidence)."])
    print("root", root)
    print("merkle", B._mroot, "leaves", B._nleaves)


if __name__ == "__main__":
    main()
