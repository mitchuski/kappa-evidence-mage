"""mint_sig_h2_any.py BASE - mint the sig_mage H2 emulator-gate evidence for record BASE into a kappa graph
(generalised from mint_sig_h2.py, which is pinned to b96b3ca; the object shape is identical).

Reads ONLY input/sig_h2_<BASE>/ (read-only snapshot from the sig_mage lead, SHA256SUMS checked).
Writes out/sig_h2_<BASE>/. Object shape follows the snapshot README's suggestion:
  one record/1 per gate row (honest / exhaust / tamper / cross), provenance = the check json blob;
  four ledgers; a check/1 per ledger whose facts verify_bundle.py recomputes from the rows;
  the eight base and eight H2 program images as blobs, with the H2 sign/expand images
  derived-from their base image and the patch-report blob; layouts, kit manifest, chronicle as blobs.
"""
from __future__ import annotations

import json
import os
import sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "b96b3ca"

import kappa as K
from bundle import NS, Bundle, redact

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(HERE, "input", f"sig_h2_{BASE}")
OUT = os.path.join(HERE, "out", f"sig_h2_{BASE}")
LANE = f"sig-golf/h2-{BASE}"
PROGRAMS = ("keygen", "sign", "expand", "verify")


def rd(*p) -> bytes:
    with open(os.path.join(IN, *p), "rb") as f:
        return f.read()


def main():
    B = Bundle(LANE, "unsigned:sig_mage")

    # 1. blobs: gate result, patch report, images, layouts, kit manifest, chronicle
    check_b = B.put_blob(rd(f"h2_{BASE}_check.json"), f"source:h2_{BASE}_check.json")
    patch_b = B.put_blob(rd(f"h2_{BASE}_patch.json"), f"source:h2_{BASE}_patch.json")
    img = {}
    for side in ("base", "h2"):
        for prog in PROGRAMS:
            for ext in ("code", "data"):
                img[(side, prog, ext)] = B.put_blob(rd(f"images_{side}", f"{prog}.{ext}"), f"image:{side}:{prog}.{ext}")
        B.put_blob(rd(f"images_{side}", "layout.json"), f"layout:{side}")
    B.put_blob(rd("kit", "files.txt"), "kit:files.txt")
    B.put_blob(rd("kit", "KITBASE"), "kit:KITBASE")
    for fn in sorted(os.listdir(IN)):
        if fn.endswith(".md") and fn[:4] == "2026":
            B.put_blob(redact(rd(fn).decode("utf-8")).encode("utf-8"), f"chronicle:{fn[:10]}")

    # H2 images derive from the base image and the patch report (sign, expand patched;
    # keygen, verify byte-identical, which the verifier checks as equal kappas)
    for prog in PROGRAMS:
        for ext in ("code", "data"):
            B.edge(img[("h2", prog, ext)], img[("base", prog, ext)], "derived-from")
        B.edge(img[("h2", prog, "code")], patch_b, "derived-from")

    # 2. gate rows as records, four ledgers, one check each
    chk = json.loads(rd(f"h2_{BASE}_check.json"))
    seq = 0
    ledgers = {}
    for kind in ("honest", "exhaust", "tamper", "cross"):
        ks = []
        for row in chk[kind]:
            ks.append(B.record(seq, kind, row, check_b))
            seq += 1
        ledgers[kind] = B.ledger(f"h2-{kind}-ledger", f"the {len(ks)} {kind} rows of the H2 emulator gate", ks)
    h = chk["honest"]
    B.check("h2-honest-check", ledgers["honest"], "sig-golf/h2-honest/1", {
        "n": len(h), "ok": sum(1 for r in h if r["ok"]), "witness_equal": sum(1 for r in h if r["witness_equal"]),
        "compact_ok": sum(1 for r in h if r["compact_ok"]),
        "verify_delta_max": max(r["verify"] - r["base_verify"] for r in h),
        "sign_delta_cycles": sorted({r["sign"] - r["base_sign"] for r in h}),
        "sign_delta_compr": sorted({r["sign_compr"] - r["base_sign_compr"] for r in h}),
        "extra_compr_eq_c": all(r["extra_compr"] == r["c"] for r in h),
        "expand_max": max(r["expand"] for r in h), "verify_max": max(r["verify"] for r in h)})
    for kind in ("exhaust", "tamper", "cross"):
        rows = chk[kind]
        B.check(f"h2-{kind}-check", ledgers[kind], "sig-golf/all-ok/1",
                {"n": len(rows), "ok": sum(1 for r in rows if r["ok"]),
                 "exits": sorted({str(r.get("exit", r.get("expand_exit"))) for r in rows})})
    failures = {0: f"{NS}/record/1", 1: seq, 2: "failures", 3: {"failures": chk["failures"]}, 4: LANE}
    fk = B.put(failures, "h2-failures")
    B.edge(fk, check_b, "evidence-provenance")

    # 3. images object (declared layout hashes are checked against the blobs by the verifier)
    images = {0: f"{NS}/images/1", 1: LANE,
              2: {side: {prog: {"code": img[(side, prog, "code")], "data": img[(side, prog, "data")]}
                         for prog in PROGRAMS} for side in ("base", "h2")},
              3: {side: B.names[f"layout:{side}"] for side in ("base", "h2")},
              4: {"patch": patch_b, "kit_files": B.names["kit:files.txt"], "kit_base": B.names["kit:KITBASE"]}}
    B.put(images, "h2-images")

    root = B.root(["h2-honest-ledger", "h2-exhaust-ledger", "h2-tamper-ledger", "h2-cross-ledger",
                   "h2-honest-check", "h2-exhaust-check", "h2-tamper-check", "h2-cross-check",
                   "h2-failures", "h2-images"],
                  extra={"record": BASE, "kit_base": rd("kit", "KITBASE").decode().strip()})
    s = chk["summary"]
    B.write(OUT, ["| gate summary (from the seat's json) | value |", "|---|---|"] +
            [f"| {k} | {json.dumps(v)} |" for k, v in s.items()] +
            ["", f"Verify from the bundle alone: `python verify_bundle.py out/sig_h2_{BASE}`."])


if __name__ == "__main__":
    main()
