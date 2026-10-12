"""verify_bundle.py - lane-neutral re-derivation of an evidence bundle from its root.

Usage: python verify_bundle.py out/<lane>

Trusts nothing but SHA-256. Checks: file names re-hash from content and objects are canonical
dCBOR; the root is a run-root/1; composed-of walk reaches every named ledger and check; every
ledger's rows exist and match its composed-of edges; every row carries evidence-provenance to a
blob in the bundle; summary/1 and check/1 facts are recomputed from the rows under the named
rule; images/1 blobs match the layout.json hashes they declare and byte-identical programs have
equal kappas; the provisional merkle root matches; leak scan. Exit 0 only if all pass.
"""
from __future__ import annotations

import json
import os
import re
import sys

import kappa as K

PRIVATE = re.compile(r"(?i)([a-z]:[\\/]users[\\/]|/c/users|/home/|/root/|desktop-|\\\\wsl|@[a-z0-9.-]+\.(local|lan))")


# -- rules: how a check/1 or summary/1 is recomputed from its ledger's rows -------------
def rule_r32_summary(rows):
    cpu = round(sum(float(c[7]) for c in rows), 2)
    return {2: len(rows), 3: cpu, 4: max(int(c[8]) for c in rows), 5: round(cpu / 3600, 2)}


def rule_h2_honest(rows):
    h = [r[3] for r in rows]
    return {"n": len(h), "ok": sum(1 for r in h if r["ok"]), "witness_equal": sum(1 for r in h if r["witness_equal"]),
            "compact_ok": sum(1 for r in h if r["compact_ok"]),
            "verify_delta_max": max(r["verify"] - r["base_verify"] for r in h),
            "sign_delta_cycles": sorted({r["sign"] - r["base_sign"] for r in h}),
            "sign_delta_compr": sorted({r["sign_compr"] - r["base_sign_compr"] for r in h}),
            "extra_compr_eq_c": all(r["extra_compr"] == r["c"] for r in h),
            "expand_max": max(r["expand"] for r in h), "verify_max": max(r["verify"] for r in h)}


def rule_all_ok(rows):
    rs = [r[3] for r in rows]
    return {"n": len(rs), "ok": sum(1 for r in rs if r["ok"]),
            "exits": sorted({str(r.get("exit", r.get("expand_exit"))) for r in rs})}


def rule_harness_tally(rows):
    st = [r[2] for r in rows]
    return {"n": len(st), "validated": sum(1 for s in st if s == "VALIDATED"), "statuses": sorted(set(st))}


def rule_hashsmash_gate_sum(rows):
    g = [r[3] for r in rows if r[2] == "gate-count/1"]
    assert len(g) == 1
    g = g[0]
    return {"total": g["per_step_gates"], "sum": g["xor"] + g["and"] + g["or"] + g["not"]}


def rule_hashsmash_experiments_completed(rows):
    ex = [r[3] for r in rows if r[2] == "experiment-result/1"]
    return {"n": len(ex), "completed": sum(1 for e in ex if e["status"] == "completed"),
            "successes": [e["successes"] for e in ex]}


def rule_lever_tally(rows):
    rs = [r[3] for r in rows]
    st = [r["status"] for r in rs]
    return {"n": len(rs), "statuses": sorted(set(st)), "by_status": {x: st.count(x) for x in sorted(set(st))},
            "cpu_s_total": round(sum(float(r["cpu_s"]) for r in rs), 2)}


def rule_orchard_ledger_sum(rows):
    import math
    g = [r[3] for r in rows if r[2] == "orchard-ledger/1"]
    assert len(g) == 1
    g = g[0]
    return {"total": g["total_ops"], "sum": sum(g["phases"].values()),
            "time_log2": round(math.log2(g["total_ops"] / g["C"]), 6),
            "score": round(math.log2(g["total_ops"] / g["C"]) + max(0, math.log2(g["memory_bytes"]) - 20), 6)}


RULES = {"hashsmash/orchard-ledger-sum/1": rule_orchard_ledger_sum, "hashsmash/lever-tally/1": rule_lever_tally, "hashsmash/gate-sum/1": rule_hashsmash_gate_sum, "hashsmash/experiments-completed/1": rule_hashsmash_experiments_completed,
         "sig-golf/h2-honest/1": rule_h2_honest, "sig-golf/all-ok/1": rule_all_ok, "harness/run-tally/1": rule_harness_tally, "rows/count/1": lambda rows: {"n": len(rows)}}


def main(bundle: str) -> int:
    bad = 0

    def fail(msg):
        nonlocal bad
        bad += 1
        print("FAIL", msg)

    objects, blobs, edges = {}, {}, {}
    for sub, store in (("objects", objects), ("edges", edges)):
        for fn in sorted(os.listdir(os.path.join(bundle, sub))):
            data = open(os.path.join(bundle, sub, fn), "rb").read()
            k = "sha256:" + fn[:-5]
            try:
                v = K.decode(data)
            except ValueError as e:
                fail(f"{sub}/{fn}: {e}"); continue
            if K.kappa_from_bytes(data) != k:
                fail(f"{sub}/{fn}: content does not hash to its name"); continue
            store[k] = v
    for fn in sorted(os.listdir(os.path.join(bundle, "blobs"))):
        data = open(os.path.join(bundle, "blobs", fn), "rb").read()
        k = "sha256:" + fn[:-4]
        if K.kappa_from_bytes(data) != k:
            fail(f"blobs/{fn}: content does not hash to its name"); continue
        blobs[k] = data
    print(f"re-hashed {len(objects)} objects, {len(blobs)} blobs, {len(edges)} edges")

    root_k = json.load(open(os.path.join(bundle, "root.json"), encoding="utf-8"))["root_kappa"]
    root = objects.get(root_k)
    if not root or not str(root.get(0, "")).endswith("/run-root/1"):
        fail("root kappa is not a run-root object in the bundle"); return 1
    print("root", root_k, "| status:", root[5], "| minted", root[2], "| lane", root[1])
    names = {n: k for n, k in root[3]}
    with open(os.path.join(bundle, "root.json"), encoding="utf-8") as f:
        meta = json.load(f)
    if meta.get("signature"):
        print("root signature present by", meta["signature"].get("by_did"), "(ed25519 not checked here; see tools/kappa_evidence.mjs verify)")
    b3 = (root.get(8) or {}).get("blake3_axis") if isinstance(root.get(8), dict) else None
    if b3:
        nb = 0
        for sk, bk in b3.items():
            if sk in blobs:
                data = blobs[sk]
            elif sk in objects:
                data = K.encode(objects[sk])
            elif sk in edges:
                data = K.encode(edges[sk])
            else:
                fail(f"blake3 axis names {sk}, which is not in the bundle"); continue
            if not K.verify_kappa(bk, data):
                fail(f"blake3 axis label {bk} does not match the bytes of {sk}"); continue
            nb += 1
        print(f"blake3 axis: {nb}/{len(b3)} dual labels recomputed")
    if meta.get("root_blake3") and not K.verify_kappa(meta["root_blake3"], K.encode(root)):
        fail("root_blake3 does not match the root's dCBOR")
    out = {}
    for e in edges.values():
        out.setdefault((e[0], K.RELATION_NAME[e[2]]), []).append(e[1])

    reached, stack = set(), [root_k]
    while stack:
        k = stack.pop()
        if k in reached:
            continue
        reached.add(k)
        for t in out.get((k, "composed-of"), []):
            if t not in objects and t not in blobs:
                fail(f"composed-of target missing: {t}")
            stack.append(t)
    for n, k in names.items():
        if k not in objects and k not in blobs:
            fail(f"named object absent: {n}")
        v = objects.get(k)
        if v and str(v.get(0, "")).split("/")[-2] in ("ledger", "summary", "check") and k not in reached:
            fail(f"{n} not reachable from the root via composed-of")
    print(f"composed-of walk reached {len(reached)} objects")

    def kind(v):
        return str(v.get(0, "")).split("/")[-2] if isinstance(v, dict) else ""

    for k, v in objects.items():
        if kind(v) == "ledger":
            if set(v[2]) != set(out.get((k, "composed-of"), [])):
                fail(f"ledger {v[1]}: composed-of edges do not match its row list")
            for rk in v[2]:
                if rk not in objects:
                    fail(f"ledger {v[1]}: row {rk} missing"); continue
                prov = out.get((rk, "evidence-provenance"), [])
                if not prov or any(p not in blobs for p in prov):
                    fail(f"row {rk} of {v[1]} lacks an evidence-provenance blob in the bundle")
    for k, v in objects.items():
        kd = kind(v)
        if kd in ("summary", "check"):
            led = objects.get(v[1])
            if not led or kind(led) != "ledger":
                fail(f"{kd} {k}: its ledger is missing"); continue
            if v[1] not in out.get((k, "derived-from"), []):
                fail(f"{kd} {k}: no derived-from edge to its ledger")
            rows = [objects[r] for r in led[2] if r in objects]
            if kd == "summary":
                rec = rule_r32_summary(rows)
                stored = {2: v[2], 3: float(v[3]), 4: v[4], 5: float(v[5])}
                label = f"summary of {led[1]}"
            else:
                fn = RULES.get(v[2])
                if not fn:
                    fail(f"check {k}: unknown rule {v[2]}"); continue
                rec, stored, label = fn(rows), v[3], f"check {v[2]} of {led[1]}"
            if rec != stored:
                fail(f"{label}: recomputed {rec} != stored {stored}")
            else:
                print(f"recomputed {label}: {json.dumps(rec)}")
    for k, v in objects.items():
        if kind(v) == "harness-gap":
            prop = objects.get(v[1]); canon_k = prop[6] if prop else None
            if not prop or canon_k not in blobs:
                fail(f"gap {k}: its proposal's canon blob is missing"); continue
            if K.split_kappa(canon_k)[1] != v[4]:
                fail(f"gap {k}: hProposal {v[4][:12]} != canon blob kappa {K.split_kappa(canon_k)[1][:12]}")
            if v[1] not in out.get((k, "derived-from"), []):
                fail(f"gap {k}: no derived-from edge to its proposal")
    gaps = sum(1 for v in objects.values() if kind(v) == "harness-gap")
    if gaps:
        print(f"{gaps} gap seed(s) derive from their proposal canon's kappa")
    for k, v in objects.items():
        if kind(v) == "images":
            for side, progs in v[2].items():
                layout = json.loads(blobs[v[3][side]])["programs"]
                for prog, bk in progs.items():
                    code, data = blobs.get(bk["code"]), blobs.get(bk["data"])
                    if code is None or data is None:
                        fail(f"images {side}/{prog}: blob missing"); continue
                    if K.split_kappa(bk["code"])[1] != layout[prog]["sha256"] or \
                       K.split_kappa(bk["data"])[1] != layout[prog]["data_sha256"]:
                        fail(f"images {side}/{prog}: layout.json hashes disagree with the blobs")
            same = [p for p in v[2]["base"] if v[2]["base"][p] == v[2]["h2"][p]]
            print(f"images: layout hashes match the blobs; byte-identical base/h2 programs: {same}")

    root_edge_ks = {ek for ek, e in edges.items() if e[0] == root_k}
    leaves = sorted((set(objects) | set(blobs) | set(edges)) - {root_k} - root_edge_ks)
    mroot = K.merkle_root([x.encode() for x in leaves]).hex()
    if mroot != root[4]:
        fail(f"merkle root mismatch: {mroot} vs {root[4]}")
    else:
        print(f"merkle root over {len(leaves)} leaves matches")

    def texts(v):
        if isinstance(v, str):
            yield v
        elif isinstance(v, dict):
            for x in v.values():
                yield from texts(x)
        elif isinstance(v, list):
            for x in v:
                yield from texts(x)
    for k, v in list(objects.items()) + list(edges.items()):
        for s in texts(v):
            if PRIVATE.search(s):
                fail(f"private string in {k}: {s[:60]!r}")
    for k, b in blobs.items():
        if PRIVATE.search(b.decode("utf-8", "replace")):
            fail(f"private string in blob {k}")
    print("leak scan done")
    print("RESULT:", "OK" if bad == 0 else f"{bad} FAILURE(S)", "| status of every kappa:", root[5])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
