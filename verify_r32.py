"""verify_r32.py - re-derive an evidence bundle from its root, trusting nothing but SHA-256.

Usage: python verify_r32.py out/r32

Sees ONLY the bundle directory. Checks, in order:
  1. every objects/*.cbor, blobs/*.bin, edges/*.cbor re-hashes to its file name
     (objects/edges: canonical dCBOR re-encodes byte-identically, i.e. the file is canonical)
  2. root.json's root kappa names an object of schema run-root/1
  3. walking composed-of from the root reaches every named ledger, and every call kappa a
     ledger lists exists in the bundle
  4. every summary's totals equal the totals recomputed from the call objects it derives from
  5. the provisional merkle root over all kappas matches
  6. a leak scan over every text field (paths, hostnames, user names)
Prints the recomputed headline numbers. Exit 0 on success, 1 on any failure.
"""
from __future__ import annotations

import json
import os
import re
import sys

import kappa as K

PRIVATE = re.compile(r"(?i)([a-z]:[\\/]users[\\/]|/c/users|/home/|/root/|desktop-|\\\\wsl|@[a-z0-9.-]+\.(local|lan))")


def main(bundle: str) -> int:
    bad = 0

    def fail(msg):
        nonlocal bad
        bad += 1
        print("FAIL", msg)

    objects, blobs, edges = {}, {}, {}
    for sub, store, kind in (("objects", objects, "obj"), ("edges", edges, "edge")):
        for fn in sorted(os.listdir(os.path.join(bundle, sub))):
            with open(os.path.join(bundle, sub, fn), "rb") as f:
                data = f.read()
            k = "sha256:" + fn[:-5]
            try:
                v = K.decode(data)           # raises on non-canonical bytes
            except ValueError as e:
                fail(f"{sub}/{fn}: {e}"); continue
            if K.kappa_from_bytes(data) != k:
                fail(f"{sub}/{fn}: content does not hash to its name"); continue
            store[k] = v
    for fn in sorted(os.listdir(os.path.join(bundle, "blobs"))):
        with open(os.path.join(bundle, "blobs", fn), "rb") as f:
            data = f.read()
        k = "sha256:" + fn[:-4]
        if K.kappa_from_bytes(data) != k:
            fail(f"blobs/{fn}: content does not hash to its name"); continue
        blobs[k] = data
    print(f"re-hashed {len(objects)} objects, {len(blobs)} blobs, {len(edges)} edges")

    with open(os.path.join(bundle, "root.json"), encoding="utf-8") as f:
        root_meta = json.load(f)
    root_k = root_meta["root_kappa"]
    root = objects.get(root_k)
    if not root or not str(root.get(0, "")).endswith("/run-root/1"):
        fail("root kappa is not a run-root object in the bundle"); return 1
    print("root", root_k, "| status:", root[5], "| minted", root[2], "| lane", root[1])

    # typed-edge index
    out = {}
    for ek, e in edges.items():
        out.setdefault((e[0], K.RELATION_NAME[e[2]]), []).append(e[1])

    # walk composed-of from the root
    reached = set()
    stack = [root_k]
    while stack:
        k = stack.pop()
        if k in reached:
            continue
        reached.add(k)
        for t in out.get((k, "composed-of"), []):
            if t not in objects and t not in blobs:
                fail(f"composed-of target missing from bundle: {t}")
            stack.append(t)
    names = {n: k for n, k in root[3]}
    for n, k in names.items():
        if n.startswith(("r32-all", "r32-search-ledger", "r32-start-ledger", "r32-search-summary", "r32-start-summary")):
            if k not in reached:
                fail(f"named object not reachable from root via composed-of: {n}")
    for n, k in names.items():
        if (k not in objects) and (k not in blobs):
            fail(f"named object absent: {n} {k}")
    print(f"composed-of walk from root reached {len(reached)} objects")

    # ledgers and summaries
    headline = {}
    for k, v in objects.items():
        if str(v.get(0, "")).endswith("/summary/1"):
            lk = v[1]
            if lk not in out.get((k, "derived-from"), []):
                fail(f"summary {k} lacks a derived-from edge to its ledger")
            led = objects.get(lk)
            if not led or not str(led.get(0, "")).endswith("/ledger/1"):
                fail(f"summary {k}: ledger {lk} missing"); continue
            calls = [objects.get(ck) for ck in led[2]]
            if any(c is None for c in calls):
                fail(f"ledger {led[1]}: a listed call kappa is missing"); continue
            if set(led[2]) != set(out.get((lk, "composed-of"), [])):
                fail(f"ledger {led[1]}: composed-of edges do not match its call list")
            n = len(calls)
            cpu = round(sum(float(c[7]) for c in calls), 2)
            peak = max(int(c[8]) for c in calls)
            ok = (n == v[2]) and (cpu == float(v[3])) and (peak == v[4]) and (round(cpu / 3600, 2) == float(v[5]))
            if not ok:
                fail(f"summary for {led[1]}: recomputed ({n}, {cpu}, {peak}) != stored ({v[2]}, {v[3]}, {v[4]})")
            headline[led[1]] = (n, cpu, peak)
            # every call must carry provenance to a source blob that is in the bundle
            for ck in led[2]:
                prov = out.get((ck, "evidence-provenance"), [])
                if not prov or any(p not in blobs for p in prov):
                    fail(f"call {ck} has no evidence-provenance blob in the bundle")
    for name, (n, cpu, peak) in sorted(headline.items()):
        print(f"recomputed {name}: {n} calls, {cpu:,.2f} CPU-s ({cpu/3600:,.2f} CPU-h), peak RSS {peak:,} KiB")

    # merkle root over all kappas except the root object and its own edges (as minted)
    root_edge_ks = {ek for ek, e in edges.items() if e[0] == root_k}
    leaves = sorted((set(objects) | set(blobs) | set(edges)) - {root_k} - root_edge_ks)
    mroot = K.merkle_root([x.encode() for x in leaves]).hex()
    if mroot != root[4]:
        fail(f"merkle root mismatch: recomputed {mroot} vs root {root[4]}")
    else:
        print(f"merkle root over {len(leaves)} leaves matches")

    # leak scan
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
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "out", "r32")))
