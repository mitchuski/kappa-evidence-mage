"""mint_r32.py - mint the hashsmash sha256-r32 search ledger into a kappa graph (P0, offline).

Reads ONLY input/r32/ (read-only snapshot of the r32 seat's exported ledger rows and the v5
package files). Writes out/r32/ as a bundle: objects/, blobs/, edges/, root.json, graph.json,
REPORT.md. Every kappa is labelled "kappa-compatible (unverified)" until P1.

Object schemas (integer keys, PERMANENT; see SCHEMA.md):
  call/1     0 schema 1 seq 2 tag 3 result 4 wall_s 5 user_s 6 sys_s 7 cpu_s 8 maxrss_kb
             [9 threads] [10 cvc_bytes] [11 t_end] [12 note] 13 source_file 14 lane
  ledger/1   0 schema 1 name 2 [call kappas, in seq order] 3 lane 4 description
  summary/1  0 schema 1 ledger_kappa 2 n_calls 3 cpu_s_total(2dp) 4 peak_maxrss_kb 5 cpu_h(2dp)
  run-root/1 0 schema 1 lane 2 minted_on 3 [[name, kappa]...] 4 merkle_root_hex 5 status
             6 asserter 7 upstream
Edges are upstream Edge records (types.rs:377-394), asserter = a placeholder string until P4
gives the lane an anchor key.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
from datetime import date

import kappa as K

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(HERE, "input", "r32")
OUT = os.path.join(HERE, "out", "r32")
LANE = "hashsmash/sha256-r32"
ASSERTER = "unsigned:hashsmash_mage"  # P4: replace with anchor_from_key(...)
MINTED_ON = date.today().isoformat()
NS = "agentprivacy-evidence"

PRIVATE = re.compile(r"(?i)(c:\\|/c/users|/home/|/root/|mitch|desktop-|\\\\wsl|@[a-z0-9.-]+\.(local|lan))")


def redact(s: str) -> str:
    return PRIVATE.sub("[redacted]", s)


def load_rows():
    rows = []
    for fname in ("ledger.jsonl", "ledger_cal_manual.jsonl"):
        with open(os.path.join(IN, fname), "rb") as f:
            raw = f.read()
        for line in raw.decode("utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                r["_source"] = fname
                rows.append(r)
    return rows


def call_object(seq: int, r: dict) -> dict:
    o = {0: f"{NS}/call/1", 1: seq, 2: r["tag"], 3: r["result"], 4: float(r["wall_s"]),
         5: float(r["user_s"]), 6: float(r["sys_s"]), 7: float(r["cpu_s"]),
         8: int(r["maxrss_kb"]), 13: r["_source"], 14: LANE}
    if "threads" in r:
        o[9] = int(r["threads"])
    if "cvc_bytes" in r:
        o[10] = int(r["cvc_bytes"])
    if "t_end" in r:
        o[11] = str(r["t_end"])
    if "note" in r:
        o[12] = redact(str(r["note"]))
    return o


def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    for d in ("objects", "blobs", "edges"):
        os.makedirs(os.path.join(OUT, d))

    objects: dict[str, dict] = {}   # kappa -> value
    blobs: dict[str, bytes] = {}    # kappa -> raw bytes
    edges: list[dict] = []
    names: dict[str, str] = {}      # name -> kappa

    def put(v: dict) -> str:
        k = K.kappa_from_value(v)
        objects[k] = v
        return k

    def put_blob(b: bytes) -> str:
        k = K.kappa_from_bytes(b)
        blobs[k] = b
        return k

    def edge(src, tgt, rel, value_kappa=None, metadata=None):
        edges.append(K.edge_record(src, tgt, rel, ASSERTER, value_kappa, metadata))

    # 1. source files as blobs (evidence provenance of every call row)
    src_kappa = {}
    for fname in ("ledger.jsonl", "ledger_cal_manual.jsonl"):
        with open(os.path.join(IN, fname), "rb") as f:
            src_kappa[fname] = put_blob(f.read())
        names[f"source:{fname}"] = src_kappa[fname]

    # 2. call objects, in source order (exported rows first, then cal/manual rows)
    rows = load_rows()
    call_k = []
    for seq, r in enumerate(rows):
        k = put(call_object(seq, r))
        call_k.append((k, r))
        edge(k, src_kappa[r["_source"]], "evidence-provenance")

    # 3. ledgers: all rows; the 59-call charged search; the 2 start runs; the superseded row
    def ledger(name, desc, ks):
        v = {0: f"{NS}/ledger/1", 1: name, 2: ks, 3: LANE, 4: desc}
        k = put(v)
        names[name] = k
        for ck in ks:
            edge(k, ck, "composed-of")
        return k

    all_k = ledger("r32-all-rows", "every ledger row the r32 seat exported, in source order",
                   [k for k, _ in call_k])
    is_start = lambda r: r["tag"] in ("start", "start2")
    is_superseded = lambda r: r["tag"] == "s2_le160" and r["result"] == "ERROR"
    search_rows = [(k, r) for k, r in call_k if not is_start(r) and not is_superseded(r)]
    start_rows = [(k, r) for k, r in call_k if is_start(r)]
    sup_rows = [(k, r) for k, r in call_k if is_superseded(r)]
    search_k = ledger("r32-search-ledger",
                      "the charged route search: every solver call except the two starting-solution "
                      "runs and the zero-CPU ERROR row for s2_le160 that the ABANDONED row supersedes",
                      [k for k, _ in search_rows])
    start_k = ledger("r32-start-ledger", "the two starting-solution runs (start, start2), charged as D",
                     [k for k, _ in start_rows])
    edge(search_k, all_k, "section-of")
    edge(start_k, all_k, "section-of")
    for k, r in sup_rows:
        aband = [ak for ak, ar in call_k if ar["tag"] == "s2_le160" and ar["result"] == "ABANDONED"]
        for ak in aband:
            edge(ak, k, "refers-to", metadata=b"supersedes")

    # 4. summaries, derived from the ledgers (the verifier recomputes these)
    def summary(name, lk, rows_):
        cpu = round(sum(float(r["cpu_s"]) for _, r in rows_), 2)
        v = {0: f"{NS}/summary/1", 1: lk, 2: len(rows_), 3: cpu,
             4: max(int(r["maxrss_kb"]) for _, r in rows_), 5: round(cpu / 3600, 2)}
        k = put(v)
        names[name] = k
        edge(k, lk, "derived-from")
        return k, v

    search_sum_k, search_sum = summary("r32-search-summary", search_k, search_rows)
    start_sum_k, start_sum = summary("r32-start-summary", start_k, start_rows)

    # 5. the v5 package (claim + proof) as blobs, derived from the ledger and its summary
    pkg = {}
    for fname in ("package_v5_claim.json", "package_v5_proof.md"):
        with open(os.path.join(IN, fname), "rb") as f:
            pkg[fname] = put_blob(f.read())
        names[f"package:{fname}"] = pkg[fname]
        edge(pkg[fname], search_k, "derived-from")
        edge(pkg[fname], search_sum_k, "derived-from")
        edge(pkg[fname], start_sum_k, "derived-from")

    # 6. edges get kappas too; then the run root over everything
    edge_k = {K.kappa_from_value(e): e for e in edges}
    leaves = sorted(list(objects) + list(blobs) + list(edge_k))
    mroot = K.merkle_root([x.encode() for x in leaves]).hex()
    root_v = {0: f"{NS}/run-root/1", 1: LANE, 2: MINTED_ON,
              3: [[n, k] for n, k in sorted(names.items())], 4: mroot, 5: K.STATUS,
              6: ASSERTER, 7: K.UPSTREAM}
    root_k = K.kappa_from_value(root_v)
    objects[root_k] = root_v
    root_edges = [K.edge_record(root_k, names[n], "composed-of", ASSERTER)
                  for n in ("r32-all-rows", "r32-search-ledger", "r32-start-ledger",
                            "r32-search-summary", "r32-start-summary")]
    for e in root_edges:
        edge_k[K.kappa_from_value(e)] = e

    # 7. write the bundle
    for k, v in objects.items():
        with open(os.path.join(OUT, "objects", K.split_kappa(k)[1] + ".cbor"), "wb") as f:
            f.write(K.encode(v))
    for k, b in blobs.items():
        with open(os.path.join(OUT, "blobs", K.split_kappa(k)[1] + ".bin"), "wb") as f:
            f.write(b)
    for k, e in edge_k.items():
        with open(os.path.join(OUT, "edges", K.split_kappa(k)[1] + ".cbor"), "wb") as f:
            f.write(K.encode(e))
    root = {"root_kappa": root_k, "status": K.STATUS, "lane": LANE, "minted_on": MINTED_ON,
            "merkle_root_sha256": mroot, "merkle_leaves": len(leaves) + 0,
            "counts": {"objects": len(objects), "blobs": len(blobs), "edges": len(edge_k)},
            "names": names, "upstream": K.UPSTREAM}
    with open(os.path.join(OUT, "root.json"), "w", encoding="utf-8") as f:
        json.dump(root, f, indent=1)

    def jsonable(v):
        if isinstance(v, dict):
            return {str(k): jsonable(x) for k, x in v.items()}
        if isinstance(v, list):
            return [jsonable(x) for x in v]
        if isinstance(v, K.RustBytes):
            return list(v)
        if isinstance(v, bytes):
            return v.hex()
        return v

    graph = {"status": K.STATUS, "root": root_k,
             "objects": {k: jsonable(v) for k, v in objects.items()},
             "blobs": {k: len(b) for k, b in blobs.items()},
             "edges": [{"kappa": k, "source": e[0], "target": e[1],
                        "relation": K.RELATION_NAME[e[2]], "asserter": e[3],
                        **({"metadata": bytes(e[5]).decode()} if 5 in e else {})}
                       for k, e in edge_k.items()]}
    with open(os.path.join(OUT, "graph.json"), "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=1)

    # 8. report
    lines = [f"# r32 evidence graph - minted {MINTED_ON} - status: {K.STATUS}", "",
             f"Run root kappa: `{root_k}`", f"Merkle root (provisional, SHA-256, {len(leaves)} leaves): `{mroot}`", "",
             "| object | kappa |", "|---|---|"]
    for n, k in sorted(names.items()):
        lines.append(f"| {n} | `{k}` |")
    lines += ["", "| summary | calls | CPU-s | CPU-h | peak RSS (KiB) |", "|---|---|---|---|---|",
              f"| r32-search-summary | {search_sum[2]} | {search_sum[3]:,.2f} | {search_sum[5]} | {search_sum[4]:,} |",
              f"| r32-start-summary | {start_sum[2]} | {start_sum[3]:,.2f} | {start_sum[5]} | {start_sum[4]:,} |",
              "", f"Objects {len(objects)}, blobs {len(blobs)}, edges {len(edge_k)}. Asserter is the placeholder "
              f"`{ASSERTER}` (no anchor key at P0).", "",
              "Verify from the bundle alone: `python verify_r32.py out/r32`."]
    with open(os.path.join(OUT, "REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
