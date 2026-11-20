"""mint_grimoire_v11.py - seal the draft universe grimoire v11 as one bundle, chained to the grimoire history seal.

Reads ONLY input/grimoire_v11/ (SHA256SUMS.txt checked): the generated grimoire, its authored part and its generator.
grimoire/1 for the grimoire (version, sha256, would-be CID, sections, status); grimoire-input/1 for the authored file
and the generator, each edged derived-from by the grimoire. source-ref/1 per source the grimoire names (path and
sha256 as the grimoire states them; provenance is the grimoire blob itself, so no source bytes enter the bundle).
The run root carries prev = the grimoire_v2 root (the 14 pins it succeeds). Ledgers with rows/count/1.
Sealed, not judged: what the grimoire says is checked by its build and the soul mage's census, not here.
"""
from __future__ import annotations
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))  # repository root
import hashlib, json, os, sys
from bundle import Bundle
from ipfs_cid import build as cid_build

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAG = "grimoire_v11"; IN = os.path.join(HERE, "input", TAG); OUT = os.path.join(HERE, "out", TAG)
PREV = json.load(open(os.path.join(HERE, "out", "grimoire_v2", "root.json"), encoding="utf-8"))["root_kappa"]
GRIM = "agentprivacy_universe_grimoire_v11.0.0.json"


def read(n): return open(os.path.join(IN, n), "rb").read()


def check_sums():
    for line in read("SHA256SUMS.txt").decode().splitlines():
        parts = line.split()
        if len(parts) >= 2 and hashlib.sha256(read(parts[-1].lstrip("*"))).hexdigest() != parts[0]:
            raise SystemExit("checksum mismatch: " + parts[-1])


def sources(g):
    seen = {}
    def walk(o):
        if isinstance(o, dict):
            if "source" in o and "source_sha256" in o: seen[o["source"]] = o["source_sha256"]
            if "file" in o and "source_sha256" in o: seen[o["file"]] = o["source_sha256"]
            for v in o.values(): walk(v)
        elif isinstance(o, list):
            for v in o: walk(v)
    walk(g); return dict(sorted(seen.items()))


def main():
    check_sums()
    data = read(GRIM); g = json.loads(data)
    B = Bundle("grimoire/" + TAG, "unsigned:privacy_mage")
    gb = B.put_blob(data, "blob:grimoire")
    gk = B.record(1, "grimoire/1", {"grimoire": g["grimoire"], "version": g["version"], "status": g["status"], "bytes": len(data),
                                    "sha256": hashlib.sha256(data).hexdigest(), "cid_if_pinned": cid_build(data, 262144, True),
                                    "succeeds_root": PREV, "sections": sorted(g.keys())}, gb, "grimoire:v11")
    ins = []
    for i, (n, role) in enumerate([("authored.json", "the authored part"), ("build_v11.py", "the generator")], start=2):
        b = read(n); bk = B.put_blob(b, "blob:" + n)
        k = B.record(i, "grimoire-input/1", {"file": n, "role": role, "bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()}, bk, "input:" + n)
        B.edge(gk, k, "derived-from"); ins.append(k)
    lk = B.ledger("grimoire-v11", "the draft grimoire and the two files it is generated from", [gk] + ins)
    B.check("grimoire-v11-count", lk, "rows/count/1", {"n": 1 + len(ins)})
    srcs = sources(g); ks = []
    for j, (path, sha) in enumerate(srcs.items(), start=10):
        k = B.record(j, "source-ref/1", {"path": path, "sha256": sha}, gb); B.edge(gk, k, "refers-to"); ks.append(k)
    sk = B.ledger("grimoire-v11-sources", f"the {len(ks)} source files the grimoire names, with the sha256 it states for each", ks)
    B.check("grimoire-v11-sources-count", sk, "rows/count/1", {"n": len(ks)})
    root = B.root(["grimoire-v11", "grimoire-v11-sources", "grimoire-v11-count", "grimoire-v11-sources-count"],
                  {"version": g["version"], "status": "draft", "sources": len(ks)}, prev=PREV)
    B.write(OUT, ["", f"Grimoire {g['version']} sealed as a DRAFT: {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()}.",
                  f"Would pin as {cid_build(data, 262144, True)} (UnixFS CIDv1, raw leaves). Not pinned: pinning is the First Person's act.",
                  f"prev = {PREV}, the grimoire_v2 seal of the 14 pins this grimoire succeeds.",
                  f"Sources named: {len(ks)} (path and sha256 as the grimoire states them; no source bytes are sealed).",
                  "Sealed, not judged. Counts are recomputed by verify_bundle.py from the bundle alone."])
    print("root", root); print("merkle", B._mroot, "leaves", B._nleaves, "sources", len(ks))


if __name__ == "__main__":
    main()
