"""mint_grimoire.py - mint the grimoire history as one bundle: what was PUBLISHED and what the site CARRIES.

Reads ONLY input/<tag>/ (SHA256SUMS.txt checked):
  pinned/<cid>.json  the grimoire versions pinned on IPFS (CIDs from agentprivacy_master src/lib/grimoire-ipfs.ts);
                     each CID is re-derived from the bytes here (UnixFS CIDv1, sha2-256, raw leaves) or the mint fails.
  site/<name>.json   the grimoire files bundled in agentprivacy_master src/data.
Writes out/<tag>/. grimoire-pin/1 per pin (line, version, cid, chunker, dates, sections); grimoire-file/1 per site
file. Version chain: each pin derived-from the previous pin in its line. A site file refers-to the pin with
identical bytes, where one exists. Ledgers per line and for the site copies; rows/count/1 on each.
Sealed, not judged: no claim inside a grimoire is checked here.
"""
from __future__ import annotations
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))  # repository root
import hashlib, json, os, sys
from bundle import Bundle
from ipfs_cid import build as cid_build
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAG = sys.argv[1] if len(sys.argv) > 1 else "grimoire_v2"
IN = os.path.join(HERE, "input", TAG); OUT = os.path.join(HERE, "out", TAG)
ASSERTER = "unsigned:privacy_mage"

def read(name): return open(os.path.join(IN, name), "rb").read()

def check_sums():
    rels = []
    for line in read("SHA256SUMS.txt").decode().splitlines():
        parts = line.split()
        if len(parts) < 2: continue
        h, rel = parts[0], parts[-1].lstrip("*")
        if hashlib.sha256(read(rel)).hexdigest() != h: raise SystemExit("checksum mismatch: " + rel)
        rels.append(rel)
    return rels

def vtuple(v): return tuple(int(x) for x in str(v).split("."))
def line_of(d, name=""):
    if name: return "privacymage" if name.startswith("privacymage") else "city-of-mages"
    return "privacymage" if vtuple(d["version"])[0] >= 8 else "city-of-mages"
def meta(d): return {} if not isinstance(d, dict) else {"declared_version": str(d.get("version", "")), "created_at": str(d.get("created_at", "")),
                     "updated_at": str(d.get("updated_at", "")), "sections": sorted(d.keys())}

def main():
    rels = check_sums()
    B = Bundle("grimoire/" + TAG, ASSERTER)
    pins, site = [], []
    for r in rels:
        data = read(r); d = json.loads(data); sha = hashlib.sha256(data).hexdigest()
        if r.startswith("pinned/"):
            cid = os.path.basename(r)[:-5]
            how = next(((c, raw) for c in (262144, 1048576) for raw in (True, False) if cid_build(data, c, raw) == cid), None)
            if not how: raise SystemExit("CID does not re-derive from bytes: " + r)
            pins.append({"rel": r, "cid": cid, "chunk": how[0], "data": data, "d": d, "sha": sha})
        else:
            site.append({"rel": r, "data": data, "d": d, "sha": sha})
    ledgers, checks, seq, by_sha = [], [], 0, {}
    for line in ("privacymage", "city-of-mages"):
        ks, prev = [], None
        for x in sorted([p for p in pins if line_of(p["d"]) == line], key=lambda p: vtuple(p["d"]["version"])):
            seq += 1
            blob = B.put_blob(x["data"], "pin:" + x["cid"])
            fields = {"cid": x["cid"], "line": line, "version": str(x["d"]["version"]), "bytes": len(x["data"]),
                      "sha256": x["sha"], "cid_rederived": True, "unixfs_chunk": x["chunk"], "raw_leaves": True, **meta(x["d"])}
            k = B.record(seq, "grimoire-pin/1", fields, blob, f"pin:{line}-v{x['d']['version']}")
            if prev: B.edge(k, prev, "derived-from")
            prev = k; by_sha[x["sha"]] = k; ks.append(k)
        name = f"grimoire-pins-{line}"
        lk = B.ledger(name, f"the {len(ks)} pinned {line} grimoire versions, oldest first", ks)
        B.check(name + "-count", lk, "rows/count/1", {"n": len(ks)})
        ledgers.append(name); checks.append(name + "-count")
    ks = []
    for x in sorted(site, key=lambda s: s["rel"]):
        seq += 1
        blob = B.put_blob(x["data"], "file:" + x["rel"])
        fields = {"file": os.path.basename(x["rel"]), "line": line_of(x["d"], os.path.basename(x["rel"])), "bytes": len(x["data"]),
                  "sha256": x["sha"], "matches_pin": x["sha"] in by_sha, **meta(x["d"])}
        k = B.record(seq, "grimoire-file/1", fields, blob, "site:" + os.path.basename(x["rel"]))
        if x["sha"] in by_sha: B.edge(k, by_sha[x["sha"]], "refers-to")
        ks.append(k)
    lk = B.ledger("grimoire-site-copies", f"the {len(ks)} grimoire files bundled in the site's data", ks)
    B.check("grimoire-site-copies-count", lk, "rows/count/1", {"n": len(ks)})
    ledgers.append("grimoire-site-copies"); checks.append("grimoire-site-copies-count")
    matched = sum(1 for x in site if x["sha"] in by_sha)
    root = B.root(ledgers + checks, {"pins": len(pins), "site_copies": len(site), "site_copies_matching_a_pin": matched})
    B.write(OUT, ["", f"Pinned versions sealed: {len(pins)} (every CID re-derived from the bytes)",
                  f"Site copies sealed: {len(site)} ({matched} byte-identical to a pin)", f"Ledgers: {', '.join(ledgers)}", "",
                  "Sealed, not judged: the bundle fixes which bytes each version was; it checks no claim inside them.",
                  "Known leak-scan result: four published pins (privacymage 10.2.0 to 10.4.0) and three site copies carry a",
                  "home-directory path in narrative_sync. The pins are immutable and public since April 2026; the bytes are",
                  "sealed as published by the First Person's ruling of 2026-11-17. verify_bundle.py reports these as FAIL",
                  "by design; the scan is not overridden. The next grimoire (v11) drops the path.",
                  "Counts are recomputed by verify_bundle.py from the bundle alone."])
    print("root", root); print("merkle", B._mroot, "leaves", B._nleaves)

if __name__ == "__main__":
    main()
