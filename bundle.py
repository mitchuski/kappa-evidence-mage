"""bundle.py - shared minting helper: objects, blobs, typed edges, run root, bundle on disk.

Lane adapters (mint_*.py) call this; verify_bundle.py reads what it writes. Schemas are in
SCHEMA.md. Every kappa is labelled kappa.STATUS until P1.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from datetime import date

import kappa as K

NS = "agentprivacy-evidence"
PRIVATE = re.compile(r"(?i)(c:\\|/c/users|/home/|/root/|mitch|desktop-|\\\\wsl|@[a-z0-9.-]+\.(local|lan))")


def redact(s: str) -> str:
    return PRIVATE.sub("[redacted]", s)


class Bundle:
    def __init__(self, lane: str, asserter: str):
        self.lane, self.asserter = lane, asserter
        self.objects: dict[str, dict] = {}
        self.blobs: dict[str, bytes] = {}
        self.edges: dict[str, dict] = {}
        self.names: dict[str, str] = {}

    # -- minting -----------------------------------------------------------------
    def put(self, v: dict, name: str | None = None) -> str:
        k = K.kappa_from_value(v)
        self.objects[k] = v
        if name:
            self.names[name] = k
        return k

    def put_blob(self, b: bytes, name: str | None = None) -> str:
        k = K.kappa_from_bytes(b)
        self.blobs[k] = b
        if name:
            self.names[name] = k
        return k

    def edge(self, src: str, tgt: str, rel: str, value_kappa=None, metadata: bytes | None = None) -> str:
        e = K.edge_record(src, tgt, rel, self.asserter, value_kappa, metadata)
        k = K.kappa_from_value(e)
        self.edges[k] = e
        return k

    def record(self, seq: int, kind: str, fields: dict, source_blob: str, name: str | None = None) -> str:
        """record/1: a generic row (text-keyed field map) with provenance to its source blob."""
        v = {0: f"{NS}/record/1", 1: seq, 2: kind, 3: fields, 4: self.lane}
        k = self.put(v, name)
        self.edge(k, source_blob, "evidence-provenance")
        return k

    def ledger(self, name: str, desc: str, ks: list[str]) -> str:
        k = self.put({0: f"{NS}/ledger/1", 1: name, 2: ks, 3: self.lane, 4: desc}, name)
        for ck in ks:
            self.edge(k, ck, "composed-of")
        return k

    def check(self, name: str, ledger_k: str, rule: str, facts: dict) -> str:
        """check/1: facts the verifier recomputes from the ledger's rows under a named rule."""
        k = self.put({0: f"{NS}/check/1", 1: ledger_k, 2: rule, 3: facts}, name)
        self.edge(k, ledger_k, "derived-from")
        return k

    # -- root and output -----------------------------------------------------------
    def root(self, composed: list[str], extra: dict | None = None) -> str:
        leaves = sorted(list(self.objects) + list(self.blobs) + list(self.edges))
        mroot = K.merkle_root([x.encode() for x in leaves]).hex()
        v = {0: f"{NS}/run-root/1", 1: self.lane, 2: date.today().isoformat(),
             3: [[n, k] for n, k in sorted(self.names.items())], 4: mroot, 5: K.STATUS,
             6: self.asserter, 7: K.UPSTREAM}
        if extra:
            v[8] = extra
        rk = K.kappa_from_value(v)
        self.objects[rk] = v
        for n in composed:
            e = K.edge_record(rk, self.names[n], "composed-of", self.asserter)
            self.edges[K.kappa_from_value(e)] = e
        self._root, self._mroot, self._nleaves = rk, mroot, len(leaves)
        return rk

    def write(self, out: str, report_lines: list[str]) -> None:
        if os.path.isdir(out):
            shutil.rmtree(out)
        for d in ("objects", "blobs", "edges"):
            os.makedirs(os.path.join(out, d))
        for k, v in self.objects.items():
            with open(os.path.join(out, "objects", K.split_kappa(k)[1] + ".cbor"), "wb") as f:
                f.write(K.encode(v))
        for k, b in self.blobs.items():
            with open(os.path.join(out, "blobs", K.split_kappa(k)[1] + ".bin"), "wb") as f:
                f.write(b)
        for k, e in self.edges.items():
            with open(os.path.join(out, "edges", K.split_kappa(k)[1] + ".cbor"), "wb") as f:
                f.write(K.encode(e))
        meta = {"root_kappa": self._root, "status": K.STATUS, "lane": self.lane,
                "minted_on": date.today().isoformat(), "merkle_root_sha256": self._mroot,
                "merkle_leaves": self._nleaves,
                "counts": {"objects": len(self.objects), "blobs": len(self.blobs), "edges": len(self.edges)},
                "names": self.names, "upstream": K.UPSTREAM}
        with open(os.path.join(out, "root.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=1)

        def js(v):
            if isinstance(v, dict):
                return {str(k): js(x) for k, x in v.items()}
            if isinstance(v, list):
                return [js(x) for x in v]
            if isinstance(v, K.RustBytes):
                return list(v)
            if isinstance(v, bytes):
                return v.hex()
            return v
        graph = {"status": K.STATUS, "root": self._root,
                 "objects": {k: js(v) for k, v in self.objects.items()},
                 "blobs": {k: len(b) for k, b in self.blobs.items()},
                 "edges": [{"kappa": k, "source": e[0], "target": e[1], "relation": K.RELATION_NAME[e[2]],
                            "asserter": e[3], **({"metadata": bytes(e[5]).decode()} if 5 in e else {})}
                           for k, e in self.edges.items()]}
        with open(os.path.join(out, "graph.json"), "w", encoding="utf-8") as f:
            json.dump(graph, f, indent=1)
        head = [f"# {self.lane} evidence graph - minted {meta['minted_on']} - status: {K.STATUS}", "",
                f"Run root kappa: `{self._root}`",
                f"Merkle root (provisional, SHA-256, {self._nleaves} leaves): `{self._mroot}`", "",
                "| object | kappa |", "|---|---|"]
        head += [f"| {n} | `{k}` |" for n, k in sorted(self.names.items())]
        head += ["", f"Objects {len(self.objects)}, blobs {len(self.blobs)}, edges {len(self.edges)}. "
                 f"Asserter `{self.asserter}` (placeholder, no anchor key yet).", ""]
        text = "\n".join(head + report_lines) + "\n"
        with open(os.path.join(out, "REPORT.md"), "w", encoding="utf-8") as f:
            f.write(text)
        print(text)
