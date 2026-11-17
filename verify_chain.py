"""verify_chain.py - verify an ordered chain of evidence bundles, and the links between them.

usage: python verify_chain.py [--expect-head KAPPA] [-v] <bundle> <bundle> ...   (oldest first)
       python verify_chain.py [--expect-head KAPPA] [-v] <dir>                    (its p<N>/r<N>/s<N> steps, by N)

verify_bundle.py checks one bundle against its own root. A chain of steps is more: each step's run root
names the root before it. This reads run-root/1 field 9 (prev, SCHEMA.md) and accepts the list when
  - every bundle verifies on its own (verify_bundle.main, exit 0);
  - every root kappa in the list is distinct, and consecutive bundles share a lane;
  - for each consecutive pair whose later root carries field 9, prev == the earlier bundle's root kappa;
  - the seq runs contiguously: the lattice step (field 8 `lattice.step`) of each bundle is one more than
    the step before it (bundles without a lattice step are numbered by position);
  - the head is the last bundle's root (and equals --expect-head when given).
A later step without field 9 is reported `unlinked (legacy)`, not failed: its link to the step before is
only the quotation of that root in a reader (EVIDENCE_CHAIN.md, a chronicle), which no verifier line checks.
This is the shape of the Lean model formal_mage Formal/Chain.lean (accepted => seq 0..n-1, each prev the
earlier kappa, head = last) restricted to the links that are present. Exit 0 only when nothing fails.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import kappa as K
import verify_bundle

STEP_DIR = re.compile(r"^([a-z]+)(\d+)$")


def expand(args: list[str]) -> list[str]:
    if len(args) == 1 and not os.path.isdir(os.path.join(args[0], "objects")):
        d = args[0]
        steps = [(m.group(1), int(m.group(2)), os.path.join(d, n)) for n in os.listdir(d)
                 if (m := STEP_DIR.match(n)) and os.path.isfile(os.path.join(d, n, "root.json"))]
        prefixes = sorted({s[0] for s in steps}, key=lambda x: -sum(1 for s in steps if s[0] == x))
        if len(prefixes) > 1:  # e.g. evidence/ holds r<N> steps and d<N> disclosures: take the longest run
            print(f"steps under {d}: taking {prefixes[0]}<N>, leaving {', '.join(p + '<N>' for p in prefixes[1:])}")
        return [p for x, _, p in sorted((s for s in steps if s[0] == prefixes[0]), key=lambda s: s[1])]
    return list(args)


def read_root(b: str):
    with open(os.path.join(b, "root.json"), encoding="utf-8") as f:
        rk = json.load(f)["root_kappa"]
    with open(os.path.join(b, "objects", K.split_kappa(rk)[1] + ".cbor"), "rb") as f:
        return rk, K.decode(f.read())


def step_of(root) -> int | None:
    ex = root.get(8)
    if isinstance(ex, dict) and isinstance(ex.get("lattice"), dict) and "step" in ex["lattice"]:
        return int(ex["lattice"]["step"])
    return None


def verify_chain(bundles: list[str], expect_head: str | None = None, verbose: bool = False, log=print) -> dict:
    fails, linked, legacy = [], 0, 0

    def fail(m):
        fails.append(m)
        log("FAIL " + m)

    prev_rk, prev_lane, prev_seq, seen = None, None, None, set()
    for i, b in enumerate(bundles):
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                rc = verify_bundle.main(b)
        except Exception as e:  # a bundle that cannot be read is a failed step
            rc, buf = 1, io.StringIO(f"FAIL {type(e).__name__}: {e}\n")
        if verbose or rc:
            for line in buf.getvalue().splitlines():
                if verbose or line.startswith("FAIL"):
                    log("    " + line)
        try:
            rk, root = read_root(b)
        except Exception as e:
            fail(f"[{i}] {b}: no readable run root ({e})"); prev_rk = None; continue
        seq = step_of(root)
        seq = i if seq is None else seq
        if rc:
            fail(f"[{i}] {b}: bundle does not verify")
        if rk in seen:
            fail(f"[{i}] {b}: root {rk} already appears earlier in the chain")
        seen.add(rk)
        p = root.get(9)
        if p is not None and not (isinstance(p, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", p)):
            fail(f"[{i}] {b}: field 9 is not a sha256 root kappa: {p!r}"); p = None
        if i == 0:
            link = f"first; prev {p} (outside this list)" if p else "first"
        else:
            if root[1] != prev_lane:
                fail(f"[{i}] {b}: lane {root[1]} differs from the previous step's {prev_lane}")
            if prev_seq is not None and seq != prev_seq + 1:
                fail(f"[{i}] {b}: seq {seq} does not follow {prev_seq}")
            if p is None:
                link, legacy = "unlinked (legacy)", legacy + 1
            elif p == prev_rk:
                link, linked = "linked: prev = previous root", linked + 1
            else:
                link = "BROKEN"
                fail(f"[{i}] {b}: prev {p} != previous root {prev_rk}")
        log(f"[{i}] seq {seq} {'ok  ' if rc == 0 else 'FAIL'} {rk} {b} | {link}")
        prev_rk, prev_lane, prev_seq = rk, root[1], seq
    head = prev_rk
    if expect_head and head != expect_head:
        fail(f"head {head} != expected {expect_head}")
    log(f"head = last root: {head}")
    log(f"CHAIN: {'OK' if not fails else str(len(fails)) + ' FAILURE(S)'} | {len(bundles)} steps, "
        f"{linked} linked, {legacy} unlinked (legacy)")
    return {"ok": not fails, "fails": fails, "head": head, "linked": linked, "legacy": legacy, "n": len(bundles)}


def main(argv: list[str]) -> int:
    expect, verbose, args = None, False, []
    it = iter(argv)
    for a in it:
        if a == "--expect-head":
            expect = next(it)
        elif a in ("-v", "--verbose"):
            verbose = True
        else:
            args.append(a)
    if not args:
        print(__doc__.strip().splitlines()[2]); return 2
    bundles = expand(args)
    if not bundles:
        print("no bundles found"); return 2
    return 0 if verify_chain(bundles, expect, verbose)["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
