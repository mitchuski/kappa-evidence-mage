"""example_mint.py - the smallest complete evidence bundle, for reading and for trying the verifier.

Usage: python example_mint.py [out_dir]        (default out/example)
Then:  python verify_bundle.py out/example

It seals one source file as a blob, three rows read from it as record/1 objects (each with an
evidence-provenance edge back to the blob), a ledger over the rows, a check/1 whose fact the
verifier recomputes from the rows (rule rows/count/1), and a run root over all of it. A real lane
adapter (mint_*.py) has the same shape with the lane's own files, rows and rules.
"""
import sys

import bundle as B

SOURCE = b"seq,tool,exit\n0,build,0\n1,test,0\n2,lint,0\n"


def main(out: str) -> None:
    b = B.Bundle("example/readme", "unsigned:example")
    blob = b.put_blob(SOURCE, "source.csv")
    rows = []
    for line in SOURCE.decode().splitlines()[1:]:
        seq, tool, code = line.split(",")
        rows.append(b.record(int(seq), "step", {"tool": tool, "exit": int(code)}, blob))
    ledger = b.ledger("steps", "three tool runs read from source.csv", rows)
    b.check("steps-count", ledger, "rows/count/1", {"n": len(rows)})
    b.root(["steps", "steps-count"])
    b.write(out, ["Example bundle: three rows, one ledger, one recomputed check."])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "out/example")
