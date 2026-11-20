"""mint_sig_letter_levers.py - kappa evidence for the four levers told in the research letter "Strokes in the Floor"
(E8, C1 cache MAC, witness trim, credit filter), minted 2026-10-20 from the notes as they were submitted to the board,
the kits that built them, the board's own list of our submissions, and the citations census of 20 October.

Snapshot into input/sig_letter_levers/ (text LF + redacted), SHA256SUMS, then mint from the snapshot only.
Usage: python mint_sig_letter_levers.py <dir with yukon_submissions_2026-10-20.txt and yukon_board_2026-10-20.txt>
Output: out/sig_letter_levers/. Then: python verify_bundle.py out/sig_letter_levers
Lever leaves are the record/1 objects named lever:E8, lever:C1, lever:trim, lever:filter.
"""
from __future__ import annotations
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))  # repository root
import hashlib, json, os, shutil, sys
import kappa as K
from bundle import Bundle, redact

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IN = os.path.join(HERE, "input", "sig_letter_levers")
OUT = os.path.join(HERE, "out", "sig_letter_levers")
SM = os.path.join(os.path.expanduser("~"), "sig_mage", "sigmage").replace("\\", "/")
TMP = sys.argv[1] if len(sys.argv) > 1 else None
LANE = "sig-golf/letter-levers"
ASSERTER = "unsigned:sig_mage"
TEXT = (".md", ".txt", ".json", ".jsonl", ".py", ".sh", ".patch", ".lean", ".log", ".credit")
SUBS = [  # id, lever, PR, base, S, C, score, outcome, date, note file
    ("62479bf4", "E8", 212, "84d1a0b", 6032, 10380, 62612160, "promoted (crown)", "2026-10-01", "e8-note.submitted-62479bf4.md"),
    ("35cff6dc", "C1", 301, "00a3e6b", 6032, 10255, 61858160, "promoted (crown)", "2026-10-02", "c1-note.submitted-35cff6dc.md"),
    ("795753b2", "E8", 459, "2424b65", 5616, 8688, 48791808, "rejected: 456 promoted first", "2026-10-03", "t3e8h3-note.submitted-795753b2.md"),
    ("86677278", "E8", 464, "f00b660", 5616, 8650, 48578400, "promoted (crown)", "2026-10-03", "t3e8h5-note.submitted-86677278.md"),
    ("f6310722", "E8", 482, "f425157", 5616, 8554, 48039264, "rejected: 480 promoted first", "2026-10-03", "t3e8h6-note.submitted-f6310722.md"),
    ("c49fc5a6", "E8", 493, "81a3399", 5456, 7941, 43326096, "promoted (record)", "2026-10-04", "t3e8p484-note.submitted-c49fc5a6.md"),
    ("8f132ef7", "trim", 564, "82b4918", 5456, 7718, 42109408, "rejected: 558 promoted first", "2026-10-04", "t3wt9v3-note.submitted-8f132ef7.md"),
    ("b7fb2880", "trim", 578, "be3d8f2", 5456, 7696, 41989376, "rejected: 574 carried it", "2026-10-04", "t3wt9v3c-note.submitted-b7fb2880.md"),
    ("34f2bdc7", "filter", 608, "c267897", 5456, 7666, 41825696, "rejected: 604 promoted first", "2026-10-05", "t3cf-c267-note.submitted-34f2bdc7.md"),
    ("b31c82ea", "filter", 613, "83a83e9", 5456, 7661, 41798416, "rejected: 611 carried it", "2026-10-05", "t3cf-83a8-note.submitted-b31c82ea.md"),
]
LEVERS = {
    "E8": ("sign the children, not the root", "verify folds h-1 times per lower tree; the upper OTS signs (L, R); dB = 4 x (-14 + 4) = -40 cycles", "lean/e8"),
    "C1": ("a ledger made of arithmetic", "poly-MAC over the 65,504-byte cache, p = 2^61 - 1, six keys and pads; signer 513 + 326 -> 3 compressions (-835); targets 185 -> 186 on layers 2 and 3; dB = -16", "lean/c1"),
    "trim": ("the empty room in the witness", "1,280 untouched bytes removed between the coordinate regions and the first layer; W 24,264 -> 22,984, charge 95 -> 90; nineteen immediates, no instruction", "lean/t3wt9v3"),
    "filter": ("counting digits the signer chooses", "signer and expander search the top counter until credit >= 9; bound proved under that predicate; B 7,580 -> 7,571; admissible encodings 169,880,087,395,417,918,897,451,495,310,468,748; moment bound 1.9990 < 2", "lean/t3cf"),
}
SKIP = {"e8_on_b444138.patch", "e8_on_pr209.patch", "e8_on_pr214.patch", "e8_wip.patch", "e8_on_84d1a0b.nogen.patch", "cf.patch", "cf_crown.patch"}


def norm(name, raw):
    if name.endswith(TEXT) or "." not in os.path.basename(name):
        try:
            return redact(raw.decode("utf-8").replace("\r\n", "\n")).encode("utf-8")
        except UnicodeDecodeError:
            return raw
    return raw


def put(rel, raw):
    data = norm(rel, raw)
    p = os.path.join(IN, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    return hashlib.sha256(data).hexdigest()


def rd(p):
    with open(p, "rb") as f:
        return f.read()


def snapshot():
    if os.path.isdir(IN):
        shutil.rmtree(IN)
    os.makedirs(IN)
    for s in SUBS:
        put("notes/" + s[9], rd(os.path.join(SM, "submissions", s[9])))
    for lev, (_, _, kit) in LEVERS.items():
        for dp, dns, fs in os.walk(os.path.join(SM, kit)):
            dns[:] = [d for d in dns if d not in ("__pycache__", "t", "v1", "work")]
            for f in fs:
                if f in SKIP or f.endswith((".pyc", ".b64")):
                    continue
                rel = os.path.relpath(os.path.join(dp, f), os.path.join(SM, kit)).replace("\\", "/")
                put(f"kits/{lev}/{rel}", rd(os.path.join(dp, f)))
    put("board/yukon_submissions_2026-10-20.txt", rd(os.path.join(TMP, "yukon_submissions_2026-10-20.txt")))
    put("board/yukon_board_2026-10-20.txt", rd(os.path.join(TMP, "yukon_board_2026-10-20.txt")))
    put("board/citations_2026-10-20.json", rd(os.path.join(SM, "diagrams", "citations_2026-10-20.json")))
    sums = []
    for dp, _, fs in os.walk(IN):
        for f in fs:
            rel = os.path.relpath(os.path.join(dp, f), IN).replace("\\", "/")
            if rel != "SHA256SUMS.txt":
                sums.append(f"{hashlib.sha256(rd(os.path.join(dp, f))).hexdigest()} *{rel}")
    with open(os.path.join(IN, "SHA256SUMS.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(sorted(sums, key=lambda s: s.split("*")[1])) + "\n")


def mint():
    B = Bundle(LANE, ASSERTER)
    blob = {}
    with open(os.path.join(IN, "SHA256SUMS.txt"), encoding="utf-8") as f:
        for line in f.read().splitlines():
            h, rel = line.split(" *", 1)
            raw = rd(os.path.join(IN, rel))
            assert hashlib.sha256(raw).hexdigest() == h, rel
            blob[rel] = B.put_blob(raw, "file:" + rel)
    subs = blob["board/yukon_submissions_2026-10-20.txt"]
    sk = []
    for i, (sid, lev, pr, base, S, C, score, outcome, date, note) in enumerate(SUBS, 1):
        k = B.record(i, "board-submission", {"submission": sid, "lever": lev, "pr": pr, "base": base, "S": S, "C": C,
                      "score": score, "outcome": outcome, "date": date, "note": blob["notes/" + note]}, subs, f"submission:{sid}")
        B.edge(k, blob["notes/" + note], "evidence-provenance")
        sk.append(k)
    lk = B.ledger("letter-submissions", "the ten board submissions behind the four levers of the letter, as the board lists them on 2026-10-20", sk)
    B.check("letter-submissions-count", lk, "rows/count/1", {"n": len(sk)})
    lv = []
    for i, (lev, (title, result, kit)) in enumerate(LEVERS.items(), 1):
        ids = [s[0] for s in SUBS if s[1] == lev]
        promoted = sum(1 for s in SUBS if s[1] == lev and s[7].startswith("promoted"))
        kitfiles = sorted(r for r in blob if r.startswith(f"kits/{lev}/"))
        primary = blob["notes/" + next(s[9] for s in SUBS if s[1] == lev)]
        k = B.record(i, "lever", {"lever": lev, "title": title, "result": result, "submissions": ids, "promoted": promoted,
                      "kit": {r.split("/", 2)[2]: blob[r] for r in kitfiles}}, primary, f"lever:{lev}")
        for r in kitfiles:
            B.edge(k, blob[r], "evidence-provenance")
        lv.append(k)
    lk2 = B.ledger("letter-levers", "the four levers of Strokes in the Floor: title, arithmetic, submissions, kit", lv)
    B.check("letter-levers-count", lk2, "rows/count/1", {"n": 4})
    cites = json.loads(rd(os.path.join(IN, "board/citations_2026-10-20.json")))
    ck = B.record(1, "citations-census", {"rule": "pull requests by other solvers whose note names mitchuski or one of these submissions",
                  "as_of": "2026-10-20", "prs": len(cites), "solvers": len({c["who"] for c in cites}),
                  "merged": sum(c["s"] == "MERGED" for c in cites), "coauthor": sum(bool(c["co"]) for c in cites),
                  "by_lever": {l: len([c for c in cites if l in c["hits"]]) for l in ("E8", "C1", "trim", "filter", "H2")}},
                  blob["board/citations_2026-10-20.json"], "census:2026-10-20")
    lk3 = B.ledger("letter-census", "the citations census of 2026-10-20", [ck])
    B.check("letter-census-count", lk3, "rows/count/1", {"n": 1})
    bk = B.record(1, "board-state", {"current_best": 36494874, "S": 5239, "C": 6966, "pr": 938, "read": "2026-10-20"},
                  blob["board/yukon_board_2026-10-20.txt"], "board:2026-10-20")
    lk4 = B.ledger("letter-board", "the board as read on 2026-10-20", [bk])
    B.check("letter-board-count", lk4, "rows/count/1", {"n": 1})
    B.root(["letter-submissions", "letter-submissions-count", "letter-levers", "letter-levers-count",
            "letter-census", "letter-census-count", "letter-board", "letter-board-count"])
    B.write(OUT, ["", "Minted 2026-10-20 for the research letter Strokes in the Floor from the notes as submitted, the kits, the board list and the census.",
                  "Lever leaves: " + ", ".join(f"{n} `{k}`" for n, k in sorted(B.names.items()) if n.startswith("lever:"))])


if __name__ == "__main__":
    snapshot()
    mint()
