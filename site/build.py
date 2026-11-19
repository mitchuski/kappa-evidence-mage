"""site/build.py - build the standalone page: template.html + core.js + the example bundle -> public/index.html.

Usage (from the repository root):
    python example_mint.py            # optional: re-mint out/example first
    python site/build.py [--refresh]  # --refresh re-reads out/example into site/example_bundle.json

The page embeds the example bundle's bytes and verifies them in the browser with core.js, an
independent JavaScript implementation of the subset of dCBOR the evidence shapes use. A run root
carries its mint date, so the embedded root is the one minted on the day example_bundle.json was
last refreshed.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def refresh() -> None:
    d = os.path.join(ROOT, "out", "example")
    o = {s: {f.split(".")[0]: open(os.path.join(d, s, f), "rb").read().hex() for f in sorted(os.listdir(os.path.join(d, s)))}
         for s in ("objects", "edges")}
    (b,) = os.listdir(os.path.join(d, "blobs"))
    o["blob"] = {"name": b.split(".")[0], "text": open(os.path.join(d, "blobs", b), "rb").read().decode()}
    with open(os.path.join(d, "root.json"), encoding="utf-8") as f:
        o["root"] = json.load(f)["root_kappa"]
    with open(os.path.join(HERE, "example_bundle.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(o, f, separators=(",", ":"))


def main() -> None:
    if "--refresh" in sys.argv:
        refresh()
    read = lambda n: open(os.path.join(HERE, n), encoding="utf-8").read()
    page = read("template.html").replace("/*CORE*/", read("core.js").strip()).replace("/*BUNDLE*/", read("example_bundle.json").strip())
    os.makedirs(os.path.join(HERE, "public"), exist_ok=True)
    out = os.path.join(HERE, "public", "index.html")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(page)
    print(f"wrote {os.path.relpath(out, ROOT)} ({len(page.encode()):,} bytes)")


if __name__ == "__main__":
    main()
