# Lane adapters

A lane is a body of work whose evidence is sealed with this format. Each `mint_<lane>.py`
here is the adapter one lane used: it reads a snapshot under `input/<name>/`, mints a bundle
into `out/<name>/`, and the lane-neutral verifier does the rest.

Run them from the repository root:

```sh
python lanes/mint_<lane>.py [tag]
python verify_bundle.py out/<tag>
```

These are working adapters from production use: cryptanalysis benchmarks, circuit
optimisation, formal proof audits and verifiable-inference replies. Their snapshots are not
distributed, so most will not run from a fresh clone. Read them as examples of shape, and
start a new lane from [`example_mint.py`](../example_mint.py).

Several adapters rebuild their `input/<name>/` snapshot from the lane's own working
directory each time they run. Run those only where that directory is the one the bundle was
minted from.

`verify_r32.py` is the first lane-specific verifier, kept for the record;
[`verify_bundle.py`](../verify_bundle.py) replaced it for every later lane.
