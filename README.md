# κ evidence

[![test](https://github.com/mitchuski/kappa-evidence-mage/actions/workflows/test.yml/badge.svg)](https://github.com/mitchuski/kappa-evidence-mage/actions/workflows/test.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![licence](https://img.shields.io/badge/licence-MIT%20OR%20Apache--2.0-blue)

**Content-addressed evidence for agent work.**

AI agents report what they did: tests passed, a benchmark scored this, a proof checked.
κ evidence turns those reports into something a third party can re-derive. Every file, row,
check and link a run produces is stored under the hash of its own bytes (its κ, "kappa") and
tied into a single root. Anyone holding the bundle can recompute that root with SHA-256 and
the verifier in this repository. One changed byte anywhere and the root no longer holds.

It is the evidence protocol of [agentprivacy](https://agentprivacy.ai) and the record layer
of Proof of Agentic Work. **See a bundle and break it in your browser:
[touchstone.mages.city](https://touchstone.mages.city).**

## Why use it

- **Verifiable by anyone, offline.** No service, no account, no network. A bundle and a
  Python interpreter are enough.
- **Facts are recomputed, not asserted.** Each stated fact names a published rule; the
  verifier runs the rule over the sealed rows and requires the same bytes.
- **Small enough to audit.** Pure Python 3, standard library only. The core, the minter and
  the verifier are about a thousand lines.
- **Interoperable.** Byte-compatible with the κ labels of the
  [UOR kappa-registry](https://github.com/UOR-Foundation/kappa-registry), with independent
  implementations in Python, JavaScript and Rust held equal on a fixed vector.
- **Formally grounded.** The Merkle tree, inclusion proofs and the chain rule carry
  machine-checked Lean 4 proofs ([`FORMAL.md`](FORMAL.md)).

## Quick start

Requires Python 3.10 or later. Nothing to install.

```sh
git clone https://github.com/mitchuski/kappa-evidence-mage
cd kappa-evidence-mage

python test_kappa.py                  # the encoder against upstream golden vectors
python example_mint.py                # mint the smallest complete bundle into out/example
python verify_bundle.py out/example   # re-derive it from its root
```

The verifier prints each step and exits 0 only if all of them pass:

```
re-hashed 6 objects, 1 blobs, 9 edges
root sha256:... | status: kappa-verified at 2af8656 | lane example/readme
blake3 axis: 13/13 dual labels recomputed
composed-of walk reached 6 objects
recomputed check rows/count/1 of steps: {"n": 3}
merkle root over 13 leaves matches
leak scan done
RESULT: OK
```

Now append one byte to the file in `out/example/blobs/` and run the verifier again. The blob
no longer hashes to its name, the rows lose their source, the Merkle root no longer matches,
and the verifier exits 1.

## Use it from code

```python
import kappa as K

K.kappa_from_bytes(b"hello world")
# 'sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'

K.kappa_from_value({0: "example/thing/1", 1: "hello", 2: 42})
# 'sha256:f722f153dc94c9a09997b092070476a79e7f9c1ac4bd5d80cc887b680d6f4aa7'

root = K.merkle_root([b"a", b"b", b"c"])
proof = K.merkle_proof([b"a", b"b", b"c"], 1)
K.merkle_verify(root, b"b", proof)        # True
```

Minting a bundle ([`example_mint.py`](example_mint.py) is the complete version):

```python
import bundle as B

b = B.Bundle("my-project/run-42", "unsigned:my-project")
log = b.put_blob(open("results.csv", "rb").read(), "results.csv")
rows = [b.record(i, "step", {"tool": t, "exit": 0}, log) for i, t in enumerate(["build", "test"])]
ledger = b.ledger("steps", "tool runs read from results.csv", rows)
b.check("steps-count", ledger, "rows/count/1", {"n": len(rows)})
b.root(["steps", "steps-count"])
b.write("out/run-42", ["Run 42."])
```

## Command line

| command | what it does |
|---|---|
| `python verify_bundle.py <bundle>` | verify one bundle against its own root |
| `python verify_chain.py <bundle> <bundle> ...` | verify an ordered chain of bundles and every link between them (`--expect-head <κ>` pins the head) |
| `python example_mint.py [out_dir]` | mint the example bundle |
| `python make_test_vector.py` | regenerate the cross-implementation vector |

## How it works

**A κ is a typed hash.** `kappa_from_bytes(b)` is `"sha256:" + hex(SHA-256(b))`.
`kappa_from_value(v)` is the same over the deterministic CBOR
([dCBOR](https://github.com/BlockchainCommons/bc-dcbor-rust)) encoding of `v`, so a
structured object has exactly one byte form and therefore one name.

**A bundle is a small graph** in three flat directories, where every file name is the κ of
the file's content:

```
<bundle>/objects/<hex>.cbor   structured objects, canonical dCBOR
<bundle>/blobs/<hex>.bin      raw bytes: logs, source files, images, proofs
<bundle>/edges/<hex>.cbor     typed links between κ's (composed-of, derived-from,
                              evidence-provenance, section-of, refers-to)
<bundle>/root.json            the root κ and counts, for tools (metadata, not hashed)
<bundle>/graph.json           everything decoded, for readers
<bundle>/REPORT.md
```

**The core shapes are few.** Each shape is registered in [`SCHEMA.md`](SCHEMA.md) before any
bundle uses it.

| object | what it holds |
|---|---|
| `record/1` | one row of evidence, with an `evidence-provenance` edge to the blob it was read from |
| `ledger/1` | an ordered list of rows |
| `check/1` | facts about a ledger under a named rule; the verifier recomputes them from the rows and requires equality |
| `run-root/1` | the root: every named object, a Merkle root over every κ in the bundle, the status label, the asserter, the upstream pins, and optionally the previous root |

**Verification trusts nothing but the hash.** The verifier re-hashes every file against its
name, requires objects to re-encode byte-identically, walks `composed-of` from the root to
every ledger and check, requires every row to point at a blob that is present, recomputes
every `check/1` from its rows, recomputes the Merkle root, and scans for private paths and
host names.

**Roots chain.** A run root may name the root before it. The chain verifier checks every
bundle and every link, so the head root commits to the whole history behind it.

**A κ can carry more than one label.** SHA-256 is the identity and names every file. Each
bundle also seals a BLAKE3 label for every object, blob and edge (the registry's
`KappaLabel::blake3` axis), recomputed by the verifier. An Orchard Poseidon axis
(`poseidon-orchard-chain/1`) is available where a circuit-friendly label is needed.

**Signing is optional and separate.** Without a key, the asserter is a placeholder
(`unsigned:<lane>`) and the bundle is an offline record. With a key, the asserter is the
registry anchor of the public key and `root.json` carries an ed25519 signature over the root
κ. The signature is metadata and is never part of a hashed preimage. Signing is implemented
in the [JavaScript twin](https://github.com/mitchuski/agentprivacy-harness); the Python
verifier reports a signature when present and does not check it.

## What a root tells you, and what it does not

A verified root tells you that the bundle is complete and unaltered, that every row traces
to sealed source bytes, and that every stated fact follows from those rows under a published
rule.

It does not tell you that the source bytes were honestly produced. A log sealed in a bundle
is exactly the log that was sealed, whoever wrote it. Rules can close that gap where the
work allows it: `flashprove/verify-rerun/1`, for example, re-runs a proof verifier on the
sealed proof bytes, so its facts are recomputed truth and not a recorded verdict.

Other limits:

- "κ-verified at 2af8656" means byte equality with `kappa-core` at that commit on the
  shapes used here. It does not mean an object is registered with any registry.
- The Merkle root in `run-root/1` is labelled provisional: it follows the upstream leaf and
  node rule but is computed locally, with no registry inclusion proof.
- An unsigned bundle carries no authorship. Only a signed root binds a key to the work.

## Assurance

| what | how | result |
|---|---|---|
| dCBOR encoder, blob κ, Merkle, edge shape | [`test_kappa.py`](test_kappa.py): expected bytes copied from the upstream test suites; runs in CI | 0 failures |
| equality with `kappa-core` as compiled | a Rust crate calling `kappa_from_value` on a fixed vector ([`docs/rust-cross-check/`](docs/rust-cross-check)) | 10 of 10 lines identical |
| a second implementation | the harness's independent JavaScript encoder and verifier, held to [`test_vector.json`](test_vector.json) | agrees on every vector |
| published addresses, re-derived in Rust | [`site_check/`](site_check): decode, re-encode, re-hash, Merkle and chain walk with `kappa-core` over every κ cited on agentprivacy.org | 188 addresses, 4,213 checks, 0 failures |
| BLAKE3 axis | pure-Python BLAKE3 against the official vectors | pass |
| Poseidon axis | [`test_poseidon_axis.py`](test_poseidon_axis.py) against the HashSmash organizer reference (needs a local clone of it) | pass |
| Merkle root, inclusion proofs, chain head | Lean 4 theorems, kernel-checked and axiom-audited ([`FORMAL.md`](FORMAL.md)) | proved |

The Rust results are recorded runs from October 2026; their outputs are in the repository.

## Sealing your own work

A *lane* is any body of work that wants its evidence sealed: an agent run, a benchmark
submission, a proof audit, a set of documents. It needs one thin adapter.

1. Snapshot the lane's files read-only under `input/<name>/`.
2. Write `mint_<lane>.py`: put each source file as a blob, each row as a `record/1`, group
   rows into ledgers, state the facts as `check/1` objects, then call `root()` and `write()`.
3. If the facts need a new rule, add the rule to `verify_bundle.py` and its row in
   `SCHEMA.md` first. A verifier that meets an unknown rule fails.
4. Run `python verify_bundle.py out/<name>`, then quote the root wherever the work is cited:
   `Evidence root: sha256:...`

The `mint_*.py` files in this repository are working adapters from production use, covering
cryptanalysis benchmarks, circuit optimisation, formal proof audits and verifiable-inference
replies. Each reads a snapshot that is not distributed here; read them as examples of shape.

## Repository layout

| path | role |
|---|---|
| [`kappa.py`](kappa.py) | the core: dCBOR encode and decode, κ from bytes and from values, edge records, anchors, Merkle root and proofs, the BLAKE3 and Poseidon axes |
| [`bundle.py`](bundle.py) | minting helper: objects, blobs, edges, ledgers, checks, the run root, the bundle on disk |
| [`verify_bundle.py`](verify_bundle.py) | lane-neutral verifier for one bundle, with the rule table |
| [`verify_chain.py`](verify_chain.py) | verifier for an ordered chain of bundles |
| [`example_mint.py`](example_mint.py) | the smallest complete bundle |
| [`SCHEMA.md`](SCHEMA.md) | the registry of object shapes, their permanent integer keys, and the rules |
| [`FORMAL.md`](FORMAL.md) | which claims about this code are proved in Lean, and where |
| [`test_kappa.py`](test_kappa.py), [`test_vector.json`](test_vector.json) | golden tests and the cross-implementation vector |
| [`ipfs_cid.py`](ipfs_cid.py) | library function `build(bytes, chunk, raw)`: re-derives a UnixFS CIDv1 from file bytes, for evidence that is also pinned |
| [`site_check/`](site_check) | Rust crate that re-derives a list of cited addresses with `kappa-core` |
| [`site/`](site) | the project page at [touchstone.mages.city](https://touchstone.mages.city), with a verifier that runs in the browser |
| `mint_*.py`, `verify_r32.py` | lane adapters, and the first lane-specific verifier |
| [`docs/`](docs) | the Rust cross-check and working notes |
| [`chronicles/`](chronicles) | the project's history, as it happened |

`out/` (minted bundles) and `input/` (lane snapshots) are local and not tracked. Public
bundles are published with the work they seal.

## Who uses it

- [agentprivacy-harness](https://github.com/mitchuski/agentprivacy-harness): the JavaScript
  twin (`tools/dcbor.mjs`, `tools/kappa_evidence.mjs` with `mint | verify | chain | root`
  and `--sign`). Every harness run is minted, and every gate run re-verifies the bundles.
- [agentprivacy-harness-demos](https://github.com/mitchuski/agentprivacy-harness-demos):
  readers bound to the evidence root they were generated from.
- [trust-tasks-formal](https://github.com/mitchuski/trust-tasks-formal) and
  [poc_mage](https://github.com/mitchuski/poc_mage): formal-proof evidence published as
  bundles beside the proofs.
- [mages.city](https://mages.city) and the
  [agentprivacy.org record](https://agentprivacy.org/harness/record/): pages that show the
  chain of roots behind a body of work.

## Notes for implementers

Anyone writing another encoder will meet these. Each was found by a disagreement between
implementations or a failed verification.

- **`Vec<u8>` is an array, not a byte string.** The upstream derive encodes `Vec<u8>`
  fields (`Edge.metadata`, the anchor's `public_key`) as a CBOR array of unsigned integers.
  An encoder that uses a byte string computes different edge and anchor κ's.
- **`None` is omitted, not null.** Optional fields that are absent do not appear in the map.
- **The status label is inside the root.** It is field 5 of `run-root/1`, so changing the
  label is a re-mint with a new root κ. The Merkle root over the leaves is unchanged.
- **The mint date is inside the root too.** The same content minted on two days gives two
  roots with one Merkle root.
- **The leaf set is a set.** A blob whose bytes equal an object's encoding shares its κ, and
  a duplicated leaf would change the root. Minters and verifiers de-duplicate before
  hashing; the Lean proofs show why this is necessary.
- **Bundles must survive `git clone`.** Mark bundle directories `-text` in `.gitattributes`
  and hash text as git stores it (LF). Otherwise a checkout with newline conversion rewrites
  every blob and every verification fails.
- **Integer keys are permanent.** Changing a key number changes every κ minted since.

## Stability

Object shapes are versioned in their names (`record/1`, `run-root/1`) and their integer keys
never change; a breaking change is a new shape with a new number, and new fields are
optional so that older objects encode exactly as before. The code is pinned to `kappa-core`
at `2af8656` and `bc-dcbor-rust` at `2e5b901`. The pin is part of the status label sealed in
every root, so a move to a newer upstream commit is visible in the bundles themselves.

## Contributing and security

Contributions are welcome: see [`CONTRIBUTING.md`](CONTRIBUTING.md). To report a case where
the verifier accepts something it should refuse, see [`SECURITY.md`](SECURITY.md).

## Credits

κ labels, edge records and the Merkle rule are the design of the
[UOR kappa-registry](https://github.com/UOR-Foundation/kappa-registry). Deterministic CBOR
is the work of [Blockchain Commons](https://github.com/BlockchainCommons/bc-dcbor-rust).
`kappa.py` is an independent re-implementation that cites the source lines it mirrors. This
repository vendors no upstream code and patches none; pins, licences and the provenance of
the Poseidon constants are in [`NOTICE.md`](NOTICE.md). The evidence shapes, the dual label
axes, the minters and the verifiers are this repository's own work.

> The decimal travels; the root stays. Whoever carries the measure carries the mint, and the
> mint remembers the hand that struck it. ([`PROVERB.md`](PROVERB.md))

## Licence

Code is MIT OR Apache-2.0 ([`LICENSE.md`](LICENSE.md), [`LICENSE-APACHE`](LICENSE-APACHE)).
Documents are CC BY 4.0. Upstream material keeps its own licence ([`NOTICE.md`](NOTICE.md)).
