# Third-party notices

This repository vendors no third-party source code. It re-implements published encoding
rules, copies one data file, and tests against or builds with upstream code that it fetches
or loads by path. Each upstream keeps its own licence; ours (`LICENSE.md`) covers only the
work written here.

| upstream | how it is used here | upstream licence |
|---|---|---|
| UOR kappa-registry (`kappa-core`), commit `2af8656` | `kappa.py` is an independent Python re-implementation of its kappa-label, edge-record and Merkle rules, citing the source lines it mirrors; `site_check/` and the P1 check are crates built *against* kappa-core in a separate local clone, which is not distributed here | MIT OR Apache-2.0 |
| Blockchain Commons `bc-dcbor-rust`, commit `2e5b901` (with `dcbor-derive`) | `kappa.py` re-implements the deterministic CBOR (dCBOR) encoding rules and the derive mapping in Python; `site_check/` depends on the crate | BSD-2-Clause-Patent (see the upstream repository) |
| zcash `halo2`, tag `halo2_poseidon-0.2.0` (`halo2_poseidon/src/fp.rs`) | `orchard_poseidon_constants.json` holds its Orchard P128Pow5T3 round constants and MDS matrix, by way of the HashSmash Pareto benchmark's JSON (provenance in `ORCHARD_POSEIDON_NOTICE.md`). Copyright the halo2 contributors | MIT OR Apache-2.0 |
| HashSmash Pareto benchmark (Eigen Labs / Yukon) `verifier/poseidon.py` | `test_poseidon_axis.py` loads it by path from a local clone to check our Poseidon axis against it; nothing is copied | organiser-owned; see the benchmark's terms |
| BLAKE3 (specification and test vectors) | `kappa.py` contains an independent pure-Python BLAKE3, written from the specification and checked against upstream vectors | CC0-1.0 OR Apache-2.0 (reference implementation) |

The modifications described in this repository (the dual BLAKE3 and Poseidon label axes,
the record/check/run-root shapes in `SCHEMA.md`, the minters and verifiers) are this
repository's own work under `LICENSE.md`. They extend the kappa-registry model. They do not
patch upstream code.
