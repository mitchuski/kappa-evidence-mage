# orchard_poseidon_constants.json — provenance

Byte-for-byte copy of `pareto/orchard-pallas-constants.json` from the HashSmash Pareto
benchmark (hashsmash-pareto, Yukon), sha256 `ad3d80f3c0145a7cdc9bbf8da51b3da28023bf662eba2e0746da37ca7800bf45`.

The constants (64 round-constant triples and the 3x3 MDS matrix of Orchard P128Pow5T3 over
Pallas) are derived from zcash/halo2 at tag `halo2_poseidon-0.2.0`, file
`halo2_poseidon/src/fp.rs` (source sha256 recorded inside the JSON). Copyright the halo2
contributors; offered upstream under MIT or Apache-2.0, at your option.

Used by the Poseidon axis of `kappa.py` (`poseidon_permute`, `poseidon2`, `poseidon_digest`,
`kappa_poseidon_from_value`, `poseidon_merkle_hex`). Held equal to the organizer reference
`verifier/poseidon.py` by `test_poseidon_axis.py`.
