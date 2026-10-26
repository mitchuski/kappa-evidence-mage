# Formally verified parts of this repository

Sealed in the κ registry: formal_mage evidence bundle `evidence/2026-10-26_75`, root `sha256:d4d42f9e333323b20d5b649525cbe28f8885fa2cb0cdd10943a04cac3793b9da` (75 theorems, 75/75 within the standard axioms).

The κ tree this repository's bundles use (kappa.py `merkle_root`, `merkle_proof`; the same loop as kappa-core merkle.rs) carries machine-checked receipts in `formal_mage` (Lean 4, core library, kernel-checked, axiom-audited). `node tools/formal_census.mjs <this repo>` in formal_mage fails if a tag names a theorem outside the audited census.

| Claim | Code | Status | Tag |
|---|---|---|---|
| The root `merkle_root` returns is a tree's root over exactly the leaves; a proof that climbs to it carries one of them (sha256 collision-free; 0x00/0x01 tags) | `kappa.py` merkle_root / merkle_verify | proved (code loop) | formal: proved formal_mage:Formal.MerkleCode.code_disclosure_sound |
| Every proof `merkle_proof` generates climbs to the root | `kappa.py` merkle_proof | proved (code loop) | formal: proved formal_mage:Formal.MerkleCode.proof_complete |
| Two different duplicate-free leaf lists never share a root | `kappa.py` merkle_root | proved (code loop) | formal: proved formal_mage:Formal.MerkleInj.codeRoot_injective |
| The condition is needed: `[a,b,c]` and `[a,b,c,c]` share a root, which is why every minter and verifier reads the leaf set as a set (bundle.py since 2026-10-25) | `bundle.py`, `verify_bundle.py`, `site_check` | proved | formal: proved formal_mage:Formal.MerkleInj.dup_collision |
| A link chain's head determines every link behind it | `site_check` step 6 | proved | formal: proved formal_mage:Formal.Chain.head_determines |
