# Formally verified parts of this repository

Sealed in the κ registry: formal_mage evidence bundle `evidence/2026-11-04_83`, root `sha256:81f2dd578a4fb486c502268e38fcd1302509f6c19656e5410d32946dd5a6f703` (83 theorems, 83/83 within the standard axioms).

Sealed beside it: formal_mage evidence bundle `evidence/2026-11-12_tt188`, root `sha256:c52609b736406d6fe646db7e735e7380d4fb6309cc9c481480fb9709c5077e8e` (188 theorems on the protocols trust tasks are written in, from [trust-tasks-formal](https://github.com/mitchuski/trust-tasks-formal) at `34d3353`, every one in its `Checks.lean` audit; published there under `evidence/`, beside the earlier 183-theorem seal `adcfbf13`).

The κ tree this repository's bundles use (kappa.py `merkle_root`, `merkle_proof`; the same loop as kappa-core merkle.rs) carries machine-checked receipts in `formal_mage` (Lean 4, core library, kernel-checked, axiom-audited). `node tools/formal_census.mjs <this repo>` in formal_mage fails if a tag names a theorem outside the audited census.

| Claim | Code | Status | Tag |
|---|---|---|---|
| The root `merkle_root` returns is a tree's root over exactly the leaves; a proof that climbs to it carries one of them (sha256 collision-free; 0x00/0x01 tags) | `kappa.py` merkle_root / merkle_verify | proved (code loop) | formal: proved formal_mage:Formal.MerkleCode.code_disclosure_sound |
| Every proof `merkle_proof` generates climbs to the root | `kappa.py` merkle_proof | proved (code loop) | formal: proved formal_mage:Formal.MerkleCode.proof_complete |
| Two different duplicate-free leaf lists never share a root | `kappa.py` merkle_root | proved (code loop) | formal: proved formal_mage:Formal.MerkleInj.codeRoot_injective |
| The condition is needed: `[a,b,c]` and `[a,b,c,c]` share a root, which is why every minter and verifier reads the leaf set as a set (bundle.py since 2026-10-25) | `bundle.py`, `verify_bundle.py`, `site_check` | proved | formal: proved formal_mage:Formal.MerkleInj.dup_collision |
| A link chain's head determines every link behind it | `site_check` step 6 | proved | formal: proved formal_mage:Formal.Chain.head_determines |
| `flashprove/verify-rerun/1` recomputes the truth of each `proven-reply` row (the verifier re-runs `cp_verify` on the sealed bytes); fails without the verifier as an unknown rule would; refuses a changed proof carrying the old verdict | `verify_bundle.py` rule_flashprove_verify_rerun | proved (model of the rule) | formal: proved formal_mage:Formal.ProvenLeaf.rerun_sound · formal: proved formal_mage:Formal.ProvenLeaf.rerun_refuses_without_verifier · formal: proved formal_mage:Formal.ProvenLeaf.rerun_detects_change |
