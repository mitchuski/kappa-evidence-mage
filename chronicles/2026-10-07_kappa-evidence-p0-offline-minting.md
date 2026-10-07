# 2026-10-07 - kappa_evidence P0: the r32 search ledger minted offline, unverified by design

**VERDICT: P0 of the kappa-addressed evidence-ledger plan is BUILT and self-consistent, and
every kappa it minted is labelled "kappa-compatible (unverified)" because the one check that
would promote it (equality with the compiled Rust `kappa_from_value`) needs cargo, and cargo
needs the WSL box that the r32 blind route search owns. A pure-Python `kappa.py` passes the
upstream dCBOR library's own 33 encode vectors, the registry's blob-kappa test and the merkle
rule; `mint_r32.py` turns the seat's 62 exported ledger rows into 68 objects, 4 blobs and 201
typed edges under one run root; `verify_r32.py`, seeing only the bundle, recomputes 59 calls
and 593,858.32 CPU-s, the figures the v5 claim quotes, and rejects a one-byte tamper on four
independent checks. The lane is shaped to merge into the solver mages, hashsmash first,
sig_mage next, per the First Person's direction that the Yukon solvers are the first
experiment.**

## What happened, in order

1. Read the proposal note (hashsmash_mage/notes, 2026-10-07) and re-verified its source
   citations against the clone at 2af8656: `kappa_from_value` = SHA-256 over dCBOR
   (compute.rs:149, canonical.rs:22); the `Edge` struct's permanent integer keys
   (types.rs:377-394); the 17 `EdgeRelation` discriminants (types.rs:233-268); the anchor
   derivation (crypto/anchor.rs:14-27); merkle leaf/node prefixes and odd-leaf promotion
   (merkle.rs:10-67).
2. The dCBOR rules the registry inherits live in a git-pinned dependency
   (bc-dcbor-rust, branch feat/dcbor-derive, 2e5b901 per Cargo.lock). No local copy existed,
   so it was cloned into the session scratchpad, read-only. A first clone landed by
   mistake under hashsmash_mage/work/sha256/vendor and was removed the same minute; nothing
   else there was touched.
3. Three encoding facts were taken from that source, not assumed: float numeric reduction
   and shortest-exact f16/f32/f64 (src/float.rs:51-85); map keys sorted bytewise by their
   encoded form (src/map.rs:17); and the derive's struct rules (dcbor-derive/src/lib.rs:
   maps with integer keys, None omitted, unit enums as bare integers). The surprise is
   F-E1: `Vec<u8>` fields take the generic `From<Vec<T>>` path (src/array.rs:46) and encode
   as an array of integers. Edge.metadata and AnchorInput.public_key are such fields.
4. Wrote `kappa.py` to mirror all of it, and `test_kappa.py` whose expected bytes are copied
   from tests/encode.rs and the conformance crate. 0 failures.
5. Reconciled the ledger on the Windows side without the WSL file: the seat's export
   (ledger_export/, 14:01 today) has 57 rows; ledger_cal_manual has 5. The note's "59-call
   ledger" = 62 minus start, start2 and the zero-CPU ERROR row for s2_le160 that the
   ABANDONED row supersedes. Sum 593,858.32, equal to R32_LOG.md. Inputs snapshotted
   read-only with SHA-256 sums; scanned clean of paths, hosts and names.
6. Minted, verified, tamper-tested. Wrote SCHEMA.md (permanent keys), P1_RUST_CHECK.md (a
   scratch crate beside the clone; the clone is never edited) and test_vector.json.
7. Checked the repo state the First Person asked about: uor_kappa_mage was level with
   origin/main (1fcfd58) before this directory was added; upstream kappa-registry main is
   still 2af8656 (ls-remote), so the vendored clone is current. Nothing pushed.

## What this changes for the lane

- The uor_kappa_mage survey closed on selection (PATHWAY sections 5-6). This is the first
  selection actually built, and it is not a credential note: it is the registry's
  content-addressing used as the evidence spine of a solver run. The trust-graph notes
  (01-06) remain the vocabulary for P4, when assertions and co-author credit become signed
  edges.
- The three findings F-E1..F-E3 are candidates for the upstream notes: an independent
  implementer who reads "Vec<u8>" as a byte string computes different anchors.

## Open

- P1: the cargo run (after WSL frees). Until then no minted kappa is cited anywhere.
- The judge-facing shape (bundle + verifier inside the package) is designed, not yet put in a
  package; that is the hashsmash v7 decision, the First Person's.
- Whether this becomes its own top-level mage directory is the First Person's call; it sits
  here as briefed.
