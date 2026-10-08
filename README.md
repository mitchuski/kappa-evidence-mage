# kappa_evidence_mage - kappa-addressed evidence ledgers for the dual-agent harness

Its own mage since 2026-10-07 (named "kappa evidence mage" by the First Person; built that
morning as `uor_kappa_mage/kappa_evidence/`, which still links here). It builds and proves
one thing, and what it proves is shaped to merge into the solver mages (hashsmash_mage
first, sig_mage next) rather than to live apart from them. The First Person's direction:
the Yukon solver lanes are the first experiment, so idea -> implementation -> test fits
inside the days of a leaderboard push. Lineage: uor_kappa_mage (the registry survey, notes
01-06) supplies the vocabulary; the vendored clone `~/kappa-registry-main` @ 2af8656 is
others' work, never edited.

The sig_mage analysis of the same day (agentprivacy-docs/research/
2026-10-07_v7_openai_math_sig_mage.md, section 3) asks for one "reproducible optimization
dossier" per lever: contract revision, candidate digest, formal statement and its
dependencies, executable image digests, signature and witness budgets, charged cost, with
empirical traces kept apart and failed candidates preserved. That dossier is this graph's
shape exactly: each item an object with a kappa, `derived-from` edges to the candidate and
the pinned contract, and killed levers that stay addressable. The sig_mage adapter maps the
dossier fields onto objects here instead of inventing a second format.

Source proposal: `~/hashsmash_mage/notes/2026-10-07_kappa_evidence_ledger_research_note.md`
(P0-P4 plan). This directory is P0 and the seam for P1.

## What is here

| file | role |
|---|---|
| `kappa.py` | canonical dCBOR + SHA-256 mirroring kappa-core @ 2af8656 and bc-dcbor-rust @ 2e5b901; Edge records; anchor input; merkle |
| `test_kappa.py` | golden tests: every expected byte copied from the upstream test suites (33 encode vectors + blob kappa + merkle + edge shape) |
| `mint_r32.py` | mints the r32 search ledger into a bundle under `out/r32/` |
| `verify_r32.py` | re-derives the r32 bundle from its root alone: hashes, canonical form, composed-of walk, totals, merkle, leak scan |
| `bundle.py` | shared minting helper (objects, blobs, typed edges, ledgers, checks, run root, bundle on disk) |
| `mint_sig_h2.py` | the sig_mage adapter: H2 gate rows, images, patch report -> `out/sig_h2_b96b3ca/` |
| `verify_bundle.py` | lane-neutral verifier for any bundle (recomputes summary/1 and check/1 facts by rule name; checks images against their layout hashes) |
| `input/sig_h2_b96b3ca/` | read-only snapshot from the sig_mage lead, SHA256SUMS checked |
| `PROVERB.md` | the prophecy proverb, its kappa, and the rule for where it goes |
| `2026-10-07_note_to_uor_collaborator.md` | send-ready note to the UOR contact (the First Person sends) |
| `make_test_vector.py` / `test_vector.json` | the fixed cross-implementation vector for P1 |
| `P1_RUST_CHECK.md` | how to run the Rust side of that check (scratch crate; the clone stays untouched) |
| `SCHEMA.md` | the object schemas with their permanent integer keys |
| `input/r32/` | read-only snapshot (chmod 444) of the seat's exported ledger rows and the v5 package files, hashes in `input/r32_SHA256SUMS.txt` |
| `out/r32/` | the minted bundle: 68 objects, 4 blobs, 201 edges, `root.json`, `graph.json`, `REPORT.md` |

## Status of every kappa: "kappa-compatible (unverified)"

The Python encoder passes the upstream library's own vectors, so the primitives are right.
What is NOT yet proven is equality with `kappa_from_value` as compiled, for the struct
shapes (Edge, AnchorInput, our call maps). That is P1, a cargo run after WSL frees. Until
then no kappa here should be cited as a registry kappa.

## What P0 established (2026-10-07)

- The r32 search ledger reconciles exactly: 57 exported rows + 5 cal/manual rows = 62;
  minus the two starting-solution runs and the superseded zero-CPU ERROR row = 59 calls,
  593,858.32 CPU-s, peak RSS 5,510,088 KiB. These are the figures in R32_LOG.md and the v5
  claim, now recomputed by a verifier that sees only the bundle.
- Run root: see `out/r32/REPORT.md`. Tampering one byte of one call object fails four
  independent checks (name hash, composed-of walk, ledger listing, merkle root).
- Finding F-E1: the upstream derive encodes `Vec<u8>` fields (Edge.metadata, the anchor's
  public_key) through dcbor's generic `From<Vec<T>>` (src/array.rs:46), i.e. as an ARRAY of
  unsigned integers, not a byte string. An independent implementation that uses a byte
  string would compute different anchors and edge kappas. Mirrored here; flagged for the
  upstream notes.
- Finding F-E2: `Option` fields that are None are omitted from the map, not encoded as null
  (dcbor-derive/src/lib.rs:10). Also mirrored.
- Finding F-E3: upstream main is still 2af8656 (checked 2026-10-07 with ls-remote); the
  vendored clone is current.

## sig_mage next: the H2 gate evidence minted (2026-10-07, afternoon)

The sig_mage lead session exported a read-only snapshot of the H2 emulator-gate evidence for
record b96b3ca (23 files, SHA256SUMS all checked, leak-scanned clean) and this mage minted it
through the same code: `bundle.py` (shared helper) + `mint_sig_h2.py` (the adapter) +
`verify_bundle.py` (lane-neutral; also re-verifies the r32 bundle). Bundle at
`out/sig_h2_b96b3ca/`: 67 objects, 17 blobs, 139 edges; gate rows as `record/1` objects in
four ledgers (24 honest, 2 exhaust, 28 tamper, 2 cross) each with a `check/1` the verifier
recomputes from the rows (24/24 ok, witness_equal 24/24, verify delta max 0, sign delta
cycles {1048}, extra_compr == c; tamper 28/28 and cross 2/2 rejected); the eight base and
eight H2 program images as blobs with `derived-from` edges H2 -> base image + patch report.

- Finding F-E4 (a stale constant, caught by the verifier): `images_h2/layout.json` declares
  the BASE sha256 and instruction counts for sign and expand, while the H2 image bytes are
  19 and 64 words longer, exactly the patch sizes. The images are right; the layout file
  was not regenerated after the patch. The verifier FAILS the images check on those two
  entries; reported to the lead session, which confirmed the cause (the patch generator
  copied the base layout through and rewrote only signatureBytes, across all seven H2
  image dirs; nothing downstream read those fields), fixed the generator, regenerated and
  re-exported. RE-MINTED on the re-export the same afternoon: the images check passes and the
  bundle verifies clean. New run root sha256:8c5209a6fb73...; the stale-snapshot root
  sha256:f8e5f72bc229... is superseded, kept on record, not cited.
- The lead's harness task card (agentprivacy-docs/plans/KAPPA_EVIDENCE_HARNESS_TASK_2026-10-07.md)
  asks for two things beyond P0: an `Evidence root: sha256:...` line in submission notes,
  and a constants-refuter seat that re-reads a record's constants at the named commit
  before a build. The second is what the images check already does for hashes and sizes;
  generalising it to the other constants is the next adapter step.

## Harness integration (2026-10-07, evening)

The agentprivacy dual-agent harness (`~/dual-agent-harness`, uncommitted there; the First Person
commits) now carries the registry axis natively: `tools/dcbor.mjs` is an independent JS
implementation of this encoder, `tools/kappa_evidence.mjs` mints a run's record into the same
bundle layout (`mint | verify | root`, optional `--sign` with an ephemeral ed25519 key whose
registry anchor becomes the edges' asserter), and `tools/check.mjs` runs the 61-check test and
verifies every minted bundle on each gate run. The two encoders agree on the fixed struct vector
(`test_vector.json`), and `verify_bundle.py` here accepts the JS-minted harness bundle
(rule `harness/run-tally/1`). That is a two-implementation agreement, not the P1 cargo check.
Also in the harness: an `Evidence root:` section in the chronicle template, a
`seats/constants-refuter.md` seat card, and a HOLONS.md section on the two axes.

Leak-scan pattern aligned across both implementations: user paths (drive-letter and POSIX),
home dirs and host names; not bare names, since public handles appear legitimately in content.

## What changed in how kappa is used (2026-10-08), and what this mage now carries

- **A twin implementation.** `tools/dcbor.mjs` in the harness is an independent JS encoder;
  the two agree on the fixed struct vector (`test_vector.json`, embedded in the harness test).
  Two encoders agreeing is not the P1 cargo check, but it means a byte-level mistake in one
  would have shown as a disagreement, and none did.
- **More shapes.** `SCHEMA.md` is the registry: record/1 (generic rows), check/1 with a rule
  table, images/1, the three harness objects, sources/1 (prose behind a kappa), transform/1 (a
  reader bound to its evidence root). A new shape is written there before a bundle uses it.
- **More minters, elsewhere.** The harness mints runs (`tools/kappa_evidence.mjs`, 34 runs
  minted); the demos repo mints sources, rows and the demos root (`tools/mint_sources.mjs`,
  `mint_rows.mjs`, `mint_demos.mjs`, `pair.mjs`). This mage keeps the Python mirror, the two
  lane adapters (r32, sig H2), the schema registry and the verifier that reads every bundle
  the others produce.
- **Verifier parity.** `verify_bundle.py` now also checks harness-gap seeds against their canon
  blob kappa and images against their layout hashes, and reports a root signature when present
  (ed25519 itself is checked by the harness verifier only; no third-party packages here).
- **Clone safety, F-E5 and F-E6.** A kappa'd blob must survive `git clone`: bundle directories are
  marked `-text` in `.gitattributes`, and text is hashed as git stores it (LF, redacted).
  Without that, a Windows checkout with newline conversion rewrites every blob and every
  verify fails; found and fixed in both public repos. Separately, the harness has a
  177-character tracked path, so Windows clones need `core.longpaths`.
- **The pair is an object.** transform/1 binds a reader's kappa to the evidence root it was
  generated from and the generator's kappa; sixteen pairs sit under the demos root
  `sha256:ad4e115f...`. The transformation creates the pair, as the First Person put it.

Public homes: this mage at github.com/mitchuski/kappa-evidence-mage; the harness tools at
github.com/mitchuski/agentprivacy-harness; the readers and pairs at
github.com/mitchuski/agentprivacy-harness-demos. `out/` and `input/` stay local here.

## Boundaries

- Windows only, no WSL (the r32 blind route search owns it). No cargo on this side.
- The vendored clone `~/kappa-registry-main` is never edited. The dcbor derive source was
  cloned into the session scratchpad for reading only.
- Pushed 2026-10-08 (public). uor_kappa_mage still holds the uncommitted links to this sibling.
- Private paths and hosts are scanned out of every object; the inputs were clean already.
- No asserter key exists at P0: edges carry a placeholder asserter and are offline records.

## Merge path into the solver mages

Each solver mage gets a thin `mint_<lane>.py` that maps its own ledger rows onto call/1 and
calls `kappa.py`; the verifier is lane-neutral already. The package then carries three
things the judge can run inside its sandbox: the bundle, `verify_<lane>.py` with `kappa.py`,
and the root kappa quoted in proof.md. For sig_mage the rows are the sigmage gate ledger;
for hashsmash the blind route search ledger (`ledger_route.jsonl`) joins the same root when
it lands (P3).

## Next

- P1 (after WSL frees): run `P1_RUST_CHECK.md`; flip the label; add the signed namespace
  root and inclusion proofs from a local registry.
- Then decide whether the v7 r32 note cites the ledger kappa and the root.
