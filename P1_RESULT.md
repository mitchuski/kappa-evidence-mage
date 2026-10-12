# P1 result — kappa.py == kappa_core::kappa::kappa_from_value on the fixed vector (2026-10-08 13:24Z)

**PASS: 10 / 10 lines identical** (text, u64, f64 1.5, f64 39.85, bytes, Edge minimal, Edge full, NodeAnchor, call/1 row 0, merkle [a,b,c]).
Rust output: `p1_run.out` (cargo 1.96.1 / rustc 1.96.1 in WSL Ubuntu). Python output: `p1_py_vector.txt` (= `python make_test_vector.py`).
The harness JS twin (`dual-agent-harness/tools/kappa_evidence.test.mjs`) could not be compared: it fails its own
assertion at line 94 ("bad signature detected") before printing the vector; that is the harness session's uncommitted work.

How it was run (`p1_run.sh`): the vendored clone `~/kappa-registry-main` (kappa-registry 2af8656) was never edited. A
WSL-side copy `~/kappa-registry-p1` differs from it only by: the root `[[test]]` block removed (cargo 1.96 rejects it in
a virtual manifest; the clone pins rust 1.95); the scratch crate `p1_check` added as a workspace member (so it shares
one dcbor); the workspace dcbor spec changed from `branch = "feat/dcbor-derive"` to `rev = "2e5b901e8c9946794c5491cf92eeec2540b84261"`
(the rev the clone's Cargo.lock pins); and the clone's Cargo.lock removed (cargo 1.96 cannot parse it: `inventory` listed
twice), so every other dependency resolved fresh. kappa-core's source is byte-identical to the clone's.
Earlier attempts and why they failed: path dependency + dcbor rev -> two dcbor versions in the graph (branch and rev are
different source ids); member + the clone's lock -> lock unparseable.

Consequence: `kappa.py` STATUS is now "kappa-verified at 2af8656". NOTE (corrects P1_RUST_CHECK.md): the status is field 5
of the run-root/1 object, so it IS an input to the root kappa; a label change means a re-mint with a new root kappa (the
merkle root over the leaves is unchanged, since the root object is not a leaf). Re-minted here: out/sig_h2_52144f3d and
out/sig_h2_b96b3ca (old roots sha256:738b23ac… and sha256:8c5209a6… superseded; both still addressable from their inputs
by re-running the old STATUS). out/r32 left for the hashsmash/kappa session to re-mint under the new STATUS.
