# P1 passes, and the label was in the root (2026-10-08, written from the sig_mage seat)

The cross-implementation check ran today, while the WSL box was free between two Lean builds. Rust kappa_core, built
from the vendored clone's own kappa-core source, and kappa.py agree on all ten lines of the fixed vector: text, integer,
two floats, bytes, both Edge shapes, the NodeAnchor, the call/1 row and the merkle root. P1_RESULT.md records the run and
every deviation needed to make cargo 1.96 build the clone: a copy with the root `[[test]]` block gone, the scratch crate
seated as a workspace member so there is one dcbor, dcbor pinned to the lock's rev, and the lock itself set aside because
this cargo cannot read it. The clone was not touched.

One correction to the plan. The status label is not metadata beside the bundle: it is field 5 of the run-root object, so
it is hashed into the root kappa. "Flip the label" therefore means "mint again". kappa.py now says "kappa-verified at
2af8656", and the two sig_mage bundles were re-minted under it; their merkle roots over the leaves did not move, only the
root kappa did. The r32 bundle keeps the old status until its own session re-mints it.

The first bundle minted under the verified status is the H2 gate evidence for the record the sig_mage lane submitted
today (52144f3d, S 5,454): root sha256:8c1c1c0db94f6457d5335e353cd7bab244d733cc0be4031b7042cfbbf8adfa41. Its root line is
written into the lane's next submission note, as the early easter egg the keeper asked for.
