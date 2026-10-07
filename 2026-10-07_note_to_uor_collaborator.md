# Note to the UOR contact - 2026-10-07 - ready to send

Lane-internal framing (not part of the message): this follows the uor_kappa_mage conventions
for outward contact. The door is Mitch's alone; this file prepares, it does not send. Same
shape as ISSUE_DRAFT.md: arrive with the understanding done, cite shipped code at file and
line, state what is unverified as unverified, offer small concrete pieces, and let the
maintainer say what matters. Upstream house rules kept: ASCII punctuation, no AI
attribution, no private paths or hosts. Nothing here has been posted or pushed.

---

Hey - a follow-up with something built rather than surveyed.

Since the convergence notes (https://github.com/mitchuski/uor-kappa-mage), I have put
kappa-registry's content addressing to work on a concrete problem I have right now: the
evidence behind a benchmark submission. On one of the Yukon solver challenges my measured
search cost got copied verbatim into other people's packages, with and without credit, and
the only proof of origin today is a PR number and a matching decimal. The judge, for its
part, prices auditability: a package failed on "participant-reported only" evidence. A
kappa graph answers both at once. Every solver call is an object, the ledger is a list of
their kappas, the totals are derived objects, and a run root sits over all of it. Reuse of a
measurement is then reuse of my object, byte for byte, and a verifier recomputes the totals
from the root without trusting me.

What exists as of today, offline and on Windows (no registry running yet):

- a pure-Python mirror of kappa_from_value: SHA-256 over canonical dCBOR
  (kappa-core/src/kappa/compute.rs:149, canonical.rs:22), with the Edge struct's integer
  keys (types.rs:377-394), the EdgeRelation discriminants (types.rs:233-268), the anchor
  derivation (crypto/anchor.rs:14-27) and the merkle leaf/node rule (merkle.rs:10-67);
- it passes the dCBOR library's own encode vectors (bc-dcbor-rust at 2e5b901, the pin in
  your Cargo.lock) and your conformance blob-kappa test;
- one real ledger minted: 59 solver calls, 593,858.32 CPU-seconds, as 68 objects, 4 blobs
  and 201 typed edges (composed-of, derived-from, evidence-provenance, section-of,
  refers-to) under one run root, with a verifier that sees only the bundle and recomputes
  the totals; a one-byte tamper fails four independent checks.

I am labelling every kappa "kappa-compatible (unverified)" until I can run the same vector
through the compiled crate, which is a cargo job queued behind a long solver run on my box.
Two things I found on the way are the reason I am writing before that run, because you can
answer them in a minute and I cannot:

1. In the derive, a Vec<u8> field goes through dcbor's generic From<Vec<T>>
   (src/array.rs:46) and so encodes as a CBOR array of unsigned integers, not a byte
   string. Edge.metadata and AnchorInput.public_key are such fields, so an anchor is
   sha256 over {0: "ed25519", 1: [1, 1, 1, ...]} rather than over a 32-byte string. Is that
   the intended canonical form, or a derive gap? Any independent implementation that
   reads "Vec<u8>" as bytes computes different anchors and different edge kappas. If it is
   intended, it deserves a sentence in the README's identity section; if it is a gap, I can
   send a PR with a byte-string specialisation plus the vector that catches it, but the
   change would re-key every existing anchor, so that is your call, not mine.
2. Option fields that are None are omitted from the map rather than encoded as null
   (dcbor-derive/src/lib.rs:10). Fine and compact; also worth one line in the docs, since
   it is the other place an outside implementer guesses wrong.

Both are mirrored in my code either way. A third, smaller offer: kappa-conformance has
determinism tests for structured values but no fixed-hex vectors for Edge, AnchorInput or
TagEntry. I have a ten-line vector set ready (primitives, two Edge shapes, the anchor from
your crypto.rs:90 test key, a merkle root) that I would be glad to PR as a conformance test
once my own cargo run confirms the numbers.

The rest of the plan, if you want to see where it goes: a local registry next (bundle, fresh
store, re-ingest, identical root), then the harness phases emitting their own kappas and
edges, then signed assertions for co-author credit under an anchor. Not asking you to carry
any of it; pointing at what you think matters is enough.

---

Attachments to send with it, if the channel allows files: `test_vector.json` and
`P1_RUST_CHECK.md` from this directory. Do not send `out/r32/` or `input/r32/` until the
hashsmash package decision is made (private shared work stays private).
