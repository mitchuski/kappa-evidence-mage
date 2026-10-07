# 2026-10-07 (afternoon) - sig_mage H2 gate evidence minted; the verifier caught a stale layout

**VERDICT: the second Yukon lane went through the same code within the hour, and the first
thing the graph did was refuse a stale constant. The sig_mage lead's read-only snapshot of
the H2 emulator gate for record b96b3ca (23 files, sums checked, leak-scanned clean) minted
into 67 objects, 17 blobs and 139 typed edges under one run root. The lane-neutral verifier
recomputes every gate fact from the rows (24/24 honest ok, witness_equal 24/24, verify delta
max 0, sign delta cycles {1048}, extra_compr == c; 28/28 tamper and 2/2 cross rejected) and
PASSES them, then FAILS the images check: `images_h2/layout.json` declares the base hashes
and base instruction counts for sign and expand, while the H2 image bytes are 19 and 64
words longer, exactly the sizes in the patch report. The images are right; the layout was
never regenerated. The failure stands, the lead was told, and every kappa remains
"kappa-compatible (unverified)" pending the cargo check.**

## In order

1. The First Person named the lane "kappa evidence mage"; the directory moved from
   `uor_kappa_mage/kappa_evidence/` to `~/kappa_evidence_mage/`; uor_kappa_mage README,
   PATHWAY and its chronicle now point at the sibling. uor_kappa_mage upstream re-check:
   main still 2af8656.
2. Read the sig_mage analysis of the day (agentprivacy-docs/research/
   2026-10-07_v7_openai_math_sig_mage.md, section 3): one reproducible optimization dossier
   per lever, failed candidates preserved. Same shape as this graph; recorded in README.
3. Wrote the send-ready note to the UOR contact in the ISSUE_DRAFT voice: what was built,
   the Vec<u8>-as-array question (F-E1), the None-omitted note (F-E2), the offer of a fixed
   conformance vector. The door is the First Person's; nothing sent.
4. The sig_mage lead session (another Claude session on this machine) announced the
   snapshot by cross-session message. Copied read-only, 23/23 sums OK, scanned clean.
5. Factored `bundle.py` out of the r32 adapter, wrote `mint_sig_h2.py` and
   `verify_bundle.py`. The r32 bundle re-verifies OK under the neutral verifier (same
   59 / 593,858.32).
6. The images check compares each image blob's kappa with the sha256 its side's
   layout.json declares. Base: 4/4 match. H2: keygen and verify match (byte-identical to
   base), sign and expand do not. Diagnosis by byte lengths: sign.code 83328 B = 20813 + 19
   words, expand.code 168824 B = 42142 + 64 words. Stale layout, not a bad image.
7. Reported to the lead session with the numbers and the fix (re-hash, instructions = code
   bytes / 4, re-export; the root kappa will change, which is the point). The lead's harness
   task card asks for an "Evidence root:" line in submission notes and a constants-refuter
   seat; the images check is that seat's first instance.

## Resolution (same afternoon)

The lead confirmed the cause (h2_patch.py copied the base layout.json through and rewrote only
signatureBytes; seven H2 image dirs affected; nothing downstream read the two fields), fixed the
generator, added a relayout tool, regenerated all seven dirs and re-exported the snapshot. Re-minted:
sums OK, images check passes, verifier RESULT OK. Run root moved from sha256:f8e5f72bc229...
(stale snapshot, superseded) to sha256:8c5209a6fb733b8951e1f4269c8857fcae5137a1a795a5a438f03b7b781abe2d.
The correction is on record as two roots, not as an overwrite.

## Open

- P1 cargo check after WSL frees; the note to the UOR contact waits on the First Person.
- Not a git repo yet; nothing pushed anywhere.
