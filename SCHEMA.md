# Evidence object schemas (integer keys, PERMANENT)

Convention copied from kappa-registry: every object is a dCBOR map with small integer keys;
the key numbers never change (changing one changes every kappa minted since). Optional keys
are omitted when absent, never null. Namespace prefix: `agentprivacy-evidence`. Two
implementations mint and verify these shapes and are held equal on a fixed vector:
`kappa.py` here and `tools/dcbor.mjs` + `tools/kappa_evidence.mjs` in the harness.

This file is the registry of shapes. A new shape is added here first, with its permanent
keys, before any bundle uses it.

## The bundle

```
<bundle>/objects/<hex>.cbor   canonical dCBOR, file name = kappa hex
<bundle>/blobs/<hex>.bin      raw bytes (kappa_from_bytes, no dCBOR wrapping)
<bundle>/edges/<hex>.cbor     Edge records
<bundle>/root.json            root kappa, status, counts, names, optional signature (metadata, not hashed)
<bundle>/graph.json           everything decoded, for readers
<bundle>/REPORT.md
```

Rules every bundle obeys:
- a file's name is its content's kappa; objects and edges re-encode byte-identically;
- every ledger row carries an `evidence-provenance` edge to a blob in the same bundle;
- a `check/1` or `summary/1` is recomputed from its ledger's rows under its named rule;
- the provisional merkle root (`run-root/1` key 4) is over every object, blob and edge
  kappa string except the root itself and its own edges, merkle.rs leaf/node rule;
- text that becomes a blob is hashed as git stores it: LF line endings, user paths and host
  names redacted (`[redacted]`), and the bundle directory is marked `-text` in
  `.gitattributes` so a checkout never rewrites the bytes;
- every kappa is labelled `kappa-compatible (unverified)` until the P1 cargo check.

## Objects

### run-root/1

0 schema, 1 lane, 2 minted_on (ISO date), 3 array of [name, kappa] pairs sorted by name,
4 provisional merkle root (hex), 5 status label, 6 asserter, 7 upstream pins,
[8 extra: a text-keyed map of lane facts, e.g. {runId, status, sourceHash, run_blob}].
`composed-of` edges root -> ledgers, summaries, checks, images.

Asserter is a placeholder string (`unsigned:<lane>`) until a key exists. With a key
(harness `--sign`), the asserter is the registry anchor `kappa_from_value({0 algorithm,
1 public_key as int array})` and root.json carries `signature: {by_anchor, by_did, alg,
over: root kappa, sig}`; the signature is metadata and never part of a preimage.

### ledger/1

0 schema, 1 name, 2 array of row kappas in order, 3 lane, 4 description.
`composed-of` edges ledger -> each row; `section-of` to a ledger it is a subset of.

### summary/1 (hashsmash r32 totals)

0 schema, 1 ledger kappa, 2 n_calls, 3 cpu_s_total rounded half-even to 2 dp, 4 peak
maxrss_kb, 5 cpu_h rounded to 2 dp. `derived-from` edge summary -> ledger. Rule: sum the
rows' `cpu_s` in seq order.

### check/1 (facts under a named rule)

0 schema, 1 ledger kappa, 2 rule name, 3 facts (text-keyed map). `derived-from` edge check
-> ledger. The verifier recomputes the facts from the ledger's rows under the rule and
requires equality. Registered rules:

| rule | rows | facts |
|---|---|---|
| `rows/count/1` | any | {n} |
| `harness/run-tally/1` | harness-verdict/1 | {n, validated, statuses sorted} |
| `sig-golf/h2-honest/1` | record/1 kind honest | {n, ok, witness_equal, compact_ok, verify_delta_max, sign_delta_cycles, sign_delta_compr, extra_compr_eq_c, expand_max, verify_max} |
| `sig-golf/all-ok/1` | record/1 kind tamper / cross / exhaust | {n, ok, exits sorted} |

### call/1 (one solver call, hashsmash r32)

0 schema, 1 seq, 2 tag, 3 result, 4 wall_s, 5 user_s, 6 sys_s, 7 cpu_s, 8 maxrss_kb,
[9 threads], [10 cvc_bytes], [11 t_end], [12 note, redacted], 13 source_file, 14 lane.

### record/1 (a generic row)

0 schema, 1 seq, 2 kind (text), 3 fields (text-keyed map, values as the source gave them,
text redacted), 4 lane. Used for the sig gate rows (kinds honest / exhaust / tamper /
cross / failures), the calibration tables, the judge digests, the ABBA sessions, the census
reports, and any table minted by the demos' `mint_rows.mjs`.

### images/1 (sig_mage program images)

0 schema, 1 lane, 2 {side: {program: {code: blob kappa, data: blob kappa}}} for sides
`base` and `h2`, 3 {side: layout.json blob kappa}, 4 {patch, kit_files, kit_base: blob
kappas}. The verifier checks every image blob's kappa hex against the sha256 its side's
layout.json declares, and reports which programs are byte-identical across sides. This is
the check that caught a stale layout on 2026-10-07.

### harness-proposal/1, harness-gap/1, harness-verdict/1 (dual-agent-harness runs)

- proposal: 0 schema, 1 seq, 2 runId, 3 roundId, 4 proposal dir name, 5 leverId, 6 canon
  blob kappa (the proposal_canon.json bytes). `evidence-provenance` -> canon blob.
- gap: 0 schema, 1 proposal kappa, 2 seedHex, [3 hSource], 4 hProposal, [5 salt], 6 mode,
  7 N, 8 count, 9 drawIndices. `derived-from` -> proposal; `evidence-provenance` -> gap.json
  blob. The verifier requires hProposal == the canon blob's kappa hex: the witnesses were
  drawn from a kappa the prover could not choose.
- verdict: 0 schema, 1 proposal kappa, 2 status, [3 metric], [4 gateResult], 5 evidence
  text. `derived-from` -> proposal; `evidence-provenance` -> verdict.json blob;
  `refers-to` -> candidate.md blob when present.

### sources/1 (prose behind a kappa)

0 schema, 1 lane, 2 array of [published name, blob kappa, bytes, origin note]; the origin
note says `redacted copy of ~/...` when the blob is a redacted LF copy. `composed-of` edges
sources -> each blob. Minted by the demos' `mint_sources.mjs`.

### transform/1 (the pair: a reader bound to its evidence)

0 schema, 1 reader kappa (sha256 of the HTML bytes; a reader never contains its own kappa),
2 evidence root kappa, 3 generator kappa (sha256 of the generator source), 4 date, 5 lane.
Minted by the demos' `pair.mjs`; the demos' own root (`mint_demos.mjs`) is a ledger of these
with `derived-from` edges to the roots they cite, which may live in other bundles.

## Edges

Exactly the upstream `Edge` struct (types.rs:377-394): {0 source, 1 target, 2 relation as
the EdgeRelation integer, 3 asserter, [4 value_kappa], [5 metadata as an array of uint, the
derive's Vec<u8> encoding]}. Relations used: composed-of (1), derived-from (11),
evidence-provenance (13), section-of (14), refers-to (15).

## Blobs

Raw bytes; kappa = `kappa_from_bytes`. A blob's kappa is also the sha256 the lane's own
tools report for the file (ledger exports, layouts, canon files), which is why the gap seed
check and the images check work without any new convention.
