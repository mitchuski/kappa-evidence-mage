# Evidence object schemas (integer keys, PERMANENT)

Convention copied from kappa-registry: every object is a dCBOR map with small integer keys;
the key numbers never change (changing one changes every kappa minted since). Optional keys
are omitted when absent, never null. Namespace prefix: `agentprivacy-evidence`.

## call/1 - one solver call, as the seat's ledger recorded it

| key | field | type | note |
|---|---|---|---|
| 0 | schema | text | `agentprivacy-evidence/call/1` |
| 1 | seq | uint | position in the source files (exported rows first, then cal/manual) |
| 2 | tag | text | e.g. `s1_le21`, `p4_le76` |
| 3 | result | text | SAT / UNSAT / TIMEOUT / ERROR / ABANDONED |
| 4 | wall_s | float | `/usr/bin/time -v` elapsed |
| 5 | user_s | float | |
| 6 | sys_s | float | |
| 7 | cpu_s | float | user + sys, as the seat charged it |
| 8 | maxrss_kb | uint | peak RSS in KiB |
| 9 | threads | uint | optional |
| 10 | cvc_bytes | uint | optional; size of the STP model fed to the call |
| 11 | t_end | text | optional; ISO local time the seat wrote |
| 12 | note | text | optional; redacted of paths and hosts |
| 13 | source_file | text | basename of the ledger file the row came from |
| 14 | lane | text | `hashsmash/sha256-r32` |

What is deliberately NOT here: the model bytes themselves (the cvc kappa and the solver
build kappa are P3, when the 19 MB models can be hashed on the WSL side), any path, any host.

## ledger/1 - an ordered list of calls

0 schema, 1 name, 2 array of call kappas in seq order, 3 lane, 4 description.
`composed-of` edges go ledger -> each call. A ledger that is a subset of another carries a
`section-of` edge to it.

## summary/1 - totals the verifier recomputes

0 schema, 1 ledger kappa, 2 n_calls, 3 cpu_s_total rounded to 2 dp, 4 peak maxrss_kb,
5 cpu_h rounded to 2 dp. `derived-from` edge summary -> ledger. The rounding rule is part of
the schema: sum the call `cpu_s` floats in seq order, round half-even to 2 dp.

## run-root/1

0 schema, 1 lane, 2 minted_on (ISO date), 3 array of [name, kappa] pairs sorted by name,
4 provisional merkle root (hex) over every object, blob and edge kappa string in the bundle
except the root itself and its own edges, 5 status label, 6 asserter, 7 upstream pins.
`composed-of` edges root -> ledgers and summaries.

The merkle root is PROVISIONAL: it uses merkle.rs's leaf/node rule over kappa strings, but
the registry's real namespace root is over tag entries and is signed. P1 replaces it.

## Blobs

Raw bytes, kappa = `kappa_from_bytes` (no dCBOR wrapping). Used for the source ledger files
and the package files (claim.json, proof.md). `evidence-provenance` edges call -> source
blob; `derived-from` edges package blob -> search ledger and summaries.

## Edges

Exactly the upstream `Edge` struct (types.rs:377-394) so a P1 registry can ingest them:
{0 source, 1 target, 2 relation as the EdgeRelation integer, 3 asserter, [4 value_kappa],
[5 metadata as an array of uint, the derive's Vec<u8> encoding]}. Asserter is the placeholder
`unsigned:hashsmash_mage` until P4 gives the lane an anchor key; the registry would reject a
placeholder asserter, which is intended: these edges are offline records, not registry edges
yet.

## Bundle layout

```
out/<lane>/objects/<hex>.cbor   canonical dCBOR, file name = kappa hex
out/<lane>/blobs/<hex>.bin      raw bytes
out/<lane>/edges/<hex>.cbor     Edge records
out/<lane>/root.json            root kappa, status, counts, names (metadata, not hashed)
out/<lane>/graph.json           everything decoded, for reading
out/<lane>/REPORT.md
```
