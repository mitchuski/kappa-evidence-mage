# Contributing

Thanks for looking. This project is small on purpose: one core module, one minter, one
verifier, and a registry of shapes. Contributions that keep it that way are the easiest to
accept.

## Ground rules

- **No third-party packages.** The core, the minter and the verifiers run on the Python 3
  standard library alone, so a reader can audit everything a verification depends on.
- **Bytes are the contract.** Any change that alters the encoding of an existing shape
  changes every κ minted since. Integer keys in `SCHEMA.md` are permanent; new fields are
  optional and omitted when absent, so older objects encode exactly as before.
- **Schema first.** A new object shape or a new `check/1` rule is added to `SCHEMA.md` before
  any bundle uses it, and to `verify_bundle.py` in the same change. A verifier that meets an
  unknown rule must fail.
- **A fact must be recomputable.** A rule takes a ledger's rows and returns the facts. If the
  verifier cannot recompute a fact from sealed bytes, it does not belong in a `check/1`.
- **Upstream is mirrored, never patched.** `kappa.py` follows `kappa-core` at the pinned
  commit. If you believe upstream behaviour is wrong, raise it upstream; here we match it.

## Before you open a pull request

```sh
python test_kappa.py                  # must print FAILURES: 0
python example_mint.py
python verify_bundle.py out/example   # must end RESULT: OK
```

If you touched the encoder, also regenerate the cross-implementation vector with
`python make_test_vector.py` and confirm `test_vector.json` did not change. If it did, the
change is a breaking one: say so in the pull request and explain why.

## Good first contributions

- A verifier in another language, held to `test_vector.json`.
- A lane adapter for a new kind of evidence (see "Adding a lane" in the README).
- Clearer errors from `verify_bundle.py` when a bundle fails.
- Test vectors for edge cases of the dCBOR rules (floats, NFC, map ordering).

## What stays out

- Minted bundles and lane snapshots (`out/`, `input/`). Bundles are published with the work
  they seal, not here.
- Private paths, host names or credentials. The minter redacts them and the verifier scans
  for them; a pull request that needs an exception will be declined.

## Licence of contributions

By contributing you agree that your code is offered under MIT OR Apache-2.0 and your
documentation under CC BY 4.0, as described in `LICENSE.md`.
