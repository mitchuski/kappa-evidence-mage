# P1: the cross-implementation check (runs after WSL frees; needs cargo)

Goal: prove `kappa.py` equals `kappa_core::kappa::kappa_from_value` byte for byte on the
fixed vector in `test_vector.json`. Until this passes, every kappa in `out/` carries the
label "kappa-compatible (unverified)". When it passes, the label changes to
"kappa-verified at 2af8656" and nothing else in the bundle changes (the labels are
metadata in root.json and REPORT.md, not inputs to any hash).

Do NOT edit the vendored clone. Make a scratch crate beside it that depends on it by path.

```
mkdir -p ~/uor_kappa_mage/kappa_evidence/p1_check && cd $_
cargo init --name p1_check
```

Cargo.toml (the dcbor git pin must match the clone's Cargo.lock, so copy the clone's
`[workspace.dependencies] dcbor` line verbatim):

```toml
[dependencies]
kappa-core = { path = "../../../kappa-registry-main/crates/kappa-core" }
dcbor = { git = "https://github.com/usrbinkat/bc-dcbor-rust", branch = "feat/dcbor-derive", features = ["derive", "multithreaded"] }
hex = "0.4"
```

src/main.rs:

```rust
use dcbor::prelude::*;
use kappa_core::kappa::{kappa_from_bytes, kappa_from_value};
use kappa_core::types::{Edge, EdgeRelation};
use kappa_core::crypto::anchor::NodeAnchor;
use kappa_core::merkle::merkle_root;

fn main() {
    println!("text 'test'        {}", kappa_from_value(&"test".to_string()));
    println!("u64 42             {}", kappa_from_value(&42u64));
    println!("f64 1.5            {}", kappa_from_value(&1.5f64));
    println!("f64 39.85          {}", kappa_from_value(&39.85f64));
    println!("bytes hello world  {}", kappa_from_bytes(b"hello world"));
    let e = Edge { source: "sha256:aa".into(), target: "sha256:bb".into(),
        relation: EdgeRelation::DerivedFrom, asserter: "anchor-x".into(),
        value_kappa: None, metadata: None };
    println!("Edge minimal       {}", kappa_from_value(&e));
    let e2 = Edge { source: "sha256:aa".into(), target: "sha256:bb".into(),
        relation: EdgeRelation::ComposedOf, asserter: "anchor-x".into(),
        value_kappa: Some("sha256:cc".into()), metadata: Some(vec![1, 255]) };
    println!("Edge full          {}", kappa_from_value(&e2));
    println!("NodeAnchor         {}", NodeAnchor::from_key("ed25519", &[1u8; 32]).as_str());
    let mut m = Map::new();
    m.insert(0, "agentprivacy-evidence/call/1"); m.insert(1, 0u64); m.insert(2, "s1_le60");
    m.insert(3, "SAT"); m.insert(4, 14.63f64); m.insert(5, 38.75f64); m.insert(6, 1.1f64);
    m.insert(7, 39.85f64); m.insert(8, 1021624u64); m.insert(9, 12u64); m.insert(10, 7104299u64);
    m.insert(11, "2026-10-05T18:58:25"); m.insert(13, "ledger.jsonl"); m.insert(14, "hashsmash/sha256-r32");
    let c: CBOR = m.into();
    println!("call/1 row 0       {}", kappa_from_value(&c));
    println!("merkle [a,b,c]     {}", hex::encode(merkle_root(&[b"a", b"b", b"c"]).unwrap()));
}
```

Run `cargo run --release` and diff each line against `python make_test_vector.py`.
Also run the crate's own tests once: `cargo test -p kappa-core kappa` (read-only on the clone;
the target dir can be redirected with `CARGO_TARGET_DIR` to keep the clone untouched).

Known risk to watch: `metadata: Some(vec![1,255])` and the anchor's `public_key` go through
dcbor's generic `From<Vec<T>>` (src/array.rs:46) and therefore encode as an ARRAY of
integers. kappa.py mirrors that (`RustBytes`). If the derive branch has since gained a
`Vec<u8>` byte-string specialisation, those two lines will differ and the Python side is the
one to change (it is a mirror, not a standard).
