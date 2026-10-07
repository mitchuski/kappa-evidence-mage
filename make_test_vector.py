"""make_test_vector.py - the fixed cross-implementation vector for P1 (see P1_RUST_CHECK.md).
Every expected value is produced by kappa.py and must equal what kappa-core @ 2af8656 computes
for the same inputs. Until that run, each is "kappa-compatible (unverified)"."""
import json
import kappa as K

V = {}
V["text 'test'"] = {"input": "kappa_from_value(&\"test\".to_string())", "dcbor_hex": K.encode("test").hex(),
                    "kappa": K.kappa_from_value("test")}
V["u64 42"] = {"input": "kappa_from_value(&42u64)", "dcbor_hex": K.encode(42).hex(), "kappa": K.kappa_from_value(42)}
V["f64 1.5"] = {"input": "kappa_from_value(&1.5f64)", "dcbor_hex": K.encode(1.5).hex(), "kappa": K.kappa_from_value(1.5)}
V["f64 39.85"] = {"input": "kappa_from_value(&39.85f64)  (a ledger cpu_s)", "dcbor_hex": K.encode(39.85).hex(),
                  "kappa": K.kappa_from_value(39.85)}
V["bytes 'hello world'"] = {"input": "kappa_from_bytes(b\"hello world\")", "kappa": K.kappa_from_bytes(b"hello world")}
e = K.edge_record("sha256:aa", "sha256:bb", "derived-from", "anchor-x")
V["Edge minimal"] = {"input": "Edge{source:\"sha256:aa\",target:\"sha256:bb\",relation:DerivedFrom,asserter:\"anchor-x\",value_kappa:None,metadata:None}",
                     "dcbor_hex": K.encode(e).hex(), "kappa": K.kappa_from_value(e)}
e2 = K.edge_record("sha256:aa", "sha256:bb", "composed-of", "anchor-x", value_kappa="sha256:cc", metadata=b"\x01\xff")
V["Edge full"] = {"input": "Edge{..., relation:ComposedOf, value_kappa:Some(\"sha256:cc\"), metadata:Some(vec![1,255])}",
                  "dcbor_hex": K.encode(e2).hex(), "kappa": K.kappa_from_value(e2)}
V["NodeAnchor ed25519 [1u8;32]"] = {"input": "NodeAnchor::from_key(\"ed25519\", &[1u8; 32]).as_str()  (conformance tests/crypto.rs:90)",
                                    "dcbor_hex": K.encode(K.anchor_input("ed25519", bytes([1]*32))).hex(),
                                    "kappa": K.anchor_from_key("ed25519", bytes([1]*32))}
call = {0: "agentprivacy-evidence/call/1", 1: 0, 2: "s1_le60", 3: "SAT", 4: 14.63, 5: 38.75, 6: 1.1, 7: 39.85,
        8: 1021624, 9: 12, 10: 7104299, 11: "2026-10-05T18:58:25", 13: "ledger.jsonl", 14: "hashsmash/sha256-r32"}
V["call/1 row 0 (s1_le60)"] = {"input": "dcbor::Map with integer keys as listed in SCHEMA.md; values: text/u64/f64",
                               "value": {str(k): v for k, v in call.items()},
                               "dcbor_hex": K.encode(call).hex(), "kappa": K.kappa_from_value(call)}
V["merkle root of [a,b,c]"] = {"input": "merkle_root(&[b\"a\", b\"b\", b\"c\"])", "hex": K.merkle_root([b"a", b"b", b"c"]).hex()}
out = {"status": K.STATUS, "upstream": K.UPSTREAM, "vectors": V}
json.dump(out, open("test_vector.json", "w"), indent=1)
for k, v in V.items():
    print(f"{k:32s} {v.get('kappa', v.get('hex'))}")
