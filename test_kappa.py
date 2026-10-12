"""Golden tests for kappa.py.

Every expected value below is copied from the upstream sources, not invented here:
  - bc-dcbor-rust @ 2e5b901 tests/encode.rs (encode_unsigned, encode_float, encode_map,
    encode_anders_map, encode_bytes, encode_string, encode_value, encode_nan)
  - kappa-registry @ 2af8656 crates/kappa-conformance/tests/kappa_label.rs (blob kappa)
  - kappa-core/src/merkle.rs unit tests (structure; roots recomputed from the stated rule)
Run: python test_kappa.py
"""
import hashlib
import sys

import kappa as K

VECTORS = [
    # encode.rs encode_unsigned / negative
    (0, "00"), (23, "17"), (255, "18ff"), (65536, "1a00010000"),
    (4294967295, "1affffffff"), (4294967296, "1b0000000100000000"),
    (18446744073709551615, "1bffffffffffffffff"),
    (-1, "20"), (-2, "21"), (-127, "387e"), (-128, "387f"), (-32768, "397fff"),
    (-9223372036854775807, "3b7ffffffffffffffe"),
    # encode.rs encode_float (shortest exact form, numeric reduction)
    (1.5, "f93e00"), (2345678.25, "fa4a0f2b39"), (1.2, "fb3ff3333333333333"),
    (float("inf"), "f97c00"), (float("-inf"), "f9fc00"), (float("nan"), "f97e00"),
    (42.0, "182a"), (2345678.0, "1a0023cace"), (-2345678.0, "3a0023cacd"), (-0.0, "00"),
    (5.960464477539063e-8, "f90001"), (1.401298464324817e-45, "fa00000001"),
    (5e-324, "fb0000000000000001"), (2.2250738585072014e-308, "fb0010000000000000"),
    (6.103515625e-5, "f90400"), (65504.0, "19ffe0"), (33554430.0, "1a01fffffe"),
    (-9223372036854774784.0, "3b7ffffffffffffbff"),
    # encode.rs encode_value
    (False, "f4"), (True, "f5"),
    # encode.rs encode_bytes / encode_string
    (K.ByteString(bytes.fromhex("00112233")), "4400112233"),
    (K.ByteString(bytes.fromhex("112233")), "43112233"),
    ("Hello", "6548656c6c6f"),
    # encode.rs encode_array / encode_map (key order bytewise by encoded key)
    ([], "80"), ({}, "a0"),
    ({-1: 3, (-1,): 7, "z": 4, 10: 1, False: 8, 100: 2, "aa": 5, (100,): 6},
     "a80a011864022003617a046261610581186406812007f408"),
    ({1: 45.7, 2: "Hi there!"}, "a201fb4046d9999999999a0269486920746865726521"),
    # NFC: "e" + combining acute -> U+00E9 (encode.rs line 319: 6365cc81 is the NFD form,
    # which dCBOR rejects; the canonical form is the composed one)
    ("e\u0301", "62c3a9"),
]

fails = 0
for value, hexexp in VECTORS:
    got = K.encode(value).hex()
    ok = got == hexexp
    fails += not ok
    print(("ok  " if ok else "FAIL"), ascii(value)[:50], got if not ok else "")

# derive quirk: Vec<u8> field -> array of unsigned ints (dcbor src/array.rs:46)
got = K.encode({1: K.RustBytes(bytes([1, 2, 200]))}).hex()
ok = got == "a1018301021 8c8".replace(" ", "")
fails += not ok
print(("ok  " if ok else "FAIL"), "RustBytes as int array", got)

# kappa_label.rs blob_kappa_is_sha256
k = K.kappa_from_bytes(b"hello world")
ok = k == "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
fails += not ok
print(("ok  " if ok else "FAIL"), "kappa_from_bytes(hello world)")
assert K.verify_kappa(k, b"hello world") and not K.verify_kappa(k, b"different")

# kappa_from_value("test") = sha256 over dCBOR text; determinism is all upstream asserts
assert K.kappa_from_value("test") == K.kappa_from_value("test")
assert K.kappa_from_value("test") == K.kappa_from_bytes(bytes.fromhex("6474657374"))

# merkle.rs: single leaf = hash_leaf; two = node(l, r); three = node(node(a,b), node(c,c))
hl, hn = K.hash_leaf, K.hash_node
assert K.merkle_root([b"only leaf"]) == hl(b"only leaf")
assert K.merkle_root([b"left", b"right"]) == hn(hl(b"left"), hl(b"right"))
assert K.merkle_root([b"a", b"b", b"c"]) == hn(hn(hl(b"a"), hl(b"b")), hn(hl(b"c"), hl(b"c")))
assert K.merkle_root([b"a", b"b", b"c", b"d"]) == hn(hn(hl(b"a"), hl(b"b")), hn(hl(b"c"), hl(b"d")))
assert K.merkle_root([]) is None
leaves = [b"l0", b"l1", b"l2", b"l3", b"l4"]
root = K.merkle_root(leaves)
for i, leaf in enumerate(leaves):
    assert K.merkle_verify(root, leaf, K.merkle_proof(leaves, i)), i
assert not K.merkle_verify(root, b"wrong", K.merkle_proof(leaves, 0))
assert K.merkle_proof(leaves, 5) is None
print("ok   merkle structure (single/two/three/four leaves, proofs for five)")

# edge record shape: None fields omitted, relation as bare integer
e = K.edge_record("sha256:aa", "sha256:bb", "derived-from", "anchor")
assert K.encode(e).hex() == K.encode({0: "sha256:aa", 1: "sha256:bb", 2: 11, 3: "anchor"}).hex()
e2 = K.edge_record("s", "t", "composed-of", "a", value_kappa="v", metadata=b"\x01\xff")
assert K.decode(K.encode(e2)) == {0: "s", 1: "t", 2: 1, 3: "a", 4: "v", 5: [1, 255]}
print("ok   edge record shape")

# decoder round trip rejects non-canonical input (canonical.rs rejects_non_canonical)
try:
    K.decode(bytes.fromhex("1900ff"))
    print("FAIL non-canonical accepted"); fails += 1
except ValueError:
    print("ok   non-canonical 1900ff rejected")

print("FAILURES:", fails)
# -- blake3 axis: upstream vectors (kappa-core/src/kappa/tests.rs:13-16) -------------------------
def test_blake3_axis():
    import kappa as K
    assert K.kappa_blake3_from_bytes(b"") == "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    assert K.kappa_blake3_from_bytes(b"hello") == "blake3:ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
    assert K.verify_kappa("blake3:ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f", b"hello")
    print("ok   blake3 axis: EMPTY_BLAKE3, HELLO_BLAKE3")


test_blake3_axis()
sys.exit(1 if fails else 0)
