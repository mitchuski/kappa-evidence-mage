"""kappa.py - kappa-labels for evidence objects, mirroring kappa-registry (2af8656).

Pure Python 3, no third-party packages. Mirrors, line for line where it matters:

  kappa_from_bytes(b)  = "sha256:" + hex(SHA-256(b))        kappa-core/src/kappa/compute.rs:140
  kappa_from_value(v)  = kappa_from_bytes(dCBOR(v))         compute.rs:149, canonical.rs:22
  dCBOR rules          = bc-dcbor-rust @ 2e5b901 (the pinned git dependency in Cargo.lock):
     - integers shortest form; floats reduced to integers when integral, else the shortest of
       f16/f32/f64 that round-trips exactly (src/float.rs:51-85)
     - map keys sorted bytewise by their encoded form (src/map.rs:17)
     - text strings NFC (src/string.rs)
     - NaN canonical 0xf97e00, +/-inf as f16
  derive(CBORCodable)  = dcbor-derive/src/lib.rs: a struct is a map with integer keys; an
     Option field that is None is OMITTED; a unit enum variant is a bare integer; and a
     Vec<u8> field goes through the generic From<Vec<T>> (src/array.rs:46), so it encodes as a
     CBOR ARRAY of unsigned integers, not a byte string. Edge.metadata and
     AnchorInput.public_key are such fields. We mirror that exactly (rust_bytes()).
  Edge record          = map {0 source, 1 target, 2 relation(int), 3 asserter,
                              [4 value_kappa], [5 metadata as int array]}   types.rs:377-394
  EdgeRelation ints    = types.rs:233-268
  Merkle               = leaf 0x00 || data, node 0x01 || l || r, odd leaf hashed with
                         itself, SHA-256                                     merkle.rs:10-67

Status label for every value produced here until P1 runs the Rust crate's own test:
    "kappa-compatible (unverified)".
"""
from __future__ import annotations

import hashlib
import math
import struct
import unicodedata

STATUS = "kappa-verified at 2af8656"  # P1 passed 2026-10-08 (P1_RESULT.md); was "kappa-compatible (unverified)"
UPSTREAM = {"kappa-registry": "2af8656", "bc-dcbor-rust": "2e5b901 (branch feat/dcbor-derive)"}

# ---------------------------------------------------------------- dCBOR encoding


class RustBytes(bytes):
    """A Rust Vec<u8> field: encodes as an ARRAY of unsigned ints (derive quirk)."""


class ByteString(bytes):
    """A real CBOR byte string (major type 2), as dcbor::ByteString would give."""


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    if n < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")
    raise ValueError("integer out of CBOR range")


def _encode_int(i: int) -> bytes:
    if i >= 0:
        return _head(0, i)
    return _head(1, -1 - i)


def _encode_float(x: float) -> bytes:
    if math.isnan(x):
        return b"\xf9\x7e\x00"
    if math.isinf(x):
        return b"\xf9\x7c\x00" if x > 0 else b"\xf9\xfc\x00"
    if x == math.floor(x):  # numeric reduction (covers -0.0 -> 0)
        i = int(x)
        if -0x10000000000000000 <= i < 0x10000000000000000:
            return _encode_int(i)
    # shortest exact float: the Rust path tries f32 then f16 inside f32_cbor_data
    try:
        f32 = struct.unpack(">f", struct.pack(">f", x))[0]
    except OverflowError:
        f32 = None
    if f32 is not None and f32 == x:
        try:
            f16 = struct.unpack(">e", struct.pack(">e", x))[0]
        except OverflowError:
            f16 = None
        if f16 is not None and f16 == x:
            return b"\xf9" + struct.pack(">e", x)
        return b"\xfa" + struct.pack(">f", x)
    return b"\xfb" + struct.pack(">d", x)


def encode(v) -> bytes:
    """Canonical dCBOR bytes of a Python value.

    bool -> simple; None -> null; int; float; str (NFC text); ByteString -> byte string;
    RustBytes -> array of ints; list/tuple -> array; dict -> map (keys sorted bytewise).
    """
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        return _encode_int(v)
    if isinstance(v, float):
        return _encode_float(v)
    if isinstance(v, str):
        s = unicodedata.normalize("NFC", v).encode("utf-8")
        return _head(3, len(s)) + s
    if isinstance(v, RustBytes):
        return _head(4, len(v)) + b"".join(_encode_int(b) for b in v)
    if isinstance(v, (ByteString, bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b"".join(encode(x) for x in v)
    if isinstance(v, dict):
        items = sorted((encode(k), encode(val)) for k, val in v.items())
        keys = [k for k, _ in items]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate map keys after canonical encoding")
        return _head(5, len(items)) + b"".join(k + val for k, val in items)
    raise TypeError(f"no dCBOR encoding for {type(v).__name__}")


# ---------------------------------------------------------------- kappa labels


def kappa_from_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def kappa_from_value(v) -> str:
    return kappa_from_bytes(encode(v))


# ---------------------------------------------------------------- blake3 axis (pure Python)
# Upstream: KappaLabel::blake3 = "blake3:" + hex(BLAKE3-256(content)), compute.rs:30; a first-class axis
# beside the default sha256 (kappa_from_bytes stays sha256, compute.rs:140; sha256 is the mandatory
# axis in multi-axis computation, compute.rs:253). Unkeyed BLAKE3, full tree mode, 32-byte output.
# No third-party packages: this is the blake3_mage reduced-round implementation at the full 7 rounds,
# held to upstream's EMPTY_BLAKE3 / HELLO_BLAKE3 vectors (kappa-core/src/kappa/tests.rs:13-16).

_B3_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
_B3_PERM = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_M32 = 0xFFFFFFFF


def _b3_compress(h, m, t, blen, flags):
    def g(v, a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) & _M32; v[d] = ((v[d] ^ v[a]) >> 16 | (v[d] ^ v[a]) << 16) & _M32
        v[c] = (v[c] + v[d]) & _M32;     v[b] = ((v[b] ^ v[c]) >> 12 | (v[b] ^ v[c]) << 20) & _M32
        v[a] = (v[a] + v[b] + y) & _M32; v[d] = ((v[d] ^ v[a]) >> 8 | (v[d] ^ v[a]) << 24) & _M32
        v[c] = (v[c] + v[d]) & _M32;     v[b] = ((v[b] ^ v[c]) >> 7 | (v[b] ^ v[c]) << 25) & _M32
    v = list(h) + list(_B3_IV[:4]) + [t & _M32, (t >> 32) & _M32, blen, flags]
    m = list(m)
    for _ in range(7):
        g(v, 0, 4, 8, 12, m[0], m[1]); g(v, 1, 5, 9, 13, m[2], m[3])
        g(v, 2, 6, 10, 14, m[4], m[5]); g(v, 3, 7, 11, 15, m[6], m[7])
        g(v, 0, 5, 10, 15, m[8], m[9]); g(v, 1, 6, 11, 12, m[10], m[11])
        g(v, 2, 7, 8, 13, m[12], m[13]); g(v, 3, 4, 9, 14, m[14], m[15])
        m = [m[i] for i in _B3_PERM]
    return [v[i] ^ v[i + 8] for i in range(8)]


def _b3_words(b: bytes):
    b = b.ljust(64, b"\0")
    return [int.from_bytes(b[4 * i:4 * i + 4], "little") for i in range(16)]


def blake3_digest(data: bytes) -> bytes:
    START, END, PARENT, ROOT = 1, 2, 4, 8

    def chunk_cv(chunk, ctr, root):
        blocks = [chunk[i:i + 64] for i in range(0, len(chunk), 64)] or [b""]
        h = _B3_IV
        for i, bl in enumerate(blocks):
            f = (START if i == 0 else 0) | (END if i == len(blocks) - 1 else 0)
            if root and i == len(blocks) - 1:
                f |= ROOT
            h = _b3_compress(h, _b3_words(bl), ctr, len(bl), f)
        return h
    chunks = [data[i:i + 1024] for i in range(0, len(data), 1024)] or [b""]
    if len(chunks) == 1:
        out = chunk_cv(chunks[0], 0, True)
    else:
        cvs = [chunk_cv(c, i, False) for i, c in enumerate(chunks)]

        def merge(cv, root):
            if len(cv) == 1:
                return cv[0]
            k = 1
            while k * 2 < len(cv):
                k *= 2
            return _b3_compress(_B3_IV, merge(cv[:k], False) + merge(cv[k:], False), 0, 64,
                                PARENT | (ROOT if root else 0))
        out = merge(cvs, True)
    return b"".join(w.to_bytes(4, "little") for w in out)


def kappa_blake3_from_bytes(data: bytes) -> str:
    """KappaLabel::blake3 - the blake3 axis label of raw bytes."""
    return "blake3:" + blake3_digest(data).hex()


def kappa_blake3_from_value(v) -> str:
    """blake3 axis over the same canonical dCBOR bytes the sha256 kappa uses."""
    return kappa_blake3_from_bytes(encode(v))


def verify_kappa(kappa: str, data: bytes) -> bool:
    axis, _, hexd = kappa.partition(":")
    if axis == "sha256":
        return hashlib.sha256(data).hexdigest() == hexd
    if axis == "blake3":
        return blake3_digest(data).hex() == hexd
    raise ValueError(f"axis {axis} is not implemented here (sha256, blake3 are)")


def split_kappa(kappa: str) -> tuple[str, str]:
    axis, _, hexd = kappa.partition(":")
    return axis, hexd


# ---------------------------------------------------------------- typed edges

EDGE_RELATION = {
    "owns": 0, "composed-of": 1, "assertion": 2, "revocation": 3, "capability": 4,
    "recovery-share": 5, "epoch-root": 6, "akd-tree-node": 7, "chunk-manifest": 8,
    "witness-receipt": 9, "offload-receipt": 10, "derived-from": 11, "certified-by": 12,
    "evidence-provenance": 13, "section-of": 14, "refers-to": 15, "delegation": 16,
}
RELATION_NAME = {n: s for s, n in EDGE_RELATION.items()}


def edge_record(source: str, target: str, relation: str, asserter: str,
                value_kappa: str | None = None, metadata: bytes | None = None) -> dict:
    """The upstream Edge struct as a dCBOR value (types.rs:377-394). None fields are omitted."""
    rec = {0: source, 1: target, 2: EDGE_RELATION[relation], 3: asserter}
    if value_kappa is not None:
        rec[4] = value_kappa
    if metadata is not None:
        rec[5] = RustBytes(metadata)
    return rec


def edge_kappa(*args, **kw) -> str:
    return kappa_from_value(edge_record(*args, **kw))


def anchor_input(algorithm: str, public_key: bytes) -> dict:
    """crypto/anchor.rs:14-27 - AnchorInput {0 algorithm, 1 public_key: Vec<u8>}."""
    return {0: algorithm, 1: RustBytes(public_key)}


def anchor_from_key(algorithm: str, public_key: bytes) -> str:
    return kappa_from_value(anchor_input(algorithm, public_key))


# ---------------------------------------------------------------- merkle (merkle.rs)


def hash_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes | None:
    if not leaves:
        return None
    level = [hash_leaf(x) for x in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            l = level[i]
            r = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(hash_node(l, r))
        level = nxt
    return level[0]


def merkle_proof(leaves: list[bytes], index: int) -> list[tuple[bytes, bool]] | None:
    """(sibling, sibling_is_left) pairs from leaf level up, as merkle.rs:74."""
    if index >= len(leaves):
        return None
    level = [hash_leaf(x) for x in leaves]
    proof = []
    while len(level) > 1:
        sib = index ^ 1
        if sib >= len(level):
            sib = index
        proof.append((level[sib], sib < index))
        nxt = []
        for i in range(0, len(level), 2):
            l = level[i]
            r = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(hash_node(l, r))
        level = nxt
        index //= 2
    return proof


def merkle_verify(root: bytes, leaf_data: bytes, proof: list[tuple[bytes, bool]]) -> bool:
    cur = hash_leaf(leaf_data)
    for sib, is_left in proof:
        cur = hash_node(sib, cur) if is_left else hash_node(cur, sib)
    return cur == root


# ---------------------------------------------------------------- minimal decoder (for verify)


def decode(data: bytes):
    """Decode canonical dCBOR produced by encode(); rejects what it cannot re-encode identically."""
    v, n = _dec(data, 0)
    if n != len(data):
        raise ValueError("trailing bytes")
    if encode(v) != data:
        raise ValueError("non-canonical input")
    return v


def _dec(b: bytes, i: int):
    ib = b[i]
    major, ai = ib >> 5, ib & 0x1F
    i += 1
    if major == 7:
        if ai == 20:
            return False, i
        if ai == 21:
            return True, i
        if ai == 22:
            return None, i
        if ai == 25:
            return struct.unpack(">e", b[i:i + 2])[0], i + 2
        if ai == 26:
            return struct.unpack(">f", b[i:i + 4])[0], i + 4
        if ai == 27:
            return struct.unpack(">d", b[i:i + 8])[0], i + 8
        raise ValueError("unsupported simple value")
    if ai < 24:
        n = ai
    elif ai == 24:
        n, i = b[i], i + 1
    elif ai == 25:
        n, i = int.from_bytes(b[i:i + 2], "big"), i + 2
    elif ai == 26:
        n, i = int.from_bytes(b[i:i + 4], "big"), i + 4
    elif ai == 27:
        n, i = int.from_bytes(b[i:i + 8], "big"), i + 8
    else:
        raise ValueError("indefinite length not allowed in dCBOR")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major == 2:
        return ByteString(b[i:i + n]), i + n
    if major == 3:
        return b[i:i + n].decode("utf-8"), i + n
    if major == 4:
        out = []
        for _ in range(n):
            x, i = _dec(b, i)
            out.append(x)
        return out, i
    if major == 5:
        out = {}
        for _ in range(n):
            k, i = _dec(b, i)
            val, i = _dec(b, i)
            out[k] = val
        return out, i
    raise ValueError("tags not supported")
