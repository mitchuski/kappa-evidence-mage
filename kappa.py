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

STATUS = "kappa-compatible (unverified)"
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


def verify_kappa(kappa: str, data: bytes) -> bool:
    axis, _, hexd = kappa.partition(":")
    if axis != "sha256":
        raise ValueError("only the sha256 axis is implemented here")
    return hashlib.sha256(data).hexdigest() == hexd


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
