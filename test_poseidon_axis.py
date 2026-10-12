"""Hold kappa.py's Poseidon axis equal to the HashSmash organizer reference.

Reference: hashsmash-pareto verifier/poseidon.py (Orchard P128Pow5T3, halo2_poseidon 0.2.0 constants),
loaded by path WITHOUT running verifier/__init__.py (which pulls the full verifier). Checks:
  - poseidon_permute == reference permute on random canonical states at r = 0, 1, 2, 5, 56
  - lane-0 digests of random 64-byte canonical encodings == reference digest at the same r
  - poseidon2 == reference ConstantLength<2> (r=56, capacity 2^65)
  - the two organizer-certified collisions (r=1, r=2) collide here and differ at other r
  - sponge / Merkle rules on small hand-checkable cases
Run: python test_poseidon_axis.py   (override paths with POSEIDON_REF / POSEIDON_CERTS env vars)
"""
import importlib.util
import os
import random
import sys
import types

import kappa as K

REF = os.environ.get("POSEIDON_REF", os.path.expanduser("~/poseidon_mage/hashsmash-pareto/verifier"))
CERTS = os.environ.get("POSEIDON_CERTS", os.path.expanduser("~/poseidon_mage/work/counted"))


def load_reference():
    pkg = types.ModuleType("hs_ref_verifier"); pkg.__path__ = [REF]; sys.modules["hs_ref_verifier"] = pkg
    for name in ("errors", "poseidon"):
        spec = importlib.util.spec_from_file_location(f"hs_ref_verifier.{name}", os.path.join(REF, f"{name}.py"))
        mod = importlib.util.module_from_spec(spec); sys.modules[spec.name] = mod; spec.loader.exec_module(mod)
    return sys.modules["hs_ref_verifier.poseidon"]


fails = 0


def check(cond, msg):
    global fails
    if not cond:
        fails += 1
        print("FAIL", msg)


def main():
    R = load_reference()
    P = K.POSEIDON_P
    check(R.P == P, "modulus")
    rng = random.Random(20261012)
    n = 0
    for r in (0, 1, 2, 5, 56):
        for _ in range(6):
            st = (rng.randrange(P), rng.randrange(P), rng.randrange(P))
            check(K.poseidon_permute(st, r) == R.permute(st, r), f"permute r={r}"); n += 1
            msg = rng.randrange(P).to_bytes(32, "little") + rng.randrange(P).to_bytes(32, "little")
            a, b = int.from_bytes(msg[:32], "little"), int.from_bytes(msg[32:], "little")
            check(K.poseidon_permute((a, b, 1 << 65), r)[0].to_bytes(32, "little") == R.digest(msg, r), f"digest r={r}"); n += 1
        check(K.poseidon_permute((0, 0, 0), r) == R.permute((0, 0, 0), r), f"permute zero r={r}"); n += 1
    for _ in range(4):
        a, b = rng.randrange(P), rng.randrange(P)
        check(K.poseidon2(a, b) == R.permute((a, b, 1 << 65), 56)[0], "poseidon2"); n += 1
    print(f"ok   {n} permutation/digest checks vs reference at r = 0, 1, 2, 5, 56")

    for r, sub in ((1, "out_r1_v4/package_r1"), (2, "out_r2_v4/package_r2")):
        d = os.path.join(CERTS, sub, "certificates")
        ma, mb = (open(os.path.join(d, f), "rb").read() for f in ("message-a.bin", "message-b.bin"))
        ea = [int.from_bytes(ma[i:i + 32], "little") for i in (0, 32)]
        eb = [int.from_bytes(mb[i:i + 32], "little") for i in (0, 32)]
        check(ma != mb and all(x < P for x in ea + eb), f"certificate r={r} canonical, distinct")
        da = K.poseidon_permute((*ea, 1 << 65), r)[0]; db = K.poseidon_permute((*eb, 1 << 65), r)[0]
        check(da == db, f"certificate r={r} collides under kappa.py")
        check(R.digest(ma, r) == R.digest(mb, r) == da.to_bytes(32, "little"), f"certificate r={r} reference agrees")
        for other in (0, 3, 56):
            if other != r:
                check(K.poseidon_permute((*ea, 1 << 65), other)[0] != K.poseidon_permute((*eb, 1 << 65), other)[0],
                      f"certificate r={r} differs at r={other}")
        print(f"ok   certified r={r} collision: digest {da.to_bytes(32, 'little').hex()[:16]}..")

    # sponge rule, recomputed by hand for short inputs
    check(K.poseidon_digest(b"") == K.poseidon2(0, 1).to_bytes(32, "little"), "sponge empty")
    check(K.poseidon_digest(b"a") == K.poseidon2(1, 0x61 | (1 << 8)).to_bytes(32, "little"), "sponge 'a'")
    x30 = bytes(range(30)); c = int.from_bytes(x30 + b"\x01", "little")
    check(K.poseidon_digest(x30) == K.poseidon2(30, c).to_bytes(32, "little"), "sponge 30 bytes, one chunk")
    x31 = bytes(range(31)); c1 = int.from_bytes(x31, "little")
    check(K.poseidon_digest(x31) == K.poseidon2(K.poseidon2(31, c1), 1).to_bytes(32, "little"), "sponge 31 bytes, two chunks")
    # Merkle rule
    lf = lambda s: int.from_bytes(K.poseidon_digest(b"\x00" + s.encode()), "little")
    check(K.poseidon_merkle_hex([]) is None, "merkle empty")
    check(K.poseidon_merkle_hex(["a"]) == lf("a").to_bytes(32, "little").hex(), "merkle single")
    abc = K.poseidon2(K.poseidon2(lf("a"), lf("b")), K.poseidon2(lf("c"), lf("c")))
    check(K.poseidon_merkle_hex(["a", "b", "c"]) == abc.to_bytes(32, "little").hex(), "merkle a,b,c")
    kv = K.kappa_poseidon_from_value({0: "x"})
    check(kv == "poseidon:" + K.poseidon_digest(K.encode({0: "x"})).hex() and K.verify_kappa(kv, K.encode({0: "x"})), "kappa label")
    print("ok   sponge poseidon-orchard-chain/1, Merkle twin, kappa label")
    print(f"{'FAIL' if fails else 'PASS'} ({fails} failures)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
