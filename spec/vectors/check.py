"""Independent check of the Mohar test vectors, written in Python with no code shared with the Rust
implementation. Usage: python check.py v1.json   (needs: pip install cryptography)

JCS (RFC 8785) matches json.dumps(sort_keys=True, separators=(",", ":")) for these vectors because they
hold only ASCII strings and integers; a general implementation needs a full JCS library.
"""
import json, hashlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
v = json.load(open(sys.argv[1], encoding="utf-8"))
canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["public_key"].split(":")[1]))
prev = "sha256:" + "0" * 64
for i, item in enumerate(v["receipts"]):
    r = item["receipt"]
    assert canon(r).hex() == item["canonical_hex"], f"canonical bytes differ at {i}"
    h = "sha256:" + hashlib.sha256(canon(r)).hexdigest()
    assert h == item["sha256"], f"hash differs at {i}"
    assert r["prev"] == prev, f"chain link broken at {i}"
    unsigned = {k: val for k, val in r.items() if k != "sig"}
    pub.verify(bytes.fromhex(r["sig"].split(":")[1]), canon(unsigned))
    prev = h
c = v["checkpoint"]
assert c["head"] == prev and c["count"] == len(v["receipts"])
pub.verify(bytes.fromhex(c["sig"].split(":")[1]), canon({k: val for k, val in c.items() if k != "sig"}))
print("independent check ok:", len(v["receipts"]), "receipts and the checkpoint")
