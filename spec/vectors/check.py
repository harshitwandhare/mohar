"""Independent check of the Mohar test vectors, written in Python with no code shared with the Rust
implementation. Needs: pip install cryptography

    python check.py v1.json                  check the byte-for-byte vectors
    python check.py conformance-v1.json      check every conformance case reaches its expected level
    python check.py --log DIR [--pinned-key FILE] [--checkpoints FILE ...]
                                             report the level (spec/receipts-v1.md) a log reaches

JCS (RFC 8785) matches json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False) for
receipts and checkpoints: every key is ASCII, the only numbers are integers below 2**53, and Python
escapes control characters the way RFC 8785 does. A general implementation needs a full JCS library.
"""
import hashlib, json, os, re, sys, tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

GENESIS = "sha256:" + "0" * 64
FIELDS = {
    None: {"v", "seq", "prev", "ts", "agent", "action", "decision", "sig", "verification"},
    "agent": {"id", "key"},
    "action": {"capability", "tool", "target", "args_sha256"},
    "decision": {"result", "level", "by", "review"},
    "verification": {"evidence_sha256", "kind", "of", "result"},
}
CHECKPOINT_FIELDS = {"v", "count", "head", "ts", "sig"}

canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
digest = lambda o: "sha256:" + hashlib.sha256(canon(o)).hexdigest()


def key(s):
    """An `ed25519:` key in strict lowercase hex, or None."""
    m = re.fullmatch(r"ed25519:([0-9a-f]{64})", (s or "").strip())
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(m.group(1))) if m else None


def signed(pub, obj):
    m = re.fullmatch(r"ed25519:([0-9a-f]{128})", obj.get("sig", ""))
    if not m:
        return False
    try:
        pub.verify(bytes.fromhex(m.group(1)), canon({k: v for k, v in obj.items() if k != "sig"}))
        return True
    except InvalidSignature:
        return False


def known_fields(r):
    """Every key is one the format defines, and the optional ones appear only when they say something
    (review only as true, verification only as an object). Anything else has a second spelling."""
    if set(r) - FIELDS[None] or r.get("decision", {}).get("review", True) is not True:
        return False
    if "verification" in r and not isinstance(r["verification"], dict):
        return False
    return all(set(r[part]) <= FIELDS[part] for part in FIELDS if part and part in r)


def chain_ok(receipts, pub):
    """Level 1: each receipt is version 1, in position, linked to the one before, and signed."""
    prev = GENESIS
    for i, r in enumerate(receipts):
        if not known_fields(r) or (r.get("v"), r.get("seq")) != (1, i) or r.get("prev") != prev:
            return False
        if type(r["v"]) is not int or type(r["seq"]) is not int:
            return False
        if not signed(pub, r):
            return False
        prev = digest(r)
    return True


def checkpoints_ok(checkpoints, receipts, pub):
    """The log still holds every receipt each checkpoint vouched for."""
    for c in checkpoints:
        if set(c) - CHECKPOINT_FIELDS or c.get("v") != 1 or not signed(pub, c):
            return False
        n = c["count"]
        if n and (len(receipts) < n or digest(receipts[n - 1]) != c["head"]):
            return False
    return True


def holds(check, *args):
    """A check that can't be completed, on input of the wrong shape, fails."""
    try:
        return check(*args)
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def level(receipts, log_key, pinned, published):
    """The highest level in spec/receipts-v1.md the log reaches (Level 3 has no checks yet)."""
    if not log_key or not holds(chain_ok, receipts, log_key):
        return 0
    if not pinned or not published or not holds(chain_ok, receipts, pinned):
        return 1
    return 2 if holds(checkpoints_ok, published, receipts, pinned) else 1


def no_repeats(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("repeated key")
    return dict(pairs)


def jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line, object_pairs_hook=no_repeats) for line in f if line.strip()]


def level_of_dir(d, pinned_path=None, checkpoint_paths=()):
    """Read a log directory the way it sits on disk; anything unreadable counts against it."""
    try:
        receipts = jsonl(os.path.join(d, "receipts.jsonl"))
        log_key = key(open(os.path.join(d, "public.key"), encoding="utf-8").read())
    except (OSError, ValueError):
        return 0
    # A file the caller named that can't be read is an error, never "nothing to check".
    pinned = key(open(pinned_path, encoding="utf-8").read()) if pinned_path else None
    if pinned_path and not pinned:
        raise ValueError(f"{pinned_path} is not an ed25519 public key")
    published = [c for p in checkpoint_paths for c in jsonl(p)]
    return level(receipts, log_key, pinned, published)


def check_bytes(v):
    pub = key(v["public_key"])
    prev = GENESIS
    for i, item in enumerate(v["receipts"]):
        r = item["receipt"]
        assert canon(r).hex() == item["canonical_hex"], f"canonical bytes differ at {i}"
        h = digest(r)
        assert h == item["sha256"], f"hash differs at {i}"
        assert r["prev"] == prev, f"chain link broken at {i}"
        if "verification" in r:
            # An outcome names an earlier decision and repeats its agent, action and decision.
            of = r["verification"]["of"]
            assert of < i, f"outcome at {i} names a later receipt"
            d = v["receipts"][of]["receipt"]
            assert "verification" not in d, f"outcome at {i} names another outcome"
            for k in ("agent", "action", "decision"):
                assert r[k] == d[k], f"outcome at {i} does not repeat its decision's {k}"
        assert signed(pub, r), f"signature fails at {i}"
        prev = h
    c = v["checkpoint"]
    assert c["head"] == prev and c["count"] == len(v["receipts"])
    assert signed(pub, c), "checkpoint signature fails"
    outcomes = sum("verification" in item["receipt"] for item in v["receipts"])
    print("independent check ok:", len(v["receipts"]), "receipts,", outcomes, "of them outcomes, and the checkpoint")


def check_conformance(v):
    """Write each case out as a log directory and read it back, so --log is what gets tested."""
    wrong = []
    for case in v["cases"]:
        with tempfile.TemporaryDirectory() as d:
            def write(name, text):
                with open(os.path.join(d, name), "w", encoding="utf-8", newline="\n") as f:
                    f.write(text)
            write("receipts.jsonl", "".join(json.dumps(r) + "\n" for r in case["receipts"]))
            write("public.key", case["log_key"] + "\n")
            pinned = None
            if case["pinned_key"]:
                write("pinned.key", case["pinned_key"] + "\n")
                pinned = os.path.join(d, "pinned.key")
            write("published.jsonl", "".join(json.dumps(c) + "\n" for c in case["published_checkpoints"]))
            got = level_of_dir(d, pinned, [os.path.join(d, "published.jsonl")])
        print(f"{case['name']}: level {got}" + ("" if got == case["expect_level"] else f", expected {case['expect_level']}"))
        if got != case["expect_level"]:
            wrong.append(case["name"])
    assert not wrong, f"wrong level for {', '.join(wrong)}"
    print("independent check ok:", len(v["cases"]), "conformance cases")


def main(args):
    if args[:1] == ["--log"] and len(args) >= 2:
        d, rest, pinned, published = args[1], args[2:], None, []
        while rest:
            flag, value, rest = rest[0], rest[1] if len(rest) > 1 else None, rest[2:]
            if flag == "--pinned-key" and value:
                pinned = value
            elif flag == "--checkpoints" and value:
                published.append(value)
            else:
                sys.exit(__doc__)
        try:
            print("level", level_of_dir(d, pinned, published))
        except (OSError, ValueError) as e:
            sys.exit(f"check.py: {e}")
        return
    if len(args) != 1:
        sys.exit(__doc__)
    v = json.load(open(args[0], encoding="utf-8"))
    check_conformance(v) if "cases" in v else check_bytes(v)


if __name__ == "__main__":
    main(sys.argv[1:])
