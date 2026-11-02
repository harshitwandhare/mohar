"""Convert Mohar receipts into two other agent-record formats and check the result against each draft's
own rules. See spec/receipts-v1.md section 12 for the field mapping and what each format loses.

    python export.py              write spec/vectors/export/*.jsonl from conformance-v1.json
    python export.py --check      rebuild both files, fail if they differ from the committed ones or
                                  if either breaks its draft's rules

The input is the "person-receipt" case of conformance-v1.json: a decision allowed on the record, one
stopped at a gate, one a person allowed, an outcome, and a person extending a plan. Both outputs are
signed again with the test seed from v1.json, because neither format signs the bytes Mohar signs.
"""

import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "export")
SHARIF = "draft-sharif-agent-audit-trail-09"
SAHU = "draft-sahu-agent-action-receipts-00"

jcs = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
b64url = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
unb64url = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def uuid4_from(*parts):
    """A UUID with version 4 and the RFC 9562 variant, taken from a hash so the output is reproducible.
    The draft asks for UUIDv4, which is random; this is the open question in section 12."""
    b = bytearray(hashlib.sha256("\0".join(parts).encode()).digest()[:16])
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def ms(ts):
    return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000)


def raw_public(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# draft-sharif-agent-audit-trail-09

SHARIF_REQUIRED = {
    "record_id", "timestamp", "agent_id", "principal", "agent_version", "session_id", "action_type",
    "action_detail", "outcome", "trust_level", "parent_record_id", "prev_hash", "record_phase",
}
SHARIF_DETAIL_REQUIRED = {
    "tool_call": {"tool_name", "parameters_hash"},
    "tool_response": set(),
    "decision": {"decision_type"},
    "escalation": {"escalation_reason", "escalation_target"},
}
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
HEX64 = re.compile(r"[0-9a-f]{64}")


def sharif_kid(pub):
    """RFC 7638 thumbprint of the OKP JWK."""
    return b64url(hashlib.sha256(jcs({"crv": "Ed25519", "kty": "OKP", "x": b64url(pub)})).digest())


def to_sharif(receipts, key):
    pub = raw_public(key)
    session = uuid4_from("session", receipts[0]["agent"]["key"])
    out, prev = [], None
    for r in receipts:
        a, d = r["action"], r["decision"]
        rec = {
            "record_id": uuid4_from("record", r["agent"]["key"], str(r["seq"])),
            "timestamp": r["ts"],
            "agent_id": "urn:mohar:agent:" + r["agent"]["id"],
            "principal": {
                "principal_type": "service",
                "principal_id": "urn:mohar:daemon:" + r["agent"]["key"],
                "authority_ref": None,
            },
            "agent_version": "0.0.0",
            "session_id": session,
            "trust_level": "L0",
            "parent_record_id": out[-1]["record_id"] if out else None,
            "prev_hash": prev,
            "sequence_number": r["seq"],
            "sig_alg": "Ed25519",
            "signer_kid": sharif_kid(pub),
        }
        if "verification" in r:
            v = r["verification"]
            rec.update(
                action_type="tool_response",
                action_detail={"tool_name": a["tool"], "output_hash": v["evidence_sha256"]},
                outcome={"pass": "success", "fail": "failure"}.get(v["result"], "success"),
                record_phase="post_execution",
            )
        elif "person" in r:
            p = r["person"]
            rec.update(
                action_type="decision",
                action_detail={"decision_type": "mohar." + p["act"], "policy_ref": a["capability"]},
                outcome="success",
                record_phase="concurrent",
                human_override={"operator_id": p["by"], "reason": p["act"], "original_action": None},
            )
        else:
            rec.update(
                action_type="tool_call",
                action_detail={"tool_name": a["tool"], "parameters_hash": a["args_sha256"]},
                outcome={"allow": "success", "escalate": "escalated", "deny": "denied"}[d["result"]],
                record_phase="pre_execution",
            )
            if d["by"] == "human":
                rec["human_override"] = {"operator_id": "unknown", "reason": "approved", "original_action": None}
        rec["signature"] = b64url(key.sign(hashlib.sha256(jcs(rec)).digest()))
        prev = hashlib.sha256(jcs(rec)).hexdigest()
        out.append(rec)
    return out


def check_sharif(records, pub):
    """Section 3 field rules, section 6.1 chain, section 6.2 signature."""
    prev, parent = None, None
    for i, rec in enumerate(records):
        missing = SHARIF_REQUIRED - set(rec)
        assert not missing, f"{SHARIF} record {i} lacks {sorted(missing)}"
        assert UUID4.fullmatch(rec["record_id"]) and UUID4.fullmatch(rec["session_id"]), f"record {i}: not UUIDv4"
        assert rec["action_type"] in SHARIF_DETAIL_REQUIRED, f"record {i}: action_type"
        assert SHARIF_DETAIL_REQUIRED[rec["action_type"]] <= set(rec["action_detail"]), f"record {i}: action_detail"
        assert not any(k.startswith("aat_") for k in rec["action_detail"]), f"record {i}: reserved prefix"
        assert rec["outcome"] in {"success", "failure", "timeout", "denied", "escalated"}, f"record {i}: outcome"
        assert rec["trust_level"] in {"L0", "L1", "L2", "L3", "L4"}, f"record {i}: trust_level"
        assert rec["record_phase"] in {"pre_execution", "post_execution", "concurrent"}, f"record {i}: phase"
        assert set(rec["principal"]) == {"principal_type", "principal_id", "authority_ref"}, f"record {i}: principal"
        assert rec["sequence_number"] == i, f"record {i}: sequence_number"
        assert rec["prev_hash"] == prev and (prev is None or HEX64.fullmatch(prev)), f"record {i}: prev_hash"
        assert rec["parent_record_id"] == parent, f"record {i}: parent_record_id"
        assert rec["signer_kid"] == sharif_kid(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))
        unsigned = {k: v for k, v in rec.items() if k not in ("signature", "signature_classical", "batch")}
        try:
            pub.verify(unb64url(rec["signature"]), hashlib.sha256(jcs(unsigned)).digest())
        except InvalidSignature:
            raise AssertionError(f"{SHARIF} record {i}: signature fails")
        prev = hashlib.sha256(jcs({k: v for k, v in rec.items() if k != "batch"})).hexdigest()
        parent = rec["record_id"]


# draft-sahu-agent-action-receipts-00

SAHU_ORDER = ["step_id", "action_id", "params", "success", "ts_ms", "actor", "prev_hash"]


def sahu_signed_bytes(rec):
    """Section 4: compact JSON, top-level members in the draft's fixed order, absent ones left out,
    members inside params sorted."""
    parts = []
    for k in SAHU_ORDER:
        if k not in rec:
            continue
        v = jcs(rec[k]).decode() if k == "params" else json.dumps(rec[k], separators=(",", ":"), ensure_ascii=False)
        parts.append(json.dumps(k) + ":" + v)
    return ("{" + ",".join(parts) + "}").encode()


def sahu_line(rec):
    """How a receipt is written to the log: its signed members, then public_key and signature."""
    body = sahu_signed_bytes(rec)[:-1].decode()
    return body + ',"public_key":"' + rec["public_key"] + '","signature":"' + rec["signature"] + '"}'


def to_sahu(receipts, key):
    pub = raw_public(key).hex()
    out, prev = [], None
    for r in receipts:
        params = {"capability": r["action"]["capability"], "target": r["action"]["target"],
                  "args_sha256": r["action"]["args_sha256"], "decision": r["decision"], "mohar_seq": r["seq"]}
        if "verification" in r:
            params["verification"] = r["verification"]
            success = r["verification"]["result"] == "pass"
        elif "person" in r:
            params["person"] = r["person"]
            success = True
        else:
            success = r["decision"]["result"] == "allow"
        rec = {"step_id": str(r["seq"]), "action_id": r["action"]["tool"], "params": params,
               "success": success, "ts_ms": ms(r["ts"]), "actor": {"agent": r["agent"]["id"]}}
        if prev is not None:
            rec["prev_hash"] = prev
        rec["public_key"] = pub
        rec["signature"] = key.sign(sahu_signed_bytes(rec)).hex()
        line = sahu_line(rec)
        prev = hashlib.sha256(line.encode()).hexdigest()
        out.append(line)
    return out


def check_sahu(lines, pub_hex):
    """Section 3 members and types, section 4 signature, section 5 chain over the exact line bytes."""
    prev, seen = None, set()
    for i, line in enumerate(lines):
        rec = json.loads(line)
        for k, t in (("step_id", str), ("action_id", str), ("success", bool), ("ts_ms", int),
                     ("public_key", str), ("signature", str)):
            assert type(rec.get(k)) is t, f"{SAHU} line {i}: {k}"
        assert "params" in rec, f"{SAHU} line {i}: params"
        assert rec["step_id"] not in seen, f"{SAHU} line {i}: step_id repeats"
        seen.add(rec["step_id"])
        assert list(rec.get("actor", {})) in (["agent"], ["user"], ["agent", "user"]), f"line {i}: actor"
        assert rec.get("prev_hash") == prev, f"{SAHU} line {i}: prev_hash"
        assert re.fullmatch(r"[0-9a-f]{64}", rec["public_key"]) and rec["public_key"] == pub_hex
        assert re.fullmatch(r"[0-9a-f]{128}", rec["signature"]), f"{SAHU} line {i}: signature form"
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
                bytes.fromhex(rec["signature"]), sahu_signed_bytes(rec))
        except InvalidSignature:
            raise AssertionError(f"{SAHU} line {i}: signature fails")
        prev = hashlib.sha256(line.encode()).hexdigest()


def refused(check, *args):
    try:
        check(*args)
    except AssertionError:
        return
    raise AssertionError(f"{check.__name__} accepted a tampered record")


def build():
    conformance = json.load(open(os.path.join(HERE, "conformance-v1.json"), encoding="utf-8"))
    seed = bytes.fromhex(json.load(open(os.path.join(HERE, "v1.json"), encoding="utf-8"))["seed_hex"])
    case = next(c for c in conformance["cases"] if c["name"] == "person-receipt")
    key = Ed25519PrivateKey.from_private_bytes(seed)
    sharif = to_sharif(case["receipts"], key)
    sahu = to_sahu(case["receipts"], key)
    check_sharif(sharif, key.public_key())
    check_sahu(sahu, raw_public(key).hex())
    return {
        SHARIF + ".jsonl": "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in sharif),
        SAHU + ".jsonl": "".join(line + "\n" for line in sahu),
    }


def main(args):
    files = build()
    if args == ["--check"]:
        for name, text in files.items():
            with open(os.path.join(OUT, name), encoding="utf-8") as f:
                assert f.read() == text, f"export/{name} is out of date; run export.py"
        # The checkers must refuse a changed record, or they prove nothing.
        conformance = json.load(open(os.path.join(HERE, "conformance-v1.json"), encoding="utf-8"))
        seed = bytes.fromhex(json.load(open(os.path.join(HERE, "v1.json"), encoding="utf-8"))["seed_hex"])
        key = Ed25519PrivateKey.from_private_bytes(seed)
        receipts = next(c for c in conformance["cases"] if c["name"] == "person-receipt")["receipts"]
        for edit in ("outcome", "timestamp", "prev_hash"):
            records = to_sharif(receipts, key)
            records[2][edit] = "denied" if edit == "outcome" else "2026-11-03T14:23:41.556Z" if edit == "timestamp" else "0" * 64
            refused(check_sharif, records, key.public_key())
        for old_, new_ in (('"success":true', '"success":false'), ('"ts_ms":17', '"ts_ms":18')):
            lines = to_sahu(receipts, key)
            lines[2] = lines[2].replace(old_, new_, 1)
            assert lines[2] != to_sahu(receipts, key)[2]
            refused(check_sahu, lines, raw_public(key).hex())
        print("export ok:", ", ".join(files), "rebuilt, unchanged, and each meets its draft's rules")
        return
    if args:
        sys.exit(__doc__)
    os.makedirs(OUT, exist_ok=True)
    for name, text in files.items():
        with open(os.path.join(OUT, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    print("wrote", ", ".join(files))


if __name__ == "__main__":
    main(sys.argv[1:])
