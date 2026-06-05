"""Signed telemetry messages + a verifying gateway.

A message is signed over its CANONICAL bytes (sorted JSON, signature excluded),
so any tampering with the payload, device id, timestamp, or nonce invalidates the
signature. The gateway also enforces freshness (timestamp window) and
single-use nonces to stop replay attacks.
"""
from __future__ import annotations

import json

from . import crypto


def canonical_bytes(msg: dict) -> bytes:
    """Deterministic serialization of everything except the signature."""
    body = {k: v for k, v in msg.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def build_signed(device_id, payload, priv, nonce, ts) -> dict:
    msg = {"device_id": device_id, "payload": payload, "nonce": nonce, "ts": ts}
    msg["signature"] = crypto.sign(priv, canonical_bytes(msg)).hex()
    return msg


class Gateway:
    """Verifies device messages against a registry of trusted public keys."""

    def __init__(self, registry: dict[str, bytes], max_age: float = 30.0):
        self.registry = registry          # device_id -> public_key_bytes
        self.max_age = max_age
        self._seen: set[tuple] = set()     # (device_id, nonce) replay cache

    def verify(self, msg: dict, now: float) -> tuple[bool, str]:
        pub = self.registry.get(msg.get("device_id"))
        if pub is None:
            return False, "unknown_device"

        sig_hex = msg.get("signature")
        if not sig_hex:
            return False, "missing_signature"
        try:
            sig = bytes.fromhex(sig_hex)
        except ValueError:
            return False, "bad_signature"
        if not crypto.verify(pub, canonical_bytes(msg), sig):
            return False, "bad_signature"      # tampered or forged

        if abs(now - msg.get("ts", 0)) > self.max_age:
            return False, "stale_or_future"

        key = (msg["device_id"], msg.get("nonce"))
        if key in self._seen:
            return False, "replay"
        self._seen.add(key)
        return True, "accepted"
