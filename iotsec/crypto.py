"""Ed25519 device identity and message signing.

Each IoT device has an Ed25519 keypair; the private key never leaves the device.
The gateway trusts a device by registering its public key. Ed25519 is fast,
small (32-byte keys, 64-byte signatures) and well-suited to constrained devices.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          PublicFormat)


def generate_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Return (private_key, public_key_bytes). public_key_bytes is the 32-byte
    raw key shared with the gateway out-of-band as the device's identity."""
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub_bytes


def sign(priv: Ed25519PrivateKey, data: bytes) -> bytes:
    return priv.sign(data)


def verify(pub_bytes: bytes, data: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False
