import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from iotsec import crypto
from iotsec.message import Gateway, build_signed, canonical_bytes

NOW = 1_000_000.0


def _gw():
    priv, pub = crypto.generate_keypair()
    return priv, Gateway({"dev-1": pub}, max_age=30)


def test_crypto_sign_verify_roundtrip():
    priv, pub = crypto.generate_keypair()
    sig = crypto.sign(priv, b"hello")
    assert crypto.verify(pub, b"hello", sig)
    assert not crypto.verify(pub, b"tampered", sig)


def test_valid_message_accepted():
    priv, gw = _gw()
    msg = build_signed("dev-1", {"t": 1}, priv, "a", NOW)
    assert gw.verify(msg, NOW) == (True, "accepted")


def test_tampered_payload_rejected():
    priv, gw = _gw()
    msg = build_signed("dev-1", {"t": 1}, priv, "b", NOW)
    msg["payload"] = {"t": 999}
    assert gw.verify(msg, NOW) == (False, "bad_signature")


def test_unknown_device_rejected():
    priv, gw = _gw()
    other, _ = crypto.generate_keypair()
    msg = build_signed("ghost", {"t": 1}, other, "c", NOW)
    assert gw.verify(msg, NOW) == (False, "unknown_device")


def test_forged_signature_rejected():
    _priv, gw = _gw()
    rogue, _ = crypto.generate_keypair()
    msg = build_signed("dev-1", {"t": 1}, rogue, "d", NOW)  # claims dev-1, signed by rogue
    assert gw.verify(msg, NOW) == (False, "bad_signature")


def test_replay_rejected():
    priv, gw = _gw()
    msg = build_signed("dev-1", {"t": 1}, priv, "e", NOW)
    assert gw.verify(msg, NOW)[0] is True
    assert gw.verify(msg, NOW) == (False, "replay")     # same nonce again


def test_stale_timestamp_rejected():
    priv, gw = _gw()
    msg = build_signed("dev-1", {"t": 1}, priv, "f", NOW - 10_000)
    assert gw.verify(msg, NOW) == (False, "stale_or_future")


def test_canonical_excludes_signature():
    priv, _ = crypto.generate_keypair()
    msg = build_signed("dev-1", {"t": 1}, priv, "g", NOW)
    assert b"signature" not in canonical_bytes(msg)
