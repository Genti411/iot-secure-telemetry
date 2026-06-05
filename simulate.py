"""In-process demo: provision trusted devices, then show the gateway accepting a
valid message and rejecting every attack (tamper, unknown device, forgery,
replay, stale). No broker needed; exits non-zero if any case misbehaves.
"""
import sys

from iotsec import crypto
from iotsec.message import Gateway, build_signed

NOW = 1_000_000.0


def main() -> int:
    priv_a, pub_a = crypto.generate_keypair()
    priv_b, pub_b = crypto.generate_keypair()
    priv_x, _pub_x = crypto.generate_keypair()  # an untrusted/rogue key
    gw = Gateway({"sensor-a": pub_a, "sensor-b": pub_b}, max_age=30)

    cases = []

    valid = build_signed("sensor-a", {"temp": 21.5}, priv_a, "n1", NOW)
    cases.append(("valid message", gw.verify(valid, NOW), True))

    tampered = build_signed("sensor-a", {"temp": 21.5}, priv_a, "n2", NOW)
    tampered["payload"] = {"temp": 99.9}            # changed after signing
    cases.append(("tampered payload", gw.verify(tampered, NOW), False))

    unknown = build_signed("rogue-1", {"temp": 20}, priv_x, "n3", NOW)
    cases.append(("unknown device", gw.verify(unknown, NOW), False))

    forged = build_signed("sensor-b", {"temp": 20}, priv_x, "n4", NOW)  # signed by wrong key
    cases.append(("forged signature", gw.verify(forged, NOW), False))

    replay = build_signed("sensor-a", {"temp": 21.5}, priv_a, "n1", NOW)  # reused nonce
    cases.append(("replayed message", gw.verify(replay, NOW), False))

    stale = build_signed("sensor-b", {"temp": 22}, priv_b, "n6", NOW - 3600)
    cases.append(("stale timestamp", gw.verify(stale, NOW), False))

    ok = True
    for name, (accepted, reason), expect in cases:
        status = "ACCEPT" if accepted else f"REJECT({reason})"
        good = accepted == expect
        ok = ok and good
        print(f"[{'OK ' if good else 'ERR'}] {name:18} -> {status}")
    print("\nRESULT:", "PASS - valid accepted, all attacks rejected" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
