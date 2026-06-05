"""End-to-end demo over a real MQTT broker.

A device publishes a valid signed message and a tampered one to the broker; the
gateway (subscribed to the same topic) verifies each and accepts/rejects. Proves
the signing layer works over actual MQTT transport, not just in-process.
"""
import json
import os
import sys
import time

import paho.mqtt.client as mqtt

from iotsec import crypto
from iotsec.message import Gateway, build_signed

HOST = os.environ.get("MQTT_HOST", "localhost")
TOPIC = "telemetry"

priv, pub = crypto.generate_keypair()
gateway = Gateway({"sensor-a": pub}, max_age=120)
received: list[bool] = []


def on_connect(client, userdata, flags, rc):
    client.subscribe(TOPIC)


def on_message(client, userdata, msg):
    m = json.loads(msg.payload.decode())
    ok, reason = gateway.verify(m, time.time())
    label = m.get("payload", {}).get("src", "?")
    print(f"[gateway] {label:9} -> {'ACCEPT' if ok else 'REJECT(' + reason + ')'}",
          flush=True)
    received.append(ok)


def main() -> int:
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    for _ in range(20):                 # wait for the broker to come up
        try:
            client.connect(HOST, 1883, 60)
            break
        except Exception:               # noqa: BLE001
            time.sleep(1)
    else:
        print("could not connect to broker")
        return 1

    client.loop_start()
    time.sleep(1)                       # let the subscription register

    valid = build_signed("sensor-a", {"temp": 21.0, "src": "valid"}, priv, "v1", time.time())
    client.publish(TOPIC, json.dumps(valid))
    time.sleep(0.5)

    tampered = build_signed("sensor-a", {"temp": 21.0, "src": "tampered"}, priv, "t1", time.time())
    tampered["payload"]["temp"] = 999  # tamper after signing
    client.publish(TOPIC, json.dumps(tampered))

    deadline = time.time() + 10
    while len(received) < 2 and time.time() < deadline:
        time.sleep(0.2)
    client.loop_stop()
    client.disconnect()

    ok = received.count(True) == 1 and received.count(False) == 1
    print("\nRESULT:",
          "PASS - valid accepted, tampered rejected over MQTT" if ok else f"FAIL {received}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
