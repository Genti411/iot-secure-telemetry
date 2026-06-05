# IoT Secure Telemetry

An **IoT security** demo: simulated devices sign their telemetry with **Ed25519**,
and a gateway verifies every message against a registry of trusted device keys —
rejecting tampered, forged, unknown-device, replayed, and stale messages. Works
both in-process and over a real **MQTT** broker.

| Area | What's shown |
|------|--------------|
| **IoT security** | per-device identity, message integrity/authenticity, replay protection |
| **Cryptography** | Ed25519 signatures over canonical message bytes |
| **MQTT** | publish/subscribe transport with an eclipse-mosquitto broker |
| **Trust model** | gateway trusts only pre-registered device public keys |

## Threat model & controls

| Attack | Control | Result |
|--------|---------|--------|
| Tamper with payload in transit | signature over canonical bytes | `bad_signature` |
| Forge a message as another device | gateway verifies with that device's public key | `bad_signature` |
| Unknown / unregistered device | device-key registry | `unknown_device` |
| Replay a captured message | single-use `(device, nonce)` cache | `replay` |
| Replay an old message later | timestamp freshness window | `stale_or_future` |

## Run

```bash
# in-process simulation (no broker) — valid accepted, all attacks rejected
docker build -t iot-secure-telemetry . && docker run --rm iot-secure-telemetry

# full demo over a real MQTT broker
docker compose up --build        # watch the `demo` container's gateway output
```

Locally: `pip install -r requirements.txt && python simulate.py`.

## Tests

```bash
python -m pytest          # Ed25519 roundtrip + every accept/reject case
```

## Layout

```
iotsec/crypto.py    Ed25519 keygen / sign / verify
iotsec/message.py   canonical signing + verifying Gateway (replay + freshness)
simulate.py         in-process accept/reject demo
mqtt_demo.py        same, over an MQTT broker (paho-mqtt)
mosquitto.conf      broker config
docker-compose.yml  broker + demo
tests/              unit tests
```
