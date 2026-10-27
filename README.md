# ofxBraid

[![ofxBraid](https://github.com/danoli3/ofxBraid/actions/workflows/ci.yml/badge.svg)](https://github.com/danoli3/ofxBraid/actions/workflows/ci.yml)

ofxBraid is an openFrameworks mailbox that keeps one person on two paths, negotiated on Bluetooth first. The person is the Bluetooth peer id. Presence carries the signing key so a UDP socket and an allowlist name the same person. ofxENet carries the packet when that peer is up, and the same packet is retried on ofxBluetoothLE when that path drops.

## Addons

Clone [ofxENet](https://github.com/danoli3/ofxENet) into `openFrameworks/addons/` next to this repo. `addon_config.mk` depends on it.

The Bluetooth path is the app's `Radio`. [ofxBluetoothLE](https://github.com/danoli3/ofxBluetoothLE-experiment) fits `SessionRadio<ofxBLEBitChatSession>`.

## Tests

`example_tests` is headless. From that folder, `make RunRelease`. It listens on UDP 60131 and 60132 and does not advertise. The process exits with the number of failed checks.

GitHub Actions builds that example on Linux and macOS, runs it, and runs CodeQL over the same build. The security checks stay on localhost: a wrong room password, a forged plaintext line, a replay of the same packet id, garbage frames, and a cipher that does not match. A passphrase holder is admitted. A stranger is not. When `setPassphrase` accepts an iteration count, the suite also checks that Force and ForceHigh do not open each other.

## Wire

The user id is the Bluetooth peer id, 16 hex characters from the identity file. It does not change when the ENet socket does. A `#P` presence line also carries the 64-hex Ed25519 signing key, so an allowlist and a UDP peer refer to the same person.

```
#L n 0000001a 3dbef9edfd1f62b9 #G M a move
```

`n` prefers ENet and falls back to Bluetooth. `r` is Bluetooth only. `b` sends both at once (presence). The receiver keeps the first copy of `(peer id, seq)`.

`setPolicy` turns each path off. UDP encryption is `Off` (plaintext), `Force` (AES-256-GCM, 200000 PBKDF2 rounds, plaintext dropped), or `ForceHigh` (the same cipher, 1000000 rounds). Both sides use the same mode. The Bluetooth mesh seal is unchanged. ForceHigh passes that count when `ofxENet::Peer::setPassphrase` accepts it. The public call today takes only the passphrase, so both modes use 200000 until that argument is published.

Call `mailbox.update()` after `mesh.update()`. ENet is updated inside the mailbox. A host listens (`settings.listen`). A phone dials `settings.connectHost`. Carrier NAT blocks inbound UDP, so a phone on LTE has to dial a reachable host. An empty host stays on the mesh.

The private mesh still clips a line at 160 bytes. The `#L` header is 31 bytes, so a Bluetooth retry can carry about 129 bytes of body.
