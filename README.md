# ofxBraid

ofxBraid is an openFrameworks mailbox that keeps one person on two paths, negotiated on Bluetooth first. The person is the Bluetooth peer id. Presence carries the signing key so a UDP socket and an allowlist name the same person. ofxENet carries the packet when that peer is up, and the same packet is retried on ofxBluetoothLE when that path drops.

## Addons

Clone these into `openFrameworks/addons/` next to this repo:

- [ofxENet](https://github.com/danoli3/ofxENet) is the network path.
- [ofxBluetoothLE](https://github.com/danoli3/ofxBluetoothLE-experiment) is the Bluetooth path. The mailbox includes `ofxBLEBitChatSession.h` from that repo.

`addon_config.mk` lists both as `ADDON_DEPENDENCIES`.

## Wire

The user id is the Bluetooth peer id, 16 hex characters from the identity file. It does not change when the ENet socket does. A `#P` presence line also carries the 64-hex Ed25519 signing key, so an allowlist and a UDP peer refer to the same person.

```
#L n 0000001a 3dbef9edfd1f62b9 #G M a move
```

`n` prefers ENet and falls back to Bluetooth. `r` is Bluetooth only. `b` sends both at once (presence). The receiver keeps the first copy of `(peer id, seq)`.

`setPolicy` turns each path off. UDP encryption is `Off` (plaintext), `Force` (AES-256-GCM, 200000 PBKDF2 rounds, plaintext dropped), or `ForceHigh` (the same cipher, 1000000 rounds). Both sides use the same mode. The Bluetooth mesh seal is unchanged.

Call `mailbox.update()` after `mesh.update()`. ENet is updated inside the mailbox. A host listens (`settings.listen`). A phone dials `settings.connectHost`. Carrier NAT blocks inbound UDP, so a phone on LTE has to dial a reachable host. An empty host stays on the mesh.

The private mesh still clips a line at 160 bytes. The `#L` header is 31 bytes, so a Bluetooth retry can carry about 129 bytes of body.
