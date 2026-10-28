# ofxBraid

[![ofxBraid](https://github.com/danoli3/ofxBraid/actions/workflows/ci.yml/badge.svg)](https://github.com/danoli3/ofxBraid/actions/workflows/ci.yml)

ofxBraid is an openFrameworks mailbox that keeps one person on three tunnels. Bluetooth is negotiated first and names the person. ofxENet carries the packet on UDP. [ofxRakNet](https://github.com/danoli3/ofxRakNet/tree/mafianet) (MafiaNet) can carry the same packet on a second UDP port. The packet is retried on ofxBluetoothLE when an IP path drops. Presence carries the signing key so each socket and an allowlist name the same person.

## Addons

Clone [ofxENet](https://github.com/danoli3/ofxENet) into `openFrameworks/addons/` next to this repo. `addon_config.mk` depends on it.

The MafiaNet tunnel is optional. Without it, ofxBraid is ENet and Bluetooth only.

```
git clone --branch mafianet https://github.com/danoli3/ofxRakNet openFrameworks/addons/ofxRakNet
```

```
# addons.make
ofxRakNet

# config.make
PROJECT_CFLAGS += -DOFXBRAID_USE_RAKNET
```

Set `settings.raknet`. `settings.rakPort` is that socket (or `port + 1` when `rakPort` is 0). ENet keeps `port`. The two UDP stacks cannot share a port.

The Bluetooth path is the app's `Radio`. [ofxBluetoothLE](https://github.com/danoli3/ofxBluetoothLE-experiment) fits `SessionRadio<ofxBLEBitChatSession>`.

## Tests

`example_tests` is headless. From that folder, `make RunRelease`. It listens on UDP 60131, 60132, and 60133 (MafiaNet) and does not advertise. The process exits with the number of failed checks. That example opts into the third tunnel.

GitHub Actions builds that example on Linux and macOS, runs it, and runs CodeQL over the same build. The security checks stay on localhost: a wrong room password, a forged plaintext line, a replay of the same packet id, garbage frames, and a cipher that does not match. A passphrase holder is admitted. A stranger is not. When `setPassphrase` accepts an iteration count, the suite also checks that Force and ForceHigh do not open each other.

## Wire

The user id is the Bluetooth peer id, 16 hex characters from the identity file. It does not change when an ENet or RakNet socket does. A `#P` presence line also carries the 64-hex Ed25519 signing key, so an allowlist and a UDP peer refer to the same person. With the MafiaNet tunnel on, presence is sent on all three paths.

```
#L n 0000001a 3dbef9edfd1f62b9 #G M a move
```

`n` prefers ENet, then MafiaNet if that socket is up, then Bluetooth. `k` is MafiaNet, with the same radio fallback. `r` is Bluetooth only. `b` is ENet and Bluetooth. `a` is all three at once. The receiver keeps the first copy of `(peer id, seq)`.

`setPolicy` turns Bluetooth and ENet off. It leaves the MafiaNet socket up, so `Priority::Net` can fail over to it. UDP encryption is `Off` (plaintext), `Force` (AES-256-GCM, 200000 PBKDF2 rounds, plaintext dropped), or `ForceHigh` (the same cipher, 1000000 rounds). Both sides use the same mode. The Bluetooth mesh seal is unchanged. ForceHigh passes that count when `ofxENet::Peer::setPassphrase` accepts it. The public call today takes only the passphrase, so both modes use 200000 until that argument is published. ofxRakNet's `setPassphrase` takes the passphrase only, so Force and ForceHigh use the same stretch on that tunnel.

Call `mailbox.update()` after `mesh.update()`. Both UDP peers are updated inside the mailbox. A host listens (`settings.listen`). A phone dials `settings.connectHost`. Carrier NAT blocks inbound UDP, so a phone on LTE has to dial a reachable host. An empty host stays on the mesh.

The private mesh still clips a line at 160 bytes. The `#L` header is 31 bytes, so a Bluetooth retry can carry about 129 bytes of body.
