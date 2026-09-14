# MeshOS — the sovereign mesh

**LIVE: https://sjgant80-hub.github.io/meshos/**

A serverless, local-first mesh node that runs entirely in your browser. Install it as a PWA
and it works with **no network at all**: your identity is a keypair generated on your device,
your data lives in your device's IndexedDB, and messages travel as compact signed wire strings
you can carry over *any* channel — paste them into a chat, a QR code, a radio, a wet napkin.
No account. No server. No tracker. Nothing to subpoena.

## What a node is

| Organ | What it does |
|---|---|
| **Identity** | An ECDSA P-256 keypair minted in your browser (WebCrypto). The public key IS your address. Never leaves the device. |
| **Bloom** | Your node's 7-ring state vector, folded to one integer by a bijective primorial codec (∏ primesᵢ^ringᵢ) — and to 8 hex chars on the wire. Only deltas travel. |
| **Wire** | `K<bloom8>-<intent2>-[len4-payload-]<sighex>` — ~12 bytes of envelope where JSON burns ~600. A malformed wire is refused, never guessed at. |
| **Capability lattice** | Attenuating grants: a child grant can never exceed its parent's scope or remaining budget. Unknown → refused. A refusal charges nothing. |
| **Witness** | A SHA-256 hash chain over everything the node does. Tamper anywhere and the chain breaks visibly — anyone can verify it. |
| **Storage** | Content-addressed (SHA-256), local IndexedDB. Your device is the server. |
| **Transports** | A pluggable router: loopback + paste-signalled WebRTC today; the panel is honest about what each rail can and cannot do from a browser. |

## Proof, not promises

The kernel (`kernel.mjs`) is **pure and total** — garbage in, `{ ok:false, why }` out, never a
throw — and it is gated by a **mutation witness**: the CI mutates the kernel's operators and
constants one by one and requires the test suite to kill every mutant (survivors must carry a
written, argued equivalence reason in `witness.baseline.json`). The page you use is **generated
from that same gated kernel** (`make-page.mjs`), and CI fails if the published page ever drifts
from the kernel (`git diff --exit-code index.html`). The logic you run is the logic that was proved.

The SHA-256 is a from-scratch synchronous implementation pinned to the FIPS test vectors, so the
witness chain and content addresses run on the real thing, inside the gate.

## Honest limits (v1)

- **Web Bluetooth cannot mesh.** Browsers can't advertise as BLE peripherals; there is no
  browser-to-browser BLE. The BLE rail is listed as *bridge-needed*, not faked.
- **LoRa needs hardware and a bridge** (serial/WebUSB gateway). Listed, not faked.
- **There is no Reticulum JS port.** The wire format is carried over what exists today:
  loopback, paste-signalled WebRTC, and any copy-paste channel.
- **Not audited.** The crypto is WebCrypto + a gated SHA-256, but no third party has audited
  this. Don't bet your life on v1.
- **For the technically adjacent.** Paste-signalling WebRTC is manual by design (no signalling
  server = no server to trust). v1 asks a little of you.

## Run it

Open the live page, or serve the repo statically (`npx serve .`) — it's one HTML file plus a
service worker. To develop:

```bash
node --test kernel.test.mjs                        # the suite
node tools/witness.mjs mutate kernel.mjs --timeout 20000 --cap 300 --test node --test kernel.test.mjs   # the gate
node make-page.mjs                                 # regenerate index.html from the gated kernel
```
