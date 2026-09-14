# MeshOS

**Private messages & sharing for your people. No account. No server for your messages. No one reading what you write.**

<p align="center">
  <a href="https://sjgant80-hub.github.io/meshos/">
    <img src="get-the-app.svg" alt="Get MeshOS — it's free. No account, no server for your messages, works offline." width="440">
  </a>
</p>

<p align="center"><b><a href="https://sjgant80-hub.github.io/meshos/">👉 https://sjgant80-hub.github.io/meshos/ 👈</a></b><br>
Open that link on your phone and tap <b>“Get the app”</b>. It installs like any app — and after the first visit it works even with no internet.</p>

## Install it (30 seconds)

| Phone | How |
|---|---|
| **Android** | Open [the link](https://sjgant80-hub.github.io/meshos/) in Chrome → tap **Get the app** → tap **Install** |
| **iPhone / iPad** | Open [the link](https://sjgant80-hub.github.io/meshos/) in Safari → tap **Share** ⬆ → **Add to Home Screen** → **Add** — then open it once |
| **Computer** | Open [the link](https://sjgant80-hub.github.io/meshos/) in Chrome or Edge → tap **Get the app** |

If the link opened inside WhatsApp or Facebook's built-in browser, choose **“Open in browser”** first — then install.

## What it does

- **Real friend-to-friend messaging, across the internet.** You and a friend swap two invite codes over anything you already use (WhatsApp, SMS, email, a note) and your phones connect **directly** — an encrypted WebRTC link with no server between you. Your words go phone to phone.
- **Group chats that hop.** Make a group, share its name. Messages travel phone-to-phone through the people between you — friend-of-a-friend delivery, no group server to seize, no account to ban.
- **No account, no phone number.** The app makes a cryptographic key on your phone. That key *is* you.
- **It keeps receipts.** Every action lands on a hash chain. Tap *verify the ledger* and a broken or edited chain shows up instantly.
- **Works offline.** After the first visit, flight mode is fine. The app itself can even travel as a single file over Bluetooth / AirDrop / a USB stick.

## The honest bits (v1, unvarnished)

- **Two phones finding each other uses a public STUN server** (Google's). It learns your rough network address — never your words, which travel directly between you, encrypted. That's the one outside party in the connection dance, and you're told about it.
- **People you connect with can see your network address.** That is what a direct connection is. MeshOS is privacy *from platforms* — it is **not** anonymity software. Organisers threatened by network-level adversaries need Tor-class tools; we won't pretend otherwise.
- **A group name is a door key.** Anyone connected to your mesh who knows the name is in. Inside a group, authorship is claimed by the envelope, not yet proven (inner signatures are v2). Group hops carry ttl 2 — friend-of-a-friend, not the whole planet.
- **GitHub hands out the app the first time** — like picking up a leaflet from a shop: they can see you took one, never what you write with it. Installed copies keep working even if the page vanishes.
- **The witness chain is tamper-evident, not tamper-proof** — entries aren't signed and there's no external anchor yet (v2).
- **LoRa radio needs an ESP32 bridge *and a driver that is the next build*** — the rail is shown honestly as not-ready; plugging hardware in does nothing in v1. Bluetooth *mesh* isn't reachable from a browser (sharing the app *file* over Bluetooth works — that's a file transfer). No Reticulum JS port exists. The relay chip is an honest placeholder.
- **Not audited.** Don't bet your life on v1.

---

## For engineers

The friendly face sits on a **mutation-gated kernel**. Everything below is the machine.

| Organ | What it does |
|---|---|
| **Identity** | An Ed25519 (ECDSA-P256 fallback) keypair minted in the browser (WebCrypto). The public key IS the address. Never leaves the device. |
| **Bloom** | The node's 7-ring state vector folded to one integer by a bijective primorial codec (∏ primesᵢ^ringᵢ) — 8 hex chars on the wire. Only deltas travel. |
| **Wire** | `K<bloom8>-<intent2>-[len4-payload-]<sighex>` — ~12 bytes of envelope (plus signature) where JSON burns ~600. A malformed wire is refused, never guessed at. |
| **Links** | Multi-peer WebRTC DataChannels (DTLS), invite-code signalling (offer/answer auto-detected), STUN for NAT traversal. Hellos are **TOFU**: verified against the key the hello itself carries, then pinned — later messages must match. Optional manual key pre-pinning defeats name-squatting. |
| **Groups** | A signed wire whose payload is a tiny envelope `{mg,g,id,ttl,from,t}`. Every hop re-signs its own wire, dedups by envelope id, and gossips onward while ttl holds (default 2). |
| **Capability lattice** | Attenuating grants: a child never exceeds its parent's scope or remaining budget. Unknown → refused. A refusal charges 0; an allowed action charges for real. |
| **Witness** | A SHA-256 hash chain over everything the node does — sends, receives, refusals, relays, group joins. Anyone can verify it. |
| **Storage** | Content-addressed (SHA-256), local IndexedDB, total against hostile storage (private mode / file:// degrade gracefully with an honest banner). |

### Proof, not promises

- `kernel.mjs` is pure and total — garbage in, `{ ok:false, why }` out, never a throw — and gated by a **mutation witness** in CI: every operator/constant mutant must be killed by the suite (survivors need a written, argued equivalence reason in `witness.baseline.json`; currently 113/115 killed, 2 argued equivalents).
- The page is **generated from the gated sources** (`make-page.mjs` injects `kernel.mjs` and `qr.mjs`), and CI fails if the published page drifts (`git diff --exit-code index.html`). The logic you run is the logic that was proved.
- The SHA-256 is a from-scratch synchronous implementation pinned to the FIPS vectors. The QR encoder was proven by decode-roundtrip against an independent decoder (jsQR, dev-only) across versions 1–10, including multi-block ECC interleaving.
- The p2p path was user-tested as **three real nodes** (separate origins, separate identities): two invite-code handshakes, TOFU hellos, a direct message, and a `#group` message relayed A→B→C where C had no link to A.

### Run it

```bash
node --test kernel.test.mjs qr.test.mjs                # the suites
node tools/witness.mjs mutate kernel.mjs --timeout 20000 --cap 300 --test node --test kernel.test.mjs   # the gate
node make-page.mjs                                     # regenerate index.html from the gated sources
```

MIT.
