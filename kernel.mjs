// MeshOS — the sovereign mesh kernel. The pure, gated core of a serverless local-first mesh:
// a 7-ring state vector folded to one integer (a bijective primorial codec), a compact wire format
// (~12 bytes vs ~600 of JSON), an attenuating capability lattice (a child grant never exceeds its
// parent; unknown → refused; a refusal costs nothing and leaves no charge), a SHA-256 hash-chained
// witness (tamper breaks the chain, anyone can verify), and content-addressing. No I/O here — the
// PWA supplies identity (Ed25519 via WebCrypto), storage (IndexedDB) and transports around this.
// Pure and total: garbage in → { ok:false, why }, never a throw.

export const PRIMES = Object.freeze([2, 3, 5, 7, 11, 13, 17]);   // one prime per ring, R0..R6
export const RING_MAX = 15;                                        // each ring 0..15 — one hex nibble
export const INTENTS = Object.freeze({
  0x00: 'hello', 0x01: 'message', 0x02: 'ack', 0x03: 'ping',
  0x10: 'grant', 0x11: 'revoke',
  0x20: 'offer', 0x21: 'accept', 0x22: 'receipt',
  0x30: 'share', 0x31: 'request',
  0x7f: 'bye',
});

const isStr = (v) => typeof v === 'string';
const isInt = (v) => Number.isInteger(v);
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const HEX = /^[0-9a-f]+$/;

// ── SHA-256, pure and synchronous (the chain + content addresses run on the real thing) ─────────
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256(text) {
  if (!isStr(text)) return { ok: false, why: 'sha256 takes a string' };
  const data = new TextEncoder().encode(text);
  const len = data.length;
  const padded = new Uint8Array((((len + 8) >> 6) << 6) + 64);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  const bitLen = len * 8;
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  for (let i = 0; i < padded.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const x = w[t - 15], y = w[t - 2];
      const s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) >>> 0;
      const s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (hh + S1 + ch + K256[t] + w[t]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  const hex = (n) => n.toString(16).padStart(8, '0');
  return { ok: true, hash: hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7) };
}

export function contentAddress(text) {
  const h = sha256(text);
  if (!h.ok) return h;
  return { ok: true, address: h.hash };
}

// ── the bloom: 7 rings, folded two ways — a prime product (bijective) and a 4-byte hex pack ─────
function validRings(rings) {
  if (!Array.isArray(rings) || rings.length !== 7) return 'rings must be an array of exactly 7 values';
  for (let i = 0; i < 7; i++) {
    if (!isInt(rings[i])) return 'ring ' + i + ' must be an integer';
    if (rings[i] < 0 || rings[i] > RING_MAX) return 'ring ' + i + ' must be within 0..' + RING_MAX;
  }
  return null;
}

/** foldBloom(rings) — the primorial fold: one integer ∏ primes[i]^rings[i]. Bijective (unique factorization). */
export function foldBloom(rings) {
  const bad = validRings(rings);
  if (bad) return { ok: false, why: bad };
  let n = 1n;
  for (let i = 0; i < 7; i++) n *= BigInt(PRIMES[i]) ** BigInt(rings[i]);
  return { ok: true, folded: n };
}

/** unfoldBloom(n) — factor the fold back to the 7 rings. Refuses anything that is not a pure 7-prime fold. */
export function unfoldBloom(n) {
  if (typeof n !== 'bigint' || n < 1n) return { ok: false, why: 'unfold takes a positive bigint' };
  const rings = [0, 0, 0, 0, 0, 0, 0];
  let rest = n;
  for (let i = 0; i < 7; i++) {
    const p = BigInt(PRIMES[i]);
    while (rest % p === 0n) { rings[i] += 1; rest /= p; }
    if (rings[i] > RING_MAX) return { ok: false, why: 'ring ' + i + ' exceeds ' + RING_MAX + ' — not a valid fold' };
  }
  if (rest !== 1n) return { ok: false, why: 'not a pure fold of the seven ring primes' };
  return { ok: true, rings };
}

/** bloomHex(rings) — the wire pack: 7 nibbles into 8 hex chars (top nibble is the version, 0). */
export function bloomHex(rings) {
  const bad = validRings(rings);
  if (bad) return { ok: false, why: bad };
  let v = 0;
  for (let i = 0; i < 7; i++) v = (v << 4) | rings[i];
  return { ok: true, hex: v.toString(16).padStart(8, '0') };
}

export function unbloomHex(hex) {
  if (!isStr(hex) || hex.length !== 8 || !HEX.test(hex)) return { ok: false, why: 'bloom hex is 8 lowercase hex chars' };
  const v = parseInt(hex, 16);
  if ((v >>> 28) !== 0) return { ok: false, why: 'unknown bloom version' };
  const rings = [];
  for (let i = 6; i >= 0; i--) rings.push((v >>> (i * 4)) & 0xf);
  return { ok: true, rings };
}

/** bloomDelta(prev, next) — only the changed rings travel. applyDelta replays them. */
export function bloomDelta(prev, next) {
  const badA = validRings(prev);
  if (badA) return { ok: false, why: 'prev: ' + badA };
  const badB = validRings(next);
  if (badB) return { ok: false, why: 'next: ' + badB };
  const delta = [];
  prev.forEach((p, i) => { if (p !== next[i]) delta.push({ r: i, v: next[i] }); });
  return { ok: true, delta };
}

export function applyDelta(rings, delta) {
  const bad = validRings(rings);
  if (bad) return { ok: false, why: bad };
  if (!Array.isArray(delta)) return { ok: false, why: 'delta must be an array of { r, v }' };
  const next = rings.slice();
  for (const d of delta) {
    if (!isObj(d) || !isInt(d.r) || !isInt(d.v)) return { ok: false, why: 'each delta entry is { r, v } integers' };
    if (d.r < 0 || d.r > 6) return { ok: false, why: 'delta ring out of range' };
    if (d.v < 0 || d.v > RING_MAX) return { ok: false, why: 'delta value out of range' };
    next[d.r] = d.v;
  }
  return { ok: true, rings: next };
}

// ── the wire format: K<bloom8>-<intent2>-[len4-payloadB64-]<sighex> ──────────────────────────────
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64encode(bytes) {
  // the source is padded to a whole number of triples up front, so the loop has no tail conditionals
  const pad = (3 - (bytes.length % 3)) % 3;
  const src = new Uint8Array(bytes.length + pad);
  src.set(bytes);
  let out = '';
  for (let i = 0; i < src.length; i += 3) {
    const a = src[i], b = src[i + 1], c = src[i + 2];
    out += B64[a >> 2] + B64[((a & 3) << 4) | (b >> 4)] + B64[((b & 15) << 2) | (c >> 6)] + B64[c & 63];
  }
  if (pad === 0) return out;
  return out.slice(0, out.length - pad) + '=='.slice(0, pad);
}
function b64decode(s) {
  if (!isStr(s) || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const clean = s.replace(/=+$/, '');
  const bytes = [];
  let buf = 0, bits = 0;
  for (const ch of clean) {
    buf = (buf << 6) | B64.indexOf(ch);
    bits += 6;
    if (bits >= 8) { bits -= 8; bytes.push((buf >> bits) & 0xff); }
  }
  return new Uint8Array(bytes);
}

export function intentName(code) {
  if (!isInt(code) || code < 0 || code > 0x7f) return { ok: false, why: 'intent codes are 0..127' };
  return { ok: true, name: INTENTS[code] || ('intent-' + code.toString(16).padStart(2, '0')) };
}

/** encodeWire({ rings, intent, payload?, sig }) — the Konomi wire string. */
export function encodeWire(msg) {
  if (!isObj(msg)) return { ok: false, why: 'encodeWire takes { rings, intent, payload?, sig }' };
  const bh = bloomHex(msg.rings);
  if (!bh.ok) return { ok: false, why: bh.why };
  if (!isInt(msg.intent) || msg.intent < 0 || msg.intent > 0x7f) return { ok: false, why: 'intent must be 0..127' };
  if (!isStr(msg.sig) || msg.sig.length < 4 || msg.sig.length % 2 !== 0 || !HEX.test(msg.sig)) return { ok: false, why: 'sig must be even-length hex, at least 4 chars' };
  const intent = msg.intent.toString(16).padStart(2, '0');
  if (msg.payload === undefined) return { ok: true, wire: 'K' + bh.hex + '-' + intent + '-' + msg.sig };
  if (!isStr(msg.payload)) return { ok: false, why: 'payload must be a string' };
  const bytes = new TextEncoder().encode(msg.payload);
  if (bytes.length > 0xffff) return { ok: false, why: 'payload exceeds 65535 bytes' };
  const len = bytes.length.toString(16).padStart(4, '0');
  return { ok: true, wire: 'K' + bh.hex + '-' + intent + '-' + len + '-' + b64encode(bytes) + '-' + msg.sig };
}

/** decodeWire(wire) — the exact inverse. A malformed wire is refused, never guessed at. */
export function decodeWire(wire) {
  if (!isStr(wire) || wire[0] !== 'K') return { ok: false, why: 'a wire message starts with K' };
  const parts = wire.slice(1).split('-');
  if (parts.length !== 3 && parts.length !== 5) return { ok: false, why: 'a wire message has 3 or 5 parts' };
  const ub = unbloomHex(parts[0]);
  if (!ub.ok) return { ok: false, why: ub.why };
  if (parts[1].length !== 2 || !HEX.test(parts[1])) return { ok: false, why: 'intent must be 2 hex chars' };
  const intent = parseInt(parts[1], 16);
  if (intent > 0x7f) return { ok: false, why: 'intent codes are 0..127' };
  const sig = parts[parts.length - 1];
  if (sig.length < 4 || sig.length % 2 !== 0 || !HEX.test(sig)) return { ok: false, why: 'sig must be even-length hex, at least 4 chars' };
  if (parts.length === 3) return { ok: true, rings: ub.rings, intent, payload: undefined, sig };
  if (parts[2].length !== 4 || !HEX.test(parts[2])) return { ok: false, why: 'payload length must be 4 hex chars' };
  const declared = parseInt(parts[2], 16);
  const bytes = b64decode(parts[3]);
  if (bytes === null) return { ok: false, why: 'payload is not valid base64' };
  if (bytes.length !== declared) return { ok: false, why: 'payload length does not match its declaration' };
  return { ok: true, rings: ub.rings, intent, payload: new TextDecoder().decode(bytes), sig };
}

// ── the capability lattice: attenuating grants — a child never exceeds its parent; unknown → none ─
function validGrant(g) {
  if (!isObj(g)) return 'a grant is { holder, scope, budget, spent }';
  if (!isStr(g.holder) || g.holder.length === 0) return 'grant holder must be a non-empty string';
  if (!Array.isArray(g.scope)) return 'grant scope must be an array of action names';
  for (const s of g.scope) if (!isStr(s) || s.length === 0) return 'each scope entry must be a non-empty string';
  if (!isInt(g.budget) || g.budget < 0) return 'grant budget must be a non-negative integer';
  if (!isInt(g.spent) || g.spent < 0) return 'grant spent must be a non-negative integer';
  if (g.spent > g.budget) return 'grant spent exceeds its budget';
  return null;
}

export function makeGrant(holder, scope, budget) {
  const g = { holder, scope: Array.isArray(scope) ? scope.slice() : scope, budget, spent: 0 };
  const bad = validGrant(g);
  if (bad) return { ok: false, why: bad };
  return { ok: true, grant: g };
}

/** attenuate(parent, holder, scope, budget) — the child gets a subset and what is left, never more. */
export function attenuate(parent, holder, scope, budget) {
  const badP = validGrant(parent);
  if (badP) return { ok: false, why: 'parent: ' + badP };
  const child = makeGrant(holder, scope, budget);
  if (!child.ok) return { ok: false, why: 'child: ' + child.why };
  for (const s of child.grant.scope) {
    if (!parent.scope.includes(s)) return { ok: false, why: 'a child cannot hold scope the parent lacks: ' + s };
  }
  const remaining = parent.budget - parent.spent;
  if (child.grant.budget > remaining) return { ok: false, why: 'a child cannot hold more budget than the parent has left' };
  return { ok: true, grant: child.grant };
}

/** mayAct(grant, action, cost) — fail-safe: anything unknown or outside the grant is refused. */
export function mayAct(grant, action, cost) {
  const bad = validGrant(grant);
  if (bad) return { ok: false, why: bad };
  if (!isStr(action) || action.length === 0) return { ok: true, allowed: false, why: 'unknown action — refused' };
  if (!isInt(cost) || cost < 0) return { ok: true, allowed: false, why: 'unknown cost — refused' };
  if (!grant.scope.includes(action)) return { ok: true, allowed: false, why: 'outside the grant — refused' };
  if (grant.spent + cost > grant.budget) return { ok: true, allowed: false, why: 'beyond the budget — refused' };
  return { ok: true, allowed: true, why: 'within the grant' };
}

/** charge(grant, action, cost) — a refused action is charged NOTHING and the grant is unchanged. */
export function charge(grant, action, cost) {
  const m = mayAct(grant, action, cost);
  if (!m.ok) return m;
  if (!m.allowed) return { ok: true, allowed: false, charged: 0, grant, why: m.why };
  return { ok: true, allowed: true, charged: cost, grant: { ...grant, scope: grant.scope.slice(), spent: grant.spent + cost }, why: m.why };
}

// ── the witness: a SHA-256 hash chain — tamper anywhere and the chain breaks visibly ─────────────
function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return '"?"';
}

export function appendWitness(chain, entry) {
  if (!Array.isArray(chain)) return { ok: false, why: 'the chain is an array' };
  if (!isObj(entry)) return { ok: false, why: 'a witness entry is an object' };
  const prevHash = chain.length === 0 ? 'GENESIS' : chain[chain.length - 1].hash;
  const h = sha256(prevHash + '|' + canon(entry));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, chain: [...chain, { seq: chain.length, prevHash, hash: h.hash, entry }] };
}

export function verifyLedger(chain) {
  if (!Array.isArray(chain)) return { ok: false, why: 'the chain is an array' };
  for (let i = 0; i < chain.length; i++) {
    const item = chain[i];
    if (!isObj(item) || !isStr(item.hash) || !isStr(item.prevHash) || !isObj(item.entry)) return { ok: true, valid: false, brokenAt: i };
    if (item.seq !== i) return { ok: true, valid: false, brokenAt: i };
    const expectedPrev = i === 0 ? 'GENESIS' : chain[i - 1].hash;
    if (item.prevHash !== expectedPrev) return { ok: true, valid: false, brokenAt: i };
    const h = sha256(item.prevHash + '|' + canon(item.entry));
    if (!h.ok || h.hash !== item.hash) return { ok: true, valid: false, brokenAt: i };
  }
  return { ok: true, valid: true, length: chain.length };
}
