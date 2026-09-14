// MeshOS — the QR organ. A spec-correct QR Code encoder (ISO/IEC 18004), byte mode, error
// correction level M, versions 1..10 auto-selected by capacity. The full rail: mode + length +
// data bit stream with terminator and 0xEC/0x11 pad bytes, Reed–Solomon ECC over GF(256) with
// block interleaving, finder/separator/timing/alignment/dark function patterns, format info
// (BCH 15,5 ^ 0x5412) in both homes, version info (BCH 18,6) for v7+, and all 8 data masks
// scored by the four penalty rules — the cheapest mask wins. The matrix carries NO quiet zone;
// a renderer adds the 4-module margin. No I/O here — pure and total: garbage in →
// { ok:false, why }, never a throw.

const isStr = (v) => typeof v === 'string';

// ── error correction level M, versions 1..10: per-block ECC codewords + data codewords per block ─
// (ISO/IEC 18004 table 9 — group-1 blocks first, then the one-codeword-longer group-2 blocks)
const EC_M = Object.freeze([
  Object.freeze({ ec: 10, blocks: Object.freeze([16]) }),                  // v1  · 26 codewords
  Object.freeze({ ec: 16, blocks: Object.freeze([28]) }),                  // v2  · 44
  Object.freeze({ ec: 26, blocks: Object.freeze([44]) }),                  // v3  · 70
  Object.freeze({ ec: 18, blocks: Object.freeze([32, 32]) }),              // v4  · 100
  Object.freeze({ ec: 24, blocks: Object.freeze([43, 43]) }),              // v5  · 134
  Object.freeze({ ec: 16, blocks: Object.freeze([27, 27, 27, 27]) }),      // v6  · 172
  Object.freeze({ ec: 18, blocks: Object.freeze([31, 31, 31, 31]) }),      // v7  · 196
  Object.freeze({ ec: 22, blocks: Object.freeze([38, 38, 39, 39]) }),      // v8  · 242
  Object.freeze({ ec: 22, blocks: Object.freeze([36, 36, 36, 37, 37]) }),  // v9  · 292
  Object.freeze({ ec: 26, blocks: Object.freeze([43, 43, 43, 43, 44]) }),  // v10 · 346
]);

// alignment pattern centre coordinates per version (ISO/IEC 18004 annex E)
const ALIGN = Object.freeze([
  Object.freeze([]), Object.freeze([6, 18]), Object.freeze([6, 22]), Object.freeze([6, 26]),
  Object.freeze([6, 30]), Object.freeze([6, 34]), Object.freeze([6, 22, 38]), Object.freeze([6, 24, 42]),
  Object.freeze([6, 26, 46]), Object.freeze([6, 28, 50]),
]);

const MAX_VERSION = 10;
const lengthBits = (version) => (version <= 9 ? 8 : 16);           // byte-mode count indicator width
const dataCodewords = (version) => EC_M[version - 1].blocks.reduce((a, b) => a + b, 0);
const byteCapacity = (version) =>
  Math.floor((dataCodewords(version) * 8 - 4 - lengthBits(version)) / 8);

// ── GF(256), primitive polynomial 0x11d — the field the ECC lives in ────────────────────────────
const GF_EXP = new Uint8Array(510);
const GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_EXP[i + 255] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
}
const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]]);

/** the degree-n Reed–Solomon generator polynomial ∏(x − α^i), i = 0..n−1, coefficients MSB first */
function rsGenerator(degree) {
  let g = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) {
      next[j] ^= g[j];                              // g(x) · x
      next[j + 1] ^= gfMul(g[j], GF_EXP[i]);        // g(x) · α^i
    }
    g = next;
  }
  return g;
}

/** polynomial-division remainder: the ECC codewords for one block */
function rsRemainder(data, generator) {
  const degree = generator.length - 1;
  const buf = new Uint8Array(data.length + degree);
  buf.set(data);
  for (let i = 0; i < data.length; i++) {
    const factor = buf[i];
    if (factor === 0) continue;
    for (let j = 1; j < generator.length; j++) buf[i + j] ^= gfMul(generator[j], factor);
  }
  return buf.slice(data.length);
}

// ── the bit stream: mode + count + data, terminator, byte padding, 0xEC/0x11 pads ───────────────
function buildCodewords(bytes, version) {
  const dcw = dataCodewords(version);
  const capacityBits = dcw * 8;
  const bits = [];
  const push = (value, count) => {
    for (let i = count - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  push(0b0100, 4);                              // byte mode
  push(bytes.length, lengthBits(version));      // character (byte) count
  for (const b of bytes) push(b, 8);
  const terminator = Math.min(4, capacityBits - bits.length);
  push(0, terminator);
  if (bits.length % 8 !== 0) push(0, 8 - (bits.length % 8));
  const codewords = new Uint8Array(dcw);
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    codewords[i >> 3] = b;
  }
  const pads = [0xec, 0x11];
  for (let i = bits.length >> 3, p = 0; i < dcw; i++, p = 1 - p) codewords[i] = pads[p];
  return codewords;
}

/** split into ECC blocks, then interleave data columns and ECC columns — the transmitted order */
function interleave(codewords, version) {
  const { ec, blocks } = EC_M[version - 1];
  const generator = rsGenerator(ec);
  const dataBlocks = [];
  const eccBlocks = [];
  let at = 0;
  for (const len of blocks) {
    const block = codewords.slice(at, at + len);
    at += len;
    dataBlocks.push(block);
    eccBlocks.push(rsRemainder(block, generator));
  }
  const out = new Uint8Array(codewords.length + ec * blocks.length);
  let o = 0;
  const longest = Math.max(...blocks);
  for (let i = 0; i < longest; i++) {
    for (const block of dataBlocks) if (i < block.length) out[o++] = block[i];
  }
  for (let i = 0; i < ec; i++) {
    for (const block of eccBlocks) out[o++] = block[i];
  }
  return out;
}

// ── the matrix: function patterns first, then the zigzag data walk, then the cheapest mask ──────
function placeFunctionPatterns(size, version) {
  const modules = new Uint8Array(size * size);      // 1 = dark
  const reserved = new Uint8Array(size * size);     // 1 = function/format/version — mask never touches
  const set = (row, col, dark) => {
    modules[row * size + col] = dark ? 1 : 0;
    reserved[row * size + col] = 1;
  };

  // timing patterns — full row 6 and column 6; finders overwrite their ends below
  for (let i = 0; i < size; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }

  // finder patterns + separators at three corners (dark unless at Chebyshev distance 2)
  const finder = (top, left) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const row = top + dr, col = left + dc;
        if (row < 0 || row >= size || col < 0 || col >= size) continue;
        const cheb = Math.max(Math.abs(dr - 3), Math.abs(dc - 3));
        set(row, col, cheb !== 2 && cheb !== 4);
      }
    }
  };
  finder(0, 0);
  finder(0, size - 7);
  finder(size - 7, 0);

  // alignment patterns (skip the three finder corners; dark unless at Chebyshev distance 1)
  const centres = ALIGN[version - 1];
  const last = centres.length - 1;
  for (let i = 0; i < centres.length; i++) {
    for (let j = 0; j < centres.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          set(centres[i] + dr, centres[j] + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
        }
      }
    }
  }

  // dark module + reserve both format-info homes (real bits land after the mask is chosen)
  set(size - 8, 8, true);
  for (let i = 0; i <= 8; i++) {
    if (i !== 6) { reserved[8 * size + i] = 1; reserved[i * size + 8] = 1; }
  }
  for (let i = 0; i < 8; i++) {
    reserved[8 * size + (size - 1 - i)] = 1;
    reserved[(size - 1 - i) * size + 8] = 1;
  }

  // version information for v7+ — two 6×3 homes, bottom-left and top-right (mask-independent)
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (version << 12) | rem;               // 18 bits, BCH(18,6)
    for (let i = 0; i < 18; i++) {
      const bit = (bits >>> i) & 1;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      set(b, a, bit);
      set(a, b, bit);
    }
  }

  return { modules, reserved };
}

/** the zigzag walk: column pairs right to left (skipping timing column 6), alternating up/down */
function placeData(modules, reserved, size, interleaved) {
  const totalBits = interleaved.length * 8;           // remainder bits stay 0 — the spec's filler
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const col = right - j;
        const upward = ((right + 1) & 2) === 0;
        const row = upward ? size - 1 - vert : vert;
        if (reserved[row * size + col]) continue;
        if (i < totalBits) modules[row * size + col] = (interleaved[i >> 3] >>> (7 - (i & 7))) & 1;
        i++;
      }
    }
  }
}

// the 8 mask conditions — a data module flips where its condition holds
const MASKS = Object.freeze([
  (r, c) => (r + c) % 2 === 0,
  (r, c) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
]);

function applyMask(modules, reserved, size, mask) {
  const fn = MASKS[mask];
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!reserved[r * size + c] && fn(r, c)) modules[r * size + c] ^= 1;
    }
  }
}

/** format info: 2 EC bits (M = 00) + 3 mask bits, BCH(15,5), ^ 0x5412 — written in BOTH homes */
function writeFormat(modules, size, mask) {
  const data = (0b00 << 3) | mask;                    // level M
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const bit = (i) => (bits >>> i) & 1;
  // first home, around the top-left finder
  for (let i = 0; i <= 5; i++) modules[i * size + 8] = bit(i);
  modules[7 * size + 8] = bit(6);
  modules[8 * size + 8] = bit(7);
  modules[8 * size + 7] = bit(8);
  for (let i = 9; i < 15; i++) modules[8 * size + (14 - i)] = bit(i);
  // second home, split along the bottom-left and top-right edges
  for (let i = 0; i < 8; i++) modules[8 * size + (size - 1 - i)] = bit(i);
  for (let i = 8; i < 15; i++) modules[(size - 15 + i) * size + 8] = bit(i);
}

// ── the four penalty rules (ISO/IEC 18004 §8.8.2) — the mask with the lowest total wins ─────────
function penalty(modules, size) {
  let score = 0;
  const at = (r, c) => modules[r * size + c];

  // rule 1: runs of 5+ same-coloured modules in a row or column → 3 + (length − 5)
  for (let r = 0; r < size; r++) {
    let runColor = at(r, 0), run = 1;
    for (let c = 1; c < size; c++) {
      if (at(r, c) === runColor) run++;
      else { if (run >= 5) score += run - 2; runColor = at(r, c); run = 1; }
    }
    if (run >= 5) score += run - 2;
  }
  for (let c = 0; c < size; c++) {
    let runColor = at(0, c), run = 1;
    for (let r = 1; r < size; r++) {
      if (at(r, c) === runColor) run++;
      else { if (run >= 5) score += run - 2; runColor = at(r, c); run = 1; }
    }
    if (run >= 5) score += run - 2;
  }

  // rule 2: every 2×2 block of one colour → 3
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = at(r, c);
      if (v === at(r, c + 1) && v === at(r + 1, c) && v === at(r + 1, c + 1)) score += 3;
    }
  }

  // rule 3: the finder-alike 1011101 with 0000 on either side, in a row or column → 40
  const dark = [1, 0, 1, 1, 1, 0, 1];
  const alike = (get, i) => {
    for (let k = 0; k < 7; k++) if (get(i + k) !== dark[k]) return false;
    return true;
  };
  const clear4 = (get, i, len) => {
    if (i < 0 || i + 4 > len) return false;
    for (let k = 0; k < 4; k++) if (get(i + k) !== 0) return false;
    return true;
  };
  for (let r = 0; r < size; r++) {
    const get = (c) => at(r, c);
    for (let c = 0; c <= size - 7; c++) {
      if (alike(get, c) && (clear4(get, c - 4, size) || clear4(get, c + 7, size))) score += 40;
    }
  }
  for (let c = 0; c < size; c++) {
    const get = (r) => at(r, c);
    for (let r = 0; r <= size - 7; r++) {
      if (alike(get, r) && (clear4(get, r - 4, size) || clear4(get, r + 7, size))) score += 40;
    }
  }

  // rule 4: dark-module balance — 10 per 5% step away from 50%
  let darkCount = 0;
  for (let i = 0; i < size * size; i++) darkCount += modules[i];
  const total = size * size;
  score += Math.floor(Math.abs(darkCount * 100 - total * 50) / (total * 5)) * 10;
  return score;
}

// ── the one export ──────────────────────────────────────────────────────────────────────────────
/**
 * qrMatrix(text) — the whole rail in one call. UTF-8 bytes of `text`, byte mode, level M,
 * version 1..10 by capacity, best-of-8 mask. → { ok:true, size, version, modules } where
 * `modules` is a row-major Uint8Array of size×size (1 = dark), quiet zone NOT included —
 * or { ok:false, why } for a non-string or text beyond version 10's capacity.
 */
export function qrMatrix(text) {
  if (!isStr(text)) return { ok: false, why: 'qrMatrix takes a string' };
  try {
    const bytes = new TextEncoder().encode(text);
    let version = 0;
    for (let v = 1; v <= MAX_VERSION; v++) {
      if (bytes.length <= byteCapacity(v)) { version = v; break; }
    }
    if (version === 0) {
      return {
        ok: false,
        why: 'text is ' + bytes.length + ' bytes — beyond the ' + byteCapacity(MAX_VERSION) +
          '-byte capacity of version ' + MAX_VERSION + ' at level M',
      };
    }

    const size = 17 + 4 * version;
    const interleaved = interleave(buildCodewords(bytes, version), version);
    const { modules, reserved } = placeFunctionPatterns(size, version);
    placeData(modules, reserved, size, interleaved);

    // score all 8 masks on the complete symbol (format bits included) and keep the cheapest
    let bestMask = 0;
    let bestScore = Infinity;
    for (let mask = 0; mask < 8; mask++) {
      applyMask(modules, reserved, size, mask);
      writeFormat(modules, size, mask);
      const score = penalty(modules, size);
      if (score < bestScore) { bestScore = score; bestMask = mask; }
      applyMask(modules, reserved, size, mask);    // XOR is its own inverse — restore
    }
    applyMask(modules, reserved, size, bestMask);
    writeFormat(modules, size, bestMask);

    return { ok: true, size, version, modules };
  } catch (e) {
    return { ok: false, why: 'qr encoding failed: ' + (e && e.message ? e.message : String(e)) };
  }
}
