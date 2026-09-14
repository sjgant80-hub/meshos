import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { qrMatrix } from './qr.mjs';

const URL = 'https://sjgant80-hub.github.io/meshos/';
const at = (q, row, col) => q.modules[row * q.size + col];

// deterministic mixed-ASCII filler for the longer symbols
function mixed(n) {
  const pool = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,:;!?#$%&()*+-/<=>@[]_{}~';
  let s = '';
  for (let i = 0; i < n; i++) s += pool[(i * 7 + 3) % pool.length];
  return s;
}

// ── geometry: the version/size law and the auto-selected version per capacity band ──────────────
test('size is 17 + 4*version, modules is size*size of 0/1', () => {
  for (const text of ['', 'hello mesh', URL, mixed(84), mixed(180), mixed(213)]) {
    const q = qrMatrix(text);
    assert.equal(q.ok, true);
    assert.equal(q.size, 17 + 4 * q.version);
    assert.equal(q.modules.length, q.size * q.size);
    assert.ok(q.modules instanceof Uint8Array);
    for (const m of q.modules) assert.ok(m === 0 || m === 1);
  }
});

test('version selection: level-M byte capacities, boundaries exact', () => {
  assert.equal(qrMatrix('x'.repeat(14)).version, 1);    // v1-M holds 14 bytes
  assert.equal(qrMatrix('x'.repeat(15)).version, 2);
  assert.equal(qrMatrix(URL).version, 3);               // the 38-byte URL sits in v3 (capacity 42)
  assert.equal(qrMatrix('x'.repeat(84)).version, 5);
  assert.equal(qrMatrix('x'.repeat(180)).version, 9);   // exact v9 fit — 5 uneven ECC blocks
  assert.equal(qrMatrix('x'.repeat(213)).version, 10);  // v10 — 16-bit length indicator
});

// ── the three finder patterns with their separators, at every version in range ──────────────────
function assertFinder(q, top, left) {
  for (let dr = 0; dr < 7; dr++) {
    for (let dc = 0; dc < 7; dc++) {
      const cheb = Math.max(Math.abs(dr - 3), Math.abs(dc - 3));
      assert.equal(at(q, top + dr, left + dc), cheb === 2 ? 0 : 1,
        `finder(${top},${left}) module +${dr},+${dc}`);
    }
  }
  // the separator: the one-module light ring around the 7×7, where it lies inside the symbol
  for (let dr = -1; dr <= 7; dr++) {
    for (let dc = -1; dc <= 7; dc++) {
      if (dr >= 0 && dr < 7 && dc >= 0 && dc < 7) continue;
      const row = top + dr, col = left + dc;
      if (row < 0 || row >= q.size || col < 0 || col >= q.size) continue;
      assert.equal(at(q, row, col), 0, `separator(${top},${left}) module +${dr},+${dc}`);
    }
  }
}

test('finder patterns + separators at the three corners, v1 through v10', () => {
  for (const text of ['hi', URL, mixed(60), mixed(84), mixed(100), mixed(110), mixed(140), mixed(180), mixed(213)]) {
    const q = qrMatrix(text);
    assert.equal(q.ok, true);
    assertFinder(q, 0, 0);
    assertFinder(q, 0, q.size - 7);
    assertFinder(q, q.size - 7, 0);
  }
});

// ── timing patterns: row 6 and column 6 alternate dark/light between the finders ────────────────
test('timing patterns alternate on row 6 and column 6', () => {
  for (const text of ['hello mesh', URL, mixed(180)]) {
    const q = qrMatrix(text);
    for (let i = 8; i <= q.size - 9; i++) {
      assert.equal(at(q, 6, i), i % 2 === 0 ? 1 : 0, `row-6 timing at col ${i}`);
      assert.equal(at(q, i, 6), i % 2 === 0 ? 1 : 0, `col-6 timing at row ${i}`);
    }
  }
});

// ── the dark module: always at (4*version + 9, 8) ───────────────────────────────────────────────
test('dark module at (size-8, 8) in every version', () => {
  for (const text of ['a', URL, mixed(84), mixed(180), mixed(213)]) {
    const q = qrMatrix(text);
    assert.equal(at(q, q.size - 8, 8), 1);
    assert.equal(q.size - 8, 4 * q.version + 9);
  }
});

// ── determinism: the same text always yields byte-identical modules ─────────────────────────────
test('deterministic: same input, identical bytes', () => {
  for (const text of ['hello mesh', URL, mixed(180)]) {
    const a = qrMatrix(text);
    const b = qrMatrix(text);
    assert.deepEqual(a, b);
    assert.deepEqual(Array.from(a.modules), Array.from(b.modules));
  }
});

// ── totality: garbage refused with a why, never a throw ─────────────────────────────────────────
test('refusals: non-strings and oversize text', () => {
  for (const garbage of [42, null, undefined, {}, [], true, 0n, Symbol('x'), () => {}]) {
    const q = qrMatrix(garbage);
    assert.equal(q.ok, false);
    assert.ok(typeof q.why === 'string' && q.why.length > 0);
  }
  const over = qrMatrix('x'.repeat(214));              // one past v10-M's 213-byte capacity
  assert.equal(over.ok, false);
  assert.match(over.why, /213/);
  assert.equal(qrMatrix('x'.repeat(213)).ok, true);    // the boundary itself fits
});

test('empty string is allowed — a valid (if blank) v1 symbol', () => {
  const q = qrMatrix('');
  assert.equal(q.ok, true);
  assert.equal(q.version, 1);
  assert.equal(q.size, 21);
});

// ── the drift pin: sha256 of the module bytes for the live MeshOS URL ───────────────────────────
// This exact matrix round-tripped through an independent third-party decoder at build time.
// Any change to the bit stream, ECC, interleave, placement, mask choice or format bits moves it.
test('pinned sha256 of the URL matrix — any encoder drift is caught', () => {
  const q = qrMatrix(URL);
  assert.equal(q.ok, true);
  assert.equal(q.version, 3);
  assert.equal(q.size, 29);
  const hash = createHash('sha256').update(Buffer.from(q.modules)).digest('hex');
  assert.equal(hash, '88a925ef4fa41df9a0c3b28670e90795bc5d92308b7bd7b91aecf0f89b6a87c2');
});
