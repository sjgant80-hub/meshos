import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  PRIMES, RING_MAX, INTENTS, sha256, contentAddress,
  foldBloom, unfoldBloom, bloomHex, unbloomHex, bloomDelta, applyDelta,
  intentName, encodeWire, decodeWire,
  makeGrant, attenuate, mayAct, charge,
  appendWitness, verifyLedger,
} from './kernel.mjs';

// ── SHA-256: the three standard vectors pin every constant and operator in the compression loop
test('sha256: FIPS test vectors', () => {
  assert.equal(sha256('').hash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256('abc').hash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq').hash,
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  assert.equal(sha256(12).ok, false);   // total on garbage
});

test('sha256: multi-block boundary (55/56 byte padding edge)', () => {
  const a55 = sha256('a'.repeat(55)).hash;
  const a56 = sha256('a'.repeat(56)).hash;
  assert.equal(a55.length, 64);
  assert.equal(a56.length, 64);
  assert.notEqual(a55, a56);
  assert.equal(sha256('a'.repeat(55)).hash, a55);   // deterministic
});

test('contentAddress: same text same address, different text different', () => {
  const a = contentAddress('hello mesh');
  assert.equal(a.ok, true);
  assert.equal(a.address, contentAddress('hello mesh').address);
  assert.notEqual(a.address, contentAddress('hello mesh!').address);
});

// ── the bloom fold: bijective primorial
test('foldBloom: pinned folds — unit rings and the primorial', () => {
  assert.equal(foldBloom([0, 0, 0, 0, 0, 0, 0]).folded, 1n);
  assert.equal(foldBloom([1, 0, 0, 0, 0, 0, 0]).folded, 2n);
  assert.equal(foldBloom([0, 0, 0, 0, 0, 0, 1]).folded, 17n);
  assert.equal(foldBloom([1, 1, 1, 1, 1, 1, 1]).folded, 510510n);   // 2·3·5·7·11·13·17
  assert.equal(foldBloom([2, 1, 0, 0, 0, 0, 0]).folded, 12n);       // 4·3
});

test('unfoldBloom: exact inverse, and refuses impostors', () => {
  for (const rings of [[0,0,0,0,0,0,0], [1,1,1,1,1,1,1], [15,0,3,0,7,0,15], [4,7,7,6,5,4,3]]) {
    const f = foldBloom(rings);
    assert.deepEqual(unfoldBloom(f.folded).rings, rings);
  }
  assert.equal(unfoldBloom(19n).ok, false);            // a prime outside the seven
  assert.equal(unfoldBloom(2n ** 16n).ok, false);      // ring would exceed 15
  assert.equal(unfoldBloom(0n).ok, false);
  assert.equal(unfoldBloom(7).ok, false);              // not a bigint
});

test('bloom rings: boundaries 0 and 15 valid, 16 and -1 refused (kills >= vs >)', () => {
  assert.equal(foldBloom([15, 15, 15, 15, 15, 15, 15]).ok, true);
  assert.equal(foldBloom([16, 0, 0, 0, 0, 0, 0]).ok, false);
  assert.equal(foldBloom([-1, 0, 0, 0, 0, 0, 0]).ok, false);
  assert.equal(foldBloom([0, 0, 0]).ok, false);        // wrong length
  assert.equal(foldBloom('x').ok, false);
});

test('bloomHex: pinned pack and exact inverse', () => {
  assert.equal(bloomHex([1, 2, 3, 4, 5, 6, 7]).hex, '01234567');
  assert.equal(bloomHex([0, 0, 0, 0, 0, 0, 0]).hex, '00000000');
  assert.equal(bloomHex([15, 15, 15, 15, 15, 15, 15]).hex, '0fffffff');
  assert.deepEqual(unbloomHex('01234567').rings, [1, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual(unbloomHex('0fffffff').rings, [15, 15, 15, 15, 15, 15, 15]);
  assert.equal(unbloomHex('f0000000').ok, false);      // unknown version nibble
  assert.equal(unbloomHex('123').ok, false);           // wrong length
  assert.equal(unbloomHex('0123456z').ok, false);      // not hex
  assert.equal(unbloomHex(5).ok, false);
});

test('bloomDelta/applyDelta: only changes travel, and replay lands exactly', () => {
  const prev = [1, 2, 3, 4, 5, 6, 7];
  const next = [1, 9, 3, 4, 0, 6, 7];
  const d = bloomDelta(prev, next);
  assert.deepEqual(d.delta, [{ r: 1, v: 9 }, { r: 4, v: 0 }]);
  assert.deepEqual(applyDelta(prev, d.delta).rings, next);
  assert.deepEqual(bloomDelta(prev, prev).delta, []);
  assert.equal(applyDelta(prev, [{ r: 7, v: 1 }]).ok, false);    // ring out of range
  assert.equal(applyDelta(prev, [{ r: 0, v: 16 }]).ok, false);   // value out of range
  assert.equal(applyDelta(prev, 'x').ok, false);
});

// ── the wire codec
test('encodeWire/decodeWire: short form — pinned wire and exact roundtrip', () => {
  const e = encodeWire({ rings: [1, 2, 3, 4, 5, 6, 7], intent: 0x01, sig: '9f3e' });
  assert.equal(e.wire, 'K01234567-01-9f3e');
  const d = decodeWire(e.wire);
  assert.deepEqual(d.rings, [1, 2, 3, 4, 5, 6, 7]);
  assert.equal(d.intent, 1);
  assert.equal(d.payload, undefined);
  assert.equal(d.sig, '9f3e');
});

test('encodeWire/decodeWire: extended form with payload roundtrips exactly', () => {
  for (const payload of ['a', 'ab', 'abc', 'hello mesh — κ holds', '']) {
    const e = encodeWire({ rings: [0, 1, 0, 2, 0, 3, 0], intent: 0x30, payload, sig: 'deadbeef' });
    assert.equal(e.ok, true, 'encode failed for: ' + payload);
    const d = decodeWire(e.wire);
    assert.equal(d.ok, true, 'decode failed for: ' + payload);
    assert.equal(d.payload, payload);
    assert.equal(d.intent, 0x30);
  }
});

test('wire: payload size boundary — 65535 accepted, 65536 refused (kills > vs >=)', () => {
  const big = encodeWire({ rings: [0,0,0,0,0,0,0], intent: 1, payload: 'a'.repeat(65535), sig: 'abcd' });
  assert.equal(big.ok, true);
  assert.equal(decodeWire(big.wire).payload.length, 65535);
  assert.equal(encodeWire({ rings: [0,0,0,0,0,0,0], intent: 1, payload: 'a'.repeat(65536), sig: 'abcd' }).ok, false);
});

test('wire: refusals — bad marker, parts, intent, sig, length lie', () => {
  assert.equal(decodeWire('X01234567-01-9f3e').ok, false);          // no K
  assert.equal(decodeWire('K01234567-01').ok, false);               // 2 parts
  assert.equal(decodeWire('K01234567-01-0001-YQ==-9f3e-zz').ok, false); // 6 parts
  assert.equal(decodeWire('K01234567-80-9f3e').ok, false);          // intent 128
  assert.equal(decodeWire('K01234567-01-9f3').ok, false);           // odd sig
  assert.equal(decodeWire('K01234567-01-9f').ok, false);            // sig too short
  assert.equal(decodeWire('K01234567-01-0002-YQ==-9f3e').ok, false); // declared 2, actual 1 byte
  assert.equal(decodeWire('K01234567-01-0001-!!!!-9f3e').ok, false); // bad base64
  assert.equal(encodeWire({ rings: [0,0,0,0,0,0,0], intent: 0x80, sig: 'abcd' }).ok, false);
  assert.equal(encodeWire({ rings: [0,0,0,0,0,0,0], intent: 1, sig: 'xyz!' }).ok, false);
  assert.equal(encodeWire(null).ok, false);
});

test('intentName: taxonomy pins and range guards', () => {
  assert.equal(intentName(0x01).name, 'message');
  assert.equal(intentName(0x22).name, 'receipt');
  assert.equal(intentName(0x55).name, 'intent-55');   // valid but unnamed
  assert.equal(intentName(0x80).ok, false);
  assert.equal(intentName(-1).ok, false);
  assert.equal(INTENTS[0x7f], 'bye');
});

// ── the capability lattice
test('makeGrant + attenuate: a child never exceeds its parent', () => {
  const root = makeGrant('simon', ['message', 'share', 'offer'], 100).grant;
  const child = attenuate(root, 'node-a', ['message', 'share'], 40);
  assert.equal(child.ok, true);
  assert.equal(child.grant.budget, 40);
  assert.equal(attenuate(root, 'node-b', ['message', 'revoke'], 10).ok, false);   // scope parent lacks
  assert.equal(attenuate(root, 'node-c', ['message'], 101).ok, false);            // more budget than remains
  assert.equal(attenuate(root, 'node-d', ['message'], 100).ok, true);             // exactly what remains — allowed (kills > vs >=)
});

test('attenuate: respects what the parent has already SPENT', () => {
  const root = { holder: 'simon', scope: ['message'], budget: 100, spent: 60 };
  assert.equal(attenuate(root, 'a', ['message'], 40).ok, true);    // exactly the remainder
  assert.equal(attenuate(root, 'b', ['message'], 41).ok, false);   // one over the remainder
});

test('mayAct: fail-safe — unknown or outside is refused; the budget boundary is exact', () => {
  const g = makeGrant('n', ['message'], 10).grant;
  assert.equal(mayAct(g, 'message', 10).allowed, true);    // exactly the budget — allowed
  assert.equal(mayAct(g, 'message', 11).allowed, false);   // one over — refused
  assert.equal(mayAct(g, 'launch', 1).allowed, false);     // outside the grant
  assert.equal(mayAct(g, '', 1).allowed, false);           // unknown action
  assert.equal(mayAct(g, 'message', -1).allowed, false);   // unknown cost
  assert.equal(mayAct(g, 'message', 1.5).allowed, false);  // non-integer cost
  assert.equal(mayAct({ holder: 'x', scope: ['a'], budget: 5, spent: 9 }, 'a', 0).ok, false);   // malformed grant (spent>budget)
});

test('charge: a refusal charges NOTHING and mutates nothing', () => {
  const g = makeGrant('n', ['message'], 10).grant;
  const refused = charge(g, 'launch', 5);
  assert.equal(refused.allowed, false);
  assert.equal(refused.charged, 0);
  assert.equal(refused.grant.spent, 0);
  const okc = charge(g, 'message', 4);
  assert.equal(okc.allowed, true);
  assert.equal(okc.charged, 4);
  assert.equal(okc.grant.spent, 4);
  assert.equal(g.spent, 0);   // the original grant object is untouched
});

// ── the witness chain
test('appendWitness/verifyLedger: a clean chain verifies; genesis is pinned', () => {
  let c = appendWitness([], { act: 'hello', who: 'a' }).chain;
  c = appendWitness(c, { act: 'message', who: 'a', to: 'b' }).chain;
  c = appendWitness(c, { act: 'receipt', who: 'b' }).chain;
  assert.equal(c[0].prevHash, 'GENESIS');
  assert.equal(c.length, 3);
  const v = verifyLedger(c);
  assert.equal(v.valid, true);
  assert.equal(v.length, 3);
  assert.equal(verifyLedger([]).valid, true);
});

test('witness: canonical hashing — key order does not change the hash', () => {
  const a = appendWitness([], { b: 1, a: 2 }).chain[0].hash;
  const b = appendWitness([], { a: 2, b: 1 }).chain[0].hash;
  assert.equal(a, b);
});

test('witness: TAMPER anywhere breaks the chain at the right link', () => {
  let c = appendWitness([], { act: 'one' }).chain;
  c = appendWitness(c, { act: 'two' }).chain;
  c = appendWitness(c, { act: 'three' }).chain;
  const tamperedEntry = c.map((x, i) => i === 1 ? { ...x, entry: { act: 'TWO-FORGED' } } : x);
  assert.equal(verifyLedger(tamperedEntry).valid, false);
  assert.equal(verifyLedger(tamperedEntry).brokenAt, 1);
  const tamperedHash = c.map((x, i) => i === 2 ? { ...x, hash: 'f'.repeat(64) } : x);
  assert.equal(verifyLedger(tamperedHash).valid, false);
  const reordered = [c[0], c[2], c[1]].map((x, i) => x);
  assert.equal(verifyLedger(reordered).valid, false);
  assert.equal(appendWitness('x', {}).ok, false);
  assert.equal(appendWitness([], 'x').ok, false);
});

// ── the constants themselves
test('constants: the seven ring primes and RING_MAX are pinned numerically', () => {
  assert.deepEqual([...PRIMES], [2, 3, 5, 7, 11, 13, 17]);
  assert.equal(RING_MAX, 15);
});

// ═══ kill probes — every guard boundary exact, every || clause isolated ═══════════════════════════

test('kill: base64 is pinned byte-for-byte through the wire (all three pad classes)', () => {
  const w = (payload) => encodeWire({ rings: [0,0,0,0,0,0,0], intent: 1, payload, sig: 'abcd' }).wire;
  assert.equal(w('a'),   'K00000000-01-0001-YQ==-abcd');   // pad 2
  assert.equal(w('ab'),  'K00000000-01-0002-YWI=-abcd');   // pad 1
  assert.equal(w('abc'), 'K00000000-01-0003-YWJj-abcd');   // pad 0
  assert.equal(w(''),    'K00000000-01-0000--abcd');       // empty payload, no b64
});

test('kill: foldBloom refuses an array-LIKE with 7 valid slots (isolates the isArray clause)', () => {
  const arrayLike = { 0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, length: 7 };
  assert.equal(foldBloom(arrayLike).ok, false);
  assert.equal(bloomHex(arrayLike).ok, false);
});

test('kill: applyDelta boundaries — r 0 and 6 valid, v 0 and 15 valid, each one-past refused', () => {
  const base = [1, 2, 3, 4, 5, 6, 7];
  assert.deepEqual(applyDelta(base, [{ r: 0, v: 9 }]).rings, [9, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual(applyDelta(base, [{ r: 6, v: 9 }]).rings, [1, 2, 3, 4, 5, 6, 9]);
  assert.deepEqual(applyDelta(base, [{ r: 0, v: 0 }]).rings, [0, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual(applyDelta(base, [{ r: 0, v: 15 }]).rings, [15, 2, 3, 4, 5, 6, 7]);
  assert.equal(applyDelta(base, [{ r: -1, v: 1 }]).ok, false);
  assert.equal(applyDelta(base, [{ r: 0, v: -1 }]).ok, false);
  assert.equal(applyDelta(base, [{ r: 'x', v: 1 }]).ok, false);   // isolates isInt(d.r)
  assert.equal(applyDelta(base, [{ r: 1, v: 'x' }]).ok, false);   // isolates isInt(d.v)
});

test('kill: intent boundaries — 0 and 0x7f valid through name, encode AND decode; each clause isolated', () => {
  assert.equal(intentName(0).name, 'hello');
  assert.equal(intentName(0x7f).name, 'bye');
  assert.equal(intentName('x').ok, false);                        // isolates isInt
  const at = (intent) => encodeWire({ rings: [0,0,0,0,0,0,0], intent, sig: 'abcd' });
  assert.equal(at(0).wire, 'K00000000-00-abcd');
  assert.equal(at(0x7f).wire, 'K00000000-7f-abcd');
  assert.equal(at(-1).ok, false);                                 // isolates intent < 0
  assert.equal(at(1.5).ok, false);                                // isolates isInt
  assert.equal(at('x').ok, false);
  assert.equal(decodeWire('K00000000-7f-abcd').intent, 0x7f);     // decode boundary: 127 accepted
  assert.equal(decodeWire('K00000000-00-abcd').intent, 0);
});

test('kill: decode refusals with exactly one clause bad', () => {
  assert.equal(decodeWire(['K', 'x']).ok, false);                  // non-string whose [0] IS K — isolates isStr
  assert.equal(decodeWire('K00000000-f-abcd').ok, false);          // intent 1 char, hex — isolates length
  assert.equal(decodeWire('K00000000-zz-abcd').ok, false);         // intent 2 chars, non-hex — isolates HEX
  assert.equal(decodeWire('K00000000-01-ab').ok, false);           // sig len 2: even+hex — isolates < 4
  assert.equal(decodeWire('K00000000-01-abcde').ok, false);        // sig len 5: ≥4+hex — isolates % 2
  assert.equal(decodeWire('K00000000-01-wxyz').ok, false);         // sig len 4: even — isolates HEX
  assert.equal(decodeWire('K00000000-01-001-YQ==-abcd').ok, false);  // len part 3 hex chars — isolates length
  assert.equal(decodeWire('K00000000-01-zzzz-YQ==-abcd').ok, false); // len part 4 non-hex — isolates HEX
  assert.equal(decodeWire('K00000000-01-0001-YQ=-abcd').ok, false);  // b64 length 3 — isolates % 4
});

test('kill: encode sig refusals with exactly one clause bad', () => {
  const at = (sig) => encodeWire({ rings: [0,0,0,0,0,0,0], intent: 1, sig });
  assert.equal(at(12).ok, false);       // isolates isStr
  assert.equal(at('ab').ok, false);     // len 2: even+hex — isolates < 4
  assert.equal(at('abcde').ok, false);  // len 5: ≥4+hex — isolates % 2
  assert.equal(at('wxyz').ok, false);   // len 4: even — isolates HEX
  assert.equal(encodeWire({ rings: [0,0,0,0,0,0,0], intent: 1, payload: 5, sig: 'abcd' }).ok, false);
});

test('kill: unbloomHex refuses uppercase (the hex alphabet is lowercase only)', () => {
  assert.equal(unbloomHex('0FFFFFFF').ok, false);
  assert.equal(unbloomHex('0fffffff').ok, true);
});

test('kill: grant guards — each clause isolated, every boundary exact', () => {
  assert.equal(makeGrant('', ['a'], 5).ok, false);        // holder empty — isolates length === 0
  assert.equal(makeGrant(7, ['a'], 5).ok, false);         // holder non-string — isolates isStr
  assert.equal(makeGrant('n', 'a', 5).ok, false);         // scope non-array
  assert.equal(makeGrant('n', ['a', ''], 5).ok, false);   // scope entry empty — isolates length
  assert.equal(makeGrant('n', ['a', 7], 5).ok, false);    // scope entry non-string — isolates isStr
  assert.equal(makeGrant('n', [], 0).ok, true);           // budget 0 is valid (kills < 0 → <= 0)
  assert.equal(makeGrant('n', [], -1).ok, false);         // isolates budget < 0
  assert.equal(makeGrant('n', [], 1.5).ok, false);        // isolates isInt
  assert.equal(mayAct(null, 'a', 1).ok, false);           // grant not an object
  assert.equal(mayAct(5, 'a', 1).ok, false);
  assert.equal(mayAct({ holder: 'x', scope: ['a'], budget: 5, spent: -1 }, 'a', 1).ok, false);   // isolates spent < 0
  assert.equal(mayAct({ holder: 'x', scope: ['a'], budget: 5, spent: 1.5 }, 'a', 1).ok, false);  // isolates isInt(spent)
  const full = { holder: 'x', scope: ['a'], budget: 5, spent: 5 };
  assert.equal(mayAct(full, 'a', 0).ok, true);            // spent === budget is a VALID grant (kills > → >=)
  assert.equal(mayAct(full, 'a', 0).allowed, true);
  assert.equal(mayAct(full, 'a', 1).allowed, false);
});

test('kill: mayAct boundaries — cost 0 valid, action type isolated', () => {
  const g = makeGrant('n', ['message'], 10).grant;
  assert.equal(mayAct(g, 'message', 0).allowed, true);    // cost 0 (kills < 0 → <= 0)
  assert.equal(mayAct(g, 7, 1).allowed, false);           // action non-string — isolates isStr
  assert.equal(charge(g, 'message', 0).charged, 0);
  assert.equal(charge(g, 'message', 10).grant.spent, 10); // charge exactly to the budget
});

test('kill: canon distinguishes primitives (numbers, booleans, null hash differently)', () => {
  const h = (entry) => appendWitness([], entry).chain[0].hash;
  assert.notEqual(h({ x: 5 }), h({ x: 6 }));
  assert.notEqual(h({ x: true }), h({ x: false }));
  assert.notEqual(h({ x: null }), h({ x: 0 }));
  assert.notEqual(h({ x: '5' }), h({ x: 5 }));
  assert.equal(appendWitness([], { x: null }).ok, true);
});

test('kill: a refusal names its TRUE reason — the clauses are distinguishable by their why', () => {
  const g = makeGrant('n', ['message'], 10).grant;
  assert.match(mayAct(g, 7, 1).why, /unknown action/);        // non-string action, NOT merely out-of-scope
  assert.match(mayAct(g, '', 1).why, /unknown action/);       // empty action, NOT merely out-of-scope
  assert.match(mayAct(g, 'launch', 1).why, /outside the grant/);
  assert.match(mayAct(g, 'message', -1).why, /unknown cost/);
  assert.match(mayAct(g, 'message', 11).why, /beyond the budget/);
});

test('kill: verifyLedger refuses an ARRAY link even when its forged fields all check out', () => {
  // an array with seq/prevHash/hash/entry properties and an honestly-computed hash: only the
  // isObj(item) clause stands between this forgery and a valid verdict
  const arr = [];
  arr.seq = 0; arr.prevHash = 'GENESIS'; arr.hash = sha256('GENESIS|' + '{}').hash; arr.entry = {};
  assert.equal(verifyLedger([arr]).valid, false);
});

test('kill: verifyLedger type guard — a string entry with a MATCHING hash is still refused', () => {
  // forge a link whose hash is honestly computed over a non-object entry: the type guard alone refuses it
  const forgedHash = sha256('GENESIS|' + '"x"').hash;
  const forged = [{ seq: 0, prevHash: 'GENESIS', hash: forgedHash, entry: 'x' }];
  assert.equal(verifyLedger(forged).valid, false);
  assert.equal(verifyLedger([null]).valid, false);
  assert.equal(verifyLedger('x').ok, false);
});
