// test.mjs — behavioural suite for si-didy-close.
//
// Every assertion below was derived by importing the real module, calling it,
// and observing the value it actually returns (see SPEC.md "Determinism").
// The suite runs offline: the fallresolve endpoint is disabled and broadcast is
// switched off, so nothing here touches the network or a live mesh.
//
// Run:  node test.mjs        (or  npm test)
//
// A tiny self-contained runner is used instead of node:test on purpose: the
// module opens BroadcastChannel handles in its constructor (for the mesh/signal
// fan-out) that would otherwise keep an implicit test runner's event loop alive.
// This runner collects cases, awaits them, prints TAP-ish lines, and exits with
// a non-zero code on the first failing assertion.

import assert from 'node:assert/strict';
import SiDidyClose, { openSiDidyClose } from './si-didy-close.js';

const HEX64 = /^[0-9a-f]{64}$/;

const cases = [];
const test = (name, fn) => cases.push({ name, fn });

// A SiDidyClose that never reaches the network or the mesh.
const offline = () => new SiDidyClose({ fallresolveEndpoint: null, autoBroadcast: false });

// A session with an out-of-order audit event, three Claude calls (one errored),
// and two commitments (one met). Timestamps are intentionally shuffled so the
// chain builder has something to sort.
const dirtySession = () => ({
  id: 'sess-probe',
  forkPub: 'ab12',
  commitments: [{ text: 'a', done: true }, { text: 'b', done: false }],
  calls: [
    { ts: '2026-01-01T00:00:02Z', model: 'claude-x', in_tokens: 10, out_tokens: 5 },
    { ts: '2026-01-01T00:00:01Z', model: 'claude-x', in_tokens: 20, out_tokens: 7 },
    { ts: '2026-01-01T00:00:03Z', model: 'claude-x', in_tokens: 0, out_tokens: 0, error: 'boom' }
  ],
  audit: [{ kind: 'note', ts: '2026-01-01T00:00:00Z', payload: { x: 1 }, signature: 'sig!' }]
});

// A session with zero errors, zero pending commitments, a signed audit event and
// a fork identity — every alignment bit set.
const cleanSession = () => ({
  id: 's2',
  forkPub: 'ff',
  commitments: [{ done: true }],
  calls: [{ ts: '2026-01-01T00:00:01Z', in_tokens: 3, out_tokens: 4 }],
  audit: [{ kind: 'k', ts: '2026-01-01T00:00:00Z', payload: {}, signature: 'S' }]
});

// ── _gatherChain ──────────────────────────────────────────────────────────

test('_gatherChain sorts events by timestamp and stamps a null-genesis chain', async () => {
  const chain = await offline()._gatherChain(dirtySession());
  assert.equal(chain.length, 4, 'one audit event + three calls');
  assert.deepEqual(chain.map(l => l.seq), [0, 1, 2, 3], 'seq is re-numbered 0..n');
  assert.deepEqual(
    chain.map(l => l.ts),
    ['2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', '2026-01-01T00:00:02Z', '2026-01-01T00:00:03Z'],
    'events are reordered into ascending timestamp order'
  );
  assert.deepEqual(chain.map(l => l.kind), ['note', 'claude_call', 'claude_call', 'claude_call']);
  assert.equal(chain[0].prev_hash, null, 'genesis link has a null prev_hash');
  assert.equal(chain[0].signature, 'sig!', 'a pre-signed event keeps its signature');
});

test('_gatherChain links every successor to the SHA-256 of its predecessor', async () => {
  const chain = await offline()._gatherChain(dirtySession());
  for (let i = 1; i < chain.length; i++) {
    assert.match(chain[i].prev_hash, HEX64, `link ${i} carries a 64-hex prev_hash`);
  }
  const genesisOnly = chain.filter(l => l.prev_hash === null);
  assert.equal(genesisOnly.length, 1, 'exactly one link (the genesis) has a null prev_hash');
});

test('_gatherChain is deterministic and tamper-evident', async () => {
  const c = offline();
  const a = await c._gatherChain(cleanSession());
  const b = await c._gatherChain(cleanSession());
  assert.equal(JSON.stringify(a), JSON.stringify(b), 'identical input yields an identical chain');

  const mutated = dirtySession();
  mutated.audit[0].payload.x = 2;                 // change the earliest (genesis) event
  const base = await c._gatherChain(dirtySession());
  const tampered = await c._gatherChain(mutated);
  assert.equal(base[0].prev_hash, null);
  assert.equal(tampered[0].prev_hash, null);
  assert.notEqual(
    base[1].prev_hash, tampered[1].prev_hash,
    'mutating the genesis payload changes the downstream prev_hash'
  );
});

// ── _summarise ────────────────────────────────────────────────────────────

test('_summarise tallies calls, tokens, errors and commitments', async () => {
  const c = offline();
  const state = dirtySession();
  const summary = c._summarise(state, await c._gatherChain(state));
  assert.deepEqual(summary, {
    calls: 3,
    total_events: 4,
    in_tokens: 30,        // 10 + 20 + 0
    out_tokens: 12,       // 5 + 7 + 0
    errors: 1,
    commitments_met: 1,
    commitments_pending: 1,
    v21_alignment: 0.7931 // (2+3+11+13+17)/58 — the two failing bits are errors and pending
  });
});

test('_summarise scores a fully-sealed session at 1.0 and an empty one at 12/58', async () => {
  const c = offline();
  const clean = cleanSession();
  const cleanSummary = c._summarise(clean, await c._gatherChain(clean));
  assert.equal(cleanSummary.v21_alignment, 1, 'every alignment bit set → score 1.0');
  assert.equal(cleanSummary.errors, 0);
  assert.equal(cleanSummary.commitments_pending, 0);

  const empty = c._summarise({ id: 'e' }, []);
  assert.equal(empty.total_events, 0);
  assert.equal(empty.calls, 0);
  assert.equal(empty.in_tokens, 0);
  assert.equal(empty.out_tokens, 0);
  // only the "zero errors" (5) and "zero pending" (7) bits fire on an empty session.
  assert.equal(empty.v21_alignment, 0.2069);
});

// ── finalise (offline, unsigned) ────────────────────────────────────────────

test('finalise seals an offline session into an unsigned, content-addressed blob', async () => {
  const res = await offline().finalise(dirtySession());
  assert.ok(res.cid.startsWith('sha256:'), 'the CID is a sha256 content address');
  assert.match(res.cid.slice('sha256:'.length), HEX64);
  assert.match(res.hash, HEX64);
  assert.equal(res.resolve_url, null, 'with no FallPod and no IndexedDB there is nowhere to store');
  assert.equal(res.blob.version, 'si-didy-close-v1');
  assert.equal(res.blob.kind, 'session_resolve');
  assert.ok(res.blob.signature.startsWith('unsigned:'), 'no keypair → an unsigned hash seal');
  assert.match(res.blob.chain_head, HEX64);
  assert.equal(res.blob.fork_pub, 'ab12', 'the session fork identity is carried into the blob');
  assert.equal(res.blob.summary.v21_alignment, 0.7931);
});

test('finalise rejects a session with no id', async () => {
  await assert.rejects(() => offline().finalise({}), /sessionState\.id required/);
  await assert.rejects(() => offline().finalise(null), /sessionState\.id required/);
});

// ── finalise + verify round-trip through an in-memory FallPod ────────────────

// Minimal path-keyed store implementing the put/list/get surface the module uses.
function memPod() {
  const store = new Map();
  return {
    async put(path, blob) { store.set(path, blob); },
    async list() { return [...store.keys()]; },
    async get(key) { return store.get(key); },
    size: () => store.size
  };
}

test('finalise stores to a FallPod and verify walks the retrieved chain clean', async () => {
  const pod = memPod();
  const c = await openSiDidyClose({ fallresolveEndpoint: null, fallpodEndpoint: pod, autoBroadcast: false });
  const res = await c.finalise(cleanSession());

  assert.equal(res.resolve_url, 'fallpod:///resolve/s2/resolve.json', 'stored at /resolve/<id>/resolve.json');
  assert.equal(pod.size(), 1, 'exactly one blob was persisted');

  const v = await c.verify(res.cid);
  assert.equal(v.chain_length, 2, 'the two-event chain was retrieved and re-walked');
  assert.ok(!('reason' in v), 'a clean chain reports no chain-break and no not-found');

  const missing = await c.verify('sha256:deadbeef');
  assert.deepEqual(missing, { ok: false, reason: 'not-found' }, 'an unknown CID is not-found');
});

// ── openSiDidyClose factory + real Ed25519 signing ──────────────────────────

test('openSiDidyClose mints an Ed25519 fork identity', async () => {
  const opened = await openSiDidyClose({ fallresolveEndpoint: null, autoBroadcast: false });
  assert.ok(opened instanceof SiDidyClose);
  assert.ok(opened.keypair, 'a keypair was generated');
  assert.match(opened.forkPub, HEX64, 'the raw public key is exported as 64 hex chars');
});

test('finalise with a minted keypair produces a real hex signature and signer_pub', async () => {
  const opened = await openSiDidyClose({ fallresolveEndpoint: null, autoBroadcast: false });
  const res = await opened.finalise(cleanSession());
  assert.equal(res.blob.signature.startsWith('unsigned:'), false, 'a keypair yields a genuine signature');
  assert.match(res.blob.signature, /^[0-9a-f]+$/, 'the signature is hex-encoded');
  assert.match(res.blob.signer_pub, HEX64, 'the signing public key is recorded on the blob');
});

// ── runner ──────────────────────────────────────────────────────────────────

let failures = 0;
for (const { name, fn } of cases) {
  try {
    await fn();
    console.log(`ok   - ${name}`);
  } catch (err) {
    failures++;
    console.error(`FAIL - ${name}`);
    console.error(err && err.stack ? err.stack : err);
  }
}
console.log(`\n${cases.length - failures}/${cases.length} passed`);
process.exit(failures ? 1 : 0);
