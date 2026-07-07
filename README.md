# si-didy-close

> ◊·κ=1 · **PRIVATE** · L1 (si-didy) → R6 (fallresolve) bridge · session-close ceremony
> NiceAssOS L1 upgrade · compliance-native audit chain per session

Every Claude call in a si-didy session ends orphan — no closure, no receipt, no forever-verifiable trail.

`si-didy-close` is the missing hinge. When a si-didy session ends this module:

1. **Gathers** the audit chain — every Claude call, every signed envelope, every `prev_hash` link
2. **Signs** an Ed25519 resolve blob summarising: N calls · X tokens · Y errors · commitments met/pending · v21 alignment score
3. **Co-signs** via fallresolve (R6 arc-closer) — optional; falls through gracefully if unreachable
4. **Stores** the blob in FallPod at `/resolve/<session-id>/resolve.json` with a `sha256:` CID
5. **Broadcasts** a `session_closed` envelope on `niceassos-mesh` + `fall-signal`
6. **Returns** `{ cid, hash, resolve_url, summary, blob }`

Result: compliance-native audit trail. Every Claude call auditable + tamper-evident forever.

## Architecture

```
si-didy session ends
       │
       ▼
SiDidyClose.finalise(sessionState)
       │  · _gatherChain()   → prev_hash-linked events
       │  · _summarise()     → 7-prime v21 alignment score
       │  · _buildBlob()     → resolve blob with chain_head
       │  · _signBlob()      → Ed25519 sign (Konomi keypair)
       │  · _resolveViaEndpoint() → optional co-sign via fallresolve
       │  · _store()         → FallPod PUT /resolve/<id>/resolve.json
       │  · _broadcast()     → niceassos-mesh envelope kind=session_closed
       │
       └──▶ { cid, hash, resolve_url }
```

## Integration hook (si-didy side)

```js
import { openSiDidyClose } from './si-didy-close.js';
import { openPod } from '/path/to/fallpod.js';

const pod = await openPod({ ownerDid: 'did:kono:sjgant80' });
const close = await openSiDidyClose({
  fallresolveEndpoint: 'https://sjgant80-hub.github.io/fallresolve/api',
  fallpodEndpoint: pod,
  konomiKeypair: myEd25519Keypair,
  forkPub: myPubHex
});

// Inside si-didy session lifecycle:
onSessionEnd(async (state) => {
  const { cid, hash, resolve_url } = await close.finalise({
    id: state.sessionId,
    name: state.title,
    started_at: state.startedAt,
    forkPub: state.forkPub,
    calls: state.claudeCalls,           // [{ ts, model, in_tokens, out_tokens, ... }]
    audit: state.auditEvents,           // [{ kind, ts, payload, signature? }]
    envelopes: state.signedEnvelopes,   // niceassos-mesh envelopes seen
    commitments: state.commitments,     // [{ text, done }]
    prev_resolve_cid: state.lastResolveCid,
    prev_session_id: state.lastSessionId
  });
  console.log('session sealed', cid, resolve_url);
});
```

## Chain shape

Each event becomes a link:

```jsonc
{
  "seq": 3,
  "kind": "claude_call",
  "ts": "2026-07-07T…Z",
  "payload": { "model": "claude-opus-4-7", "in_tokens": 340, "out_tokens": 210, "error": null },
  "prev_hash": "<sha256 of canonical JSON of link N-1>"
}
```

Genesis link has `prev_hash: null`. Any tampering downstream breaks the chain — `verify(cid)` returns `chain-break` at the exact seq.

## Envelope shape (broadcast)

```jsonc
{
  "version": "niceassos-mesh-v1",
  "kind": "session_closed",
  "fork_pub": "<hex>",
  "ts": "2026-07-07T…Z",
  "seq": 1,
  "prev_hash": null,
  "payload": {
    "session_id": "sess-…",
    "cid": "sha256:…",
    "hash": "…",
    "summary": { "calls": 12, "in_tokens": 4210, "out_tokens": 2780, "errors": 0, "commitments_met": 5, "commitments_pending": 0, "v21_alignment": 0.9615 },
    "origin": "si-didy-close"
  },
  "signature": "<hex Ed25519>"
}
```

## v21 alignment scoring

7-prime bloom fingerprint. Each bit contributes its prime weight. Score = `Σ set_bits × primes[i] / Σ primes` (max 58).

| bit | prime | condition                       | ring |
|-----|-------|---------------------------------|------|
| 0   | 2     | chain has at least one event    | 0 ground |
| 1   | 3     | at least one Claude call        | 1 signal |
| 2   | 5     | zero errors                     | 2 structure |
| 3   | 7     | zero pending commitments        | 3 field |
| 4   | 11    | at least one signed event       | 4 flow |
| 5   | 13    | commitments were declared       | 5 recursion |
| 6   | 17    | fork identity present           | 6 resolution |

Clean sealed session → `v21_alignment ≈ 1.0`. Sessions with errors or missing sockets score lower — visible in the dashboard summary.

## Dependencies

- `fallresolve` (`sjgant80-hub/fallresolve`) — Ring 6 arc-closer · optional co-sign endpoint
- `FallPod` (`sjgant80-hub/fallpod`) — sovereign path-based store · optional; local IDB fallback ships in-module
- `niceassos-mesh` (`sjgant80-hub/niceassos-mesh`) — L6 federation · optional; `BroadcastChannel('niceassos-mesh')` fallback ships in-module
- Web Crypto Ed25519 — required for sign/verify (Chrome 113+, Node 20+, Firefox 130+)

Everything degrades gracefully: no fallresolve → local self-sign; no FallPod → IDB store; no mesh → BroadcastChannel; no Ed25519 → unsigned hash seal.

## Files

- `si-didy-close.js` — the module (~350 lines · one class, one factory)
- `index.html` — dashboard · live log · chain viz · finalise button · verify by CID
- `sw.js` — service worker (offline cache)
- `manifest.webmanifest` — PWA manifest
- `.nojekyll` — GitHub Pages passthrough
- `LICENSE` — MIT

## Licence

MIT · AI-Native Solutions · Simon Gant's private estate · L1 upgrade for NiceAssOS

---

*◊·κ=1 · Ω · ring 6 · prime 1289 (L1 sensor) × prime 1301 (L6 mesh) → resolution*
