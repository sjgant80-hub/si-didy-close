# SPEC — si-didy-close

Design note for the `si-didy-close` module. Engineering contract only: data
model, invariants, public API, determinism guarantees, and versioning. This is
the durable record of what the code is supposed to do, so that a reviewer (human
or automated) can tell whether it is wrong.

Spec version: `spec-0.1` · module version constant: `si-didy-close-v1`.

## 1. Purpose

When a si-didy session ends, its Claude calls and audit events are scattered and
unverifiable. `si-didy-close` turns that loose history into a single, ordered,
hash-linked **resolve blob** that is content-addressed and (optionally) signed,
so the session can be re-verified later by anyone holding the blob.

The module is written to run in a browser (Web Crypto, IndexedDB, BroadcastChannel)
and, for testing, under Node 20+ (which provides the same `crypto.subtle` and
`BroadcastChannel` globals). Every external collaborator — the co-sign endpoint,
the store, the mesh — is optional and degrades to an in-module fallback.

## 2. Data model

### 2.1 Session state (input)

`finalise(sessionState)` accepts an object with an `id` (required) and any of:

| field                | shape                                                        | role |
|----------------------|-------------------------------------------------------------|------|
| `id`                 | string (required)                                           | session identifier; store path key |
| `name`               | string                                                      | human label, copied into the blob |
| `forkPub`            | hex string                                                  | fork identity of the session |
| `started_at`         | ISO string                                                  | copied into the blob |
| `calls`              | `[{ ts, model, in_tokens, out_tokens, error?, … }]`         | Claude calls |
| `audit`              | `[{ kind, ts, payload, signature? }]`                       | arbitrary audit events |
| `envelopes`          | `[ envelope ]`                                              | pre-shaped mesh envelopes |
| `commitments`        | `[{ text, done? | met? | status? }]`                        | tracked commitments |
| `prev_resolve_cid`   | string                                                      | lineage back-pointer |
| `prev_session_id`    | string                                                      | lineage back-pointer |

### 2.2 Chain link

Every event (from `envelopes` + `audit` + `calls`) becomes a link:

```jsonc
{ "seq": 0, "kind": "note", "ts": "…Z", "payload": { … },
  "prev_hash": null, "signature": "…"?  }
```

`seq` is re-numbered `0..n-1` after a stable sort by `ts`. `signature` is present
only when the source event carried one.

### 2.3 Resolve blob

```jsonc
{ "version": "si-didy-close-v1", "kind": "session_resolve",
  "session_id": "…", "session_name": …, "fork_pub": …,
  "started_at": …, "closed_at": "…Z",
  "chain": [ …links ], "chain_head": "<sha256 of last link>",
  "summary": { … }, "lineage": { "prev": …, "prevSession": … },
  "hash": "<sha256 of the blob above>", "signature": "…", "signer_pub": … }
```

### 2.4 Summary

`summarise` reduces the chain to counters plus an alignment score:

```jsonc
{ "calls": 3, "total_events": 4, "in_tokens": 30, "out_tokens": 12,
  "errors": 1, "commitments_met": 1, "commitments_pending": 1,
  "v21_alignment": 0.7931 }
```

`v21_alignment` is a weighted bit-vector score. Seven independent booleans about
the session are each weighted by a distinct prime `[2,3,5,7,11,13,17]` (sum 58);
the score is `Σ(set-bit prime) / 58`, rounded to four decimals. The bits are:
non-empty chain, ≥1 Claude call, zero errors, zero pending commitments, ≥1 signed
event, commitments declared, fork identity present. A fully-sealed session scores
`1.0`; an empty session scores `12/58 = 0.2069` (only the two "zero-of-something"
bits fire).

## 3. Invariants

1. **Genesis is null-anchored.** Exactly one link — the first — has `prev_hash === null`.
2. **Hash linking.** For every `i ≥ 1`, `chain[i].prev_hash` is the SHA-256 (64
   lowercase hex) of the canonical JSON of `chain[i-1]`. Any downstream mutation
   changes every following `prev_hash`, so tampering is detectable at a precise `seq`.
3. **Causal order.** Links are sorted by `ts` ascending before numbering.
4. **Content addressing.** The stored CID is `sha256:` + SHA-256 of the canonical
   JSON of the signed blob. The same blob always yields the same CID.
5. **Graceful degradation.** No co-sign endpoint → local self-sign; no store →
   IndexedDB, else no persisted URL; no mesh → BroadcastChannel; no Ed25519 →
   an `unsigned:<hash-prefix>` seal. A missing collaborator never throws.
6. **Id required.** `finalise` rejects a session state without an `id`.

## 4. Public API

- `new SiDidyClose(opts)` — options: `fallresolveEndpoint`, `fallpodEndpoint`
  (instance with `put/list/get`, or a URL string), `meshInstance`,
  `konomiKeypair` (Ed25519 `CryptoKeyPair`), `forkPub`, `autoBroadcast`,
  `signalChannel`.
- `async finalise(sessionState) → { cid, hash, resolve_url, summary, duration_ms, blob }`.
- `async verify(cid) → { ok, chain_length, signature_valid } | { ok:false, reason }`
  where `reason` is `not-found` or `chain-break` (with `at`).
- `async listResolves()` — enumerate locally persisted resolves (IndexedDB only).
- `openSiDidyClose(opts)` — factory that mints an Ed25519 keypair and derives
  `forkPub` when none is supplied, then returns a `SiDidyClose`.

## 5. Determinism

Serialization is a canonical JSON with **sorted object keys**, so hashing is
stable across engines and key-insertion order. All hashing is SHA-256 via Web
Crypto. Given identical input and no live collaborators, `_gatherChain`,
`_summarise`, and the resulting CID are byte-for-byte reproducible. The test
suite asserts this directly.

## 6. Versioning

The blob carries `version: "si-didy-close-v1"`. A change to the chain-link shape,
the blob shape, or the alignment-bit definition is a breaking change and must bump
both that constant and this document's spec version.

## 7. Known limitation

`verify` recomputes the signed payload from the stored blob but leaves the
`signer_pub` field in that payload, whereas `_signBlob` computes the signature
over the blob **before** `signer_pub` is attached. As a result, `signature_valid`
returns `false` for an otherwise-genuine Ed25519-signed blob. The chain-integrity
walk and content-addressed retrieval are unaffected and verified by the suite;
signature round-tripping is documented here as a known gap rather than silently
asserted as working. Fixing it is a logic change, out of scope for this note.
