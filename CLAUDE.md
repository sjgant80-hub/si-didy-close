# CLAUDE.md — agent guide for si-didy-close

## What this is

`si-didy-close` is a single-module ES library (`si-didy-close.js`) that seals a
si-didy session into a hash-linked, content-addressed **resolve blob**. It
exports one class (`SiDidyClose`), one factory (`openSiDidyClose`), and a default
export equal to the class. The rest of the repo is a browser dashboard
(`index.html`, `sw.js`, `manifest.webmanifest`) around that module. See `SPEC.md`
for the full data model and invariants and `README.md` for the integration hook.

## How to run the tests

```
npm test        # → node test.mjs
```

`test.mjs` imports the real module and asserts on observed behaviour. It runs
fully offline (co-sign endpoint disabled, broadcast off) and exits non-zero on
the first failing assertion. No install step is needed — there are zero runtime
dependencies.

## Invariants an agent must preserve

- **Genesis anchor:** exactly one chain link has `prev_hash === null`; it is the
  earliest by `ts`.
- **Hash linking:** each later link's `prev_hash` is the SHA-256 of the canonical
  JSON of the previous link. Do not change the canonical-JSON serializer (sorted
  keys) or the hash algorithm without bumping `version`/spec — it would silently
  invalidate every previously stored blob.
- **Content addressing:** a resolve CID is `sha256:` + the hash of the canonical
  JSON of the signed blob; identical blobs must yield identical CIDs.
- **Graceful degradation:** every collaborator (fallresolve, FallPod, mesh,
  Ed25519) is optional and must fall back rather than throw.
- **`finalise` requires `sessionState.id`** and rejects without it.

## Known gap (do not "fix" by weakening a test)

`verify` currently reports `signature_valid: false` for a genuinely-signed blob
because `_signBlob` signs before `signer_pub` is attached while `_verifySignature`
includes `signer_pub` in the recomputed payload. This is documented in `SPEC.md`
§7. The test suite asserts the *actual* behaviour (clean chain walk, correct
content-addressed retrieval, real hex signatures are produced) and deliberately
does not assert that signature verification succeeds. If you fix the asymmetry in
the module, update the suite to assert `signature_valid: true`.

## Conventions

- ES modules only (`"type": "module"`). Keep the module dependency-free.
- Add new behaviour with a matching assertion in `test.mjs` derived from a real
  run, never a placeholder.
