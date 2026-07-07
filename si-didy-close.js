// si-didy-close · fallresolve integration · session-close ceremony
// L1 (si-didy) → R6 (fallresolve) bridge · NiceAssOS upgrade
// AI-Native Solutions · MIT · PRIVATE
//
// When a si-didy session ends this module:
//   1. gathers the audit chain (Claude calls, signed envelopes, prev_hash links)
//   2. POSTs to fallresolve which signs a resolve blob
//   3. stores blob in FallPod at /resolve/<id>/
//   4. emits session_closed envelope on niceassos-mesh
//   5. returns { cid, hash, resolve_url }

const DEFAULT_FALLRESOLVE = 'https://sjgant80-hub.github.io/fallresolve/api';
const DEFAULT_FALLPOD_ROOT = '/resolve';
const MESH_CHANNEL = 'niceassos-mesh';
const FALL_SIGNAL = 'fall-signal';
const VERSION = 'si-didy-close-v1';

// ─── crypto helpers ─────────────────────────────────────────────────
const enc = new TextEncoder();
const dec = new TextDecoder();

function toHex(bytes) {
  return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
async function sha256(bytes) {
  const buf = await crypto.subtle.digest('SHA-256', bytes);
  return toHex(buf);
}
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

// ─── SiDidyClose ────────────────────────────────────────────────────
export class SiDidyClose {
  constructor({
    fallresolveEndpoint = DEFAULT_FALLRESOLVE,
    fallpodEndpoint = null,     // FallPod instance (preferred) OR URL for HTTP put
    meshInstance = null,        // niceassos-mesh instance OR null → BroadcastChannel fallback
    konomiKeypair = null,       // { publicKey, privateKey } CryptoKeyPair (Ed25519)
    forkPub = null,             // hex string of Ed25519 pubkey
    autoBroadcast = true,
    signalChannel = FALL_SIGNAL
  } = {}) {
    this.fallresolveEndpoint = fallresolveEndpoint;
    this.fallpod = fallpodEndpoint;
    this.mesh = meshInstance;
    this.keypair = konomiKeypair;
    this.forkPub = forkPub;
    this.autoBroadcast = autoBroadcast;
    this.signalChannel = signalChannel;
    this._seq = 0;
    this._bc = null;
    try {
      if (typeof BroadcastChannel !== 'undefined') {
        this._bc = new BroadcastChannel(signalChannel);
        this._mc = new BroadcastChannel(MESH_CHANNEL);
      }
    } catch { /* node env */ }
  }

  // ── public API ────────────────────────────────────────────────────
  async finalise(sessionState) {
    if (!sessionState || !sessionState.id) {
      throw new Error('sessionState.id required');
    }
    const started = Date.now();
    const chain = await this._gatherChain(sessionState);
    const summary = this._summarise(sessionState, chain);
    const blob = await this._buildBlob(sessionState, chain, summary);
    const signed = await this._signBlob(blob);
    let stored;
    try {
      stored = await this._resolveViaEndpoint(signed);
    } catch (e) {
      // fallresolve unreachable → local self-sign fallback
      stored = { ...signed, _fallback: 'local-self-sign', reason: String(e && e.message || e) };
    }
    const put = await this._store(sessionState.id, stored);
    if (this.autoBroadcast) {
      await this._broadcast(sessionState.id, put.cid, put.hash, summary);
    }
    return {
      cid: put.cid,
      hash: put.hash,
      resolve_url: put.url,
      summary,
      duration_ms: Date.now() - started,
      blob: stored
    };
  }

  async verify(cid) {
    // Retrieve stored blob and verify prev_hash chain + signature
    const blob = await this._retrieve(cid);
    if (!blob) return { ok: false, reason: 'not-found' };
    const chain = blob.chain || [];
    let last = null;
    for (const link of chain) {
      const expect = last ? await sha256(enc.encode(canonicalJSON(last))) : null;
      if (link.prev_hash !== expect) {
        return { ok: false, reason: 'chain-break', at: link.seq };
      }
      last = link;
    }
    const sigOk = await this._verifySignature(blob);
    return { ok: sigOk && true, chain_length: chain.length, signature_valid: sigOk };
  }

  // ── internals ─────────────────────────────────────────────────────
  async _gatherChain(sessionState) {
    // Compile prev_hash chain from audit events. Accepts either:
    //   sessionState.audit  → array of { kind, ts, payload, signature?, prev_hash? }
    //   sessionState.calls  → array of { model, ts, request, response, ... }
    //   sessionState.envelopes → array of pre-shaped envelopes
    const events = [];
    if (Array.isArray(sessionState.envelopes)) {
      for (const e of sessionState.envelopes) events.push({ ...e });
    }
    if (Array.isArray(sessionState.audit)) {
      for (const a of sessionState.audit) events.push({
        kind: a.kind || 'audit',
        ts: a.ts || new Date().toISOString(),
        payload: a.payload || a,
        signature: a.signature || null
      });
    }
    if (Array.isArray(sessionState.calls)) {
      for (const c of sessionState.calls) events.push({
        kind: 'claude_call',
        ts: c.ts || new Date().toISOString(),
        payload: {
          model: c.model || 'claude',
          in_tokens: c.in_tokens || 0,
          out_tokens: c.out_tokens || 0,
          error: c.error || null,
          request_hash: c.request_hash || null,
          response_hash: c.response_hash || null
        }
      });
    }
    // Sort by ts to preserve causal order
    events.sort((a, b) => new Date(a.ts) - new Date(b.ts));
    // Walk and stitch prev_hash chain
    const chain = [];
    let prev = null;
    for (let i = 0; i < events.length; i++) {
      const link = {
        seq: i,
        kind: events[i].kind,
        ts: events[i].ts,
        payload: events[i].payload,
        prev_hash: prev
      };
      if (events[i].signature) link.signature = events[i].signature;
      chain.push(link);
      prev = await sha256(enc.encode(canonicalJSON(link)));
    }
    return chain;
  }

  _summarise(sessionState, chain) {
    const calls = chain.filter(x => x.kind === 'claude_call');
    const errors = chain.filter(x => x.payload && x.payload.error);
    let in_tokens = 0, out_tokens = 0;
    for (const c of calls) {
      in_tokens += (c.payload && c.payload.in_tokens) | 0;
      out_tokens += (c.payload && c.payload.out_tokens) | 0;
    }
    const commitments = sessionState.commitments || [];
    const met = commitments.filter(c => c.done || c.met || c.status === 'done').length;
    const pending = commitments.length - met;
    // v21 alignment score: 7 dims × prime[i] × bit → normalized 0..1
    const primes = [2, 3, 5, 7, 11, 13, 17];
    const bits = [
      chain.length > 0,                              // signal
      calls.length > 0,                              // structure
      errors.length === 0,                           // field integrity
      pending === 0,                                 // flow
      chain.some(x => x.signature),                  // recursion (signed)
      commitments.length > 0,                        // resolution
      (sessionState.forkPub || this.forkPub) != null // ground (identity)
    ];
    let score = 0, max = 0;
    for (let i = 0; i < 7; i++) {
      max += primes[i];
      if (bits[i]) score += primes[i];
    }
    const v21_alignment = max ? +(score / max).toFixed(4) : 0;
    return {
      calls: calls.length,
      total_events: chain.length,
      in_tokens, out_tokens,
      errors: errors.length,
      commitments_met: met,
      commitments_pending: pending,
      v21_alignment
    };
  }

  async _buildBlob(sessionState, chain, summary) {
    const head = chain.length ? await sha256(enc.encode(canonicalJSON(chain[chain.length - 1]))) : null;
    return {
      version: VERSION,
      kind: 'session_resolve',
      session_id: sessionState.id,
      session_name: sessionState.name || null,
      fork_pub: sessionState.forkPub || this.forkPub || null,
      started_at: sessionState.started_at || null,
      closed_at: new Date().toISOString(),
      chain,
      chain_head: head,
      summary,
      lineage: {
        prev: sessionState.prev_resolve_cid || null,
        prevSession: sessionState.prev_session_id || null
      }
    };
  }

  async _signBlob(blob) {
    const bytes = enc.encode(canonicalJSON(blob));
    const hash = await sha256(bytes);
    let signature = null;
    let pub = this.forkPub;
    if (this.keypair && this.keypair.privateKey) {
      try {
        const sig = await crypto.subtle.sign(
          { name: 'Ed25519' },
          this.keypair.privateKey,
          bytes
        );
        signature = toHex(sig);
        if (!pub && this.keypair.publicKey) {
          const raw = await crypto.subtle.exportKey('raw', this.keypair.publicKey);
          pub = toHex(raw);
        }
      } catch (e) {
        // Ed25519 not available → fallback to HMAC-shaped seal
        signature = 'unsigned:' + hash.slice(0, 32);
      }
    } else {
      signature = 'unsigned:' + hash.slice(0, 32);
    }
    return { ...blob, hash, signature, signer_pub: pub };
  }

  async _resolveViaEndpoint(signed) {
    if (!this.fallresolveEndpoint) return signed;
    try {
      const res = await fetch(this.fallresolveEndpoint + '/sign', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(signed)
      });
      if (!res.ok) throw new Error('fallresolve HTTP ' + res.status);
      const co = await res.json();
      // Merge: keep our local signature, add fallresolve co-sign
      return { ...signed, cosign: co.signature || null, cosign_pub: co.pub || null };
    } catch (e) {
      // Endpoint likely a static Pages site with no /sign · that's OK
      throw e;
    }
  }

  async _store(sessionId, signed) {
    const path = `${DEFAULT_FALLPOD_ROOT}/${sessionId}/resolve.json`;
    const bytes = enc.encode(canonicalJSON(signed));
    const cid = 'sha256:' + await sha256(bytes);
    let url = null;

    if (this.fallpod && typeof this.fallpod.put === 'function') {
      // FallPod instance
      await this.fallpod.put(path, signed, { encrypt: false, sign: true });
      url = 'fallpod://' + path;
    } else if (typeof this.fallpod === 'string') {
      // HTTP endpoint
      try {
        await fetch(this.fallpod.replace(/\/$/, '') + path, {
          method: 'PUT',
          headers: { 'content-type': 'application/json' },
          body: canonicalJSON(signed)
        });
        url = this.fallpod.replace(/\/$/, '') + path;
      } catch { /* offline */ }
    } else if (typeof indexedDB !== 'undefined') {
      // Local IDB fallback
      await this._idbPut(sessionId, signed, cid);
      url = 'idb://si-didy-close/' + sessionId;
    }
    return { cid, hash: signed.hash, url, path };
  }

  async _retrieve(cid) {
    if (this.fallpod && typeof this.fallpod.list === 'function') {
      const keys = await this.fallpod.list(DEFAULT_FALLPOD_ROOT);
      for (const k of keys) {
        const rec = await this.fallpod.get(k);
        if (rec && ('sha256:' + await sha256(enc.encode(canonicalJSON(rec)))) === cid) return rec;
      }
    }
    if (typeof indexedDB !== 'undefined') {
      return await this._idbGetByCid(cid);
    }
    return null;
  }

  async _verifySignature(blob) {
    if (!blob.signature || blob.signature.startsWith('unsigned:')) return false;
    if (!blob.signer_pub) return false;
    try {
      const pub = await crypto.subtle.importKey(
        'raw', fromHex(blob.signer_pub),
        { name: 'Ed25519' }, false, ['verify']
      );
      const { signature, hash, cosign, cosign_pub, ...rest } = blob;
      const bytes = enc.encode(canonicalJSON(rest));
      return await crypto.subtle.verify({ name: 'Ed25519' }, pub, fromHex(signature), bytes);
    } catch { return false; }
  }

  async _broadcast(sessionId, cid, hash, summary) {
    this._seq++;
    const envelope = {
      version: 'niceassos-mesh-v1',
      kind: 'session_closed',
      fork_pub: this.forkPub || null,
      ts: new Date().toISOString(),
      seq: this._seq,
      prev_hash: null,
      payload: {
        session_id: sessionId,
        cid, hash,
        summary,
        origin: 'si-didy-close'
      },
      signature: null
    };
    if (this.keypair && this.keypair.privateKey) {
      try {
        const sig = await crypto.subtle.sign(
          { name: 'Ed25519' },
          this.keypair.privateKey,
          enc.encode(canonicalJSON({ ...envelope, signature: undefined }))
        );
        envelope.signature = toHex(sig);
      } catch { /* skip */ }
    }
    try { this._mc && this._mc.postMessage(envelope); } catch { }
    try { this._bc && this._bc.postMessage({ kind: 'session_closed', ...envelope.payload }); } catch { }
    if (this.mesh && typeof this.mesh.publish === 'function') {
      try { await this.mesh.publish(envelope); } catch { }
    }
    return envelope;
  }

  // ── local IDB fallback (persists resolves when no FallPod attached) ──
  async _idbOpen() {
    if (this._idb) return this._idb;
    this._idb = await new Promise((res, rej) => {
      const r = indexedDB.open('si-didy-close', 1);
      r.onupgradeneeded = () => {
        const db = r.result;
        if (!db.objectStoreNames.contains('resolves')) db.createObjectStore('resolves', { keyPath: 'session_id' });
        if (!db.objectStoreNames.contains('by_cid')) db.createObjectStore('by_cid', { keyPath: 'cid' });
      };
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    return this._idb;
  }
  async _idbPut(sessionId, blob, cid) {
    const db = await this._idbOpen();
    return new Promise((res, rej) => {
      const tx = db.transaction(['resolves', 'by_cid'], 'readwrite');
      tx.objectStore('resolves').put({ session_id: sessionId, cid, blob, stored: Date.now() });
      tx.objectStore('by_cid').put({ cid, blob });
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
  }
  async _idbGetByCid(cid) {
    const db = await this._idbOpen();
    return new Promise((res) => {
      const tx = db.transaction('by_cid', 'readonly');
      const r = tx.objectStore('by_cid').get(cid);
      r.onsuccess = () => res(r.result ? r.result.blob : null);
      r.onerror = () => res(null);
    });
  }
  async listResolves() {
    if (typeof indexedDB === 'undefined') return [];
    const db = await this._idbOpen();
    return new Promise((res) => {
      const tx = db.transaction('resolves', 'readonly');
      const r = tx.objectStore('resolves').getAll();
      r.onsuccess = () => res(r.result || []);
      r.onerror = () => res([]);
    });
  }
}

// Convenience factory · mints Ed25519 keypair if none supplied
export async function openSiDidyClose(opts = {}) {
  if (!opts.konomiKeypair) {
    try {
      opts.konomiKeypair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
      const raw = await crypto.subtle.exportKey('raw', opts.konomiKeypair.publicKey);
      opts.forkPub = toHex(raw);
    } catch { /* browser lacks Ed25519 · caller must supply */ }
  }
  return new SiDidyClose(opts);
}

export default SiDidyClose;
