// ---- κ core: dCBOR (the subset the evidence shapes use), SHA-256, Merkle, bundle verify ----
const enc = new TextEncoder(), dec = new TextDecoder();
const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const unhex = h => Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const sha = async b => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
const kappa = async b => 'sha256:' + hex(await sha(b));
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

function head(major, n) {
  const m = major << 5;
  if (n < 24) return Uint8Array.of(m | n);
  if (n < 0x100) return Uint8Array.of(m | 24, n);
  if (n < 0x10000) return Uint8Array.of(m | 25, n >> 8, n & 255);
  if (n < 0x100000000) return Uint8Array.of(m | 26, n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  throw new Error('integer too large for this demo');
}
function encode(v) {
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'boolean') return Uint8Array.of(v ? 0xf5 : 0xf4);
  if (typeof v === 'string') { const b = enc.encode(v.normalize('NFC')); return cat(head(3, b.length), b); }
  if (v instanceof Uint8Array) return cat(head(2, v.length), v);
  if (Array.isArray(v)) return cat(head(4, v.length), ...v.map(encode));
  if (v instanceof Map) {
    const es = [...v].map(([k, x]) => [encode(k), encode(x)]);
    es.sort((a, b) => { const p = a[0], q = b[0]; for (let i = 0; i < Math.min(p.length, q.length); i++) if (p[i] !== q[i]) return p[i] - q[i]; return p.length - q.length; });
    return cat(head(5, es.length), ...es.flat());
  }
  throw new Error('unsupported value');
}
function decode(b) {
  let i = 0;
  const arg = info => {
    if (info < 24) return info;
    const n = 1 << (info - 24); if (info > 26) throw new Error('unsupported length');
    let x = 0; for (let j = 0; j < n; j++) x = x * 256 + b[i++]; return x;
  };
  const item = () => {
    const ib = b[i++], major = ib >> 5, info = ib & 31;
    if (major === 7) { if (info === 20) return false; if (info === 21) return true; throw new Error('unsupported simple value'); }
    const n = arg(info);
    if (major === 0) return n;
    if (major === 1) return -1 - n;
    if (major === 2) { const s = b.slice(i, i + n); i += n; return s; }
    if (major === 3) { const s = dec.decode(b.slice(i, i + n)); i += n; return s; }
    if (major === 4) { const a = []; for (let j = 0; j < n; j++) a.push(item()); return a; }
    if (major === 5) { const m = new Map(); for (let j = 0; j < n; j++) { const k = item(); m.set(k, item()); } return m; }
    throw new Error('unsupported major type');
  };
  const v = item(); if (i !== b.length) throw new Error('trailing bytes'); return v;
}
async function merkleRoot(leaves) {
  let level = await Promise.all(leaves.map(x => sha(cat(Uint8Array.of(0), x))));
  while (level.length > 1) {
    const nxt = [];
    for (let j = 0; j < level.length; j += 2) nxt.push(await sha(cat(Uint8Array.of(1), level[j], level[j + 1] || level[j])));
    level = nxt;
  }
  return hex(level[0]);
}
const REL = { 1: 'composed-of', 11: 'derived-from', 13: 'evidence-provenance' };

// bundle: {objects:{name:Uint8Array}, edges:{name:Uint8Array}, blob:{name, bytes}, root:'sha256:..'}
async function verifyBundle(B) {
  const out = [], say = (ok, text) => out.push({ ok, text });
  const short = k => k.replace('sha256:', '').slice(0, 10) + '…';
  const objs = {}, edges = {}, actual = [], badNames = [];
  let bad = 0;
  for (const [store, into] of [[B.objects, objs], [B.edges, edges]]) {
    for (const [name, bytes] of Object.entries(store)) {
      const k = await kappa(bytes); actual.push(k);
      let v = null, canon = false;
      try { v = decode(bytes); canon = same(encode(v), bytes); } catch (e) { }
      if (k !== 'sha256:' + name) { bad++; badNames.push('sha256:' + name); say(false, `${short(name)} no longer hashes to its name (now ${short(k)})`); }
      else if (!canon) { bad++; say(false, `${short(name)} is not canonical dCBOR`); }
      into['sha256:' + name] = v;
    }
  }
  const blobK = await kappa(B.blob.bytes); actual.push(blobK);
  const blobOk = blobK === 'sha256:' + B.blob.name;
  if (!blobOk) { bad++; badNames.push('sha256:' + B.blob.name); say(false, `blob ${short(B.blob.name)} no longer hashes to its name (now ${short(blobK)})`); }
  if (!bad) say(true, `re-hashed ${Object.keys(objs).length} objects, 1 blob, ${Object.keys(edges).length} edges: every name is the hash of its bytes`);

  const root = objs[B.root];
  if (!(root instanceof Map) || root.get(0) !== 'agentprivacy-evidence/run-root/1') { say(false, 'root is not a run-root/1'); return { ok: false, steps: out, badNames, mOk: false }; }
  const E = Object.entries(edges).filter(([, e]) => e instanceof Map).map(([k, e]) => ({ k, src: e.get(0), tgt: e.get(1), rel: REL[e.get(2)] }));
  const from = (src, rel) => E.filter(e => e.src === src && e.rel === rel).map(e => e.tgt);

  const reached = new Set([B.root]);
  let walkOk = true, provOk = true, checkOk = true, nRows = 0;
  for (const k of from(B.root, 'composed-of')) {
    const o = objs[k]; reached.add(k);
    if (!(o instanceof Map)) { walkOk = false; say(false, `root names ${short(k)}, which is missing`); continue; }
    if (o.get(0) === 'agentprivacy-evidence/ledger/1') {
      const rows = o.get(2), linked = new Set(from(k, 'composed-of'));
      nRows = rows.length;
      for (const r of rows) {
        reached.add(r);
        if (!(objs[r] instanceof Map) || !linked.has(r)) { walkOk = false; say(false, `ledger row ${short(r)} is missing or unlinked`); continue; }
        const src = from(r, 'evidence-provenance');
        if (!src.length || !src.every(t => t === 'sha256:' + B.blob.name && blobOk)) { provOk = false; say(false, `row ${objs[r].get(1)} points at a source blob that is not in the bundle`); }
      }
    }
  }
  if (walkOk) say(true, `composed-of walk from the root reached ${reached.size} objects`);
  if (provOk) say(true, `every row traces to a sealed source blob`);
  for (const [k, o] of Object.entries(objs)) {
    if (!(o instanceof Map) || o.get(0) !== 'agentprivacy-evidence/check/1') continue;
    const ledger = objs[o.get(1)], rule = o.get(2), stored = o.get(3);
    if (rule !== 'rows/count/1' || !(ledger instanceof Map)) { checkOk = false; say(false, `check uses a rule this verifier does not know: ${rule}`); continue; }
    const facts = new Map([['n', ledger.get(2).length]]);
    if (same(encode(facts), encode(stored))) say(true, `recomputed check ${rule}: {"n": ${facts.get('n')}} equals the stored facts`);
    else { checkOk = false; say(false, `check ${rule}: recomputed {"n": ${facts.get('n')}} but the bundle states {"n": ${stored.get('n')}}`); }
  }
  const rootEdges = new Set(E.filter(e => e.src === B.root).map(e => e.k));
  const leaves = [...new Set(actual)].filter(k => k !== B.root && !rootEdges.has(k)).sort();
  const m = await merkleRoot(leaves.map(k => enc.encode(k)));
  const mOk = m === root.get(4);
  say(mOk, mOk ? `Merkle root over ${leaves.length} leaves matches the root` : `Merkle root over the bytes as they are now is ${m.slice(0, 10)}…, the root seals ${String(root.get(4)).slice(0, 10)}…`);
  return { ok: !bad && walkOk && provOk && checkOk && mOk, steps: out, status: root.get(5), lane: root.get(1), badNames, mOk };
}
