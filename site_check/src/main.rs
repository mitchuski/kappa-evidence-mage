// site_check: re-derive every address of the labs site from the sealed soul_mage bundles with kappa-core itself.
// usage: site_check --site <addresses.txt> <bundle-dir>...
use dcbor::prelude::*;
use kappa_core::kappa::{kappa_from_bytes, kappa_from_value, verify_kappa};
use kappa_core::merkle::merkle_root;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

struct Tally { ok: usize, bad: usize }
impl Tally { fn hit(&mut self, cond: bool, msg: &str) { if cond { self.ok += 1 } else { self.bad += 1; println!("  FAIL {msg}") } } }

fn text(m: &Map, k: u64) -> Option<String> { m.get::<u64, String>(k) }
fn uint(m: &Map, k: u64) -> Option<u64> { m.get::<u64, u64>(k) }

fn check_bundle(dir: &Path, t: &mut Tally) -> BTreeSet<String> {
    let name = dir.file_name().unwrap().to_string_lossy().to_string();
    let mut objects: BTreeMap<String, CBOR> = BTreeMap::new();
    let mut edges: BTreeMap<String, CBOR> = BTreeMap::new();
    let mut blobs: BTreeSet<String> = BTreeSet::new();
    for (sub, store) in [("objects", true), ("edges", false)] {
        let mut n = 0usize;
        for ent in fs::read_dir(dir.join(sub)).expect("dir") {
            let p = ent.unwrap().path();
            let stem = p.file_stem().unwrap().to_string_lossy().to_string();
            let bytes = fs::read(&p).unwrap();
            let want = format!("sha256:{stem}");
            // 1. the bytes decode as valid dCBOR under the Rust crate (dcbor rejects non-canonical input)
            let cbor = match CBOR::try_from_data(&bytes) { Ok(c) => c, Err(e) => { t.hit(false, &format!("{name}/{sub}/{stem}: not dCBOR: {e}")); continue } };
            // 2. re-encoding in Rust reproduces the Python bytes exactly
            t.hit(cbor.to_cbor_data() == bytes, &format!("{name}/{sub}/{stem}: Rust re-encoding differs"));
            // 3. kappa_from_value over the decoded value == the file's address; kappa_from_bytes agrees; verify_kappa agrees
            let k = kappa_from_value(&cbor);
            t.hit(k == want && kappa_from_bytes(&bytes) == want && verify_kappa(&want, &bytes).unwrap_or(false),
                  &format!("{name}/{sub}/{stem}: kappa mismatch, got {k}"));
            if store { objects.insert(want, cbor); } else { edges.insert(want, cbor); }
            n += 1;
        }
        println!("  {name}/{sub}: {n} files");
    }
    if let Ok(rd) = fs::read_dir(dir.join("blobs")) {
        for ent in rd { let p = ent.unwrap().path(); let stem = p.file_stem().unwrap().to_string_lossy().to_string();
            let b = fs::read(&p).unwrap(); let want = format!("sha256:{stem}");
            t.hit(kappa_from_bytes(&b) == want, &format!("{name}/blobs/{stem}: kappa mismatch")); blobs.insert(want); }
    }
    let meta: serde_json::Value = serde_json::from_str(&fs::read_to_string(dir.join("root.json")).unwrap()).unwrap();
    let root_k = meta["root_kappa"].as_str().unwrap().to_string();
    let meta_mroot = meta["merkle_root_sha256"].as_str().unwrap().to_string();
    let meta_status = meta["status"].as_str().unwrap().to_string();
    let meta_leaves = meta["merkle_leaves"].as_u64().unwrap() as usize;
    // 4. the run-root object: type, status, merkle root recomputed in Rust over the pre-root leaves
    let root = objects.get(&root_k).cloned();
    t.hit(root.is_some(), &format!("{name}: root object {root_k} missing"));
    if let Some(root) = root {
        let m = root.as_map().unwrap();
        t.hit(text(m, 0).as_deref() == Some("agentprivacy-evidence/run-root/1"), &format!("{name}: root type"));
        t.hit(text(m, 5).as_deref() == Some(meta_status.as_str()), &format!("{name}: root status != root.json"));
        let mut leaves: Vec<String> = objects.keys().filter(|k| **k != root_k).cloned().collect();
        for (k, e) in &edges { if text(e.as_map().unwrap(), 0).as_deref() != Some(root_k.as_str()) { leaves.push(k.clone()); } }
        leaves.extend(blobs.iter().cloned());
        leaves.sort();
        // the leaf set is a set (as the Python and JS verifiers read it): a κ that is
        // both an object and a blob counts once
        leaves.dedup();
        let refs: Vec<&[u8]> = leaves.iter().map(|s| s.as_bytes()).collect();
        let mr = hex::encode(merkle_root(&refs).unwrap());
        t.hit(mr == meta_mroot && text(m, 4).as_deref() == Some(mr.as_str()) && leaves.len() == meta_leaves,
              &format!("{name}: merkle root {mr} ({} leaves) != recorded {meta_mroot} ({meta_leaves})", leaves.len()));
        println!("  {name}: status \"{}\" · root {} · merkle {} over {} leaves", text(m, 5).unwrap_or_default(), &root_k[..23], &mr[..16], leaves.len());
    }
    // 5. every edge endpoint is in the bundle
    let all: BTreeSet<String> = objects.keys().chain(edges.keys()).chain(blobs.iter()).cloned().collect();
    for (k, e) in &edges { let m = e.as_map().unwrap();
        let s = text(m, 0).unwrap_or_default(); let d = text(m, 1).unwrap_or_default();
        t.hit(all.contains(&s) && all.contains(&d), &format!("{name}: edge {k} dangles ({s} -> {d})")); }
    // 6. the link chain: seq 0..n contiguous, each link's record present, each prev == the link before
    let mut links: BTreeMap<u64, (String, String, Option<String>)> = BTreeMap::new();
    for (k, o) in &objects { let m = o.as_map().unwrap();
        if text(m, 0).as_deref() == Some("agentprivacy-evidence/link/1") {
            let seq = uint(m, 1).unwrap();
            // two links with one seq must fail, not let the later silently replace the earlier
            let dup = links.insert(seq, (k.clone(), text(m, 2).unwrap_or_default(), text(m, 3))).is_some();
            t.hit(!dup, &format!("{name}: two links share seq {seq}")); } }
    let mut prev: Option<String> = None;
    for (i, (seq, (k, rec, p))) in links.iter().enumerate() {
        t.hit(*seq == i as u64, &format!("{name}: link seq gap at {seq}"));
        t.hit(objects.contains_key(rec), &format!("{name}: link {seq} record {rec} missing"));
        t.hit(*p == prev, &format!("{name}: link {seq} prev mismatch"));
        prev = Some(k.clone());
    }
    println!("  {name}: {} links walked, {} objects, {} edges", links.len(), objects.len(), edges.len());
    all
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut site: Option<String> = None; let mut anchors: Option<String> = None; let mut dirs = vec![];
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--site" { site = it.next(); }
        else if a == "--anchors" { anchors = it.next(); }
        else if a == "--text-file" { // kappa_from_value over a text file's exact contents as a dCBOR text string
            let f = it.next().unwrap(); let s = fs::read_to_string(&f).unwrap();
            println!("text-file {f}: {} chars -> {}", s.chars().count(), kappa_from_value(&s)); }
        else { dirs.push(a); } }
    let mut t = Tally { ok: 0, bad: 0 };
    let mut all = BTreeSet::new();
    for d in &dirs { println!("bundle {d}"); all.extend(check_bundle(Path::new(d), &mut t)); }
    if let Some(f) = site {
        let addrs: Vec<String> = fs::read_to_string(&f).unwrap().lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        // anchors: addresses a page CITES (contents of an anchor record, not members of a chain), each verified by other
        // means and listed as "<kappa> <how>" in the anchors file; reported, never counted as bundle members.
        let mut anch: BTreeMap<String, String> = BTreeMap::new();
        if let Some(f) = anchors { for l in fs::read_to_string(&f).unwrap().lines() {
            let mut p = l.trim().splitn(2, ' '); if let Some(k) = p.next() { if !k.is_empty() { anch.insert(k.to_string(), p.next().unwrap_or("").to_string()); } } } }
        let (mut missing, mut cited) = (0, 0);
        for a in &addrs { if all.contains(a) { continue; }
            if let Some(how) = anch.get(a) { cited += 1; println!("  anchor {} — {how}", &a[..23]); }
            else { missing += 1; println!("  FAIL site address not in any verified bundle: {a}"); } }
        t.hit(missing == 0, "site addresses missing");
        println!("site: {} addresses · {} chain members re-derived here · {} cited anchors verified separately · {} missing",
                 addrs.len(), addrs.len() - missing - cited, cited, missing);
    }
    println!("site_check: {} checks, {} failures — {}", t.ok + t.bad, t.bad, if t.bad == 0 { "PASS" } else { "FAIL" });
    std::process::exit(if t.bad == 0 { 0 } else { 1 });
}
