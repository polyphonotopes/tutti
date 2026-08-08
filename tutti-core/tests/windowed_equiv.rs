//! `windowed_equiv` — the M3.0 hard correctness gate
//! (`docs/vision/windowed-store-design.md` §6.3).
//!
//! The whole M3.0 claim in one suite: while `N ≤ W`, the bounded
//! [`WindowedStore`] folds **byte-identically** to a full [`Store`], both agreeing
//! with the kernel `ReachIndex` reference oracle — under shuffled arrival,
//! multi-author concurrent add/remove races, narrow-horizon laggards, equivocating
//! (forked) author logs, and object resurrection straddling the window. Plus the
//! §1.3 fence: the instant `N > W`, the window truncates and `view()` **refuses**
//! rather than silently mis-answer `is_ancestor` across the cut.
//!
//! Style matches `tests/second_domain.rs` and walkie's `reach_equiv`: seeded
//! SplitMix64, shuffled ingest, `view() == view_reference()` (kernel `ReachIndex`)
//! as the root of trust. The test alphabet [`WinLang`] exercises every combinator
//! the design's retention lemmas cover (§6.3): content-keyed add-wins (A), a full-
//! horizon register (R), a sub-horizon-gated read (R′, the lock), and an object
//! graph with resurrection (P/M) — so every lemma has teeth in one alphabet, even
//! though M3.0 discards nothing (retain-everything, §7).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use hhhs::cover::ReachIndex;
use hhhs::{DagRead, GrowthEpoch};

use tutti_core::{
    AuthorId, EntryHash, FoldCtx, LogHead, OpId, OpLanguage, Reach, SignedOp, SigningKey,
    Store, VerifiedOpG, VersionedOpG, WindowedStore, causal_maxima, sign_versioned_op,
    signing_key_from_seed, verify_signed_op_in,
};

// ===========================================================================
// The fourth OpLanguage: every retention-lemma combinator in one alphabet (§6.3).
// ===========================================================================

/// A(dd)/R(em): content-keyed add-wins over a small keyspace (degrees-shaped).
/// SetReg: a full-horizon register (tuning/config-shaped, R). SetLock: a register
/// whose value gates object ops per their causal past (pieces_locked-shaped, R′).
/// Put/Move/Del/Undel: an object graph with resurrection (pieces-shaped, P/M) — an
/// object id is its `Put` op id; `Del` kills observed asserts; `Undel` overrides the
/// `Del` it observed, resurrecting the object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum WinOp {
    Add { key: u16 },
    Rem { key: u16 },
    SetReg { slot: u8, val: u32 },
    SetLock { locked: bool },
    Put { emoji: u8, pos: u32 },
    Move { obj: OpId, pos: u32 },
    Del { obj: OpId },
    Undel { del: OpId },
}

/// The materialized read model — small, primitive-typed fields so a canonical
/// `state_root` (below) is unambiguous.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WinView {
    /// Add-wins live content keys.
    live_keys: BTreeSet<u16>,
    /// Per live key, the authors holding a live add of it.
    key_authors: BTreeMap<u16, BTreeSet<AuthorId>>,
    /// Full-horizon register winners per slot (R).
    reg: BTreeMap<u8, u32>,
    /// Full-horizon lock-register read (the view field).
    locked: bool,
    /// Live objects: id → (emoji, resolved position) (P/M).
    objects: BTreeMap<OpId, (u8, u32)>,
}

struct WinLang;

impl OpLanguage for WinLang {
    type Op = WinOp;
    type View = WinView;

    const SCHEMA_VERSION: u16 = 1;
    const ENTRY_FRAME_MAGIC: &'static [u8] = b"tutti.winlang.entry/1";
    const WIRE_MAGIC: &'static [u8] = b"tutti.winlang.wire/1\0";
    const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

    fn validate_wire(_op: &WinOp) -> Result<(), String> {
        Ok(())
    }

    /// Registers → add-wins keys → objects, mirroring walkie's staged
    /// `with_registers`/`with_pitches`/`with_pieces` composition (src/room/store.rs).
    /// Reads ancestry ONLY through the erased [`FoldCtx`] combinators, so the exact
    /// same code runs on the cheap `Reach`, the kernel `ReachIndex`, and the
    /// `WindowedReach` bitset — the equivalence the gate asserts.
    fn fold(ctx: &FoldCtx<'_, Self>) -> WinView {
        let mut reg_writes: BTreeMap<u8, BTreeSet<EntryHash>> = BTreeMap::new();
        let mut lock_writes: BTreeSet<EntryHash> = BTreeSet::new();
        let mut adds: BTreeMap<u16, Vec<EntryHash>> = BTreeMap::new();
        let mut rems: BTreeMap<u16, Vec<EntryHash>> = BTreeMap::new();
        let mut puts: Vec<(EntryHash, OpId, u8, u32)> = Vec::new();
        let mut moves: Vec<(EntryHash, OpId, u32)> = Vec::new();
        let mut dels: Vec<(EntryHash, OpId, OpId)> = Vec::new();
        let mut undels: Vec<(EntryHash, OpId)> = Vec::new();

        for (entry, decoded) in ctx.decoded() {
            let op_id = ctx.op_id(entry);
            match decoded.op() {
                WinOp::Add { key } => adds.entry(*key).or_default().push(*entry),
                WinOp::Rem { key } => rems.entry(*key).or_default().push(*entry),
                WinOp::SetReg { slot, .. } => {
                    reg_writes.entry(*slot).or_default().insert(*entry);
                }
                WinOp::SetLock { .. } => {
                    lock_writes.insert(*entry);
                }
                WinOp::Put { emoji, pos } => puts.push((*entry, op_id, *emoji, *pos)),
                WinOp::Move { obj, pos } => moves.push((*entry, *obj, *pos)),
                WinOp::Del { obj } => dels.push((*entry, op_id, *obj)),
                WinOp::Undel { del } => undels.push((*entry, *del)),
            }
        }

        // R — full-horizon registers.
        let mut reg = BTreeMap::new();
        for (slot, candidates) in &reg_writes {
            if let Some(winner) = ctx.resolve(candidates)
                && let WinOp::SetReg { val, .. } = ctx.decoded()[&winner].op()
            {
                reg.insert(*slot, *val);
            }
        }
        // Full-horizon lock read (the view field).
        let locked = ctx
            .resolve(&lock_writes)
            .map(|w| matches!(ctx.decoded()[&w].op(), WinOp::SetLock { locked: true }))
            .unwrap_or(false);

        // R′ — the sub-horizon lock gate: resolve the lock register over ONLY an op's
        // causal ancestors. A move/del/undel is suppressed iff an active lock sits in
        // its causal past (a lock CONCURRENT with the op does not suppress it).
        let locked_as_of = |op: &EntryHash| -> bool {
            let observed: BTreeSet<EntryHash> = lock_writes
                .iter()
                .copied()
                .filter(|w| ctx.is_ancestor(w, op))
                .collect();
            ctx.resolve(&observed)
                .is_some_and(|w| matches!(ctx.decoded()[&w].op(), WinOp::SetLock { locked: true }))
        };

        // A — add-wins content keys.
        let mut live_keys = BTreeSet::new();
        let mut key_authors = BTreeMap::new();
        for (key, add_entries) in &adds {
            let key_rems = rems.get(key).map(Vec::as_slice).unwrap_or(&[]);
            let mut authors: BTreeSet<AuthorId> = BTreeSet::new();
            for add in add_entries {
                let killed = key_rems.iter().any(|r| ctx.is_ancestor(add, r));
                if !killed {
                    authors.insert(ctx.decoded()[add].author());
                }
            }
            if !authors.is_empty() {
                live_keys.insert(*key);
                key_authors.insert(*key, authors);
            }
        }

        // P/M — objects with resurrection + lock-gated moves/dels/undels + a position
        // register over the surviving adds.
        let mut objects = BTreeMap::new();
        for (put_entry, obj_id, emoji, put_pos) in &puts {
            let effective_removes: Vec<EntryHash> = dels
                .iter()
                .filter(|(_, _, target)| target == obj_id)
                .filter(|(del_entry, del_id, _)| {
                    if locked_as_of(del_entry) {
                        return false;
                    }
                    let overridden = undels.iter().any(|(un_entry, target_del)| {
                        target_del == del_id
                            && ctx.is_ancestor(del_entry, un_entry)
                            && !locked_as_of(un_entry)
                    });
                    !overridden
                })
                .map(|(del_entry, _, _)| *del_entry)
                .collect();

            let survives = |add: &EntryHash| {
                !effective_removes.iter().any(|r| ctx.is_ancestor(add, r))
            };
            let mut surviving: BTreeSet<EntryHash> = BTreeSet::new();
            if survives(put_entry) {
                surviving.insert(*put_entry);
            }
            for (move_entry, _, _) in moves.iter().filter(|(_, target, _)| target == obj_id) {
                if !locked_as_of(move_entry) && survives(move_entry) {
                    surviving.insert(*move_entry);
                }
            }
            if surviving.is_empty() {
                continue;
            }
            let pos = ctx
                .resolve(&surviving)
                .map(|w| match ctx.decoded()[&w].op() {
                    WinOp::Put { pos, .. } | WinOp::Move { pos, .. } => *pos,
                    _ => unreachable!("a surviving add is a Put or Move"),
                })
                .unwrap_or(*put_pos);
            objects.insert(*obj_id, (*emoji, pos));
        }

        WinView {
            live_keys,
            key_authors,
            reg,
            locked,
            objects,
        }
    }

    /// **M3.1 monotone-shadowing retention** (`windowed-store-design.md` §2.5). The
    /// residue this domain keeps at a cut, composed from the shadowing lemmas:
    ///
    /// - **A (degrees, add-wins):** per key, keep the **per-author causal maxima of
    ///   the surviving adds** (adds no remove observed); discard killed adds,
    ///   non-maximal survivors, and **all removes**. (Lemmas A1-A3: a kill is final;
    ///   a remove is fully consumed once its victims are dropped; a survivor `a₁ < a₂`
    ///   of the same author is redundant — any future remove reaching `a₂` reaches
    ///   `a₁`, and per-author maxima preserve `key_authors`.)
    /// - **R (full-horizon `SetReg`):** per slot, keep the **causal maxima** of the
    ///   writes; discard superseded ones (Lemma R — supersession is permanent, and
    ///   the maxima of the retained set equal the maxima of the full set, so every
    ///   future `resolve` picks the identical winner + tiebreak).
    /// - **R′ (sub-horizon `SetLock`) + P/M (pieces):** **retained wholesale.** The
    ///   lock is read sub-horizon by `locked_as_of` (§2.5-R′: maxima-only retention is
    ///   *unsound* at a wide cut), and pieces resurrect via `Undel` (§2.5-P:
    ///   non-monotone, honestly unbounded residue). Conservative retention is always
    ///   sound — "when in doubt, retain" (§2.4).
    fn retain(ctx: &FoldCtx<'_, Self>, cut: &BTreeSet<EntryHash>) -> BTreeSet<EntryHash> {
        let mut keep: BTreeSet<EntryHash> = BTreeSet::new();
        let mut adds: BTreeMap<u16, Vec<EntryHash>> = BTreeMap::new();
        let mut rems: BTreeMap<u16, Vec<EntryHash>> = BTreeMap::new();
        let mut reg_writes: BTreeMap<u8, BTreeSet<EntryHash>> = BTreeMap::new();

        for entry in cut {
            let Some(decoded) = ctx.decoded().get(entry) else {
                continue;
            };
            match decoded.op() {
                WinOp::Add { key } => adds.entry(*key).or_default().push(*entry),
                // Removes are discarded once their kills are recorded (Lemma A2); we
                // collect them here only to compute which adds survive.
                WinOp::Rem { key } => rems.entry(*key).or_default().push(*entry),
                // R — full-horizon register: compact to per-slot maxima below.
                WinOp::SetReg { slot, .. } => {
                    reg_writes.entry(*slot).or_default().insert(*entry);
                }
                // R′ sub-horizon lock + non-monotone pieces: retain wholesale.
                WinOp::SetLock { .. }
                | WinOp::Put { .. }
                | WinOp::Move { .. }
                | WinOp::Del { .. }
                | WinOp::Undel { .. } => {
                    keep.insert(*entry);
                }
            }
        }

        // R — per-slot register maxima.
        for writes in reg_writes.values() {
            keep.extend(causal_maxima(ctx, writes));
        }

        // A — per-key, per-author maxima of the surviving adds.
        for (key, key_adds) in &adds {
            let key_rems = rems.get(key).map(Vec::as_slice).unwrap_or(&[]);
            let mut by_author: BTreeMap<AuthorId, BTreeSet<EntryHash>> = BTreeMap::new();
            for add in key_adds {
                let killed = key_rems.iter().any(|r| ctx.is_ancestor(add, r));
                if !killed {
                    by_author
                        .entry(ctx.decoded()[add].author())
                        .or_default()
                        .insert(*add);
                }
            }
            for author_adds in by_author.values() {
                keep.extend(causal_maxima(ctx, author_adds));
            }
        }

        keep
    }
}

/// A canonical blake3-256 digest of a [`WinView`] — a stand-in `state_root` (§4.3:
/// "`state_root` survives windowing completely intact"; the generic `L::View:
/// Canonical` bound is not wired in tutti-core, so the gate defines its own canonical
/// encoding). A pure, deterministic function of the sorted view fields.
fn win_state_root(v: &WinView) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"tutti.winlang.state/1");
    h.update(&[v.locked as u8]);
    h.update(b"|keys|");
    for k in &v.live_keys {
        h.update(&k.to_le_bytes());
    }
    h.update(b"|key_authors|");
    for (k, authors) in &v.key_authors {
        h.update(&k.to_le_bytes());
        for a in authors {
            h.update(&a.0);
        }
        h.update(b";");
    }
    h.update(b"|reg|");
    for (slot, val) in &v.reg {
        h.update(&[*slot]);
        h.update(&val.to_le_bytes());
    }
    h.update(b"|obj|");
    for (id, (emoji, pos)) in &v.objects {
        h.update(&id.0);
        h.update(&[*emoji]);
        h.update(&pos.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

// ===========================================================================
// Deterministic harness — seeded SplitMix64, per-author log heads, laggard +
// equivocation injection. No Date::now / no rand crate.
// ===========================================================================

const TOPIC: &str = "winlang-windowed-equiv";
const TS_BASE: u64 = 1_700_000_000_000_000;

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn upto(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
    fn pct(&mut self, p: u64) -> bool {
        self.next() % 100 < p
    }
}

/// Deterministic Fisher-Yates over a seeded PRNG.
fn shuffled(ops: &[SignedOp], seed: u64) -> Vec<SignedOp> {
    let mut items = ops.to_vec();
    let mut rng = Rng::new(seed ^ 0x5EED_5EED_5EED_5EED);
    for i in (1..items.len()).rev() {
        let j = rng.upto(i + 1);
        items.swap(i, j);
    }
    items
}

/// A per-author signing log head, so the harness controls each op's `observed`
/// horizon (laggards) and can fork a log (equivocation) — capabilities `commit`'s
/// auto-frontier does not give.
struct Author {
    key: SigningKey,
    head: LogHead,
}
impl Author {
    fn new(seed: u8) -> Self {
        Self {
            key: signing_key_from_seed(&[seed; 32]),
            head: LogHead::genesis(),
        }
    }
    fn author_id(&self) -> AuthorId {
        AuthorId(*self.key.verifying_key().as_bytes())
    }
    /// Sign, advancing this author's head. Returns the wire bytes + the op's id.
    fn sign(&mut self, ts: u64, observed: Vec<[u8; 32]>, op: WinOp) -> (SignedOp, [u8; 32]) {
        let versioned =
            VersionedOpG::<WinLang>::current_for_topic(op, ts, TOPIC).observing(observed);
        let (signed, advanced) = sign_versioned_op(&self.key, &self.head, versioned);
        self.head = advanced;
        let id = verify_signed_op_in::<WinLang>(&signed).expect("verifies").hash();
        (signed, id)
    }
    /// Sign from an explicit (stale) head WITHOUT advancing — a forked-log op sharing
    /// a seq/backlink with the op that really advanced the head (equivocation, which
    /// verification admits: ops.rs:626-630). Distinct content ⇒ distinct hash.
    fn fork(&self, head: LogHead, ts: u64, observed: Vec<[u8; 32]>, op: WinOp) -> (SignedOp, [u8; 32]) {
        let versioned =
            VersionedOpG::<WinLang>::current_for_topic(op, ts, TOPIC).observing(observed);
        let (signed, _adv) = sign_versioned_op(&self.key, &head, versioned);
        let id = verify_signed_op_in::<WinLang>(&signed).expect("verifies").hash();
        (signed, id)
    }
}

/// A seeded-random multi-author causal history in valid causal order, with laggard
/// horizons, equivocation forks, and object resurrection races (§6.3 "Drive").
///
/// Every op's `observed` references only PRIOR op hashes, so ingest in generation
/// order never parks and any shuffle drains — while the horizons range from the full
/// recent frontier to deliberately stale early prefixes (laggards), so removes /
/// unremoves / register writes straddle every point of history both causally and
/// temporally.
fn build_history(seed: u64, authors: usize, steps: usize) -> Vec<SignedOp> {
    let mut rng = Rng::new(seed);
    let mut peers: Vec<Author> = (0..authors).map(|i| Author::new((i + 1) as u8)).collect();

    let mut out: Vec<SignedOp> = Vec::new();
    let mut op_hashes: Vec<[u8; 32]> = Vec::new();
    let mut put_ids: Vec<OpId> = Vec::new();
    let mut del_ids: Vec<OpId> = Vec::new();

    for step in 0..steps {
        let author = rng.upto(authors);
        let ts = TS_BASE + step as u64;

        // Horizon: usually recent (last few ops), sometimes a STALE early prefix
        // (laggard) — the narrow-horizon source of add-wins concurrency and the R′
        // sub-horizon-read hazard.
        let laggard = rng.pct(22);
        let mut observed: Vec<[u8; 32]> = Vec::new();
        if !op_hashes.is_empty() {
            let (lo, hi) = if laggard {
                (0, (op_hashes.len() / 3).max(1))
            } else {
                (op_hashes.len().saturating_sub(6), op_hashes.len())
            };
            for h in &op_hashes[lo..hi] {
                if observed.len() >= 4 {
                    break;
                }
                if rng.pct(45) {
                    observed.push(*h);
                }
            }
        }

        let op = match rng.upto(12) {
            0..=2 => WinOp::Add { key: rng.upto(4) as u16 },
            3 => WinOp::Rem { key: rng.upto(4) as u16 },
            4 => WinOp::SetReg { slot: rng.upto(3) as u8, val: rng.upto(1000) as u32 },
            5 => WinOp::SetLock { locked: rng.pct(50) },
            6 => WinOp::Put { emoji: rng.upto(4) as u8, pos: rng.upto(88) as u32 },
            7 => match pick(&put_ids, &mut rng) {
                Some(obj) => WinOp::Move { obj, pos: rng.upto(88) as u32 },
                None => WinOp::Add { key: 0 },
            },
            8 | 9 => match pick(&put_ids, &mut rng) {
                Some(obj) => WinOp::Del { obj },
                None => WinOp::Add { key: 1 },
            },
            _ => match pick(&del_ids, &mut rng) {
                Some(del) => WinOp::Undel { del },
                None => WinOp::Add { key: 2 },
            },
        };

        let head_before = peers[author].head;
        let (signed, id) = peers[author].sign(ts, observed.clone(), op.clone());
        match &op {
            WinOp::Put { .. } => put_ids.push(OpId(id)),
            WinOp::Del { .. } => del_ids.push(OpId(id)),
            _ => {}
        }
        op_hashes.push(id);
        out.push(signed);

        // Equivocation: ~1-in-13 steps, the same author ALSO signs a forked op from
        // the pre-advance head — a genuine antichain of per-author maxima (§2.5-A3).
        if rng.pct(8) {
            let fork_op = WinOp::Add { key: rng.upto(4) as u16 };
            let (fsigned, fid) =
                peers[author].fork(head_before, ts + 500, observed, fork_op);
            op_hashes.push(fid);
            out.push(fsigned);
        }
    }
    out
}

fn pick(ids: &[OpId], rng: &mut Rng) -> Option<OpId> {
    if ids.is_empty() {
        None
    } else {
        Some(ids[rng.upto(ids.len())])
    }
}

fn verified(signed: &SignedOp) -> VerifiedOpG<WinLang> {
    verify_signed_op_in::<WinLang>(signed).expect("op verifies")
}

fn ingest_full(ops: &[SignedOp]) -> Store<WinLang> {
    let mut store = Store::new();
    for signed in ops {
        store.ingest_verified(verified(signed));
    }
    store
}

fn ingest_windowed(cap: usize, ops: &[SignedOp]) -> WindowedStore<WinLang> {
    let mut store = WindowedStore::with_cap(cap);
    for signed in ops {
        store.ingest_verified(verified(signed));
    }
    store
}

// ===========================================================================
// The gate.
// ===========================================================================

/// The cheap half of the bundle: view triple-equality against the kernel oracle, and
/// identity of `state_root` / entry-set / `sync_root` between a windowed store and a
/// full store fed the same ops with `N ≤ W` (window complete).
fn assert_view_equiv(windowed: &WindowedStore<WinLang>, full: &Store<WinLang>, label: &str) {
    assert!(windowed.is_complete(), "{label}: window must be complete (N <= W)");
    assert_eq!(windowed.pending_len(), 0, "{label}: windowed liveness (pending == 0)");
    assert_eq!(full.pending_len(), 0, "{label}: full liveness (pending == 0)");

    // The retained set equals the full set while N <= W.
    assert_eq!(windowed.entry_hashes(), full.entry_hashes(), "{label}: retained set == full set");

    // View triple-equality: windowed bitset == full cheap Reach == kernel ReachIndex.
    let wv = windowed.view();
    let fv = full.view();
    assert_eq!(wv, fv, "{label}: windowed.view() != full.view()");
    assert_eq!(fv, full.view_reference(), "{label}: full.view() != full.view_reference() (kernel oracle)");
    assert_eq!(wv, windowed.view_reference(), "{label}: windowed.view() != windowed.view_reference()");

    // state_root survives windowing intact (§4.3).
    assert_eq!(
        win_state_root(&wv),
        win_state_root(&fv),
        "{label}: windowed state_root != full state_root"
    );

    // Cut-scoped sync_root over the retained set == full sync_root (identical set).
    assert_eq!(windowed.sync_root(), full.sync_root(), "{label}: sync_root mismatch");
}

/// The expensive half: the bitset `is_ancestor` ≡ kernel `ReachIndex::is_ancestor`
/// for EVERY in-window pair (§6.3) — the O(N²) reach cross-check, run on a focused
/// subset of the random cases (and on every small targeted vector).
fn assert_reach_equiv(windowed: &WindowedStore<WinLang>, full: &Store<WinLang>, label: &str) {
    let wreach = windowed.windowed_reach();
    let kernel = ReachIndex::new(&full.dag().snapshot());
    let hashes: Vec<EntryHash> = full.entry_hashes().into_iter().collect();
    for a in &hashes {
        for b in &hashes {
            assert_eq!(
                Reach::is_ancestor(&wreach, a, b),
                ReachIndex::is_ancestor(&kernel, a, b),
                "{label}: WindowedReach vs ReachIndex is_ancestor disagreement",
            );
        }
    }
}

/// The FULL bundle (cheap + reach) — used by the small targeted vectors.
fn assert_windowed_equiv(windowed: &WindowedStore<WinLang>, full: &Store<WinLang>, label: &str) {
    assert_view_equiv(windowed, full, label);
    assert_reach_equiv(windowed, full, label);
}

/// THE gate: over many seeded histories, two replicas with DIFFERENT W (both `N ≤ W`)
/// ingesting SHUFFLED arrivals equal each other, the full store, and the kernel
/// oracle — including `ops_root` equality over the retained set (feature `merkle`).
#[test]
fn windowed_equiv_matches_full_history() {
    let mut view_checks = 0usize;
    let mut reach_checks = 0usize;
    for seed in 0..8u64 {
        let authors = 3 + (seed as usize % 2);
        let steps = 90 + (seed as usize % 5) * 20;
        let ops = build_history(seed, authors, steps);
        let n = ops.len();
        // Two DIFFERENT windows, both comfortably >= N so nothing truncates.
        let w1 = n + 1;
        let w2 = n + 137;

        for (order_idx, order_seed) in [1u64, 999_983].into_iter().enumerate() {
            let arrival = shuffled(&ops, seed ^ order_seed);
            let full = ingest_full(&arrival);
            let windowed_a = ingest_windowed(w1, &arrival);
            let windowed_b = ingest_windowed(w2, &shuffled(&ops, seed ^ order_seed ^ 0xABCD));

            assert_view_equiv(&windowed_a, &full, &format!("seed {seed} W={w1} order {order_seed}"));
            assert_view_equiv(&windowed_b, &full, &format!("seed {seed} W={w2} order {order_seed}"));

            // §4.1 — different W, different shuffles, SAME op-set ⇒ equal views.
            assert_eq!(
                windowed_a.view(),
                windowed_b.view(),
                "seed {seed}: replicas with different W diverged (§4.1)"
            );

            // ops_root over the retained set == full ops_root (identical set, §4.3).
            #[cfg(feature = "merkle")]
            {
                assert_eq!(windowed_a.ops_root(), full.ops_root(), "seed {seed}: windowed ops_root != full");
                assert_eq!(windowed_b.ops_root(), full.ops_root(), "seed {seed}: windowed ops_root != full");
            }
            view_checks += 1;

            // The O(N²) bitset-vs-ReachIndex pairwise cross-check, once per seed (on
            // the first arrival order) — every adversarial DAG gets its full pairwise
            // audit; the small targeted vectors below add more, cheaply.
            if order_idx == 0 {
                assert_reach_equiv(
                    &windowed_a,
                    &full,
                    &format!("seed {seed} W={w1} pairwise"),
                );
                reach_checks += 1;
            }
        }
        assert!(!ops.is_empty());
    }
    println!(
        "PASS windowed_equiv: {view_checks} (seed x order) view/state/root/set checks + \
         {reach_checks} full O(N^2) is_ancestor pairwise audits; windowed.view() == full.view() == \
         kernel ReachIndex oracle; bitset is_ancestor == ReachIndex on all in-window pairs; \
         state_root/sync_root/ops_root/entry-set identical; different-W replicas converge"
    );
}

/// §4.1 convergence, isolated: two windowed replicas with different W and randomized
/// arrival orders reach equal views at every quiescent point across MANY seeds.
#[test]
fn different_windows_converge() {
    let mut cases = 0usize;
    for seed in 0..12u64 {
        let ops = build_history(seed ^ 0xC0FFEE, 4, 120 + (seed as usize % 7) * 10);
        let n = ops.len();
        let a = ingest_windowed(n + 3, &shuffled(&ops, seed));
        let b = ingest_windowed(n + 200, &shuffled(&ops, seed ^ 0xF00D));
        assert_eq!(a.pending_len(), 0);
        assert_eq!(b.pending_len(), 0);
        assert!(a.is_complete() && b.is_complete());
        assert_eq!(a.view(), b.view(), "seed {seed}: different-W windows diverged");
        assert_eq!(a.entry_hashes(), b.entry_hashes());
        cases += 1;
    }
    println!("PASS different_windows_converge: {cases} seeds, different-W replicas converge (§4.1)");
}

// ===========================================================================
// Targeted vectors the design names (§6.3 "Targeted vectors").
// ===========================================================================

/// old-add-killed-by-a-later-remove, both retained (`N ≤ W`): a remove observing an
/// early add kills it across a long span of intervening ops — the exact "old add
/// killed by a future remove" the design opens with (§2.3), answered identically by
/// the window's bitset and the kernel.
#[test]
fn old_add_killed_by_later_remove_in_window() {
    let mut a = Author::new(1);
    let mut b = Author::new(2);
    let mut ops: Vec<SignedOp> = Vec::new();

    let (add, add_id) = a.sign(TS_BASE, vec![], WinOp::Add { key: 9 });
    ops.push(add);
    // A concurrent add of the same key by B (add-wins keeps the key alive via B).
    let (badd, _bid) = b.sign(TS_BASE + 1, vec![], WinOp::Add { key: 9 });
    ops.push(badd);
    // 40 unrelated ops widen the span between the add and its remove.
    let mut hashes = vec![add_id];
    for i in 0..40u64 {
        let (o, h) = a.sign(TS_BASE + 10 + i, vec![], WinOp::Add { key: (i % 3) as u16 });
        hashes.push(h);
        ops.push(o);
    }
    // Remove observing ONLY the first add ⇒ kills a's add but not b's concurrent one.
    let (rem, _r) = a.sign(TS_BASE + 100, vec![add_id], WinOp::Rem { key: 9 });
    ops.push(rem);

    let full = ingest_full(&ops);
    let windowed = ingest_windowed(ops.len() + 5, &ops);
    assert_windowed_equiv(&windowed, &full, "old_add_killed_by_later_remove");
    // The add-wins survivor keeps key 9 live (B's concurrent add was never observed).
    assert!(windowed.view().live_keys.contains(&9), "add-wins survivor keeps key 9 live");
    assert_eq!(windowed.view().key_authors[&9], BTreeSet::from([b.author_id()]));
    println!("PASS targeted: old add killed by a later remove, both in-window; windowed == full");
}

/// killed-object-resurrected-by-a-later-undel whose target del is EARLY: the window
/// must still answer `is_ancestor(del, undel)` correctly across the span, or
/// resurrection arithmetic diverges (§2.3, §2.5-P).
#[test]
fn killed_object_resurrected_by_later_undel_in_window() {
    let mut a = Author::new(1);
    let mut ops: Vec<SignedOp> = Vec::new();

    let (put, put_id) = a.sign(TS_BASE, vec![], WinOp::Put { emoji: 7, pos: 60 });
    ops.push(put);
    let (del, del_id) = a.sign(TS_BASE + 1, vec![put_id], WinOp::Del { obj: OpId(put_id) });
    ops.push(del);
    // A long span.
    for i in 0..30u64 {
        let (o, _h) = a.sign(TS_BASE + 10 + i, vec![], WinOp::Add { key: (i % 3) as u16 });
        ops.push(o);
    }
    // Undel observing the early del ⇒ overrides it, resurrecting the object.
    let (undel, _u) = a.sign(TS_BASE + 100, vec![del_id], WinOp::Undel { del: OpId(del_id) });
    ops.push(undel);

    let full = ingest_full(&ops);
    let windowed = ingest_windowed(ops.len() + 5, &ops);
    assert_windowed_equiv(&windowed, &full, "resurrection");
    assert!(windowed.view().objects.contains_key(&OpId(put_id)), "undel resurrects the object");
    println!("PASS targeted: killed object resurrected by a later undel, both in-window; windowed == full");
}

/// register write read by a narrow-horizon laggard — the R′ hazard (§2.5, §8.7): a
/// move CONCURRENT with a lock still applies, while a move observing the lock is
/// suppressed. The window's sub-horizon `locked_as_of` (a `resolve` over an op's
/// causal ancestors) must match the kernel exactly.
#[test]
fn narrow_horizon_lock_gate_r_prime() {
    let mut a = Author::new(1);
    let mut b = Author::new(2);
    let mut ops: Vec<SignedOp> = Vec::new();

    let (put, put_id) = a.sign(TS_BASE, vec![], WinOp::Put { emoji: 3, pos: 60 });
    ops.push(put);
    // Lock observing the put.
    let (lock, lock_id) = a.sign(TS_BASE + 1, vec![put_id], WinOp::SetLock { locked: true });
    ops.push(lock);
    // Move CONCURRENT with the lock (observes only the put) ⇒ still applies.
    let (mov_concurrent, _m1) = b.sign(TS_BASE + 2, vec![put_id], WinOp::Move { obj: OpId(put_id), pos: 64 });
    ops.push(mov_concurrent);
    // Move observing the lock ⇒ suppressed.
    let (mov_locked, _m2) = b.sign(TS_BASE + 3, vec![lock_id], WinOp::Move { obj: OpId(put_id), pos: 70 });
    ops.push(mov_locked);

    let full = ingest_full(&ops);
    let windowed = ingest_windowed(ops.len() + 5, &ops);
    assert_windowed_equiv(&windowed, &full, "r_prime_lock_gate");
    assert!(windowed.view().locked, "the room ends up locked (full-horizon)");
    // The surviving position is the concurrent move (64), never the locked move (70).
    assert_eq!(windowed.view().objects[&OpId(put_id)].1, 64, "concurrent move applied; locked move suppressed");
    println!("PASS targeted: R' narrow-horizon lock gate (concurrent move applies, observed move suppressed); windowed == full");
}

// ===========================================================================
// The §1.3 fence: N > W trips it (a refusal, never a silent wrong answer).
// ===========================================================================

/// N > W truncates the window: it stays bounded at `W`, reports itself INCOMPLETE,
/// yields NO view, and reports `appended_since` past its boundary as `None` — the
/// design's option (a) refusal, not a silent mis-answer (§1.3, §6.2 delta 6).
#[test]
fn fence_n_gt_w_is_incomplete_bounded_and_yields_no_view() {
    let ops = build_history(0x5CA1AB1E, 3, 40);
    let cap = 8;
    let windowed = ingest_windowed(cap, &ops);

    assert!(ops.len() > cap, "the history must exceed the window to trip the fence");
    assert!(!windowed.is_complete(), "window past W must report incomplete");
    assert!(windowed.len() <= cap, "window stays bounded at W (len={}, cap={cap})", windowed.len());
    assert!(windowed.try_view().is_none(), "fence: no view over a truncated window");
    assert!(
        windowed.appended_since(GrowthEpoch::INITIAL).is_none(),
        "appended_since past the window boundary is None (dag.rs:228-235)"
    );
    println!(
        "PASS fence: N={} > W={cap} -> incomplete, bounded (len={}), try_view()==None, appended_since==None",
        ops.len(),
        windowed.len()
    );
}

/// The fence is a HARD refusal: `view()` panics rather than fold a truncated window
/// (a silent wrong answer is the one thing M3.0 must never ship, §1.3).
#[test]
#[should_panic(expected = "windowed view fence")]
fn fence_view_panics_on_truncated_window() {
    let ops = build_history(0x5CA1AB1E, 3, 40);
    let windowed = ingest_windowed(8, &ops);
    // Precondition: actually truncated.
    assert!(!windowed.is_complete());
    let _ = windowed.view(); // MUST panic — never a silent mis-answer.
}

// ===========================================================================
// M3.1 — the compaction gate: N ≫ W, adversarial cuts, view ≡ full ≡ kernel.
// (`windowed-store-design.md` §2.4-2.6, §6.3.)
//
// The M3.1 claim in one suite: a compacting `WindowedStore` (built with
// `with_window`, so `WinLang::retain` discards the monotone-shadowed degree adds /
// removes and superseded registers at every cut) folds **byte-identically** to a
// full `Store` for `N ≫ W` — under shuffled arrival, laggards, equivocation,
// resurrection races, and adversarially-randomized compaction points on two replicas
// with different W. The frozen ancestry summary answers `is_ancestor` across the cut
// exactly as the kernel `ReachIndex` over full history. If compaction were unsound
// (a non-shadowed op discarded, or the summary wrong across the cut), the per-step
// `view() == full.view()` assertion fails — the whole point of the gate.
// ===========================================================================

#[derive(Default)]
struct CompactStats {
    steps: usize,
    compactions: usize,
    discarded: usize,
}

/// The frozen ancestry summary of a compacted store answers `is_ancestor` EXACTLY as
/// the kernel `ReachIndex` over FULL history, for every retained pair (§3, §6.3) —
/// the boundary-oracle cross-check, now across a real cut (residue × window, residue ×
/// residue, window × window all folded into one closure).
fn assert_compacted_reach_equiv(w: &WindowedStore<WinLang>, full: &Store<WinLang>, label: &str) {
    let wreach = w.windowed_reach();
    let kernel = ReachIndex::new(&full.dag().snapshot());
    let retained: Vec<EntryHash> = w.entry_hashes().into_iter().collect();
    for a in &retained {
        for b in &retained {
            assert_eq!(
                Reach::is_ancestor(&wreach, a, b),
                ReachIndex::is_ancestor(&kernel, a, b),
                "{label}: frozen-summary is_ancestor != kernel ReachIndex over full history",
            );
        }
    }
}

/// Ingest `ops` (shuffled by `order_seed`) into a compacting windowed replica (window
/// `W`) and a full store IN THE SAME ORDER, calling `compact()` at seeded-random
/// points (`comp_seed`) on top of the store's own auto-compaction. Assert after EVERY
/// step that the compacted view equals the full view (same lifted set, since the
/// order is shared) and the `state_root` matches; periodically root that in the kernel
/// `ReachIndex` oracle and audit the boundary oracle.
fn run_compacting_replica(
    ops: &[SignedOp],
    window: usize,
    order_seed: u64,
    comp_seed: u64,
    label: &str,
    stats: &mut CompactStats,
) -> (WindowedStore<WinLang>, Store<WinLang>) {
    let arrival = shuffled(ops, order_seed);
    let mut full = Store::new();
    let mut windowed = WindowedStore::with_window(window);
    assert!(windowed.is_compacting(), "with_window must enable compaction");
    let mut comp_rng = Rng::new(comp_seed);

    for (i, signed) in arrival.iter().enumerate() {
        full.ingest_verified(verified(signed));
        windowed.ingest_verified(verified(signed));

        // Adversarial explicit cut at seeded-random points (independent of the store's
        // auto-compaction at the window budget) — this is the "different compaction
        // points" axis (§4.1, §6.3).
        if comp_rng.pct(18) {
            windowed.compact();
        }

        // Same arrival order ⇒ identical lifted/pending set in both stores.
        assert_eq!(
            windowed.pending_len(),
            full.pending_len(),
            "{label} step {i}: pending diverged (lift must be identical)"
        );
        assert!(windowed.is_answerable(), "{label} step {i}: compacted store must be answerable");

        // The core assertion: compaction never changes the view (§2.6).
        let wv = windowed.view();
        let fv = full.view();
        assert_eq!(wv, fv, "{label} step {i}: compacted windowed.view() != full.view() (N>>W)");
        assert_eq!(
            win_state_root(&wv),
            win_state_root(&fv),
            "{label} step {i}: state_root diverged (§4.3 — state_root survives windowing intact)"
        );

        // Periodic root-of-trust: the full view equals the kernel ReachIndex oracle,
        // and the frozen summary matches the kernel across the cut.
        if i % 37 == 0 {
            assert_eq!(fv, full.view_reference(), "{label} step {i}: full.view() != kernel ReachIndex oracle");
            assert_compacted_reach_equiv(&windowed, &full, &format!("{label} step {i}"));
        }
        stats.steps += 1;
    }

    assert_eq!(windowed.pending_len(), 0, "{label}: quiescent (pending == 0)");
    assert_eq!(full.pending_len(), 0, "{label}: full quiescent");
    // Final full audit: view triple-equality + boundary oracle over the retained set.
    assert_eq!(windowed.view(), full.view(), "{label}: final compacted view != full");
    assert_eq!(full.view(), full.view_reference(), "{label}: final full view != kernel oracle");
    assert_compacted_reach_equiv(&windowed, &full, &format!("{label} final"));
    (windowed, full)
}

/// THE M3.1 gate: over several seeded histories with `N ≫ W`, two compacting replicas
/// with **different W** and **different randomized compaction schedules** ingesting
/// **different shuffles** each fold identically to a full store at every step, agree
/// with the kernel oracle, keep `state_root` intact, and converge with each other at
/// quiescence (§4.1). Real compaction happens: the retained fold-input is far smaller
/// than the full history it reproduces.
#[test]
fn windowed_compacts_beyond_window_matches_full() {
    let mut stats = CompactStats::default();
    let mut largest_full = 0usize;
    let mut smallest_final_retained = usize::MAX;

    for seed in 0..5u64 {
        let authors = 3 + (seed as usize % 3);
        let steps = 150 + (seed as usize % 4) * 40; // N ≈ 150-290
        let ops = build_history(seed ^ 0x3151_9A2C, authors, steps);
        let n = ops.len();

        let w_a = 12usize;
        let w_b = 30usize;
        assert!(n > 4 * w_b, "seed {seed}: N={n} must be >> W (w_b={w_b})");

        let (wa, full_a) = run_compacting_replica(
            &ops,
            w_a,
            seed ^ 0xA11CE,
            seed ^ 0xC0FFEE,
            &format!("seed {seed} A W={w_a}"),
            &mut stats,
        );
        let (wb, _full_b) = run_compacting_replica(
            &ops,
            w_b,
            seed ^ 0xB0B0,
            seed ^ 0xF00D,
            &format!("seed {seed} B W={w_b}"),
            &mut stats,
        );

        // §4.1 — different W, different cut schedules, different shuffles, SAME
        // op-set ⇒ equal views. Convergence needs no coordination of cuts.
        assert_eq!(
            wa.view(),
            wb.view(),
            "seed {seed}: different-W compacting replicas diverged (§4.1)"
        );
        // Compaction really shrank the fold input below the full history.
        assert!(
            wa.len() < full_a.len(),
            "seed {seed}: compaction did not shrink the retained set (retained {} vs full {})",
            wa.len(),
            full_a.len()
        );
        largest_full = largest_full.max(full_a.len());
        smallest_final_retained = smallest_final_retained.min(wa.len());
        stats.compactions += wa.compaction_count() + wb.compaction_count();
        stats.discarded += wa.total_discarded() + wb.total_discarded();
    }

    assert!(stats.discarded > 0, "compaction must discard monotone-shadowed ops");
    println!(
        "PASS windowed compaction N>>W: {} per-step (windowed.view()==full.view() + state_root) checks; \
         {} compaction events discarded {} monotone-shadowed ops total (auto + adversarial cuts); \
         largest full history {} ops folded identically from a residue+window as small as {}; frozen \
         summary is_ancestor == kernel ReachIndex over full history on every retained pair; \
         different-W/different-cut replicas converge (§4.1); state_root intact throughout (§4.3)",
        stats.steps, stats.compactions, stats.discarded, largest_full, smallest_final_retained
    );
}

// ===========================================================================
// M3.1 targeted vectors the design names (§6.3 "Targeted vectors"), now with the
// cut actually straddling the vector.
// ===========================================================================

/// **Remove straddling the cut.** An old add is retained across a compaction, killed
/// by a later remove, then both are discarded at the next compaction — the view must
/// stay correct ("key dead where it was the only add; alive via a concurrent
/// survivor"), never "live forever" from a dropped add (§2.3, Lemma A1-A2).
#[test]
fn remove_straddling_the_cut_compacted() {
    let mut a = Author::new(1);
    let mut b = Author::new(2);
    let mut pre: Vec<SignedOp> = Vec::new();

    let (add, add_id) = a.sign(TS_BASE, vec![], WinOp::Add { key: 9 });
    pre.push(add);
    // B's concurrent add of key 9 (the remove never observes it) — the add-wins
    // survivor that must keep key 9 live after A's add is killed and discarded.
    let (badd, _bid) = b.sign(TS_BASE + 1, vec![], WinOp::Add { key: 9 });
    pre.push(badd);
    // A long span forces auto-compaction with a small window, so A's add is retained
    // ACROSS a cut before the remove arrives.
    for i in 0..30u64 {
        pre.push(a.sign(TS_BASE + 10 + i, vec![], WinOp::SetReg { slot: (i % 3) as u8, val: i as u32 }).0);
    }
    let (rem, _r) = a.sign(TS_BASE + 100, vec![add_id], WinOp::Rem { key: 9 });

    let mut full = Store::new();
    let mut windowed = WindowedStore::with_window(6);
    for signed in &pre {
        full.ingest_verified(verified(signed));
        windowed.ingest_verified(verified(signed));
    }
    windowed.compact();
    assert_eq!(windowed.view(), full.view(), "pre-remove: compacted view != full");
    assert!(windowed.view().live_keys.contains(&9), "key 9 live before the remove");
    // A's add is still retained here (a surviving per-author maximum), so the remove
    // that arrives next genuinely straddles the cut.
    let add_entry = windowed.lifted_entry(OpId(add_id)).expect("add bound");
    assert!(windowed.entry_hashes().contains(&add_entry), "A's add retained across the first cut");

    full.ingest_verified(verified(&rem));
    windowed.ingest_verified(verified(&rem));
    let report = windowed.compact();
    assert!(report.discarded >= 1, "the killed add + remove are discarded at the straddling cut");
    assert!(!windowed.entry_hashes().contains(&add_entry), "the killed add is now compacted away");

    assert_eq!(windowed.view(), full.view(), "post-remove: view != full (remove straddling the cut)");
    assert_eq!(full.view(), full.view_reference(), "kernel oracle");
    assert!(windowed.view().live_keys.contains(&9), "add-wins survivor keeps key 9 live");
    assert_eq!(
        windowed.view().key_authors[&9],
        BTreeSet::from([b.author_id()]),
        "only B survives; A's add was killed by the straddling remove"
    );
    println!(
        "PASS targeted: remove straddling the cut — A's add retained across a cut then killed by a \
         later remove (both compacted away), B's concurrent survivor keeps key 9 live; windowed == \
         full == kernel"
    );
}

/// **Resurrection across the cut.** Pieces are retained wholesale (§2.5-P): a put +
/// del compacted across a wide cut still resurrect when a later undel observes the
/// (pre-cut) del. The put/del are NEVER discarded — the "do not compact the
/// non-monotone subgraph" scope, verified under `N ≫ W`.
#[test]
fn resurrection_across_the_cut_compacted() {
    let mut a = Author::new(1);
    let mut pre: Vec<SignedOp> = Vec::new();

    let (put, put_id) = a.sign(TS_BASE, vec![], WinOp::Put { emoji: 7, pos: 60 });
    pre.push(put);
    let (del, del_id) = a.sign(TS_BASE + 1, vec![put_id], WinOp::Del { obj: OpId(put_id) });
    pre.push(del);
    for i in 0..30u64 {
        pre.push(a.sign(TS_BASE + 10 + i, vec![], WinOp::Add { key: (i % 4) as u16 }).0);
    }
    let (undel, _u) = a.sign(TS_BASE + 100, vec![del_id], WinOp::Undel { del: OpId(del_id) });

    let mut full = Store::new();
    let mut windowed = WindowedStore::with_window(6);
    for signed in &pre {
        full.ingest_verified(verified(signed));
        windowed.ingest_verified(verified(signed));
    }
    windowed.compact();
    assert_eq!(windowed.view(), full.view(), "pre-undel: view != full");
    assert!(!windowed.view().objects.contains_key(&OpId(put_id)), "object deleted pre-undel");
    // The put and del are retained wholesale (pieces are never compacted).
    let put_entry = windowed.lifted_entry(OpId(put_id)).expect("put bound");
    let del_entry = windowed.lifted_entry(OpId(del_id)).expect("del bound");
    assert!(windowed.entry_hashes().contains(&put_entry), "put RETAINED across the cut");
    assert!(windowed.entry_hashes().contains(&del_entry), "del RETAINED across the cut");

    full.ingest_verified(verified(&undel));
    windowed.ingest_verified(verified(&undel));
    windowed.compact();
    assert_eq!(windowed.view(), full.view(), "resurrection across the cut: windowed != full");
    assert_eq!(full.view(), full.view_reference(), "kernel oracle");
    assert!(
        windowed.view().objects.contains_key(&OpId(put_id)),
        "undel resurrects the compacted-across object"
    );
    println!(
        "PASS targeted: resurrection across the cut — put/del retained wholesale (never compacted), \
         later undel resurrects; windowed == full == kernel"
    );
}

/// **R′ narrow-horizon lock straddling the cut.** The sub-horizon lock register is
/// retained wholesale (§2.5-R′): a move concurrent with a lock still applies, a move
/// observing the lock is suppressed — even when the lock write straddles a
/// compaction. The fold must not read a cut-collapsed maximum of the lock register.
#[test]
fn r_prime_lock_gate_across_the_cut_compacted() {
    let mut a = Author::new(1);
    let mut b = Author::new(2);
    let mut pre: Vec<SignedOp> = Vec::new();

    let (put, put_id) = a.sign(TS_BASE, vec![], WinOp::Put { emoji: 3, pos: 60 });
    pre.push(put);
    let (lock, lock_id) = a.sign(TS_BASE + 1, vec![put_id], WinOp::SetLock { locked: true });
    pre.push(lock);
    // Concurrent-with-lock (observes only the put) ⇒ applies.
    let (mov_concurrent, _m1) = b.sign(TS_BASE + 2, vec![put_id], WinOp::Move { obj: OpId(put_id), pos: 64 });
    pre.push(mov_concurrent);
    // Observes the lock ⇒ suppressed.
    let (mov_locked, _m2) = b.sign(TS_BASE + 3, vec![lock_id], WinOp::Move { obj: OpId(put_id), pos: 70 });
    pre.push(mov_locked);
    for i in 0..30u64 {
        pre.push(a.sign(TS_BASE + 10 + i, vec![], WinOp::SetReg { slot: 0, val: i as u32 }).0);
    }

    let mut full = Store::new();
    let mut windowed = WindowedStore::with_window(6);
    for signed in &pre {
        full.ingest_verified(verified(signed));
        windowed.ingest_verified(verified(signed));
    }
    windowed.compact();

    assert_eq!(windowed.view(), full.view(), "R′ across the cut: windowed != full");
    assert_eq!(full.view(), full.view_reference(), "kernel oracle");
    assert!(windowed.view().locked, "room ends up locked (full-horizon read)");
    assert_eq!(
        windowed.view().objects[&OpId(put_id)].1,
        64,
        "concurrent move applied (64); observed move suppressed (never 70) across the cut"
    );
    println!(
        "PASS targeted: R′ narrow-horizon lock gate across the cut — concurrent move applies, \
         observed move suppressed; the sub-horizon lock register is retained wholesale (never \
         collapsed to a maximum); windowed == full == kernel"
    );
}

/// **Conservative retention + idempotence.** Compacting never changes the view, and
/// re-compacting a compacted store discards nothing more (§2.6 corollary i). The
/// no-discarded-op-changes-the-fold property, made concrete.
#[test]
fn compact_twice_is_idempotent_and_conservative() {
    let ops = build_history(0x1DE0_1234, 4, 130);
    // Window > N so nothing auto-compacts: the first explicit compact does the whole
    // job, and we can watch it discard, then watch the second do nothing.
    let mut windowed = WindowedStore::with_window(ops.len() + 8);
    for signed in shuffled(&ops, 0x11).iter() {
        windowed.ingest_verified(verified(signed));
    }
    let full = ingest_full(&ops);

    let v0 = windowed.view();
    assert_eq!(v0, full.view(), "pre-explicit-compact view != full");
    let first = windowed.compact();
    let v1 = windowed.view();
    let second = windowed.compact(); // no new ops
    let v2 = windowed.view();

    assert!(first.discarded > 0, "the first compaction must discard the monotone-shadowed ops");
    assert_eq!(v0, v1, "compaction changed the view (conservative-retention violated)");
    assert_eq!(v1, v2, "second compaction changed the view");
    assert_eq!(
        second.discarded, 0,
        "re-compacting a compacted store with no new ops discards nothing (idempotent, §2.6 cor. i)"
    );
    assert_eq!(v2, full.view(), "compacted view != full view");
    assert_eq!(full.view(), full.view_reference(), "kernel oracle");
    println!(
        "PASS targeted: compact-twice idempotence + conservative retention — view stable across \
         compactions (first discarded {}, second discarded {}); view == full == kernel",
        first.discarded, second.discarded
    );
}

// ===========================================================================
// M3.2 — the memory-bound gate: the packed ancestry summary is O(W+|R|²), NOT O(N)/O(N²).
// (`windowed-store-design.md` §3.2 cut masks + §3.3 in-window bitset + §3.4 residue reach
// matrix.)
//
// M3.1 answered `is_ancestor` across the cut from an EXACT-but-UNBOUNDED summary: a full
// strict-ancestor SET per lifted op — Θ(N²), the very ReachIndex cost windowing exists to
// avoid. M3.2 replaces it with the packed bitset closure over the retained set alone. This
// test proves the reduction is real: at a FIXED window with BOUNDED residue, the packed
// summary's size does NOT grow with N, while the M3.1 exact-`anc` baseline it replaces
// grows quadratically. Without this assertion there is no M3.2 deliverable.
// ===========================================================================

/// A **bounded-residue** history: only add-wins (A) and full-horizon registers (R) over a
/// SMALL key/slot space, multi-author, with laggard horizons — and deliberately NO
/// pieces/locks (which are retained wholesale, §2.5-P/R′, and would let the residue grow
/// with N, §8.2). So the residue `R` (per-key-per-author surviving-add maxima + per-slot
/// register maxima) is bounded by ≈ keys×authors + slots×authors, INDEPENDENT of N — the
/// precondition for the packed summary to be flat in N (the M3.2 memory-bound claim). Each
/// author's ops still chain by backlink, so laggards' stale `observed` reference early ops
/// that get discarded, exercising the courier-deferred discarded-reach path.
fn build_bounded_history(seed: u64, authors: usize, steps: usize) -> Vec<SignedOp> {
    const KEYS: usize = 4;
    const SLOTS: usize = 3;
    let mut rng = Rng::new(seed ^ 0xB0DE_5EED);
    let mut peers: Vec<Author> = (0..authors).map(|i| Author::new((i + 1) as u8)).collect();
    let mut out: Vec<SignedOp> = Vec::new();
    let mut op_hashes: Vec<[u8; 32]> = Vec::new();

    for step in 0..steps {
        let author = rng.upto(authors);
        let ts = TS_BASE + step as u64;

        let laggard = rng.pct(25);
        let mut observed: Vec<[u8; 32]> = Vec::new();
        if !op_hashes.is_empty() {
            let (lo, hi) = if laggard {
                (0, (op_hashes.len() / 3).max(1))
            } else {
                (op_hashes.len().saturating_sub(6), op_hashes.len())
            };
            for h in &op_hashes[lo..hi] {
                if observed.len() >= 4 {
                    break;
                }
                if rng.pct(45) {
                    observed.push(*h);
                }
            }
        }

        let op = match rng.upto(6) {
            0..=2 => WinOp::Add { key: rng.upto(KEYS) as u16 },
            3 => WinOp::Rem { key: rng.upto(KEYS) as u16 },
            _ => WinOp::SetReg { slot: rng.upto(SLOTS) as u8, val: rng.upto(1000) as u32 },
        };
        let (signed, id) = peers[author].sign(ts, observed, op);
        op_hashes.push(id);
        out.push(signed);
    }
    out
}

/// **THE M3.2 gate.** At a FIXED window with bounded residue, grow N 8× and assert the
/// packed ancestry summary's size does NOT grow — O(W+|R|²), not O(N)/O(N²). Cross-check
/// that the bounded packing is still EXACT (folds identically to the full store, and its
/// `is_ancestor` matches the kernel `ReachIndex` over full history on every retained pair),
/// then compare its byte size against M3.1's exact-`anc` baseline (Σ|strict ancestors| over
/// all N ops — what the replaced `BTreeMap<EntryHash, BTreeSet<EntryHash>>` stored: Θ(N²)).
#[test]
fn packed_summary_is_bounded_independent_of_n() {
    let window = 24usize;
    // columns per N: (N, summary_entries, summary_bytes, courier_gap, m31_anc_pairs)
    let mut table: Vec<(usize, usize, usize, usize, usize)> = Vec::new();

    for &steps in &[80usize, 160, 320, 640] {
        let ops = build_bounded_history(0x5233_A2C0, 3, steps);
        let n = ops.len();

        // The compacting windowed leaf at a FIXED small window.
        let mut w = WindowedStore::with_window(window);
        for s in &ops {
            w.ingest_verified(verified(s));
        }
        // Final explicit cut so the measurement is the stable §3.4 residue reach matrix
        // (window empty): the cleanest bounded-summary snapshot.
        w.compact();

        // The full store — correctness oracle + the M3.1 Θ(N²) baseline.
        let full = ingest_full(&ops);

        // The bounded packing must still be EXACT, not merely small.
        assert_eq!(
            w.view(),
            full.view(),
            "N={n}: bounded packed summary must fold identically to the full store"
        );
        assert_eq!(full.view(), full.view_reference(), "N={n}: kernel oracle");
        assert_compacted_reach_equiv(&w, &full, &format!("N={n} bounded packing"));
        assert!(
            w.total_discarded() > 0,
            "N={n}: compaction must actually discard (else nothing is bounded)"
        );

        // M3.1 baseline: what the replaced exact `anc` stored = Σ over all N ops of
        // |strict ancestors| (a full EntryHash SET per lifted op) — Θ(N²).
        let kernel = ReachIndex::new(&full.dag().snapshot());
        let hashes: Vec<EntryHash> = full.entry_hashes().into_iter().collect();
        let mut m31_pairs = 0usize;
        for b in &hashes {
            for a in &hashes {
                if a != b && ReachIndex::is_ancestor(&kernel, a, b) {
                    m31_pairs += 1;
                }
            }
        }

        table.push((
            n,
            w.packed_summary_entries(),
            w.packed_summary_bytes(),
            w.courier_gap_entries(),
            m31_pairs,
        ));
    }

    let first = *table.first().unwrap();
    let last = *table.last().unwrap();

    // THE M3.2 assertion: the packed summary proper is ~FLAT in N. N grew 8× (80 → 640);
    // at a fixed window + bounded residue the retained matrix is O((W+|R|)²), so its size
    // must NOT track N.
    assert!(
        last.2 <= first.2 * 2,
        "packed summary bytes must be ~flat in N (O(W+|R|²), NOT O(N)): {table:?}"
    );
    assert!(
        last.1 <= first.1 * 2,
        "packed summary entry-count must be ~flat in N: {table:?}"
    );

    // The M3.1 baseline it replaces DID grow super-linearly with N.
    assert!(
        last.4 >= first.4 * 4,
        "the M3.1 exact-`anc` baseline (Θ(N²)) must grow with N: {table:?}"
    );

    // Concretely, at the largest N the replaced M3.1 summary dwarfs M3.2's packed one.
    let m31_bytes_last = last.4 * std::mem::size_of::<EntryHash>();
    assert!(
        m31_bytes_last > last.2 * 8,
        "M3.2 packed summary must be far smaller than M3.1's exact anc at large N: \
         M3.1 ≈ {m31_bytes_last} B vs M3.2 {} B",
        last.2
    );

    println!("PASS packed_summary_is_bounded — M3.2 memory bound (§3.2 cut-contact / §3.3 in-window / §3.4 residue matrix):");
    println!(
        "   N   | M3.2 summary rows | M3.2 summary bytes | courier gap (discarded rows, O(N)) | M3.1 anc pairs Θ(N²) | M3.1 anc bytes"
    );
    for (n, ent, bytes, gap, pairs) in &table {
        println!(
            "  {n:<5}| {ent:<17} | {bytes:<18} | {gap:<34} | {pairs:<20} | {}",
            pairs * std::mem::size_of::<EntryHash>()
        );
    }
    println!(
        "  => M3.2 packed summary FLAT in N ({}B @ N={} -> {}B @ N={}, {} rows -> {} rows) while N grew {}x; \
         M3.1 exact `anc` grew {}x ({} -> {} ancestor-pairs). Headline: Θ(N²) -> O(W+|R|²).",
        first.2, first.0, last.2, last.0, first.1, last.1,
        last.0 / first.0.max(1),
        last.4 / first.4.max(1), first.4, last.4
    );
}
