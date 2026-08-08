//! [`WindowedStore<L>`] — the leaf-profile domain sibling of [`Store<L>`](crate::Store),
//! plus its **M3.1 monotone-shadowing compaction** bookkeeping
//! (`docs/vision/windowed-store-design.md` §7 "M3.0"/"M3.1", §6.1, §3, §2.4-2.6).
//!
//! The L-free machinery this store drives — the bounded-window
//! [`WindowedDag`](hhhs_dag::WindowedDag), its [`WindowedReach`](hhhs_dag::WindowedReach)
//! backend, and the bounded [`PackedSummary`](hhhs_dag::PackedSummary) ancestry summary
//! — lives in the floor (`hhhs_dag::windowed`). What stays here is the `L`-threaded
//! half: lift / strict-deferral / drain over signed ops, the cut-scoped sync surface,
//! the fenced [`WindowedStore::view`], and compaction driven by [`OpLanguage::retain`].
//!
//! **M3.0 — the bounded window** ([`WindowedStore::with_cap`]). With `retain` left at
//! its retain-everything default, the window holds every op it lifts; while `N ≤ W`
//! the windowed fold is byte-identical to the full-history fold (§2.6) and bounded to
//! `≤ W` ops. The instant `N > W` the window would truncate — and because a plain
//! reach over a truncated DAG silently computes `is_ancestor = false` across the cut
//! (a **wrong view, not an error**, §1.3), M3.0's [`WindowedStore::view`]
//! **hard-refuses** rather than fold it. Exact only for `N ≤ W`.
//!
//! **M3.1 — monotone-shadowing compaction** ([`WindowedStore::with_window`],
//! [`WindowedStore::compact`]). At a causally-closed cut the domain's
//! [`OpLanguage::retain`] names the residue — the ops whose contribution to a *future*
//! fold is not yet **monotone-shadowed** (§2.4): killed by an unconditional remove, or
//! superseded by a retained later write; never dependent on the continued *absence* of
//! a future op. Everything else is discarded from the fold's decoded map (the
//! [`Checkpoint`]-tracked ancestry summary answers `is_ancestor` across the cut
//! exactly, §3.2/§3.4), so `L::fold` over `checkpoint ⊕ window` equals the full-history
//! fold for `N > W` (§2.6) — *iff* the domain's retention is sound, which the
//! `windowed_equiv` gate falsifies adversarially. The [`WindowedStore::view`] fence
//! relaxes from "complete" to [`WindowedStore::is_answerable`]: a compacted store is
//! not complete but *is* answerable; only an M3.0 window that hard-truncated still
//! refuses.
//!
//! **Scope (§2.5, honestly).** Compaction handles the **monotone** domains — add-wins
//! sets (survivor per-author maxima) and full-horizon causal-maxima registers (R). It
//! does **not** compact the non-monotone piece/resurrection subgraph (`Undel` makes
//! kills flip; §2.5-P) or a sub-horizon-read register (the R′ hazard, §2.5-R′); those
//! are **retained wholesale** — conservative retention is always sound ("when in doubt,
//! retain").
//!
//! **M3.2 — bounded ancestry packing.** The frozen ancestry summary the checkpoint
//! carries across the cut is the floor's [`PackedSummary`](hhhs_dag::PackedSummary):
//! one dense retained-ancestor bitset closure, `O((|R|+|window|)²)` bits — **independent
//! of total history N**, so the store's *memory* is bounded to the leaf budget (§5),
//! not just its fold input.

use std::collections::{BTreeMap, BTreeSet};

use hhhs_dag::windowed::{PackedSummary, WindowedDag, WindowedReach};
use hhhs_dag::{DagRead, Entry, EntryHash, GrowthEpoch, Position};

#[cfg(any(test, feature = "test-support"))]
use hhhs::cover::ReachIndex;

use crate::ops::{AuthorId, LogHead, OpId, OpLanguage, SignedOp, SigningKey, VerifiedOpG};
use crate::store::{DecodedOp, FoldCtx, frame_signed, sync_root_of, unframe_signed};

// ===========================================================================
// §2.2 — the checkpoint: compacted state + packed ancestry summary.
// ===========================================================================

/// The **checkpoint** a compacted [`WindowedStore`] carries across the cut
/// (`docs/vision/windowed-store-design.md` §2.2). Present iff the store was built for
/// compaction ([`WindowedStore::with_window`]).
///
/// The checkpoint's job is to let the *unchanged* `L::fold` run over a **shrunken
/// decoded map** (residue ∪ window — the monotone-shadowed ops discarded, §2.5) while
/// still answering `is_ancestor`/`resolve` exactly as full history would (§3), in
/// **bounded** memory (the M3.2 [`PackedSummary`]). It is **not** a folded `L::View`
/// snapshot: the fold is an arbitrary pure function, not a monoid, so the residue-of-
/// ops model keeps the fold code identical and puts all the intelligence into *what to
/// retain* — where the soundness argument lives (§2.2).
struct Checkpoint {
    /// **The packed ancestry summary** (§3.2/§3.3/§3.4) — the M3.2 bounded replacement
    /// for M3.1's Θ(N²) `anc`. See [`PackedSummary`].
    summary: PackedSummary,
    /// §4.3 **pinned cut `ops_root`**: the Merkle commitment over full history at the
    /// first compaction (computed while the leaf still held everything). The
    /// verifiability anchor a self-compacted leaf checks discarded-op proofs against
    /// (Mode A). `None` under `--no-default-features` (no `merkle`) or before the
    /// first compaction.
    #[cfg(feature = "merkle")]
    pinned_cut_ops_root: Option<[u8; 32]>,
    /// Total ops discarded across every compaction (diagnostics / [`Compaction`]).
    total_discarded: usize,
    /// Number of compaction events (diagnostics).
    compactions: usize,
}

impl Checkpoint {
    fn new() -> Self {
        Self {
            summary: PackedSummary::default(),
            #[cfg(feature = "merkle")]
            pinned_cut_ops_root: None,
            total_discarded: 0,
            compactions: 0,
        }
    }
}

/// The outcome of one [`WindowedStore::compact`] call (§2.5): how many monotone-
/// shadowed ops were discarded and how many are retained (residue ∪ window) after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compaction {
    /// Ops discarded by this compaction (monotone-shadowed, §2.4).
    pub discarded: usize,
    /// Ops the fold still iterates afterward (residue ∪ window).
    pub retained: usize,
}

// ===========================================================================
// §6.1 — `WindowedStore<L>`: the leaf-profile domain sibling of `Store<L>`.
// ===========================================================================

/// The leaf-profile sibling of [`Store<L>`](crate::Store): the same lift / strict-
/// deferral / drain machinery over a bounded [`WindowedDag`], a fenced
/// [`WindowedStore::view`], and a cut-scoped sync surface (§1.2, §4.2).
///
/// It is **byte-compatible by construction** with [`Store<L>`](crate::Store): it lifts
/// through the identical [`frame_signed`] framing, so the same op yields the same
/// [`EntryHash`] on a windowed leaf and a full peer — the precondition for
/// convergence (§4.1). While `N ≤ W` its retained set equals a full store's, so
/// `entry_hashes`, `sync_root`, `ops_root` and, above all, `view()` all match a
/// [`Store<L>`](crate::Store) fed the same ops (§2.6, the §6.3 gate).
///
/// **Two profiles, one type:**
///
/// - [`with_cap`](WindowedStore::with_cap) — the **M3.0 bounded window**: no
///   compaction, hard-evict past `W`, `view()` *refuses* once truncated (§1.3). Exact
///   only for `N ≤ W`. Every existing M3.0 test is this profile, unchanged.
/// - [`with_window`](WindowedStore::with_window) — the **M3.1 compacting leaf**:
///   [`compact`](WindowedStore::compact) discards the monotone-shadowed ops at a
///   causally-closed cut (§2.4-2.5) and folds `checkpoint ⊕ window` correctly for
///   `N > W`. The residue (whatever the domain's [`OpLanguage::retain`] keeps) plus
///   the window is what the fold iterates; ancestry crosses the cut via the frozen
///   summary (§3).
pub struct WindowedStore<L: OpLanguage> {
    /// The bounded-window causal DAG. Identity ([`EntryHash`]) is fixed here.
    dag: WindowedDag,
    /// op id → entry that lifts it. Kept for **every** lifted op (retained *and*
    /// discarded) so a later op referencing a discarded prev still resolves it to the
    /// same [`EntryHash`] a full peer computes — the precondition for the lifted
    /// entry hash (and thus convergence, §4.1) to match. Bounding this to a
    /// retained-only table + courier resolution of deep-laggard bindings is M3.2
    /// (§4.5).
    source_to_entry: BTreeMap<OpId, EntryHash>,
    /// retained entry → op id (inverse). Retained-only: it backs `op_id` in the fold
    /// and the cut-scoped identity set (`entry_hashes`/`sync_root`/`ops_root`, §4.2).
    entry_to_source: BTreeMap<EntryHash, OpId>,
    /// retained entry → decoded op — the map the fold iterates (§2.2). **This is the
    /// compacted set**: monotone-shadowed ops are dropped from it at compaction, so a
    /// discarded op never reaches the fold.
    decoded: BTreeMap<EntryHash, DecodedOp<L>>,
    /// Per-author log head, so the local author can chain new commits. (The own-author
    /// head is checkpoint state that must survive compaction, §1.2.)
    heads: BTreeMap<AuthorId, LogHead>,
    /// Ops whose causal past is not all lifted yet — parked (strict deferral), drained
    /// after every successful lift.
    pending: Vec<VerifiedOpG<L>>,
    /// M3.1: `Some` iff this store compacts (built via [`WindowedStore::with_window`]).
    /// Holds the frozen ancestry summary + pinned roots. `None` is the M3.0
    /// no-compaction profile (bounded window, hard fence).
    checkpoint: Option<Checkpoint>,
    /// M3.1: the window budget `W` that triggers auto-compaction (compaction profile
    /// only) — the store compacts when `decoded` grows past it, so steady-state memory
    /// stays `≈ residue + W`. Explicit [`compact`](WindowedStore::compact) is layered
    /// on top for adversarial cut schedules.
    window_cap: usize,
}

impl<L: OpLanguage> WindowedStore<L> {
    /// A **M3.0 bounded window** with cap `W` (`cap ≥ 1`): no compaction, hard fence
    /// past `W`. Exactly the pre-compaction store.
    pub fn with_cap(cap: usize) -> Self {
        Self {
            dag: WindowedDag::with_cap(cap),
            source_to_entry: BTreeMap::new(),
            entry_to_source: BTreeMap::new(),
            decoded: BTreeMap::new(),
            heads: BTreeMap::new(),
            pending: Vec::new(),
            checkpoint: None,
            window_cap: cap,
        }
    }

    /// A **M3.1 compacting leaf** with window budget `W` (`W ≥ 1`): auto-compacts when
    /// the retained set grows past `W`, and [`compact`](WindowedStore::compact) can be
    /// called at any causally-closed point for an adversarial cut schedule. Total
    /// retained is `residue + window`, not capped at `W` — the residue is whatever the
    /// domain's [`OpLanguage::retain`] keeps (§2.5). Folds correctly for `N > W`.
    pub fn with_window(window_cap: usize) -> Self {
        assert!(window_cap >= 1, "windowed store window budget must be >= 1");
        Self {
            // The DAG never hard-evicts in this profile (the store bounds memory via
            // `compact`); a large cap keeps the M3.0 `append_capped` path unused while
            // never allocating a `W`-wide `BitRow`.
            dag: WindowedDag::with_cap(usize::MAX),
            source_to_entry: BTreeMap::new(),
            entry_to_source: BTreeMap::new(),
            decoded: BTreeMap::new(),
            heads: BTreeMap::new(),
            pending: Vec::new(),
            checkpoint: Some(Checkpoint::new()),
            window_cap,
        }
    }

    /// Whether this store compacts (M3.1 profile, [`WindowedStore::with_window`]).
    pub fn is_compacting(&self) -> bool {
        self.checkpoint.is_some()
    }

    /// The window cap `W`.
    pub fn cap(&self) -> usize {
        self.window_cap
    }

    /// Whether the store still holds its **entire** lifted causal history in `decoded`
    /// — i.e. nothing has been dropped, by hard eviction (M3.0) *or* compaction
    /// (M3.1). `true` for a fresh store and while `N ≤ W` with no compaction. Distinct
    /// from [`WindowedStore::is_answerable`], which is the fence: a compacted store is
    /// *not* complete but *is* answerable.
    pub fn is_complete(&self) -> bool {
        match &self.checkpoint {
            Some(cp) => cp.total_discarded == 0,
            None => self.dag.is_complete(),
        }
    }

    /// Whether [`WindowedStore::view`] can produce a **correct** fold — the relaxed
    /// M3.1 fence (§6.2 delta 6). `true` when either the window is complete (M3.0,
    /// `N ≤ W`) *or* every drop went through sound compaction (M3.1): a compacted
    /// store answers `checkpoint ⊕ window` correctly for `N > W`. `false` only for a
    /// genuinely-unanswerable state — an M3.0 window that hard-truncated past `W`
    /// (the one thing that must still refuse, never silently mis-answer).
    pub fn is_answerable(&self) -> bool {
        match &self.checkpoint {
            // M3.1: only sound (retention-checked) discards ever happen, and the
            // frozen summary answers ancestry exactly across the cut.
            Some(_) => true,
            // M3.0: exact iff the window never truncated.
            None => self.dag.is_complete(),
        }
    }

    /// Number of retained (materialized) ops the fold iterates (residue ∪ window).
    pub fn len(&self) -> usize {
        self.decoded.len()
    }

    pub fn is_empty(&self) -> bool {
        self.decoded.is_empty()
    }

    /// The retained entry-hash identity set (cut-scoped, §4.2). While `N ≤ W` this
    /// equals a full [`Store<L>`](crate::Store)'s set for the same ops.
    pub fn entry_hashes(&self) -> BTreeSet<EntryHash> {
        self.entry_to_source.keys().copied().collect()
    }

    /// Ops parked awaiting their causal past (strict deferral). Zero after quiescence
    /// is the liveness invariant.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Whether an op is already lifted (retained) or parked.
    pub fn knows_op(&self, id: OpId) -> bool {
        self.source_to_entry.contains_key(&id) || self.pending.iter().any(|p| p.id() == id)
    }

    /// The retained entry lifting op `id`, if materialized (and not since evicted).
    pub fn lifted_entry(&self, id: OpId) -> Option<EntryHash> {
        self.source_to_entry.get(&id).copied()
    }

    /// The cut-scoped convergence digest over the retained entry-hash set (§4.2).
    ///
    /// Uses the identical [`sync_root_of`] definition a full peer uses, so for a
    /// session anchored at the window's boundary both sides digest the same set. While
    /// `N ≤ W` the retained set is the whole set, so this equals a full store's
    /// `sync_root` outright.
    pub fn sync_root(&self) -> [u8; 32] {
        sync_root_of(self.entry_to_source.keys())
    }

    /// The verbatim signed bytes of every retained op, keyed by lifting entry hash —
    /// the cut-scoped RBSR `Fetch` surface (§1.2). Recovered losslessly from the DAG
    /// payloads, byte-identical to what the author signed.
    pub fn signed_ops(&self) -> BTreeMap<EntryHash, SignedOp> {
        self.dag
            .entries_topo()
            .into_iter()
            .map(|entry| (entry.hash(), unframe_signed::<L>(&entry.payload)))
            .collect()
    }

    /// Signed bytes plus causal-entry predecessors for ONE retained entry (§1.2).
    pub fn repair_record(&self, hash: &EntryHash) -> Option<(SignedOp, Vec<EntryHash>)> {
        let entry = self.dag.entry(hash)?;
        Some((
            unframe_signed::<L>(&entry.payload),
            entry.header.prevs.0.iter().copied().collect(),
        ))
    }

    /// The op ids of the retained frontier — the causal horizon a new local op stamps
    /// into its `observed`. Narrow by construction (§1.2), deterministic (ascending
    /// entry-hash order).
    pub fn observed_frontier(&self) -> Vec<[u8; 32]> {
        self.dag
            .frontier()
            .0
            .iter()
            .filter_map(|entry| self.entry_to_source.get(entry).map(|id| id.0))
            .collect()
    }

    /// Lift a verified op into the window. Deduplicates, advances the author's head,
    /// parks on incomplete causal past (strict deferral), and drains the pending set
    /// after every successful lift. Identical control flow to
    /// [`Store::ingest_verified`](crate::Store::ingest_verified); the only difference
    /// is the bounded backing DAG.
    ///
    /// Returns the entries this call newly lifted. An empty return means the op parked
    /// (or is a duplicate). A parked op is not in [`WindowedStore::entry_hashes`].
    pub fn ingest_verified(&mut self, op: VerifiedOpG<L>) -> Vec<EntryHash> {
        let id = op.id();
        if self.source_to_entry.contains_key(&id) {
            return Vec::new();
        }
        if self.pending.iter().any(|p| p.id() == id) {
            return Vec::new();
        }
        self.advance_head(&op);
        self.pending.push(op);
        let lifted = self.drain_pending();
        // M3.1: keep steady-state memory ≈ residue + W by compacting once the retained
        // set outgrows the window budget. Explicit `compact()` (adversarial cuts) is
        // layered on top; both call the same sound retention path.
        if self.checkpoint.is_some() && self.decoded.len() > self.window_cap {
            self.compact();
        }
        lifted
    }

    /// Advance (never regress) the author's tracked head to the greatest seq seen.
    fn advance_head(&mut self, op: &VerifiedOpG<L>) {
        let advanced = op.advanced_head();
        let slot = self.heads.entry(op.author()).or_insert_with(LogHead::genesis);
        if advanced.next_seq > slot.next_seq {
            *slot = advanced;
        }
    }

    /// Resolve an op's `prevs` = `{ lift(backlink) } ∪ { lift(o) : o in observed }`
    /// against the *retained* window. `None` (defer) if any referenced op is not
    /// retained — including a deep-laggard reference below the window boundary, which
    /// parks (defer-never-reject). While `N ≤ W` no reference is ever below the
    /// boundary.
    fn resolve_prevs(&self, op: &VerifiedOpG<L>) -> Option<BTreeSet<EntryHash>> {
        let mut prevs = BTreeSet::new();
        if let Some(backlink) = op.backlink() {
            prevs.insert(*self.source_to_entry.get(&OpId(backlink))?);
        }
        for observed in op.observed() {
            prevs.insert(*self.source_to_entry.get(&OpId(*observed))?);
        }
        Some(prevs)
    }

    /// Try to lift one op. Returns its entry hash iff appended; `None` (no mutation) if
    /// its causal past is incomplete.
    ///
    /// **M3.0** (no compaction): `append_capped` with hard eviction past `W`; evicted
    /// entries are pruned from every map in lockstep with the [`WindowedDag`].
    ///
    /// **M3.2** (compaction): a non-evicting insert, and the **packed ancestry summary**
    /// is extended for this op via [`PackedSummary::lift`] — one bounded strict-
    /// retained-ancestor [`BitRow`], `reach(entry) = ⋃_{p ∈ prevs}({index(p)} ∪
    /// reach(p))` (§3.2/§3.3). Because the store lifts an op only once every prev is
    /// present (strict deferral) and every prev's row is already built, the new row is
    /// exact (§3.2 boundary lemma; the standard memoized-topo closure, in bits).
    /// Eviction is deferred to [`WindowedStore::compact`].
    fn try_lift(&mut self, op: &VerifiedOpG<L>) -> Option<EntryHash> {
        let prevs = self.resolve_prevs(op)?;
        let entry = Entry::new(frame_signed::<L>(&op.signed()), Position(prevs.clone()));
        let entry_hash = entry.hash();
        let id = op.id();

        if let Some(cp) = self.checkpoint.as_mut() {
            // M3.2 compaction profile: non-evicting insert + packed-summary extension.
            self.dag.insert(&entry);
            cp.summary.lift(entry_hash, &prevs);
            self.source_to_entry.insert(id, entry_hash);
            self.entry_to_source.insert(entry_hash, id);
            self.decoded.insert(
                entry_hash,
                DecodedOp::new(op.author(), op.payload().clone(), op.timestamp_ms(), op.seq_num()),
            );
            return Some(entry_hash);
        }

        // M3.0 profile: unchanged bounded-window hard eviction.
        let evicted = self.dag.append_capped(&entry);
        self.source_to_entry.insert(id, entry_hash);
        self.entry_to_source.insert(entry_hash, id);
        self.decoded.insert(
            entry_hash,
            DecodedOp::new(op.author(), op.payload().clone(), op.timestamp_ms(), op.seq_num()),
        );
        for gone in evicted {
            if let Some(gone_id) = self.entry_to_source.remove(&gone) {
                self.source_to_entry.remove(&gone_id);
            }
            self.decoded.remove(&gone);
        }
        Some(entry_hash)
    }

    /// Repeatedly attempt to lift parked ops until a full pass makes no progress.
    fn drain_pending(&mut self) -> Vec<EntryHash> {
        let mut lifted = Vec::new();
        loop {
            let parked = std::mem::take(&mut self.pending);
            let mut still_pending = Vec::with_capacity(parked.len());
            let mut progressed = false;
            for op in parked {
                if let Some(hash) = self.try_lift(&op) {
                    lifted.push(hash);
                    progressed = true;
                } else {
                    still_pending.push(op);
                }
            }
            self.pending = still_pending;
            if !progressed {
                break;
            }
        }
        lifted
    }

    /// **M3.2 — compact at the current frontier** (`windowed-store-design.md`
    /// §2.4-2.5). A no-op on the M3.0 profile (returns zero discards).
    ///
    /// The cut `C` is the whole currently-retained set (causally closed by strict
    /// deferral, §2.1). The domain's [`OpLanguage::retain`] names the residue
    /// `R ⊆ C` — the ops whose contribution to a *future* fold is not yet
    /// monotone-shadowed (§2.4); everything else is discarded from `decoded` (the
    /// fold never sees it again) and from the DAG. The **packed ancestry summary** is
    /// rebuilt over `R` in lockstep ([`PackedSummary::rebuild`]), reclaiming dense
    /// indices so it stays `O(|R|²)`-wide, and staying exact for every retained pair
    /// (so `is_ancestor` across the cut is unchanged). The fold over `checkpoint ⊕
    /// window` then equals the full-history fold (§2.6) — *iff* the domain's retention
    /// honors the shadowing law. That "iff" is the whole adversarial gate: an unsound
    /// `retain` makes `view() != full.view()`, which the §6.3 suite catches.
    ///
    /// Idempotent and composable: compacting a compacted store at a later cut folds
    /// the same fold-equivalent object (§2.6 corollary i). Repeated calls with no new
    /// ops discard nothing more.
    pub fn compact(&mut self) -> Compaction {
        if self.checkpoint.is_none() {
            return Compaction {
                discarded: 0,
                retained: self.decoded.len(),
            };
        }

        // The cut = every retained op. Ask the domain what to keep, folding through
        // the packed-summary oracle (borrowed, no clone) so `retain` reasons over the
        // exact same `is_ancestor`/`resolve` the fold uses.
        let cut: BTreeSet<EntryHash> = self.decoded.keys().copied().collect();
        let keep = {
            let cp = self.checkpoint.as_ref().expect("compaction profile");
            let reach = cp.summary.reach();
            let ctx = FoldCtx::over(&self.decoded, &self.entry_to_source, Box::new(reach));
            L::retain(&ctx, &cut)
        };

        // Pin the cut `ops_root` at the FIRST compaction — full history is still
        // resident here (discards happen just below), so this commits to it (§4.3).
        #[cfg(feature = "merkle")]
        {
            let full_root = crate::merkle::ops_root_of(self.entry_to_source.keys());
            let cp = self.checkpoint.as_mut().expect("compaction profile");
            if cp.pinned_cut_ops_root.is_none() {
                cp.pinned_cut_ops_root = Some(full_root);
            }
        }

        let discard: BTreeSet<EntryHash> = cut.difference(&keep).copied().collect();

        // Rebuild the packed summary over the new residue `keep`: reclaim dense indices
        // (keeping it `O(|R|²)`-wide, independent of N — the M3.2 bound) while staying
        // exact for every retained pair. Discarded ops keep a bounded residue-ancestor
        // row in `discarded_reach` so a later laggard referencing one still folds
        // correctly with no courier (§4.5 residual — the O(N) part M3.2 does not yet
        // bound; deep-laggard courier admission would eliminate it).
        {
            let cp = self.checkpoint.as_mut().expect("compaction profile");
            cp.summary.rebuild(&keep);
            cp.total_discarded += discard.len();
            cp.compactions += 1;
        }

        // Discard C \ R from the fold's view (decoded), the cut-scoped identity map,
        // and the DAG — the fold never iterates or names a discarded op again, and the
        // dominant per-op memory (the decoded record, §5.1) is freed. `source_to_entry`
        // is deliberately KEPT for every lifted op, so a later op referencing a
        // discarded prev still resolves it to the same [`EntryHash`] a full peer
        // computes — convergence (§4.1). Bounding that binding table (courier-resolved
        // deep-laggard admission, §4.5) is deferred.
        for d in &discard {
            self.decoded.remove(d);
            self.entry_to_source.remove(d);
            self.dag.discard(d);
        }

        Compaction {
            discarded: discard.len(),
            retained: self.decoded.len(),
        }
    }

    /// Total ops discarded across every compaction (auto + explicit) — diagnostics.
    /// `0` on the M3.0 profile.
    pub fn total_discarded(&self) -> usize {
        self.checkpoint.as_ref().map_or(0, |cp| cp.total_discarded)
    }

    /// Number of compaction events run so far (auto + explicit) — diagnostics.
    pub fn compaction_count(&self) -> usize {
        self.checkpoint.as_ref().map_or(0, |cp| cp.compactions)
    }

    /// The pinned cut `ops_root` (§4.3), if this store has compacted at least once
    /// under feature `merkle`. The self-made commitment against which a Mode-A leaf
    /// verifies proofs for discarded ops.
    #[cfg(feature = "merkle")]
    pub fn pinned_cut_ops_root(&self) -> Option<[u8; 32]> {
        self.checkpoint
            .as_ref()
            .and_then(|cp| cp.pinned_cut_ops_root)
    }

    /// Author and sign a local op without mutating the projection (two-phase commit,
    /// for durable runtimes). Stamps the retained frontier as `observed`.
    pub fn prepare_commit(
        &self,
        key: &SigningKey,
        topic: &str,
        ts_micros: u64,
        op: L::Op,
    ) -> SignedOp {
        use crate::ops::{VersionedOpG, sign_versioned_op};
        let author = AuthorId(*key.verifying_key().as_bytes());
        let head = self.heads.get(&author).copied().unwrap_or_else(LogHead::genesis);
        let observed = self.observed_frontier();
        let versioned =
            VersionedOpG::<L>::current_for_topic(op, ts_micros, topic).observing(observed);
        let (signed, _advanced) = sign_versioned_op(key, &head, versioned);
        signed
    }

    /// Author, sign, verify, and ingest a new local op, returning the signed bytes.
    /// In-memory/test convenience; durable runtimes call [`WindowedStore::prepare_commit`]
    /// then persist then ingest.
    pub fn commit(
        &mut self,
        key: &SigningKey,
        topic: &str,
        ts_micros: u64,
        op: L::Op,
    ) -> SignedOp {
        use crate::ops::verify_signed_op_in;
        let signed = self.prepare_commit(key, topic, ts_micros, op);
        let verified = verify_signed_op_in::<L>(&signed).expect("a just-signed op verifies");
        self.ingest_verified(verified);
        signed
    }

    /// The bounded-window [`DagDelta::appended_since`](hhhs_dag::DagDelta) contract,
    /// forwarded from the backing [`WindowedDag`](hhhs_dag::WindowedDag): `Some` inside
    /// the window, `None` past its boundary (§1.3, §7).
    pub fn appended_since(&self, since: GrowthEpoch) -> Option<Vec<Entry>> {
        self.dag.appended_since(since)
    }

    /// Materialize the read model — **fenced** (§1.3, §6.2 delta 6), now relaxed for
    /// M3.1 compaction.
    ///
    /// The fold runs the byte-identical `L::fold` over the retained-op map
    /// (residue ∪ window) through a [`Reach`](hhhs_dag::Reach) backend assembled via
    /// the public [`FoldCtx::over`](crate::FoldCtx::over) constructor — so
    /// windowed-vs-full equivalence is *structural* (same fold, only the ancestry
    /// backend differs, §3.5):
    ///
    /// - **M3.0** (no compaction): the §3.3 window bitset
    ///   ([`WindowedDag::windowed_reach`](hhhs_dag::WindowedDag::windowed_reach)).
    /// - **M3.2** (compaction): the packed ancestry summary (§3.2/§3.3/§3.4) — exact
    ///   across the cut in bounded memory, so the fold over `checkpoint ⊕ window`
    ///   equals the full fold for `N > W` (§2.6).
    ///
    /// # The fence (relaxed, §6.2 delta 6)
    ///
    /// It **hard-refuses (panics)** only for a genuinely-unanswerable state
    /// ([`WindowedStore::is_answerable`] is `false`): an M3.0 window that
    /// hard-truncated past `W` with no compaction to account for the dropped ops.
    /// That is the one case that must never silently mis-answer `is_ancestor` across
    /// the cut (a *wrong view, not an error*, §1.3). A **compacted** store is not
    /// complete but *is* answerable — its packed summary answers ancestry exactly —
    /// so it folds without refusing. Use [`WindowedStore::try_view`] for the
    /// non-panicking form.
    pub fn view(&self) -> L::View {
        assert!(
            self.is_answerable(),
            "windowed view fence: the window hard-truncated (N > W) with no compaction \
             to account for the dropped ops. A fold over it would silently mis-answer \
             is_ancestor across the cut (a wrong view, not an error — \
             windowed-store-design.md §1.3, §6.2 delta 6). Build the store with \
             `with_window` (M3.1 compaction) to fold past W.",
        );
        match self.checkpoint.as_ref() {
            Some(cp) => {
                // M3.2: fold over residue ∪ window through the packed summary.
                let reach = cp.summary.reach();
                let ctx = FoldCtx::over(&self.decoded, &self.entry_to_source, Box::new(reach));
                L::fold(&ctx)
            }
            None => {
                // M3.0: fold over the complete window through the §3.3 bitset.
                let reach = self.dag.windowed_reach();
                let ctx = FoldCtx::over(&self.decoded, &self.entry_to_source, Box::new(reach));
                L::fold(&ctx)
            }
        }
    }

    /// The non-panicking form of [`WindowedStore::view`]: `Some(view)` while
    /// answerable (M3.0 `N ≤ W`, or any compacted M3.1 state), `None` once an M3.0
    /// window has hard-truncated. The fence, as a value.
    pub fn try_view(&self) -> Option<L::View> {
        if self.is_answerable() {
            Some(self.view())
        } else {
            None
        }
    }

    /// The §3.5 boundary oracle over the current retained set, exposed so the §6.3
    /// gate can assert `WindowedReach::is_ancestor ≡ ReachIndex::is_ancestor` on the
    /// full store for every retained pair (M3.0: window bitset; M3.2: packed summary).
    /// Panics if an M3.0 window truncated.
    pub fn windowed_reach(&self) -> WindowedReach {
        match self.checkpoint.as_ref() {
            Some(cp) => cp.summary.to_windowed_reach(),
            None => self.dag.windowed_reach(),
        }
    }

    /// **The M3.2 memory-bound instrument (§3.2/§3.3/§3.4).** The number of retained-op
    /// rows in the packed ancestry summary — `|R| + |window|`, the height of the
    /// bounded reach matrix. Flat in `N` at fixed `W` + bounded residue (the memory-
    /// bound gate asserts it). `0` on the M3.0 profile.
    #[cfg(any(test, feature = "test-support"))]
    pub fn packed_summary_entries(&self) -> usize {
        self.checkpoint.as_ref().map_or(0, |cp| cp.summary.len())
    }

    /// **The M3.2 memory-bound instrument (§3.2/§3.3/§3.4).** Backing-store bytes of the
    /// packed ancestry summary *proper* (the retained-op reach matrix + its dense
    /// index) — `O((|R|+|window|)²)`, **independent of N**. This is the headline figure:
    /// M3.1's exact `anc` was Θ(N²); this is flat. Excludes the courier-deferred
    /// [`WindowedStore::courier_gap_entries`] residual.
    #[cfg(any(test, feature = "test-support"))]
    pub fn packed_summary_bytes(&self) -> usize {
        self.checkpoint
            .as_ref()
            .map_or(0, |cp| cp.summary.summary_bytes())
    }

    /// **The honest residual (§4.5).** The number of discarded ops whose bounded
    /// residue-ancestor row is retained so a future laggard referencing one still folds
    /// with no courier. This map is `O(N)` (one bounded row per discarded op) — the part
    /// M3.2 does **not** yet bound; deep-laggard courier admission (§4.5) would drop it.
    /// Still far below M3.1's Θ(N²) exact `anc`. `0` on the M3.0 profile.
    #[cfg(any(test, feature = "test-support"))]
    pub fn courier_gap_entries(&self) -> usize {
        self.checkpoint
            .as_ref()
            .map_or(0, |cp| cp.summary.discarded_len())
    }

    /// The backing bounded-window DAG, read-only. Exposed (feature `test-support`) so
    /// the equivalence gate can build a kernel `ReachIndex` over the window and
    /// cross-check the bitset reach.
    #[cfg(any(test, feature = "test-support"))]
    pub fn dag(&self) -> &WindowedDag {
        &self.dag
    }

    /// The reference projection: the identical `L::fold` driven by an independent
    /// oracle — the windowed analogue of
    /// [`Store::view_reference`](crate::Store::view_reference).
    ///
    /// **M3.0** (complete window): the kernel `ReachIndex` rebuilt over the window,
    /// giving the root-of-trust cross-check the §6.3 gate makes against the cheap
    /// bitset. Fenced (panics if truncated — a `ReachIndex` over a hard-truncated
    /// window would silently mis-answer, §1.3).
    ///
    /// **M3.1** (compacted): a `ReachIndex` over the *truncated* DAG would be exactly
    /// the §1.3 foot-gun, so the independent kernel oracle for a compacted store lives
    /// on the **full** store (`full.view_reference()`), which the gate compares
    /// against. Here this returns the frozen-summary fold ([`WindowedStore::view`]),
    /// which the gate proves equal to that full-history oracle.
    #[cfg(any(test, feature = "test-support"))]
    pub fn view_reference(&self) -> L::View {
        if self.checkpoint.is_some() {
            return self.view();
        }
        assert!(
            self.dag.is_complete(),
            "windowed view_reference fence: truncated window (windowed-store-design.md §1.3)",
        );
        let snapshot = self.dag.snapshot();
        let reach = ReachIndex::new(&snapshot);
        let ctx = FoldCtx::over(&self.decoded, &self.entry_to_source, Box::new(reach));
        L::fold(&ctx)
    }
}

/// Generic Merkle commitments over the retained entry-hash set (feature `merkle`),
/// mirroring [`Store<L>`](crate::Store)'s. `ops_root` over the window is the **window
/// `ops_root`** of §4.3 (comparable cut-scoped); while `N ≤ W` it equals a full
/// store's outright.
#[cfg(feature = "merkle")]
impl<L: OpLanguage> WindowedStore<L> {
    /// The window `ops_root`: a canonical blake3-256 Merkle commitment to the retained
    /// entry-hash set (§4.3), over the same `entry_to_source.keys()` iterator
    /// [`WindowedStore::sync_root`] digests.
    pub fn ops_root(&self) -> [u8; 32] {
        crate::merkle::ops_root_of(self.entry_to_source.keys())
    }

    /// An inclusion / non-inclusion proof for `entry` against
    /// [`WindowedStore::ops_root`] — producible only for retained entries (§4.3).
    pub fn prove_op(&self, entry: &EntryHash) -> radix_immutable::Proof {
        crate::merkle::prove_op(self.entry_to_source.keys(), entry)
    }
}
