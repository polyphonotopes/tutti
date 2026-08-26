//! [`WindowedStore<L>`] — the leaf-profile domain sibling of [`Store<L>`](crate::Store),
//! plus its **M3.1 monotone-shadowing compaction** bookkeeping.
//!
//! The L-free machinery this store drives — the bounded-window
//! [`WindowedDag`], its [`WindowedReach`]
//! backend, and the bounded [`PackedSummary`] ancestry summary
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
//! `Checkpoint`-tracked ancestry summary answers `is_ancestor` across the cut
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
//! carries across the cut is the floor's [`PackedSummary`]:
//! one dense retained-ancestor bitset closure, `O((|R|+|window|)²)` bits — **independent
//! of total history N**, so the store's *memory* is bounded to the leaf budget (§5),
//! not just its fold input.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use hhhs_dag::windowed::{
    Courier, CourierFault, DiscardProof, LiftOutcome, PackedSummary, WindowedDag, WindowedReach,
};
use hhhs_dag::{DagRead, Digest, Entry, EntryHash, GrowthEpoch, Position};

#[cfg(any(test, feature = "test-support"))]
use hhhs::cover::ReachIndex;

use crate::ops::{AuthorId, LogHead, OpId, OpLanguage, SignedOp, SigningKey, VerifiedOpG};
use crate::store::{DecodedOp, FoldCtx, frame_signed, sync_root_of, unframe_signed};

// ===========================================================================
// §2.2 — the checkpoint: compacted state + packed ancestry summary.
// ===========================================================================

/// The [`Default`] cap on retained discard-journal **entries** (not batches) — twice
/// [`PackedSummary::DEFAULT_DISCARD_CAP`], so the journal outlives the reach cache: an
/// op whose cached reach row was just evicted is still provable for a while before its
/// whole batch ages out of the journal too.
pub const DEFAULT_DISCARD_HISTORY_CAP: usize = PackedSummary::DEFAULT_DISCARD_CAP * 2;

/// Monotone sequence number of one discard batch — the `n`-th non-empty batch this
/// store's compactions ever folded into its pinned discard root (0-based).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscardBatchSeq(pub u64);

/// One retained discard batch, owned by the journal.
#[derive(Clone, Debug)]
struct StoredDiscardBatch {
    seq: DiscardBatchSeq,
    /// Canonical ascending [`EntryHash`] order; semantically a set.
    entries: Box<[EntryHash]>,
}

/// A borrowed view of one retained discard batch
/// ([`WindowedStore::discard_batches`]) — what a fuller peer copies to track this
/// store's discard chain and answer its couriers.
#[derive(Clone, Copy, Debug)]
pub struct DiscardBatchRef<'a> {
    pub seq: DiscardBatchSeq,
    /// Ascending [`EntryHash`] order; semantically a set.
    pub entries: &'a [EntryHash],
}

/// The **bounded discard journal** (M3.2 courier responder floor): the most recent
/// discard batches, verbatim, so this store — or a peer that copied them — can
/// construct a [`DiscardProof`] for any member of a retained batch against the
/// store's own chained [`PackedSummary::discard_root`].
///
/// `PackedSummary::rebuild` commits each non-empty batch into the 32-byte pinned
/// root and then forgets the batch itself; this journal records the identical
/// `discard` set [`WindowedStore::compact`] computes, capped by **entry** count.
/// Eviction is by whole batch (front/oldest first): retaining only part of a batch
/// cannot reconstruct its Merkle path. `pinned_before_front` re-anchors the chain as
/// batches age out, so proofs for every retained batch keep verifying against the
/// current root. Past eviction, [`WindowedStore::prove_discarded_at`] returns `None`
/// and the deep laggard stays safely deferred — memory stays `O(entry_cap)`,
/// independent of total history.
struct DiscardHistory {
    /// The pinned discard root's value immediately before `batches.front()` was
    /// folded in (all-zero while nothing has been evicted).
    pinned_before_front: Digest,
    /// Retained batches, oldest first.
    batches: VecDeque<StoredDiscardBatch>,
    /// Total entries across `batches`.
    stored_entries: usize,
    /// Cap on `stored_entries`; enforced by whole-batch eviction.
    entry_cap: usize,
    /// Sequence number the next recorded batch gets.
    next_seq: u64,
}

impl DiscardHistory {
    fn new(entry_cap: usize) -> Self {
        Self {
            pinned_before_front: Digest([0u8; 32]),
            batches: VecDeque::new(),
            stored_entries: 0,
            entry_cap,
            next_seq: 0,
        }
    }

    /// Record one non-empty discard batch. `pinned_before` is the pinned discard
    /// root's value just before this batch was folded in (i.e. before the
    /// [`PackedSummary::rebuild`] that committed it).
    ///
    /// An oversized batch (`entries.len() > entry_cap`) is itself unprovable, and it
    /// forces every older batch out too: a proof for an older batch must name this
    /// batch's root among its `later_batches`, which requires holding the batch.
    fn record(&mut self, entries: Box<[EntryHash]>, pinned_before: Digest) {
        debug_assert!(!entries.is_empty(), "empty batches are never pinned");
        debug_assert!(
            entries.is_sorted(),
            "batch entries must be canonically sorted"
        );
        let seq = DiscardBatchSeq(self.next_seq);
        self.next_seq += 1;
        if entries.len() > self.entry_cap {
            let root = Self::root_of(&entries);
            self.batches.clear();
            self.stored_entries = 0;
            // With no retained batches the front anchor IS the current root.
            self.pinned_before_front = DiscardProof::fold_pinned(&pinned_before, &root);
            return;
        }
        self.stored_entries += entries.len();
        self.batches.push_back(StoredDiscardBatch { seq, entries });
        while self.stored_entries > self.entry_cap {
            let popped = self
                .batches
                .pop_front()
                .expect("over-cap journal has an oldest batch");
            self.stored_entries -= popped.entries.len();
            self.pinned_before_front = DiscardProof::fold_pinned(
                &self.pinned_before_front,
                &Self::root_of(&popped.entries),
            );
        }
    }

    /// The canonical Merkle root of one stored batch.
    fn root_of(entries: &[EntryHash]) -> Digest {
        DiscardProof::batch_root(&entries.iter().copied().collect())
    }

    /// A membership proof for `member` against the chain this journal has retained,
    /// or `None` if `member`'s batch has been evicted (or was never discarded).
    fn prove(&self, member: &EntryHash) -> Option<DiscardProof> {
        let idx = self
            .batches
            .iter()
            .position(|batch| batch.entries.binary_search(member).is_ok())?;
        let mut pinned_before = self.pinned_before_front;
        for earlier in self.batches.iter().take(idx) {
            pinned_before =
                DiscardProof::fold_pinned(&pinned_before, &Self::root_of(&earlier.entries));
        }
        let later: Vec<Digest> = self
            .batches
            .iter()
            .skip(idx + 1)
            .map(|batch| Self::root_of(&batch.entries))
            .collect();
        let batch: BTreeSet<EntryHash> = self.batches[idx].entries.iter().copied().collect();
        DiscardProof::for_member(&batch, member, pinned_before, later)
    }
}

/// The **checkpoint** a compacted [`WindowedStore`] carries across the cut. Present
/// iff the store was built for compaction ([`WindowedStore::with_window`]).
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
    /// The bounded discard journal backing [`WindowedStore::prove_discarded_at`] and
    /// [`WindowedStore::discard_batches`] — the courier responder's proof floor.
    discard_history: DiscardHistory,
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
    fn with_limits(discard_reach_cap: usize, discard_history_entry_cap: usize) -> Self {
        Self {
            summary: PackedSummary::with_discard_cap(discard_reach_cap),
            discard_history: DiscardHistory::new(discard_history_entry_cap),
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
// §4.5 — deep-laggard deferral surfaced to the sync layer.
// ===========================================================================

/// One verified op the store could NOT admit locally: a `prev` was discarded and its
/// cached reach row has been evicted, so an exact ancestor row cannot be built
/// without courier help (§4.5). The op stays parked in `pending` — deferred, never
/// wrong — until [`WindowedStore::lift_pending_via_courier`] admits it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeferredLift {
    /// The locally re-derived entry hash the op would lift under — stable, because
    /// strict deferral fixes the op's resolved `prevs` (`source_to_entry` keeps
    /// discarded bindings).
    pub candidate: EntryHash,
    /// The evicted-predecessor rows a courier must answer for.
    pub missing: BTreeSet<EntryHash>,
}

/// What one [`WindowedStore::ingest_verified`] call did: the entries it lifted, plus
/// the ops it had to park for courier admission.
#[derive(Clone, Debug, Default)]
pub struct WindowIngest {
    /// Entries newly lifted (materialized and indexed), in lift order.
    pub lifted: Vec<EntryHash>,
    /// Ops deferred pending a courier round trip (§4.5), deduplicated by candidate.
    pub courier: Vec<DeferredLift>,
}

/// The outcome of one internal lift attempt.
enum TryLift {
    /// Appended under this entry hash.
    Lifted(EntryHash),
    /// Ordinary missing `OpId` reference; wait for RBSR closure (strict deferral).
    MissingSources,
    /// Every source resolves but a discarded prev's reach is gone — courier needed.
    Courier(DeferredLift),
}

/// The horizon a courier request is answered against: the requester's pinned discard
/// root plus its current retained identity set. The responder's ancestor mask
/// indexes `retained` positionally, so admission requires the store's context to
/// still equal the one the request was built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CourierContext {
    /// [`PackedSummary::discard_root`] at request time.
    pub discard_root: Digest,
    /// The sorted current retained entry-hash universe; a response mask indexes this
    /// exact array.
    pub retained: Box<[EntryHash]>,
}

/// Why [`WindowedStore::lift_pending_via_courier`] declined to admit. The store is
/// unchanged in every case — the op stays parked (§4.5 defer-never-reject).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeferredLiftError {
    /// The store's current [`WindowedStore::courier_context`] no longer equals the
    /// context the answer was produced against (a compaction or lift intervened, or
    /// this is not a compacting store). Re-request under the fresh context.
    StaleContext,
    /// No parked op currently derives this candidate hash with fully resolved
    /// sources.
    UnknownCandidate(EntryHash),
    /// The floor rejected the courier's answer ([`CourierFault`]); nothing admitted.
    Courier(CourierFault),
}

impl core::fmt::Display for DeferredLiftError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StaleContext => write!(f, "courier context is stale; re-request"),
            Self::UnknownCandidate(hash) => {
                write!(f, "no parked op derives candidate {:?}", hash)
            }
            Self::Courier(fault) => write!(f, "courier admission failed: {fault:?}"),
        }
    }
}

impl std::error::Error for DeferredLiftError {}

// ===========================================================================
// §6.1 — `WindowedStore<L>`: the leaf-profile domain sibling of `Store<L>`.
// ===========================================================================

/// The leaf-profile sibling of [`Store<L>`](crate::Store): the same lift / strict-
/// deferral / drain machinery over a bounded [`WindowedDag`], a fenced
/// [`WindowedStore::view`], and a cut-scoped sync surface (§1.2, §4.2).
///
/// It is **byte-compatible by construction** with [`Store<L>`](crate::Store): it lifts
/// through the identical `frame_signed` framing, so the same op yields the same
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
        Self::with_window_limits(
            window_cap,
            PackedSummary::DEFAULT_DISCARD_CAP,
            DEFAULT_DISCARD_HISTORY_CAP,
        )
    }

    /// [`WindowedStore::with_window`] with explicit M3.2 residual bounds:
    /// `discard_reach_cap` caps the cached discarded-op reach rows (ordinary
    /// stragglers admit locally while their prev's row is cached; past it they defer
    /// to the courier, §4.5), and `discard_history_entry_cap` caps the discard
    /// journal backing [`WindowedStore::prove_discarded_at`] (past it a member's
    /// proof is `None` and its laggard stays safely deferred).
    pub fn with_window_limits(
        window_cap: usize,
        discard_reach_cap: usize,
        discard_history_entry_cap: usize,
    ) -> Self {
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
            checkpoint: Some(Checkpoint::with_limits(
                discard_reach_cap,
                discard_history_entry_cap,
            )),
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
    /// Returns what this call did: [`WindowIngest::lifted`] names the entries newly
    /// lifted (empty means the op parked or is a duplicate — a parked op is not in
    /// [`WindowedStore::entry_hashes`]), and [`WindowIngest::courier`] names any op
    /// deferred for courier admission (§4.5: a referenced prev was discarded and its
    /// cached reach row is gone, so the op parks rather than admit a wrong row).
    pub fn ingest_verified(&mut self, op: VerifiedOpG<L>) -> WindowIngest {
        let id = op.id();
        if self.source_to_entry.contains_key(&id) {
            return WindowIngest::default();
        }
        if self.pending.iter().any(|p| p.id() == id) {
            return WindowIngest::default();
        }
        self.advance_head(&op);
        self.pending.push(op);
        let ingest = self.drain_pending();
        // M3.1: keep steady-state memory ≈ residue + W by compacting once the retained
        // set outgrows the window budget. Explicit `compact()` (adversarial cuts) is
        // layered on top; both call the same sound retention path.
        if self.checkpoint.is_some() && self.decoded.len() > self.window_cap {
            self.compact();
        }
        ingest
    }

    /// Advance (never regress) the author's tracked head to the greatest seq seen.
    fn advance_head(&mut self, op: &VerifiedOpG<L>) {
        let advanced = op.advanced_head();
        let slot = self
            .heads
            .entry(op.author())
            .or_insert_with(LogHead::genesis);
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

    /// Try to lift one op. [`TryLift::Lifted`] iff appended; otherwise no mutation:
    /// [`TryLift::MissingSources`] when its causal past is incomplete (ordinary
    /// strict deferral), [`TryLift::Courier`] when every source resolves but a
    /// discarded prev's reach row is gone (§4.5 deep laggard — park for the courier).
    ///
    /// **M3.0** (no compaction): `append_capped` with hard eviction past `W`; evicted
    /// entries are pruned from every map in lockstep with the [`WindowedDag`].
    ///
    /// **M3.2** (compaction): a non-evicting insert, and the **packed ancestry summary**
    /// is extended for this op via [`PackedSummary::lift`] — one bounded strict-
    /// retained-ancestor [`BitRow`], `reach(entry) = ⋃_{p ∈ prevs}({index(p)} ∪
    /// reach(p))` (§3.2/§3.3). Because the store lifts an op only once every prev is
    /// present (strict deferral) and every prev's row is already built, the new row is
    /// exact (§3.2 boundary lemma; the standard memoized-topo closure, in bits). A
    /// [`LiftOutcome::Deferred`] answer leaves the summary — and the store — entirely
    /// unmutated: no DAG, source-map, or decoded insertion happens for a deferred op.
    /// Eviction is deferred to [`WindowedStore::compact`].
    fn try_lift(&mut self, op: &VerifiedOpG<L>) -> TryLift {
        let Some(prevs) = self.resolve_prevs(op) else {
            return TryLift::MissingSources;
        };
        let entry = Entry::new(frame_signed::<L>(&op.signed()), Position(prevs.clone()));
        let entry_hash = entry.hash();
        let id = op.id();

        if let Some(cp) = self.checkpoint.as_mut() {
            // M3.2 compaction profile: packed-summary extension first — only a
            // Lifted verdict may materialize anything.
            match cp.summary.lift(entry_hash, &prevs) {
                LiftOutcome::Lifted => {}
                LiftOutcome::Deferred { missing } => {
                    return TryLift::Courier(DeferredLift {
                        candidate: entry_hash,
                        missing,
                    });
                }
            }
            self.dag.insert(&entry);
            self.source_to_entry.insert(id, entry_hash);
            self.entry_to_source.insert(entry_hash, id);
            self.decoded.insert(
                entry_hash,
                DecodedOp::new(
                    op.author(),
                    op.payload().clone(),
                    op.timestamp_ms(),
                    op.seq_num(),
                ),
            );
            return TryLift::Lifted(entry_hash);
        }

        // M3.0 profile: unchanged bounded-window hard eviction.
        let evicted = self.dag.append_capped(&entry);
        self.source_to_entry.insert(id, entry_hash);
        self.entry_to_source.insert(entry_hash, id);
        self.decoded.insert(
            entry_hash,
            DecodedOp::new(
                op.author(),
                op.payload().clone(),
                op.timestamp_ms(),
                op.seq_num(),
            ),
        );
        for gone in evicted {
            if let Some(gone_id) = self.entry_to_source.remove(&gone) {
                self.source_to_entry.remove(&gone_id);
            }
            self.decoded.remove(&gone);
        }
        TryLift::Lifted(entry_hash)
    }

    /// Repeatedly attempt to lift parked ops until a full pass makes no progress.
    /// Courier-deferred ops stay parked and are reported once per candidate.
    fn drain_pending(&mut self) -> WindowIngest {
        let mut lifted = Vec::new();
        let mut courier: BTreeMap<EntryHash, DeferredLift> = BTreeMap::new();
        loop {
            let parked = std::mem::take(&mut self.pending);
            let mut still_pending = Vec::with_capacity(parked.len());
            let mut progressed = false;
            for op in parked {
                match self.try_lift(&op) {
                    TryLift::Lifted(hash) => {
                        lifted.push(hash);
                        progressed = true;
                    }
                    TryLift::MissingSources => still_pending.push(op),
                    TryLift::Courier(deferred) => {
                        courier.insert(deferred.candidate, deferred);
                        still_pending.push(op);
                    }
                }
            }
            self.pending = still_pending;
            if !progressed {
                break;
            }
        }
        // Defensive: a candidate that ultimately lifted is not a courier case.
        for hash in &lifted {
            courier.remove(hash);
        }
        WindowIngest {
            lifted,
            courier: courier.into_values().collect(),
        }
    }

    /// **M3.2 — compact at the current frontier.** A no-op on the M3.0 profile
    /// (returns zero discards).
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
        // correctly with no courier; past that cap the laggard defers and is admitted
        // through `lift_pending_via_courier` (§4.5). The identical discard set is
        // journaled (bounded) so this store — or a peer copying the journal — can
        // prove membership of a discarded op against the pinned root the rebuild
        // chains; `pinned_before` is captured BEFORE the rebuild folds the batch in.
        {
            let cp = self.checkpoint.as_mut().expect("compaction profile");
            let pinned_before = cp.summary.discard_root();
            cp.summary.rebuild(&keep);
            if !discard.is_empty() {
                cp.discard_history.record(
                    discard
                        .iter()
                        .copied()
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                    pinned_before,
                );
            }
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

    // -----------------------------------------------------------------------
    // §4.5 — the discard journal (courier responder floor) and courier admission.
    // -----------------------------------------------------------------------

    /// This store's pinned discard root — the chained
    /// [`PackedSummary::discard_root`] every [`DiscardProof`] must verify against
    /// (all-zero until the first discarding compaction). `None` on the M3.0 profile.
    pub fn discard_root(&self) -> Option<Digest> {
        self.checkpoint.as_ref().map(|cp| cp.summary.discard_root())
    }

    /// The retained discard batches, oldest first — the journal a fuller peer copies
    /// (per batch, in order) to track this store's discard chain and later answer
    /// its courier requests. Bounded: whole batches age out oldest-first past the
    /// journal's entry cap. Empty on the M3.0 profile.
    pub fn discard_batches(&self) -> impl DoubleEndedIterator<Item = DiscardBatchRef<'_>> + '_ {
        self.checkpoint.iter().flat_map(|cp| {
            cp.discard_history
                .batches
                .iter()
                .map(|batch| DiscardBatchRef {
                    seq: batch.seq,
                    entries: &batch.entries,
                })
        })
    }

    /// The oldest retained batch's sequence number, or `None` if the journal is
    /// empty (nothing discarded yet, or everything retained has aged out).
    pub fn oldest_discard_batch(&self) -> Option<DiscardBatchSeq> {
        self.checkpoint
            .as_ref()
            .and_then(|cp| cp.discard_history.batches.front())
            .map(|batch| batch.seq)
    }

    /// The sequence number the next non-empty discard batch will get.
    pub fn next_discard_batch(&self) -> DiscardBatchSeq {
        DiscardBatchSeq(
            self.checkpoint
                .as_ref()
                .map_or(0, |cp| cp.discard_history.next_seq),
        )
    }

    /// A membership proof that `member` is committed in this store's own discard
    /// chain, against `expected_root` — the self-serve form of the courier
    /// responder. `None` for a root mismatch (`expected_root` is not the current
    /// [`WindowedStore::discard_root`]), for a member whose batch has been evicted
    /// from the bounded journal, or for a member this store never discarded — the
    /// asking laggard then simply stays deferred (§4.5 defer-never-reject).
    pub fn prove_discarded_at(
        &self,
        member: &EntryHash,
        expected_root: Digest,
    ) -> Option<DiscardProof> {
        let cp = self.checkpoint.as_ref()?;
        if expected_root != cp.summary.discard_root() {
            return None;
        }
        cp.discard_history.prove(member)
    }

    /// Retry every parked op: anything unblocked since the last attempt lifts (and
    /// is reported in [`WindowIngest::lifted`]), and whatever still needs courier
    /// help is enumerated in [`WindowIngest::courier`] — the poll a sync driver runs
    /// between courier round trips (§4.5). A no-op returning empty vectors when
    /// nothing is parked.
    pub fn retry_pending(&mut self) -> WindowIngest {
        self.drain_pending()
    }

    /// The horizon a courier request must be answered against: the current pinned
    /// discard root plus the sorted retained identity set (the array a response's
    /// ancestor mask indexes). `None` on the M3.0 profile — a non-compacting store
    /// never courier-defers.
    pub fn courier_context(&self) -> Option<CourierContext> {
        let cp = self.checkpoint.as_ref()?;
        Some(CourierContext {
            discard_root: cp.summary.discard_root(),
            retained: self
                .entry_to_source
                .keys()
                .copied()
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        })
    }

    /// Admit a courier-deferred op ([`DeferredLift`]) with a courier's answers
    /// (§4.5). `expected_context` is the context the answers were produced against;
    /// it must still equal the store's current [`WindowedStore::courier_context`] —
    /// a stale context is rejected BEFORE the floor is consulted, since its mask
    /// indexes a retained array that no longer exists.
    ///
    /// On success the op is materialized exactly as a local lift would have
    /// materialized it, removed from `pending`, and every op it unblocks is drained;
    /// the returned entries are `candidate` first, then the drained lifts. On any
    /// error **nothing is mutated** and the op stays parked — deferred, never
    /// rejected, never wrong ([`PackedSummary::lift_via_courier`] verifies the proof
    /// half against the pinned root and admits only then).
    pub fn lift_pending_via_courier(
        &mut self,
        candidate: EntryHash,
        expected_context: &CourierContext,
        courier: &dyn Courier,
    ) -> Result<Vec<EntryHash>, DeferredLiftError> {
        let current = self
            .courier_context()
            .ok_or(DeferredLiftError::StaleContext)?;
        if current != *expected_context {
            return Err(DeferredLiftError::StaleContext);
        }

        // Re-derive the parked op this candidate names. Strict deferral makes the
        // derivation stable: resolved prevs come from `source_to_entry`, which keeps
        // discarded bindings.
        let mut found: Option<(usize, BTreeSet<EntryHash>, Entry)> = None;
        for (i, op) in self.pending.iter().enumerate() {
            let Some(prevs) = self.resolve_prevs(op) else {
                continue;
            };
            let entry = Entry::new(frame_signed::<L>(&op.signed()), Position(prevs.clone()));
            if entry.hash() == candidate {
                found = Some((i, prevs, entry));
                break;
            }
        }
        let (idx, prevs, entry) = found.ok_or(DeferredLiftError::UnknownCandidate(candidate))?;

        {
            let cp = self
                .checkpoint
                .as_mut()
                .expect("courier_context() answered, so this is a compacting store");
            cp.summary
                .lift_via_courier(candidate, &prevs, courier)
                .map_err(DeferredLiftError::Courier)?;
        }

        // Admitted by the floor: materialize exactly as a local lift would.
        let op = self.pending.remove(idx);
        self.dag.insert(&entry);
        self.source_to_entry.insert(op.id(), candidate);
        self.entry_to_source.insert(candidate, op.id());
        self.decoded.insert(
            candidate,
            DecodedOp::new(
                op.author(),
                op.payload().clone(),
                op.timestamp_ms(),
                op.seq_num(),
            ),
        );

        let mut lifted = vec![candidate];
        lifted.extend(self.drain_pending().lifted);
        // The same steady-state memory rule `ingest_verified` applies.
        if self.decoded.len() > self.window_cap {
            self.compact();
        }
        Ok(lifted)
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
        let head = self
            .heads
            .get(&author)
            .copied()
            .unwrap_or_else(LogHead::genesis);
        let observed = self.observed_frontier();
        let versioned =
            VersionedOpG::<L>::current_for_topic(op, ts_micros, topic).observing(observed);
        let (signed, _advanced) = sign_versioned_op(key, &head, versioned);
        signed
    }

    /// Author, sign, verify, and ingest a new local op, returning the signed bytes.
    /// In-memory/test convenience; durable runtimes call [`WindowedStore::prepare_commit`]
    /// then persist then ingest.
    pub fn commit(&mut self, key: &SigningKey, topic: &str, ts_micros: u64, op: L::Op) -> SignedOp {
        use crate::ops::verify_signed_op_in;
        let signed = self.prepare_commit(key, topic, ts_micros, op);
        let verified = verify_signed_op_in::<L>(&signed).expect("a just-signed op verifies");
        self.ingest_verified(verified);
        signed
    }

    /// The bounded-window [`DagDelta::appended_since`](hhhs_dag::DagDelta) contract,
    /// forwarded from the backing [`WindowedDag`]: `Some` inside
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
             is_ancestor across the cut (a wrong view, not an error). Build the store with \
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
            "windowed view_reference fence: truncated window",
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
