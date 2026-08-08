//! [`Store<L>`]: lift verified p2panda ops into an hhhs causal DAG and fold
//! the domain read model HHHS-natively.
//!
//! Every [`VerifiedOpG`] is deterministically lifted to a kernel [`Entry`] whose
//! payload is the **verbatim framed signed bytes** of the op, and whose `prevs`
//! are the entries that lift the op's `backlink` and each of its `observed`
//! op ids. Because the payload and the prev set are both pure functions of the
//! signed op, the resulting [`EntryHash`] is identical on every peer regardless
//! of the order ops arrive — which is what makes cross-peer convergence hold.
//!
//! The read model (`L::View`) is then computed by [`OpLanguage::fold`] over the
//! causal indexes packaged into a [`FoldCtx`]: the decoded op set, the entry↔op
//! map, and a causal-ancestry oracle behind the floor [`Reach`] contract. Ancestry
//! in production is the cheap lazy [`LazyReach`] (O(N + E) `prevs` adjacency,
//! reverse-walk `is_ancestor`, memoized per call) — never the whole-DAG kernel
//! `ReachIndex` closure.
//!
//! Signature verification happens once, at ingest, against a [`VerifiedOpG`];
//! reads never re-verify. None of this names a domain: the alphabet, the fold
//! rule and the view type are all `L`.

use std::collections::{BTreeMap, BTreeSet};

use hhhs_dag::{AppendOutcome, DagRead, Entry, EntryHash, LazyReach, MemDagStore, Position, Reach};

// The kernel `ReachIndex` ancestor closure backs only the reference projection
// ([`Store::view_reference`]) and this crate's equivalence tests (feature
// `test-support`); its `Reach` impl (and the `register::resolve` it forwards to) live
// in `hhhs`. Production `view()` uses the cheap lazy `LazyReach`, never an ancestor
// closure.
#[cfg(any(test, feature = "test-support"))]
use hhhs::cover::ReachIndex;

use crate::ops::{
    AuthorId, LogHead, OpId, OpLanguage, SignedOp, SigningKey, VerifiedOpG, VersionedOpG,
    sign_versioned_op, verify_signed_op_in,
};

/// Deterministically frame a signed op into an entry payload:
/// `MAGIC ++ len(header) ++ header ++ len(payload) ++ payload` (u64 little-endian
/// lengths). A pure function of the signed op — never of any decoded record — so
/// the entry hash matches byte-for-byte across peers.
///
/// The `MAGIC` is `L::ENTRY_FRAME_MAGIC`, so it fully determines the lifted entry
/// hash — the golden entry-hash vector pins it. Bumping the magic changes every
/// [`EntryHash`], so it is a schema pin.
///
/// `pub(crate)` so the leaf-profile [`crate::windowed::WindowedStore`] lifts with
/// the byte-identical framing — a windowed leaf and a full peer MUST produce the
/// same [`EntryHash`] for the same op or convergence breaks
/// (windowed-store-design.md §4.1).
pub(crate) fn frame_signed<L: OpLanguage>(signed: &SignedOp) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        L::ENTRY_FRAME_MAGIC.len() + 16 + signed.header.len() + signed.payload.len(),
    );
    out.extend_from_slice(L::ENTRY_FRAME_MAGIC);
    out.extend_from_slice(&(signed.header.len() as u64).to_le_bytes());
    out.extend_from_slice(&signed.header);
    out.extend_from_slice(&(signed.payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&signed.payload);
    out
}

/// Inverse of [`frame_signed`]: recover the verbatim [`SignedOp`] from a lifted
/// entry's payload. A total inverse of the deterministic framing above, so a
/// round-trip through the DAG payload is lossless — this is what lets the store
/// re-emit the exact bytes an author signed for anti-entropy transfer.
///
/// `pub(crate)` so [`crate::windowed::WindowedStore`] serves the same cut-scoped
/// RBSR surface (`signed_ops`/`repair_record`, windowed-store-design.md §1.2).
pub(crate) fn unframe_signed<L: OpLanguage>(bytes: &[u8]) -> SignedOp {
    let mut pos = L::ENTRY_FRAME_MAGIC.len();
    let read_len = |bytes: &[u8], pos: usize| -> usize {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[pos..pos + 8]);
        u64::from_le_bytes(buf) as usize
    };
    let header_len = read_len(bytes, pos);
    pos += 8;
    let header = bytes[pos..pos + header_len].to_vec();
    pos += header_len;
    let payload_len = read_len(bytes, pos);
    pos += 8;
    let payload = bytes[pos..pos + payload_len].to_vec();
    SignedOp { header, payload }
}

/// Domain tag for [`sync_root_of`], so a convergence digest can never be confused
/// with an entry hash or an op frame.
const SYNC_ROOT_MAGIC: &[u8] = b"walkie.hhhs.sync-root/1";

/// The canonical convergence digest over an entry-hash identity set.
///
/// `hashes` MUST be in ascending order — every caller feeds it a `BTreeMap`/
/// `BTreeSet` iterator, which is. The digest is over the identity set alone, so
/// two peers agree iff they hold exactly the same lifted entries, independent of
/// arrival order or anything parked.
///
/// One definition, used by both [`Store::sync_root`] and the sync layer's
/// snapshot, so the value a peer cross-checks on `Done` cannot drift from the
/// value the local store would compute.
pub fn sync_root_of<'a>(hashes: impl IntoIterator<Item = &'a EntryHash>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SYNC_ROOT_MAGIC);
    for hash in hashes {
        hasher.update(hash.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// The op contents kept alongside a lifted entry, so reads never re-verify a
/// signature or re-decode a payload. Generic over the [`OpLanguage`] `L` so `op`
/// carries the domain alphabet `L::Op`.
///
/// Public with accessors so an out-of-crate domain `fold` (which lives beside the
/// domain's `L::View`, not in this crate) can read the decoded op-set through
/// [`FoldCtx::decoded`].
pub struct DecodedOp<L: OpLanguage> {
    author: AuthorId,
    op: L::Op,
    /// Author-stamped time (display / last-resort tiebreak only; unused by the
    /// causal view but kept per the store contract).
    #[allow(dead_code)]
    ts_ms: u64,
    /// This op's per-author log position. The shared object fold resolves cross-
    /// author, so seqs (incomparable across authors) no longer decide anything;
    /// retained as part of the decoded record.
    #[allow(dead_code)]
    seq: u64,
}

impl<L: OpLanguage> DecodedOp<L> {
    /// Assemble a decoded record. `pub(crate)` so [`crate::windowed::WindowedStore`]
    /// populates its own retained-op map with the identical record shape
    /// [`Store::try_lift`] builds — the fold cannot tell the two stores apart
    /// (windowed-store-design.md §2.2: "the fold code does not change; it iterates a
    /// decoded map that happens to be residue ∪ window").
    pub(crate) fn new(author: AuthorId, op: L::Op, ts_ms: u64, seq: u64) -> Self {
        Self {
            author,
            op,
            ts_ms,
            seq,
        }
    }

    /// The verified author of this op.
    pub fn author(&self) -> AuthorId {
        self.author
    }
    /// The decoded domain op.
    pub fn op(&self) -> &L::Op {
        &self.op
    }
}

/// The causal-DAG mirror of a room's signed op log plus everything reads need,
/// generic over the domain [`OpLanguage`] `L`. Every field is `L`-threaded but
/// otherwise identical to the pre-extraction store, so the lifted entry hashes
/// and the projected view are byte-for-byte unchanged.
pub struct Store<L: OpLanguage> {
    /// The opaque-payload causal DAG. Identity ([`EntryHash`]) is fixed here.
    dag: MemDagStore,
    /// p2panda op id -> the entry that lifts it. The resolution table for prevs.
    source_to_entry: BTreeMap<OpId, EntryHash>,
    /// entry -> p2panda op id (inverse of `source_to_entry`).
    entry_to_source: BTreeMap<EntryHash, OpId>,
    /// entry -> decoded op contents (author, payload, ts, seq).
    decoded: BTreeMap<EntryHash, DecodedOp<L>>,
    /// Per-author log head, so the local author can chain new commits.
    heads: BTreeMap<AuthorId, LogHead>,
    /// Ops whose `backlink`/`observed` are not all lifted yet — parked until
    /// their full causal past arrives (strict deferral), then drained.
    pending: Vec<VerifiedOpG<L>>,
}

/// Hand-written so `Store<L>` is `Default` without a spurious `L: Default` bound
/// (the marker `L` never impls `Default`); every field defaults independently.
impl<L: OpLanguage> Default for Store<L> {
    fn default() -> Self {
        Self {
            dag: MemDagStore::default(),
            source_to_entry: BTreeMap::new(),
            entry_to_source: BTreeMap::new(),
            decoded: BTreeMap::new(),
            heads: BTreeMap::new(),
            pending: Vec::new(),
        }
    }
}

impl<L: OpLanguage> Store<L> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of lifted (materialized) ops.
    pub fn len(&self) -> usize {
        self.source_to_entry.len()
    }

    pub fn is_empty(&self) -> bool {
        self.source_to_entry.is_empty()
    }

    /// The entry hashes of every lifted (materialized) op. The RBSR anti-entropy
    /// index is built from exactly this set, and it is the cross-peer identity set
    /// convergence is asserted over. Permanent public API: the sync layer needs it.
    pub fn entry_hashes(&self) -> BTreeSet<EntryHash> {
        self.entry_to_source.keys().copied().collect()
    }

    /// The number of ops parked awaiting their causal past (strict deferral). Zero
    /// after quiescence is the liveness invariant: nothing is stuck behind a
    /// predecessor that already arrived. Permanent public API.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Whether an operation is already lifted or is waiting on causal
    /// predecessors. Persistence and repair use this to avoid journal growth from
    /// duplicate gossip frames.
    pub fn knows_op(&self, id: OpId) -> bool {
        self.source_to_entry.contains_key(&id)
            || self.pending.iter().any(|pending| pending.id() == id)
    }

    /// The entry hash lifting op `id`, if that op is already materialized.
    ///
    /// `None` for parked and unknown ops alike — a parked op cannot resolve its
    /// `prevs` yet, so it has no entry hash to report.
    pub fn lifted_entry(&self, id: OpId) -> Option<EntryHash> {
        self.source_to_entry.get(&id).copied()
    }

    /// The verbatim signed bytes of every lifted op, keyed by the entry hash that
    /// lifts it. Recovered losslessly from the DAG payloads, so it is exactly the
    /// bytes each author signed — what an anti-entropy transfer re-ingests on the
    /// far side. Permanent public API for the sync/reconcile layer.
    pub fn signed_ops(&self) -> BTreeMap<EntryHash, SignedOp> {
        self.dag
            .entries_topo()
            .into_iter()
            .map(|entry| (entry.hash(), unframe_signed::<L>(&entry.payload)))
            .collect()
    }

    /// A convergence digest over this store's entry-hash identity set.
    ///
    /// Carried on `Done` so the two halves cross-check that they actually agree.
    /// [`Store::ops_root`](Store::ops_root) (feature `merkle`) is a strictly
    /// stronger digest over the *same* entry-hash set, so `sync_root` is
    /// superseded for proofs but retained as the value the RBSR session
    /// cross-checks on `Done`.
    pub fn sync_root(&self) -> [u8; 32] {
        sync_root_of(self.entry_to_source.keys())
    }

    /// Signed bytes plus causal predecessors for ONE lifted entry.
    ///
    /// Exists so the sync layer can fold newly-lifted entries into its
    /// `(EntrySource, Index)` pair in O(lifted) instead of rebuilding the whole
    /// snapshot.
    pub fn repair_record(&self, hash: &EntryHash) -> Option<(SignedOp, Vec<EntryHash>)> {
        let entry = self.dag.entry(hash)?;
        Some((
            unframe_signed::<L>(&entry.payload),
            entry.header.prevs.0.iter().copied().collect(),
        ))
    }

    /// Signed bytes plus causal-entry predecessors for a transport-neutral repair
    /// snapshot.
    pub fn repair_records(&self) -> BTreeMap<EntryHash, (SignedOp, Vec<EntryHash>)> {
        self.dag
            .entries_topo()
            .into_iter()
            .map(|entry| {
                (
                    entry.hash(),
                    (
                        unframe_signed::<L>(&entry.payload),
                        entry.header.prevs.0.iter().copied().collect(),
                    ),
                )
            })
            .collect()
    }

    /// Which p2panda op id each lifted entry hash lifts. The RBSR index advertises
    /// entry hashes; this resolves an advertised hash back to its op id (and
    /// thence its causal predecessors) without re-verifying. Permanent public API
    /// for the sync/reconcile layer.
    pub fn lifted_op_ids(&self) -> BTreeMap<EntryHash, OpId> {
        self.entry_to_source.clone()
    }

    /// Lift a verified op into the DAG. Deduplicates, advances the author's head,
    /// and — via strict deferral — parks the op if any referenced op id is not yet
    /// lifted, draining the pending set after every successful lift.
    ///
    /// Returns the entries this call newly LIFTED: the op itself if its causal past
    /// was complete, plus everything it unblocked. An empty return means the op
    /// parked. Callers must not treat "accepted" as "materialized" — a parked op is
    /// not in [`Store::entry_hashes`], is not advertised to peers, and cannot be
    /// served, so counting it as ingested overstates progress.
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
        self.drain_pending()
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

    /// Resolve an op's `prevs` = `{ lift(backlink) } ∪ { lift(o) : o in observed }`.
    /// Returns `None` (defer) if ANY referenced op id is not yet lifted — never
    /// omit a prev, or the entry hash would depend on arrival order.
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

    /// Try to lift one op. Returns the lifted entry hash iff it was appended (or
    /// already present); `None` (with no mutation) if its causal past is
    /// incomplete.
    fn try_lift(&mut self, op: &VerifiedOpG<L>) -> Option<EntryHash> {
        let prevs = self.resolve_prevs(op)?;
        let entry = Entry::new(frame_signed::<L>(&op.signed()), Position(prevs));
        let entry_hash = entry.hash();
        match self.dag.append(&entry) {
            AppendOutcome::Appended | AppendOutcome::Duplicate => {}
            // Unreachable: every prev was resolved from `source_to_entry`, so it is
            // present in the DAG, and the payload hashes to its own digest.
            other => {
                debug_assert!(false, "unexpected append outcome: {other:?}");
                return None;
            }
        }
        let id = op.id();
        self.source_to_entry.insert(id, entry_hash);
        self.entry_to_source.insert(entry_hash, id);
        self.decoded.insert(
            entry_hash,
            DecodedOp {
                author: op.author(),
                op: op.payload().clone(),
                ts_ms: op.timestamp_ms(),
                seq: op.seq_num(),
            },
        );
        Some(entry_hash)
    }

    /// Repeatedly attempt to lift parked ops until a full pass makes no progress,
    /// returning every entry lifted along the way.
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

    /// The op ids of the current DAG frontier — the causal horizon a new local op
    /// should stamp into its `observed`. Deterministic (ascending entry-hash order).
    pub fn observed_frontier(&self) -> Vec<[u8; 32]> {
        self.dag
            .frontier()
            .0
            .iter()
            .filter_map(|entry| self.entry_to_source.get(entry).map(|id| id.0))
            .collect()
    }

    /// Author and sign a local op without mutating the in-memory projection.
    ///
    /// Durable runtimes use this two-phase surface to fsync the signed bytes
    /// before ingestion, so a storage failure cannot leave a visible but
    /// unrecoverable operation.
    pub fn prepare_commit(
        &self,
        key: &SigningKey,
        topic: &str,
        ts_micros: u64,
        op: L::Op,
    ) -> SignedOp {
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

    /// Author, sign, verify, and ingest a new local op, returning the signed bytes
    /// for gossip. In-memory/test callers use this convenience wrapper; durable
    /// runtimes should call [`Store::prepare_commit`], persist, then ingest.
    pub fn commit(
        &mut self,
        key: &SigningKey,
        topic: &str,
        ts_micros: u64,
        op: L::Op,
    ) -> SignedOp {
        let signed = self.prepare_commit(key, topic, ts_micros, op);
        let verified = verify_signed_op_in::<L>(&signed).expect("a just-signed op verifies");
        self.ingest_verified(verified);
        signed
    }

    /// Materialize the read model from the current DAG: [`OpLanguage::fold`] over
    /// the causal indexes packaged into a [`FoldCtx`].
    ///
    /// The ancestry backend is the cheap lazy [`LazyReach`] (O(N + E) `prevs`
    /// adjacency, reverse-walk `is_ancestor`, memoized per call) — never the
    /// whole-DAG kernel `ReachIndex` ancestor closure.
    pub fn view(&self) -> L::View {
        L::fold(&FoldCtx::new(self))
    }

    /// The reference projection: the identical [`OpLanguage::fold`], but driven by
    /// the kernel `ReachIndex` and `hhhs::register::resolve` instead of the cheap
    /// [`LazyReach`]. Provided (feature `test-support`) as the oracle a downstream
    /// crate's equivalence tests assert `view()` equals — so any drift in the cheap
    /// backend is caught directly against the kernel it replaced. Only the [`Reach`]
    /// backend behind the [`FoldCtx`] differs.
    #[cfg(any(test, feature = "test-support"))]
    pub fn view_reference(&self) -> L::View {
        let snapshot = self.dag.snapshot();
        L::fold(&FoldCtx::with_reach(
            self,
            Box::new(ReachIndex::new(&snapshot)),
        ))
    }

    /// The underlying causal DAG, read-only. Exposed (feature `test-support`) so a
    /// downstream crate's equivalence tests can build both a [`LazyReach`] and a
    /// kernel `ReachIndex` over the same store and assert they agree.
    #[cfg(any(test, feature = "test-support"))]
    pub fn dag(&self) -> &MemDagStore {
        &self.dag
    }
}

/// Generic Merkle commitments over the entry-hash identity set (feature `merkle`).
///
/// `ops_root`/`prove_op` commit to the entry-hash set alone — already domain-
/// agnostic, so they live here on `Store<L>`. The domain `state_root` is NOT
/// here: it folds `L::View` and needs an `L::View: Canonical` bound that is not
/// wired yet, so it stays walkie-facing until then (tutti extraction Track-D:
/// deferred with the canonical-view work).
#[cfg(feature = "merkle")]
impl<L: OpLanguage> Store<L> {
    /// The additive `ops_root`: a canonical blake3-256 Merkle commitment to this
    /// store's entry-hash identity set, computed over exactly the same
    /// `entry_to_source.keys()` iterator [`Store::sync_root`] digests (so the two
    /// can never skew). Strictly stronger than `sync_root`: root equality iff
    /// entry-set equality, PLUS the proofs [`Store::prove_op`] emits.
    pub fn ops_root(&self) -> [u8; 32] {
        crate::merkle::ops_root_of(self.entry_to_source.keys())
    }

    /// An inclusion (op present) or non-inclusion (op absent) proof for `entry`
    /// against [`Store::ops_root`]. Verify standalone — no store, no crate state —
    /// with [`radix_immutable::verify`]: `Some(&[])` demands inclusion (the `()`
    /// leaf value is empty bytes), `None` demands non-inclusion.
    pub fn prove_op(&self, entry: &EntryHash) -> radix_immutable::Proof {
        crate::merkle::prove_op(self.entry_to_source.keys(), entry)
    }
}

/// The read-only causal indexes a domain [`OpLanguage::fold`] consumes: the
/// decoded op set, the entry↔op-id map, and a causal-ancestry backend behind the
/// floor [`Reach`] contract. A domain `fold` is one ordinary function over these,
/// with no framework and no facet DSL (staging is just Rust control flow).
///
/// The backend is erased behind `dyn Reach` so the SAME `fold` runs on either
/// ancestry backend: the cheap lazy [`LazyReach`] in production ([`FoldCtx::new`])
/// and the kernel `ReachIndex` in the reference projection
/// ([`Store::view_reference`]). The decoded op-set and the entry→op map are read
/// through [`FoldCtx::decoded`] / [`FoldCtx::op_id`]; the ancestry surface is
/// [`FoldCtx::is_ancestor`] / [`FoldCtx::resolve`].
pub struct FoldCtx<'a, L: OpLanguage> {
    decoded: &'a BTreeMap<EntryHash, DecodedOp<L>>,
    entry_to_source: &'a BTreeMap<EntryHash, OpId>,
    reach: Box<dyn Reach + 'a>,
}

impl<'a, L: OpLanguage> FoldCtx<'a, L> {
    /// The production fold context over `store`: the cheap lazy [`LazyReach`]
    /// ancestry backend (O(N + E), memoized per call). This is what [`Store::view`]
    /// builds.
    pub fn new(store: &'a Store<L>) -> Self {
        Self::with_reach(store, Box::new(LazyReach::new(&store.dag)))
    }

    /// A fold context over `store` with an explicit ancestry backend. Used by the
    /// reference projection to drive the SAME fold with the kernel `ReachIndex`
    /// instead of the cheap [`LazyReach`].
    fn with_reach(store: &'a Store<L>, reach: Box<dyn Reach + 'a>) -> Self {
        Self {
            decoded: &store.decoded,
            entry_to_source: &store.entry_to_source,
            reach,
        }
    }

    /// A fold context assembled directly from its parts — the decoded op-set, the
    /// entry→op-id map, and an ancestry backend — rather than from a [`Store`]
    /// (windowed-store-design.md §6.2 delta 1: "`FoldCtx` construction is hardwired
    /// to `&Store<L>`; wanted: a public constructor over the parts").
    ///
    /// This is what lets a SECOND store type drive the byte-identical `L::fold`: the
    /// leaf-profile [`crate::windowed::WindowedStore`] folds its retained-op map
    /// through this constructor with the boundary-aware [`WindowedReach`] backend, so
    /// windowed-vs-full equivalence is *structural* — the same fold code, only the
    /// [`Reach`] backend differs (§3.5). Additive: [`FoldCtx::new`] and
    /// [`Store::view`] are unchanged.
    ///
    /// The caller owns the fence: `L::fold` reads `is_ancestor` present-only over
    /// whatever `reach` answers, so passing a reach that cannot see a decoded op's
    /// full causal past yields a silently wrong view. [`Store::view`] pairs `decoded`
    /// with a whole-history [`LazyReach`]; [`crate::windowed::WindowedStore::view`]
    /// pairs its window with a window-complete [`WindowedReach`] and refuses to fold a
    /// truncated window (§1.3's foot-gun, §6.2 delta 6).
    pub fn over(
        decoded: &'a BTreeMap<EntryHash, DecodedOp<L>>,
        entry_to_source: &'a BTreeMap<EntryHash, OpId>,
        reach: Box<dyn Reach + 'a>,
    ) -> Self {
        Self {
            decoded,
            entry_to_source,
            reach,
        }
    }

    /// The decoded op-set, keyed by lifting entry hash. A domain `fold` iterates
    /// and indexes this to read each op's [`DecodedOp::op`] and
    /// [`DecodedOp::author`].
    pub fn decoded(&self) -> &BTreeMap<EntryHash, DecodedOp<L>> {
        self.decoded
    }

    /// The p2panda [`OpId`] the entry `entry` lifts. Used where a domain object's
    /// identity is its creating op's id.
    pub fn op_id(&self, entry: &EntryHash) -> OpId {
        self.entry_to_source[entry]
    }

    /// Strict causal ancestry — the ONE reachability question the fold asks:
    /// `true` iff `a` is strictly in the causal past of `b`. Content-keyed add-wins
    /// and observed-remove folds are built on exactly this.
    pub fn is_ancestor(&self, a: &EntryHash, b: &EntryHash) -> bool {
        self.reach.is_ancestor(a, b)
    }

    /// The causal-maxima register winner over `candidates` (drop strict ancestors,
    /// break remaining maxima by max raw-bytes [`EntryHash`]); see
    /// [`Reach::resolve`]. `None` iff `candidates` is empty.
    pub fn resolve(&self, candidates: &BTreeSet<EntryHash>) -> Option<EntryHash> {
        self.reach.resolve(candidates)
    }
}

#[cfg(test)]
mod smoke {
    //! A minimal generic smoke test — NOT the walkie oracle (which stays in
    //! walkie, testing `WalkieLang`). A trivial two-op language exercises the
    //! lift/commit/view path and the `LazyReach` ≡ `ReachIndex` equivalence the
    //! substrate rests on, with no domain in sight.
    use super::*;
    use crate::ops::{OpLanguage, signing_key_from_seed};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
    enum TinyOp {
        Set(u32),
        Clear(u32),
    }

    struct Tiny;
    impl OpLanguage for Tiny {
        type Op = TinyOp;
        type View = BTreeSet<u32>;
        const SCHEMA_VERSION: u16 = 1;
        const ENTRY_FRAME_MAGIC: &'static [u8] = b"tutti.tiny/1";
        const WIRE_MAGIC: &'static [u8] = b"tutti.tiny.wire/1\0";
        const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
        fn validate_wire(_op: &TinyOp) -> Result<(), String> {
            Ok(())
        }
        fn fold(ctx: &FoldCtx<'_, Self>) -> BTreeSet<u32> {
            // Content-keyed add-wins: a Set(k) is live iff no Clear(k) observed it.
            let mut sets: BTreeMap<u32, Vec<EntryHash>> = BTreeMap::new();
            let mut clears: BTreeMap<u32, Vec<EntryHash>> = BTreeMap::new();
            for (entry, d) in ctx.decoded() {
                match d.op() {
                    TinyOp::Set(k) => sets.entry(*k).or_default().push(*entry),
                    TinyOp::Clear(k) => clears.entry(*k).or_default().push(*entry),
                }
            }
            let mut live = BTreeSet::new();
            for (k, adds) in &sets {
                let rems = clears.get(k).map(Vec::as_slice).unwrap_or(&[]);
                if adds
                    .iter()
                    .any(|a| !rems.iter().any(|r| ctx.is_ancestor(a, r)))
                {
                    live.insert(*k);
                }
            }
            live
        }
    }

    #[test]
    fn commit_view_and_reference_agree() {
        let key = signing_key_from_seed(&[5u8; 32]);
        let mut store: Store<Tiny> = Store::new();
        store.commit(&key, "t", 1, TinyOp::Set(1));
        store.commit(&key, "t", 2, TinyOp::Set(2));
        store.commit(&key, "t", 3, TinyOp::Clear(1));
        assert_eq!(store.pending_len(), 0);
        assert_eq!(store.view(), BTreeSet::from([2]));
        // Cheap LazyReach view equals the kernel-ReachIndex reference.
        assert_eq!(store.view(), store.view_reference());

        // LazyReach ≡ ReachIndex for every pair.
        let reach = LazyReach::new(store.dag());
        let kernel = ReachIndex::new(&store.dag().snapshot());
        let hashes: Vec<EntryHash> = store.entry_hashes().into_iter().collect();
        for a in &hashes {
            for b in &hashes {
                assert_eq!(
                    Reach::is_ancestor(&reach, a, b),
                    ReachIndex::is_ancestor(&kernel, a, b),
                );
            }
        }
    }
}
