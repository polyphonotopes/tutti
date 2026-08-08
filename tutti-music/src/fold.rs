//! The music fold combinators — plain functions over the substrate's `FoldCtx`,
//! shared by every dialect of the protocol.
//!
//! [`MusicLang`](crate::MusicLang) folds through exactly these, and so can a
//! superset dialect that keeps its own wire (walkie's `WalkieLang` expresses its
//! degree and register stages through them) — one semantics, however many wires.
//! Each combinator reads ancestry only through the erased `FoldCtx`
//! (`is_ancestor`/`resolve`), so full-store, reference-oracle, and windowed
//! projections all agree by construction.

use std::collections::{BTreeMap, BTreeSet};

use tutti_core::{AuthorId, DecodedOp, EntryHash, FoldCtx, OpLanguage};

/// How one op acts on an add-wins set keyed by `K` — the classification a
/// domain's [`add_wins_set`] closure returns for its set-shaped ops.
pub enum SetOp<K> {
    /// Assert the key into the set.
    Add(K),
    /// Retract the key: cancels only the adds this op causally observed.
    Remove(K),
}

/// The output of [`add_wins_set`]: the live keys and, for each, the authors that
/// hold a live add of it (authorship-as-channel — attribution is protocol).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddWins<K> {
    /// Keys with at least one add not causally observed by any same-key remove.
    pub live: BTreeSet<K>,
    /// For each live key, the authors of its surviving adds.
    pub holders: BTreeMap<K, BTreeSet<AuthorId>>,
}

impl<K> Default for AddWins<K> {
    fn default() -> Self {
        Self {
            live: BTreeSet::new(),
            holders: BTreeMap::new(),
        }
    }
}

/// Fold an **add-wins observed-remove set** with per-key author attribution.
///
/// `classify` names which ops act on the set (returning `None` for the rest —
/// including ops the domain filters out, e.g. keys invalid under the resolved
/// tuning). A key is live iff SOME add of it is not causally observed
/// (`is_ancestor`) by ANY remove of it: a remove cancels only the adds in its
/// causal past, so a concurrent add survives.
pub fn add_wins_set<L: OpLanguage, K: Ord + Copy>(
    ctx: &FoldCtx<'_, L>,
    classify: impl Fn(&DecodedOp<L>) -> Option<SetOp<K>>,
) -> AddWins<K> {
    let mut adds: BTreeMap<K, Vec<EntryHash>> = BTreeMap::new();
    let mut removes: BTreeMap<K, Vec<EntryHash>> = BTreeMap::new();
    for (entry, decoded) in ctx.decoded() {
        match classify(decoded) {
            Some(SetOp::Add(key)) => adds.entry(key).or_default().push(*entry),
            Some(SetOp::Remove(key)) => removes.entry(key).or_default().push(*entry),
            None => {}
        }
    }

    let mut out = AddWins::default();
    for (key, add_entries) in &adds {
        let key_removes = removes.get(key).map(Vec::as_slice).unwrap_or(&[]);
        let mut authors: BTreeSet<AuthorId> = BTreeSet::new();
        for add in add_entries {
            let killed = key_removes
                .iter()
                .any(|remove| ctx.is_ancestor(add, remove));
            if !killed {
                authors.insert(ctx.decoded()[add].author());
            }
        }
        if !authors.is_empty() {
            out.live.insert(*key);
            out.holders.insert(*key, authors);
        }
    }
    out
}

/// Fold **one causal-maxima register**: the candidates are the ops `read`
/// accepts, and the result is the winning write's value — causal precedence
/// where comparable, then the substrate's max raw-bytes entry-hash tiebreak
/// among concurrent maxima. `None` iff no op wrote the register.
pub fn register<L: OpLanguage, T>(
    ctx: &FoldCtx<'_, L>,
    read: impl Fn(&DecodedOp<L>) -> Option<T>,
) -> Option<T> {
    let mut writes: BTreeMap<EntryHash, T> = BTreeMap::new();
    for (entry, decoded) in ctx.decoded() {
        if let Some(value) = read(decoded) {
            writes.insert(*entry, value);
        }
    }
    let candidates: BTreeSet<EntryHash> = writes.keys().copied().collect();
    ctx.resolve(&candidates)
        .and_then(|winner| writes.remove(&winner))
}

/// Fold **one register per key** (the facet shape): `read` names which ops write
/// which key, and each key resolves to its own causal-maxima winner
/// independently — disjoint keys merge, contested keys pick one write.
pub fn registers<L: OpLanguage, K: Ord, T>(
    ctx: &FoldCtx<'_, L>,
    read: impl Fn(&DecodedOp<L>) -> Option<(K, T)>,
) -> BTreeMap<K, T> {
    let mut writes: BTreeMap<K, BTreeMap<EntryHash, T>> = BTreeMap::new();
    for (entry, decoded) in ctx.decoded() {
        if let Some((key, value)) = read(decoded) {
            writes.entry(key).or_default().insert(*entry, value);
        }
    }
    writes
        .into_iter()
        .filter_map(|(key, mut key_writes)| {
            let candidates: BTreeSet<EntryHash> = key_writes.keys().copied().collect();
            ctx.resolve(&candidates)
                .and_then(|winner| key_writes.remove(&winner))
                .map(|value| (key, value))
        })
        .collect()
}
