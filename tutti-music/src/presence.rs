//! Bounded realtime presence, deliberately separate from durable music history.
//!
//! A controller's held degrees are replaceable lease state. Multiple sources
//! converge by set union; releasing or expiring one source cannot silence a
//! degree still held by another. This module owns no clock, authentication,
//! transport, actor identity, or retry policy. Callers apply exact snapshots
//! and explicitly release a source when its lease expires.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::TunedDegree;
use crate::render::PitchSetDiff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresenceLimits {
    pub max_sources: usize,
    pub max_held_per_source: usize,
}

impl PresenceLimits {
    pub const fn new(max_sources: usize, max_held_per_source: usize) -> Self {
        Self {
            max_sources,
            max_held_per_source,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PresenceError {
    #[error("presence source limit reached ({0})")]
    SourceLimit(usize),
    #[error("one presence source exceeds its held-degree limit ({0})")]
    HeldLimit(usize),
    #[error("presence index is outside the fixed domain ({0})")]
    IndexLimit(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresenceApply {
    Stale,
    Applied(PitchSetDiff<TunedDegree>),
}

/// A fixed-capacity set of small non-negative indices.
///
/// This is the allocator-free representation used by embedded presence
/// backends. The protocol meaning of an index belongs to the caller (for
/// Tutti it is normally a degree in one explicitly agreed tuning). Operations
/// outside `WORDS * 64` fail instead of allocating, evicting, or truncating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedBitSet<const WORDS: usize> {
    words: [u64; WORDS],
}

impl<const WORDS: usize> Default for FixedBitSet<WORDS> {
    fn default() -> Self {
        Self { words: [0; WORDS] }
    }
}

impl<const WORDS: usize> FixedBitSet<WORDS> {
    pub const fn from_words(words: [u64; WORDS]) -> Self {
        Self { words }
    }

    pub const fn words(&self) -> &[u64; WORDS] {
        &self.words
    }

    pub const fn capacity() -> usize {
        WORDS * u64::BITS as usize
    }

    pub fn len(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    pub fn contains(&self, index: usize) -> bool {
        let Some(word) = self.words.get(index / u64::BITS as usize) else {
            return false;
        };
        word & (1_u64 << (index % u64::BITS as usize)) != 0
    }

    pub fn insert(&mut self, index: usize) -> Result<bool, PresenceError> {
        let capacity = Self::capacity();
        let Some(word) = self.words.get_mut(index / u64::BITS as usize) else {
            return Err(PresenceError::IndexLimit(capacity));
        };
        let mask = 1_u64 << (index % u64::BITS as usize);
        let changed = *word & mask == 0;
        *word |= mask;
        Ok(changed)
    }

    pub fn remove(&mut self, index: usize) -> bool {
        let Some(word) = self.words.get_mut(index / u64::BITS as usize) else {
            return false;
        };
        let mask = 1_u64 << (index % u64::BITS as usize);
        let changed = *word & mask != 0;
        *word &= !mask;
        changed
    }

    pub fn union_with(&mut self, other: &Self) {
        for (word, other_word) in self.words.iter_mut().zip(other.words) {
            *word |= other_word;
        }
    }

    pub fn difference(&self, other: &Self) -> Self {
        let mut result = Self::default();
        for ((result_word, word), other_word) in
            result.words.iter_mut().zip(self.words).zip(other.words)
        {
            *result_word = word & !other_word;
        }
        result
    }

    pub fn iter(&self) -> FixedBitSetIter<'_, WORDS> {
        FixedBitSetIter {
            set: self,
            next_index: 0,
        }
    }
}

pub struct FixedBitSetIter<'a, const WORDS: usize> {
    set: &'a FixedBitSet<WORDS>,
    next_index: usize,
}

impl<const WORDS: usize> Iterator for FixedBitSetIter<'_, WORDS> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_index < FixedBitSet::<WORDS>::capacity() {
            let index = self.next_index;
            self.next_index += 1;
            if self.set.contains(index) {
                return Some(index);
            }
        }
        None
    }
}

/// Allocator-free equivalent of [`PitchSetDiff`] for a fixed index domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedPresenceDiff<const WORDS: usize> {
    pub retracted: FixedBitSet<WORDS>,
    pub added: FixedBitSet<WORDS>,
}

impl<const WORDS: usize> FixedPresenceDiff<WORDS> {
    pub fn is_empty(&self) -> bool {
        self.retracted.is_empty() && self.added.is_empty()
    }

    fn between(before: &FixedBitSet<WORDS>, after: &FixedBitSet<WORDS>) -> Self {
        Self {
            retracted: before.difference(after),
            added: after.difference(before),
        }
    }
}

#[derive(Clone, Debug)]
struct FixedPresenceSlot<S, const WORDS: usize> {
    source: S,
    held: FixedBitSet<WORDS>,
}

/// Fixed-source, fixed-degree presence with no allocation after construction.
///
/// RAM usage is determined entirely by `SOURCES`, `WORDS`, and `S`. The union
/// is recomputed from the small source array on replacement; that bounded work
/// avoids a heap map and per-degree reference-count nodes.
#[derive(Clone, Debug)]
pub struct FixedPresenceSet<S, const SOURCES: usize, const WORDS: usize> {
    max_held_per_source: usize,
    slots: [Option<FixedPresenceSlot<S, WORDS>>; SOURCES],
    live: FixedBitSet<WORDS>,
}

impl<S: Eq, const SOURCES: usize, const WORDS: usize> FixedPresenceSet<S, SOURCES, WORDS> {
    pub fn new(max_held_per_source: usize) -> Result<Self, PresenceError> {
        if max_held_per_source > FixedBitSet::<WORDS>::capacity() {
            return Err(PresenceError::HeldLimit(FixedBitSet::<WORDS>::capacity()));
        }
        Ok(Self {
            max_held_per_source,
            slots: std::array::from_fn(|_| None),
            live: FixedBitSet::default(),
        })
    }

    pub fn source_count(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    pub fn live(&self) -> &FixedBitSet<WORDS> {
        &self.live
    }

    pub fn source(&self, source: &S) -> Option<&FixedBitSet<WORDS>> {
        self.slots
            .iter()
            .flatten()
            .find(|slot| slot.source == *source)
            .map(|slot| &slot.held)
    }

    pub fn replace(
        &mut self,
        source: S,
        held: FixedBitSet<WORDS>,
    ) -> Result<FixedPresenceDiff<WORDS>, PresenceError> {
        if held.len() > self.max_held_per_source {
            return Err(PresenceError::HeldLimit(self.max_held_per_source));
        }
        let existing = self
            .slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.source == source));
        if held.is_empty() {
            if let Some(index) = existing {
                self.slots[index] = None;
            } else {
                return Ok(FixedPresenceDiff::between(&self.live, &self.live));
            }
        } else if let Some(index) = existing {
            self.slots[index] = Some(FixedPresenceSlot { source, held });
        } else if let Some(index) = self.slots.iter().position(Option::is_none) {
            self.slots[index] = Some(FixedPresenceSlot { source, held });
        } else {
            return Err(PresenceError::SourceLimit(SOURCES));
        }

        let before = self.live;
        self.recompute_live();
        Ok(FixedPresenceDiff::between(&before, &self.live))
    }

    pub fn release(&mut self, source: &S) -> Result<FixedPresenceDiff<WORDS>, PresenceError> {
        self.replace_by_reference(source, FixedBitSet::default())
    }

    fn replace_by_reference(
        &mut self,
        source: &S,
        held: FixedBitSet<WORDS>,
    ) -> Result<FixedPresenceDiff<WORDS>, PresenceError> {
        if held.len() > self.max_held_per_source {
            return Err(PresenceError::HeldLimit(self.max_held_per_source));
        }
        let Some(index) = self
            .slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.source == *source))
        else {
            return Ok(FixedPresenceDiff::between(&self.live, &self.live));
        };
        if held.is_empty() {
            self.slots[index] = None;
        } else if let Some(slot) = self.slots[index].as_mut() {
            slot.held = held;
        }
        let before = self.live;
        self.recompute_live();
        Ok(FixedPresenceDiff::between(&before, &self.live))
    }

    pub fn clear(&mut self) -> FixedPresenceDiff<WORDS> {
        let before = self.live;
        self.slots.fill_with(|| None);
        self.live = FixedBitSet::default();
        FixedPresenceDiff::between(&before, &self.live)
    }

    fn recompute_live(&mut self) {
        self.live = FixedBitSet::default();
        for slot in self.slots.iter().flatten() {
            self.live.union_with(&slot.held);
        }
    }
}

#[derive(Clone, Debug)]
struct FixedRegisterSlot<S, const WORDS: usize> {
    source: S,
    revision: u64,
    held: FixedBitSet<WORDS>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedPresenceApply<const WORDS: usize> {
    Stale,
    Applied(FixedPresenceDiff<WORDS>),
}

/// Fixed-capacity monotonic exact-state registers for authenticated peers.
///
/// Expiry clears a peer's held bits but retains its revision fence. A new
/// authenticated session must call [`Self::reset_source`] before restarting a
/// peer's revision at zero.
#[derive(Clone, Debug)]
pub struct FixedPresenceRegisters<S, const SOURCES: usize, const WORDS: usize> {
    max_held_per_source: usize,
    slots: [Option<FixedRegisterSlot<S, WORDS>>; SOURCES],
    live: FixedBitSet<WORDS>,
}

impl<S: Eq, const SOURCES: usize, const WORDS: usize> FixedPresenceRegisters<S, SOURCES, WORDS> {
    pub fn new(max_held_per_source: usize) -> Result<Self, PresenceError> {
        if max_held_per_source > FixedBitSet::<WORDS>::capacity() {
            return Err(PresenceError::HeldLimit(FixedBitSet::<WORDS>::capacity()));
        }
        Ok(Self {
            max_held_per_source,
            slots: std::array::from_fn(|_| None),
            live: FixedBitSet::default(),
        })
    }

    pub fn live(&self) -> &FixedBitSet<WORDS> {
        &self.live
    }

    pub fn apply(
        &mut self,
        source: S,
        revision: u64,
        held: FixedBitSet<WORDS>,
    ) -> Result<FixedPresenceApply<WORDS>, PresenceError> {
        if held.len() > self.max_held_per_source {
            return Err(PresenceError::HeldLimit(self.max_held_per_source));
        }
        let existing = self
            .slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.source == source));
        if let Some(index) = existing {
            let slot = self.slots[index]
                .as_mut()
                .expect("the located register slot exists");
            if revision <= slot.revision {
                return Ok(FixedPresenceApply::Stale);
            }
            slot.revision = revision;
            slot.held = held;
        } else if let Some(index) = self.slots.iter().position(Option::is_none) {
            self.slots[index] = Some(FixedRegisterSlot {
                source,
                revision,
                held,
            });
        } else {
            return Err(PresenceError::SourceLimit(SOURCES));
        }

        let before = self.live;
        self.recompute_live();
        Ok(FixedPresenceApply::Applied(FixedPresenceDiff::between(
            &before, &self.live,
        )))
    }

    pub fn expire(&mut self, source: &S) -> FixedPresenceDiff<WORDS> {
        let before = self.live;
        if let Some(slot) = self
            .slots
            .iter_mut()
            .flatten()
            .find(|slot| slot.source == *source)
        {
            slot.held = FixedBitSet::default();
        }
        self.recompute_live();
        FixedPresenceDiff::between(&before, &self.live)
    }

    pub fn reset_source(&mut self, source: &S) -> FixedPresenceDiff<WORDS> {
        let before = self.live;
        if let Some(index) = self
            .slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.source == *source))
        {
            self.slots[index] = None;
        }
        self.recompute_live();
        FixedPresenceDiff::between(&before, &self.live)
    }

    fn recompute_live(&mut self) {
        self.live = FixedBitSet::default();
        for slot in self.slots.iter().flatten() {
            self.live.union_with(&slot.held);
        }
    }
}

/// Exact, bounded held-degree state for several independently leased sources.
///
/// `S` is deliberately caller-owned: a firmware may use local adapter IDs and
/// authenticated peer identities, while a browser host may use connection IDs.
#[derive(Clone, Debug)]
pub struct PresenceSet<S> {
    limits: PresenceLimits,
    sources: BTreeMap<S, BTreeSet<TunedDegree>>,
    holders: BTreeMap<TunedDegree, usize>,
    live: BTreeSet<TunedDegree>,
}

impl<S: Ord> PresenceSet<S> {
    pub fn new(limits: PresenceLimits) -> Self {
        Self {
            limits,
            sources: BTreeMap::new(),
            holders: BTreeMap::new(),
            live: BTreeSet::new(),
        }
    }

    pub fn limits(&self) -> PresenceLimits {
        self.limits
    }

    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    pub fn live(&self) -> &BTreeSet<TunedDegree> {
        &self.live
    }

    /// Replace one source from an exact heartbeat/snapshot.
    ///
    /// The returned diff is the change in the union across every source, not
    /// merely the source-local delta. It is therefore safe to render directly.
    pub fn replace(
        &mut self,
        source: S,
        held: BTreeSet<TunedDegree>,
    ) -> Result<PitchSetDiff<TunedDegree>, PresenceError> {
        if held.len() > self.limits.max_held_per_source {
            return Err(PresenceError::HeldLimit(self.limits.max_held_per_source));
        }
        let previous = self.sources.remove(&source).unwrap_or_default();
        if previous.is_empty() && !held.is_empty() && self.sources.len() == self.limits.max_sources
        {
            return Err(PresenceError::SourceLimit(self.limits.max_sources));
        }

        let mut diff = PitchSetDiff {
            retracted: BTreeSet::new(),
            added: BTreeSet::new(),
        };
        for degree in previous.difference(&held) {
            let count = self
                .holders
                .get_mut(degree)
                .expect("a source-held degree has a holder count");
            *count -= 1;
            if *count == 0 {
                self.holders.remove(degree);
                self.live.remove(degree);
                diff.retracted.insert(*degree);
            }
        }
        for degree in held.difference(&previous) {
            let count = self.holders.entry(*degree).or_default();
            if *count == 0 {
                self.live.insert(*degree);
                diff.added.insert(*degree);
            }
            *count += 1;
        }
        if !held.is_empty() {
            self.sources.insert(source, held);
        }
        Ok(diff)
    }

    pub fn release(&mut self, source: S) -> Result<PitchSetDiff<TunedDegree>, PresenceError> {
        self.replace(source, BTreeSet::new())
    }

    pub fn clear(&mut self) -> PitchSetDiff<TunedDegree> {
        self.sources.clear();
        self.holders.clear();
        PitchSetDiff {
            retracted: std::mem::take(&mut self.live),
            added: BTreeSet::new(),
        }
    }
}

/// Monotonic exact-state register per authenticated source.
///
/// Revisions are meaningful only inside the caller's source epoch (normally an
/// authenticated transport session). [`Self::reset_source`] starts a new epoch.
/// Expiry releases sound but deliberately retains the revision fence, so a
/// delayed old snapshot cannot resurrect a note after fail-safe cleanup.
#[derive(Clone, Debug)]
pub struct PresenceRegisters<S> {
    revisions: BTreeMap<S, u64>,
    presence: PresenceSet<S>,
}

impl<S: Ord + Clone> PresenceRegisters<S> {
    pub fn new(limits: PresenceLimits) -> Self {
        Self {
            revisions: BTreeMap::new(),
            presence: PresenceSet::new(limits),
        }
    }

    pub fn live(&self) -> &BTreeSet<TunedDegree> {
        self.presence.live()
    }

    pub fn apply(
        &mut self,
        source: S,
        revision: u64,
        held: BTreeSet<TunedDegree>,
    ) -> Result<PresenceApply, PresenceError> {
        if self
            .revisions
            .get(&source)
            .is_some_and(|current| revision <= *current)
        {
            return Ok(PresenceApply::Stale);
        }
        let diff = self.presence.replace(source.clone(), held)?;
        self.revisions.insert(source, revision);
        Ok(PresenceApply::Applied(diff))
    }

    pub fn expire(&mut self, source: S) -> Result<PitchSetDiff<TunedDegree>, PresenceError> {
        self.presence.release(source)
    }

    pub fn reset_source(&mut self, source: S) -> Result<PitchSetDiff<TunedDegree>, PresenceError> {
        self.revisions.remove(&source);
        self.presence.release(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Tuning;

    fn degree(index: u16) -> TunedDegree {
        TunedDegree::new(&Tuning::twelve_tet(), index).unwrap()
    }

    #[test]
    fn shared_degree_survives_one_source_release() {
        let mut presence = PresenceSet::new(PresenceLimits::new(2, 4));
        assert_eq!(
            presence
                .replace("web", BTreeSet::from([degree(7)]))
                .unwrap()
                .added,
            BTreeSet::from([degree(7)])
        );
        assert!(
            presence
                .replace("midi", BTreeSet::from([degree(7)]))
                .unwrap()
                .is_empty()
        );
        assert!(presence.release("web").unwrap().is_empty());
        assert_eq!(
            presence.release("midi").unwrap().retracted,
            BTreeSet::from([degree(7)])
        );
        assert!(presence.live().is_empty());
    }

    #[test]
    fn exact_replacement_emits_only_union_changes() {
        let mut presence = PresenceSet::new(PresenceLimits::new(2, 4));
        presence
            .replace("web", BTreeSet::from([degree(0), degree(4)]))
            .unwrap();
        let diff = presence
            .replace("web", BTreeSet::from([degree(4), degree(7)]))
            .unwrap();
        assert_eq!(diff.retracted, BTreeSet::from([degree(0)]));
        assert_eq!(diff.added, BTreeSet::from([degree(7)]));
    }

    #[test]
    fn source_and_held_bounds_are_enforced_without_partial_mutation() {
        let mut presence = PresenceSet::new(PresenceLimits::new(1, 1));
        presence.replace(1, BTreeSet::from([degree(0)])).unwrap();
        assert_eq!(
            presence.replace(2, BTreeSet::from([degree(4)])),
            Err(PresenceError::SourceLimit(1))
        );
        assert_eq!(
            presence.replace(1, BTreeSet::from([degree(0), degree(4)])),
            Err(PresenceError::HeldLimit(1))
        );
        assert_eq!(presence.live(), &BTreeSet::from([degree(0)]));
    }

    #[test]
    fn register_rejects_stale_snapshots_and_expiry_fences_resurrection() {
        let mut registers = PresenceRegisters::new(PresenceLimits::new(2, 4));
        assert!(matches!(
            registers
                .apply("peer", 8, BTreeSet::from([degree(4)]))
                .unwrap(),
            PresenceApply::Applied(_)
        ));
        assert_eq!(
            registers
                .apply("peer", 7, BTreeSet::from([degree(7)]))
                .unwrap(),
            PresenceApply::Stale
        );
        assert_eq!(
            registers.expire("peer").unwrap().retracted,
            BTreeSet::from([degree(4)])
        );
        assert_eq!(
            registers
                .apply("peer", 8, BTreeSet::from([degree(4)]))
                .unwrap(),
            PresenceApply::Stale
        );
        registers.reset_source("peer").unwrap();
        assert!(matches!(
            registers
                .apply("peer", 1, BTreeSet::from([degree(7)]))
                .unwrap(),
            PresenceApply::Applied(_)
        ));
    }

    fn bits<const WORDS: usize>(indices: &[usize]) -> FixedBitSet<WORDS> {
        let mut bits = FixedBitSet::default();
        for index in indices {
            bits.insert(*index).unwrap();
        }
        bits
    }

    #[test]
    fn fixed_bit_set_is_bounded_and_iterates_in_order() {
        let mut set = bits::<2>(&[0, 63, 64, 127]);
        assert_eq!(set.len(), 4);
        assert_eq!(set.iter().collect::<Vec<_>>(), vec![0, 63, 64, 127]);
        assert!(set.remove(64));
        assert!(!set.remove(64));
        assert_eq!(set.insert(128), Err(PresenceError::IndexLimit(128)));
    }

    #[test]
    fn fixed_presence_preserves_shared_degrees_without_allocating_nodes() {
        let mut presence = FixedPresenceSet::<u8, 2, 1>::new(4).unwrap();
        assert_eq!(presence.replace(1, bits(&[7])).unwrap().added, bits(&[7]));
        assert!(presence.replace(2, bits(&[7])).unwrap().is_empty());
        assert!(presence.release(&1).unwrap().is_empty());
        assert_eq!(presence.release(&2).unwrap().retracted, bits(&[7]));
        assert!(presence.live().is_empty());
    }

    #[test]
    fn fixed_presence_limits_are_transactional() {
        let mut presence = FixedPresenceSet::<u8, 1, 1>::new(1).unwrap();
        presence.replace(1, bits(&[4])).unwrap();
        assert_eq!(
            presence.replace(2, bits(&[7])),
            Err(PresenceError::SourceLimit(1))
        );
        assert_eq!(
            presence.replace(1, bits(&[4, 7])),
            Err(PresenceError::HeldLimit(1))
        );
        assert_eq!(presence.live(), &bits(&[4]));
    }

    #[test]
    fn fixed_register_expiry_retains_revision_fence() {
        let mut registers = FixedPresenceRegisters::<u8, 2, 1>::new(4).unwrap();
        assert!(matches!(
            registers.apply(3, 8, bits(&[4])).unwrap(),
            FixedPresenceApply::Applied(_)
        ));
        assert_eq!(registers.expire(&3).retracted, bits(&[4]));
        assert_eq!(
            registers.apply(3, 8, bits(&[4])).unwrap(),
            FixedPresenceApply::Stale
        );
        registers.reset_source(&3);
        assert!(matches!(
            registers.apply(3, 1, bits(&[7])).unwrap(),
            FixedPresenceApply::Applied(_)
        ));
    }

    #[test]
    fn fixed_backend_has_static_compact_storage() {
        // Two 128-bit source sets plus the cached union and small metadata.
        // This guards against accidentally replacing the slots with heap-backed
        // collections while allowing normal target-dependent alignment.
        assert!(std::mem::size_of::<FixedPresenceSet<u8, 2, 2>>() <= 96);
    }
}
