//! [`MusicLang`] — the canonical `OpLanguage` instantiation of the music
//! protocol, and [`MusicView`], its materialized read model.

use std::collections::{BTreeMap, BTreeSet};

use tutti_core::{AuthorId, EntryHash, FoldCtx, OpLanguage, causal_maxima};

use crate::facets::Envelope;
use crate::fold::{SetOp, add_wins_set, register, registers};
use crate::ops::{MusicOp, validate_wire};
use crate::tuning::{TunedDegree, TuningDefinition};

/// The materialized music read model: the live pitch-set, its holders, the
/// per-degree envelope registers, and the resolved room tuning.
///
/// Everything degree-keyed is scoped to the resolved tuning: switching tunings
/// hides other-tuning state, and switching back resurrects it — a property of
/// tuning-scoped keys, not extra bookkeeping.
///
/// **Facet persistence, stated honestly:** an envelope register is independent
/// of its degree's add-wins liveness. Removing a degree drops its sounding note
/// (it leaves `live`) but the register persists, so a re-add resumes under the
/// converged curve. A renderer only *applies* a facet while its degree is live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MusicView {
    /// The live pitch-set, folded add-wins (observed-remove).
    pub live: BTreeSet<TunedDegree>,
    /// For each live degree, the authors holding a live add of it.
    pub holders: BTreeMap<TunedDegree, BTreeSet<AuthorId>>,
    /// Per-degree envelope facets, each a causal-maxima register.
    pub envelopes: BTreeMap<TunedDegree, Envelope>,
    /// The resolved room tuning (register; built-in 12-TET when unset).
    pub tuning: TuningDefinition,
}

impl Default for MusicView {
    fn default() -> Self {
        Self {
            live: BTreeSet::new(),
            holders: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            tuning: TuningDefinition::twelve_tet(),
        }
    }
}

/// The canonical music `OpLanguage`. Its wire consts are its own — cross-domain
/// frame separation rejects any other domain's bytes at ingress.
pub struct MusicLang;

impl OpLanguage for MusicLang {
    type Op = MusicOp;
    type View = MusicView;

    /// Generation 2 of the music wire: degree identity moved from a bare index +
    /// compile-time EDO to tuning-scoped [`TunedDegree`] + the in-log
    /// [`MusicOp::SetTuning`] register — bumped once, while the protocol had
    /// zero deployed history.
    const SCHEMA_VERSION: u16 = 3;
    const ENTRY_FRAME_MAGIC: &'static [u8] = b"tutti.music.entry/2";
    const WIRE_MAGIC: &'static [u8] = b"tutti.music.wire/2\0";
    const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

    fn validate_wire(op: &MusicOp) -> Result<(), String> {
        validate_wire(op)
    }

    /// One deterministic fold through the shared combinators: the tuning
    /// register resolves first so the degree set and facet registers can scope
    /// themselves to it (the staged fold — facets are not independent, and the
    /// API admits it).
    fn fold(ctx: &FoldCtx<'_, Self>) -> MusicView {
        let tuning = register(ctx, |decoded| match decoded.op() {
            MusicOp::SetTuning { definition } => Some(definition.clone()),
            _ => None,
        })
        .unwrap_or_else(TuningDefinition::twelve_tet);

        // A register winner was wire-validated at ingress, so this is purely
        // defensive: an unusable tuning yields an empty view under it.
        let Ok(active) = tuning.validate("active room tuning") else {
            return MusicView {
                tuning,
                ..MusicView::default()
            };
        };

        let degrees = add_wins_set(ctx, |decoded| match decoded.op() {
            MusicOp::AddDegree { degree } if degree.validate(&active).is_ok() => {
                Some(SetOp::Add(*degree))
            }
            MusicOp::RemoveDegree { degree } if degree.validate(&active).is_ok() => {
                Some(SetOp::Remove(*degree))
            }
            _ => None,
        });

        let envelopes = registers(ctx, |decoded| match decoded.op() {
            MusicOp::SetEnvelope { degree, env } if degree.validate(&active).is_ok() => {
                Some((*degree, env.clone()))
            }
            _ => None,
        });

        MusicView {
            live: degrees.live,
            holders: degrees.holders,
            envelopes,
            tuning,
        }
    }

    /// Compaction retention — what a bounded leaf store must keep of a
    /// causally-closed cut so every admissible future fold is unchanged:
    ///
    /// * **removes**: the causal maxima per degree (a dominated remove's kill
    ///   set is contained in its dominator's, by transitivity — this covers
    ///   late-arriving adds too);
    /// * **adds**: the causal maxima per (degree, author) of the *surviving*
    ///   adds — killed adds are shadowed forever by the retained remove that
    ///   observed them, and a dominated surviving add can neither change
    ///   liveness nor holders while its dominator survives;
    /// * **registers** (per-degree envelopes, the room tuning): the causal
    ///   maxima per slot — a superseded write can never re-win.
    ///
    /// No tuning filter is applied here: a future `SetTuning` may re-scope the
    /// view, so retention is per tuning-scoped key, conservatively.
    fn retain(ctx: &FoldCtx<'_, Self>, cut: &BTreeSet<EntryHash>) -> BTreeSet<EntryHash> {
        let mut adds: BTreeMap<(TunedDegree, AuthorId), BTreeSet<EntryHash>> = BTreeMap::new();
        let mut removes: BTreeMap<TunedDegree, BTreeSet<EntryHash>> = BTreeMap::new();
        let mut env_writes: BTreeMap<TunedDegree, BTreeSet<EntryHash>> = BTreeMap::new();
        let mut tuning_writes: BTreeSet<EntryHash> = BTreeSet::new();
        for (entry, decoded) in ctx.decoded() {
            if !cut.contains(entry) {
                continue;
            }
            match decoded.op() {
                MusicOp::AddDegree { degree } => {
                    adds.entry((*degree, decoded.author()))
                        .or_default()
                        .insert(*entry);
                }
                MusicOp::RemoveDegree { degree } => {
                    removes.entry(*degree).or_default().insert(*entry);
                }
                MusicOp::SetEnvelope { degree, .. } => {
                    env_writes.entry(*degree).or_default().insert(*entry);
                }
                MusicOp::SetTuning { .. } => {
                    tuning_writes.insert(*entry);
                }
            }
        }

        let mut keep: BTreeSet<EntryHash> = BTreeSet::new();
        for key_removes in removes.values() {
            keep.extend(causal_maxima(ctx, key_removes));
        }
        for ((degree, _author), key_adds) in &adds {
            let key_removes = removes.get(degree);
            let surviving: BTreeSet<EntryHash> = key_adds
                .iter()
                .copied()
                .filter(|add| {
                    key_removes.is_none_or(|removes| {
                        !removes.iter().any(|remove| ctx.is_ancestor(add, remove))
                    })
                })
                .collect();
            keep.extend(causal_maxima(ctx, &surviving));
        }
        for key_writes in env_writes.values() {
            keep.extend(causal_maxima(ctx, key_writes));
        }
        keep.extend(causal_maxima(ctx, &tuning_writes));
        keep
    }
}
