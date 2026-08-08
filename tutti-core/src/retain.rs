//! M3.1 retention combinators — the shadowing-lemma primitives a domain composes
//! into its [`OpLanguage::retain`](crate::OpLanguage::retain), beside the way it
//! composes its fold (`docs/vision/windowed-store-design.md` §2.5, §6.2 delta 3).
//!
//! Every combinator here is a pure function of a [`FoldCtx`]'s ancestry surface
//! (`is_ancestor` / `resolve`), so a domain's retention reasons over the *same*
//! causal oracle its fold reads — and the same boundary-aware oracle the compacted
//! [`WindowedStore`](crate::WindowedStore) drives at a cut. They compute *candidate
//! residues*, never verdicts: the discarded ops are the ones each shadowing lemma
//! proves the fold evaluates identically without (§2.6).
//!
//! What is NOT here: the non-monotone piece / resurrection residue (P/M) and the
//! sub-horizon lock register (R′). Those are conservatively **retained wholesale**
//! by a domain — the design's honest bound (§2.5-P, §8.7): "when in doubt, retain."

use std::collections::BTreeSet;

use hhhs_dag::EntryHash;

use crate::ops::OpLanguage;
use crate::store::FoldCtx;

/// The **causal maxima** of `candidates`: the members with no *other* candidate as a
/// strict causal descendant — an antichain, the currently-winning ops
/// (`docs/vision/windowed-store-design.md` §2.5, the shared kernel of Lemma R and
/// Lemma A3). This is the register-supersession primitive (per slot) and the
/// survivor-dominance primitive (per key-per-author) both.
///
/// *Why maxima retention is sound (Lemma R / A3, sketch).* If `d < m` (strict
/// ancestor) and `m` is retained, `d` can never re-win: `resolve`'s rule 1 drops any
/// candidate that is a strict ancestor of another (store.rs), the op log is
/// grow-only so `m` never leaves, and the maxima of the full set equal the maxima of
/// the retained set — so every future `resolve` sees the identical winner and the
/// identical raw-byte tiebreak among concurrent maxima. Discarding the non-maxima is
/// therefore invisible to every admissible future fold.
pub fn causal_maxima<L: OpLanguage>(
    ctx: &FoldCtx<'_, L>,
    candidates: &BTreeSet<EntryHash>,
) -> BTreeSet<EntryHash> {
    candidates
        .iter()
        .copied()
        .filter(|m| {
            !candidates
                .iter()
                .any(|other| other != m && ctx.is_ancestor(m, other))
        })
        .collect()
}
