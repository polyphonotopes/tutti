//! The render seam — what every target (AMY, MIDI, OSC, UI) consumes to turn
//! convergent state into events.
//!
//! Outbound events are **derived from state, never queued from events**: a
//! renderer holds the previous projection, diffs it against the current view,
//! and emits exactly the delta. Rollback needs no code — a reverted op
//! re-projects the view and the diff emits the corrective events.

use std::collections::BTreeSet;

use crate::tuning::{PeriodicPitch, Tuning};

/// The state diff a renderer turns into events.
///
/// **Ordering contract: retractions are emitted before additions** — the
/// offs-before-ons rule, so a voice freed by the transition is reused rather
/// than stomped, and no interleaving can leave a stuck note.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PitchSetDiff<T> {
    /// Members of `before` absent from `after` — retract (note-off) these first.
    pub retracted: BTreeSet<T>,
    /// Members of `after` absent from `before` — then assert (note-on) these.
    pub added: BTreeSet<T>,
}

impl<T: Ord + Clone> PitchSetDiff<T> {
    /// Diff two projections of the convergent view.
    pub fn between(before: &BTreeSet<T>, after: &BTreeSet<T>) -> Self {
        Self {
            retracted: before.difference(after).cloned().collect(),
            added: after.difference(before).cloned().collect(),
        }
    }

    /// True iff the transition emits nothing.
    pub fn is_empty(&self) -> bool {
        self.retracted.is_empty() && self.added.is_empty()
    }
}

/// The (possibly fractional) MIDI note number `pitch` resolves to under
/// `tuning` (69.0 = A440) — the microtonal currency of every render target:
/// targets that take float notes render it exactly; 7-bit targets split it into
/// note + pitch-bend.
pub fn fractional_midi(tuning: &Tuning, pitch: PeriodicPitch) -> f64 {
    let hz = tuning.hz_for_periodic_pitch(pitch);
    69.0 + 12.0 * (hz / 440.0).log2()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tuning::ScaleDegree;

    #[test]
    fn diff_emits_only_the_delta() {
        let before: BTreeSet<u16> = BTreeSet::from([0, 7]);
        let after: BTreeSet<u16> = BTreeSet::from([0, 4]);
        let diff = PitchSetDiff::between(&before, &after);
        assert_eq!(diff.retracted, BTreeSet::from([7]));
        assert_eq!(diff.added, BTreeSet::from([4]));
        assert!(PitchSetDiff::between(&after, &after).is_empty());
    }

    #[test]
    fn fractional_midi_matches_twelve_tet_anchors() {
        let tuning = Tuning::twelve_tet();
        let degree = |index: u16, period: i32| {
            PeriodicPitch::from_degree(ScaleDegree::new(index, 12).unwrap(), period)
        };
        assert!((fractional_midi(&tuning, degree(9, 0)) - 69.0).abs() < 1e-9);
        assert!((fractional_midi(&tuning, degree(0, 0)) - 60.0).abs() < 1e-9);
        assert!((fractional_midi(&tuning, degree(0, 1)) - 72.0).abs() < 1e-9);
    }

    #[test]
    fn fractional_midi_is_fractional_off_twelve_tet() {
        // One step of 31-EDO above the reference — 60 + 12/31 ≈ 60.387.
        let scl: String = std::iter::once("31-EDO\n31\n".to_string())
            .chain((1..=31).map(|i| format!("{:.6}\n", f64::from(i) * 1200.0 / 31.0)))
            .collect();
        let tuning = Tuning::from_scl_text(
            "31-EDO",
            &scl,
            Some("0\n0\n127\n60\n60\n261.6255653005986\n0\n"),
        )
        .unwrap();
        let pitch = PeriodicPitch::from_degree(ScaleDegree::new(1, 31).unwrap(), 0);
        assert!((fractional_midi(&tuning, pitch) - (60.0 + 12.0 / 31.0)).abs() < 1e-6);
    }
}
