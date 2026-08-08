//! Inbound MIDI: physical notes → source-balanced, tuning-scoped degree intent.
//!
//! Events fold into state — the tracker never mutates a view; the app commits
//! ops (or refreshes presence leases) from the actions it returns, and the
//! outbound side then re-projects. Local hardware input and remote peers
//! converge through the identical path.

use std::collections::{BTreeMap, BTreeSet};

use tutti_music::tuning::{TunedDegree, TunedPeriodicPitch, Tuning};

/// Physical note identity retained from note-on until its matching note-off.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysicalMidiKey {
    pub port_id: String,
    pub channel: u8,
    pub note: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldInputAction {
    DegreeActivated(TunedDegree),
    DegreeReleased(TunedDegree),
}

/// Turns a physical MIDI input stream into source-balanced tuning-scoped
/// degrees. The note-on mapping is retained until note-off, so a room tuning
/// change cannot reinterpret a held key midway through its lifetime.
#[derive(Debug, Default)]
pub struct MidiInputTracker {
    held: BTreeMap<PhysicalMidiKey, TunedPeriodicPitch>,
    degree_refcounts: BTreeMap<TunedDegree, usize>,
}

impl MidiInputTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    pub fn note_on(&mut self, key: PhysicalMidiKey, tuning: &Tuning) -> Vec<HeldInputAction> {
        if self.held.contains_key(&key) {
            return Vec::new();
        }
        let hz = midi_note_frequency_hz(key.note);
        let Ok(quantized) = tuning.quantize(hz) else {
            return Vec::new();
        };
        let pitch = TunedPeriodicPitch {
            tuning_id: tuning.id(),
            pitch: quantized.periodic_pitch,
        };
        self.held.insert(key, pitch);
        let count = self.degree_refcounts.entry(pitch.degree()).or_default();
        *count += 1;
        if *count == 1 {
            vec![HeldInputAction::DegreeActivated(pitch.degree())]
        } else {
            Vec::new()
        }
    }

    pub fn note_off(&mut self, key: &PhysicalMidiKey) -> Vec<HeldInputAction> {
        let Some(pitch) = self.held.remove(key) else {
            return Vec::new();
        };
        let degree = pitch.degree();
        let Some(count) = self.degree_refcounts.get_mut(&degree) else {
            return Vec::new();
        };
        *count -= 1;
        if *count == 0 {
            self.degree_refcounts.remove(&degree);
            vec![HeldInputAction::DegreeReleased(degree)]
        } else {
            Vec::new()
        }
    }

    pub fn release_port(&mut self, port_id: &str) -> Vec<HeldInputAction> {
        let keys: Vec<_> = self
            .held
            .keys()
            .filter(|key| key.port_id == port_id)
            .cloned()
            .collect();
        let mut actions = Vec::new();
        for key in keys {
            actions.extend(self.note_off(&key));
        }
        actions
    }

    pub fn clear(&mut self) -> Vec<HeldInputAction> {
        let degrees: BTreeSet<_> = self.degree_refcounts.keys().copied().collect();
        self.held.clear();
        self.degree_refcounts.clear();
        degrees
            .into_iter()
            .map(HeldInputAction::DegreeReleased)
            .collect()
    }
}

/// Defined MIDI note frequency in conventional 12-TET, independent of the
/// current room tuning.
pub fn midi_note_frequency_hz(note: u8) -> f64 {
    440.0 * 2.0_f64.powf((f64::from(note) - 69.0) / 12.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(note: u8) -> PhysicalMidiKey {
        PhysicalMidiKey {
            port_id: "controller-a".to_owned(),
            channel: 0,
            note,
        }
    }

    #[test]
    fn input_uses_frequency_quantization_for_non_twelve_tet() {
        let tuning = Tuning::from_scl_text(
            "19edo",
            "19 equal divisions\n19\n63.1578947\n126.3157895\n189.4736842\n252.6315789\n315.7894737\n378.9473684\n442.1052632\n505.2631579\n568.4210526\n631.5789474\n694.7368421\n757.8947368\n821.0526316\n884.2105263\n947.3684211\n1010.5263158\n1073.6842105\n1136.8421053\n1200.0\n",
            None,
        )
        .unwrap();
        let mut tracker = MidiInputTracker::new();
        let actions = tracker.note_on(key(69), &tuning);
        let HeldInputAction::DegreeActivated(degree) = actions[0] else {
            panic!("expected activation");
        };
        // A4 is 900 cents above C4, nearest 19-EDO degree is 14
        // (884.21 cents), not 69 modulo 19 (= 12).
        assert_eq!(degree.degree.index(), 14);
    }

    #[test]
    fn multiple_keys_quantized_to_one_degree_release_only_once() {
        let tuning = Tuning::from_scl_text("one", "single degree\n1\n1200.0\n", None).unwrap();
        let mut tracker = MidiInputTracker::new();
        assert_eq!(tracker.note_on(key(60), &tuning).len(), 1);
        assert!(tracker.note_on(key(61), &tuning).is_empty());
        assert!(tracker.note_off(&key(60)).is_empty());
        assert_eq!(tracker.note_off(&key(61)).len(), 1);
    }

    #[test]
    fn duplicate_note_on_is_idempotent_and_unmatched_off_is_ignored() {
        let tuning = Tuning::twelve_tet();
        let mut tracker = MidiInputTracker::new();
        assert_eq!(tracker.note_on(key(64), &tuning).len(), 1);
        assert!(tracker.note_on(key(64), &tuning).is_empty());
        assert_eq!(tracker.note_off(&key(64)).len(), 1);
        assert!(tracker.note_off(&key(64)).is_empty());
    }

    #[test]
    fn release_port_affects_only_that_device() {
        let tuning = Tuning::twelve_tet();
        let mut tracker = MidiInputTracker::new();
        tracker.note_on(key(60), &tuning);
        tracker.note_on(
            PhysicalMidiKey {
                port_id: "controller-b".to_owned(),
                channel: 0,
                note: 64,
            },
            &tuning,
        );
        assert_eq!(tracker.release_port("controller-a").len(), 1);
        assert_eq!(tracker.held_count(), 1);
    }
}
