//! Pure projection from a materialized Tutti music view to AMY wire messages.
//!
//! This crate deliberately does not link AMY. Desktop renderers and embedded
//! leaves therefore share exactly one transition compiler while each platform
//! owns its own AMY runtime and audio hardware.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use tutti_music::render::fractional_midi;
use tutti_music::tuning::{PeriodicPitch, TunedDegree, TunedPeriodicPitch, Tuning};

pub use tutti_music::facets::{Envelope, Interp, MAX_ENV_LEVEL, MAX_ENV_POINTS};

/// A materialized pitch set cannot be represented by the configured AMY
/// oscillator pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmyVoiceCapacityError {
    pub required: usize,
    pub available: u16,
}

impl fmt::Display for AmyVoiceCapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "AMY projection needs {} voices but only {} oscillators are available",
            self.required, self.available
        )
    }
}

impl Error for AmyVoiceCapacityError {}

/// Deterministically assign distinct oscillators to every live degree.
///
/// A degree's index remains its preferred oscillator, preserving the compact
/// historical wire for ordinary scales. Collisions use deterministic linear
/// probing instead of aliasing two sounding degrees onto one oscillator.
fn assignments(
    pitches: &BTreeSet<TunedPeriodicPitch>,
    max_oscs: u16,
) -> Result<BTreeMap<TunedPeriodicPitch, u16>, AmyVoiceCapacityError> {
    if pitches.len() > usize::from(max_oscs) {
        return Err(AmyVoiceCapacityError {
            required: pitches.len(),
            available: max_oscs,
        });
    }
    if pitches.is_empty() {
        return Ok(BTreeMap::new());
    }

    let mut used = BTreeSet::new();
    let mut assigned = BTreeMap::new();
    for pitch in pitches {
        let preferred = (i64::from(pitch.pitch.period()) * 257
            + i64::from(pitch.pitch.degree().index()))
        .rem_euclid(i64::from(max_oscs)) as u16;
        let oscillator = (0..max_oscs)
            .map(|offset| (preferred + offset) % max_oscs)
            .find(|candidate| !used.contains(candidate))
            .expect("capacity was checked before assigning voices");
        used.insert(oscillator);
        assigned.insert(*pitch, oscillator);
    }
    Ok(assigned)
}

fn by_oscillator(
    assignments: &BTreeMap<TunedPeriodicPitch, u16>,
) -> BTreeMap<u16, TunedPeriodicPitch> {
    assignments
        .iter()
        .map(|(degree, oscillator)| (*oscillator, *degree))
        .collect()
}

/// Format a MIDI note for AMY's compact wire grammar.
fn fmt_midi_note(note: f64) -> String {
    if note.fract().abs() < 1e-4 {
        format!("{}", note.round() as i64)
    } else {
        let formatted = format!("{note:.3}");
        formatted
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_owned()
    }
}

/// Compile one exact materialized-set transition into AMY wire messages.
///
/// Every live degree receives a distinct oscillator. If collision resolution
/// changes a held degree's oscillator, its old voice is stopped before the new
/// voice starts. The function refuses oversubscription without emitting a
/// partial transition.
pub fn degrees_to_amy_events(
    before: &BTreeSet<TunedDegree>,
    after: &BTreeSet<TunedDegree>,
    envelopes: &BTreeMap<TunedDegree, Envelope>,
    tuning: &Tuning,
    max_oscs: u16,
) -> Result<Vec<String>, AmyVoiceCapacityError> {
    let before: BTreeSet<_> = before
        .iter()
        .map(|degree| TunedPeriodicPitch {
            tuning_id: degree.tuning_id,
            pitch: PeriodicPitch::from_degree(degree.degree, 0),
        })
        .collect();
    let after: BTreeSet<_> = after
        .iter()
        .map(|degree| TunedPeriodicPitch {
            tuning_id: degree.tuning_id,
            pitch: PeriodicPitch::from_degree(degree.degree, 0),
        })
        .collect();
    pitches_to_amy_events(&before, &after, envelopes, tuning, max_oscs)
}

/// Compile absolute periodic pitches into AMY messages. Unlike the legacy
/// degree-only entry point, this preserves octave/period information from MIDI
/// and other live controllers.
pub fn pitches_to_amy_events(
    before: &BTreeSet<TunedPeriodicPitch>,
    after: &BTreeSet<TunedPeriodicPitch>,
    envelopes: &BTreeMap<TunedDegree, Envelope>,
    tuning: &Tuning,
    max_oscs: u16,
) -> Result<Vec<String>, AmyVoiceCapacityError> {
    let before = assignments(before, max_oscs)?;
    let after = assignments(after, max_oscs)?;
    let before_by_oscillator = by_oscillator(&before);
    let after_by_oscillator = by_oscillator(&after);
    let oscillators: BTreeSet<_> = before_by_oscillator
        .keys()
        .chain(after_by_oscillator.keys())
        .copied()
        .collect();

    let mut events = Vec::new();
    for oscillator in &oscillators {
        if before_by_oscillator.contains_key(oscillator)
            && before_by_oscillator.get(oscillator) != after_by_oscillator.get(oscillator)
        {
            events.push(format!("v{oscillator}l0"));
        }
    }
    for oscillator in oscillators {
        let Some(degree) = after_by_oscillator.get(&oscillator) else {
            continue;
        };
        if before_by_oscillator.get(&oscillator) == Some(degree) {
            continue;
        }
        let note = fractional_midi(tuning, degree.pitch);
        let mut event = format!("v{oscillator}n{}", fmt_midi_note(note));
        if let Some(envelope) = envelopes.get(&degree.degree()) {
            event.push_str(&envelope_to_amy(envelope));
        }
        event.push_str("l1");
        events.push(event);
    }
    Ok(events)
}

fn eg_type_code(interp: Interp) -> u8 {
    match interp {
        Interp::Linear | Interp::Step => 1,
        Interp::Exp => 3,
    }
}

fn fmt_level(level: u8) -> String {
    let value = f32::from(level.min(MAX_ENV_LEVEL)) / f32::from(MAX_ENV_LEVEL);
    let formatted = format!("{value:.4}");
    let trimmed = formatted.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

const STEP_JUMP_MS: u16 = 1;

fn staircase(points: &[(u16, u8)]) -> Vec<(u16, u8)> {
    if points.len() <= 1 {
        return points.to_vec();
    }
    let mut expanded = Vec::with_capacity(points.len() * 2 - 1);
    expanded.push(points[0]);
    for window in points.windows(2) {
        let (_, previous_level) = window[0];
        let (segment_ms, level) = window[1];
        expanded.push((segment_ms.saturating_sub(STEP_JUMP_MS), previous_level));
        expanded.push((STEP_JUMP_MS, level));
    }
    expanded
}

/// Project a converged envelope facet into AMY's amplitude-EG wire fragment.
pub fn envelope_to_amy(envelope: &Envelope) -> String {
    let points = match envelope.interp {
        Interp::Step => staircase(&envelope.points),
        _ => envelope.points.clone(),
    };
    let mut wire = String::from("A");
    for (index, (milliseconds, level)) in points.iter().enumerate() {
        if index > 0 {
            wire.push(',');
        }
        wire.push_str(&milliseconds.to_string());
        wire.push(',');
        wire.push_str(&fmt_level(*level));
    }
    wire.push('T');
    wire.push_str(&eg_type_code(envelope.interp).to_string());
    wire
}

#[cfg(test)]
mod tests {
    use super::*;

    fn equal_division(count: u16) -> Tuning {
        let mut scl = format!("equal division\n{count}\n");
        for step in 1..=count {
            scl.push_str(&format!(
                "{:.6}\n",
                f64::from(step) * 1200.0 / f64::from(count)
            ));
        }
        Tuning::from_scl_text("equal division", &scl, None).unwrap()
    }

    fn set(tuning: &Tuning, indices: &[u16]) -> BTreeSet<TunedDegree> {
        indices
            .iter()
            .map(|index| TunedDegree::new(tuning, *index).unwrap())
            .collect()
    }

    #[test]
    fn ordinary_chord_preserves_compact_degree_mapping() {
        let tuning = Tuning::twelve_tet();
        let events = degrees_to_amy_events(
            &BTreeSet::new(),
            &set(&tuning, &[0, 4, 7]),
            &BTreeMap::new(),
            &tuning,
            40,
        )
        .unwrap();
        assert_eq!(events, ["v0n60l1", "v4n64l1", "v7n67l1"]);
    }

    #[test]
    fn sparse_degree_collision_gets_a_distinct_voice() {
        let tuning = equal_division(41);
        let events = degrees_to_amy_events(
            &BTreeSet::new(),
            &set(&tuning, &[0, 40]),
            &BTreeMap::new(),
            &tuning,
            40,
        )
        .unwrap();
        assert!(events[0].starts_with("v0n"));
        assert!(events[1].starts_with("v1n"));
    }

    #[test]
    fn removing_a_colliding_degree_revoices_without_a_stuck_note() {
        let tuning = equal_division(41);
        let events = degrees_to_amy_events(
            &set(&tuning, &[0, 40]),
            &set(&tuning, &[40]),
            &BTreeMap::new(),
            &tuning,
            40,
        )
        .unwrap();
        assert_eq!(&events[..2], ["v0l0", "v1l0"]);
        assert!(events[2].starts_with("v0n"));
    }

    #[test]
    fn oversubscription_is_an_error_not_partial_wire() {
        let tuning = equal_division(41);
        let error = degrees_to_amy_events(
            &BTreeSet::new(),
            &set(&tuning, &(0..41).collect::<Vec<_>>()),
            &BTreeMap::new(),
            &tuning,
            40,
        )
        .unwrap_err();
        assert_eq!(
            error,
            AmyVoiceCapacityError {
                required: 41,
                available: 40,
            }
        );
    }

    #[test]
    fn absolute_pitch_keeps_midi_octaves_distinct() {
        let tuning = Tuning::twelve_tet();
        let pitch = |midi| TunedPeriodicPitch {
            tuning_id: tuning.id(),
            pitch: tuning.periodic_pitch_for_midi(midi).unwrap(),
        };
        let events = pitches_to_amy_events(
            &BTreeSet::new(),
            &BTreeSet::from([pitch(48), pitch(72)]),
            &BTreeMap::new(),
            &tuning,
            31,
        )
        .unwrap();
        assert!(events.iter().any(|event| event.contains("n48")));
        assert!(events.iter().any(|event| event.contains("n72")));
    }

    #[test]
    fn envelope_projection_preserves_amy_grammar() {
        let envelope = Envelope {
            points: vec![(0, 127), (120, 12), (40, 0)],
            interp: Interp::Exp,
        };
        assert_eq!(envelope_to_amy(&envelope), "A0,1,120,0.0945,40,0T3");
    }
}
