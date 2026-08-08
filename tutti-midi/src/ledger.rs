//! The source-balanced MIDI output ledger.
//!
//! **Sources, not pitches, are the unit of ownership**: a source key `S` is one
//! independent reason a note sounds (a shared degree held by one author, a
//! moving object, a live voice, a local key press — the app chooses the type).
//! Two sources may share an output voice without either being able to silence
//! the other; the voice stays on until its last owner releases.
//!
//! Output is a deterministic sequence of MIDI 1.0 messages checkable against a
//! fake sink — no ports, no runtime. The ledger doubles as the endpoint
//! *shadow*: its `sources`/voice map IS what the endpoint currently sounds,
//! which is what the reconnect bridge in [`crate::reconcile`] diffs against.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use tutti_music::tuning::{TunedPeriodicPitch, Tuning, TuningId};

pub const DEFAULT_VELOCITY: u8 = 100;
const PITCH_BEND_CENTER: u16 = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MidiVoice {
    /// Zero-based MIDI channel.
    pub channel: u8,
    pub note: u8,
    /// Raw MIDI 1.0 14-bit pitch-bend value.
    pub bend: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidiMessage {
    NoteOn {
        channel: u8,
        note: u8,
        velocity: u8,
    },
    NoteOff {
        channel: u8,
        note: u8,
        velocity: u8,
    },
    PitchBend {
        channel: u8,
        value: u16,
    },
    ControlChange {
        channel: u8,
        controller: u8,
        value: u8,
    },
}

impl MidiMessage {
    pub fn to_bytes(self) -> [u8; 3] {
        match self {
            Self::NoteOn {
                channel,
                note,
                velocity,
            } => [0x90 | (channel & 0x0f), note, velocity],
            Self::NoteOff {
                channel,
                note,
                velocity,
            } => [0x80 | (channel & 0x0f), note, velocity],
            Self::PitchBend { channel, value } => [
                0xe0 | (channel & 0x0f),
                (value & 0x7f) as u8,
                ((value >> 7) & 0x7f) as u8,
            ],
            Self::ControlChange {
                channel,
                controller,
                value,
            } => [0xb0 | (channel & 0x0f), controller, value],
        }
    }
}

/// Exact 12-TET uses a shared conventional channel. Microtonal output uses an
/// MPE-compatible pool with channel 1 (zero-based 0) conventionally reserved
/// for the master channel and channels 2..16 used as members.
#[derive(Debug, Clone, PartialEq)]
pub enum MidiOutputConfig {
    ExactTwelveTet {
        channel: u8,
    },
    Mpe {
        master_channel: u8,
        member_channels: Vec<u8>,
        pitch_bend_range_semitones: f64,
    },
}

impl Default for MidiOutputConfig {
    fn default() -> Self {
        Self::Mpe {
            master_channel: 0,
            member_channels: (1..=15).collect(),
            pitch_bend_range_semitones: 2.0,
        }
    }
}

impl MidiOutputConfig {
    pub fn exact_twelve_tet() -> Self {
        Self::ExactTwelveTet { channel: 0 }
    }

    fn validate(&self) -> Result<(), MidiRouteError> {
        match self {
            Self::ExactTwelveTet { channel } if *channel < 16 => Ok(()),
            Self::ExactTwelveTet { channel } => Err(MidiRouteError::InvalidChannel(*channel)),
            Self::Mpe {
                master_channel,
                member_channels,
                pitch_bend_range_semitones,
            } => {
                if *master_channel >= 16 {
                    return Err(MidiRouteError::InvalidChannel(*master_channel));
                }
                if !pitch_bend_range_semitones.is_finite() || *pitch_bend_range_semitones <= 0.0 {
                    return Err(MidiRouteError::InvalidPitchBendRange);
                }
                if member_channels.is_empty() {
                    return Err(MidiRouteError::EmptyMemberPool);
                }
                let mut seen = BTreeSet::new();
                for channel in member_channels {
                    if *channel >= 16 {
                        return Err(MidiRouteError::InvalidChannel(*channel));
                    }
                    if *channel == *master_channel || !seen.insert(*channel) {
                        return Err(MidiRouteError::InvalidMemberPool);
                    }
                }
                Ok(())
            }
        }
    }

    fn reset_channels(&self) -> Vec<u8> {
        match self {
            Self::ExactTwelveTet { channel } => vec![*channel],
            Self::Mpe {
                master_channel,
                member_channels,
                ..
            } => {
                let mut channels = Vec::with_capacity(member_channels.len() + 1);
                channels.push(*master_channel);
                channels.extend(member_channels.iter().copied());
                channels
            }
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum MidiRouteError {
    #[error("MIDI channel {0} is outside 0..=15")]
    InvalidChannel(u8),
    #[error("MPE pitch-bend range must be finite and greater than zero")]
    InvalidPitchBendRange,
    #[error("MPE output needs at least one member channel")]
    EmptyMemberPool,
    #[error("MPE member channels must be unique and must not include the master channel")]
    InvalidMemberPool,
    #[error("pitch belongs to tuning {actual}, expected {expected}")]
    WrongTuning {
        expected: TuningId,
        actual: TuningId,
    },
    #[error("the periodic pitch lies outside the MIDI note range")]
    PitchOutsideMidiRange,
    #[error(
        "pitch needs {deviation_semitones:.6} semitones of bend, outside the configured ±{range_semitones:.6}"
    )]
    PitchBendOutOfRange {
        deviation_semitones: f64,
        range_semitones: f64,
    },
    #[error("all configured MPE member channels are occupied")]
    MpeChannelsExhausted,
    #[error("exact 12-TET mode cannot represent a non-standard tuning")]
    MicrotonalOutputDisabled,
}

/// Source-balanced MIDI output state, generic over the app's source key `S`.
#[derive(Debug, Clone)]
pub struct MidiLedger<S: Ord + Clone> {
    config: MidiOutputConfig,
    tuning_id: TuningId,
    sources: BTreeMap<S, MidiVoice>,
    voice_refcounts: BTreeMap<MidiVoice, usize>,
}

impl<S: Ord + Clone> MidiLedger<S> {
    pub fn new(tuning: &Tuning, config: MidiOutputConfig) -> Result<Self, MidiRouteError> {
        config.validate()?;
        Ok(Self {
            config,
            tuning_id: tuning.id(),
            sources: BTreeMap::new(),
            voice_refcounts: BTreeMap::new(),
        })
    }

    pub fn tuning_id(&self) -> TuningId {
        self.tuning_id
    }

    /// The active output config (for the bridge's panic-and-repopulate path).
    pub(crate) fn config(&self) -> MidiOutputConfig {
        self.config.clone()
    }

    /// Re-key an EMPTY shadow to a new tuning with no messages — only legal
    /// after [`Self::forget`], when the endpoint is known silent.
    pub(crate) fn align_silent(&mut self, tuning: &Tuning) {
        debug_assert!(self.sources.is_empty() && self.voice_refcounts.is_empty());
        self.tuning_id = tuning.id();
    }

    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    pub fn sources(&self) -> impl Iterator<Item = (&S, &MidiVoice)> {
        self.sources.iter()
    }

    pub fn voice_for_source(&self, source: &S) -> Option<MidiVoice> {
        self.sources.get(source).copied()
    }

    /// Set or clear one logical source. Conversion and channel allocation are
    /// completed before the old voice is changed, so a rejected update leaves
    /// the ledger untouched.
    pub fn set_source(
        &mut self,
        source: S,
        pitch: Option<TunedPeriodicPitch>,
        tuning: &Tuning,
    ) -> Result<Vec<MidiMessage>, MidiRouteError> {
        if tuning.id() != self.tuning_id {
            return Err(MidiRouteError::WrongTuning {
                expected: self.tuning_id,
                actual: tuning.id(),
            });
        }
        let existing = self.sources.get(&source).copied();
        let next = match pitch {
            None => None,
            Some(pitch) => {
                if pitch.tuning_id != tuning.id() {
                    return Err(MidiRouteError::WrongTuning {
                        expected: tuning.id(),
                        actual: pitch.tuning_id,
                    });
                }
                Some(self.allocate_voice(&source, pitch, tuning)?)
            }
        };
        if existing == next {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        if let Some(voice) = existing {
            self.release_voice(&source, voice, &mut messages);
        }
        if let Some(voice) = next {
            self.acquire_voice(source, voice, &mut messages);
        }
        Ok(messages)
    }

    /// Change tuning with a full balanced release. Callers then repopulate the
    /// ledger from the new room projection.
    pub fn change_tuning(
        &mut self,
        tuning: &Tuning,
        config: MidiOutputConfig,
    ) -> Result<Vec<MidiMessage>, MidiRouteError> {
        config.validate()?;
        let messages = self.panic();
        self.tuning_id = tuning.id();
        self.config = config;
        Ok(messages)
    }

    /// Forget all tracked sources and voices WITHOUT emitting anything — for an
    /// endpoint known to be silent already (a power-cycled synth, a fresh
    /// peer). The messages a panic would send describe notes that endpoint
    /// never heard; the honest reconcile from silence is note-ons only.
    pub fn forget(&mut self) {
        self.sources.clear();
        self.voice_refcounts.clear();
    }

    /// Release all tracked sources and reset all configured channels.
    pub fn panic(&mut self) -> Vec<MidiMessage> {
        let mut messages = Vec::new();
        for voice in self.voice_refcounts.keys().copied().collect::<Vec<_>>() {
            messages.push(MidiMessage::NoteOff {
                channel: voice.channel,
                note: voice.note,
                velocity: 0,
            });
            if voice.bend != PITCH_BEND_CENTER {
                messages.push(MidiMessage::PitchBend {
                    channel: voice.channel,
                    value: PITCH_BEND_CENTER,
                });
            }
        }
        self.sources.clear();
        self.voice_refcounts.clear();
        for channel in self.config.reset_channels() {
            // Reset All Controllers followed by All Notes Off.
            messages.push(MidiMessage::ControlChange {
                channel,
                controller: 121,
                value: 0,
            });
            messages.push(MidiMessage::ControlChange {
                channel,
                controller: 123,
                value: 0,
            });
        }
        messages
    }

    fn allocate_voice(
        &self,
        source: &S,
        pitch: TunedPeriodicPitch,
        tuning: &Tuning,
    ) -> Result<MidiVoice, MidiRouteError> {
        match &self.config {
            MidiOutputConfig::ExactTwelveTet { channel } => {
                if !tuning.supports_standard_note_names() {
                    return Err(MidiRouteError::MicrotonalOutputDisabled);
                }
                let absolute = 60_i64
                    + i64::from(pitch.pitch.period()) * 12
                    + i64::from(pitch.pitch.degree().index());
                let note =
                    u8::try_from(absolute).map_err(|_| MidiRouteError::PitchOutsideMidiRange)?;
                if note > 127 {
                    return Err(MidiRouteError::PitchOutsideMidiRange);
                }
                Ok(MidiVoice {
                    channel: *channel,
                    note,
                    bend: PITCH_BEND_CENTER,
                })
            }
            MidiOutputConfig::Mpe {
                member_channels,
                pitch_bend_range_semitones,
                ..
            } => {
                let hz = tuning.hz_for_periodic_pitch(pitch.pitch);
                let fractional_note = 69.0 + 12.0 * (hz / 440.0).log2();
                let rounded = fractional_note.round();
                if !rounded.is_finite() || !(0.0..=127.0).contains(&rounded) {
                    return Err(MidiRouteError::PitchOutsideMidiRange);
                }
                let deviation = fractional_note - rounded;
                if deviation.abs() > *pitch_bend_range_semitones {
                    return Err(MidiRouteError::PitchBendOutOfRange {
                        deviation_semitones: deviation,
                        range_semitones: *pitch_bend_range_semitones,
                    });
                }
                let bend = bend_value(deviation, *pitch_bend_range_semitones);
                let note = rounded as u8;

                // Identical voices safely share one note-on/refcount.
                if let Some(voice) = self
                    .voice_refcounts
                    .keys()
                    .find(|voice| voice.note == note && voice.bend == bend)
                {
                    return Ok(*voice);
                }

                // Treat this source's sole old channel as available for an
                // atomic pitch change.
                let occupied_by_others: BTreeSet<u8> = self
                    .sources
                    .iter()
                    .filter(|(candidate, _)| *candidate != source)
                    .map(|(_, voice)| voice.channel)
                    .collect();
                let channel = member_channels
                    .iter()
                    .copied()
                    .find(|channel| !occupied_by_others.contains(channel))
                    .ok_or(MidiRouteError::MpeChannelsExhausted)?;
                Ok(MidiVoice {
                    channel,
                    note,
                    bend,
                })
            }
        }
    }

    fn acquire_voice(&mut self, source: S, voice: MidiVoice, messages: &mut Vec<MidiMessage>) {
        let count = self.voice_refcounts.entry(voice).or_default();
        if *count == 0 {
            if voice.bend != PITCH_BEND_CENTER {
                messages.push(MidiMessage::PitchBend {
                    channel: voice.channel,
                    value: voice.bend,
                });
            }
            messages.push(MidiMessage::NoteOn {
                channel: voice.channel,
                note: voice.note,
                velocity: DEFAULT_VELOCITY,
            });
        }
        *count += 1;
        self.sources.insert(source, voice);
    }

    fn release_voice(&mut self, source: &S, voice: MidiVoice, messages: &mut Vec<MidiMessage>) {
        self.sources.remove(source);
        let Some(count) = self.voice_refcounts.get_mut(&voice) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            self.voice_refcounts.remove(&voice);
            messages.push(MidiMessage::NoteOff {
                channel: voice.channel,
                note: voice.note,
                velocity: 0,
            });
            if voice.bend != PITCH_BEND_CENTER {
                messages.push(MidiMessage::PitchBend {
                    channel: voice.channel,
                    value: PITCH_BEND_CENTER,
                });
            }
        }
    }
}

fn bend_value(deviation_semitones: f64, range_semitones: f64) -> u16 {
    let raw = if deviation_semitones >= 0.0 {
        f64::from(PITCH_BEND_CENTER)
            + deviation_semitones / range_semitones
                * f64::from(u16::MAX.min(16383) - PITCH_BEND_CENTER)
    } else {
        f64::from(PITCH_BEND_CENTER)
            + deviation_semitones / range_semitones * f64::from(PITCH_BEND_CENTER)
    };
    raw.round().clamp(0.0, 16383.0) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use tutti_music::tuning::Tuning;

    /// The ledger is generic over the source key — plain numbers suffice here.
    fn voice_source(byte: u8) -> u8 {
        byte
    }

    #[test]
    fn exact_twelve_tet_preserves_a4_and_rejects_out_of_range() {
        let tuning = Tuning::twelve_tet();
        let mut ledger = MidiLedger::new(&tuning, MidiOutputConfig::exact_twelve_tet()).unwrap();
        let a4 = TunedPeriodicPitch::new(&tuning, 9, 0).unwrap();
        let messages = ledger
            .set_source(voice_source(1), Some(a4), &tuning)
            .unwrap();
        assert_eq!(
            messages,
            vec![MidiMessage::NoteOn {
                channel: 0,
                note: 69,
                velocity: DEFAULT_VELOCITY,
            }]
        );
        let too_high = TunedPeriodicPitch::new(&tuning, 0, 6).unwrap();
        assert_eq!(
            ledger.set_source(voice_source(2), Some(too_high), &tuning),
            Err(MidiRouteError::PitchOutsideMidiRange)
        );
    }

    #[test]
    fn shared_note_stays_on_until_last_source_releases() {
        let tuning = Tuning::twelve_tet();
        let mut ledger = MidiLedger::new(&tuning, MidiOutputConfig::exact_twelve_tet()).unwrap();
        let pitch = TunedPeriodicPitch::new(&tuning, 0, 0).unwrap();
        assert_eq!(
            ledger
                .set_source(voice_source(1), Some(pitch), &tuning)
                .unwrap()
                .len(),
            1
        );
        assert!(
            ledger
                .set_source(voice_source(2), Some(pitch), &tuning)
                .unwrap()
                .is_empty()
        );
        assert!(
            ledger
                .set_source(voice_source(1), None, &tuning)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            ledger.set_source(voice_source(2), None, &tuning).unwrap(),
            vec![MidiMessage::NoteOff {
                channel: 0,
                note: 60,
                velocity: 0,
            }]
        );
    }

    #[test]
    fn two_sources_remain_polyphonic_when_one_changes() {
        let tuning = Tuning::twelve_tet();
        let mut ledger = MidiLedger::new(&tuning, MidiOutputConfig::exact_twelve_tet()).unwrap();
        let c = TunedPeriodicPitch::new(&tuning, 0, 0).unwrap();
        let e = TunedPeriodicPitch::new(&tuning, 4, 0).unwrap();
        let g = TunedPeriodicPitch::new(&tuning, 7, 0).unwrap();
        ledger
            .set_source(voice_source(1), Some(c), &tuning)
            .unwrap();
        ledger
            .set_source(voice_source(2), Some(e), &tuning)
            .unwrap();
        let changed = ledger
            .set_source(voice_source(1), Some(g), &tuning)
            .unwrap();
        assert_eq!(
            changed,
            vec![
                MidiMessage::NoteOff {
                    channel: 0,
                    note: 60,
                    velocity: 0,
                },
                MidiMessage::NoteOn {
                    channel: 0,
                    note: 67,
                    velocity: DEFAULT_VELOCITY,
                },
            ]
        );
        assert_eq!(ledger.voice_for_source(&voice_source(2)).unwrap().note, 64);
    }

    #[test]
    fn mpe_bends_before_note_and_resets_after_release() {
        let tuning =
            Tuning::from_scl_text("quarter", "quarter tones\n2\n50.0\n1200.0\n", None).unwrap();
        let mut ledger = MidiLedger::new(&tuning, MidiOutputConfig::default()).unwrap();
        let pitch = TunedPeriodicPitch::new(&tuning, 1, 0).unwrap();
        let on = ledger
            .set_source(voice_source(1), Some(pitch), &tuning)
            .unwrap();
        let voice = ledger.voice_for_source(&voice_source(1)).unwrap();
        assert!(matches!(
            on.as_slice(),
            [MidiMessage::PitchBend { channel: 1, value },
                MidiMessage::NoteOn {
                    channel: 1,
                    note,
                    ..
                }
            ] if *value != PITCH_BEND_CENTER && *note == voice.note
        ));
        let off = ledger.set_source(voice_source(1), None, &tuning).unwrap();
        assert_eq!(
            off,
            vec![
                MidiMessage::NoteOff {
                    channel: 1,
                    note: voice.note,
                    velocity: 0,
                },
                MidiMessage::PitchBend {
                    channel: 1,
                    value: PITCH_BEND_CENTER,
                },
            ]
        );
    }

    #[test]
    fn mpe_exhaustion_is_deterministic_and_non_mutating() {
        let tuning =
            Tuning::from_scl_text("quarter", "quarter tones\n2\n50.0\n1200.0\n", None).unwrap();
        let config = MidiOutputConfig::Mpe {
            master_channel: 0,
            member_channels: vec![3],
            pitch_bend_range_semitones: 2.0,
        };
        let mut ledger = MidiLedger::new(&tuning, config).unwrap();
        let first = TunedPeriodicPitch::new(&tuning, 0, 0).unwrap();
        let second = TunedPeriodicPitch::new(&tuning, 1, 0).unwrap();
        ledger
            .set_source(voice_source(1), Some(first), &tuning)
            .unwrap();
        assert_eq!(
            ledger.set_source(voice_source(2), Some(second), &tuning),
            Err(MidiRouteError::MpeChannelsExhausted)
        );
        assert_eq!(ledger.source_count(), 1);
    }

    #[test]
    fn panic_balances_notes_and_resets_every_configured_channel() {
        let tuning = Tuning::twelve_tet();
        let mut ledger = MidiLedger::new(&tuning, MidiOutputConfig::exact_twelve_tet()).unwrap();
        let pitch = TunedPeriodicPitch::new(&tuning, 4, 0).unwrap();
        ledger
            .set_source(voice_source(1), Some(pitch), &tuning)
            .unwrap();
        let messages = ledger.panic();
        assert_eq!(messages[0].to_bytes(), [0x80, 64, 0]);
        assert!(messages.contains(&MidiMessage::ControlChange {
            channel: 0,
            controller: 121,
            value: 0,
        }));
        assert!(messages.contains(&MidiMessage::ControlChange {
            channel: 0,
            controller: 123,
            value: 0,
        }));
        assert_eq!(ledger.source_count(), 0);
    }
}
