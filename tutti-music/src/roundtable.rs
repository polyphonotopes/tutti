//! Durable musical parameters for the round-table pulse performance.
//!
//! This module describes musical meaning only. Start/stop, the current turn,
//! deadlines, retries, membership, and packets are live session concerns and
//! deliberately do not appear in [`RoundTableConfig`].

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MIN_PLAYABLE_MILLIHZ: u32 = 30_000;
pub const MAX_PLAYABLE_MILLIHZ: u32 = 240_000;
pub const MIN_CENTER_MILLIHZ: u32 = 60_000;
pub const MAX_CENTER_MILLIHZ: u32 = 120_000;
pub const MAX_SPREAD_SEMITONES: u8 = 12;
pub const MIN_PULSE_MS: u16 = 80;
pub const MAX_PULSE_MS: u16 = 2_000;
pub const MAX_GAP_MS: u16 = 2_000;
pub const MAX_LEVEL_PER_MILLE: u16 = 450;
pub const MAX_PATTERN_NOTES: usize = 24;
pub const MIN_MIDI_MILLIHZ: u32 = 8_000;
pub const MAX_MIDI_MILLIHZ: u32 = 13_000_000;

/// How the round table chooses the next member of the shared note set.
///
/// Both modes use the same note set and register controls. The mode changes
/// ordering only; it never introduces a pitch class which is absent from the
/// set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RoundTablePitchMode {
    Ascending,
    Random,
}

impl RoundTablePitchMode {
    pub const fn id(self) -> u8 {
        match self {
            Self::Ascending => 0,
            Self::Random => 1,
        }
    }

    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Ascending),
            1 => Some(Self::Random),
            _ => None,
        }
    }
}

/// A bounded, canonical set of MIDI keys used as an ascending arpeggio.
///
/// Two words cover the complete MIDI key domain without heap allocation. The
/// population limit keeps UI edits, canonical records, and session work
/// bounded even though any MIDI key may be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RoundTablePattern {
    words: [u64; 2],
}

impl RoundTablePattern {
    pub const fn from_words(words: [u64; 2]) -> Self {
        Self { words }
    }

    pub const fn words(self) -> [u64; 2] {
        self.words
    }

    pub fn len(self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    pub fn is_empty(self) -> bool {
        self.words == [0; 2]
    }

    pub fn contains(self, note: u8) -> bool {
        let index = usize::from(note);
        if index >= 128 {
            return false;
        }
        self.words[index / 64] & (1_u64 << (index % 64)) != 0
    }

    pub fn iter(self) -> impl Iterator<Item = u8> {
        (0_u8..=127).filter(move |note| self.contains(*note))
    }

    /// The pitch classes represented by this set, independent of register.
    pub fn pitch_class_mask(self) -> u16 {
        self.iter()
            .fold(0_u16, |mask, note| mask | (1_u16 << (note % 12)))
    }

    pub fn contains_pitch_class(self, note: u8) -> bool {
        self.pitch_class_mask() & (1_u16 << (note % 12)) != 0
    }

    /// Canonicalize this carrier representation to one key per pitch class.
    ///
    /// The shared musical meaning is a pitch-class set. The 128-bit carrier
    /// remains useful for MIDI/GATT compatibility, but octave aliases must not
    /// become distinct members. `base` chooses the displayed octave.
    pub fn canonical_pitch_classes(self, base: u8) -> Result<Self, RoundTableConfigError> {
        let mut canonical = Self::default().cleared();
        let mask = self.pitch_class_mask();
        for pitch_class in 0_u8..12 {
            if mask & (1_u16 << pitch_class) != 0 {
                let note = base
                    .checked_add(pitch_class)
                    .ok_or(RoundTableConfigError::Pattern)?;
                canonical = canonical.toggled(note)?;
            }
        }
        Ok(canonical)
    }

    /// Toggle the one shared member addressed by any octave of `note`.
    pub fn toggled_pitch_class(self, note: u8, base: u8) -> Result<Self, RoundTableConfigError> {
        let was_present = self.contains_pitch_class(note);
        let mut canonical = self.canonical_pitch_classes(base)?;
        let canonical_note = base
            .checked_add(note % 12)
            .ok_or(RoundTableConfigError::Pattern)?;
        if was_present {
            canonical = canonical.toggled(canonical_note)?;
        } else if !canonical.contains(canonical_note) {
            canonical = canonical.toggled(canonical_note)?;
        }
        Ok(canonical)
    }

    pub fn toggled(mut self, note: u8) -> Result<Self, RoundTableConfigError> {
        let index = usize::from(note);
        if index >= 128 {
            return Err(RoundTableConfigError::Pattern);
        }
        let mask = 1_u64 << (index % 64);
        let was_present = self.words[index / 64] & mask != 0;
        let population = self.len();
        let word = &mut self.words[index / 64];
        if was_present {
            *word &= !mask;
        } else {
            if population >= MAX_PATTERN_NOTES {
                return Err(RoundTableConfigError::Pattern);
            }
            *word |= mask;
        }
        Ok(self)
    }

    pub const fn cleared(self) -> Self {
        let _ = self;
        Self { words: [0; 2] }
    }

    pub const fn union(self, other: Self) -> Self {
        Self {
            words: [
                self.words[0] | other.words[0],
                self.words[1] | other.words[1],
            ],
        }
    }
}

/// One-press/one-toggle gate for MIDI-style arpeggiator editors.
///
/// Controllers may repeat note-on while a key is held. A latch editor must
/// toggle only on the first note-on and use note-off solely to re-arm that
/// physical key. This bounded state machine makes that input contract shared
/// and testable without putting event-gating state into durable music history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoundTableInputGate {
    held: [u64; 2],
}

impl RoundTableInputGate {
    /// Returns `true` exactly once between a key's press and release.
    pub fn press(&mut self, note: u8) -> bool {
        let index = usize::from(note);
        if index >= 128 {
            return false;
        }
        let mask = 1_u64 << (index % 64);
        let word = &mut self.held[index / 64];
        if *word & mask != 0 {
            false
        } else {
            *word |= mask;
            true
        }
    }

    pub fn release(&mut self, note: u8) -> bool {
        let index = usize::from(note);
        if index >= 128 {
            return false;
        }
        let mask = 1_u64 << (index % 64);
        let word = &mut self.held[index / 64];
        let was_held = *word & mask != 0;
        *word &= !mask;
        was_held
    }

    pub fn clear(&mut self) {
        self.held = [0; 2];
    }
}

impl Default for RoundTablePattern {
    fn default() -> Self {
        // C3, E-flat3, G3, B-flat3: immediately musical, fully visible on the
        // default browser keyboard, and still low enough for the small amp.
        Self::from_words([(1 << 48) | (1 << 51) | (1 << 55) | (1 << 58), 0])
    }
}

/// Named note-set presets from the original Amped-ESP32 round-table demo.
///
/// These masks are UI conveniences: applying one writes its notes into the
/// shared set. The pulse planner never treats this catalog as a second pitch
/// filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RoundTableScale {
    Root,
    MinorPentatonic,
    MajorPentatonic,
    NaturalMinor,
    Major,
    Dorian,
    Chromatic,
}

impl RoundTableScale {
    pub const ALL: [Self; 7] = [
        Self::Root,
        Self::MinorPentatonic,
        Self::MajorPentatonic,
        Self::NaturalMinor,
        Self::Major,
        Self::Dorian,
        Self::Chromatic,
    ];

    pub const fn mask(self) -> u16 {
        match self {
            Self::Root => 0x001,
            Self::MinorPentatonic => 0x4a9,
            Self::MajorPentatonic => 0x295,
            Self::NaturalMinor => 0x5ad,
            Self::Major => 0xab5,
            Self::Dorian => 0x6ad,
            Self::Chromatic => 0xfff,
        }
    }

    pub const fn id(self) -> u8 {
        match self {
            Self::Root => 0,
            Self::MinorPentatonic => 1,
            Self::MajorPentatonic => 2,
            Self::NaturalMinor => 3,
            Self::Major => 4,
            Self::Dorian => 5,
            Self::Chromatic => 6,
        }
    }

    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Root),
            1 => Some(Self::MinorPentatonic),
            2 => Some(Self::MajorPentatonic),
            3 => Some(Self::NaturalMinor),
            4 => Some(Self::Major),
            5 => Some(Self::Dorian),
            6 => Some(Self::Chromatic),
            _ => None,
        }
    }

    /// Materialize this named preset into the one authoritative note set.
    ///
    /// `root` is the MIDI key used for degree zero. Applying a preset is an
    /// edit of the set, not a persistent filter on later pulse selection.
    pub fn pattern(self, root: u8) -> Result<RoundTablePattern, RoundTableConfigError> {
        let mut pattern = RoundTablePattern::default().cleared();
        for offset in 0_u8..12 {
            if self.mask() & (1_u16 << offset) == 0 {
                continue;
            }
            let note = root
                .checked_add(offset)
                .ok_or(RoundTableConfigError::Pattern)?;
            pattern = pattern.toggled(note)?;
        }
        Ok(pattern)
    }
}

/// Convergent room-wide settings for the bass pulse performance.
///
/// Integer units keep the canonical encoding stable across desktop and
/// embedded targets. Device master volume and DAC gain remain local settings;
/// `level_per_mille` is the musical voice level shared by the room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RoundTableConfig {
    pub pitch_mode: RoundTablePitchMode,
    pub pattern: RoundTablePattern,
    pub center_millihz: u32,
    pub scale: RoundTableScale,
    pub spread_semitones: u8,
    pub level_per_mille: u16,
    pub pulse_ms: u16,
    pub gap_ms: u16,
}

impl Default for RoundTableConfig {
    fn default() -> Self {
        Self {
            pitch_mode: RoundTablePitchMode::Ascending,
            pattern: RoundTablePattern::default(),
            center_millihz: 80_000,
            scale: RoundTableScale::MinorPentatonic,
            spread_semitones: 5,
            level_per_mille: 300,
            pulse_ms: 80,
            gap_ms: 10,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RoundTableConfigError {
    #[error("bass center must be {MIN_CENTER_MILLIHZ}..={MAX_CENTER_MILLIHZ} millihertz")]
    Center,
    #[error("pitch spread must be at most {MAX_SPREAD_SEMITONES} semitones")]
    Spread,
    #[error("voice level must be 1..={MAX_LEVEL_PER_MILLE} per mille")]
    Level,
    #[error("pulse duration must be {MIN_PULSE_MS}..={MAX_PULSE_MS} milliseconds")]
    Pulse,
    #[error("gap duration must be at most {MAX_GAP_MS} milliseconds")]
    Gap,
    #[error("arpeggiator pattern must contain at most {MAX_PATTERN_NOTES} notes")]
    Pattern,
}

impl RoundTableConfig {
    pub fn validate(self) -> Result<Self, RoundTableConfigError> {
        if !(MIN_CENTER_MILLIHZ..=MAX_CENTER_MILLIHZ).contains(&self.center_millihz) {
            return Err(RoundTableConfigError::Center);
        }
        if self.spread_semitones > MAX_SPREAD_SEMITONES {
            return Err(RoundTableConfigError::Spread);
        }
        if !(1..=MAX_LEVEL_PER_MILLE).contains(&self.level_per_mille) {
            return Err(RoundTableConfigError::Level);
        }
        if !(MIN_PULSE_MS..=MAX_PULSE_MS).contains(&self.pulse_ms) {
            return Err(RoundTableConfigError::Pulse);
        }
        if self.gap_ms > MAX_GAP_MS {
            return Err(RoundTableConfigError::Gap);
        }
        if self.pattern.len() > MAX_PATTERN_NOTES {
            return Err(RoundTableConfigError::Pattern);
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_defaults_are_valid_and_stable() {
        let config = RoundTableConfig::default().validate().unwrap();
        assert_eq!(config.pitch_mode, RoundTablePitchMode::Ascending);
        assert_eq!(config.pattern.iter().collect::<Vec<_>>(), [48, 51, 55, 58]);
        assert_eq!(config.center_millihz, 80_000);
        assert_eq!(config.scale.mask(), 0x4a9);
        assert_eq!(config.spread_semitones, 5);
        assert_eq!(config.pulse_ms, 80);
        assert_eq!(config.gap_ms, 10);
    }

    #[test]
    fn every_scale_has_root_and_a_unique_id() {
        for scale in RoundTableScale::ALL {
            assert_ne!(scale.mask() & 1, 0);
            assert_eq!(RoundTableScale::from_id(scale.id()), Some(scale));
        }
    }

    #[test]
    fn named_preset_materializes_directly_into_the_note_set() {
        let pattern = RoundTableScale::MinorPentatonic.pattern(48).unwrap();
        assert_eq!(pattern.iter().collect::<Vec<_>>(), [48, 51, 53, 55, 58]);
    }

    #[test]
    fn pattern_toggle_is_sorted_bounded_and_reversible() {
        let mut pattern = RoundTablePattern::from_words([0; 2]);
        for note in (0..MAX_PATTERN_NOTES as u8).rev() {
            pattern = pattern.toggled(note).unwrap();
        }
        assert_eq!(
            pattern.iter().collect::<Vec<_>>(),
            (0..24).collect::<Vec<_>>()
        );
        assert_eq!(pattern.toggled(24), Err(RoundTableConfigError::Pattern));
        pattern = pattern.toggled(7).unwrap();
        assert!(!pattern.contains(7));
        assert_eq!(pattern.len(), MAX_PATTERN_NOTES - 1);
        assert!(pattern.cleared().is_empty());
    }

    #[test]
    fn pattern_pitch_classes_ignore_duplicate_registers() {
        let mut pattern = RoundTablePattern::default().cleared();
        pattern = pattern.toggled(36).unwrap();
        pattern = pattern.toggled(48).unwrap();
        pattern = pattern.toggled(55).unwrap();
        assert_eq!(pattern.pitch_class_mask(), (1 << 0) | (1 << 7));
        assert!(pattern.contains_pitch_class(60));
        assert!(pattern.contains_pitch_class(67));
        assert!(!pattern.contains_pitch_class(61));
        assert_eq!(
            pattern
                .canonical_pitch_classes(48)
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            [48, 55]
        );
    }

    #[test]
    fn octave_aliases_toggle_the_same_shared_member() {
        let empty = RoundTablePattern::default().cleared();
        let c = empty.toggled_pitch_class(48, 48).unwrap();
        assert_eq!(c.iter().collect::<Vec<_>>(), [48]);
        let empty_again = c.toggled_pitch_class(60, 48).unwrap();
        assert!(empty_again.is_empty());
    }

    #[test]
    fn input_gate_toggles_once_per_physical_press_and_rearms_on_release() {
        let mut gate = RoundTableInputGate::default();
        assert!(gate.press(60));
        assert!(
            !gate.press(60),
            "key repeat must not toggle the latch again"
        );
        assert!(gate.release(60));
        assert!(!gate.release(60));
        assert!(gate.press(60), "note-off rearms the next physical press");
        gate.clear();
        assert!(
            gate.press(60),
            "mode changes and disconnects clear the gate"
        );
        assert!(!gate.press(128));
    }

    #[test]
    fn out_of_domain_notes_never_index_outside_the_fixed_pattern() {
        let pattern = RoundTablePattern::default();
        assert!(!pattern.contains(128));
        assert_eq!(pattern.toggled(255), Err(RoundTableConfigError::Pattern));
    }
}
