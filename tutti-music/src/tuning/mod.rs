//! Validated periodic tuning, keyboard mapping, and frequency quantization —
//! the protocol floor of tutti-music.
//!
//! A tuning's identity is content: [`TuningId`] is the blake3 hash of the
//! canonical scale + mapping bytes, so two peers holding byte-different `.scl`
//! files with the same musical content agree on the id. Degrees are then scoped
//! to that identity ([`TunedDegree`]), which is what lets a shared pitch-set
//! survive a room-wide tuning change without misreading old ops.

mod kbm;
mod scl;

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use kbm::{KbmParseError, KeyboardMapping, parse_kbm};
pub use scl::{MAX_SCALE_DEGREES, SclParseError, SclScale, parse_scl};

/// The canonical-bytes domain tag [`TuningId`] hashes over. **Byte-pinned wart,
/// kept deliberately:** the literal predates the extraction (it names walkie),
/// and `TuningId`s derived from it are wire-visible in deployed walkie rooms —
/// changing it would silently re-key every tuning-scoped degree. A neutral tag is
/// a schema move to schedule with a deliberate generation bump, never a rename.
const CANONICAL_TUNING_MAGIC: &[u8] = b"walkie-songie/tuning\0";
const CANONICAL_TUNING_VERSION: u16 = 2;
#[cfg(test)]
const C4_HZ: f64 = 261.625_565_3;
pub const TWELVE_TET_SCL: &str = r#"! walkie-songie built-in 12-TET
12-tone equal temperament
12
100.0
200.0
300.0
400.0
500.0
600.0
700.0
800.0
900.0
1000.0
1100.0
1200.0
"#;

/// A raw, tuning-unscoped degree index — the loose carrier UI and compatibility
/// code passes around before a bound is known.
///
/// Durable and transport code uses [`ScaleDegree`], which cannot be constructed
/// outside the bounds of a specific tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PitchClass(pub u16);

impl PitchClass {
    pub fn new(index: impl Into<u16>) -> Self {
        Self(index.into())
    }

    pub fn index(self) -> u16 {
        self.0
    }
}

/// A scale degree checked against a tuning's degree count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScaleDegree(u16);

impl ScaleDegree {
    pub fn new(index: u16, degree_count: usize) -> Result<Self, PitchDomainError> {
        if usize::from(index) >= degree_count {
            return Err(PitchDomainError::DegreeOutOfRange {
                degree: index,
                degree_count,
            });
        }
        Ok(Self(index))
    }

    pub const fn index(self) -> u16 {
        self.0
    }
}

impl From<ScaleDegree> for PitchClass {
    fn from(value: ScaleDegree) -> Self {
        Self(value.index())
    }
}

/// One validated scale degree plus a signed repetition of the scale's period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PeriodicPitch {
    degree: ScaleDegree,
    period: i32,
}

impl PeriodicPitch {
    pub fn new(degree: u16, period: i32, degree_count: usize) -> Result<Self, PitchDomainError> {
        Ok(Self {
            degree: ScaleDegree::new(degree, degree_count)?,
            period,
        })
    }

    pub const fn from_degree(degree: ScaleDegree, period: i32) -> Self {
        Self { degree, period }
    }

    pub const fn degree(self) -> ScaleDegree {
        self.degree
    }

    pub const fn period(self) -> i32 {
        self.period
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PitchDomainError {
    #[error("scale degree {degree} is outside a {degree_count}-degree tuning")]
    DegreeOutOfRange { degree: u16, degree_count: usize },
    #[error("absolute scale degree is outside the supported i32 range")]
    AbsoluteDegreeOverflow,
}

/// Stable hash of versioned canonical tuning and keyboard-mapping bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TuningId([u8; 32]);

impl TuningId {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Decode an already-hashed identifier from a wire or storage record.
    ///
    /// This does not make the identifier a known tuning; ingress validation
    /// must still match it against a validated [`TuningDefinition`].
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for TuningId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum TuningError {
    #[error(transparent)]
    Scl(#[from] SclParseError),
    #[error(transparent)]
    Kbm(#[from] KbmParseError),
    #[error("tuning must contain between 1 and {MAX_SCALE_DEGREES} degrees")]
    InvalidDegreeCount,
    #[error("degree zero must be exactly 0 cents")]
    InvalidRoot,
    #[error("scale degrees must be finite, non-negative, and strictly ascending")]
    InvalidDegrees,
    #[error("period must be finite, positive, and above the final scale degree")]
    InvalidPeriod,
    #[error("reference MIDI note is unmapped")]
    UnmappedReferenceNote,
    #[error("derived root frequency is invalid")]
    InvalidRootFrequency,
    #[error("tuning definition declares {declared}, but canonical content hashes to {actual}")]
    TuningIdMismatch {
        declared: TuningId,
        actual: TuningId,
    },
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum QuantizeError {
    #[error("frequency must be finite and greater than zero, got {0}")]
    InvalidFrequency(f64),
}

/// Exact result of nearest-degree quantization.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QuantizeResult {
    pub periodic_pitch: PeriodicPitch,
    /// Compatibility view of `periodic_pitch.degree`.
    pub pitch_class: PitchClass,
    /// Signed input-minus-center distance. It is intentionally not clamped.
    pub cents_deviation: f64,
    pub center_hz: f64,
    /// Compatibility linear degree index with C4/root represented as 60.
    pub absolute_pitch: i32,
}

/// Canonical source material carried by a durable tuning-register operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuningDefinition {
    pub id: TuningId,
    pub scl: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kbm: Option<String>,
}

impl TuningDefinition {
    pub fn new(scl: String, kbm: Option<String>) -> Result<Self, TuningError> {
        let tuning = Tuning::from_scl_text("room tuning", &scl, kbm.as_deref())?;
        Ok(Self {
            id: tuning.id(),
            scl,
            kbm,
        })
    }

    pub fn validate(&self, name: impl Into<String>) -> Result<Tuning, TuningError> {
        let tuning = Tuning::from_scl_text(name, &self.scl, self.kbm.as_deref())?;
        if tuning.id() != self.id {
            return Err(TuningError::TuningIdMismatch {
                declared: self.id,
                actual: tuning.id(),
            });
        }
        Ok(tuning)
    }

    pub fn twelve_tet() -> Self {
        Self::new(TWELVE_TET_SCL.to_owned(), None).expect("the built-in 12-TET definition is valid")
    }
}

/// A degree explicitly scoped to one canonical tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TunedDegree {
    pub tuning_id: TuningId,
    pub degree: ScaleDegree,
}

impl TunedDegree {
    pub fn new(tuning: &Tuning, degree: u16) -> Result<Self, PitchDomainError> {
        Ok(Self {
            tuning_id: tuning.id(),
            degree: tuning.degree(degree)?,
        })
    }

    pub fn validate(self, tuning: &Tuning) -> Result<Self, TunedPitchError> {
        if self.tuning_id != tuning.id() {
            return Err(TunedPitchError::WrongTuning {
                expected: tuning.id(),
                actual: self.tuning_id,
            });
        }
        ScaleDegree::new(self.degree.index(), tuning.pitch_class_count())?;
        Ok(self)
    }
}

/// An absolute periodic pitch explicitly scoped to one canonical tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TunedPeriodicPitch {
    pub tuning_id: TuningId,
    pub pitch: PeriodicPitch,
}

impl TunedPeriodicPitch {
    pub fn new(tuning: &Tuning, degree: u16, period: i32) -> Result<Self, PitchDomainError> {
        Ok(Self {
            tuning_id: tuning.id(),
            pitch: PeriodicPitch::new(degree, period, tuning.pitch_class_count())?,
        })
    }

    pub fn validate(self, tuning: &Tuning) -> Result<Self, TunedPitchError> {
        if self.tuning_id != tuning.id() {
            return Err(TunedPitchError::WrongTuning {
                expected: tuning.id(),
                actual: self.tuning_id,
            });
        }
        PeriodicPitch::new(
            self.pitch.degree().index(),
            self.pitch.period(),
            tuning.pitch_class_count(),
        )?;
        Ok(self)
    }

    pub const fn degree(self) -> TunedDegree {
        TunedDegree {
            tuning_id: self.tuning_id,
            degree: self.pitch.degree(),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TunedPitchError {
    #[error("pitch uses tuning {actual}, expected {expected}")]
    WrongTuning {
        expected: TuningId,
        actual: TuningId,
    },
    #[error(transparent)]
    InvalidPitch(#[from] PitchDomainError),
}

/// A finite, strictly ascending periodic scale plus a keyboard mapping.
#[derive(Debug, Clone)]
pub struct Tuning {
    pub name: String,
    root_reference_hz: f64,
    degree_cents: Vec<f64>,
    period_cents: f64,
    note_names: Vec<String>,
    keyboard_mapping: KeyboardMapping,
    id: TuningId,
}

impl Default for Tuning {
    fn default() -> Self {
        Self::twelve_tet()
    }
}

impl Tuning {
    pub fn twelve_tet() -> Self {
        let scale = SclScale {
            description: "12-tone equal temperament".to_owned(),
            degree_cents: (0..12).map(|index| f64::from(index) * 100.0).collect(),
            period_cents: 1200.0,
        };
        let mapping = KeyboardMapping::default_for_scale(12).expect("12 is valid");
        Self::from_scale_and_mapping("12-TET".to_owned(), scale, mapping)
            .expect("built-in 12-TET is valid")
    }

    pub fn from_scl(
        name: String,
        scale: SclScale,
        mapping: Option<KeyboardMapping>,
    ) -> Result<Self, TuningError> {
        let mapping = match mapping {
            Some(mapping) => mapping,
            None => KeyboardMapping::default_for_scale(scale.degree_cents.len())?,
        };
        Self::from_scale_and_mapping(name, scale, mapping)
    }

    pub fn from_scl_text(
        name: impl Into<String>,
        scl: &str,
        kbm: Option<&str>,
    ) -> Result<Self, TuningError> {
        let scale = parse_scl(scl)?;
        let mapping = kbm.map(parse_kbm).transpose()?;
        Self::from_scl(name.into(), scale, mapping)
    }

    fn from_scale_and_mapping(
        name: String,
        scale: SclScale,
        keyboard_mapping: KeyboardMapping,
    ) -> Result<Self, TuningError> {
        validate_scale(&scale)?;
        let keyboard_mapping = keyboard_mapping.resolve_for_scale(scale.degree_cents.len());
        let canonical_bytes = canonical_bytes(&scale, &keyboard_mapping);
        let id = TuningId::from_canonical_bytes(&canonical_bytes);
        let degree_count = scale.degree_cents.len();

        let reference_absolute_degree = keyboard_mapping
            .absolute_degree_for_midi(keyboard_mapping.reference_midi)
            .ok_or(TuningError::UnmappedReferenceNote)?;
        let reference_pitch = periodic_pitch_from_absolute(reference_absolute_degree, degree_count)
            .map_err(|_| TuningError::InvalidRootFrequency)?;
        let reference_cents = scale.degree_cents[usize::from(reference_pitch.degree.index())]
            + f64::from(reference_pitch.period) * scale.period_cents;
        let root_reference_hz =
            keyboard_mapping.reference_frequency_hz / 2.0_f64.powf(reference_cents / 1200.0);
        if !root_reference_hz.is_finite() || root_reference_hz <= 0.0 {
            return Err(TuningError::InvalidRootFrequency);
        }

        let is_standard_twelve_tet =
            is_twelve_tet(&scale) && keyboard_mapping == KeyboardMapping::default_for_scale(12)?;
        let note_names = if is_standard_twelve_tet {
            [
                "C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        } else {
            (0..degree_count)
                .map(|index| format!("degree {index}"))
                .collect()
        };

        Ok(Self {
            name,
            root_reference_hz,
            degree_cents: scale.degree_cents,
            period_cents: scale.period_cents,
            note_names,
            keyboard_mapping,
            id,
        })
    }

    pub const fn id(&self) -> TuningId {
        self.id
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_parts(
            &self.degree_cents,
            self.period_cents,
            &self.keyboard_mapping,
        )
    }

    pub fn pitch_class_count(&self) -> usize {
        self.degree_cents.len()
    }

    pub const fn period_cents(&self) -> f64 {
        self.period_cents
    }

    pub const fn root_reference_hz(&self) -> f64 {
        self.root_reference_hz
    }

    pub fn keyboard_mapping(&self) -> &KeyboardMapping {
        &self.keyboard_mapping
    }

    pub fn supports_standard_note_names(&self) -> bool {
        self.pitch_class_count() == 12
            && (self.period_cents - 1200.0).abs() < 1e-9
            && self
                .degree_cents
                .iter()
                .enumerate()
                .all(|(index, cents)| (*cents - index as f64 * 100.0).abs() < 1e-9)
            && self.keyboard_mapping
                == KeyboardMapping::default_for_scale(12)
                    .expect("12-degree default mapping is valid")
    }

    pub fn degree(&self, index: u16) -> Result<ScaleDegree, PitchDomainError> {
        ScaleDegree::new(index, self.pitch_class_count())
    }

    pub fn note_name(&self, pitch_class: PitchClass) -> &str {
        self.note_names
            .get(usize::from(pitch_class.0))
            .map(String::as_str)
            .unwrap_or("?")
    }

    pub fn degree_label(&self, degree: ScaleDegree) -> &str {
        &self.note_names[usize::from(degree.index())]
    }

    pub fn note_name_with_octave(&self, pitch_class: PitchClass, period: i32) -> String {
        format!("{}{}", self.note_name(pitch_class), period + 4)
    }

    pub fn hz_for_periodic_pitch(&self, pitch: PeriodicPitch) -> f64 {
        let cents = self.degree_cents[usize::from(pitch.degree.index())]
            + f64::from(pitch.period) * self.period_cents;
        self.root_reference_hz * 2.0_f64.powf(cents / 1200.0)
    }

    /// Compatibility helper where `octave == 4` means period zero.
    pub fn hz_for_pitch(&self, pitch_class: PitchClass, octave: i32) -> Option<f64> {
        let degree = self.degree(pitch_class.0).ok()?;
        Some(self.hz_for_periodic_pitch(PeriodicPitch::from_degree(degree, octave - 4)))
    }

    pub fn periodic_pitch_for_midi(&self, midi: u8) -> Option<PeriodicPitch> {
        let absolute_degree = self.keyboard_mapping.absolute_degree_for_midi(midi)?;
        periodic_pitch_from_absolute(absolute_degree, self.pitch_class_count()).ok()
    }

    pub fn hz_for_midi(&self, midi: u8) -> Option<f64> {
        self.periodic_pitch_for_midi(midi)
            .map(|pitch| self.hz_for_periodic_pitch(pitch))
    }

    pub fn quantize(&self, hz: f64) -> Result<QuantizeResult, QuantizeError> {
        if !hz.is_finite() || hz <= 0.0 {
            return Err(QuantizeError::InvalidFrequency(hz));
        }

        let input_cents = 1200.0 * (hz / self.root_reference_hz).log2();
        let base_period = (input_cents / self.period_cents).floor() as i32;
        let mut best: Option<(f64, f64, PeriodicPitch)> = None;

        for period in (base_period - 1)..=(base_period + 1) {
            for (index, degree_cents) in self.degree_cents.iter().copied().enumerate() {
                let center_cents = degree_cents + f64::from(period) * self.period_cents;
                let deviation = input_cents - center_cents;
                let degree = ScaleDegree(index as u16);
                let pitch = PeriodicPitch::from_degree(degree, period);
                let replace = match best {
                    None => true,
                    Some((best_abs, best_center, _)) => {
                        deviation.abs() < best_abs
                            || (deviation.abs() == best_abs && center_cents < best_center)
                    }
                };
                if replace {
                    best = Some((deviation.abs(), center_cents, pitch));
                }
            }
        }

        let (_, center_cents, periodic_pitch) =
            best.expect("a validated tuning always has a degree");
        let cents_deviation = input_cents - center_cents;
        let center_hz = self.root_reference_hz * 2.0_f64.powf(center_cents / 1200.0);
        let absolute_degree = i64::from(periodic_pitch.period) * self.pitch_class_count() as i64
            + i64::from(periodic_pitch.degree.index());
        let absolute_pitch =
            i32::try_from(60_i64 + absolute_degree).unwrap_or(if absolute_degree.is_negative() {
                i32::MIN
            } else {
                i32::MAX
            });

        Ok(QuantizeResult {
            periodic_pitch,
            pitch_class: periodic_pitch.degree.into(),
            cents_deviation,
            center_hz,
            absolute_pitch,
        })
    }
}

fn validate_scale(scale: &SclScale) -> Result<(), TuningError> {
    if !(1..=MAX_SCALE_DEGREES).contains(&scale.degree_cents.len()) {
        return Err(TuningError::InvalidDegreeCount);
    }
    if scale.degree_cents[0].to_bits() != 0.0_f64.to_bits() {
        return Err(TuningError::InvalidRoot);
    }
    let mut previous = -1.0;
    for cents in &scale.degree_cents {
        if !cents.is_finite() || *cents < 0.0 || *cents <= previous {
            return Err(TuningError::InvalidDegrees);
        }
        previous = *cents;
    }
    if !scale.period_cents.is_finite()
        || scale.period_cents <= 0.0
        || scale.period_cents <= previous
    {
        return Err(TuningError::InvalidPeriod);
    }
    Ok(())
}

fn is_twelve_tet(scale: &SclScale) -> bool {
    scale.degree_cents.len() == 12
        && (scale.period_cents - 1200.0).abs() < 1e-9
        && scale
            .degree_cents
            .iter()
            .enumerate()
            .all(|(index, cents)| (*cents - index as f64 * 100.0).abs() < 1e-9)
}

fn periodic_pitch_from_absolute(
    absolute_degree: i32,
    degree_count: usize,
) -> Result<PeriodicPitch, PitchDomainError> {
    let degree_count =
        i32::try_from(degree_count).map_err(|_| PitchDomainError::AbsoluteDegreeOverflow)?;
    let period = absolute_degree.div_euclid(degree_count);
    let degree = absolute_degree.rem_euclid(degree_count) as u16;
    PeriodicPitch::new(degree, period, degree_count as usize)
}

fn canonical_bytes(scale: &SclScale, mapping: &KeyboardMapping) -> Vec<u8> {
    canonical_parts(&scale.degree_cents, scale.period_cents, mapping)
}

fn canonical_parts(degree_cents: &[f64], period_cents: f64, mapping: &KeyboardMapping) -> Vec<u8> {
    let mut output = Vec::with_capacity(64 + degree_cents.len() * 8);
    output.extend_from_slice(CANONICAL_TUNING_MAGIC);
    output.extend_from_slice(&CANONICAL_TUNING_VERSION.to_be_bytes());
    output.extend_from_slice(&(degree_cents.len() as u32).to_be_bytes());
    for cents in degree_cents {
        output.extend_from_slice(&cents.to_bits().to_be_bytes());
    }
    output.extend_from_slice(&period_cents.to_bits().to_be_bytes());
    mapping.append_canonical_bytes(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hz_at_cents(root: f64, cents: f64) -> f64 {
        root * 2.0_f64.powf(cents / 1200.0)
    }

    #[test]
    fn twelve_tet_basics_and_frequency_oracle() {
        let tuning = Tuning::twelve_tet();
        assert_eq!(tuning.pitch_class_count(), 12);
        assert_eq!(tuning.note_name(PitchClass(0)), "C");
        assert_eq!(tuning.note_name(PitchClass(9)), "A");
        assert!((tuning.hz_for_pitch(PitchClass(9), 4).unwrap() - 440.0).abs() < 1e-6);
        assert!((tuning.hz_for_midi(69).unwrap() - 440.0).abs() < 1e-6);
    }

    #[test]
    fn quantization_carries_wrap_period_and_exact_center() {
        let tuning = Tuning::twelve_tet();
        let input = 520.0;
        let result = tuning.quantize(input).unwrap();
        assert_eq!(result.periodic_pitch, PeriodicPitch::new(0, 1, 12).unwrap());
        assert_eq!(result.absolute_pitch, 72);
        assert!((result.center_hz - C4_HZ * 2.0).abs() < 1e-8);
        let oracle = 1200.0 * (input / result.center_hz).log2();
        assert!((result.cents_deviation - oracle).abs() < 1e-10);
    }

    #[test]
    fn quantization_does_not_clamp_large_uneven_gap() {
        let tuning = Tuning::from_scl_text("uneven", "uneven\n2\n100.0\n1200.0\n", None).unwrap();
        let input = hz_at_cents(tuning.root_reference_hz(), 650.0);
        let result = tuning.quantize(input).unwrap();
        assert_eq!(result.periodic_pitch.degree().index(), 1);
        assert!((result.cents_deviation - 550.0).abs() < 1e-9);
    }

    #[test]
    fn non_octave_period_drives_frequency_and_quantization() {
        let tuning = Tuning::from_scl_text(
            "Bohlen-Pierce fragment",
            "tritave\n3\n7/5\n7/3\n3/1\n",
            None,
        )
        .unwrap();
        let root = tuning.root_reference_hz();
        let period = tuning.hz_for_periodic_pitch(PeriodicPitch::new(0, 1, 3).unwrap());
        assert!((period / root - 3.0).abs() < 1e-12);
        let result = tuning.quantize(period).unwrap();
        assert_eq!(result.periodic_pitch, PeriodicPitch::new(0, 1, 3).unwrap());
        assert!(result.cents_deviation.abs() < 1e-9);
    }

    #[test]
    fn invalid_frequencies_are_rejected() {
        let tuning = Tuning::twelve_tet();
        assert!(tuning.quantize(0.0).is_err());
        assert!(tuning.quantize(f64::NAN).is_err());
        assert!(tuning.quantize(f64::INFINITY).is_err());
    }

    #[test]
    fn canonical_id_ignores_scl_description_and_formatting() {
        let a = Tuning::from_scl_text("a", "name a\n2\n100.0\n1200.0\n", None).unwrap();
        let b = Tuning::from_scl_text(
            "b",
            "! comment\nname b\n2 notes\n100.0 suffix\n1200.0 period\n",
            None,
        )
        .unwrap();
        assert_eq!(a.id(), b.id());
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn scale_degree_and_periodic_pitch_validate_bounds() {
        assert_eq!(ScaleDegree::new(11, 12).unwrap().index(), 11);
        assert!(ScaleDegree::new(12, 12).is_err());
        assert!(PeriodicPitch::new(12, 0, 12).is_err());
    }

    #[test]
    fn parser_accepts_configured_maximum_scale() {
        let count = MAX_SCALE_DEGREES;
        let mut scl = format!("large\n{count}\n");
        for index in 1..=count {
            scl.push_str(&format!("{:.8}\n", index as f64));
        }
        let scale = parse_scl(&scl).unwrap();
        assert_eq!(scale.degree_cents.len(), count);
        assert_eq!(scale.period_cents, count as f64);
    }

    #[test]
    fn scala_zero_kbm_shortcuts_resolve_to_the_scale() {
        let tuning = Tuning::from_scl_text(
            "12-TET linear KBM",
            TWELVE_TET_SCL,
            Some("0\n0\n127\n60\n69\n440.0\n0\n"),
        )
        .unwrap();

        assert_eq!(
            tuning.keyboard_mapping(),
            &KeyboardMapping {
                map_size: 12,
                first_midi: 0,
                last_midi: 127,
                middle_midi: 60,
                reference_midi: 69,
                reference_frequency_hz: 440.0,
                formal_period_degree: 12,
                mapping: (0..12).map(Some).collect(),
            }
        );
        assert!((tuning.hz_for_midi(69).unwrap() - 440.0).abs() < 1e-10);
        assert_eq!(
            tuning.periodic_pitch_for_midi(48),
            Some(PeriodicPitch::new(0, -1, 12).unwrap())
        );
        assert_eq!(
            tuning.periodic_pitch_for_midi(72),
            Some(PeriodicPitch::new(0, 1, 12).unwrap())
        );
    }

    #[test]
    fn zero_formal_period_uses_scale_period_for_non_linear_map() {
        let tuning = Tuning::from_scl_text(
            "12-TET two-key pattern",
            TWELVE_TET_SCL,
            Some("2\n0\n127\n60\n60\n261.6255653\n0\n0\n1\n"),
        )
        .unwrap();
        assert_eq!(tuning.keyboard_mapping().formal_period_degree, 12);
        assert_eq!(
            tuning.periodic_pitch_for_midi(62),
            Some(PeriodicPitch::new(0, 1, 12).unwrap())
        );
    }
}
