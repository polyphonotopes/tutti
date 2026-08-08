//! Scala keyboard-mapping (`.kbm`) parsing.

use thiserror::Error;

use super::scl::{MAX_SCALE_DEGREES, MAX_SCL_BYTES, MAX_SCL_LINE_BYTES};

/// A Scala keyboard mapping. Mapping entries are scale-degree numbers relative
/// to `middle_midi`; `None` is an unmapped `x` key.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyboardMapping {
    pub map_size: u16,
    pub first_midi: u8,
    pub last_midi: u8,
    pub middle_midi: u8,
    pub reference_midi: u8,
    pub reference_frequency_hz: f64,
    pub formal_period_degree: i32,
    pub mapping: Vec<Option<i32>>,
}

impl KeyboardMapping {
    /// Deterministic mapping used when a room supplies only an SCL file.
    ///
    /// Degree zero is C4 (MIDI 60) at 261.6255653 Hz, keys cycle through every
    /// scale degree, and one key-cycle advances one scale period.
    pub fn default_for_scale(degree_count: usize) -> Result<Self, KbmParseError> {
        if !(1..=MAX_SCALE_DEGREES).contains(&degree_count) {
            return Err(KbmParseError::MapSizeOutOfRange {
                size: degree_count,
                max: MAX_SCALE_DEGREES,
            });
        }
        let map_size = degree_count as u16;
        Ok(Self {
            map_size,
            first_midi: 0,
            last_midi: 127,
            middle_midi: 60,
            reference_midi: 60,
            reference_frequency_hz: 261.625_565_3,
            formal_period_degree: i32::from(map_size),
            mapping: (0..map_size)
                .map(|degree| Some(i32::from(degree)))
                .collect(),
        })
    }

    /// Resolve the two context-sensitive shortcuts defined by Scala's KBM
    /// format. A zero-sized map is linear, while formal period degree zero
    /// means the scale's final (repeating) degree.
    pub(crate) fn resolve_for_scale(mut self, degree_count: usize) -> Self {
        let degree_count =
            i32::try_from(degree_count).expect("validated scale sizes fit in an i32");
        if self.map_size == 0 {
            self.map_size = degree_count as u16;
            self.mapping = (0..degree_count).map(Some).collect();
            self.formal_period_degree = degree_count;
        } else if self.formal_period_degree == 0 {
            self.formal_period_degree = degree_count;
        }
        self
    }

    /// Map a MIDI key to an absolute scale-degree number. The result may be
    /// negative; callers split it into a Euclidean period and degree.
    pub fn absolute_degree_for_midi(&self, midi: u8) -> Option<i32> {
        if midi < self.first_midi || midi > self.last_midi {
            return None;
        }
        let offset = i32::from(midi) - i32::from(self.middle_midi);
        // Raw zero-sized KBMs are Scala's linear-mapping shorthand. Tunings
        // normalize this before storing or hashing the mapping.
        if self.map_size == 0 {
            return Some(offset);
        }
        let map_size = i32::from(self.map_size);
        let cycle = offset.div_euclid(map_size);
        let slot = offset.rem_euclid(map_size) as usize;
        self.mapping
            .get(slot)
            .copied()
            .flatten()?
            .checked_add(cycle.checked_mul(self.formal_period_degree)?)
    }

    pub(crate) fn append_canonical_bytes(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.map_size.to_be_bytes());
        output.push(self.first_midi);
        output.push(self.last_midi);
        output.push(self.middle_midi);
        output.push(self.reference_midi);
        output.extend_from_slice(&self.reference_frequency_hz.to_bits().to_be_bytes());
        output.extend_from_slice(&self.formal_period_degree.to_be_bytes());
        for entry in &self.mapping {
            match entry {
                Some(degree) => {
                    output.push(1);
                    output.extend_from_slice(&degree.to_be_bytes());
                }
                None => output.push(0),
            }
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum KbmParseError {
    #[error("KBM content is empty")]
    Empty,
    #[error("KBM content is {actual} bytes; the maximum is {max}")]
    InputTooLarge { actual: usize, max: usize },
    #[error("line {line} is {actual} bytes; the maximum is {max}")]
    LineTooLong {
        line: usize,
        actual: usize,
        max: usize,
    },
    #[error("KBM needs seven header values, found {actual}")]
    MissingHeader { actual: usize },
    #[error("invalid {field} on line {line}: {value:?}")]
    InvalidField {
        field: &'static str,
        line: usize,
        value: String,
    },
    #[error("mapping size {size} is outside the supported range 0..={max}")]
    MapSizeOutOfRange { size: usize, max: usize },
    #[error("first MIDI note must not be above last MIDI note")]
    ReversedMidiRange,
    #[error("reference frequency must be finite and greater than zero")]
    InvalidReferenceFrequency,
    #[error("mapping declares at most {expected} entries, found {actual}")]
    TooManyMappingEntries { expected: usize, actual: usize },
}

pub fn parse_kbm(content: &str) -> Result<KeyboardMapping, KbmParseError> {
    if content.len() > MAX_SCL_BYTES {
        return Err(KbmParseError::InputTooLarge {
            actual: content.len(),
            max: MAX_SCL_BYTES,
        });
    }

    let mut lines = Vec::new();
    for (index, raw) in content.lines().enumerate() {
        let line_number = index + 1;
        if raw.len() > MAX_SCL_LINE_BYTES {
            return Err(KbmParseError::LineTooLong {
                line: line_number,
                actual: raw.len(),
                max: MAX_SCL_LINE_BYTES,
            });
        }
        let trimmed = raw.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('!') {
            lines.push((line_number, trimmed));
        }
    }
    if lines.is_empty() {
        return Err(KbmParseError::Empty);
    }
    if lines.len() < 7 {
        return Err(KbmParseError::MissingHeader {
            actual: lines.len(),
        });
    }

    let parse = |index: usize, field: &'static str| -> Result<&str, KbmParseError> {
        let (line, value) = lines[index];
        value
            .split_whitespace()
            .next()
            .ok_or_else(|| KbmParseError::InvalidField {
                field,
                line,
                value: value.to_owned(),
            })
    };
    let parse_u16 = |index, field| -> Result<u16, KbmParseError> {
        let token = parse(index, field)?;
        token.parse().map_err(|_| KbmParseError::InvalidField {
            field,
            line: lines[index].0,
            value: token.to_owned(),
        })
    };
    let parse_u8 = |index, field| -> Result<u8, KbmParseError> {
        let token = parse(index, field)?;
        token.parse().map_err(|_| KbmParseError::InvalidField {
            field,
            line: lines[index].0,
            value: token.to_owned(),
        })
    };

    let map_size = parse_u16(0, "mapping size")?;
    if usize::from(map_size) > MAX_SCALE_DEGREES {
        return Err(KbmParseError::MapSizeOutOfRange {
            size: usize::from(map_size),
            max: MAX_SCALE_DEGREES,
        });
    }
    let first_midi = parse_u8(1, "first MIDI note")?;
    let last_midi = parse_u8(2, "last MIDI note")?;
    if first_midi > last_midi {
        return Err(KbmParseError::ReversedMidiRange);
    }
    let middle_midi = parse_u8(3, "middle MIDI note")?;
    let reference_midi = parse_u8(4, "reference MIDI note")?;
    let reference_token = parse(5, "reference frequency")?;
    let reference_frequency_hz =
        reference_token
            .parse::<f64>()
            .map_err(|_| KbmParseError::InvalidField {
                field: "reference frequency",
                line: lines[5].0,
                value: reference_token.to_owned(),
            })?;
    if !reference_frequency_hz.is_finite() || reference_frequency_hz <= 0.0 {
        return Err(KbmParseError::InvalidReferenceFrequency);
    }
    let formal_period_token = parse(6, "formal period degree")?;
    let formal_period_degree =
        formal_period_token
            .parse::<i32>()
            .map_err(|_| KbmParseError::InvalidField {
                field: "formal period degree",
                line: lines[6].0,
                value: formal_period_token.to_owned(),
            })?;

    let mapping_lines = &lines[7..];
    if mapping_lines.len() > usize::from(map_size) {
        return Err(KbmParseError::TooManyMappingEntries {
            expected: usize::from(map_size),
            actual: mapping_lines.len(),
        });
    }
    let mut mapping = Vec::with_capacity(usize::from(map_size));
    for &(line, text) in mapping_lines {
        let token = text.split_whitespace().next().unwrap_or_default();
        if token.eq_ignore_ascii_case("x") {
            mapping.push(None);
        } else {
            let degree = token
                .parse::<i32>()
                .map_err(|_| KbmParseError::InvalidField {
                    field: "mapping degree",
                    line,
                    value: token.to_owned(),
                })?;
            mapping.push(Some(degree));
        }
    }
    mapping.resize(usize::from(map_size), None);

    Ok(KeyboardMapping {
        map_size,
        first_midi,
        last_midi,
        middle_midi,
        reference_midi,
        reference_frequency_hz,
        formal_period_degree,
        mapping,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCALA_DOCUMENTATION_TEMPLATE: &str = r#"
! Template from the Scala keyboard-mapping documentation.
12
0
127
60
69
440.0
12
0
1
2
3
4
5
6
7
8
9
10
11
"#;

    #[test]
    fn parses_official_template() {
        let mapping = parse_kbm(SCALA_DOCUMENTATION_TEMPLATE).unwrap();
        assert_eq!(mapping.absolute_degree_for_midi(60), Some(0));
        assert_eq!(mapping.absolute_degree_for_midi(69), Some(9));
        assert_eq!(mapping.absolute_degree_for_midi(72), Some(12));
    }

    #[test]
    fn parses_mapping_with_unmapped_key() {
        let mapping = parse_kbm("3\n0\n127\n60\n60\n261.6255653\n3\n0\nx\n2\n").unwrap();
        assert_eq!(mapping.absolute_degree_for_midi(60), Some(0));
        assert_eq!(mapping.absolute_degree_for_midi(61), None);
        assert_eq!(mapping.absolute_degree_for_midi(63), Some(3));
        assert_eq!(mapping.absolute_degree_for_midi(59), Some(-1));
    }

    #[test]
    fn default_mapping_is_c4_root_and_periodic() {
        let mapping = KeyboardMapping::default_for_scale(12).unwrap();
        assert_eq!(mapping.absolute_degree_for_midi(60), Some(0));
        assert_eq!(mapping.absolute_degree_for_midi(69), Some(9));
        assert_eq!(mapping.absolute_degree_for_midi(72), Some(12));
    }

    #[test]
    fn zero_size_is_linear_and_trailing_unmapped_entries_may_be_omitted() {
        let linear = parse_kbm("0\n0\n127\n60\n69\n440.0\n0\n").unwrap();
        assert_eq!(linear.absolute_degree_for_midi(48), Some(-12));
        assert_eq!(linear.absolute_degree_for_midi(72), Some(12));

        let sparse = parse_kbm("3\n0\n127\n60\n60\n261.6255653\n3\n0\n").unwrap();
        assert_eq!(sparse.mapping, vec![Some(0), None, None]);
        assert_eq!(sparse.absolute_degree_for_midi(61), None);
    }

    #[test]
    fn accepts_signed_degrees_and_rejects_excess_entries() {
        let mapping = parse_kbm("3\n0\n127\n60\n60\n261.6255653\n-3\n-2\n0\n3\n").unwrap();
        assert_eq!(mapping.absolute_degree_for_midi(60), Some(-2));
        assert_eq!(mapping.absolute_degree_for_midi(63), Some(-5));

        assert!(matches!(
            parse_kbm("2\n0\n127\n60\n60\n440.0\n2\n0\n1\nx\n"),
            Err(KbmParseError::TooManyMappingEntries {
                expected: 2,
                actual: 3
            })
        ));
    }
}
