//! Strict Scala (`.scl`) tuning-file parsing.
//!
//! The format is defined by the Scala scale-file specification. In particular,
//! a pitch token containing `.` is a cents value, while an integer token is an
//! integer ratio (`5` means `5/1`, never five cents). Text following a valid
//! pitch token is descriptive and ignored.

use thiserror::Error;

pub const MAX_SCL_BYTES: usize = 1024 * 1024;
pub const MAX_SCL_LINE_BYTES: usize = 64 * 1024;
pub const MAX_SCALE_DEGREES: usize = 4096;

/// A parsed periodic Scala scale.
///
/// `degree_cents` contains the implicit `1/1` at zero and excludes the final
/// pitch line, because that final line defines `period_cents`.
#[derive(Debug, Clone, PartialEq)]
pub struct SclScale {
    pub description: String,
    pub degree_cents: Vec<f64>,
    pub period_cents: f64,
}

/// Errors produced while parsing or validating an SCL document.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SclParseError {
    #[error("SCL content is empty")]
    Empty,
    #[error("SCL content is {actual} bytes; the maximum is {max}")]
    InputTooLarge { actual: usize, max: usize },
    #[error("line {line} is {actual} bytes; the maximum is {max}")]
    LineTooLong {
        line: usize,
        actual: usize,
        max: usize,
    },
    #[error("missing pitch count")]
    MissingPitchCount,
    #[error("invalid pitch count on line {line}: {value:?}")]
    InvalidPitchCount { line: usize, value: String },
    #[error("pitch count {count} is outside the supported range 1..={max}")]
    PitchCountOutOfRange { count: usize, max: usize },
    #[error("expected exactly {expected} pitch lines, found {actual}")]
    PitchCountMismatch { expected: usize, actual: usize },
    #[error("invalid pitch on line {line}: {value:?} ({reason})")]
    InvalidPitch {
        line: usize,
        value: String,
        reason: &'static str,
    },
    #[error(
        "pitch on line {line} is not strictly above the previous pitch ({previous_cents} cents)"
    )]
    NonAscendingPitch { line: usize, previous_cents: String },
    #[error("the final pitch on line {line} must define a finite positive period")]
    InvalidPeriod { line: usize },
}

/// Parse and validate one complete SCL document.
pub fn parse_scl(content: &str) -> Result<SclScale, SclParseError> {
    if content.len() > MAX_SCL_BYTES {
        return Err(SclParseError::InputTooLarge {
            actual: content.len(),
            max: MAX_SCL_BYTES,
        });
    }

    let mut data_lines = Vec::new();
    for (index, raw) in content.lines().enumerate() {
        let line_number = index + 1;
        if raw.len() > MAX_SCL_LINE_BYTES {
            return Err(SclParseError::LineTooLong {
                line: line_number,
                actual: raw.len(),
                max: MAX_SCL_LINE_BYTES,
            });
        }
        let trimmed = raw.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('!') {
            data_lines.push((line_number, trimmed));
        }
    }

    let Some((_, description)) = data_lines.first().copied() else {
        return Err(SclParseError::Empty);
    };
    let Some((count_line, count_text)) = data_lines.get(1).copied() else {
        return Err(SclParseError::MissingPitchCount);
    };

    let count_token = count_text.split_whitespace().next().unwrap_or_default();
    let pitch_count =
        count_token
            .parse::<usize>()
            .map_err(|_| SclParseError::InvalidPitchCount {
                line: count_line,
                value: count_text.to_owned(),
            })?;
    if !(1..=MAX_SCALE_DEGREES).contains(&pitch_count) {
        return Err(SclParseError::PitchCountOutOfRange {
            count: pitch_count,
            max: MAX_SCALE_DEGREES,
        });
    }

    let pitch_lines = &data_lines[2..];
    if pitch_lines.len() != pitch_count {
        return Err(SclParseError::PitchCountMismatch {
            expected: pitch_count,
            actual: pitch_lines.len(),
        });
    }

    let mut parsed = Vec::with_capacity(pitch_count);
    let mut previous = 0.0;
    for &(line, text) in pitch_lines {
        let cents = parse_pitch_value(line, text)?;
        let is_period = parsed.len() + 1 == pitch_count;
        if is_period && (!cents.is_finite() || cents <= 0.0) {
            return Err(SclParseError::InvalidPeriod { line });
        }
        if cents <= previous {
            return Err(SclParseError::NonAscendingPitch {
                line,
                previous_cents: previous.to_string(),
            });
        }
        previous = cents;
        parsed.push((line, cents));
    }

    let (period_line, period_cents) = parsed.pop().expect("pitch_count is at least one");
    if !period_cents.is_finite() || period_cents <= 0.0 {
        return Err(SclParseError::InvalidPeriod { line: period_line });
    }

    let mut degree_cents = Vec::with_capacity(pitch_count);
    degree_cents.push(0.0);
    degree_cents.extend(parsed.into_iter().map(|(_, cents)| cents));

    Ok(SclScale {
        description: description.to_owned(),
        degree_cents,
        period_cents,
    })
}

fn parse_pitch_value(line: usize, text: &str) -> Result<f64, SclParseError> {
    let token = text.split_whitespace().next().unwrap_or_default();
    let invalid = |reason| SclParseError::InvalidPitch {
        line,
        value: token.to_owned(),
        reason,
    };

    if token.is_empty() {
        return Err(invalid("missing pitch token"));
    }

    let cents = if token.contains('/') {
        let (numerator, denominator) = token
            .split_once('/')
            .ok_or_else(|| invalid("ratio must contain one slash"))?;
        if denominator.contains('/') {
            return Err(invalid("ratio must contain one slash"));
        }
        let numerator = numerator
            .parse::<u128>()
            .map_err(|_| invalid("ratio numerator must be a positive integer"))?;
        let denominator = denominator
            .parse::<u128>()
            .map_err(|_| invalid("ratio denominator must be a positive integer"))?;
        if numerator == 0 || denominator == 0 {
            return Err(invalid("ratio components must be greater than zero"));
        }
        1200.0 * ((numerator as f64) / (denominator as f64)).log2()
    } else if token.contains('.') {
        token
            .parse::<f64>()
            .map_err(|_| invalid("cents value is not a number"))?
    } else {
        let ratio = token
            .parse::<u128>()
            .map_err(|_| invalid("integer pitch must be a positive integer ratio"))?;
        if ratio == 0 {
            return Err(invalid("integer ratio must be greater than zero"));
        }
        1200.0 * (ratio as f64).log2()
    };

    if !cents.is_finite() {
        return Err(invalid("pitch must be finite"));
    }
    Ok(cents)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TET_12: &str = r#"! 12-TET
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

    #[test]
    fn parses_twelve_tet_and_separates_period() {
        let scale = parse_scl(TET_12).unwrap();
        assert_eq!(scale.description, "12-tone equal temperament");
        assert_eq!(scale.degree_cents.len(), 12);
        assert_eq!(scale.degree_cents[0], 0.0);
        assert!((scale.degree_cents[11] - 1100.0).abs() < 1e-12);
        assert!((scale.period_cents - 1200.0).abs() < 1e-12);
    }

    #[test]
    fn integer_is_always_an_integer_ratio_and_suffix_is_ignored() {
        let scale = parse_scl("integer ratios\n2\n5 fifth harmonic\n10/1 period").unwrap();
        assert!((scale.degree_cents[1] - 1200.0 * 5.0_f64.log2()).abs() < 1e-10);
        assert!((scale.period_cents - 1200.0 * 10.0_f64.log2()).abs() < 1e-10);
    }

    #[test]
    fn parses_just_intonation_ratios() {
        let scale = parse_scl("Just major\n7\n9/8\n5/4\n4/3\n3/2\n5/3\n15/8\n2/1\n").unwrap();
        assert_eq!(scale.degree_cents.len(), 7);
        assert!((scale.degree_cents[1] - 203.910_001_7).abs() < 1e-6);
        assert!((scale.degree_cents[4] - 701.955_000_9).abs() < 1e-6);
    }

    #[test]
    fn requires_exact_pitch_count() {
        assert!(matches!(
            parse_scl("short\n2\n100.0\n"),
            Err(SclParseError::PitchCountMismatch {
                expected: 2,
                actual: 1
            })
        ));
        assert!(matches!(
            parse_scl("long\n1\n1200.0\n2400.0\n"),
            Err(SclParseError::PitchCountMismatch {
                expected: 1,
                actual: 2
            })
        ));
    }

    #[test]
    fn rejects_zero_ratio_nonascending_and_missing_period() {
        assert!(matches!(
            parse_scl("zero\n1\n0/1\n"),
            Err(SclParseError::InvalidPitch { .. })
        ));
        assert!(matches!(
            parse_scl("descending\n2\n700.0\n600.0\n"),
            Err(SclParseError::NonAscendingPitch { .. })
        ));
        assert!(matches!(
            parse_scl("no pitches\n1\n"),
            Err(SclParseError::PitchCountMismatch { .. })
        ));
    }
}
