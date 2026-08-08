//! OSC 1.0 message encoding/decoding — the small, exact subset the bridge
//! needs: `i` (int32), `f` (float32), `s` (string) arguments, 4-byte alignment,
//! big-endian. Bundles are deliberately absent until a consumer needs them.

use std::fmt;

/// One OSC argument.
#[derive(Debug, Clone, PartialEq)]
pub enum OscArg {
    Int(i32),
    Float(f32),
    Str(String),
}

/// One OSC message: an address pattern plus typed arguments.
#[derive(Debug, Clone, PartialEq)]
pub struct OscMessage {
    pub addr: String,
    pub args: Vec<OscArg>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OscCodecError {
    /// The packet ended before a complete element was read.
    Truncated,
    /// The address or a string argument was not valid UTF-8.
    BadString,
    /// The type-tag string was missing its leading `,`.
    BadTypeTags,
    /// A type tag this codec does not speak.
    UnsupportedTag(char),
}

impl fmt::Display for OscCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "OSC packet truncated"),
            Self::BadString => write!(f, "OSC string was not valid UTF-8"),
            Self::BadTypeTags => write!(f, "OSC type tags missing the leading ','"),
            Self::UnsupportedTag(tag) => write!(f, "unsupported OSC type tag '{tag}'"),
        }
    }
}

impl std::error::Error for OscCodecError {}

/// Append `s` as an OSC string: NUL-terminated, padded to a 4-byte boundary.
fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// Read an OSC string starting at `*at`; advances past its padding.
fn take_str(bytes: &[u8], at: &mut usize) -> Result<String, OscCodecError> {
    let start = *at;
    let nul = bytes[start..]
        .iter()
        .position(|&b| b == 0)
        .ok_or(OscCodecError::Truncated)?;
    let s = std::str::from_utf8(&bytes[start..start + nul])
        .map_err(|_| OscCodecError::BadString)?
        .to_string();
    // Consume the string, its NUL, and the padding to the next 4-byte boundary.
    let consumed = nul + 1;
    *at = start + consumed.div_ceil(4) * 4;
    if *at > bytes.len() {
        return Err(OscCodecError::Truncated);
    }
    Ok(s)
}

fn take_4(bytes: &[u8], at: &mut usize) -> Result<[u8; 4], OscCodecError> {
    let end = *at + 4;
    if end > bytes.len() {
        return Err(OscCodecError::Truncated);
    }
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[*at..end]);
    *at = end;
    Ok(word)
}

impl OscMessage {
    /// Encode to OSC 1.0 wire bytes: padded address, `,`-prefixed type tags,
    /// then the big-endian arguments.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.addr.len() + 8 + self.args.len() * 4);
        put_str(&mut out, &self.addr);
        let mut tags = String::with_capacity(self.args.len() + 1);
        tags.push(',');
        for arg in &self.args {
            tags.push(match arg {
                OscArg::Int(_) => 'i',
                OscArg::Float(_) => 'f',
                OscArg::Str(_) => 's',
            });
        }
        put_str(&mut out, &tags);
        for arg in &self.args {
            match arg {
                OscArg::Int(value) => out.extend_from_slice(&value.to_be_bytes()),
                OscArg::Float(value) => out.extend_from_slice(&value.to_be_bytes()),
                OscArg::Str(value) => put_str(&mut out, value),
            }
        }
        out
    }

    /// Decode one OSC 1.0 message from wire bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, OscCodecError> {
        let mut at = 0usize;
        let addr = take_str(bytes, &mut at)?;
        let tags = take_str(bytes, &mut at)?;
        let tags = tags.strip_prefix(',').ok_or(OscCodecError::BadTypeTags)?;
        let mut args = Vec::with_capacity(tags.len());
        for tag in tags.chars() {
            args.push(match tag {
                'i' => OscArg::Int(i32::from_be_bytes(take_4(bytes, &mut at)?)),
                'f' => OscArg::Float(f32::from_be_bytes(take_4(bytes, &mut at)?)),
                's' => OscArg::Str(take_str(bytes, &mut at)?),
                other => return Err(OscCodecError::UnsupportedTag(other)),
            });
        }
        Ok(Self { addr, args })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_arg_kind() {
        let msg = OscMessage {
            addr: "/tutti/1/room/degrees".to_string(),
            args: vec![
                OscArg::Float(60.387),
                OscArg::Int(-7),
                OscArg::Str("31-EDO".to_string()),
            ],
        };
        let bytes = msg.encode();
        assert_eq!(bytes.len() % 4, 0, "OSC packets are 4-byte aligned");
        assert_eq!(OscMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn empty_args_round_trip() {
        let msg = OscMessage {
            addr: "/tutti/1/room/degree/4/env".to_string(),
            args: vec![],
        };
        assert_eq!(OscMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn known_wire_layout() {
        // "/a" + NUL + pad, ",i" + NUL + pad, 0x00000001.
        let msg = OscMessage {
            addr: "/a".to_string(),
            args: vec![OscArg::Int(1)],
        };
        assert_eq!(
            msg.encode(),
            vec![b'/', b'a', 0, 0, b',', b'i', 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn truncation_and_bad_tags_are_errors() {
        let msg = OscMessage {
            addr: "/x".to_string(),
            args: vec![OscArg::Int(7)],
        };
        let bytes = msg.encode();
        assert_eq!(
            OscMessage::decode(&bytes[..bytes.len() - 1]),
            Err(OscCodecError::Truncated)
        );
        // Address "/x" followed by a tag string missing its leading ','.
        assert_eq!(
            OscMessage::decode(&[b'/', b'x', 0, 0, b'x', 0, 0, 0]),
            Err(OscCodecError::BadTypeTags)
        );
    }
}
