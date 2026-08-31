//! Compact, carrier-independent realtime payloads for Tutti sessions.
//!
//! Authentication, replay protection, fragmentation, clocks, and durable
//! confirmation belong to the surrounding session/carrier. This crate owns
//! only bounded musical payloads. Existing round-table frames are embedded
//! byte-for-byte rather than reimplemented.

#![forbid(unsafe_code)]

use thiserror::Error;

const MIDI_MAGIC: [u8; 4] = *b"TMI1";
/// Compatibility generation for every payload accepted by [`decode`].
///
/// This advances whenever an existing realtime payload changes incompatibly.
/// Carriers must negotiate it before sending realtime frames; the four-byte
/// per-frame magics remain useful corruption/type guards, not negotiation.
pub const WIRE_GENERATION: u8 = 4;
pub const MIDI_FRAME_BYTES: usize = 4 + 1 + 4 + 1 + 1 + 2;
pub const MAX_FRAME_BYTES: usize = if MIDI_FRAME_BYTES > tutti_roundtable::MAX_FRAME_BYTES {
    MIDI_FRAME_BYTES
} else {
    tutti_roundtable::MAX_FRAME_BYTES
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum MidiKind {
    NoteOn = 1,
    NoteOff = 2,
    Choke = 3,
    PolyPressure = 4,
    PitchBend = 5,
    ChannelPressure = 6,
}

impl MidiKind {
    fn from_byte(byte: u8) -> Result<Self, FrameError> {
        match byte {
            1 => Ok(Self::NoteOn),
            2 => Ok(Self::NoteOff),
            3 => Ok(Self::Choke),
            4 => Ok(Self::PolyPressure),
            5 => Ok(Self::PitchBend),
            6 => Ok(Self::ChannelPressure),
            _ => Err(FrameError::Malformed),
        }
    }
}

/// One MIDI-shaped transient event.
///
/// DAW sample offsets are intentionally absent: they are local scheduling
/// metadata and have no stable meaning after radio/network transit. Receivers
/// schedule the event at their next safe boundary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MidiFrame {
    /// CLAP/MPE voice identity, or `-1` when the source has none.
    pub voice_id: i32,
    pub channel: u8,
    pub note: u8,
    pub kind: MidiKind,
    /// Normalized 0..=65535 value for velocity, pressure, or pitch bend.
    pub value: u16,
}

impl MidiFrame {
    pub const NO_VOICE_ID: i32 = -1;

    pub fn from_normalized(
        voice_id: i32,
        channel: u8,
        note: u8,
        kind: MidiKind,
        value: f32,
    ) -> Result<Self, FrameError> {
        let normalized = if value.is_finite() {
            value.clamp(0.0, 1.0)
        } else {
            return Err(FrameError::Malformed);
        };
        let frame = Self {
            voice_id,
            channel,
            note,
            kind,
            value: (normalized * f32::from(u16::MAX)).round() as u16,
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn normalized_value(self) -> f32 {
        f32::from(self.value) / f32::from(u16::MAX)
    }

    fn validate(self) -> Result<(), FrameError> {
        if self.channel > 15 || self.note > 127 {
            return Err(FrameError::Malformed);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Frame {
    Midi(MidiFrame),
    RoundTable(tutti_roundtable::Frame),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EncodedFrame {
    bytes: [u8; MAX_FRAME_BYTES],
    len: u8,
}

impl EncodedFrame {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum FrameError {
    #[error("realtime frame is malformed")]
    Malformed,
}

pub fn encode(frame: Frame) -> Result<EncodedFrame, FrameError> {
    let mut encoded = EncodedFrame {
        bytes: [0; MAX_FRAME_BYTES],
        len: 0,
    };
    match frame {
        Frame::Midi(midi) => {
            midi.validate()?;
            encoded.bytes[..4].copy_from_slice(&MIDI_MAGIC);
            encoded.bytes[4] = midi.kind as u8;
            encoded.bytes[5..9].copy_from_slice(&midi.voice_id.to_be_bytes());
            encoded.bytes[9] = midi.channel;
            encoded.bytes[10] = midi.note;
            encoded.bytes[11..13].copy_from_slice(&midi.value.to_be_bytes());
            encoded.len = MIDI_FRAME_BYTES as u8;
        }
        Frame::RoundTable(round_table) => {
            let round_table = tutti_roundtable::encode(round_table);
            encoded.bytes[..round_table.as_bytes().len()].copy_from_slice(round_table.as_bytes());
            encoded.len = round_table.as_bytes().len() as u8;
        }
    }
    Ok(encoded)
}

pub fn decode(bytes: &[u8]) -> Result<Frame, FrameError> {
    if bytes.get(..4) == Some(&MIDI_MAGIC) {
        if bytes.len() != MIDI_FRAME_BYTES {
            return Err(FrameError::Malformed);
        }
        let frame = MidiFrame {
            kind: MidiKind::from_byte(bytes[4])?,
            voice_id: i32::from_be_bytes(
                bytes[5..9].try_into().map_err(|_| FrameError::Malformed)?,
            ),
            channel: bytes[9],
            note: bytes[10],
            value: u16::from_be_bytes(
                bytes[11..13]
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
        };
        frame.validate()?;
        Ok(Frame::Midi(frame))
    } else {
        tutti_roundtable::decode(bytes)
            .map(Frame::RoundTable)
            .map_err(|_| FrameError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use tutti_roundtable::{ParticipantId, RunEpoch, RunState};

    use super::*;

    #[test]
    fn midi_frame_is_compact_strict_and_stable() {
        let midi =
            MidiFrame::from_normalized(0x0102_0304, 2, 67, MidiKind::PitchBend, 0.5).unwrap();
        let encoded = encode(Frame::Midi(midi)).unwrap();
        assert_eq!(
            encoded.as_bytes(),
            &[0x54, 0x4d, 0x49, 0x31, 5, 1, 2, 3, 4, 2, 67, 0x80, 0x00]
        );
        assert_eq!(decode(encoded.as_bytes()), Ok(Frame::Midi(midi)));

        let mut trailing = encoded.as_bytes().to_vec();
        trailing.push(0);
        assert_eq!(decode(&trailing), Err(FrameError::Malformed));
    }

    #[test]
    fn round_table_wire_is_embedded_byte_for_byte() {
        let epoch = RunEpoch {
            nonce: 9,
            origin: ParticipantId::from_bytes([7; 32]),
        };
        let round_table = tutti_roundtable::Frame::Run(RunState {
            epoch,
            config_version: epoch,
            running: true,
            config: Default::default(),
        });
        let canonical = tutti_roundtable::encode(round_table);
        let realtime = encode(Frame::RoundTable(round_table)).unwrap();
        assert_eq!(realtime.as_bytes(), canonical.as_bytes());
        assert_eq!(
            decode(realtime.as_bytes()),
            Ok(Frame::RoundTable(round_table))
        );
    }
}
