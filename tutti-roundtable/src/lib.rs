//! Bounded, transport-independent live coordination for Tutti's round-table
//! bass performance.
//!
//! Durable musical parameters live in `tutti-music` and converge through the
//! HHHS adapter. This crate owns only short-lived run epochs, deterministic
//! turn assignment, pulse selection, and a compact body codec. Authentication,
//! replay protection, clocks, retransmission, discovery, and audio remain the
//! caller's responsibility.

#![forbid(unsafe_code)]

use thiserror::Error;
use tutti_music::roundtable::{
    MAX_PLAYABLE_MILLIHZ, MIN_PLAYABLE_MILLIHZ, RoundTableConfig, RoundTablePattern,
    RoundTablePitchMode, RoundTableScale,
};

const MAGIC: [u8; 4] = *b"TRT3";
const KIND_RUN: u8 = 1;
const KIND_PULSE: u8 = 2;
const KIND_CONFIG: u8 = 3;
const CONFIG_BYTES: usize = 4 + 1 + 4 + 1 + 1 + 2 + 2 + 2 + 1 + 16;
const RUN_BYTES: usize = 4 + 1 + 8 + 32 + 8 + 32 + 1 + (CONFIG_BYTES - 5);
const PULSE_BYTES: usize = 4 + 1 + 8 + 32 + 4 + 32 + 4 + 2 + 2;
pub const MAX_FRAME_BYTES: usize = if RUN_BYTES > PULSE_BYTES {
    RUN_BYTES
} else {
    PULSE_BYTES
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ParticipantId([u8; 32]);

impl ParticipantId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A start nonce plus its authenticated origin. Concurrent starts therefore
/// have a deterministic total order without consulting a wall clock.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RunEpoch {
    pub nonce: u64,
    pub origin: ParticipantId,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RunState {
    pub epoch: RunEpoch,
    /// Total-ordered version of the configuration mirrored into this run.
    /// It may advance while `epoch` and the pulse sequence remain stable.
    pub config_version: RunEpoch,
    pub running: bool,
    /// Session copy of the durable HHHS settings, captured at start so the
    /// performance need not wait for a full history repair.
    pub config: RoundTableConfig,
}

/// Resolve a received run state without clocks or arrival-order dependence.
///
/// A higher epoch always wins. Within one epoch, stop dominates start and
/// retains the configuration captured by the accepted start. Consequently, a
/// delayed start from the same or an older epoch cannot resurrect a stopped
/// performance.
pub fn resolve_run_state(current: Option<RunState>, incoming: RunState) -> RunState {
    let Some(current) = current else {
        return incoming;
    };
    if incoming.epoch > current.epoch {
        incoming
    } else if incoming.epoch == current.epoch {
        let (config_version, config) = match incoming.config_version.cmp(&current.config_version) {
            std::cmp::Ordering::Greater => (incoming.config_version, incoming.config),
            std::cmp::Ordering::Less => (current.config_version, current.config),
            // Honest writers never reuse a version for different content.
            // The tie-break keeps malformed/conflicting delivery order-independent.
            std::cmp::Ordering::Equal if incoming.config > current.config => {
                (incoming.config_version, incoming.config)
            }
            std::cmp::Ordering::Equal => (current.config_version, current.config),
        };
        RunState {
            epoch: current.epoch,
            config_version,
            // Stop dominates every same-epoch update. Only a new run epoch
            // can start again.
            running: current.running && incoming.running,
            config,
        }
    } else {
        current
    }
}

/// A configuration intent/confirmation which does not alter run lifecycle.
/// The receiver authors or observes the durable HHHS value, then assigns its
/// own in-run `config_version` if a performance is active.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConfigState {
    pub config: RoundTableConfig,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pulse {
    pub epoch: RunEpoch,
    pub sequence: u32,
    pub target: ParticipantId,
    pub frequency_millihz: u32,
    pub level_per_mille: u16,
    pub duration_ms: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Frame {
    Run(RunState),
    Pulse(Pulse),
    Config(ConfigState),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum FrameError {
    #[error("round-table frame is malformed")]
    Malformed,
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

pub fn encode(frame: Frame) -> EncodedFrame {
    let mut encoded = EncodedFrame {
        bytes: [0; MAX_FRAME_BYTES],
        len: 0,
    };
    encoded.bytes[..4].copy_from_slice(&MAGIC);
    match frame {
        Frame::Run(run) => {
            encoded.bytes[4] = KIND_RUN;
            encoded.bytes[5..13].copy_from_slice(&run.epoch.nonce.to_be_bytes());
            encoded.bytes[13..45].copy_from_slice(run.epoch.origin.as_bytes());
            encoded.bytes[45..53].copy_from_slice(&run.config_version.nonce.to_be_bytes());
            encoded.bytes[53..85].copy_from_slice(run.config_version.origin.as_bytes());
            encoded.bytes[85] = u8::from(run.running);
            encode_config(run.config, &mut encoded.bytes[86..115]);
            encoded.len = RUN_BYTES as u8;
        }
        Frame::Pulse(pulse) => {
            encoded.bytes[4] = KIND_PULSE;
            encoded.bytes[5..13].copy_from_slice(&pulse.epoch.nonce.to_be_bytes());
            encoded.bytes[13..45].copy_from_slice(pulse.epoch.origin.as_bytes());
            encoded.bytes[45..49].copy_from_slice(&pulse.sequence.to_be_bytes());
            encoded.bytes[49..81].copy_from_slice(pulse.target.as_bytes());
            encoded.bytes[81..85].copy_from_slice(&pulse.frequency_millihz.to_be_bytes());
            encoded.bytes[85..87].copy_from_slice(&pulse.level_per_mille.to_be_bytes());
            encoded.bytes[87..89].copy_from_slice(&pulse.duration_ms.to_be_bytes());
            encoded.len = PULSE_BYTES as u8;
        }
        Frame::Config(config) => {
            encoded.bytes[4] = KIND_CONFIG;
            encode_config(config.config, &mut encoded.bytes[5..CONFIG_BYTES]);
            encoded.len = CONFIG_BYTES as u8;
        }
    }
    encoded
}

fn encode_config(config: RoundTableConfig, bytes: &mut [u8]) {
    debug_assert_eq!(bytes.len(), CONFIG_BYTES - 5);
    bytes[0..4].copy_from_slice(&config.center_millihz.to_be_bytes());
    bytes[4] = config.scale.id();
    bytes[5] = config.spread_semitones;
    bytes[6..8].copy_from_slice(&config.level_per_mille.to_be_bytes());
    bytes[8..10].copy_from_slice(&config.pulse_ms.to_be_bytes());
    bytes[10..12].copy_from_slice(&config.gap_ms.to_be_bytes());
    bytes[12] = config.pitch_mode.id();
    let pattern = config.pattern.words();
    bytes[13..21].copy_from_slice(&pattern[0].to_be_bytes());
    bytes[21..29].copy_from_slice(&pattern[1].to_be_bytes());
}

fn decode_config(bytes: &[u8]) -> Result<RoundTableConfig, FrameError> {
    if bytes.len() != CONFIG_BYTES - 5 {
        return Err(FrameError::Malformed);
    }
    RoundTableConfig {
        pitch_mode: RoundTablePitchMode::from_id(bytes[12]).ok_or(FrameError::Malformed)?,
        pattern: RoundTablePattern::from_words([
            u64::from_be_bytes(
                bytes[13..21]
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
            u64::from_be_bytes(
                bytes[21..29]
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
        ]),
        center_millihz: u32::from_be_bytes(
            bytes[0..4].try_into().map_err(|_| FrameError::Malformed)?,
        ),
        scale: RoundTableScale::from_id(bytes[4]).ok_or(FrameError::Malformed)?,
        spread_semitones: bytes[5],
        level_per_mille: u16::from_be_bytes(
            bytes[6..8].try_into().map_err(|_| FrameError::Malformed)?,
        ),
        pulse_ms: u16::from_be_bytes(bytes[8..10].try_into().map_err(|_| FrameError::Malformed)?),
        gap_ms: u16::from_be_bytes(
            bytes[10..12]
                .try_into()
                .map_err(|_| FrameError::Malformed)?,
        ),
    }
    .validate()
    .map_err(|_| FrameError::Malformed)
}

pub fn decode(bytes: &[u8]) -> Result<Frame, FrameError> {
    if bytes.get(..4) != Some(&MAGIC) {
        return Err(FrameError::Malformed);
    }
    let epoch = || {
        Ok::<_, FrameError>(RunEpoch {
            nonce: u64::from_be_bytes(
                bytes
                    .get(5..13)
                    .ok_or(FrameError::Malformed)?
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
            origin: ParticipantId::from_bytes(
                bytes
                    .get(13..45)
                    .ok_or(FrameError::Malformed)?
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
        })
    };
    match (bytes.get(4), bytes.len()) {
        (Some(&KIND_RUN), RUN_BYTES) if matches!(bytes[85], 0 | 1) => Ok(Frame::Run(RunState {
            epoch: epoch()?,
            config_version: RunEpoch {
                nonce: u64::from_be_bytes(
                    bytes[45..53]
                        .try_into()
                        .map_err(|_| FrameError::Malformed)?,
                ),
                origin: ParticipantId::from_bytes(
                    bytes[53..85]
                        .try_into()
                        .map_err(|_| FrameError::Malformed)?,
                ),
            },
            running: bytes[85] == 1,
            config: decode_config(&bytes[86..115])?,
        })),
        (Some(&KIND_PULSE), PULSE_BYTES) => Ok(Frame::Pulse(Pulse {
            epoch: epoch()?,
            sequence: u32::from_be_bytes(
                bytes[45..49]
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
            target: ParticipantId::from_bytes(
                bytes[49..81]
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
            frequency_millihz: u32::from_be_bytes(
                bytes[81..85]
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
            level_per_mille: u16::from_be_bytes(
                bytes[85..87]
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
            duration_ms: u16::from_be_bytes(
                bytes[87..89]
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
        })),
        (Some(&KIND_CONFIG), CONFIG_BYTES) => Ok(Frame::Config(ConfigState {
            config: decode_config(&bytes[5..CONFIG_BYTES])?,
        })),
        _ => Err(FrameError::Malformed),
    }
}

/// Sorted fixed-capacity membership. Transport code may rebuild it from
/// authenticated live peers without allocating or leaking carrier addresses
/// into the session model.
#[derive(Clone, Debug)]
pub struct Roster<const N: usize> {
    members: [Option<ParticipantId>; N],
    len: usize,
}

impl<const N: usize> Default for Roster<N> {
    fn default() -> Self {
        Self {
            members: [None; N],
            len: 0,
        }
    }
}

impl<const N: usize> Roster<N> {
    pub fn insert(&mut self, participant: ParticipantId) -> bool {
        let search = self.search(&participant);
        if search.is_ok() || self.len == N {
            return false;
        }
        let index = search.unwrap_or_else(|index| index);
        for slot in (index..self.len).rev() {
            self.members[slot + 1] = self.members[slot];
        }
        self.members[index] = Some(participant);
        self.len += 1;
        true
    }

    pub fn remove(&mut self, participant: &ParticipantId) -> bool {
        let Ok(index) = self.search(participant) else {
            return false;
        };
        for slot in index..self.len - 1 {
            self.members[slot] = self.members[slot + 1];
        }
        self.len -= 1;
        self.members[self.len] = None;
        true
    }

    fn search(&self, participant: &ParticipantId) -> Result<usize, usize> {
        let mut left = 0;
        let mut right = self.len;
        while left < right {
            let middle = left + (right - left) / 2;
            match self
                .member(middle)
                .expect("roster prefix slots are occupied")
                .cmp(participant)
            {
                std::cmp::Ordering::Less => left = middle + 1,
                std::cmp::Ordering::Greater => right = middle,
                std::cmp::Ordering::Equal => return Ok(middle),
            }
        }
        Err(left)
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn member(&self, index: usize) -> Option<ParticipantId> {
        self.members.get(index).copied().flatten()
    }

    pub fn iter(&self) -> impl Iterator<Item = ParticipantId> + '_ {
        self.members[..self.len]
            .iter()
            .map(|member| member.expect("roster prefix slots are occupied"))
    }

    pub fn leader(&self) -> Option<ParticipantId> {
        self.member(0)
    }

    pub fn target(&self, sequence: u32) -> Option<ParticipantId> {
        (!self.is_empty())
            .then(|| self.member(sequence as usize % self.len))
            .flatten()
    }
}

/// Build the deterministic pulse for one sequence. The carrier's elected
/// leader sends this plan; every peer can independently verify its contents.
pub fn plan_pulse<const N: usize>(
    config: RoundTableConfig,
    roster: &Roster<N>,
    epoch: RunEpoch,
    sequence: u32,
) -> Option<Pulse> {
    let config = config.validate().ok()?;
    let target = roster.target(sequence)?;
    let center_note =
        (69.0 + 12.0 * (f64::from(config.center_millihz) / 440_000.0).log2()).round() as i16;
    let spread = i16::from(config.spread_semitones);
    let first_note = (center_note - spread).clamp(0, 127) as u8;
    let last_note = (center_note + spread).clamp(0, 127) as u8;
    let candidates = (first_note..=last_note)
        .filter(|note| config.pattern.contains_pitch_class(*note))
        .count();
    if candidates == 0 {
        return None;
    }
    let choice = match config.pitch_mode {
        RoundTablePitchMode::Ascending => sequence as usize % candidates,
        RoundTablePitchMode::Random => {
            (mix64(epoch.nonce ^ u64::from(sequence)) % candidates as u64) as usize
        }
    };
    let note = (first_note..=last_note)
        .filter(|note| config.pattern.contains_pitch_class(*note))
        .nth(choice)?;
    let hz = 440.0 * 2.0_f64.powf((f64::from(note) - 69.0) / 12.0);
    let frequency_millihz = (hz * 1_000.0).round().clamp(
        f64::from(MIN_PLAYABLE_MILLIHZ),
        f64::from(MAX_PLAYABLE_MILLIHZ),
    ) as u32;
    Some(Pulse {
        epoch,
        sequence,
        target,
        frequency_millihz,
        level_per_mille: config.level_per_mille,
        duration_ms: config.pulse_ms,
    })
}

fn mix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> ParticipantId {
        ParticipantId::from_bytes([byte; 32])
    }

    #[test]
    fn frame_codec_is_exact_and_rejects_trailing_bytes() {
        let epoch = RunEpoch {
            nonce: 0x1234,
            origin: id(1),
        };
        let frames = [
            Frame::Run(RunState {
                epoch,
                config_version: epoch,
                running: true,
                config: RoundTableConfig::default(),
            }),
            Frame::Pulse(Pulse {
                epoch,
                sequence: 9,
                target: id(2),
                frequency_millihz: 80_000,
                level_per_mille: 300,
                duration_ms: 500,
            }),
            Frame::Config(ConfigState {
                config: RoundTableConfig::default(),
            }),
        ];
        for frame in frames {
            let encoded = encode(frame);
            assert_eq!(decode(encoded.as_bytes()), Ok(frame));
            let mut trailing = encoded.as_bytes().to_vec();
            trailing.push(0);
            assert_eq!(decode(&trailing), Err(FrameError::Malformed));
        }
    }

    #[test]
    fn roster_is_stable_and_turns_include_self() {
        let mut roster = Roster::<4>::default();
        assert!(roster.insert(id(3)));
        assert!(roster.insert(id(1)));
        assert!(roster.insert(id(2)));
        assert!(!roster.insert(id(2)));
        assert_eq!(roster.iter().collect::<Vec<_>>(), [id(1), id(2), id(3)]);
        assert_eq!(roster.leader(), Some(id(1)));
        assert_eq!(roster.target(4), Some(id(2)));
        assert!(roster.remove(&id(2)));
        assert_eq!(roster.iter().collect::<Vec<_>>(), [id(1), id(3)]);
    }

    #[test]
    fn random_mode_is_deterministic_and_never_leaves_the_shared_note_set() {
        let mut roster = Roster::<8>::default();
        roster.insert(id(3));
        roster.insert(id(1));
        let config = RoundTableConfig {
            pitch_mode: RoundTablePitchMode::Random,
            ..RoundTableConfig::default()
        };
        let epoch = RunEpoch {
            nonce: 99,
            origin: id(3),
        };
        for sequence in 0..256 {
            let first = plan_pulse(config, &roster, epoch, sequence).unwrap();
            let second = plan_pulse(config, &roster, epoch, sequence).unwrap();
            assert_eq!(first, second);
            assert!(
                (MIN_PLAYABLE_MILLIHZ..=MAX_PLAYABLE_MILLIHZ).contains(&first.frequency_millihz)
            );
            assert_eq!(first.target, roster.target(sequence).unwrap());
            let midi = (69.0 + 12.0 * (f64::from(first.frequency_millihz) / 440_000.0).log2())
                .round() as u8;
            assert!(config.pattern.contains_pitch_class(midi));
        }
    }

    #[test]
    fn ascending_mode_walks_only_latched_pitch_classes_in_the_shared_register() {
        let mut roster = Roster::<2>::default();
        roster.insert(id(1));
        let config = RoundTableConfig::default();
        let epoch = RunEpoch {
            nonce: 7,
            origin: id(1),
        };
        let expected = [58_270, 65_406, 77_782, 97_999, 58_270];
        for (sequence, frequency) in expected.into_iter().enumerate() {
            let pulse = plan_pulse(config, &roster, epoch, sequence as u32).unwrap();
            assert_eq!(pulse.frequency_millihz, frequency);
            assert_eq!(pulse.target, id(1));
        }
        let empty = RoundTableConfig {
            pattern: RoundTablePattern::from_words([0; 2]),
            ..config
        };
        assert_eq!(plan_pulse(empty, &roster, epoch, 0), None);
    }

    #[test]
    fn palette_metadata_cannot_filter_or_introduce_notes() {
        let mut roster = Roster::<1>::default();
        roster.insert(id(1));
        let epoch = RunEpoch {
            nonce: 17,
            origin: id(1),
        };
        let mut root = RoundTableConfig::default();
        root.scale = RoundTableScale::Root;
        let mut chromatic = root;
        chromatic.scale = RoundTableScale::Chromatic;
        for mode in [RoundTablePitchMode::Ascending, RoundTablePitchMode::Random] {
            root.pitch_mode = mode;
            chromatic.pitch_mode = mode;
            for sequence in 0..32 {
                assert_eq!(
                    plan_pulse(root, &roster, epoch, sequence),
                    plan_pulse(chromatic, &roster, epoch, sequence)
                );
            }
        }
    }

    #[test]
    fn run_state_is_order_independent_and_stale_start_cannot_resurrect() {
        let low = RunEpoch {
            nonce: 10,
            origin: id(1),
        };
        let high = RunEpoch {
            nonce: 11,
            origin: id(2),
        };
        let config = RoundTableConfig::default();
        let stale_start = RunState {
            epoch: low,
            config_version: low,
            running: true,
            config,
        };
        let high_start = RunState {
            epoch: high,
            config_version: high,
            running: true,
            config,
        };
        let high_stop = RunState {
            epoch: high,
            config_version: high,
            running: false,
            config,
        };
        for order in [
            [stale_start, high_start, high_stop],
            [high_stop, stale_start, high_start],
            [high_start, high_stop, stale_start],
        ] {
            let resolved = order
                .into_iter()
                .fold(None, |current, incoming| {
                    Some(resolve_run_state(current, incoming))
                })
                .unwrap();
            assert_eq!(resolved, high_stop);
        }
        assert_eq!(resolve_run_state(Some(high_stop), stale_start), high_stop);
        assert_eq!(resolve_run_state(Some(high_stop), high_start), high_stop);
    }

    #[test]
    fn same_epoch_stop_keeps_the_started_configuration() {
        let epoch = RunEpoch {
            nonce: 42,
            origin: id(1),
        };
        let started = RunState {
            epoch,
            config_version: RunEpoch {
                nonce: 5,
                origin: id(1),
            },
            running: true,
            config: RoundTableConfig::default(),
        };
        let mut conflicting = RoundTableConfig::default();
        conflicting.center_millihz = 90_000;
        let stopped = resolve_run_state(
            Some(started),
            RunState {
                epoch,
                config_version: RunEpoch {
                    nonce: 4,
                    origin: id(2),
                },
                running: false,
                config: conflicting,
            },
        );
        assert!(!stopped.running);
        assert_eq!(stopped.config, started.config);
    }

    #[test]
    fn config_update_preserves_run_epoch_and_advances_the_pattern_at_the_next_sequence() {
        let epoch = RunEpoch {
            nonce: 42,
            origin: id(1),
        };
        let started = RunState {
            epoch,
            config_version: RunEpoch {
                nonce: 1,
                origin: id(1),
            },
            running: true,
            config: RoundTableConfig::default(),
        };
        let mut pattern = RoundTablePattern::default().cleared();
        pattern = pattern.toggled(60).unwrap();
        pattern = pattern.toggled(67).unwrap();
        let updated = resolve_run_state(
            Some(started),
            RunState {
                epoch,
                config_version: RunEpoch {
                    nonce: 2,
                    origin: id(2),
                },
                running: true,
                config: RoundTableConfig {
                    pattern,
                    ..started.config
                },
            },
        );
        assert!(updated.running);
        assert_eq!(updated.epoch, epoch);

        let mut roster = Roster::<1>::default();
        assert!(roster.insert(id(1)));
        let pulse = plan_pulse(updated.config, &roster, epoch, 5).unwrap();
        // Sequence 5 continues from the old run; it is not reset to zero.
        assert_eq!(pulse.sequence, 5);
        assert_eq!(pulse.frequency_millihz, 97_999);
    }
}
