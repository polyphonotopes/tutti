//! Bounded, platform-neutral framing for a Tutti BLE GATT link.
//!
//! This crate does not open a Bluetooth adapter. A phone, plugin host, or
//! embedded application owns discovery, connection policy, GATT callbacks,
//! queues, and reconnect supervision. This crate owns only the byte-exact
//! interoperability waist shared by those hosts:
//!
//! - a fixed service/characteristic identity;
//! - a boot-scoped peer hello used to bind [`tutti_session`] handshakes;
//! - bounded fragmentation below the GATT characteristic-value limit;
//! - authenticated multiplexing of control, realtime, and HHHS repair lanes;
//! - an [`hhhs_sync::FrameStream`] adapter over an application-demultiplexed
//!   repair lane.
//!
//! The authenticated session currently provides integrity and peer
//! authentication, not confidentiality. Hosts that deliberately avoid BLE
//! pairing must not put secrets in these frames.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, future::Future};

use hhhs_sync::FrameStream;
use thiserror::Error;
use tutti_session::{
    ANSWER_BYTES, Answer, ChannelBinding, OFFER_BYTES, Offer, PeerIdentity, ProtocolId,
    ReplayError, ReplayWindow, SessionError, SessionKeys, TAG_BYTES,
};

/// Canonical, network-byte-order UUID for the Tutti bridge GATT service.
pub const SERVICE_UUID: u128 = 0x9de5_a180_6c44_4f43_a754_f44b_cf12_0201;
/// Phone/host to ESP characteristic: write or write-without-response.
pub const RX_CHARACTERISTIC_UUID: u128 = 0x9de5_a180_6c44_4f43_a754_f44b_cf12_0202;
/// ESP to phone/host characteristic: notify.
pub const TX_CHARACTERISTIC_UUID: u128 = 0x9de5_a180_6c44_4f43_a754_f44b_cf12_0203;
/// Read/notify bootstrap and status characteristic.
pub const INFO_CHARACTERISTIC_UUID: u128 = 0x9de5_a180_6c44_4f43_a754_f44b_cf12_0204;

pub const CAPABILITY_REALTIME: u32 = 1 << 0;
pub const CAPABILITY_HHHS_REPAIR: u32 = 1 << 1;
pub const CAPABILITY_BLE_MIDI_COEXISTENCE: u32 = 1 << 2;

// Authenticated lane-profile capabilities are distinct from the boot/GATT
// capabilities above. Keep their names separate so a transport feature cannot
// accidentally be interpreted as an application lane.
pub const PROFILE_CAP_MUSIC: u32 = 1 << 0;
pub const PROFILE_CAP_HHHS_REPAIR: u32 = 1 << 1;
pub const PROFILE_CAP_REALTIME: u32 = 1 << 2;
pub const PROFILE_CAP_WALKIE_EXTENSION: u32 = 1 << 3;

// The authenticated lane profile uses the high byte of its capability word
// for the realtime payload generation. Keeping this inside TBP2 means a peer
// can be refused with a useful compatibility error before either side sends
// musical payloads.
const REALTIME_GENERATION_SHIFT: u32 = 24;
const REALTIME_GENERATION_MASK: u32 = 0xff << REALTIME_GENERATION_SHIFT;

pub const fn with_realtime_generation(capabilities: u32, generation: u8) -> u32 {
    (capabilities & !REALTIME_GENERATION_MASK) | ((generation as u32) << REALTIME_GENERATION_SHIFT)
}

pub const fn realtime_generation(capabilities: u32) -> u8 {
    ((capabilities & REALTIME_GENERATION_MASK) >> REALTIME_GENERATION_SHIFT) as u8
}

const HELLO_MAGIC: [u8; 4] = *b"TBH1";
const WIRE_MAGIC: [u8; 4] = *b"TBL1";
const FRAGMENT_MAGIC: [u8; 2] = *b"TB";
const FRAGMENT_VERSION: u8 = 1;
const WIRE_OFFER: u8 = 1;
const WIRE_ANSWER: u8 = 2;
const WIRE_AUTHENTICATED: u8 = 3;
const CONTROL_MAGIC: [u8; 4] = *b"TBC1";
const CONTROL_PROFILE: u8 = 1;
const CONTROL_CAPABILITY_BUNDLE: u8 = 2;
const CONTROL_REPAIR_FIN: u8 = 3;
const CONTROL_REPAIR_ACK: u8 = 4;
const CONTROL_CAPABILITY_READY: u8 = 5;
// TBP3 additionally binds the canonical music vocabulary and complete Replica
// record ceiling. These are room policy, never a per-link negotiated minimum.
const PROFILE_MAGIC: [u8; 4] = *b"TBP3";
const FLAG_START: u8 = 1 << 0;
const FLAG_END: u8 = 1 << 1;
const KNOWN_FRAGMENT_FLAGS: u8 = FLAG_START | FLAG_END;
const AUTHENTICATED_HEADER_BYTES: usize = 4 + 1 + 8 + 8 + 1 + 2;

pub const HELLO_BYTES: usize = 4 + 32 + 8 + 2 + 4;
pub const FRAGMENT_HEADER_BYTES: usize = 2 + 1 + 1 + 2 + 2 + 2;
pub const MIN_FRAGMENT_VALUE_BYTES: usize = FRAGMENT_HEADER_BYTES + 1;
pub const HARD_MAX_WIRE_BYTES: usize = u16::MAX as usize;
pub const AUTHENTICATED_FRAME_OVERHEAD_BYTES: usize = AUTHENTICATED_HEADER_BYTES + TAG_BYTES;
pub const MAX_BOOTSTRAP_WIRE_BYTES: usize = 5 + ANSWER_BYTES;
pub const HARD_MAX_PAYLOAD_BYTES: usize = HARD_MAX_WIRE_BYTES - AUTHENTICATED_FRAME_OVERHEAD_BYTES;
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 4 * 1024;
pub const SESSION_PROTOCOL_LABEL: &[u8] = b"tutti BLE bridge session v1";
pub const PROFILE_BYTES: usize = 4 + 4 * 9;
pub const CONTROL_FRAME_HEADER_BYTES: usize = 5;
pub const CONTROL_PROFILE_BYTES: usize = CONTROL_FRAME_HEADER_BYTES + PROFILE_BYTES;
pub const REPAIR_ATTEMPT_ID_BYTES: usize = 16;
pub const CONTROL_REPAIR_LIFECYCLE_BYTES: usize =
    CONTROL_FRAME_HEADER_BYTES + REPAIR_ATTEMPT_ID_BYTES + 8;
pub const CONTROL_CAPABILITY_READY_BYTES: usize = CONTROL_FRAME_HEADER_BYTES + 32;

pub const fn complete_wire_ceiling(max_payload_bytes: usize) -> Option<usize> {
    let authenticated = match max_payload_bytes.checked_add(AUTHENTICATED_FRAME_OVERHEAD_BYTES) {
        Some(value) => value,
        None => return None,
    };
    Some(if authenticated > MAX_BOOTSTRAP_WIRE_BYTES {
        authenticated
    } else {
        MAX_BOOTSTRAP_WIRE_BYTES
    })
}

/// Exact signed-session protocol identifier shared by every Tutti BLE host.
pub fn session_protocol_id() -> ProtocolId {
    ProtocolId::derive(SESSION_PROTOCOL_LABEL)
}

/// Authenticated control-lane compatibility and allocation profile.
///
/// The GATT MTU remains in [`PeerHello`]; these limits apply after complete
/// message reassembly. A peer may reduce them after negotiation, never expand
/// its local allocation budget to satisfy the remote endpoint.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LaneProfile {
    pub music_generation: u32,
    pub music_vocabulary_generation: u32,
    pub max_replica_record_bytes: u32,
    pub hhhs_strategy_version: u32,
    pub hhhs_repair_generation: u32,
    pub application_generation: u32,
    pub capabilities: u32,
    pub max_authenticated_payload_bytes: u32,
    pub max_repair_frame_bytes: u32,
}

impl LaneProfile {
    pub fn encode(self) -> [u8; PROFILE_BYTES] {
        let mut bytes = [0; PROFILE_BYTES];
        bytes[..4].copy_from_slice(&PROFILE_MAGIC);
        for (index, value) in [
            self.music_generation,
            self.music_vocabulary_generation,
            self.max_replica_record_bytes,
            self.hhhs_strategy_version,
            self.hhhs_repair_generation,
            self.application_generation,
            self.capabilities,
            self.max_authenticated_payload_bytes,
            self.max_repair_frame_bytes,
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 4 + index * 4;
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BleWireError> {
        if bytes.len() != PROFILE_BYTES || bytes[..4] != PROFILE_MAGIC {
            return Err(BleWireError::MalformedProfile);
        }
        let value = |index: usize| {
            let offset = 4 + index * 4;
            u32::from_be_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .expect("validated profile layout"),
            )
        };
        let profile = Self {
            music_generation: value(0),
            music_vocabulary_generation: value(1),
            max_replica_record_bytes: value(2),
            hhhs_strategy_version: value(3),
            hhhs_repair_generation: value(4),
            application_generation: value(5),
            capabilities: value(6),
            max_authenticated_payload_bytes: value(7),
            max_repair_frame_bytes: value(8),
        };
        if profile.music_vocabulary_generation == 0
            || profile.max_replica_record_bytes == 0
            || profile.max_authenticated_payload_bytes == 0
            || profile.max_authenticated_payload_bytes as usize > HARD_MAX_PAYLOAD_BYTES
            || profile.max_repair_frame_bytes == 0
            || profile.max_repair_frame_bytes as usize > HARD_MAX_WIRE_BYTES
        {
            return Err(BleWireError::MalformedProfile);
        }
        Ok(profile)
    }
}

/// Link/session-bound identifier for one BLE repair attempt.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RepairAttemptId([u8; REPAIR_ATTEMPT_ID_BYTES]);

impl RepairAttemptId {
    pub const fn new(bytes: [u8; REPAIR_ATTEMPT_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; REPAIR_ATTEMPT_ID_BYTES] {
        self.0
    }
}

/// Carrier close declaration sent only after the local HHHS attempt reaches a
/// terminal outcome. The sequence names the final authenticated repair-lane
/// message belonging to this attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RepairFin {
    pub attempt: RepairAttemptId,
    pub last_repair_sequence: u64,
}

/// Symmetric carrier acknowledgement for the peer's authenticated FIN.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RepairAck {
    pub attempt: RepairAttemptId,
    pub fin_sequence: u64,
}

/// Authenticated BLE close state for one HHHS repair attempt.
///
/// HHHS `Done`/`Ack` establishes the causal result; this state establishes
/// that both BLE directions carried the complete terminal prefix. EOF,
/// disconnect, queue acceptance, or a FIN for another attempt never closes an
/// attempt successfully.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RepairCloseState {
    attempt: RepairAttemptId,
    local_terminal: bool,
    local_last_repair_sequence: Option<u64>,
    local_fin_sequence: Option<u64>,
    local_fin_acked: bool,
    remote_last_repair_sequence: Option<u64>,
    remote_fin: Option<RepairFin>,
    remote_fin_sequence: Option<u64>,
    remote_ack_sequence: Option<u64>,
    remote_ack_confirmed: bool,
}

impl RepairCloseState {
    pub const fn new(attempt: RepairAttemptId) -> Self {
        Self {
            attempt,
            local_terminal: false,
            local_last_repair_sequence: None,
            local_fin_sequence: None,
            local_fin_acked: false,
            remote_last_repair_sequence: None,
            remote_fin: None,
            remote_fin_sequence: None,
            remote_ack_sequence: None,
            remote_ack_confirmed: false,
        }
    }

    pub const fn attempt(&self) -> RepairAttemptId {
        self.attempt
    }

    pub const fn has_local_fin(&self) -> bool {
        self.local_fin_sequence.is_some()
    }

    pub const fn has_remote_ack(&self) -> bool {
        self.remote_ack_sequence.is_some()
    }

    pub const fn local_fin_pending(&self) -> bool {
        self.local_terminal
            && self.local_last_repair_sequence.is_some()
            && self.local_fin_sequence.is_none()
    }

    pub fn remote_ack_pending(&self) -> bool {
        self.local_terminal
            && match self.remote_fin {
                Some(fin) => {
                    self.remote_last_repair_sequence == Some(fin.last_repair_sequence)
                        && self.remote_ack_sequence.is_none()
                }
                None => false,
            }
    }

    pub fn observe_local_repair(&mut self, sequence: u64) -> Result<(), RepairCloseError> {
        if self.local_fin_sequence.is_some() {
            return Err(RepairCloseError::RepairAfterFin);
        }
        if self
            .local_last_repair_sequence
            .is_some_and(|previous| sequence <= previous)
        {
            return Err(RepairCloseError::NonMonotonicRepairSequence);
        }
        self.local_last_repair_sequence = Some(sequence);
        Ok(())
    }

    pub fn observe_remote_repair(&mut self, sequence: u64) -> Result<(), RepairCloseError> {
        if self
            .remote_last_repair_sequence
            .is_some_and(|previous| sequence <= previous)
        {
            return Err(RepairCloseError::NonMonotonicRepairSequence);
        }
        if self
            .remote_fin
            .is_some_and(|fin| sequence > fin.last_repair_sequence)
        {
            return Err(RepairCloseError::RepairAfterFin);
        }
        self.remote_last_repair_sequence = Some(sequence);
        Ok(())
    }

    pub fn mark_local_terminal(&mut self) {
        self.local_terminal = true;
    }

    pub fn local_fin(&self) -> Result<RepairFin, RepairCloseError> {
        if !self.local_terminal {
            return Err(RepairCloseError::FinBeforeTerminal);
        }
        let last_repair_sequence = self
            .local_last_repair_sequence
            .ok_or(RepairCloseError::MissingRepairPrefix)?;
        if self.local_fin_sequence.is_some() {
            return Err(RepairCloseError::DuplicateFin);
        }
        Ok(RepairFin {
            attempt: self.attempt,
            last_repair_sequence,
        })
    }

    pub fn observe_local_fin_encoded(&mut self, sequence: u64) -> Result<(), RepairCloseError> {
        if !self.local_terminal {
            return Err(RepairCloseError::FinBeforeTerminal);
        }
        if self.local_fin_sequence.is_some() {
            return Err(RepairCloseError::DuplicateFin);
        }
        self.local_fin_sequence = Some(sequence);
        Ok(())
    }

    pub fn observe_remote_fin(
        &mut self,
        fin: RepairFin,
        fin_sequence: u64,
    ) -> Result<(), RepairCloseError> {
        if fin.attempt != self.attempt {
            return Err(RepairCloseError::WrongAttempt);
        }
        if let Some(current) = self.remote_fin {
            return if current == fin && self.remote_fin_sequence == Some(fin_sequence) {
                Ok(())
            } else {
                Err(RepairCloseError::ConflictingFin)
            };
        }
        if self
            .remote_last_repair_sequence
            .is_some_and(|sequence| sequence > fin.last_repair_sequence)
        {
            return Err(RepairCloseError::RepairAfterFin);
        }
        self.remote_fin = Some(fin);
        self.remote_fin_sequence = Some(fin_sequence);
        Ok(())
    }

    pub fn remote_ack(&self) -> Result<RepairAck, RepairCloseError> {
        if !self.local_terminal {
            return Err(RepairCloseError::FinBeforeTerminal);
        }
        let fin = self.remote_fin.ok_or(RepairCloseError::MissingRemoteFin)?;
        if self.remote_last_repair_sequence != Some(fin.last_repair_sequence) {
            return Err(RepairCloseError::MissingRepairPrefix);
        }
        if self.remote_ack_sequence.is_some() {
            return Err(RepairCloseError::DuplicateAck);
        }
        Ok(RepairAck {
            attempt: self.attempt,
            fin_sequence: self
                .remote_fin_sequence
                .ok_or(RepairCloseError::MissingRemoteFin)?,
        })
    }

    pub fn observe_remote_ack_encoded(&mut self, sequence: u64) -> Result<(), RepairCloseError> {
        // Re-run the readiness checks so an ACK can never be recorded merely
        // because a caller constructed the public value by hand.
        let _ = self.remote_ack()?;
        self.remote_ack_sequence = Some(sequence);
        Ok(())
    }

    pub fn confirm_remote_ack_sent(&mut self, sequence: u64) -> Result<(), RepairCloseError> {
        if self.remote_ack_sequence != Some(sequence) {
            return Err(RepairCloseError::WrongAckSequence);
        }
        self.remote_ack_confirmed = true;
        Ok(())
    }

    pub fn observe_local_fin_ack(&mut self, ack: RepairAck) -> Result<(), RepairCloseError> {
        if ack.attempt != self.attempt {
            return Err(RepairCloseError::WrongAttempt);
        }
        if self.local_fin_sequence != Some(ack.fin_sequence) {
            return Err(RepairCloseError::WrongAckSequence);
        }
        self.local_fin_acked = true;
        Ok(())
    }

    pub const fn is_confirmed_closed(&self) -> bool {
        self.local_terminal
            && self.local_fin_acked
            && self.remote_fin.is_some()
            && self.remote_ack_confirmed
    }
}

/// Derive the carrier attempt identity from the authenticated link placement
/// and the byte-exact HHHS opening frame. Both endpoints therefore agree
/// without adding an unauthenticated repair-begin message.
pub fn repair_attempt_id(session_id: u64, opening_frame: &[u8]) -> RepairAttemptId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tutti BLE HHHS repair attempt v1");
    hasher.update(&session_id.to_be_bytes());
    hasher.update(opening_frame);
    let digest = hasher.finalize();
    let mut attempt = [0; REPAIR_ATTEMPT_ID_BYTES];
    attempt.copy_from_slice(&digest.as_bytes()[..REPAIR_ATTEMPT_ID_BYTES]);
    RepairAttemptId::new(attempt)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum RepairCloseError {
    #[error("repair lifecycle message belongs to another attempt")]
    WrongAttempt,
    #[error("repair sequence did not advance monotonically")]
    NonMonotonicRepairSequence,
    #[error("repair frame arrived after FIN")]
    RepairAfterFin,
    #[error("repair FIN was requested before the HHHS attempt became terminal")]
    FinBeforeTerminal,
    #[error("repair attempt has no authenticated frame prefix")]
    MissingRepairPrefix,
    #[error("repair FIN is duplicated")]
    DuplicateFin,
    #[error("repair FIN conflicts with the previously authenticated FIN")]
    ConflictingFin,
    #[error("remote repair FIN has not arrived")]
    MissingRemoteFin,
    #[error("repair ACK is duplicated")]
    DuplicateAck,
    #[error("repair ACK names another authenticated FIN sequence")]
    WrongAckSequence,
}

/// Leaf acknowledgement that the exact receiver-bound bundle was imported,
/// every selected leaf is available, and the current device identity matches
/// the receiver proven by the authenticated session.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapabilityReady {
    pub bundle_digest: [u8; 32],
}

/// Versioned authenticated control-lane message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ControlFrame<'a> {
    Profile(LaneProfile),
    CapabilityBundle(&'a [u8]),
    RepairFin(RepairFin),
    RepairAck(RepairAck),
    CapabilityReady(CapabilityReady),
}

fn encode_control_body(kind: u8, body: &[u8]) -> Result<Vec<u8>, BleWireError> {
    let total = CONTROL_FRAME_HEADER_BYTES.checked_add(body.len()).ok_or(
        BleWireError::PayloadTooLarge {
            actual: usize::MAX,
            maximum: HARD_MAX_PAYLOAD_BYTES,
        },
    )?;
    if total > HARD_MAX_PAYLOAD_BYTES {
        return Err(BleWireError::PayloadTooLarge {
            actual: total,
            maximum: HARD_MAX_PAYLOAD_BYTES,
        });
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&CONTROL_MAGIC);
    bytes.push(kind);
    bytes.extend_from_slice(body);
    Ok(bytes)
}

pub fn encode_control_profile(profile: LaneProfile) -> Vec<u8> {
    encode_control_body(CONTROL_PROFILE, &profile.encode())
        .expect("the fixed control profile fits the hard payload ceiling")
}

pub fn encode_control_capability_bundle(bundle: &[u8]) -> Result<Vec<u8>, BleWireError> {
    encode_control_body(CONTROL_CAPABILITY_BUNDLE, bundle)
}

pub fn encode_control_repair_fin(fin: RepairFin) -> Vec<u8> {
    let mut body = [0; REPAIR_ATTEMPT_ID_BYTES + 8];
    body[..REPAIR_ATTEMPT_ID_BYTES].copy_from_slice(&fin.attempt.as_bytes());
    body[REPAIR_ATTEMPT_ID_BYTES..].copy_from_slice(&fin.last_repair_sequence.to_be_bytes());
    encode_control_body(CONTROL_REPAIR_FIN, &body)
        .expect("the fixed repair FIN fits the hard payload ceiling")
}

pub fn encode_control_repair_ack(ack: RepairAck) -> Vec<u8> {
    let mut body = [0; REPAIR_ATTEMPT_ID_BYTES + 8];
    body[..REPAIR_ATTEMPT_ID_BYTES].copy_from_slice(&ack.attempt.as_bytes());
    body[REPAIR_ATTEMPT_ID_BYTES..].copy_from_slice(&ack.fin_sequence.to_be_bytes());
    encode_control_body(CONTROL_REPAIR_ACK, &body)
        .expect("the fixed repair ACK fits the hard payload ceiling")
}

pub fn encode_control_capability_ready(ready: CapabilityReady) -> Vec<u8> {
    encode_control_body(CONTROL_CAPABILITY_READY, &ready.bundle_digest)
        .expect("the fixed capability-ready acknowledgement fits the hard payload ceiling")
}

pub fn decode_control_frame(bytes: &[u8]) -> Result<ControlFrame<'_>, BleWireError> {
    if bytes.len() < CONTROL_FRAME_HEADER_BYTES || bytes[..4] != CONTROL_MAGIC {
        return Err(BleWireError::MalformedControlFrame);
    }
    let body = &bytes[CONTROL_FRAME_HEADER_BYTES..];
    match bytes[4] {
        CONTROL_PROFILE => Ok(ControlFrame::Profile(LaneProfile::decode(body)?)),
        CONTROL_CAPABILITY_BUNDLE => Ok(ControlFrame::CapabilityBundle(body)),
        CONTROL_REPAIR_FIN | CONTROL_REPAIR_ACK => {
            let expected = REPAIR_ATTEMPT_ID_BYTES + 8;
            if body.len() != expected {
                return Err(BleWireError::MalformedControlFrame);
            }
            let mut attempt = [0; REPAIR_ATTEMPT_ID_BYTES];
            attempt.copy_from_slice(&body[..REPAIR_ATTEMPT_ID_BYTES]);
            let sequence = u64::from_be_bytes(
                body[REPAIR_ATTEMPT_ID_BYTES..]
                    .try_into()
                    .expect("validated repair lifecycle control layout"),
            );
            let attempt = RepairAttemptId::new(attempt);
            if bytes[4] == CONTROL_REPAIR_FIN {
                Ok(ControlFrame::RepairFin(RepairFin {
                    attempt,
                    last_repair_sequence: sequence,
                }))
            } else {
                Ok(ControlFrame::RepairAck(RepairAck {
                    attempt,
                    fin_sequence: sequence,
                }))
            }
        }
        CONTROL_CAPABILITY_READY => {
            let bundle_digest = body
                .try_into()
                .map_err(|_| BleWireError::MalformedControlFrame)?;
            Ok(ControlFrame::CapabilityReady(CapabilityReady {
                bundle_digest,
            }))
        }
        kind => Err(BleWireError::UnknownControlFrame(kind)),
    }
}

/// One boot-scoped endpoint description exchanged before the signed session
/// offer. The hello is not trusted on its own: the subsequent signed offer or
/// answer must contain the same persistent identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PeerHello {
    pub identity: PeerIdentity,
    pub boot_nonce: u64,
    /// Largest complete GATT characteristic value this endpoint accepts,
    /// including the Tutti fragment header.
    pub max_fragment_value_bytes: u16,
    pub capabilities: u32,
}

impl PeerHello {
    pub fn encode(self) -> [u8; HELLO_BYTES] {
        let mut bytes = [0; HELLO_BYTES];
        bytes[..4].copy_from_slice(&HELLO_MAGIC);
        bytes[4..36].copy_from_slice(self.identity.as_bytes());
        bytes[36..44].copy_from_slice(&self.boot_nonce.to_be_bytes());
        bytes[44..46].copy_from_slice(&self.max_fragment_value_bytes.to_be_bytes());
        bytes[46..50].copy_from_slice(&self.capabilities.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BleWireError> {
        if bytes.len() != HELLO_BYTES || bytes[..4] != HELLO_MAGIC {
            return Err(BleWireError::MalformedHello);
        }
        let hello = Self {
            identity: PeerIdentity::from_bytes(
                bytes[4..36]
                    .try_into()
                    .map_err(|_| BleWireError::MalformedHello)?,
            ),
            boot_nonce: u64::from_be_bytes(
                bytes[36..44]
                    .try_into()
                    .map_err(|_| BleWireError::MalformedHello)?,
            ),
            max_fragment_value_bytes: u16::from_be_bytes(
                bytes[44..46]
                    .try_into()
                    .map_err(|_| BleWireError::MalformedHello)?,
            ),
            capabilities: u32::from_be_bytes(
                bytes[46..50]
                    .try_into()
                    .map_err(|_| BleWireError::MalformedHello)?,
            ),
        };
        if usize::from(hello.max_fragment_value_bytes) < MIN_FRAGMENT_VALUE_BYTES {
            return Err(BleWireError::FragmentValueTooSmall {
                actual: usize::from(hello.max_fragment_value_bytes),
                minimum: MIN_FRAGMENT_VALUE_BYTES,
            });
        }
        Ok(hello)
    }

    pub const fn supports(self, capability: u32) -> bool {
        self.capabilities & capability == capability
    }
}

/// Bind the signed session transcript to both persistent identities, both
/// fresh boot epochs, and the exact BLE service generation. Roles are ordered:
/// swapping initiator and responder intentionally produces another binding.
pub fn channel_binding(initiator: PeerHello, responder: PeerHello) -> ChannelBinding {
    let mut context = [0; 4 + HELLO_BYTES * 2];
    context[..4].copy_from_slice(b"TCB1");
    context[4..4 + HELLO_BYTES].copy_from_slice(&initiator.encode());
    context[4 + HELLO_BYTES..].copy_from_slice(&responder.encode());
    ChannelBinding::derive(&context)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Lane {
    /// Handshake extensions, liveness, and link supervision after admission.
    Control = 0,
    /// Compact notes, pitch, tempo, gestures, and round-table pulses.
    Realtime = 1,
    /// Byte-exact `hhhs-sync` repair frames.
    HhhsRepair = 2,
}

impl Lane {
    fn from_byte(value: u8) -> Result<Self, BleWireError> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::Realtime),
            2 => Ok(Self::HhhsRepair),
            _ => Err(BleWireError::UnknownLane(value)),
        }
    }
}

pub fn encode_offer(offer: &Offer) -> Vec<u8> {
    encode_bootstrap(WIRE_OFFER, offer.as_bytes())
}

pub fn decode_offer(bytes: &[u8]) -> Result<Offer, BleWireError> {
    let body = decode_bootstrap(bytes, WIRE_OFFER, OFFER_BYTES)?;
    Offer::decode(body).map_err(BleWireError::Session)
}

pub fn encode_answer(answer: &Answer) -> Vec<u8> {
    encode_bootstrap(WIRE_ANSWER, answer.as_bytes())
}

pub fn decode_answer(bytes: &[u8]) -> Result<Answer, BleWireError> {
    let body = decode_bootstrap(bytes, WIRE_ANSWER, ANSWER_BYTES)?;
    Answer::decode(body).map_err(BleWireError::Session)
}

fn encode_bootstrap(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(5 + body.len());
    bytes.extend_from_slice(&WIRE_MAGIC);
    bytes.push(kind);
    bytes.extend_from_slice(body);
    bytes
}

fn decode_bootstrap(
    bytes: &[u8],
    expected_kind: u8,
    body_bytes: usize,
) -> Result<&[u8], BleWireError> {
    if bytes.len() != 5 + body_bytes || bytes[..4] != WIRE_MAGIC || bytes[4] != expected_kind {
        return Err(BleWireError::MalformedBootstrap);
    }
    Ok(&bytes[5..])
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthenticatedMessage {
    pub lane: Lane,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EncodedAuthenticatedMessage {
    pub sequence: u64,
    pub wire: Vec<u8>,
}

/// Stateful authenticated codec for one established BLE connection.
///
/// Sequence numbers and the replay window are directional. Create one codec
/// per connection and discard it on reconnect; never share one across peers.
pub struct SessionCodec {
    keys: SessionKeys,
    next_send_sequence: u64,
    receive_replay: ReplayWindow,
    max_payload_bytes: usize,
}

impl SessionCodec {
    pub fn new(keys: SessionKeys, max_payload_bytes: usize) -> Result<Self, BleWireError> {
        if max_payload_bytes > HARD_MAX_PAYLOAD_BYTES {
            return Err(BleWireError::PayloadTooLarge {
                actual: max_payload_bytes,
                maximum: HARD_MAX_PAYLOAD_BYTES,
            });
        }
        Ok(Self {
            keys,
            next_send_sequence: 0,
            receive_replay: ReplayWindow::default(),
            max_payload_bytes,
        })
    }

    pub const fn session_id(&self) -> u64 {
        self.keys.session_id()
    }

    pub const fn peer(&self) -> PeerIdentity {
        self.keys.peer()
    }

    pub const fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }

    /// Reduce the accepted and emitted authenticated payload budget after the
    /// remote control profile is verified.
    pub fn restrict_max_payload_bytes(&mut self, maximum: usize) -> Result<(), BleWireError> {
        if maximum == 0 || maximum > self.max_payload_bytes {
            return Err(BleWireError::InvalidPayloadRestriction {
                current: self.max_payload_bytes,
                requested: maximum,
            });
        }
        self.max_payload_bytes = maximum;
        Ok(())
    }

    pub fn encode(&mut self, lane: Lane, payload: &[u8]) -> Result<Vec<u8>, BleWireError> {
        self.encode_with_sequence(lane, payload)
            .map(|message| message.wire)
    }

    /// Encode one authenticated message while retaining the sequence needed
    /// by repair FIN/Ack fencing. The sequence is carrier metadata and never
    /// enters HHHS canonical or repair-frame bytes.
    pub fn encode_with_sequence(
        &mut self,
        lane: Lane,
        payload: &[u8],
    ) -> Result<EncodedAuthenticatedMessage, BleWireError> {
        if payload.len() > self.max_payload_bytes {
            return Err(BleWireError::PayloadTooLarge {
                actual: payload.len(),
                maximum: self.max_payload_bytes,
            });
        }
        let payload_len =
            u16::try_from(payload.len()).map_err(|_| BleWireError::PayloadTooLarge {
                actual: payload.len(),
                maximum: self.max_payload_bytes.min(u16::MAX as usize),
            })?;
        let sequence = self.next_send_sequence;
        self.next_send_sequence = self
            .next_send_sequence
            .checked_add(1)
            .ok_or(BleWireError::SequenceExhausted)?;

        let mut bytes = Vec::with_capacity(AUTHENTICATED_HEADER_BYTES + payload.len() + TAG_BYTES);
        bytes.extend_from_slice(&WIRE_MAGIC);
        bytes.push(WIRE_AUTHENTICATED);
        bytes.extend_from_slice(&self.keys.session_id().to_be_bytes());
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.push(lane as u8);
        bytes.extend_from_slice(&payload_len.to_be_bytes());
        bytes.extend_from_slice(payload);
        let tag = self.keys.authenticate(&bytes);
        bytes.extend_from_slice(&tag);
        Ok(EncodedAuthenticatedMessage {
            sequence,
            wire: bytes,
        })
    }

    pub fn decode(&mut self, bytes: &[u8]) -> Result<AuthenticatedMessage, BleWireError> {
        let minimum = AUTHENTICATED_HEADER_BYTES + TAG_BYTES;
        if bytes.len() < minimum || bytes[..4] != WIRE_MAGIC || bytes[4] != WIRE_AUTHENTICATED {
            return Err(BleWireError::MalformedAuthenticatedFrame);
        }
        let session_id = u64::from_be_bytes(
            bytes[5..13]
                .try_into()
                .map_err(|_| BleWireError::MalformedAuthenticatedFrame)?,
        );
        if session_id != self.keys.session_id() {
            return Err(BleWireError::WrongSession);
        }
        let sequence = u64::from_be_bytes(
            bytes[13..21]
                .try_into()
                .map_err(|_| BleWireError::MalformedAuthenticatedFrame)?,
        );
        let lane = Lane::from_byte(bytes[21])?;
        let payload_len = usize::from(u16::from_be_bytes(
            bytes[22..24]
                .try_into()
                .map_err(|_| BleWireError::MalformedAuthenticatedFrame)?,
        ));
        if payload_len > self.max_payload_bytes {
            return Err(BleWireError::PayloadTooLarge {
                actual: payload_len,
                maximum: self.max_payload_bytes,
            });
        }
        let signed_len = AUTHENTICATED_HEADER_BYTES
            .checked_add(payload_len)
            .ok_or(BleWireError::MalformedAuthenticatedFrame)?;
        if bytes.len() != signed_len + TAG_BYTES {
            return Err(BleWireError::MalformedAuthenticatedFrame);
        }
        self.keys
            .verify(&bytes[..signed_len], &bytes[signed_len..])
            .map_err(BleWireError::Session)?;
        self.receive_replay
            .check_and_mark(sequence)
            .map_err(BleWireError::Replay)?;
        Ok(AuthenticatedMessage {
            lane,
            sequence,
            payload: bytes[AUTHENTICATED_HEADER_BYTES..signed_len].to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Fragment<'a> {
    pub message_id: u16,
    pub total_bytes: u16,
    pub offset: u16,
    pub start: bool,
    pub end: bool,
    pub payload: &'a [u8],
}

impl Fragment<'_> {
    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, BleWireError> {
        let required = FRAGMENT_HEADER_BYTES + self.payload.len();
        if output.len() < required {
            return Err(BleWireError::FragmentOutputTooSmall {
                required,
                actual: output.len(),
            });
        }
        output[..2].copy_from_slice(&FRAGMENT_MAGIC);
        output[2] = FRAGMENT_VERSION;
        output[3] = (u8::from(self.start) * FLAG_START) | (u8::from(self.end) * FLAG_END);
        output[4..6].copy_from_slice(&self.message_id.to_be_bytes());
        output[6..8].copy_from_slice(&self.total_bytes.to_be_bytes());
        output[8..10].copy_from_slice(&self.offset.to_be_bytes());
        output[10..required].copy_from_slice(self.payload);
        Ok(required)
    }
}

pub fn decode_fragment(bytes: &[u8]) -> Result<Fragment<'_>, BleWireError> {
    if bytes.len() < FRAGMENT_HEADER_BYTES
        || bytes[..2] != FRAGMENT_MAGIC
        || bytes[2] != FRAGMENT_VERSION
        || bytes[3] & !KNOWN_FRAGMENT_FLAGS != 0
    {
        return Err(BleWireError::MalformedFragment);
    }
    let flags = bytes[3];
    let message_id = u16::from_be_bytes(
        bytes[4..6]
            .try_into()
            .map_err(|_| BleWireError::MalformedFragment)?,
    );
    let total_bytes = u16::from_be_bytes(
        bytes[6..8]
            .try_into()
            .map_err(|_| BleWireError::MalformedFragment)?,
    );
    let offset = u16::from_be_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| BleWireError::MalformedFragment)?,
    );
    let payload = &bytes[FRAGMENT_HEADER_BYTES..];
    let end_offset = usize::from(offset)
        .checked_add(payload.len())
        .ok_or(BleWireError::MalformedFragment)?;
    let total = usize::from(total_bytes);
    let start = flags & FLAG_START != 0;
    let end = flags & FLAG_END != 0;
    let empty_message = total == 0 && offset == 0 && payload.is_empty() && start && end;
    if (!empty_message && payload.is_empty())
        || end_offset > total
        || start != (offset == 0)
        || end != (end_offset == total)
    {
        return Err(BleWireError::MalformedFragment);
    }
    Ok(Fragment {
        message_id,
        total_bytes,
        offset,
        start,
        end,
        payload,
    })
}

/// Allocation-free iterator over borrowed logical-message fragments.
pub struct Fragmenter<'a> {
    message_id: u16,
    bytes: &'a [u8],
    value_bytes: usize,
    offset: usize,
    emitted_empty: bool,
}

impl<'a> Fragmenter<'a> {
    pub fn new(message_id: u16, bytes: &'a [u8], value_bytes: usize) -> Result<Self, BleWireError> {
        if value_bytes < MIN_FRAGMENT_VALUE_BYTES {
            return Err(BleWireError::FragmentValueTooSmall {
                actual: value_bytes,
                minimum: MIN_FRAGMENT_VALUE_BYTES,
            });
        }
        if bytes.len() > HARD_MAX_WIRE_BYTES {
            return Err(BleWireError::WireMessageTooLarge {
                actual: bytes.len(),
                maximum: HARD_MAX_WIRE_BYTES,
            });
        }
        Ok(Self {
            message_id,
            bytes,
            value_bytes,
            offset: 0,
            emitted_empty: false,
        })
    }
}

impl<'a> Iterator for Fragmenter<'a> {
    type Item = Fragment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let total_bytes = u16::try_from(self.bytes.len()).ok()?;
        if self.bytes.is_empty() {
            if self.emitted_empty {
                return None;
            }
            self.emitted_empty = true;
            return Some(Fragment {
                message_id: self.message_id,
                total_bytes,
                offset: 0,
                start: true,
                end: true,
                payload: &[],
            });
        }
        if self.offset == self.bytes.len() {
            return None;
        }
        let start = self.offset;
        let end = (start + self.value_bytes - FRAGMENT_HEADER_BYTES).min(self.bytes.len());
        self.offset = end;
        Some(Fragment {
            message_id: self.message_id,
            total_bytes,
            offset: u16::try_from(start).ok()?,
            start: start == 0,
            end: end == self.bytes.len(),
            payload: &self.bytes[start..end],
        })
    }
}

/// Owned, incremental fragmentation cursor.
///
/// Queue owners retain one bounded authenticated wire message and materialize
/// at most one GATT value at a time. This avoids duplicating a 1.5 KiB repair
/// frame into a hundred tiny queue allocations and permits a scheduler to
/// interleave higher-priority message fragments explicitly.
pub struct FragmentCursor {
    message_id: u16,
    bytes: Vec<u8>,
    value_bytes: usize,
    offset: usize,
    emitted_empty: bool,
}

impl FragmentCursor {
    pub fn new(message_id: u16, bytes: Vec<u8>, value_bytes: usize) -> Result<Self, BleWireError> {
        Fragmenter::new(message_id, &bytes, value_bytes)?;
        Ok(Self {
            message_id,
            bytes,
            value_bytes,
            offset: 0,
            emitted_empty: false,
        })
    }

    pub fn retained_wire_bytes(&self) -> usize {
        self.bytes.len()
    }

    pub const fn fragment_value_bytes(&self) -> usize {
        self.value_bytes
    }

    pub fn is_complete(&self) -> bool {
        (self.bytes.is_empty() && self.emitted_empty)
            || (!self.bytes.is_empty() && self.offset == self.bytes.len())
    }

    pub fn encode_next(&mut self, output: &mut [u8]) -> Result<Option<usize>, BleWireError> {
        let total_bytes =
            u16::try_from(self.bytes.len()).map_err(|_| BleWireError::WireMessageTooLarge {
                actual: self.bytes.len(),
                maximum: HARD_MAX_WIRE_BYTES,
            })?;
        if self.bytes.is_empty() {
            if self.emitted_empty {
                return Ok(None);
            }
            let used = Fragment {
                message_id: self.message_id,
                total_bytes,
                offset: 0,
                start: true,
                end: true,
                payload: &[],
            }
            .encode_into(output)?;
            self.emitted_empty = true;
            return Ok(Some(used));
        }
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let start = self.offset;
        let end = (start + self.value_bytes - FRAGMENT_HEADER_BYTES).min(self.bytes.len());
        let used = Fragment {
            message_id: self.message_id,
            total_bytes,
            offset: u16::try_from(start).map_err(|_| BleWireError::MalformedFragment)?,
            start: start == 0,
            end: end == self.bytes.len(),
            payload: &self.bytes[start..end],
        }
        .encode_into(output)?;
        self.offset = end;
        Ok(Some(used))
    }
}

struct PartialMessage {
    message_id: u16,
    total_bytes: u16,
    next_offset: u16,
    bytes: Vec<u8>,
}

/// Bounded reassembler for a small number of interleaved logical messages.
///
/// Both the message count and total declared assembly bytes are capped before
/// allocation. A host should use one instance per direction and reset it when
/// the authenticated connection closes.
pub struct Reassembler {
    budget: ReassemblyBudget,
    retained_partial_bytes: usize,
    partials: BTreeMap<u16, PartialMessage>,
}

pub const MAX_INTERLEAVED_REASSEMBLIES: u8 = 8;

/// Allocation and concurrency limits for one BLE receive direction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReassemblyBudget {
    max_wire_bytes: usize,
    max_partial_messages: u8,
    max_total_partial_bytes: usize,
}

impl ReassemblyBudget {
    pub fn new(
        max_wire_bytes: usize,
        max_partial_messages: u8,
        max_total_partial_bytes: usize,
    ) -> Result<Self, BleWireError> {
        if max_wire_bytes == 0
            || max_wire_bytes > HARD_MAX_WIRE_BYTES
            || max_partial_messages == 0
            || max_partial_messages > MAX_INTERLEAVED_REASSEMBLIES
            || max_total_partial_bytes == 0
        {
            return Err(BleWireError::InvalidReassemblyBudget);
        }
        Ok(Self {
            max_wire_bytes,
            max_partial_messages,
            max_total_partial_bytes,
        })
    }

    pub fn single(max_wire_bytes: usize) -> Result<Self, BleWireError> {
        Self::new(max_wire_bytes, 1, max_wire_bytes)
    }

    pub const fn max_wire_bytes(self) -> usize {
        self.max_wire_bytes
    }

    pub const fn max_partial_messages(self) -> u8 {
        self.max_partial_messages
    }

    pub const fn max_total_partial_bytes(self) -> usize {
        self.max_total_partial_bytes
    }
}

impl Reassembler {
    pub fn new(max_wire_bytes: usize) -> Result<Self, BleWireError> {
        Self::with_budget(ReassemblyBudget::single(max_wire_bytes)?)
    }

    /// Create a reassembler that permits a bounded number of fragmented
    /// logical messages to make progress concurrently. A lane-aware sender can
    /// therefore yield between repair fragments for control or realtime while
    /// total retained assembly memory remains explicit.
    pub fn with_budget(budget: ReassemblyBudget) -> Result<Self, BleWireError> {
        Ok(Self {
            budget,
            retained_partial_bytes: 0,
            partials: BTreeMap::new(),
        })
    }

    pub fn reset(&mut self) {
        self.partials.clear();
        self.retained_partial_bytes = 0;
    }

    pub const fn retained_partial_bytes(&self) -> usize {
        self.retained_partial_bytes
    }

    pub const fn budget(&self) -> ReassemblyBudget {
        self.budget
    }

    pub fn restrict_budget(&mut self, budget: ReassemblyBudget) -> Result<(), BleWireError> {
        if budget.max_wire_bytes > self.budget.max_wire_bytes
            || budget.max_partial_messages > self.budget.max_partial_messages
            || budget.max_total_partial_bytes > self.budget.max_total_partial_bytes
            || self.partials.len() > usize::from(budget.max_partial_messages)
            || self.retained_partial_bytes > budget.max_total_partial_bytes
            || self
                .partials
                .values()
                .any(|partial| usize::from(partial.total_bytes) > budget.max_wire_bytes)
        {
            return Err(BleWireError::InvalidReassemblyBudget);
        }
        self.budget = budget;
        Ok(())
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, BleWireError> {
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.reset();
        }
        result
    }

    fn push_inner(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, BleWireError> {
        let fragment = decode_fragment(bytes)?;
        let total = usize::from(fragment.total_bytes);
        if total > self.budget.max_wire_bytes {
            return Err(BleWireError::WireMessageTooLarge {
                actual: total,
                maximum: self.budget.max_wire_bytes,
            });
        }
        if fragment.start {
            if self.partials.contains_key(&fragment.message_id)
                || self.partials.len() == usize::from(self.budget.max_partial_messages)
            {
                return Err(BleWireError::InterleavedMessages);
            }
            let retained = self.retained_partial_bytes.checked_add(total).ok_or(
                BleWireError::PartialAssemblyBudgetExceeded {
                    requested: usize::MAX,
                    maximum: self.budget.max_total_partial_bytes,
                },
            )?;
            if retained > self.budget.max_total_partial_bytes {
                return Err(BleWireError::PartialAssemblyBudgetExceeded {
                    requested: retained,
                    maximum: self.budget.max_total_partial_bytes,
                });
            }
            let mut assembled = Vec::new();
            assembled
                .try_reserve_exact(total)
                .map_err(|_| BleWireError::AllocationFailed(total))?;
            self.partials.insert(
                fragment.message_id,
                PartialMessage {
                    message_id: fragment.message_id,
                    total_bytes: fragment.total_bytes,
                    next_offset: 0,
                    bytes: assembled,
                },
            );
            self.retained_partial_bytes = retained;
        }
        let partial = self
            .partials
            .get_mut(&fragment.message_id)
            .ok_or(BleWireError::MissingFragmentStart)?;
        if partial.message_id != fragment.message_id
            || partial.total_bytes != fragment.total_bytes
            || partial.next_offset != fragment.offset
        {
            return Err(BleWireError::FragmentDiscontinuity);
        }
        partial.bytes.extend_from_slice(fragment.payload);
        partial.next_offset = partial
            .next_offset
            .checked_add(
                u16::try_from(fragment.payload.len())
                    .map_err(|_| BleWireError::MalformedFragment)?,
            )
            .ok_or(BleWireError::MalformedFragment)?;
        if !fragment.end {
            return Ok(None);
        }
        let complete = self
            .partials
            .remove(&fragment.message_id)
            .ok_or(BleWireError::MissingFragmentStart)?;
        self.retained_partial_bytes = self
            .retained_partial_bytes
            .saturating_sub(usize::from(complete.total_bytes));
        if complete.bytes.len() != total {
            return Err(BleWireError::FragmentDiscontinuity);
        }
        Ok(Some(complete.bytes))
    }
}

/// A bounded queue or platform task endpoint dedicated to lane 2. The BLE
/// owner performs GATT I/O, fragmentation, authentication, and lane routing;
/// this narrow interface keeps all of those concerns out of HHHS.
pub trait RepairFrameIo {
    type Error: std::error::Error + Send + Sync + 'static;

    fn send_repair_frame(&mut self, frame: &[u8]) -> impl Future<Output = Result<(), Self::Error>>;

    fn receive_repair_frame(
        &mut self,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, Self::Error>>;

    /// Complete the carrier's explicit repair close handshake. Returning
    /// success means the peer confirmed the terminal boundary; EOF alone is
    /// never repair success.
    fn close(self) -> impl Future<Output = Result<(), Self::Error>>;
}

/// Adapt an application-demultiplexed BLE repair lane to HHHS's carrier seam.
pub struct BleRepairStream<I> {
    io: I,
}

impl<I> BleRepairStream<I> {
    pub const fn new(io: I) -> Self {
        Self { io }
    }

    pub const fn inner(&self) -> &I {
        &self.io
    }

    pub fn inner_mut(&mut self) -> &mut I {
        &mut self.io
    }

    pub fn into_inner(self) -> I {
        self.io
    }
}

impl<I: RepairFrameIo> FrameStream for BleRepairStream<I> {
    type Error = I::Error;

    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.io.send_repair_frame(frame).await
    }

    async fn recv_frame(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.io.receive_repair_frame().await
    }

    async fn close(self) -> Result<(), Self::Error> {
        self.io.close().await
    }
}

#[derive(Debug, Error)]
pub enum BleWireError {
    #[error("malformed Tutti BLE peer hello")]
    MalformedHello,
    #[error("malformed Tutti BLE bootstrap frame")]
    MalformedBootstrap,
    #[error("malformed authenticated Tutti BLE frame")]
    MalformedAuthenticatedFrame,
    #[error("malformed Tutti BLE control profile")]
    MalformedProfile,
    #[error("malformed authenticated Tutti BLE control frame")]
    MalformedControlFrame,
    #[error("unknown authenticated Tutti BLE control frame {0}")]
    UnknownControlFrame(u8),
    #[error("malformed Tutti BLE fragment")]
    MalformedFragment,
    #[error("fragment value is {actual} bytes; minimum is {minimum}")]
    FragmentValueTooSmall { actual: usize, minimum: usize },
    #[error("fragment output has {actual} bytes; {required} required")]
    FragmentOutputTooSmall { required: usize, actual: usize },
    #[error("wire message is {actual} bytes; maximum is {maximum}")]
    WireMessageTooLarge { actual: usize, maximum: usize },
    #[error("payload is {actual} bytes; maximum is {maximum}")]
    PayloadTooLarge { actual: usize, maximum: usize },
    #[error("invalid BLE reassembly budget")]
    InvalidReassemblyBudget,
    #[error("fragment stream started another message before finishing the current one")]
    InterleavedMessages,
    #[error("partial BLE assemblies retain {requested} declared bytes; maximum is {maximum}")]
    PartialAssemblyBudgetExceeded { requested: usize, maximum: usize },
    #[error("fragment arrived without a start fragment")]
    MissingFragmentStart,
    #[error("fragment id, size, or offset is discontinuous")]
    FragmentDiscontinuity,
    #[error("could not reserve {0} bytes for a bounded wire message")]
    AllocationFailed(usize),
    #[error("authenticated frame belongs to another session")]
    WrongSession,
    #[error("unknown authenticated lane {0}")]
    UnknownLane(u8),
    #[error("outbound sequence space is exhausted")]
    SequenceExhausted,
    #[error("payload restriction {requested} must be within 1..={current}")]
    InvalidPayloadRestriction { current: usize, requested: usize },
    #[error("session error: {0}")]
    Session(#[source] SessionError),
    #[error("replay error: {0}")]
    Replay(#[source] ReplayError),
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::convert::Infallible;

    use ed25519_dalek::SigningKey;
    use futures::executor::block_on;
    use hhhs_sync::FrameStream;
    use tutti_session::{EphemeralSecret, PendingInitiator, ProtocolId};

    use super::*;

    fn establish() -> (SessionKeys, SessionKeys, PeerHello, PeerHello) {
        let initiator_key = SigningKey::from_bytes(&[1; 32]);
        let responder_key = SigningKey::from_bytes(&[2; 32]);
        let initiator_hello = PeerHello {
            identity: PeerIdentity::from_signing_key(&initiator_key),
            boot_nonce: 11,
            max_fragment_value_bytes: 185,
            capabilities: CAPABILITY_REALTIME | CAPABILITY_HHHS_REPAIR,
        };
        let responder_hello = PeerHello {
            identity: PeerIdentity::from_signing_key(&responder_key),
            boot_nonce: 22,
            max_fragment_value_bytes: 185,
            capabilities: CAPABILITY_REALTIME
                | CAPABILITY_HHHS_REPAIR
                | CAPABILITY_BLE_MIDI_COEXISTENCE,
        };
        let binding = channel_binding(initiator_hello, responder_hello);
        let (pending, offer) = PendingInitiator::begin(
            &initiator_key,
            ProtocolId::derive(b"tutti BLE bridge test"),
            binding,
            77,
            EphemeralSecret::from_bytes([3; 32]),
        );
        let offer_wire = encode_offer(&offer);
        let verified = decode_offer(&offer_wire)
            .unwrap()
            .verify(ProtocolId::derive(b"tutti BLE bridge test"), binding)
            .unwrap();
        assert_eq!(verified.identity(), initiator_hello.identity);
        let (answer, responder) = verified
            .respond(&responder_key, EphemeralSecret::from_bytes([4; 32]))
            .unwrap();
        let answer_wire = encode_answer(&answer);
        let initiator = pending
            .complete(
                decode_answer(&answer_wire).unwrap().as_bytes(),
                responder_hello.identity,
            )
            .unwrap();
        (initiator, responder, initiator_hello, responder_hello)
    }

    #[test]
    fn hello_round_trips_and_binds_roles_and_boots() {
        let (_, _, initiator, responder) = establish();
        assert_eq!(PeerHello::decode(&initiator.encode()).unwrap(), initiator);
        assert!(responder.supports(CAPABILITY_BLE_MIDI_COEXISTENCE));
        assert_ne!(
            channel_binding(initiator, responder),
            channel_binding(responder, initiator)
        );
        let mut rebooted = responder;
        rebooted.boot_nonce += 1;
        assert_ne!(
            channel_binding(initiator, responder),
            channel_binding(initiator, rebooted)
        );
    }

    #[test]
    fn session_protocol_and_lane_profile_are_frozen() {
        assert_eq!(
            session_protocol_id().as_bytes(),
            &[
                0xe8, 0x2a, 0xc5, 0x74, 0x1b, 0x59, 0xbc, 0x35, 0x60, 0x78, 0xdd, 0x97, 0x52, 0xd9,
                0x14, 0x55, 0x62, 0xe3, 0x91, 0x3a, 0xc2, 0x68, 0xf3, 0x5f, 0xcd, 0x5b, 0xa8, 0x4d,
                0x93, 0x01, 0x6f, 0x8c,
            ]
        );
        let capabilities = with_realtime_generation(3, 7);
        assert_eq!(realtime_generation(capabilities), 7);
        assert_eq!(capabilities & 0x00ff_ffff, 3);
        let profile = LaneProfile {
            music_generation: 7,
            music_vocabulary_generation: 1,
            max_replica_record_bytes: 1456,
            hhhs_strategy_version: 1,
            hhhs_repair_generation: 2,
            application_generation: 5,
            capabilities,
            max_authenticated_payload_bytes: 4_096,
            max_repair_frame_bytes: 60 * 1_024,
        };
        let bytes = profile.encode();
        assert_eq!(&bytes[..4], b"TBP3");
        assert_eq!(LaneProfile::decode(&bytes).unwrap(), profile);
        let mut legacy = bytes;
        legacy[..4].copy_from_slice(b"TBP1");
        assert!(matches!(
            LaneProfile::decode(&legacy),
            Err(BleWireError::MalformedProfile)
        ));
        let mut invalid = bytes;
        invalid[32..36].fill(0);
        assert!(matches!(
            LaneProfile::decode(&invalid),
            Err(BleWireError::MalformedProfile)
        ));
    }

    #[test]
    fn authenticated_control_vocabulary_is_tagged_and_versioned() {
        let profile = LaneProfile {
            music_generation: 8,
            music_vocabulary_generation: 1,
            max_replica_record_bytes: 1456,
            hhhs_strategy_version: 1,
            hhhs_repair_generation: 2,
            application_generation: 5,
            capabilities: with_realtime_generation(PROFILE_CAP_MUSIC, 3),
            max_authenticated_payload_bytes: 1541,
            max_repair_frame_bytes: 1536,
        };
        let encoded_profile = encode_control_profile(profile);
        assert_eq!(encoded_profile.len(), CONTROL_PROFILE_BYTES);
        assert_eq!(&encoded_profile[..5], b"TBC1\x01");
        assert_eq!(
            decode_control_frame(&encoded_profile).unwrap(),
            ControlFrame::Profile(profile)
        );
        assert!(matches!(
            decode_control_frame(&profile.encode()),
            Err(BleWireError::MalformedControlFrame)
        ));

        let bundle = vec![0x42; 1118];
        let encoded_bundle = encode_control_capability_bundle(&bundle).unwrap();
        assert_eq!(&encoded_bundle[..5], b"TBC1\x02");
        assert_eq!(
            decode_control_frame(&encoded_bundle).unwrap(),
            ControlFrame::CapabilityBundle(&bundle)
        );

        let attempt = RepairAttemptId::new([0xa5; REPAIR_ATTEMPT_ID_BYTES]);
        let fin = RepairFin {
            attempt,
            last_repair_sequence: 41,
        };
        let ack = RepairAck {
            attempt,
            fin_sequence: 42,
        };
        let encoded_fin = encode_control_repair_fin(fin);
        let encoded_ack = encode_control_repair_ack(ack);
        assert_eq!(encoded_fin.len(), CONTROL_REPAIR_LIFECYCLE_BYTES);
        assert_eq!(encoded_ack.len(), CONTROL_REPAIR_LIFECYCLE_BYTES);
        assert_eq!(
            decode_control_frame(&encoded_fin).unwrap(),
            ControlFrame::RepairFin(fin)
        );
        assert_eq!(
            decode_control_frame(&encoded_ack).unwrap(),
            ControlFrame::RepairAck(ack)
        );
        let ready = CapabilityReady {
            bundle_digest: [0x5a; 32],
        };
        let encoded_ready = encode_control_capability_ready(ready);
        assert_eq!(encoded_ready.len(), CONTROL_CAPABILITY_READY_BYTES);
        assert_eq!(
            decode_control_frame(&encoded_ready).unwrap(),
            ControlFrame::CapabilityReady(ready)
        );

        let mut unknown = encoded_profile;
        unknown[4] = 0xff;
        assert!(matches!(
            decode_control_frame(&unknown),
            Err(BleWireError::UnknownControlFrame(0xff))
        ));
    }

    #[test]
    fn repair_attempt_identity_binds_link_and_opening_frame() {
        let first = repair_attempt_id(7, b"hhhs hello");
        assert_eq!(first, repair_attempt_id(7, b"hhhs hello"));
        assert_ne!(first, repair_attempt_id(8, b"hhhs hello"));
        assert_ne!(first, repair_attempt_id(7, b"another hello"));
    }

    #[test]
    fn repair_close_requires_both_terminal_prefixes_and_confirmed_acks() {
        let attempt = repair_attempt_id(17, b"opening");
        let mut left = RepairCloseState::new(attempt);
        let mut right = RepairCloseState::new(attempt);

        left.observe_local_repair(10).unwrap();
        right.observe_remote_repair(10).unwrap();
        right.observe_local_repair(11).unwrap();
        left.observe_remote_repair(11).unwrap();
        left.mark_local_terminal();
        right.mark_local_terminal();

        let left_fin = left.local_fin().unwrap();
        left.observe_local_fin_encoded(12).unwrap();
        right.observe_remote_fin(left_fin, 12).unwrap();
        let right_fin = right.local_fin().unwrap();
        right.observe_local_fin_encoded(13).unwrap();
        left.observe_remote_fin(right_fin, 13).unwrap();

        let left_ack = left.remote_ack().unwrap();
        left.observe_remote_ack_encoded(14).unwrap();
        let right_ack = right.remote_ack().unwrap();
        right.observe_remote_ack_encoded(15).unwrap();
        right.observe_local_fin_ack(left_ack).unwrap();
        left.observe_local_fin_ack(right_ack).unwrap();

        assert!(!left.is_confirmed_closed());
        assert!(!right.is_confirmed_closed());
        left.confirm_remote_ack_sent(14).unwrap();
        right.confirm_remote_ack_sent(15).unwrap();
        assert!(left.is_confirmed_closed());
        assert!(right.is_confirmed_closed());
    }

    #[test]
    fn repair_close_refuses_early_stale_and_truncated_lifecycle_messages() {
        let attempt = RepairAttemptId::new([0x31; REPAIR_ATTEMPT_ID_BYTES]);
        let other = RepairAttemptId::new([0x32; REPAIR_ATTEMPT_ID_BYTES]);
        let mut state = RepairCloseState::new(attempt);
        state.observe_local_repair(4).unwrap();
        assert_eq!(state.local_fin(), Err(RepairCloseError::FinBeforeTerminal));
        state.mark_local_terminal();
        assert_eq!(
            state.observe_remote_fin(
                RepairFin {
                    attempt: other,
                    last_repair_sequence: 8,
                },
                9,
            ),
            Err(RepairCloseError::WrongAttempt)
        );

        state.observe_remote_repair(7).unwrap();
        state
            .observe_remote_fin(
                RepairFin {
                    attempt,
                    last_repair_sequence: 8,
                },
                9,
            )
            .unwrap();
        assert_eq!(
            state.remote_ack(),
            Err(RepairCloseError::MissingRepairPrefix)
        );
        assert_eq!(
            state.observe_remote_repair(9),
            Err(RepairCloseError::RepairAfterFin)
        );
        assert_eq!(
            state.observe_local_fin_ack(RepairAck {
                attempt,
                fin_sequence: 99,
            }),
            Err(RepairCloseError::WrongAckSequence)
        );
    }

    #[test]
    fn duplicate_local_fin_is_failure_atomic() {
        let attempt = RepairAttemptId::new([0x41; REPAIR_ATTEMPT_ID_BYTES]);
        let mut state = RepairCloseState::new(attempt);
        state.observe_local_repair(4).unwrap();
        state.mark_local_terminal();
        state.observe_local_fin_encoded(5).unwrap();
        assert_eq!(
            state.observe_local_fin_encoded(6),
            Err(RepairCloseError::DuplicateFin)
        );
        state
            .observe_local_fin_ack(RepairAck {
                attempt,
                fin_sequence: 5,
            })
            .expect("duplicate refusal must preserve the original FIN sequence");
    }

    #[test]
    fn authenticated_lanes_round_trip_and_replays_fail() {
        let (initiator, responder, _, _) = establish();
        let mut sender = SessionCodec::new(initiator, DEFAULT_MAX_PAYLOAD_BYTES).unwrap();
        let mut receiver = SessionCodec::new(responder, DEFAULT_MAX_PAYLOAD_BYTES).unwrap();
        let encoded = sender
            .encode(Lane::HhhsRepair, b"one canonical HHHS frame")
            .unwrap();
        assert_eq!(
            encoded,
            [
                0x54, 0x42, 0x4c, 0x31, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x18, 0x6f, 0x6e, 0x65, 0x20,
                0x63, 0x61, 0x6e, 0x6f, 0x6e, 0x69, 0x63, 0x61, 0x6c, 0x20, 0x48, 0x48, 0x48, 0x53,
                0x20, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x70, 0x8a, 0xea, 0x89, 0x78, 0x10, 0xee, 0x2a,
                0x0f, 0x1e, 0x51, 0x3b, 0xbb, 0x48, 0x0e, 0x98,
            ]
        );
        let decoded = receiver.decode(&encoded).unwrap();
        assert_eq!(decoded.lane, Lane::HhhsRepair);
        assert_eq!(decoded.sequence, 0);
        assert_eq!(decoded.payload, b"one canonical HHHS frame");
        assert!(matches!(
            receiver.decode(&encoded),
            Err(BleWireError::Replay(ReplayError::Duplicate))
        ));
    }

    #[test]
    fn negotiated_payload_budget_can_only_decrease() {
        let (initiator, _, _, _) = establish();
        let mut codec = SessionCodec::new(initiator, 4_096).unwrap();
        codec.restrict_max_payload_bytes(512).unwrap();
        assert_eq!(codec.max_payload_bytes(), 512);
        assert!(matches!(
            codec.restrict_max_payload_bytes(513),
            Err(BleWireError::InvalidPayloadRestriction { .. })
        ));
    }

    #[test]
    fn authentication_covers_lane_sequence_and_payload() {
        let (initiator, responder, _, _) = establish();
        let mut sender = SessionCodec::new(initiator, 128).unwrap();
        let mut receiver = SessionCodec::new(responder, 128).unwrap();
        let encoded = sender.encode(Lane::Realtime, b"note on").unwrap();
        for offset in [13, 21, AUTHENTICATED_HEADER_BYTES] {
            let mut tampered = encoded.clone();
            tampered[offset] ^= 1;
            assert!(receiver.decode(&tampered).is_err());
        }
    }

    fn fragmented_round_trip(value_bytes: usize, payload: &[u8]) {
        let mut reassembler = Reassembler::new(HARD_MAX_WIRE_BYTES).unwrap();
        let mut completed = None;
        for fragment in Fragmenter::new(41, payload, value_bytes).unwrap() {
            let mut packet = vec![0; value_bytes];
            let used = fragment.encode_into(&mut packet).unwrap();
            assert!(used <= value_bytes);
            let next = reassembler.push(&packet[..used]).unwrap();
            if next.is_some() {
                assert!(completed.is_none());
                completed = next;
            }
        }
        assert_eq!(completed.as_deref(), Some(payload));
    }

    #[test]
    fn fragments_round_trip_at_minimum_and_larger_gatt_values() {
        let payload = (0_u16..600).flat_map(u16::to_be_bytes).collect::<Vec<_>>();
        fragmented_round_trip(MIN_FRAGMENT_VALUE_BYTES, &payload);
        fragmented_round_trip(20, &payload);
        fragmented_round_trip(185, &payload);
        fragmented_round_trip(512, &payload);
        fragmented_round_trip(20, &[]);
    }

    #[test]
    fn incremental_fragmentation_interleaves_two_bounded_messages() {
        let repair = vec![0x52; 1_536];
        let realtime = vec![0x4d; 52];
        let mut repair_cursor = FragmentCursor::new(70, repair.clone(), 20).unwrap();
        let mut realtime_cursor = FragmentCursor::new(71, realtime.clone(), 20).unwrap();
        assert_eq!(repair_cursor.retained_wire_bytes(), repair.len());
        assert_eq!(realtime_cursor.retained_wire_bytes(), realtime.len());
        let mut receiver =
            Reassembler::with_budget(ReassemblyBudget::new(1_536, 2, 1_536 * 2).unwrap()).unwrap();
        let mut packet = [0_u8; 20];
        let mut completed = BTreeMap::new();

        while !repair_cursor.is_complete() || !realtime_cursor.is_complete() {
            for (id, cursor) in [(70_u16, &mut repair_cursor), (71_u16, &mut realtime_cursor)] {
                if let Some(used) = cursor.encode_next(&mut packet).unwrap()
                    && let Some(message) = receiver.push(&packet[..used]).unwrap()
                {
                    completed.insert(id, message);
                }
            }
        }

        assert_eq!(completed.remove(&70), Some(repair));
        assert_eq!(completed.remove(&71), Some(realtime));
    }

    fn encoded_test_fragment(
        message_id: u16,
        total_bytes: u16,
        offset: u16,
        start: bool,
        end: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet =
            vec![0; MIN_FRAGMENT_VALUE_BYTES.max(FRAGMENT_HEADER_BYTES + payload.len())];
        let used = Fragment {
            message_id,
            total_bytes,
            offset,
            start,
            end,
            payload,
        }
        .encode_into(&mut packet)
        .unwrap();
        packet.truncate(used);
        packet
    }

    #[test]
    fn partial_assembly_budget_refuses_declared_byte_dos_and_recovers() {
        let mut receiver =
            Reassembler::with_budget(ReassemblyBudget::new(1_536, 3, 1_600).unwrap()).unwrap();
        let first = encoded_test_fragment(80, 1_536, 0, true, false, &[1; 8]);
        assert!(receiver.push(&first).unwrap().is_none());
        assert_eq!(receiver.retained_partial_bytes(), 1_536);

        let over_budget = encoded_test_fragment(81, 100, 0, true, false, &[2; 8]);
        assert!(matches!(
            receiver.push(&over_budget),
            Err(BleWireError::PartialAssemblyBudgetExceeded {
                requested: 1_636,
                maximum: 1_600,
            })
        ));
        assert_eq!(receiver.retained_partial_bytes(), 0);

        let complete = encoded_test_fragment(82, 3, 0, true, true, b"new");
        assert_eq!(
            receiver.push(&complete).unwrap().as_deref(),
            Some(&b"new"[..])
        );
    }

    #[test]
    fn duplicate_start_or_discontinuity_resets_all_partial_messages() {
        let mut receiver =
            Reassembler::with_budget(ReassemblyBudget::new(64, 2, 128).unwrap()).unwrap();
        let a_start = encoded_test_fragment(90, 20, 0, true, false, b"aaaa");
        assert!(receiver.push(&a_start).unwrap().is_none());
        assert!(matches!(
            receiver.push(&a_start),
            Err(BleWireError::InterleavedMessages)
        ));
        assert_eq!(receiver.retained_partial_bytes(), 0);

        assert!(receiver.push(&a_start).unwrap().is_none());
        let b_start = encoded_test_fragment(91, 10, 0, true, false, b"bb");
        assert!(receiver.push(&b_start).unwrap().is_none());
        let discontinuous = encoded_test_fragment(90, 20, 5, false, false, b"c");
        assert!(matches!(
            receiver.push(&discontinuous),
            Err(BleWireError::FragmentDiscontinuity)
        ));
        assert_eq!(receiver.retained_partial_bytes(), 0);

        let complete = encoded_test_fragment(92, 2, 0, true, true, b"ok");
        assert_eq!(
            receiver.push(&complete).unwrap().as_deref(),
            Some(&b"ok"[..])
        );
    }

    #[test]
    fn hello_and_fragment_vectors_are_frozen() {
        let identity = PeerIdentity::from_bytes([0x11; 32]);
        let hello = PeerHello {
            identity,
            boot_nonce: 0x0102_0304_0506_0708,
            max_fragment_value_bytes: 0x00b9,
            capabilities: CAPABILITY_REALTIME | CAPABILITY_HHHS_REPAIR,
        };
        assert_eq!(
            hello.encode(),
            [
                0x54, 0x42, 0x48, 0x31, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x07, 0x08, 0x00, 0xb9, 0x00, 0x00, 0x00, 0x03,
            ]
        );

        let fragment = Fragment {
            message_id: 0x1234,
            total_bytes: 3,
            offset: 0,
            start: true,
            end: true,
            payload: &[0xaa, 0xbb, 0xcc],
        };
        let mut encoded = [0; 13];
        assert_eq!(fragment.encode_into(&mut encoded).unwrap(), 13);
        assert_eq!(
            encoded,
            [
                0x54, 0x42, 0x01, 0x03, 0x12, 0x34, 0x00, 0x03, 0x00, 0x00, 0xaa, 0xbb, 0xcc,
            ]
        );
    }

    #[test]
    fn reassembly_is_bounded_and_resets_after_discontinuity() {
        let payload = vec![7; 128];
        let mut fragments = Fragmenter::new(8, &payload, 32).unwrap();
        let first = fragments.next().unwrap();
        let second = fragments.next().unwrap();
        let mut packet = [0; 32];
        let used = first.encode_into(&mut packet).unwrap();
        let mut reassembler = Reassembler::new(64).unwrap();
        assert!(matches!(
            reassembler.push(&packet[..used]),
            Err(BleWireError::WireMessageTooLarge { .. })
        ));

        let mut reassembler = Reassembler::new(128).unwrap();
        let used = first.encode_into(&mut packet).unwrap();
        assert!(reassembler.push(&packet[..used]).unwrap().is_none());
        let mut discontinuous = second;
        discontinuous.offset += 1;
        let used = discontinuous.encode_into(&mut packet).unwrap();
        assert!(matches!(
            reassembler.push(&packet[..used]),
            Err(BleWireError::FragmentDiscontinuity)
        ));
        let used = first.encode_into(&mut packet).unwrap();
        assert!(reassembler.push(&packet[..used]).unwrap().is_none());
    }

    #[derive(Default)]
    struct MemoryRepairIo {
        sent: Vec<Vec<u8>>,
        receive: VecDeque<Vec<u8>>,
        closed: bool,
    }

    impl RepairFrameIo for MemoryRepairIo {
        type Error = Infallible;

        async fn send_repair_frame(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
            self.sent.push(frame.to_vec());
            Ok(())
        }

        async fn receive_repair_frame(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.receive.pop_front())
        }

        async fn close(mut self) -> Result<(), Self::Error> {
            self.closed = true;
            Ok(())
        }
    }

    #[test]
    fn repair_adapter_is_an_hhhs_frame_stream() {
        let io = MemoryRepairIo {
            receive: VecDeque::from([b"repair-in".to_vec()]),
            ..MemoryRepairIo::default()
        };
        let mut stream = BleRepairStream::new(io);
        block_on(stream.send_frame(b"repair-out")).unwrap();
        assert_eq!(stream.inner().sent, [b"repair-out".to_vec()]);
        assert_eq!(
            block_on(stream.recv_frame()).unwrap(),
            Some(b"repair-in".to_vec())
        );
    }
}
