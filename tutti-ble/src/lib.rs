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

use std::future::Future;

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

// The authenticated lane profile uses the high byte of its capability word
// for the realtime payload generation. Keeping this inside the existing TBP1
// profile means an old peer can still decode the profile and be refused with a
// useful compatibility error before either side sends musical payloads.
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
const PROFILE_MAGIC: [u8; 4] = *b"TBP1";
const FLAG_START: u8 = 1 << 0;
const FLAG_END: u8 = 1 << 1;
const KNOWN_FRAGMENT_FLAGS: u8 = FLAG_START | FLAG_END;
const AUTHENTICATED_HEADER_BYTES: usize = 4 + 1 + 8 + 8 + 1 + 2;

pub const HELLO_BYTES: usize = 4 + 32 + 8 + 2 + 4;
pub const FRAGMENT_HEADER_BYTES: usize = 2 + 1 + 1 + 2 + 2 + 2;
pub const MIN_FRAGMENT_VALUE_BYTES: usize = FRAGMENT_HEADER_BYTES + 1;
pub const HARD_MAX_WIRE_BYTES: usize = u16::MAX as usize;
pub const HARD_MAX_PAYLOAD_BYTES: usize =
    HARD_MAX_WIRE_BYTES - AUTHENTICATED_HEADER_BYTES - TAG_BYTES;
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 4 * 1024;
pub const SESSION_PROTOCOL_LABEL: &[u8] = b"tutti BLE bridge session v1";
pub const PROFILE_BYTES: usize = 4 + 4 * 6;

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
    pub hhhs_strategy_version: u32,
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
            self.hhhs_strategy_version,
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
            hhhs_strategy_version: value(1),
            application_generation: value(2),
            capabilities: value(3),
            max_authenticated_payload_bytes: value(4),
            max_repair_frame_bytes: value(5),
        };
        if profile.max_authenticated_payload_bytes == 0
            || profile.max_authenticated_payload_bytes as usize > HARD_MAX_PAYLOAD_BYTES
            || profile.max_repair_frame_bytes == 0
            || profile.max_repair_frame_bytes as usize > HARD_MAX_WIRE_BYTES
        {
            return Err(BleWireError::MalformedProfile);
        }
        Ok(profile)
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
        Ok(bytes)
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

struct PartialMessage {
    message_id: u16,
    total_bytes: u16,
    next_offset: u16,
    bytes: Vec<u8>,
}

/// One-message-at-a-time bounded reassembler. GATT preserves value order on a
/// connection; a host should use one instance per direction and reset it when
/// the connection closes.
pub struct Reassembler {
    max_wire_bytes: usize,
    partial: Option<PartialMessage>,
}

impl Reassembler {
    pub fn new(max_wire_bytes: usize) -> Result<Self, BleWireError> {
        if max_wire_bytes > HARD_MAX_WIRE_BYTES {
            return Err(BleWireError::WireMessageTooLarge {
                actual: max_wire_bytes,
                maximum: HARD_MAX_WIRE_BYTES,
            });
        }
        Ok(Self {
            max_wire_bytes,
            partial: None,
        })
    }

    pub fn reset(&mut self) {
        self.partial = None;
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
        if total > self.max_wire_bytes {
            return Err(BleWireError::WireMessageTooLarge {
                actual: total,
                maximum: self.max_wire_bytes,
            });
        }
        if fragment.start {
            if self.partial.is_some() {
                return Err(BleWireError::InterleavedMessages);
            }
            let mut assembled = Vec::new();
            assembled
                .try_reserve_exact(total)
                .map_err(|_| BleWireError::AllocationFailed(total))?;
            self.partial = Some(PartialMessage {
                message_id: fragment.message_id,
                total_bytes: fragment.total_bytes,
                next_offset: 0,
                bytes: assembled,
            });
        }
        let partial = self
            .partial
            .as_mut()
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
            .partial
            .take()
            .ok_or(BleWireError::MissingFragmentStart)?;
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

    fn close(self) -> impl Future<Output = ()>;
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

    async fn close(self) {
        self.io.close().await;
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
    #[error("fragment stream started another message before finishing the current one")]
    InterleavedMessages,
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
            hhhs_strategy_version: 1,
            application_generation: 5,
            capabilities,
            max_authenticated_payload_bytes: 4_096,
            max_repair_frame_bytes: 60 * 1_024,
        };
        let bytes = profile.encode();
        assert_eq!(&bytes[..4], b"TBP1");
        assert_eq!(LaneProfile::decode(&bytes).unwrap(), profile);
        let mut invalid = bytes;
        invalid[20..24].fill(0);
        assert!(matches!(
            LaneProfile::decode(&invalid),
            Err(BleWireError::MalformedProfile)
        ));
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

        async fn close(mut self) {
            self.closed = true;
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
