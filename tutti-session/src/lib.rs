//! Authenticated, transport-independent sessions for Tutti peers.
//!
//! One Ed25519-authenticated ephemeral X25519 handshake establishes
//! directional channel keys. Subsequent transport frames use a short keyed
//! BLAKE3 tag and a replay window; they do not perform public-key operations.
//! This crate authenticates but does not encrypt frame contents.
//!
//! Discovery, trust policy (pinning/TOFU/allow-list), retransmission, packet
//! sizing, and HHHS admission remain caller-owned boundaries.

#![forbid(unsafe_code)]

use blake3::Hasher;
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

const MAGIC: [u8; 4] = *b"TSA1";
const OFFER_KIND: u8 = 1;
const ANSWER_KIND: u8 = 2;
const OFFER_DOMAIN: &[u8] = b"tutti authenticated session offer v1\0";
const ANSWER_DOMAIN: &[u8] = b"tutti authenticated session answer v1\0";
const KEY_DOMAIN: &str = "tutti authenticated session keys v1";
const EXPORT_DOMAIN: &[u8] = b"tutti authenticated session directional exporter v1\0";
const TAG_DOMAIN: &[u8] = b"tutti authenticated channel frame v1\0";
pub const TAG_BYTES: usize = 16;
pub const OFFER_BYTES: usize = 4 + 1 + 8 + 32 + 32 + 32 + 32 + 64;
pub const ANSWER_BYTES: usize = 4 + 1 + 8 + 32 + 32 + 32 + 32 + 32 + 64;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PeerIdentity([u8; 32]);

impl PeerIdentity {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_signing_key(key: &SigningKey) -> Self {
        Self(key.verifying_key().to_bytes())
    }

    fn verifying_key(self) -> Result<VerifyingKey, SessionError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| SessionError::InvalidIdentity)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ProtocolId([u8; 32]);

impl ProtocolId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn derive(label: &[u8]) -> Self {
        Self(*blake3::hash(label).as_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Caller-defined binding for the concrete channel endpoints and boot epochs.
/// A transport should include both endpoint addresses and both fresh boot
/// nonces so a handshake cannot be replayed onto another link or process.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ChannelBinding([u8; 32]);

impl ChannelBinding {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn derive(context: &[u8]) -> Self {
        Self(*blake3::hash(context).as_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Fresh 32-byte randomness supplied by the platform for one handshake.
pub struct EphemeralSecret([u8; 32]);

impl EphemeralSecret {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn public(&self) -> [u8; 32] {
        MontgomeryPoint::mul_base_clamped(self.0).to_bytes()
    }

    fn agree(&self, peer: [u8; 32]) -> Result<[u8; 32], SessionError> {
        let shared = MontgomeryPoint(peer).mul_clamped(self.0).to_bytes();
        if constant_time_eq(&shared, &[0; 32]) {
            return Err(SessionError::InvalidKeyAgreement);
        }
        Ok(shared)
    }
}

impl Drop for EphemeralSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Offer([u8; OFFER_BYTES]);

impl Offer {
    pub fn decode(bytes: &[u8]) -> Result<Self, SessionError> {
        if bytes.len() != OFFER_BYTES {
            return Err(SessionError::Malformed);
        }
        let mut encoded = [0; OFFER_BYTES];
        encoded.copy_from_slice(bytes);
        if encoded[..4] != MAGIC || encoded[4] != OFFER_KIND {
            return Err(SessionError::Malformed);
        }
        Ok(Self(encoded))
    }

    pub const fn as_bytes(&self) -> &[u8; OFFER_BYTES] {
        &self.0
    }

    pub fn session_id(&self) -> u64 {
        u64::from_be_bytes(self.0[5..13].try_into().expect("fixed offer layout"))
    }

    pub fn protocol(&self) -> ProtocolId {
        ProtocolId(self.0[13..45].try_into().expect("fixed offer layout"))
    }

    pub fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding(self.0[45..77].try_into().expect("fixed offer layout"))
    }

    pub fn identity(&self) -> PeerIdentity {
        PeerIdentity(self.0[77..109].try_into().expect("fixed offer layout"))
    }

    fn ephemeral_public(&self) -> [u8; 32] {
        self.0[109..141].try_into().expect("fixed offer layout")
    }

    fn signed_body(&self) -> &[u8] {
        &self.0[..141]
    }

    fn digest(&self) -> [u8; 32] {
        domain_digest(OFFER_DOMAIN, self.signed_body())
    }

    pub fn verify(
        self,
        protocol: ProtocolId,
        binding: ChannelBinding,
    ) -> Result<VerifiedOffer, SessionError> {
        if self.protocol() != protocol {
            return Err(SessionError::WrongProtocol);
        }
        if self.channel_binding() != binding {
            return Err(SessionError::WrongChannelBinding);
        }
        let signature = Signature::from_bytes(
            &self.0[141..205]
                .try_into()
                .expect("fixed offer signature layout"),
        );
        self.identity()
            .verifying_key()?
            .verify_strict(&self.digest(), &signature)
            .map_err(|_| SessionError::Authentication)?;
        Ok(VerifiedOffer { offer: self })
    }
}

pub struct PendingInitiator {
    offer: Offer,
    secret: EphemeralSecret,
}

impl PendingInitiator {
    pub fn begin(
        identity: &SigningKey,
        protocol: ProtocolId,
        binding: ChannelBinding,
        session_id: u64,
        secret: EphemeralSecret,
    ) -> (Self, Offer) {
        let mut bytes = [0; OFFER_BYTES];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4] = OFFER_KIND;
        bytes[5..13].copy_from_slice(&session_id.to_be_bytes());
        bytes[13..45].copy_from_slice(protocol.as_bytes());
        bytes[45..77].copy_from_slice(binding.as_bytes());
        bytes[77..109].copy_from_slice(&identity.verifying_key().to_bytes());
        bytes[109..141].copy_from_slice(&secret.public());
        let digest = domain_digest(OFFER_DOMAIN, &bytes[..141]);
        bytes[141..].copy_from_slice(&identity.sign(&digest).to_bytes());
        let offer = Offer(bytes);
        (
            Self {
                offer: offer.clone(),
                secret,
            },
            offer,
        )
    }

    pub fn complete(
        self,
        answer_bytes: &[u8],
        expected_peer: PeerIdentity,
    ) -> Result<SessionKeys, SessionError> {
        let answer = Answer::decode(answer_bytes)?;
        if answer.session_id() != self.offer.session_id()
            || answer.protocol() != self.offer.protocol()
            || answer.channel_binding() != self.offer.channel_binding()
            || answer.offer_digest() != self.offer.digest()
        {
            return Err(SessionError::TranscriptMismatch);
        }
        if answer.identity() != expected_peer {
            return Err(SessionError::UnexpectedPeer);
        }
        answer.verify()?;
        let shared = self.secret.agree(answer.ephemeral_public())?;
        Ok(derive_keys(
            Role::Initiator,
            self.offer.session_id(),
            self.offer.identity(),
            answer.identity(),
            shared,
            &self.offer,
            &answer,
        ))
    }
}

pub struct VerifiedOffer {
    offer: Offer,
}

impl VerifiedOffer {
    pub fn identity(&self) -> PeerIdentity {
        self.offer.identity()
    }

    pub fn session_id(&self) -> u64 {
        self.offer.session_id()
    }

    pub fn respond(
        self,
        identity: &SigningKey,
        secret: EphemeralSecret,
    ) -> Result<(Answer, SessionKeys), SessionError> {
        let mut bytes = [0; ANSWER_BYTES];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4] = ANSWER_KIND;
        bytes[5..13].copy_from_slice(&self.offer.session_id().to_be_bytes());
        bytes[13..45].copy_from_slice(self.offer.protocol().as_bytes());
        bytes[45..77].copy_from_slice(self.offer.channel_binding().as_bytes());
        bytes[77..109].copy_from_slice(&identity.verifying_key().to_bytes());
        bytes[109..141].copy_from_slice(&secret.public());
        bytes[141..173].copy_from_slice(&self.offer.digest());
        let digest = domain_digest(ANSWER_DOMAIN, &bytes[..173]);
        bytes[173..].copy_from_slice(&identity.sign(&digest).to_bytes());
        let answer = Answer(bytes);
        let shared = secret.agree(self.offer.ephemeral_public())?;
        let keys = derive_keys(
            Role::Responder,
            self.offer.session_id(),
            self.offer.identity(),
            answer.identity(),
            shared,
            &self.offer,
            &answer,
        );
        Ok((answer, keys))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Answer([u8; ANSWER_BYTES]);

impl Answer {
    pub fn decode(bytes: &[u8]) -> Result<Self, SessionError> {
        if bytes.len() != ANSWER_BYTES {
            return Err(SessionError::Malformed);
        }
        let mut encoded = [0; ANSWER_BYTES];
        encoded.copy_from_slice(bytes);
        if encoded[..4] != MAGIC || encoded[4] != ANSWER_KIND {
            return Err(SessionError::Malformed);
        }
        Ok(Self(encoded))
    }

    pub const fn as_bytes(&self) -> &[u8; ANSWER_BYTES] {
        &self.0
    }

    pub fn session_id(&self) -> u64 {
        u64::from_be_bytes(self.0[5..13].try_into().expect("fixed answer layout"))
    }

    pub fn protocol(&self) -> ProtocolId {
        ProtocolId(self.0[13..45].try_into().expect("fixed answer layout"))
    }

    pub fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding(self.0[45..77].try_into().expect("fixed answer layout"))
    }

    pub fn identity(&self) -> PeerIdentity {
        PeerIdentity(self.0[77..109].try_into().expect("fixed answer layout"))
    }

    fn ephemeral_public(&self) -> [u8; 32] {
        self.0[109..141].try_into().expect("fixed answer layout")
    }

    fn offer_digest(&self) -> [u8; 32] {
        self.0[141..173].try_into().expect("fixed answer layout")
    }

    fn signed_body(&self) -> &[u8] {
        &self.0[..173]
    }

    fn digest(&self) -> [u8; 32] {
        domain_digest(ANSWER_DOMAIN, self.signed_body())
    }

    fn verify(&self) -> Result<(), SessionError> {
        let signature = Signature::from_bytes(
            &self.0[173..237]
                .try_into()
                .expect("fixed answer signature layout"),
        );
        self.identity()
            .verifying_key()?
            .verify_strict(&self.digest(), &signature)
            .map_err(|_| SessionError::Authentication)
    }
}

#[derive(Clone)]
pub struct SessionKeys {
    session_id: u64,
    peer: PeerIdentity,
    send: [u8; 32],
    receive: [u8; 32],
}

impl SessionKeys {
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    pub const fn peer(&self) -> PeerIdentity {
        self.peer
    }

    pub fn authenticate(&self, bytes: &[u8]) -> [u8; TAG_BYTES] {
        frame_tag(&self.send, self.session_id, bytes)
    }

    pub fn verify(&self, bytes: &[u8], tag: &[u8]) -> Result<(), SessionError> {
        if tag.len() != TAG_BYTES
            || !constant_time_eq(&frame_tag(&self.receive, self.session_id, bytes), tag)
        {
            return Err(SessionError::Authentication);
        }
        Ok(())
    }

    /// Derive one pair of direction-specific secrets for a higher-level
    /// protocol bound to `context`.
    ///
    /// This is the only supported bridge from the authenticated ephemeral
    /// X25519 handshake into another packet-protection protocol. Callers must
    /// bind the exact higher-level manifest and carrier channel; the original
    /// handshake keys are never exposed. The returned material is deliberately
    /// not `Clone` and is erased when dropped.
    pub fn export_directional(&self, context: &[u8]) -> DirectionalSecrets {
        let derive = |key: &[u8; 32]| {
            let mut hasher = Hasher::new_keyed(key);
            hasher.update(EXPORT_DOMAIN);
            hasher.update(&self.session_id.to_be_bytes());
            hasher.update(&(context.len() as u64).to_be_bytes());
            hasher.update(context);
            *hasher.finalize().as_bytes()
        };
        DirectionalSecrets {
            // `self.send` is the remote's `self.receive` (and vice versa).
            // The underlying transcript keys already separate directions, so
            // a role-local "send"/"receive" label would incorrectly make the
            // two ends derive different packet keys for the same lane.
            send: derive(&self.send),
            receive: derive(&self.receive),
        }
    }
}

/// Erasable directional output from one authenticated key-establishment
/// transcript. It is intended to be consumed immediately by the negotiated
/// packet-protection implementation.
pub struct DirectionalSecrets {
    send: [u8; 32],
    receive: [u8; 32],
}

impl DirectionalSecrets {
    pub fn take_send(&mut self) -> [u8; 32] {
        std::mem::take(&mut self.send)
    }

    pub fn take_receive(&mut self) -> [u8; 32] {
        std::mem::take(&mut self.receive)
    }
}

impl Drop for DirectionalSecrets {
    fn drop(&mut self) {
        self.send.zeroize();
        self.receive.zeroize();
    }
}

#[derive(Clone, Copy, Debug)]
enum Role {
    Initiator,
    Responder,
}

fn derive_keys(
    role: Role,
    session_id: u64,
    initiator: PeerIdentity,
    responder: PeerIdentity,
    shared: [u8; 32],
    offer: &Offer,
    answer: &Answer,
) -> SessionKeys {
    let mut material = [0; 104];
    material[..32].copy_from_slice(&shared);
    material[32..64].copy_from_slice(&offer.digest());
    material[64..96].copy_from_slice(&answer.digest());
    material[96..].copy_from_slice(&session_id.to_be_bytes());
    let master = blake3::derive_key(KEY_DOMAIN, &material);
    let initiator_send = *blake3::keyed_hash(&master, b"initiator to responder").as_bytes();
    let responder_send = *blake3::keyed_hash(&master, b"responder to initiator").as_bytes();
    let (send, receive, peer) = match role {
        Role::Initiator => (initiator_send, responder_send, responder),
        Role::Responder => (responder_send, initiator_send, initiator),
    };
    SessionKeys {
        session_id,
        peer,
        send,
        receive,
    }
}

fn domain_digest(domain: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain);
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

fn frame_tag(key: &[u8; 32], session_id: u64, bytes: &[u8]) -> [u8; TAG_BYTES] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(TAG_DOMAIN);
    hasher.update(&session_id.to_be_bytes());
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.as_bytes()[..TAG_BYTES]
        .try_into()
        .expect("fixed tag length")
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

/// Sliding 64-message replay window. Newer messages advance the window while
/// unique out-of-order messages within it are accepted exactly once.
#[derive(Clone, Copy, Default, Debug)]
pub struct ReplayWindow {
    highest: Option<u64>,
    seen: u64,
}

impl ReplayWindow {
    pub fn check_and_mark(&mut self, sequence: u64) -> Result<(), ReplayError> {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.seen = 1;
            return Ok(());
        };
        if sequence > highest {
            let shift = sequence - highest;
            self.seen = if shift >= 64 {
                1
            } else {
                (self.seen << shift) | 1
            };
            self.highest = Some(sequence);
            return Ok(());
        }
        let distance = highest - sequence;
        if distance >= 64 {
            return Err(ReplayError::TooOld);
        }
        let bit = 1_u64 << distance;
        if self.seen & bit != 0 {
            return Err(ReplayError::Duplicate);
        }
        self.seen |= bit;
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum ReplayError {
    #[error("message is older than the replay window")]
    TooOld,
    #[error("message was already accepted")]
    Duplicate,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum SessionError {
    #[error("malformed session message")]
    Malformed,
    #[error("session message belongs to another protocol")]
    WrongProtocol,
    #[error("session message belongs to another channel binding")]
    WrongChannelBinding,
    #[error("session transcript fields do not match")]
    TranscriptMismatch,
    #[error("peer identity key is invalid")]
    InvalidIdentity,
    #[error("session message authentication failed")]
    Authentication,
    #[error("the responder is not the expected peer")]
    UnexpectedPeer,
    #[error("ephemeral key agreement produced an invalid shared key")]
    InvalidKeyAgreement,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn establish() -> (SessionKeys, SessionKeys) {
        let initiator_key = SigningKey::from_bytes(&[1; 32]);
        let responder_key = SigningKey::from_bytes(&[2; 32]);
        let protocol = ProtocolId::derive(b"tutti test repair lane");
        let binding = ChannelBinding::derive(b"mac-a/boot-a/mac-b/boot-b");
        let (pending, offer) = PendingInitiator::begin(
            &initiator_key,
            protocol,
            binding,
            77,
            EphemeralSecret::from_bytes([3; 32]),
        );
        let verified = Offer::decode(offer.as_bytes())
            .unwrap()
            .verify(protocol, binding)
            .unwrap();
        assert_eq!(
            verified.identity(),
            PeerIdentity::from_signing_key(&initiator_key)
        );
        let (answer, responder) = verified
            .respond(&responder_key, EphemeralSecret::from_bytes([4; 32]))
            .unwrap();
        let initiator = pending
            .complete(
                answer.as_bytes(),
                PeerIdentity::from_signing_key(&responder_key),
            )
            .unwrap();
        (initiator, responder)
    }

    #[test]
    fn handshake_derives_directional_interoperable_keys() {
        let (initiator, responder) = establish();
        assert_eq!(initiator.peer(), responder_identity());
        let frame = b"one ordinary HHHS repair frame";
        let tag = initiator.authenticate(frame);
        responder.verify(frame, &tag).unwrap();
        assert!(responder.verify(b"tampered", &tag).is_err());
        assert!(initiator.verify(frame, &tag).is_err());

        let reply = b"repair reply";
        initiator
            .verify(reply, &responder.authenticate(reply))
            .unwrap();

        let context = b"exact hhhs manifest digest plus channel binding";
        let mut initiator_export = initiator.export_directional(context);
        let mut responder_export = responder.export_directional(context);
        assert_eq!(
            initiator_export.take_send(),
            responder_export.take_receive()
        );
        assert_eq!(
            initiator_export.take_receive(),
            responder_export.take_send()
        );
        assert_ne!(
            initiator.export_directional(context).take_send(),
            initiator
                .export_directional(b"another hhhs manifest")
                .take_send()
        );
    }

    fn responder_identity() -> PeerIdentity {
        PeerIdentity::from_signing_key(&SigningKey::from_bytes(&[2; 32]))
    }

    #[test]
    fn handshake_binds_protocol_channel_peer_and_transcript() {
        let initiator_key = SigningKey::from_bytes(&[11; 32]);
        let responder_key = SigningKey::from_bytes(&[12; 32]);
        let protocol = ProtocolId::derive(b"expected protocol");
        let binding = ChannelBinding::derive(b"expected endpoints and boots");
        let (pending, offer) = PendingInitiator::begin(
            &initiator_key,
            protocol,
            binding,
            91,
            EphemeralSecret::from_bytes([13; 32]),
        );
        assert_eq!(
            Offer::decode(offer.as_bytes())
                .unwrap()
                .verify(ProtocolId::derive(b"other protocol"), binding)
                .err(),
            Some(SessionError::WrongProtocol)
        );
        let verified = Offer::decode(offer.as_bytes())
            .unwrap()
            .verify(protocol, binding)
            .unwrap();
        let (mut answer, _) = verified
            .respond(&responder_key, EphemeralSecret::from_bytes([14; 32]))
            .unwrap();
        answer.0[141] ^= 1;
        assert_eq!(
            pending
                .complete(
                    answer.as_bytes(),
                    PeerIdentity::from_signing_key(&responder_key),
                )
                .err(),
            Some(SessionError::TranscriptMismatch)
        );
    }

    #[test]
    fn replay_window_accepts_reordering_once() {
        let mut window = ReplayWindow::default();
        window.check_and_mark(100).unwrap();
        window.check_and_mark(102).unwrap();
        window.check_and_mark(101).unwrap();
        assert_eq!(window.check_and_mark(101), Err(ReplayError::Duplicate));
        assert_eq!(window.check_and_mark(1), Err(ReplayError::TooOld));
        window.check_and_mark(200).unwrap();
    }
}
