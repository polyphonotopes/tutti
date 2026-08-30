//! Executable design probe for a capability-authorized realtime music session.
//!
//! This is intentionally a model, not a public packet API. It fixes the seam
//! between the fast and durable planes while leaving the eventual session
//! crate, key agreement, AEAD, replay window, MIDI 2.0/UMP vocabulary, and
//! expiry policy open to measurement and review.
//!
//! The invariants exercised here are the durable contract:
//!
//! - one HHHS capability presentation authorizes a bounded session transcript;
//! - the transcript binds the namespace, actor, epoch, and compact bindings;
//! - short authenticated frames can project immediately without becoming HHHS
//!   entries one-for-one;
//! - the same binding maps to an ordinary `MusicOp` for durable admission;
//! - exact durable state confirms or corrects the fast projection; and
//! - Replica repair remains the convergence authority after loss or reconnect.

use std::collections::{BTreeMap, BTreeSet};

use futures::executor::block_on;
use hhhs::{DagRead, DagSnapshot, Digest, Encoder, EntryHash};
use hhhs_cap::{AuthorizationDecision, CapabilitySnapshot, Right};
use hhhs_proof::{
    Ed25519Verifier, PresentationContext, PresentationEnvelope, PresentationVerifier, SigningKey,
};
use hhhs_replica::{ReplicaRepairHost, ReplicaRepairSnapshot};
use hhhs_store::MemoryStorage;
use hhhs_sync::{EntrySource, RepairHost, entry_set_root};
use tutti_music::{MusicOp, TunedDegree, Tuning};
use tutti_music_hhhs::{
    ActorId, MusicReplica, MusicView, author, delegate, initialize, materialize, notes_area,
};

const SESSION_TRANSCRIPT_DOMAIN: &[u8] = b"tutti realtime session model v1";
const FRAME_MAGIC: [u8; 2] = *b"TS";
const FRAME_VERSION: u8 = 1;
const FRAME_BODY_BYTES: usize = 23;
const FRAME_TAG_BYTES: usize = 16;
const FRAME_BYTES: usize = FRAME_BODY_BYTES + FRAME_TAG_BYTES;
const MAX_SESSION_BINDINGS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SessionManifest {
    session: u64,
    epoch: u32,
    namespace: Digest,
    actor: ActorId,
    bindings: BTreeMap<u16, TunedDegree>,
}

impl SessionManifest {
    fn action_digest(&self) -> Digest {
        let mut encoder = Encoder::new();
        encoder
            .bytes(SESSION_TRANSCRIPT_DOMAIN)
            .digest(&self.namespace)
            .u64(self.session)
            .u32(self.epoch)
            .bytes(&self.actor.0)
            .u64(self.bindings.len() as u64);
        for (binding, degree) in &self.bindings {
            encoder
                .u32(u32::from(*binding))
                .bytes(degree.tuning_id.as_bytes())
                .u32(u32::from(degree.degree.index()));
        }
        encoder.digest_finish()
    }

    fn durable_command(&self, binding: u16, active: bool) -> Option<MusicOp> {
        let degree = *self.bindings.get(&binding)?;
        Some(if active {
            MusicOp::AddDegree { degree }
        } else {
            MusicOp::RemoveDegree { degree }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionOpenError {
    TooManyBindings,
    Proof,
    ActorMismatch,
    CapabilityDenied,
}

fn presentation_for(
    manifest: &SessionManifest,
    history: &DagSnapshot,
    grant: EntryHash,
    key: &SigningKey,
) -> (PresentationEnvelope, PresentationContext) {
    let context = PresentationContext::new(
        manifest.namespace,
        manifest.action_digest(),
        history.frontier(),
        notes_area(manifest.namespace),
        Right::Invoke,
    )
    .unwrap();
    let presentation = Ed25519Verifier::present(key, vec![grant], &context).unwrap();
    (presentation, context)
}

fn accept_manifest(
    manifest: SessionManifest,
    presentation: &PresentationEnvelope,
    history: &DagSnapshot,
    capability_root: EntryHash,
) -> Result<SessionManifest, SessionOpenError> {
    if manifest.bindings.len() > MAX_SESSION_BINDINGS {
        return Err(SessionOpenError::TooManyBindings);
    }
    let expected = PresentationContext::new(
        manifest.namespace,
        manifest.action_digest(),
        history.frontier(),
        notes_area(manifest.namespace),
        Right::Invoke,
    )
    .map_err(|_| SessionOpenError::Proof)?;
    let verified = Ed25519Verifier
        .verify(&presentation.payload, &expected)
        .map_err(|_| SessionOpenError::Proof)?;
    if verified.receiver().as_bytes() != manifest.actor.0 {
        return Err(SessionOpenError::ActorMismatch);
    }
    let capabilities = CapabilitySnapshot::capture_lazy(history, [capability_root]);
    match capabilities.authorize(&verified.authorization_request(history.frontier())) {
        AuthorizationDecision::Allowed(_) => Ok(manifest),
        AuthorizationDecision::Denied(_) => Err(SessionOpenError::CapabilityDenied),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GateFrame {
    session: u64,
    epoch: u32,
    sequence: u32,
    binding: u16,
    active: bool,
    velocity: u8,
}

impl GateFrame {
    fn encode(self, key: &[u8; 32]) -> [u8; FRAME_BYTES] {
        let mut bytes = [0_u8; FRAME_BYTES];
        bytes[..2].copy_from_slice(&FRAME_MAGIC);
        bytes[2] = FRAME_VERSION;
        bytes[3..11].copy_from_slice(&self.session.to_be_bytes());
        bytes[11..15].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[15..19].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[19..21].copy_from_slice(&self.binding.to_be_bytes());
        bytes[21] = u8::from(self.active);
        bytes[22] = self.velocity;
        let tag = blake3::keyed_hash(key, &bytes[..FRAME_BODY_BYTES]);
        bytes[FRAME_BODY_BYTES..].copy_from_slice(&tag.as_bytes()[..FRAME_TAG_BYTES]);
        bytes
    }

    fn decode(bytes: &[u8], key: &[u8; 32]) -> Result<Self, FrameError> {
        if bytes.len() != FRAME_BYTES || bytes[..2] != FRAME_MAGIC || bytes[2] != FRAME_VERSION {
            return Err(FrameError::Malformed);
        }
        let expected = blake3::keyed_hash(key, &bytes[..FRAME_BODY_BYTES]);
        let mut tag_difference = 0_u8;
        for (actual, expected) in bytes[FRAME_BODY_BYTES..]
            .iter()
            .zip(&expected.as_bytes()[..FRAME_TAG_BYTES])
        {
            tag_difference |= actual ^ expected;
        }
        if tag_difference != 0 {
            return Err(FrameError::Authentication);
        }
        let active = match bytes[21] {
            0 => false,
            1 => true,
            _ => return Err(FrameError::Malformed),
        };
        Ok(Self {
            session: u64::from_be_bytes(bytes[3..11].try_into().unwrap()),
            epoch: u32::from_be_bytes(bytes[11..15].try_into().unwrap()),
            sequence: u32::from_be_bytes(bytes[15..19].try_into().unwrap()),
            binding: u16::from_be_bytes(bytes[19..21].try_into().unwrap()),
            active,
            velocity: bytes[22],
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameError {
    Malformed,
    Authentication,
    WrongSession,
    WrongEpoch,
    Replay,
    UnknownBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiveOutcome {
    Applied,
    AppliedAfterGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableOutcome {
    Confirmed,
    Corrected,
}

struct SessionReceiver {
    manifest: SessionManifest,
    key: [u8; 32],
    last_sequence: u32,
    live: BTreeSet<TunedDegree>,
}

impl SessionReceiver {
    fn new(manifest: SessionManifest, key: [u8; 32], durable: &MusicView) -> Self {
        Self {
            manifest,
            key,
            last_sequence: 0,
            live: durable.live.clone(),
        }
    }

    fn receive(&mut self, bytes: &[u8]) -> Result<ReceiveOutcome, FrameError> {
        let frame = GateFrame::decode(bytes, &self.key)?;
        if frame.session != self.manifest.session {
            return Err(FrameError::WrongSession);
        }
        if frame.epoch != self.manifest.epoch {
            return Err(FrameError::WrongEpoch);
        }
        if frame.sequence <= self.last_sequence {
            return Err(FrameError::Replay);
        }
        let degree = *self
            .manifest
            .bindings
            .get(&frame.binding)
            .ok_or(FrameError::UnknownBinding)?;
        let outcome = if frame.sequence == self.last_sequence + 1 {
            ReceiveOutcome::Applied
        } else {
            ReceiveOutcome::AppliedAfterGap
        };
        self.last_sequence = frame.sequence;
        if frame.active {
            self.live.insert(degree);
        } else {
            self.live.remove(&degree);
        }
        Ok(outcome)
    }

    fn digest(&self) -> Digest {
        degree_set_digest(&self.live)
    }

    fn reconcile_durable(&mut self, durable: &MusicView) -> DurableOutcome {
        if self.live == durable.live {
            DurableOutcome::Confirmed
        } else {
            self.live.clone_from(&durable.live);
            DurableOutcome::Corrected
        }
    }
}

fn degree_set_digest(degrees: &BTreeSet<TunedDegree>) -> Digest {
    let mut encoder = Encoder::new();
    encoder
        .bytes(b"tutti realtime projected degree set v1")
        .u64(degrees.len() as u64);
    for degree in degrees {
        encoder
            .bytes(degree.tuning_id.as_bytes())
            .u32(u32::from(degree.degree.index()));
    }
    encoder.digest_finish()
}

fn repair_through(
    source: &MusicReplica<MemoryStorage>,
    target: &MusicReplica<MemoryStorage>,
    latest: EntryHash,
) {
    let snapshot: ReplicaRepairSnapshot = ReplicaRepairHost::new(source.clone())
        .capture([7; 16])
        .unwrap();
    let delivered = snapshot.bytes_with_closure(&latest, &mut BTreeSet::new());
    let mut target = ReplicaRepairHost::new(target.clone());
    let report = block_on(target.apply(&delivered)).unwrap();
    assert!(report.refused.is_empty());
    assert!(report.admitted.contains(&latest));
}

fn replica_root(replica: &MusicReplica<MemoryStorage>) -> [u8; 32] {
    entry_set_root(
        replica
            .snapshot()
            .history
            .entries_topo()
            .into_iter()
            .map(|entry| entry.hash()),
    )
}

#[test]
fn compact_fast_path_is_confirmed_or_corrected_by_durable_replica_state() {
    let owner_key = SigningKey::from_bytes(&[1; 32]);
    let member_key = SigningKey::from_bytes(&[2; 32]);
    let owner = ActorId::from_signing_key(&owner_key);
    let member = ActorId::from_signing_key(&member_key);
    let namespace = Digest::of(b"tutti executable realtime-session probe");
    let (owner_replica, root) = initialize(namespace, owner, MemoryStorage::new()).unwrap();
    let (member_replica, member_root) = initialize(namespace, owner, MemoryStorage::new()).unwrap();
    assert_eq!(root, member_root);

    let grant = delegate(&owner_replica, namespace, root, &owner_key, member)
        .unwrap()
        .entry;
    repair_through(&owner_replica, &member_replica, grant);

    let degree = TunedDegree::new(&Tuning::twelve_tet(), 6).unwrap();
    let manifest = SessionManifest {
        session: 0x0102_0304_0506_0708,
        epoch: 4,
        namespace,
        actor: member,
        bindings: BTreeMap::from([(7, degree)]),
    };
    let (presentation, _) = presentation_for(
        &manifest,
        &member_replica.snapshot().history,
        grant,
        &member_key,
    );
    let accepted = accept_manifest(
        manifest.clone(),
        &presentation,
        &owner_replica.snapshot().history,
        root,
    )
    .unwrap();
    let session_key = [0x5a; 32];
    let durable_before = materialize(&owner_replica.snapshot().history, &[root]);
    let mut receiver = SessionReceiver::new(accepted, session_key, &durable_before);

    let add = GateFrame {
        session: manifest.session,
        epoch: manifest.epoch,
        sequence: 1,
        binding: 7,
        active: true,
        velocity: 96,
    };
    let encoded = add.encode(&session_key);
    assert_eq!(
        encoded.len(),
        39,
        "model frame stays far below a full record"
    );
    let mut tampered = encoded;
    tampered[22] ^= 1;
    assert_eq!(receiver.receive(&tampered), Err(FrameError::Authentication));
    assert_eq!(receiver.receive(&encoded), Ok(ReceiveOutcome::Applied));
    assert_eq!(receiver.receive(&encoded), Err(FrameError::Replay));
    assert_eq!(receiver.live, BTreeSet::from([degree]));
    assert_ne!(receiver.digest(), degree_set_digest(&durable_before.live));

    let add_entry = author(
        &member_replica,
        namespace,
        &member_key,
        vec![grant],
        manifest.durable_command(7, true).unwrap(),
    )
    .unwrap()
    .entry;
    repair_through(&member_replica, &owner_replica, add_entry);
    let durable_add = materialize(&owner_replica.snapshot().history, &[root]);
    assert_eq!(
        receiver.reconcile_durable(&durable_add),
        DurableOutcome::Confirmed
    );
    assert_eq!(receiver.digest(), degree_set_digest(&durable_add.live));

    // The realtime removal is lost. Durable admission and ordinary HHHS repair
    // still correct the remote projection instead of preserving a stuck note.
    let remove_entry = author(
        &member_replica,
        namespace,
        &member_key,
        vec![grant],
        manifest.durable_command(7, false).unwrap(),
    )
    .unwrap()
    .entry;
    repair_through(&member_replica, &owner_replica, remove_entry);
    let durable_remove = materialize(&owner_replica.snapshot().history, &[root]);
    assert_eq!(
        receiver.reconcile_durable(&durable_remove),
        DurableOutcome::Corrected
    );
    assert!(receiver.live.is_empty());
    assert_eq!(replica_root(&owner_replica), replica_root(&member_replica));
}

#[test]
fn session_proof_cannot_be_replayed_for_other_bindings_or_receiver() {
    let owner_key = SigningKey::from_bytes(&[11; 32]);
    let member_key = SigningKey::from_bytes(&[12; 32]);
    let attacker_key = SigningKey::from_bytes(&[13; 32]);
    let owner = ActorId::from_signing_key(&owner_key);
    let member = ActorId::from_signing_key(&member_key);
    let namespace = Digest::of(b"tutti session transcript binding probe");
    let (replica, root) = initialize(namespace, owner, MemoryStorage::new()).unwrap();
    let grant = delegate(&replica, namespace, root, &owner_key, member)
        .unwrap()
        .entry;
    let tuning = Tuning::twelve_tet();
    let manifest = SessionManifest {
        session: 44,
        epoch: 2,
        namespace,
        actor: member,
        bindings: BTreeMap::from([(3, TunedDegree::new(&tuning, 3).unwrap())]),
    };
    let history = replica.snapshot().history;
    let (presentation, _) = presentation_for(&manifest, &history, grant, &member_key);

    let mut changed = manifest.clone();
    changed
        .bindings
        .insert(4, TunedDegree::new(&tuning, 8).unwrap());
    assert_eq!(
        accept_manifest(changed, &presentation, &history, root),
        Err(SessionOpenError::Proof)
    );

    let mut attacker_manifest = manifest;
    attacker_manifest.actor = ActorId::from_signing_key(&attacker_key);
    let (attacker_presentation, _) =
        presentation_for(&attacker_manifest, &history, grant, &attacker_key);
    assert_eq!(
        accept_manifest(attacker_manifest, &attacker_presentation, &history, root),
        Err(SessionOpenError::CapabilityDenied)
    );
}

#[test]
fn session_manifest_refuses_an_unbounded_binding_table() {
    let owner_key = SigningKey::from_bytes(&[21; 32]);
    let owner = ActorId::from_signing_key(&owner_key);
    let namespace = Digest::of(b"bounded tutti session manifest");
    let (replica, root) = initialize(namespace, owner, MemoryStorage::new()).unwrap();
    let tuning = Tuning::from_scl_text(
        "large equal division",
        &format!(
            "large equal division\n{}\n{}",
            MAX_SESSION_BINDINGS + 1,
            (1..=MAX_SESSION_BINDINGS + 1)
                .map(|step| format!(
                    "{:.6}\n",
                    step as f64 * 1200.0 / (MAX_SESSION_BINDINGS + 1) as f64
                ))
                .collect::<String>()
        ),
        None,
    )
    .unwrap();
    let bindings = (0..=MAX_SESSION_BINDINGS)
        .map(|index| {
            (
                index as u16,
                TunedDegree::new(&tuning, index as u16).unwrap(),
            )
        })
        .collect();
    let manifest = SessionManifest {
        session: 55,
        epoch: 1,
        namespace,
        actor: owner,
        bindings,
    };
    let (presentation, _) =
        presentation_for(&manifest, &replica.snapshot().history, root, &owner_key);
    assert_eq!(
        accept_manifest(manifest, &presentation, &replica.snapshot().history, root),
        Err(SessionOpenError::TooManyBindings)
    );
}
