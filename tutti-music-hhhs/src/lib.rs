//! Capability-native HHHS Replica protocol for [`tutti_music`].
//!
//! This crate is the narrow interoperability seam shared by full applications
//! and music-only peers. It owns the music command encoding, semantic
//! capability areas, admission policy, deterministic root construction, and
//! rebuildable materializer. It owns no discovery, endpoint, mesh, carrier,
//! task, clock, filesystem, or application-extension state.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use hhhs::{DagRead, DagSnapshot, Digest, Entry, EntryHash, Position, ReachIndex};
use hhhs_cap::{
    Area, AuthorizationDecision, AuthorizationRequest, CapabilityOp, CapabilitySnapshot, Grant,
    Receiver, Right, Rights, decode_op as decode_capability, encode_op as encode_capability,
};
use hhhs_proof::{MAX_PRESENTED_GRANTS, SigningKey};
use hhhs_replica::{
    AdmissionOutcome, AdmissionPolicy, AdmissionRequest, AdmittedAuthority, Replica, ReplicaError,
};
use hhhs_store::{Materializer, ProjectionCheckpoint, ProjectionKey, ReplicaStorage};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tutti_music::{Envelope, MusicOp, TunedDegree, TuningDefinition};

pub const PROTOCOL_GENERATION: u32 = 5;
pub const REPAIR_ALPN: &[u8] = b"tutti/music/hhhs-replica/5";
pub const STRATEGY_VERSION: u32 = 1;
pub const STRATEGY_NAME: &str = "tutti-music-hhhs-entry";

pub const COMMAND_DOMAIN: &[u8] = b"tutti music command v5\0";
const MAX_COMMAND_BYTES: usize = 1024 * 1024;

/// Stable Ed25519 receiver identity used by music commands and holder views.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct ActorId(pub [u8; 32]);

impl ActorId {
    pub fn from_signing_key(key: &SigningKey) -> Self {
        Self(key.verifying_key().to_bytes())
    }

    pub fn receiver(self) -> Receiver {
        Receiver::new(self.0.to_vec()).expect("a 32-byte actor is a valid receiver")
    }

    pub fn to_hex(self) -> String {
        use std::fmt::Write;
        self.0.iter().fold(
            String::with_capacity(self.0.len() * 2),
            |mut encoded, byte| {
                let _ = write!(encoded, "{byte:02x}");
                encoded
            },
        )
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CommandEnvelope {
    generation: u32,
    namespace: [u8; 32],
    actor: ActorId,
    presented: Vec<[u8; 32]>,
    command: MusicOp,
}

impl CommandEnvelope {
    pub const fn actor(&self) -> ActorId {
        self.actor
    }

    pub fn command(&self) -> &MusicOp {
        &self.command
    }

    pub const fn namespace(&self) -> Digest {
        Digest(self.namespace)
    }

    pub fn presented(&self) -> Result<Vec<EntryHash>, String> {
        presented_ids(self)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum CommandCodecError {
    #[error("command is too large: {0} bytes")]
    TooLarge(usize),
    #[error("command belongs to another protocol domain")]
    WrongDomain,
    #[error("command JSON is malformed")]
    Malformed,
    #[error("command encoding is not canonical")]
    NonCanonical,
    #[error("unsupported command generation {0}")]
    UnsupportedGeneration(u32),
}

pub fn encode_command(
    namespace: Digest,
    actor: ActorId,
    presented: &[EntryHash],
    command: MusicOp,
) -> Result<Vec<u8>, CommandCodecError> {
    encode_envelope(&CommandEnvelope {
        generation: PROTOCOL_GENERATION,
        namespace: *namespace.as_bytes(),
        actor,
        presented: presented.iter().map(|grant| *grant.as_bytes()).collect(),
        command,
    })
}

fn encode_envelope(envelope: &CommandEnvelope) -> Result<Vec<u8>, CommandCodecError> {
    let json = serde_json::to_vec(envelope).map_err(|_| CommandCodecError::Malformed)?;
    let mut bytes = Vec::with_capacity(COMMAND_DOMAIN.len() + json.len());
    bytes.extend_from_slice(COMMAND_DOMAIN);
    bytes.extend_from_slice(&json);
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(CommandCodecError::TooLarge(bytes.len()));
    }
    Ok(bytes)
}

pub fn decode_command(bytes: &[u8]) -> Result<CommandEnvelope, CommandCodecError> {
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(CommandCodecError::TooLarge(bytes.len()));
    }
    let json = bytes
        .strip_prefix(COMMAND_DOMAIN)
        .ok_or(CommandCodecError::WrongDomain)?;
    let envelope: CommandEnvelope =
        serde_json::from_slice(json).map_err(|_| CommandCodecError::Malformed)?;
    if envelope.generation != PROTOCOL_GENERATION {
        return Err(CommandCodecError::UnsupportedGeneration(
            envelope.generation,
        ));
    }
    if encode_envelope(&envelope)? != bytes {
        return Err(CommandCodecError::NonCanonical);
    }
    Ok(envelope)
}

pub fn notes_area(namespace: Digest) -> Area {
    Area::new(namespace, [b"music".to_vec(), b"notes".to_vec()]).expect("bounded command area")
}

pub fn tuning_area(namespace: Digest) -> Area {
    Area::new(namespace, [b"music".to_vec(), b"tuning".to_vec()]).expect("bounded command area")
}

pub fn command_area(namespace: Digest, command: &MusicOp) -> Area {
    match command {
        MusicOp::AddDegree { .. } | MusicOp::RemoveDegree { .. } | MusicOp::SetEnvelope { .. } => {
            notes_area(namespace)
        }
        MusicOp::SetTuning { .. } => tuning_area(namespace),
    }
}

fn presented_ids(envelope: &CommandEnvelope) -> Result<Vec<EntryHash>, String> {
    if envelope.presented.is_empty() || envelope.presented.len() > MAX_PRESENTED_GRANTS {
        return Err("command presents an invalid number of capability grants".into());
    }
    let ids: Vec<_> = envelope
        .presented
        .iter()
        .map(|bytes| EntryHash(Digest(*bytes)))
        .collect();
    let unique: BTreeSet<_> = ids.iter().copied().collect();
    if unique.len() != ids.len() {
        return Err("command repeats a presented capability grant".into());
    }
    Ok(ids)
}

/// Admission policy shared byte-for-byte by full and music-only Replicas.
#[derive(Clone)]
pub struct MusicAdmissionPolicy {
    namespace: Digest,
}

impl MusicAdmissionPolicy {
    pub const fn new(namespace: Digest) -> Self {
        Self { namespace }
    }

    fn validate_capability(
        &self,
        op: &CapabilityOp,
        entry: &Entry,
        history: &DagSnapshot,
        authority: &AdmittedAuthority,
    ) -> Result<(), String> {
        match (op, authority) {
            (CapabilityOp::Grant(grant), AdmittedAuthority::TrustedRoot) => {
                if grant.parent.is_some()
                    || grant.issuer != grant.receiver
                    || grant.area != Area::root(self.namespace)
                    || grant.rights != Rights::ALL
                    || grant.receiver.as_bytes().len() != 32
                {
                    return Err("invalid music Replica top-level capability grant".into());
                }
                Ok(())
            }
            (CapabilityOp::Grant(grant), AdmittedAuthority::Presented { presentation, .. }) => {
                let parent = grant
                    .parent
                    .ok_or_else(|| "delegation is missing its parent".to_owned())?;
                if grant.issuer != *presentation.receiver()
                    || !presentation.presented().contains(&parent)
                    || presentation.context().area != grant.area
                    || presentation.context().right != Right::Invoke
                    || grant.receiver.as_bytes().len() != 32
                {
                    return Err("invalid music capability delegation".into());
                }
                Ok(())
            }
            (CapabilityOp::Revoke(revoke), AdmittedAuthority::Presented { presentation, .. }) => {
                if revoke.revoker != *presentation.receiver() {
                    return Err("revoker does not equal proof receiver".into());
                }
                let target_entry = history
                    .entry(&revoke.target)
                    .ok_or_else(|| "revocation target is missing".to_owned())?;
                let CapabilityOp::Grant(target) = decode_capability(&target_entry.payload)
                    .map_err(|_| "revocation target is not a grant".to_owned())?
                else {
                    return Err("revocation target is not a grant".into());
                };
                if (revoke.revoker != target.issuer && revoke.revoker != target.receiver)
                    || presentation.context().area != target.area
                    || presentation.context().right != Right::Invoke
                    || !ReachIndex::new(history).is_ancestor(&revoke.target, &entry.hash())
                {
                    return Err("invalid music capability revocation".into());
                }
                Ok(())
            }
            _ => Err("capability operation used the wrong authority path".into()),
        }
    }
}

impl AdmissionPolicy for MusicAdmissionPolicy {
    fn validate(
        &self,
        entry: &Entry,
        history: &DagSnapshot,
        authority: &AdmittedAuthority,
    ) -> Result<(), String> {
        if let Ok(capability) = decode_capability(&entry.payload) {
            return self.validate_capability(&capability, entry, history, authority);
        }
        let envelope = decode_command(&entry.payload).map_err(|error| error.to_string())?;
        if envelope.namespace != *self.namespace.as_bytes() {
            return Err("command namespace does not match this Replica".into());
        }
        let AdmittedAuthority::Presented { presentation, .. } = authority else {
            return Err("music commands require a verified capability presentation".into());
        };
        if presentation.receiver().as_bytes() != envelope.actor.0
            || presentation.presented() != presented_ids(&envelope)?
            || presentation.context().area != command_area(self.namespace, &envelope.command)
            || presentation.context().right != Right::Invoke
        {
            return Err("music command presentation does not match its envelope".into());
        }
        tutti_music::ops::validate(&envelope.command)
    }
}

pub type MusicReplica<S> = Replica<S, MusicAdmissionPolicy>;

/// Build the deterministic capability root and a storage-aware music Replica.
pub fn initialize<S: ReplicaStorage + 'static>(
    namespace: Digest,
    owner: ActorId,
    storage: S,
) -> Result<(MusicReplica<S>, EntryHash), ReplicaError> {
    let root = hhhs_cap::entry(
        &CapabilityOp::Grant(Grant {
            issuer: owner.receiver(),
            receiver: owner.receiver(),
            area: Area::root(namespace),
            rights: Rights::ALL,
            parent: None,
        }),
        Position::empty(),
    );
    let root_id = root.hash();
    let replica = Replica::builder(storage, MusicAdmissionPolicy::new(namespace), namespace)
        .ed25519_capabilities([root_id])?
        .build()?;
    if !replica.snapshot().history.contains(&root_id) {
        replica.admit(AdmissionRequest::trusted_root(root))?;
    }
    Ok((replica, root_id))
}

pub fn author<S: ReplicaStorage + 'static>(
    replica: &MusicReplica<S>,
    namespace: Digest,
    key: &SigningKey,
    presented: Vec<EntryHash>,
    command: MusicOp,
) -> Result<AdmissionOutcome, ReplicaError> {
    let area = command_area(namespace, &command);
    let payload = encode_command(
        namespace,
        ActorId::from_signing_key(key),
        &presented,
        command,
    )
    .map_err(|error| ReplicaError::ApplicationRejected(error.to_string()))?;
    replica.author_ed25519(payload, area, Right::Invoke, presented, key)
}

fn currently_authorized(
    capabilities: &CapabilitySnapshot,
    history: &DagSnapshot,
    entry: EntryHash,
    envelope: &CommandEnvelope,
) -> bool {
    let Ok(presented) = presented_ids(envelope) else {
        return false;
    };
    matches!(
        capabilities.authorize(&AuthorizationRequest {
            receiver: envelope.actor.receiver(),
            area: command_area(Digest(envelope.namespace), &envelope.command),
            right: Right::Invoke,
            presented,
            at: Position::of([entry]),
            from: history.frontier(),
        }),
        AuthorizationDecision::Allowed(_)
    )
}

pub fn commands(history: &DagSnapshot, roots: &[EntryHash]) -> Vec<(EntryHash, ActorId, MusicOp)> {
    let capabilities = CapabilitySnapshot::capture(history, roots.iter().copied());
    history
        .entries_topo()
        .into_iter()
        .filter_map(|entry| {
            let id = entry.hash();
            let envelope = decode_command(&entry.payload).ok()?;
            currently_authorized(&capabilities, history, id, &envelope).then_some((
                id,
                envelope.actor,
                envelope.command,
            ))
        })
        .collect()
}

fn resolve_register<T>(reach: &ReachIndex, values: Vec<(EntryHash, T)>) -> Option<T> {
    let ids: Vec<_> = values.iter().map(|(id, _)| *id).collect();
    let winner = ids
        .iter()
        .filter(|candidate| !ids.iter().any(|other| reach.is_ancestor(candidate, other)))
        .max()
        .copied()?;
    values
        .into_iter()
        .find_map(|(id, value)| (id == winner).then_some(value))
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MusicView {
    pub live: BTreeSet<TunedDegree>,
    pub holders: BTreeMap<TunedDegree, BTreeSet<ActorId>>,
    pub envelopes: BTreeMap<TunedDegree, Envelope>,
    pub tuning: TuningDefinition,
}

impl Default for MusicView {
    fn default() -> Self {
        Self {
            live: BTreeSet::new(),
            holders: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            tuning: TuningDefinition::twelve_tet(),
        }
    }
}

pub fn materialize(history: &DagSnapshot, roots: &[EntryHash]) -> MusicView {
    let commands = commands(history, roots);
    let reach = ReachIndex::new(history);
    let tuning = resolve_register(
        &reach,
        commands
            .iter()
            .filter_map(|(id, _, command)| match command {
                MusicOp::SetTuning { definition } => Some((*id, definition.clone())),
                _ => None,
            })
            .collect(),
    )
    .unwrap_or_else(TuningDefinition::twelve_tet);
    let Ok(active) = tuning.validate("active music Replica tuning") else {
        return MusicView {
            tuning,
            ..MusicView::default()
        };
    };

    let mut live = BTreeSet::new();
    let mut holders: BTreeMap<TunedDegree, BTreeSet<ActorId>> = BTreeMap::new();
    for (add, actor, degree) in commands.iter().filter_map(|(id, actor, command)| {
        let MusicOp::AddDegree { degree } = command else {
            return None;
        };
        degree
            .validate(&active)
            .ok()
            .map(|degree| (*id, *actor, degree))
    }) {
        let killed = commands.iter().any(|(remove, _, command)| {
            matches!(command, MusicOp::RemoveDegree { degree: removed } if *removed == degree)
                && reach.is_ancestor(&add, remove)
        });
        if !killed {
            live.insert(degree);
            holders.entry(degree).or_default().insert(actor);
        }
    }

    let mut envelope_slots: BTreeMap<TunedDegree, Vec<(EntryHash, Envelope)>> = BTreeMap::new();
    for (id, _, command) in &commands {
        if let MusicOp::SetEnvelope { degree, env } = command
            && degree.validate(&active).is_ok()
        {
            envelope_slots
                .entry(*degree)
                .or_default()
                .push((*id, env.clone()));
        }
    }
    let envelopes = envelope_slots
        .into_iter()
        .filter_map(|(degree, values)| {
            resolve_register(&reach, values).map(|value| (degree, value))
        })
        .collect();
    MusicView {
        live,
        holders,
        envelopes,
        tuning,
    }
}

#[derive(Clone, Copy)]
pub struct MusicMaterializer {
    root: EntryHash,
}

impl MusicMaterializer {
    pub const fn new(root: EntryHash) -> Self {
        Self { root }
    }
}

#[derive(Serialize, Deserialize)]
struct CheckpointState {
    live: Vec<TunedDegree>,
    holders: Vec<(TunedDegree, Vec<ActorId>)>,
    envelopes: Vec<(TunedDegree, Envelope)>,
    tuning: TuningDefinition,
}

impl From<MusicView> for CheckpointState {
    fn from(view: MusicView) -> Self {
        Self {
            live: view.live.into_iter().collect(),
            holders: view
                .holders
                .into_iter()
                .map(|(degree, actors)| (degree, actors.into_iter().collect()))
                .collect(),
            envelopes: view.envelopes.into_iter().collect(),
            tuning: view.tuning,
        }
    }
}

impl TryFrom<&ProjectionCheckpoint> for MusicView {
    type Error = serde_json::Error;

    fn try_from(checkpoint: &ProjectionCheckpoint) -> Result<Self, Self::Error> {
        let state: CheckpointState = serde_json::from_slice(checkpoint.bytes())?;
        Ok(Self {
            live: state.live.into_iter().collect(),
            holders: state
                .holders
                .into_iter()
                .map(|(degree, actors)| (degree, actors.into_iter().collect()))
                .collect(),
            envelopes: state.envelopes.into_iter().collect(),
            tuning: state.tuning,
        })
    }
}

impl Materializer for MusicMaterializer {
    type Error = serde_json::Error;

    fn key(&self) -> ProjectionKey {
        ProjectionKey::new("tutti/music", PROTOCOL_GENERATION).expect("constant projection key")
    }

    fn project(
        &self,
        history: &DagSnapshot,
        _prior: Option<&ProjectionCheckpoint>,
    ) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(&CheckpointState::from(materialize(history, &[self.root])))
    }
}

pub fn delegation_payload(
    namespace: Digest,
    parent: EntryHash,
    issuer: ActorId,
    receiver: ActorId,
) -> Vec<u8> {
    encode_capability(&CapabilityOp::Grant(Grant {
        issuer: issuer.receiver(),
        receiver: receiver.receiver(),
        area: Area::root(namespace),
        rights: Rights::INVOKE,
        parent: Some(parent),
    }))
}

#[cfg(test)]
mod tests {
    use hhhs_store::MemoryStorage;
    use tutti_music::{MusicOp, TunedDegree, Tuning};

    use super::*;

    #[test]
    fn standalone_replica_authors_and_materializes_music() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let owner = ActorId::from_signing_key(&key);
        let namespace = Digest::of(b"independent tutti music object");
        let (replica, root) = initialize(namespace, owner, MemoryStorage::new()).unwrap();
        let degree = TunedDegree::new(&Tuning::twelve_tet(), 4).unwrap();
        author(
            &replica,
            namespace,
            &key,
            vec![root],
            MusicOp::AddDegree { degree },
        )
        .unwrap();
        assert_eq!(
            materialize(&replica.snapshot().history, &[root]).live,
            [degree].into()
        );
    }
}
