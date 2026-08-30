//! HHHS Replica protocol for [`tutti_music`].
//!
//! This crate is the narrow interoperability seam shared by full applications
//! and music-only peers. It owns the music command encoding, semantic
//! authority profiles, admission policy, deterministic capability-root
//! construction, and rebuildable materializer. It owns no discovery, session
//! establishment, endpoint, mesh, carrier, task, clock, filesystem, or
//! application-extension state.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use hhhs::{
    DagRead, DagSnapshot, Digest, Entry, EntryHash, LazyReach, Position, Reach, ReachIndex,
    WalkingReach,
};
use hhhs_cap::{
    Area, AuthorizationDecision, AuthorizationRequest, CapabilityOp, CapabilitySnapshot, Grant,
    Receiver, Right, Rights, decode_op as decode_capability, encode_op as encode_capability,
};
use hhhs_proof::{MAX_PRESENTED_GRANTS, SigningKey};
use hhhs_replica::{
    AdmissionOutcome, AdmissionPolicy, AdmissionRequest, AdmittedAuthority, Replica, ReplicaError,
};
use hhhs_store::{
    Materializer, ProjectionCheckpoint, ProjectionInput, ProjectionKey, ProjectionUpdate,
    ReplicaStorage,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tutti_music::{
    Envelope, MusicOp, RoundTableConfig, SharedPitchSet, TunedDegree, TunedPeriodicPitch,
    TuningDefinition,
};

pub const PROTOCOL_GENERATION: u32 = 8;
const PROJECTION_SCHEMA: u32 = 6;
pub const REPAIR_ALPN: &[u8] = b"tutti/music/hhhs-replica/8";
pub const STRATEGY_VERSION: u32 = 1;
pub const STRATEGY_NAME: &str = "tutti-music-hhhs-entry";

pub const COMMAND_DOMAIN: &[u8] = b"tutti music command v8\0";
const MAX_COMMAND_BYTES: usize = 1024 * 1024;

/// Stable actor identity used by music commands and holder views.
///
/// Capability authority binds these bytes to an Ed25519 receiver. Open-session
/// authority treats them as an application-level identity supplied by an
/// already-authenticated channel.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct ActorId(pub [u8; 32]);

impl ActorId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

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

pub fn performance_area(namespace: Digest) -> Area {
    Area::new(namespace, [b"music".to_vec(), b"performance".to_vec()])
        .expect("bounded command area")
}

pub fn command_area(namespace: Digest, command: &MusicOp) -> Area {
    match command {
        MusicOp::AddDegree { .. }
        | MusicOp::RemoveDegree { .. }
        | MusicOp::AddPitch { .. }
        | MusicOp::RemovePitch { .. }
        | MusicOp::SetEnvelope { .. } => notes_area(namespace),
        MusicOp::SetTuning { .. } => tuning_area(namespace),
        MusicOp::SetRoundTable { .. } => performance_area(namespace),
    }
}

fn presented_ids(envelope: &CommandEnvelope) -> Result<Vec<EntryHash>, String> {
    if envelope.presented.len() > MAX_PRESENTED_GRANTS {
        return Err("command presents too many capability grants".into());
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

fn capability_ids(envelope: &CommandEnvelope) -> Result<Vec<EntryHash>, String> {
    let ids = presented_ids(envelope)?;
    if ids.is_empty() {
        return Err("capability-authorized command presents no grants".into());
    }
    Ok(ids)
}

/// The authority contract of a music Replica.
///
/// This is intentionally explicit and forms part of the protocol profile:
/// peers configured for different modes refuse one another's entries instead
/// of silently downgrading authentication.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MusicAuthority {
    Capabilities,
    OpenSession,
}

/// Admission policy shared byte-for-byte by full and music-only Replicas.
#[derive(Clone)]
pub struct MusicAdmissionPolicy {
    namespace: Digest,
    authority: MusicAuthority,
}

impl MusicAdmissionPolicy {
    /// Capability-authorized policy retained as the conservative default.
    pub const fn new(namespace: Digest) -> Self {
        Self::capabilities(namespace)
    }

    pub const fn capabilities(namespace: Digest) -> Self {
        Self {
            namespace,
            authority: MusicAuthority::Capabilities,
        }
    }

    pub const fn open_session(namespace: Digest) -> Self {
        Self {
            namespace,
            authority: MusicAuthority::OpenSession,
        }
    }

    pub const fn authority(&self) -> MusicAuthority {
        self.authority
    }

    fn validate_capability(
        &self,
        op: &CapabilityOp,
        entry: &Entry,
        history: &DagSnapshot,
        authority: &AdmittedAuthority,
    ) -> Result<(), String> {
        if self.authority != MusicAuthority::Capabilities {
            return Err("capability operation is disabled for open-session music".into());
        }
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
        match (self.authority, authority) {
            (MusicAuthority::Capabilities, AdmittedAuthority::Presented { presentation, .. }) => {
                if presentation.receiver().as_bytes() != envelope.actor.0
                    || presentation.presented() != capability_ids(&envelope)?
                    || presentation.context().area
                        != command_area(self.namespace, &envelope.command)
                    || presentation.context().right != Right::Invoke
                {
                    return Err("music command presentation does not match its envelope".into());
                }
            }
            (MusicAuthority::OpenSession, AdmittedAuthority::Open { .. }) => {
                if !envelope.presented.is_empty() {
                    return Err("open-session command must not present capability grants".into());
                }
            }
            (MusicAuthority::Capabilities, _) => {
                return Err("music commands require a verified capability presentation".into());
            }
            (MusicAuthority::OpenSession, _) => {
                return Err("open-session music requires HHHS open authority".into());
            }
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
    let replica = Replica::builder(
        storage,
        MusicAdmissionPolicy::capabilities(namespace),
        namespace,
    )
    .ed25519_capabilities([root_id])?
    .build()?;
    if !replica.snapshot().history.contains(&root_id) {
        replica.admit(AdmissionRequest::trusted_root(root))?;
    }
    Ok((replica, root_id))
}

/// Build a music Replica whose trust boundary is an authenticated session.
///
/// Entries retain HHHS hashing, causal ordering, validation, merge, and repair,
/// but carry no per-entry capability proof. Callers must only feed repair data
/// received through a channel whose peer was authenticated independently.
pub fn initialize_open<S: ReplicaStorage + 'static>(
    namespace: Digest,
    storage: S,
) -> Result<MusicReplica<S>, ReplicaError> {
    Replica::builder(
        storage,
        MusicAdmissionPolicy::open_session(namespace),
        namespace,
    )
    .open()
    .build()
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

/// Author through HHHS open authority after the caller's session boundary has
/// authenticated the actor. This performs no public-key operation.
pub fn author_open<S: ReplicaStorage + 'static>(
    replica: &MusicReplica<S>,
    namespace: Digest,
    actor: ActorId,
    command: MusicOp,
) -> Result<AdmissionOutcome, ReplicaError> {
    let payload = encode_command(namespace, actor, &[], command)
        .map_err(|error| ReplicaError::ApplicationRejected(error.to_string()))?;
    replica.author_open(payload)
}

fn currently_authorized<R: Reach>(
    capabilities: &CapabilitySnapshot<R>,
    history: &DagSnapshot,
    entry: EntryHash,
    envelope: &CommandEnvelope,
) -> bool {
    let Ok(presented) = capability_ids(envelope) else {
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

fn valid_open_command(namespace: Digest, envelope: &CommandEnvelope) -> bool {
    envelope.namespace == *namespace.as_bytes()
        && envelope.presented.is_empty()
        && tutti_music::ops::validate(&envelope.command).is_ok()
}

pub fn commands(history: &DagSnapshot, roots: &[EntryHash]) -> Vec<(EntryHash, ActorId, MusicOp)> {
    let capabilities = CapabilitySnapshot::<LazyReach>::capture_with(
        history,
        roots.iter().copied(),
        LazyReach::new,
    );
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

/// Decode commands admitted under the open-session profile.
///
/// This does not authenticate actors. The enclosing session is responsible for
/// authenticating every repair sender before its entries reach the Replica.
pub fn open_commands(
    history: &DagSnapshot,
    namespace: Digest,
) -> Vec<(EntryHash, ActorId, MusicOp)> {
    history
        .entries_topo()
        .into_iter()
        .filter_map(|entry| {
            let id = entry.hash();
            let envelope = decode_command(&entry.payload).ok()?;
            valid_open_command(namespace, &envelope).then_some((
                id,
                envelope.actor,
                envelope.command,
            ))
        })
        .collect()
}

/// Advance causal maxima while consuming entries in topological order.
///
/// Any existing candidate in the new entry's past has been superseded. The
/// remaining candidates are concurrent with the new one, so retaining only
/// these maxima bounds common-case work by actual concurrency instead of total
/// retained history.
fn advance_maxima<T, R: Reach>(
    reach: &R,
    maxima: &mut Vec<(EntryHash, T)>,
    id: EntryHash,
    value: T,
) {
    maxima.retain(|(candidate, _)| !reach.is_ancestor(candidate, &id));
    maxima.push((id, value));
}

fn resolve_maxima<T>(values: Vec<(EntryHash, T)>) -> Option<T> {
    let winner = values.iter().map(|(id, _)| *id).max()?;
    values
        .into_iter()
        .find_map(|(id, value)| (id == winner).then_some(value))
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MusicView {
    pub live: BTreeSet<TunedDegree>,
    pub holders: BTreeMap<TunedDegree, BTreeSet<ActorId>>,
    pub live_pitches: BTreeSet<TunedPeriodicPitch>,
    pub pitch_holders: BTreeMap<TunedPeriodicPitch, BTreeSet<ActorId>>,
    pub envelopes: BTreeMap<TunedDegree, Envelope>,
    pub tuning: TuningDefinition,
    pub round_table: RoundTableConfig,
    /// One room-owned pitch set. Any authorized peer may edit any member.
    pub shared_pitches: SharedPitchSet,
}

impl Default for MusicView {
    fn default() -> Self {
        Self {
            live: BTreeSet::new(),
            holders: BTreeMap::new(),
            live_pitches: BTreeSet::new(),
            pitch_holders: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            tuning: TuningDefinition::twelve_tet(),
            round_table: RoundTableConfig::default(),
            shared_pitches: SharedPitchSet::default(),
        }
    }
}

pub fn materialize(history: &DagSnapshot, roots: &[EntryHash]) -> MusicView {
    let commands = commands(history, roots);
    materialize_commands(history, &commands)
}

pub fn materialize_open(history: &DagSnapshot, namespace: Digest) -> MusicView {
    let commands = open_commands(history, namespace);
    materialize_commands(history, &commands)
}

fn materialize_commands(
    history: &DagSnapshot,
    commands: &[(EntryHash, ActorId, MusicOp)],
) -> MusicView {
    fold_state(history, commands).view()
}

#[derive(Clone, Default)]
struct FoldState {
    tuning_maxima: Vec<(EntryHash, TuningDefinition)>,
    round_table_maxima: Vec<(EntryHash, RoundTableConfig)>,
    live_adds: BTreeMap<TunedDegree, Vec<(EntryHash, ActorId)>>,
    live_pitch_adds: BTreeMap<TunedPeriodicPitch, Vec<(EntryHash, ActorId)>>,
    envelope_maxima: BTreeMap<TunedDegree, Vec<(EntryHash, Envelope)>>,
}

impl FoldState {
    fn tuning(&self) -> TuningDefinition {
        resolve_maxima(self.tuning_maxima.clone()).unwrap_or_else(TuningDefinition::twelve_tet)
    }

    fn round_table(&self) -> RoundTableConfig {
        resolve_maxima(self.round_table_maxima.clone()).unwrap_or_default()
    }

    fn apply_commands(
        &mut self,
        history: &DagSnapshot,
        commands: &[(EntryHash, ActorId, MusicOp)],
    ) {
        let tuning = self.tuning();
        let Ok(active) = tuning.validate("active music Replica tuning") else {
            return;
        };
        let reach = WalkingReach::new(history);
        for (id, actor, command) in commands {
            match command {
                MusicOp::AddDegree { degree } if degree.validate(&active).is_ok() => {
                    self.live_adds
                        .entry(*degree)
                        .or_default()
                        .push((*id, *actor));
                }
                MusicOp::RemoveDegree { degree } => {
                    if let Some(adds) = self.live_adds.get_mut(degree) {
                        adds.retain(|(add, _)| !reach.is_ancestor(add, id));
                    }
                }
                MusicOp::AddPitch { pitch } if pitch.validate(&active).is_ok() => {
                    self.live_pitch_adds
                        .entry(*pitch)
                        .or_default()
                        .push((*id, *actor));
                }
                MusicOp::RemovePitch { pitch } => {
                    if let Some(adds) = self.live_pitch_adds.get_mut(pitch) {
                        adds.retain(|(add, _)| !reach.is_ancestor(add, id));
                    }
                }
                MusicOp::SetEnvelope { degree, env } if degree.validate(&active).is_ok() => {
                    advance_maxima(
                        &reach,
                        self.envelope_maxima.entry(*degree).or_default(),
                        *id,
                        env.clone(),
                    );
                }
                MusicOp::SetRoundTable { config } => {
                    advance_maxima(&reach, &mut self.round_table_maxima, *id, *config);
                }
                MusicOp::SetTuning { .. }
                | MusicOp::SetEnvelope { .. }
                | MusicOp::AddDegree { .. }
                | MusicOp::AddPitch { .. } => {}
            }
        }
    }

    fn view(&self) -> MusicView {
        let tuning = self.tuning();
        if tuning.validate("active music Replica tuning").is_err() {
            return MusicView {
                tuning,
                round_table: self.round_table(),
                ..MusicView::default()
            };
        }
        let mut live = BTreeSet::new();
        let mut holders = BTreeMap::new();
        for (degree, adds) in &self.live_adds {
            if !adds.is_empty() {
                live.insert(*degree);
                holders.insert(*degree, adds.iter().map(|(_, actor)| *actor).collect());
            }
        }
        let mut live_pitches = BTreeSet::new();
        let mut pitch_holders = BTreeMap::new();
        for (pitch, adds) in &self.live_pitch_adds {
            if !adds.is_empty() {
                live_pitches.insert(*pitch);
                pitch_holders.insert(*pitch, adds.iter().map(|(_, actor)| *actor).collect());
            }
        }
        let envelopes = self
            .envelope_maxima
            .iter()
            .filter_map(|(degree, values)| {
                resolve_maxima(values.clone()).map(|value| (*degree, value))
            })
            .collect();
        let shared_pitches = SharedPitchSet {
            pitch_classes: live.clone(),
            pitches: live_pitches.clone(),
        };
        MusicView {
            live,
            holders,
            live_pitches,
            pitch_holders,
            envelopes,
            tuning,
            round_table: self.round_table(),
            shared_pitches,
        }
    }
}

fn fold_state(history: &DagSnapshot, commands: &[(EntryHash, ActorId, MusicOp)]) -> FoldState {
    let reach = WalkingReach::new(history);
    let mut state = FoldState::default();
    for (id, _, command) in commands {
        if let MusicOp::SetTuning { definition } = command {
            advance_maxima(&reach, &mut state.tuning_maxima, *id, definition.clone());
        }
    }
    state.apply_commands(history, commands);
    state
}

#[derive(Clone)]
enum MaterializationAuthority {
    Capabilities(Vec<EntryHash>),
    OpenSession(Digest),
}

#[derive(Clone)]
pub struct MusicMaterializer {
    authority: MaterializationAuthority,
}

impl MusicMaterializer {
    pub fn new(root: EntryHash) -> Self {
        Self::from_roots([root])
    }

    /// Materialize a federated room whose accepted commands may descend from
    /// more than one explicitly trusted capability root. Roots are sorted and
    /// deduplicated so every peer derives the same projection identity.
    pub fn from_roots(roots: impl IntoIterator<Item = EntryHash>) -> Self {
        let roots: BTreeSet<_> = roots.into_iter().collect();
        Self {
            authority: MaterializationAuthority::Capabilities(roots.into_iter().collect()),
        }
    }

    /// Materialize open-authority entries from one authenticated session
    /// namespace. The namespace is included in the projection identity.
    pub const fn open_session(namespace: Digest) -> Self {
        Self {
            authority: MaterializationAuthority::OpenSession(namespace),
        }
    }

    pub fn roots(&self) -> &[EntryHash] {
        match &self.authority {
            MaterializationAuthority::Capabilities(roots) => roots,
            MaterializationAuthority::OpenSession(_) => &[],
        }
    }

    fn projection_name(&self) -> String {
        use std::fmt::Write;

        let mut binding = Vec::new();
        match &self.authority {
            MaterializationAuthority::Capabilities(roots) => {
                binding.extend_from_slice(b"capabilities\0");
                binding.reserve(roots.len() * 32);
                for root in roots {
                    binding.extend_from_slice(root.as_bytes());
                }
            }
            MaterializationAuthority::OpenSession(namespace) => {
                binding.extend_from_slice(b"open-session\0");
                binding.extend_from_slice(namespace.as_bytes());
            }
        }
        let digest = Digest::of(&binding);
        let suffix =
            digest
                .as_bytes()
                .iter()
                .fold(String::with_capacity(64), |mut encoded, byte| {
                    let _ = write!(encoded, "{byte:02x}");
                    encoded
                });
        format!("tutti/music/{suffix}")
    }
}

#[derive(Serialize, Deserialize)]
struct CheckpointState {
    tuning_maxima: Vec<(EntryHash, TuningDefinition)>,
    round_table_maxima: Vec<(EntryHash, RoundTableConfig)>,
    live_adds: Vec<(TunedDegree, Vec<(EntryHash, ActorId)>)>,
    live_pitch_adds: Vec<(TunedPeriodicPitch, Vec<(EntryHash, ActorId)>)>,
    envelope_maxima: Vec<(TunedDegree, Vec<(EntryHash, Envelope)>)>,
}

impl From<FoldState> for CheckpointState {
    fn from(state: FoldState) -> Self {
        Self {
            tuning_maxima: state.tuning_maxima,
            round_table_maxima: state.round_table_maxima,
            live_adds: state.live_adds.into_iter().collect(),
            live_pitch_adds: state.live_pitch_adds.into_iter().collect(),
            envelope_maxima: state.envelope_maxima.into_iter().collect(),
        }
    }
}

impl From<CheckpointState> for FoldState {
    fn from(state: CheckpointState) -> Self {
        Self {
            tuning_maxima: state.tuning_maxima,
            round_table_maxima: state.round_table_maxima,
            live_adds: state.live_adds.into_iter().collect(),
            live_pitch_adds: state.live_pitch_adds.into_iter().collect(),
            envelope_maxima: state.envelope_maxima.into_iter().collect(),
        }
    }
}

impl TryFrom<&ProjectionCheckpoint> for MusicView {
    type Error = serde_json::Error;

    fn try_from(checkpoint: &ProjectionCheckpoint) -> Result<Self, Self::Error> {
        let state: CheckpointState = serde_json::from_slice(checkpoint.bytes())?;
        Ok(FoldState::from(state).view())
    }
}

impl Materializer for MusicMaterializer {
    type Error = serde_json::Error;

    fn key(&self) -> ProjectionKey {
        ProjectionKey::new(self.projection_name(), PROJECTION_SCHEMA)
            .expect("bounded music projection key")
    }

    fn project(
        &self,
        history: &DagSnapshot,
        _prior: Option<&ProjectionCheckpoint>,
    ) -> Result<Vec<u8>, Self::Error> {
        let commands = match &self.authority {
            MaterializationAuthority::Capabilities(roots) => commands(history, roots),
            MaterializationAuthority::OpenSession(namespace) => open_commands(history, *namespace),
        };
        serde_json::to_vec(&CheckpointState::from(fold_state(history, &commands)))
    }

    fn update(&self, input: ProjectionInput<'_>) -> Result<Vec<u8>, Self::Error> {
        let ProjectionUpdate::Incremental { appended } = input.update else {
            return self.project(input.history, None);
        };
        let Some(prior) = input.prior else {
            return self.project(input.history, None);
        };

        let mut incremental = Vec::new();
        let capabilities = match &self.authority {
            MaterializationAuthority::Capabilities(roots) => {
                Some(CapabilitySnapshot::<LazyReach>::capture_with(
                    input.history,
                    roots.iter().copied(),
                    LazyReach::new,
                ))
            }
            MaterializationAuthority::OpenSession(_) => None,
        };
        for entry in appended {
            if capabilities.is_some() && decode_capability(&entry.payload).is_ok() {
                return self.project(input.history, None);
            }
            let Ok(envelope) = decode_command(&entry.payload) else {
                return self.project(input.history, None);
            };
            if matches!(envelope.command, MusicOp::SetTuning { .. }) {
                return self.project(input.history, None);
            }
            let accepted = match (&self.authority, capabilities.as_ref()) {
                (MaterializationAuthority::Capabilities(_), Some(capabilities)) => {
                    currently_authorized(capabilities, input.history, entry.hash(), &envelope)
                }
                (MaterializationAuthority::OpenSession(namespace), None) => {
                    valid_open_command(*namespace, &envelope)
                }
                _ => false,
            };
            if accepted {
                incremental.push((entry.hash(), envelope.actor, envelope.command));
            }
        }

        let checkpoint: CheckpointState = serde_json::from_slice(prior.bytes())?;
        let mut state = FoldState::from(checkpoint);
        state.apply_commands(input.history, &incremental);
        serde_json::to_vec(&CheckpointState::from(state))
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

/// Delegate music invocation to one receiver through the same typed Replica
/// admission path used for commands. The returned entry hash is the grant the
/// receiver presents when authoring subsequent music commands.
pub fn delegate<S: ReplicaStorage + 'static>(
    replica: &MusicReplica<S>,
    namespace: Digest,
    parent: EntryHash,
    issuer_key: &SigningKey,
    receiver: ActorId,
) -> Result<AdmissionOutcome, ReplicaError> {
    let issuer = ActorId::from_signing_key(issuer_key);
    replica.author_ed25519(
        delegation_payload(namespace, parent, issuer, receiver),
        Area::root(namespace),
        Right::Invoke,
        vec![parent],
        issuer_key,
    )
}

#[cfg(test)]
mod tests {
    use hhhs_store::MemoryStorage;
    use tutti_music::{MusicOp, TunedDegree, Tuning};

    use super::*;

    fn resolve_reference<T>(reach: &ReachIndex, values: Vec<(EntryHash, T)>) -> Option<T> {
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

    /// The pre-optimization all-pairs fold, kept only as a semantic oracle.
    fn materialize_reference(
        history: &DagSnapshot,
        commands: &[(EntryHash, ActorId, MusicOp)],
    ) -> MusicView {
        let reach = ReachIndex::new(history);
        let tuning = resolve_reference(
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
        let round_table = resolve_reference(
            &reach,
            commands
                .iter()
                .filter_map(|(id, _, command)| match command {
                    MusicOp::SetRoundTable { config } => Some((*id, *config)),
                    _ => None,
                })
                .collect(),
        )
        .unwrap_or_default();
        let Ok(active) = tuning.validate("reference tuning") else {
            return MusicView {
                tuning,
                round_table,
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
        for (id, _, command) in commands {
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
                resolve_reference(&reach, values).map(|value| (degree, value))
            })
            .collect();
        let mut live_pitches = BTreeSet::new();
        let mut pitch_holders: BTreeMap<TunedPeriodicPitch, BTreeSet<ActorId>> = BTreeMap::new();
        for (add, actor, pitch) in commands.iter().filter_map(|(id, actor, command)| {
            let MusicOp::AddPitch { pitch } = command else {
                return None;
            };
            pitch
                .validate(&active)
                .ok()
                .map(|pitch| (*id, *actor, pitch))
        }) {
            let killed = commands.iter().any(|(remove, _, command)| {
                matches!(command, MusicOp::RemovePitch { pitch: removed } if *removed == pitch)
                    && reach.is_ancestor(&add, remove)
            });
            if !killed {
                live_pitches.insert(pitch);
                pitch_holders.entry(pitch).or_default().insert(actor);
            }
        }
        let shared_pitches = SharedPitchSet {
            pitch_classes: live.clone(),
            pitches: live_pitches.clone(),
        };
        MusicView {
            live,
            holders,
            live_pitches,
            pitch_holders,
            envelopes,
            tuning,
            round_table,
            shared_pitches,
        }
    }

    fn topo_commands(
        history: &DagSnapshot,
        commands: BTreeMap<EntryHash, (ActorId, MusicOp)>,
    ) -> Vec<(EntryHash, ActorId, MusicOp)> {
        history
            .entries_topo()
            .into_iter()
            .filter_map(|entry| {
                let id = entry.hash();
                commands
                    .get(&id)
                    .cloned()
                    .map(|(actor, command)| (id, actor, command))
            })
            .collect()
    }

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

    #[test]
    fn open_session_replica_keeps_crdt_semantics_without_per_entry_proofs() {
        let namespace = Digest::of(b"authenticated channel open music object");
        let actor = ActorId::from_bytes([0x51; 32]);
        let replica = initialize_open(namespace, MemoryStorage::new()).unwrap();
        let projection = MusicMaterializer::open_session(namespace);
        let initial =
            hhhs_store::materialize(&projection, &replica.snapshot().history, None).unwrap();
        let degree = TunedDegree::new(&Tuning::twelve_tet(), 5).unwrap();

        author_open(&replica, namespace, actor, MusicOp::AddDegree { degree }).unwrap();
        let added =
            hhhs_store::materialize(&projection, &replica.snapshot().history, Some(&initial))
                .unwrap();
        let added_view = MusicView::try_from(&added).unwrap();
        assert_eq!(added_view.live, BTreeSet::from([degree]));
        assert_eq!(added_view.holders[&degree], BTreeSet::from([actor]));

        author_open(&replica, namespace, actor, MusicOp::RemoveDegree { degree }).unwrap();
        let removed =
            hhhs_store::materialize(&projection, &replica.snapshot().history, Some(&added))
                .unwrap();
        let rebuilt =
            hhhs_store::materialize(&projection, &replica.snapshot().history, None).unwrap();
        assert!(MusicView::try_from(&removed).unwrap().live.is_empty());
        assert_eq!(removed.bytes(), rebuilt.bytes());
    }

    #[test]
    fn authority_profiles_refuse_implicit_downgrades() {
        let namespace = Digest::of(b"no implicit music authority downgrade");
        let actor = ActorId::from_bytes([0x61; 32]);
        let open = initialize_open(namespace, MemoryStorage::new()).unwrap();
        let capability_payload = delegation_payload(
            namespace,
            EntryHash(Digest::of(b"absent parent")),
            actor,
            actor,
        );
        assert!(open.author_open(capability_payload).is_err());

        let key = SigningKey::from_bytes(&[0x62; 32]);
        let owner = ActorId::from_signing_key(&key);
        let (capability, _) = initialize(namespace, owner, MemoryStorage::new()).unwrap();
        let payload = encode_command(
            namespace,
            owner,
            &[],
            MusicOp::AddDegree {
                degree: TunedDegree::new(&Tuning::twelve_tet(), 1).unwrap(),
            },
        )
        .unwrap();
        assert!(capability.author_open(payload).is_err());
    }

    #[test]
    fn federated_materializer_accepts_explicitly_trusted_peer_roots() {
        let first_key = SigningKey::from_bytes(&[31; 32]);
        let second_key = SigningKey::from_bytes(&[32; 32]);
        let first = ActorId::from_signing_key(&first_key);
        let second = ActorId::from_signing_key(&second_key);
        let namespace = Digest::of(b"federated embedded music room");
        let (replica, first_root) = initialize(namespace, first, MemoryStorage::new()).unwrap();
        let second_root_entry = hhhs_cap::entry(
            &CapabilityOp::Grant(Grant {
                issuer: second.receiver(),
                receiver: second.receiver(),
                area: Area::root(namespace),
                rights: Rights::ALL,
                parent: None,
            }),
            Position::empty(),
        );
        let second_root = second_root_entry.hash();
        replica.trust_root(second_root).unwrap();
        replica
            .admit(AdmissionRequest::trusted_root(second_root_entry))
            .unwrap();

        let first_degree = TunedDegree::new(&Tuning::twelve_tet(), 2).unwrap();
        let second_degree = TunedDegree::new(&Tuning::twelve_tet(), 9).unwrap();
        author(
            &replica,
            namespace,
            &first_key,
            vec![first_root],
            MusicOp::AddDegree {
                degree: first_degree,
            },
        )
        .unwrap();
        author(
            &replica,
            namespace,
            &second_key,
            vec![second_root],
            MusicOp::AddDegree {
                degree: second_degree,
            },
        )
        .unwrap();

        let projection = MusicMaterializer::from_roots([second_root, first_root, second_root]);
        assert_eq!(
            projection.roots(),
            &[first_root.min(second_root), first_root.max(second_root)]
        );
        let checkpoint =
            hhhs_store::materialize(&projection, &replica.snapshot().history, None).unwrap();
        assert_eq!(
            MusicView::try_from(&checkpoint).unwrap().live,
            BTreeSet::from([first_degree, second_degree])
        );
    }

    #[test]
    fn projection_checkpoint_incrementally_tracks_note_on_and_off() {
        let owner_key = SigningKey::from_bytes(&[41; 32]);
        let owner = ActorId::from_signing_key(&owner_key);
        let namespace = Digest::of(b"incremental tutti materializer");
        let (replica, root) = initialize(namespace, owner, MemoryStorage::new()).unwrap();
        let projection = MusicMaterializer::new(root);
        let initial_history = replica.snapshot().history;
        let initial = hhhs_store::materialize(&projection, &initial_history, None).unwrap();

        let tuning = tutti_music::Tuning::twelve_tet();
        let degree = TunedDegree::new(&tuning, 7).unwrap();
        author(
            &replica,
            namespace,
            &owner_key,
            vec![root],
            MusicOp::AddDegree { degree },
        )
        .unwrap();
        let added_history = replica.snapshot().history;
        let added = hhhs_store::materialize(&projection, &added_history, Some(&initial)).unwrap();
        assert_eq!(
            MusicView::try_from(&added).unwrap().live,
            BTreeSet::from([degree])
        );

        author(
            &replica,
            namespace,
            &owner_key,
            vec![root],
            MusicOp::RemoveDegree { degree },
        )
        .unwrap();
        let removed_history = replica.snapshot().history;
        let incremental =
            hhhs_store::materialize(&projection, &removed_history, Some(&added)).unwrap();
        let rebuilt = hhhs_store::materialize(&projection, &removed_history, None).unwrap();
        assert!(MusicView::try_from(&incremental).unwrap().live.is_empty());
        assert_eq!(incremental.bytes(), rebuilt.bytes());
    }

    #[test]
    fn typed_delegation_authorizes_the_receiver_without_an_acl() {
        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let member_key = SigningKey::from_bytes(&[2; 32]);
        let owner = ActorId::from_signing_key(&owner_key);
        let member = ActorId::from_signing_key(&member_key);
        let namespace = Digest::of(b"delegated tutti music object");
        let (replica, root) = initialize(namespace, owner, MemoryStorage::new()).unwrap();
        let grant = delegate(&replica, namespace, root, &owner_key, member)
            .unwrap()
            .entry;
        let degree = TunedDegree::new(&Tuning::twelve_tet(), 7).unwrap();

        author(
            &replica,
            namespace,
            &member_key,
            vec![grant],
            MusicOp::AddDegree { degree },
        )
        .unwrap();

        let view = materialize(&replica.snapshot().history, &[root]);
        assert_eq!(view.live, [degree].into());
        assert_eq!(view.holders[&degree], [member].into());
    }

    #[test]
    fn sparse_fold_matches_reference_for_linear_history() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let owner = ActorId::from_signing_key(&key);
        let namespace = Digest::of(b"linear music fold equivalence");
        let (replica, root) = initialize(namespace, owner, MemoryStorage::new()).unwrap();
        let tuning = Tuning::twelve_tet();

        for index in 0..48 {
            let degree = TunedDegree::new(&tuning, (index / 2) % 12).unwrap();
            let command = if index % 2 == 0 {
                MusicOp::AddDegree { degree }
            } else {
                MusicOp::RemoveDegree { degree }
            };
            author(&replica, namespace, &key, vec![root], command).unwrap();
        }

        let history = replica.snapshot().history;
        let commands = commands(&history, &[root]);
        assert_eq!(
            materialize_commands(&history, &commands),
            materialize_reference(&history, &commands)
        );
    }

    #[test]
    fn sparse_fold_matches_reference_across_concurrent_add_remove_and_registers() {
        let root = Entry::new(vec![0], Position::empty());
        let left_add = Entry::new(vec![1], Position::of([root.hash()]));
        let left_remove = Entry::new(vec![2], Position::of([left_add.hash()]));
        let right_add = Entry::new(vec![3], Position::of([root.hash()]));
        let left_envelope = Entry::new(vec![4], Position::of([left_add.hash()]));
        let right_envelope = Entry::new(vec![5], Position::of([right_add.hash()]));
        let entries = [
            root,
            left_add.clone(),
            left_remove.clone(),
            right_add.clone(),
            left_envelope.clone(),
            right_envelope.clone(),
        ];
        let history = DagSnapshot::from_entries(entries);
        let degree = TunedDegree::new(&Tuning::twelve_tet(), 7).unwrap();
        let left_actor = ActorId([4; 32]);
        let right_actor = ActorId([5; 32]);
        let mut by_entry = BTreeMap::new();
        by_entry.insert(left_add.hash(), (left_actor, MusicOp::AddDegree { degree }));
        by_entry.insert(
            left_remove.hash(),
            (left_actor, MusicOp::RemoveDegree { degree }),
        );
        by_entry.insert(
            right_add.hash(),
            (right_actor, MusicOp::AddDegree { degree }),
        );
        by_entry.insert(
            left_envelope.hash(),
            (
                left_actor,
                MusicOp::SetEnvelope {
                    degree,
                    env: Envelope {
                        points: vec![(10, 40)],
                        ..Envelope::default()
                    },
                },
            ),
        );
        by_entry.insert(
            right_envelope.hash(),
            (
                right_actor,
                MusicOp::SetEnvelope {
                    degree,
                    env: Envelope {
                        points: vec![(20, 80)],
                        ..Envelope::default()
                    },
                },
            ),
        );
        let commands = topo_commands(&history, by_entry);

        let sparse = materialize_commands(&history, &commands);
        assert_eq!(sparse, materialize_reference(&history, &commands));
        assert_eq!(sparse.live, [degree].into());
        assert_eq!(sparse.holders[&degree], [right_actor].into());
    }
}
