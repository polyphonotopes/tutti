//! The signed operation envelope — a durable, gossiped, per-author append-only
//! op log built on `p2panda-core`, domain-agnostic over an [`OpLanguage`].
//!
//! Every domain contribution becomes an `L::Op` wrapped in a [`VersionedOpG`]
//! envelope, CBOR-encoded as a p2panda `Body`, and signed by the author's Ed25519
//! key via `Header::sign`. Verification runs `validate_operation` plus the
//! domain's `L::validate_wire`, so who contributed which op is cryptographically
//! established before it can reach a store write ([`VerifiedOpG`]'s fields are
//! private; the only constructor is [`verify_signed_op_in`]).
//!
//! These signed ops are the source of truth; the HHHS causal-DAG mirror
//! ([`crate::store`]) lifts them into a read model.
//!
//! **Evolution discipline (stated generically, was walkie's):** append variants
//! to `L::Op`, never reorder them, add fields only as `#[serde(default)]`, and
//! bump [`OpLanguage::SCHEMA_VERSION`] when the payload shape changes.
//!
//! **wasm timestamps:** `ts_micros` must be author-supplied. On wasm pass
//! `js_sys::Date::now() as u64 * 1000`; never call p2panda's `Timestamp::now()`
//! (it uses `SystemTime::now()`, which panics on `wasm32`).

use std::collections::BTreeSet;

use p2panda_core::cbor::{DecodeError, decode_cbor, encode_cbor};
use p2panda_core::{Body, Hash, Header, Operation, OperationError, validate_operation};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use hhhs_dag::EntryHash;

use crate::store::FoldCtx;

/// Re-exported so downstream crates name the key types through `tutti_core` and
/// never take a direct `p2panda-core` dependency. `SigningKey::from_bytes` is
/// infallible — any 32 bytes are a valid Ed25519 seed.
pub use p2panda_core::{SigningKey, VerifyingKey};

/// Largest legal signed payload — the ROOT of the size ladder, not a free
/// parameter. Everything that has to carry one op (gossip message cap, journal
/// record cap, and above all the anti-entropy frame cap) is derived from
/// [`MAX_SIGNED_OP_WIRE_BYTES`] below and asserted at compile time by the
/// carrying layers.
///
/// An op whose wire size exceeds a transport cap can verify, gossip, and lift but
/// then never be re-served by anti-entropy — permanently poisoning sync for a
/// whole room. This value is the shared ceiling that keeps that impossible.
pub const MAX_SIGNED_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Cap on an op's declared causal horizon (`observed` op ids).
pub const MAX_OBSERVED_OPS: usize = 4096;
/// Cap on a bound room-topic string.
pub const MAX_TOPIC_BYTES: usize = 256;
/// The generation marker on the length-delimited signed-op wire frame emitted by
/// the crate-const framing methods [`SignedOp::to_wire_bytes`] /
/// [`SignedOp::from_wire_bytes`].
///
/// `SignedOp` is NOT generic over `L` (it is opaque header+payload bytes carried
/// by every transport, the journal, and RBSR), so the crate-const framing keeps
/// this fixed marker. The domain-separating framing
/// ([`SignedOp::to_wire_bytes_in`] / [`SignedOp::from_wire_bytes_in`]) instead
/// threads [`OpLanguage::WIRE_MAGIC`], so two tutti domains refuse each other at
/// the frame. This const is walkie's literal value, and
/// `WalkieLang::WIRE_MAGIC == SIGNED_OP_WIRE_MAGIC`, so both framing paths produce
/// byte-identical frames for walkie.
pub const SIGNED_OP_WIRE_MAGIC: &[u8] = b"walkie.signed-op/3\0";
pub const MAX_SIGNED_HEADER_BYTES: usize = 64 * 1024;

/// Largest possible [`SignedOp::to_wire_bytes`] output for a legal op — the unit
/// every carrying layer must be able to move whole. Anti-entropy has no way to
/// split one op across frames, so a transport cap below this is a permanent
/// convergence failure, not a slow path.
pub const MAX_SIGNED_OP_WIRE_BYTES: usize =
    SIGNED_OP_WIRE_MAGIC.len() + 8 + MAX_SIGNED_HEADER_BYTES + MAX_SIGNED_PAYLOAD_BYTES;

/// The domain seam: a downstream app implements this once, describing its op
/// alphabet, its schema/framing identity, and its deterministic fold.
///
/// Generics over payload beat trait objects for a fold that returns a domain view
/// type, and the contract's real force is in tests (golden vectors, permutation
/// convergence, oracle parity), not vtables — so this is the runtime seam, and
/// the four-property substrate contract ships as a conformance test suite.
///
/// Every associated const is byte-defining: for walkie they are wired to the
/// pre-extraction literals, so serialized signed bytes and lifted entry hashes
/// are byte-for-byte unchanged. The golden entry-hash vector is the hard gate.
pub trait OpLanguage: Sized + 'static {
    /// The domain alphabet. CBOR via serde; evolution discipline: append
    /// variants, never reorder, add fields only as `#[serde(default)]`, and bump
    /// [`OpLanguage::SCHEMA_VERSION`] on a payload-shape change.
    type Op: Serialize + DeserializeOwned + Clone + PartialEq;

    /// The op-payload schema version stamped into every envelope.
    const SCHEMA_VERSION: u16;
    /// Framing tag prefixed to the verbatim signed bytes when they become a
    /// kernel entry payload. Consumed by [`crate::store::Store`]'s lift framing,
    /// so it fully determines the lifted entry hash — the golden entry-hash
    /// vector pins that it is byte-for-byte the domain's literal. Bumping it
    /// changes every entry hash, so it is a schema pin.
    const ENTRY_FRAME_MAGIC: &'static [u8];
    /// Generation marker on the length-delimited signed-op wire frame. Threaded
    /// by the domain-separating framing [`SignedOp::to_wire_bytes_in`] /
    /// [`SignedOp::from_wire_bytes_in`], which write it on frame and REJECT a frame
    /// whose leading magic differs ([`SignedOpWireError::WrongDomain`]) — so two
    /// tutti domains cannot ingest each other's frames. See [`SIGNED_OP_WIRE_MAGIC`]
    /// (walkie's literal, and `WalkieLang::WIRE_MAGIC` equals it, so walkie's frame
    /// is byte-identical).
    const WIRE_MAGIC: &'static [u8];
    /// Root of the size ladder — the largest legal signed payload.
    const MAX_PAYLOAD_BYTES: usize;

    /// Domain wire validation — bounds and well-formedness, run once at ingress
    /// inside [`verify_signed_op_in`].
    fn validate_wire(op: &Self::Op) -> Result<(), String>;

    /// The materialized read model this language folds to. The `Canonical` bound
    /// — the byte encoding a domain `state_root` commits to — is a later step and
    /// deliberately omitted here.
    type View: Default + Clone + PartialEq;

    /// THE deterministic fold: a pure function of the decoded op-set and its
    /// causal indexes ([`FoldCtx`]). Two peers with equal verified op-sets MUST
    /// return equal views (contract property (b)).
    fn fold(ctx: &FoldCtx<'_, Self>) -> Self::View;

    /// **M3.1 compaction retention** — the domain names, at a causally-closed cut,
    /// exactly which of the cut's ops it must keep as residue; the rest are
    /// monotone-shadowed and may be discarded
    /// (`docs/vision/windowed-store-design.md` §6.2 delta 2, §2.4-2.5).
    ///
    /// `cut` is the set of currently-retained entry hashes at a compaction point
    /// (causally closed by strict deferral). `ctx` folds over exactly that set with
    /// the boundary-aware ancestry oracle, so `retain` decides using the same
    /// `is_ancestor`/`resolve`/`decoded` surface the fold uses. The return value is
    /// the residue `R ⊆ cut`: every op NOT returned is discarded.
    ///
    /// **The soundness law (§2.4).** An op may be dropped iff its contribution to
    /// *every admissible future fold* is already shadowed by retained ops — a
    /// monotone consequence of causal facts fixed at lift (a kill by an
    /// unconditional remove, a supersession by a retained later write), NEVER a
    /// consequence of the continued *absence* of a future op. Retention must be
    /// **conservative**: when in doubt, keep it (wrong-but-retained is
    /// correct-and-bigger; wrong-and-discarded is a convergence bug). A domain that
    /// discards an op whose liveness could still flip breaks the windowed-fold
    /// equivalence theorem (§2.6) — which the `windowed_equiv` gate falsifies.
    ///
    /// **Default = retain everything** (`cut.clone()`): compaction off, the theorem
    /// trivially true, and every non-opting language ([`crate::Store`]'s domains) is
    /// completely unaffected. Only a language that overrides this ever discards an
    /// op, and only [`crate::WindowedStore`] ever calls it. Default-method-only
    /// evolution, exactly the frozen-trait freeze contract.
    fn retain(ctx: &FoldCtx<'_, Self>, cut: &BTreeSet<EntryHash>) -> BTreeSet<EntryHash> {
        let _ = ctx;
        cut.clone()
    }
}

/// A 32-byte author identity — the Ed25519 verifying-key bytes. Doubles as the
/// peer's stable id across an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthorId(pub [u8; 32]);

impl AuthorId {
    pub fn to_hex(&self) -> String {
        hex32(&self.0)
    }
}

/// A p2panda operation id — `blake3(header bytes)` of a signed op. Used as the
/// stable, cross-peer identity for domain objects and as the causal-horizon
/// references an op carries in [`VersionedOpG::observed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OpId(pub [u8; 32]);

impl OpId {
    pub fn to_hex(&self) -> String {
        hex32(&self.0)
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(&mut s, "{b:02x}");
        s
    })
}

/// The signed-op envelope: the exact struct CBOR-encoded into the p2panda `Body`.
///
/// Generic over the [`OpLanguage`] `L`. The CBOR layout — field order, the
/// `default`/`skip` attrs, and the schema version stamped by
/// [`VersionedOpG::current`] — is identical to the pre-extraction struct, so
/// every signed byte is unchanged.
///
/// `Serialize`/`Deserialize` are derived with an explicit `#[serde(bound)]` so
/// they constrain `L::Op` (guaranteed by [`OpLanguage`]) rather than the marker
/// `L`; `Clone`/`PartialEq`/`Eq`/`Debug` are hand-written for the same reason.
#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "L::Op: Serialize",
    deserialize = "L::Op: DeserializeOwned"
))]
pub struct VersionedOpG<L: OpLanguage> {
    pub version: u16,
    /// Author-stamped time in microseconds since the epoch (display/tiebreak-of-
    /// last-resort only; ordering is causal, never wall-clock).
    pub ts_micros: u64,
    /// The room topic this op is bound to, preventing replay into another room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// The op ids this author had already accepted when signing — its causal
    /// horizon beyond its own log. The HHHS mirror lifts these into an entry's
    /// predecessors, which is what makes cross-author causality (add-wins
    /// supersession, register recency) expressible at all. Stamped from the store
    /// frontier on every commit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed: Vec<[u8; 32]>,
    pub op: L::Op,
}

impl<L: OpLanguage> Clone for VersionedOpG<L> {
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            ts_micros: self.ts_micros,
            topic: self.topic.clone(),
            observed: self.observed.clone(),
            op: self.op.clone(),
        }
    }
}

impl<L: OpLanguage> PartialEq for VersionedOpG<L> {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.ts_micros == other.ts_micros
            && self.topic == other.topic
            && self.observed == other.observed
            && self.op == other.op
    }
}

impl<L: OpLanguage> Eq for VersionedOpG<L> where L::Op: Eq {}

impl<L: OpLanguage> std::fmt::Debug for VersionedOpG<L>
where
    L::Op: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionedOp")
            .field("version", &self.version)
            .field("ts_micros", &self.ts_micros)
            .field("topic", &self.topic)
            .field("observed", &self.observed)
            .field("op", &self.op)
            .finish()
    }
}

impl<L: OpLanguage> VersionedOpG<L> {
    pub fn current(op: L::Op, ts_micros: u64) -> Self {
        Self {
            version: L::SCHEMA_VERSION,
            ts_micros,
            topic: None,
            observed: Vec::new(),
            op,
        }
    }

    pub fn current_for_topic(op: L::Op, ts_micros: u64, topic: &str) -> Self {
        Self {
            version: L::SCHEMA_VERSION,
            ts_micros,
            topic: Some(topic.to_string()),
            observed: Vec::new(),
            op,
        }
    }

    /// Attach the causal horizon (op ids this author has observed).
    pub fn observing(mut self, observed: impl IntoIterator<Item = [u8; 32]>) -> Self {
        self.observed = observed.into_iter().collect();
        self
    }

    /// Whether this build can apply the op as-is (peer isn't ahead on schema).
    pub fn is_supported(&self) -> bool {
        self.version == L::SCHEMA_VERSION
    }
}

/// The head of an author's op log: the seq_num the *next* op must carry and the
/// hash of the current head op (its backlink).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogHead {
    pub next_seq: u64,
    pub backlink: Option<[u8; 32]>,
}

impl LogHead {
    pub fn genesis() -> Self {
        Self {
            next_seq: 0,
            backlink: None,
        }
    }
}

impl Default for LogHead {
    fn default() -> Self {
        Self::genesis()
    }
}

/// A signed op on the wire: the exact bytes the author signed. Opaque
/// header+payload — not generic over `L` — so every transport, the journal, and
/// RBSR move it uniformly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOp {
    /// CBOR of the signed `Header<()>`.
    pub header: Vec<u8>,
    /// CBOR of the [`VersionedOpG`] (the p2panda `Body` bytes).
    pub payload: Vec<u8>,
}

impl SignedOp {
    /// Stable length-delimited gossip/persistence frame containing the verbatim
    /// header and payload bytes, framed with the crate-const marker
    /// [`SIGNED_OP_WIRE_MAGIC`] and validated against the crate-const payload
    /// ceiling [`MAX_SIGNED_PAYLOAD_BYTES`]. Verification still happens after
    /// decoding. This is the fixed-marker frame every walkie transport, the
    /// journal, and RBSR move; since `WalkieLang::WIRE_MAGIC == SIGNED_OP_WIRE_MAGIC`
    /// and `WalkieLang::MAX_PAYLOAD_BYTES == MAX_SIGNED_PAYLOAD_BYTES`, it is
    /// byte-identical to `to_wire_bytes_in::<WalkieLang>`.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, SignedOpWireError> {
        self.frame_with(SIGNED_OP_WIRE_MAGIC, MAX_SIGNED_PAYLOAD_BYTES)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, SignedOpWireError> {
        Self::deframe_with(bytes, SIGNED_OP_WIRE_MAGIC, MAX_SIGNED_PAYLOAD_BYTES)
    }

    /// The domain-separating frame: writes [`OpLanguage::WIRE_MAGIC`] and validates
    /// the payload against [`OpLanguage::MAX_PAYLOAD_BYTES`] (fixes #2 + #3 — the
    /// magic and the size ladder are the domain's, matching what
    /// [`verify_signed_op_in`] checks). A frame written by domain `L` is refused by
    /// any domain `L'` whose `WIRE_MAGIC` differs.
    pub fn to_wire_bytes_in<L: OpLanguage>(&self) -> Result<Vec<u8>, SignedOpWireError> {
        self.frame_with(L::WIRE_MAGIC, L::MAX_PAYLOAD_BYTES)
    }

    /// Inverse of [`SignedOp::to_wire_bytes_in`]: deframes with
    /// [`OpLanguage::WIRE_MAGIC`] and REJECTS a frame whose leading magic differs
    /// with [`SignedOpWireError::WrongDomain`] — cross-domain frame separation. The
    /// payload length is bounded by [`OpLanguage::MAX_PAYLOAD_BYTES`].
    pub fn from_wire_bytes_in<L: OpLanguage>(bytes: &[u8]) -> Result<Self, SignedOpWireError> {
        Self::deframe_with(bytes, L::WIRE_MAGIC, L::MAX_PAYLOAD_BYTES).map_err(|error| {
            // A magic mismatch means the frame is well-formed but belongs to another
            // domain — surface that distinctly from the crate-const path's
            // `InvalidMagic`.
            match error {
                SignedOpWireError::InvalidMagic => SignedOpWireError::WrongDomain,
                other => other,
            }
        })
    }

    /// Frame `header ++ payload` behind `magic`, validating both against their
    /// caps. The frame layout (`magic ++ len(header):u32le ++ len(payload):u32le ++
    /// header ++ payload`) is fixed; only the marker and the payload ceiling vary.
    fn frame_with(&self, magic: &[u8], max_payload: usize) -> Result<Vec<u8>, SignedOpWireError> {
        validate_wire_lengths(self.header.len(), self.payload.len(), max_payload)?;
        let mut output =
            Vec::with_capacity(magic.len() + 8 + self.header.len() + self.payload.len());
        output.extend_from_slice(magic);
        output.extend_from_slice(&(self.header.len() as u32).to_le_bytes());
        output.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        output.extend_from_slice(&self.header);
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    /// Deframe a `magic`-tagged frame, validating the payload against `max_payload`.
    /// Returns [`SignedOpWireError::InvalidMagic`] if the leading bytes are not
    /// `magic`; callers that carry a domain remap that to
    /// [`SignedOpWireError::WrongDomain`].
    fn deframe_with(
        bytes: &[u8],
        magic: &[u8],
        max_payload: usize,
    ) -> Result<Self, SignedOpWireError> {
        let prefix = magic.len();
        if bytes.len() < prefix + 8 || &bytes[..prefix] != magic {
            return Err(SignedOpWireError::InvalidMagic);
        }
        let header_len =
            u32::from_le_bytes(bytes[prefix..prefix + 4].try_into().expect("fixed slice")) as usize;
        let payload_len = u32::from_le_bytes(
            bytes[prefix + 4..prefix + 8]
                .try_into()
                .expect("fixed slice"),
        ) as usize;
        validate_wire_lengths(header_len, payload_len, max_payload)?;
        let expected = prefix
            .checked_add(8)
            .and_then(|length| length.checked_add(header_len))
            .and_then(|length| length.checked_add(payload_len))
            .ok_or(SignedOpWireError::LengthMismatch)?;
        if bytes.len() != expected {
            return Err(SignedOpWireError::LengthMismatch);
        }
        let header_start = prefix + 8;
        let payload_start = header_start + header_len;
        Ok(Self {
            header: bytes[header_start..payload_start].to_vec(),
            payload: bytes[payload_start..].to_vec(),
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SignedOpWireError {
    #[error("signed operation frame has an invalid generation marker")]
    InvalidMagic,
    /// The frame is well-formed but its leading magic is not the deframing domain's
    /// [`OpLanguage::WIRE_MAGIC`] — a frame from another tutti domain. Only the
    /// domain-threaded [`SignedOp::from_wire_bytes_in`] returns this.
    #[error("signed operation frame belongs to a different domain")]
    WrongDomain,
    #[error("signed operation frame lengths do not match its bytes")]
    LengthMismatch,
    #[error("signed header is {actual} bytes; maximum is {max}")]
    HeaderTooLarge { actual: usize, max: usize },
    #[error("signed payload is {actual} bytes; maximum is {max}")]
    PayloadTooLarge { actual: usize, max: usize },
}

/// Bound a frame's header (crate-const [`MAX_SIGNED_HEADER_BYTES`]) and payload
/// (`max_payload` — the crate const for the fixed-marker frame, or
/// [`OpLanguage::MAX_PAYLOAD_BYTES`] for the domain-threaded frame, so framing and
/// [`verify_signed_op_in`] agree on the same size ladder).
fn validate_wire_lengths(
    header_len: usize,
    payload_len: usize,
    max_payload: usize,
) -> Result<(), SignedOpWireError> {
    if header_len > MAX_SIGNED_HEADER_BYTES {
        return Err(SignedOpWireError::HeaderTooLarge {
            actual: header_len,
            max: MAX_SIGNED_HEADER_BYTES,
        });
    }
    if payload_len > max_payload {
        return Err(SignedOpWireError::PayloadTooLarge {
            actual: payload_len,
            max: max_payload,
        });
    }
    Ok(())
}

/// A successfully verified op. Fields are **private**: the only constructor is
/// [`verify_signed_op_in`], so a store write that takes a `VerifiedOpG` cannot be
/// handed unverified data — the capability invariant survives genericization
/// intact.
///
/// Generic over the [`OpLanguage`] `L`. `Clone`/`Debug` are hand-written so they
/// constrain `L::Op` rather than the marker `L`.
pub struct VerifiedOpG<L: OpLanguage> {
    author: AuthorId,
    payload: L::Op,
    topic: Option<String>,
    observed: Vec<[u8; 32]>,
    timestamp_ms: u64,
    seq_num: u64,
    backlink: Option<[u8; 32]>,
    hash: [u8; 32],
    header_bytes: Vec<u8>,
    payload_bytes: Vec<u8>,
}

impl<L: OpLanguage> Clone for VerifiedOpG<L> {
    fn clone(&self) -> Self {
        Self {
            author: self.author,
            payload: self.payload.clone(),
            topic: self.topic.clone(),
            observed: self.observed.clone(),
            timestamp_ms: self.timestamp_ms,
            seq_num: self.seq_num,
            backlink: self.backlink,
            hash: self.hash,
            header_bytes: self.header_bytes.clone(),
            payload_bytes: self.payload_bytes.clone(),
        }
    }
}

impl<L: OpLanguage> std::fmt::Debug for VerifiedOpG<L>
where
    L::Op: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedOp")
            .field("author", &self.author)
            .field("payload", &self.payload)
            .field("topic", &self.topic)
            .field("observed", &self.observed)
            .field("timestamp_ms", &self.timestamp_ms)
            .field("seq_num", &self.seq_num)
            .field("backlink", &self.backlink)
            .field("hash", &self.hash)
            .field("header_bytes", &self.header_bytes)
            .field("payload_bytes", &self.payload_bytes)
            .finish()
    }
}

impl<L: OpLanguage> VerifiedOpG<L> {
    pub fn author(&self) -> AuthorId {
        self.author
    }
    pub fn payload(&self) -> &L::Op {
        &self.payload
    }
    pub fn topic(&self) -> Option<&str> {
        self.topic.as_deref()
    }
    /// The op ids this author had observed when signing (its causal horizon).
    pub fn observed(&self) -> &[[u8; 32]] {
        &self.observed
    }
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }
    pub fn seq_num(&self) -> u64 {
        self.seq_num
    }
    pub fn backlink(&self) -> Option<[u8; 32]> {
        self.backlink
    }
    /// The operation id (`blake3(header bytes)`).
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
    /// This op's id as an [`OpId`] (stable, cross-peer).
    pub fn id(&self) -> OpId {
        OpId(self.hash)
    }
    /// The verbatim signed bytes, for durable persistence / rebroadcast / HHHS lift.
    pub fn signed(&self) -> SignedOp {
        SignedOp {
            header: self.header_bytes.clone(),
            payload: self.payload_bytes.clone(),
        }
    }
    /// The log head *after* this op — what the author's next op signs against.
    pub fn advanced_head(&self) -> LogHead {
        LogHead {
            next_seq: self.seq_num + 1,
            backlink: Some(self.hash),
        }
    }
}

/// Build a signing key from a 32-byte seed.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// The general signing primitive.
///
/// Generic over the [`OpLanguage`] `L` — it only CBOR-encodes the envelope, so
/// the signed bytes are a pure function of `L::Op`'s serialization.
pub fn sign_versioned_op<L: OpLanguage>(
    signing_key: &SigningKey,
    head: &LogHead,
    versioned: VersionedOpG<L>,
) -> (SignedOp, LogHead) {
    let payload = encode_cbor(&versioned).expect("VersionedOp is always CBOR-encodable");
    let body = Body::new(&payload);

    let mut header: Header<()> = Header {
        version: 1,
        verifying_key: signing_key.verifying_key(),
        signature: None,
        payload_size: body.size(),
        payload_hash: Some(body.hash()),
        // p2panda-core 0.7's `seq_num` is a `u32`; our `LogHead` keeps `u64`.
        // Guard the narrowing rather than silently truncating a pathological log.
        seq_num: u32::try_from(head.next_seq).expect("op-log seq_num exceeds u32::MAX"),
        backlink: head.backlink.map(Hash::from_bytes),
        extensions: (),
    };
    header.sign(signing_key);

    let hash = header.hash();
    let signed = SignedOp {
        header: header.to_bytes(),
        payload,
    };
    let advanced = LogHead {
        next_seq: head.next_seq + 1,
        backlink: Some(*hash.as_bytes()),
    };
    (signed, advanced)
}

/// Why a [`SignedOp`] failed verification.
#[derive(Debug)]
pub enum OpVerifyError {
    /// The header bytes did not CBOR-decode to a `Header<()>`.
    HeaderDecode(DecodeError),
    /// p2panda's `validate_operation` rejected it — bad signature, wrong version,
    /// payload hash/size mismatch, or a structural seq/backlink rule.
    Invalid(OperationError),
    /// The header verified, but the payload did not CBOR-decode to a [`VersionedOpG`].
    PayloadDecode(DecodeError),
    /// A well-formed op from a peer on a newer schema than this build can apply.
    UnsupportedVersion(u16),
    /// The signed payload exceeds a configured resource bound.
    PayloadTooLarge { actual: usize, max: usize },
    /// The signature is valid, but the domain payload is invalid or excessive.
    InvalidDomain(String),
    /// A room-scoped read required a topic, but the signed body did not carry one.
    MissingTopic,
    /// The signed body belongs to another room topic.
    TopicMismatch { expected: String, actual: String },
}

impl std::fmt::Display for OpVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpVerifyError::HeaderDecode(e) => write!(f, "header decode failed: {e}"),
            OpVerifyError::Invalid(e) => write!(f, "operation invalid: {e}"),
            OpVerifyError::PayloadDecode(e) => write!(f, "payload decode failed: {e}"),
            OpVerifyError::UnsupportedVersion(v) => write!(f, "unsupported op version: {v}"),
            OpVerifyError::PayloadTooLarge { actual, max } => {
                write!(f, "signed payload is {actual} bytes; maximum is {max}")
            }
            OpVerifyError::InvalidDomain(error) => {
                write!(f, "signed domain payload is invalid: {error}")
            }
            OpVerifyError::MissingTopic => write!(f, "signed operation is missing its room topic"),
            OpVerifyError::TopicMismatch { expected, actual } => {
                write!(
                    f,
                    "signed operation belongs to topic {actual}, expected {expected}"
                )
            }
        }
    }
}

impl std::error::Error for OpVerifyError {}

/// The generic verification core over any [`OpLanguage`] `L`. Pure: checks the
/// signature and internal consistency, but NOT log continuity against a stored
/// head (that is store state — see [`LogHead`]). Run identically at every peer's
/// ingress.
///
/// The payload-size cap is `L::MAX_PAYLOAD_BYTES`, the schema gate is
/// `L::SCHEMA_VERSION`, and domain well-formedness is `L::validate_wire`. The
/// topic/horizon caps are crate constants ([`MAX_TOPIC_BYTES`],
/// [`MAX_OBSERVED_OPS`]) — envelope-level resource bounds, not domain rules.
pub fn verify_signed_op_in<L: OpLanguage>(
    signed: &SignedOp,
) -> Result<VerifiedOpG<L>, OpVerifyError> {
    if signed.payload.len() > L::MAX_PAYLOAD_BYTES {
        return Err(OpVerifyError::PayloadTooLarge {
            actual: signed.payload.len(),
            max: L::MAX_PAYLOAD_BYTES,
        });
    }
    let header: Header<()> =
        decode_cbor(signed.header.as_slice()).map_err(OpVerifyError::HeaderDecode)?;

    let hash = header.hash();
    let body = Body::from(signed.payload.clone());
    let operation = Operation {
        hash,
        header: header.clone(),
        body: Some(body),
    };
    validate_operation(&operation).map_err(OpVerifyError::Invalid)?;

    let versioned: VersionedOpG<L> =
        decode_cbor(signed.payload.as_slice()).map_err(OpVerifyError::PayloadDecode)?;
    if !versioned.is_supported() {
        return Err(OpVerifyError::UnsupportedVersion(versioned.version));
    }
    if versioned
        .topic
        .as_ref()
        .is_some_and(|topic| topic.len() > MAX_TOPIC_BYTES)
    {
        return Err(OpVerifyError::InvalidDomain(format!(
            "room topic exceeds {MAX_TOPIC_BYTES} UTF-8 bytes"
        )));
    }
    if versioned.observed.len() > MAX_OBSERVED_OPS {
        return Err(OpVerifyError::InvalidDomain(format!(
            "causal horizon exceeds {MAX_OBSERVED_OPS} operations"
        )));
    }
    L::validate_wire(&versioned.op).map_err(OpVerifyError::InvalidDomain)?;

    Ok(VerifiedOpG {
        author: AuthorId(*header.verifying_key.as_bytes()),
        timestamp_ms: versioned.ts_micros / 1_000,
        payload: versioned.op,
        topic: versioned.topic,
        observed: versioned.observed,
        seq_num: header.seq_num as u64,
        backlink: header.backlink.map(|h| *h.as_bytes()),
        hash: *hash.as_bytes(),
        header_bytes: signed.header.clone(),
        payload_bytes: signed.payload.clone(),
    })
}
