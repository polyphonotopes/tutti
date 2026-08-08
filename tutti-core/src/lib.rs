//! **tutti-core** — the domain-agnostic reconciling signed-op substrate.
//!
//! This crate is the band that sits ATOP `hhhs` and below any music (or
//! other) app: the signed, per-author, topic-bound op envelope with
//! verification-at-ingress; the deterministic lift of verbatim signed bytes into
//! the kernel causal DAG (strict deferral + drain, dual `OpId ↔ EntryHash` maps,
//! per-author heads); and the pure causal fold seam ([`OpLanguage`] + [`FoldCtx`])
//! a downstream domain instantiates once. It owns exactly what `hhhs`
//! deliberately does not: signatures, authorship, topic binding, wire framing.
//!
//! It carries **no domain alphabet, no domain fold rule, and no UI**. Walkie-songie
//! is the first instantiation: it supplies `WalkieOp`, its `walkie_fold`, and
//! `RoomView`, and names the store as `Store<WalkieLang>`. The extraction is
//! **byte-compatible by construction** — the framing magics, size ladder, CBOR
//! envelope and fold semantics are unchanged, so the golden entry-hash vector and
//! the L0 convergence suite hold unmodified against `Store<WalkieLang>`.
//!
//! This is **tutti extraction Track-D step 3**: the mechanical relocation of the
//! now-generic substrate out of walkie's `src/room/` into this crate. Steps 1+2
//! genericized the envelope and store in place over an `OpLanguage`; this step
//! moved them. Deliberately still parked here: the domain `state_root` (needs
//! `L::View: Canonical`), presence-lease and journal extraction, and the
//! `tutti-testkit` split — all left walkie-side to keep a clean compile.
//!
//! Dependency posture (leaf-safe): production tutti names only the causal floor —
//! `p2panda-core` + `hhhs-dag` + `blake3` + `serde` (+ optional `radix_immutable`
//! under `merkle`). The facts front door `hhhs` is a dev / `test-support`-only
//! dependency (the reference-oracle surface). All wasm-safe, no tokio, no iroh, no
//! web-sys.

pub mod ops;
pub mod retain;
pub mod store;
pub mod windowed;

#[cfg(feature = "merkle")]
pub mod merkle;

pub use ops::{
    AuthorId, LogHead, MAX_OBSERVED_OPS, MAX_SIGNED_HEADER_BYTES, MAX_SIGNED_OP_WIRE_BYTES,
    MAX_SIGNED_PAYLOAD_BYTES, MAX_TOPIC_BYTES, OpId, OpLanguage, OpVerifyError, SIGNED_OP_WIRE_MAGIC,
    SignedOp, SignedOpWireError, SigningKey, VerifiedOpG, VerifyingKey, VersionedOpG,
    sign_versioned_op, signing_key_from_seed, verify_signed_op_in,
};
pub use retain::causal_maxima;
pub use store::{DecodedOp, FoldCtx, Store, sync_root_of};
pub use windowed::{Compaction, WindowedStore};

/// The ancestry seam and the bounded-window floor pieces, re-exported from `hhhs-dag`
/// so every `tutti_core::…` spelling keeps compiling after they sank to the floor:
/// the [`Reach`] contract + the lazy [`LazyReach`] oracle, and the L-free
/// [`WindowedDag`]/[`WindowedReach`] the leaf-profile [`WindowedStore`] drives.
pub use hhhs_dag::reach::{LazyReach, Reach};
pub use hhhs_dag::windowed::{WindowedDag, WindowedReach};

/// The kernel's opaque-payload entry identity, re-exported so a downstream domain
/// names it through `tutti_core` and never takes a direct, rev-pinned `hhhs-dag`
/// dependency purely to spell it. It is the key type of [`FoldCtx::decoded`] and
/// the argument to [`FoldCtx::is_ancestor`]/[`FoldCtx::resolve`], so a domain
/// `fold` cannot collect its `BTreeSet<EntryHash>` candidates without naming it.
pub use hhhs_dag::EntryHash;
