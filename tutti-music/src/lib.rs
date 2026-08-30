//! **tutti-music** — the music protocol of the tutti stack: what MIDI standardized
//! for event streams, this crate standardizes for *convergent state*.
//!
//! The shared object is never a note stream. It is the **pitch-set, its tuning,
//! and its facets** as bounded protocol commands:
//!
//! * [`tuning`] — validated periodic tuning (Scala `.scl`/`.kbm`), content-hashed
//!   [`TuningId`]s, and the tuning-scoped degree identity ([`TunedDegree`]) that is
//!   this protocol's floor — the thing raw MIDI famously lacks.
//! * [`facets`] — per-degree configuration carried as op payload: the amplitude
//!   [`Envelope`] (sparse breakpoints + an interpolation rule — a function, never
//!   samples).
//! * [`ops`] — the canonical [`MusicOp`] alphabet used by capability-native
//!   Replica adapters such as `tutti-music-hhhs`.
//! * [`render`] — the target-agnostic seam every renderer (AMY, MIDI, OSC, UI)
//!   consumes: the state diff with its offs-before-ons contract, and fractional-
//!   MIDI pitch resolution.
//!
//! **State-first, stated once:** the log stores descriptions — degrees, curves,
//! tunings. Performance (held notes, previews) is presence-lease-shaped and never
//! enters durable history. Events are a *projection* of the convergent view, which
//! is what lets a bridge reconcile a reconnected endpoint instead of replaying a
//! gap.
//!
//! The old source-log fold remains behind the opt-in `legacy-source-log`
//! feature for bounded downstream migration. The default protocol crate has no
//! p2panda or old-HHHS dependency. It owns no I/O, UI, network, or renderer.

pub mod facets;
#[cfg(feature = "legacy-source-log")]
pub mod fold;
#[cfg(feature = "legacy-source-log")]
pub mod lang;
#[cfg(feature = "legacy-source-log")]
pub mod net;
pub mod ops;
pub mod presence;
pub mod render;
pub mod roundtable;
pub mod shared_set;
pub mod tuning;

pub use facets::{Envelope, Interp};
#[cfg(feature = "legacy-source-log")]
pub use lang::{MusicLang, MusicView};
#[cfg(feature = "legacy-source-log")]
pub use net::{LANE_STRATEGY_VERSION, MUSIC_COURIER_ALPN, MUSIC_RBSR_ALPN, MUSIC_STRATEGY_NAME};
pub use ops::MusicOp;
pub use roundtable::{
    RoundTableConfig, RoundTableInputGate, RoundTablePattern, RoundTablePitchMode, RoundTableScale,
};
pub use shared_set::SharedPitchSet;
pub use tuning::{TunedDegree, TunedPeriodicPitch, Tuning, TuningDefinition, TuningId};

/// Legacy source-log author identity.
#[cfg(feature = "legacy-source-log")]
pub use tutti_core::AuthorId;
