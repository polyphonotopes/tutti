//! **tutti-music** — the music protocol of the tutti stack: what MIDI standardized
//! for event streams, this crate standardizes for *convergent state*.
//!
//! The shared object is never a note stream. It is the **pitch-set, its tuning,
//! and its facets** as CRDT ops with pinned wire bytes and pinned fold verdicts:
//!
//! * [`tuning`] — validated periodic tuning (Scala `.scl`/`.kbm`), content-hashed
//!   [`TuningId`]s, and the tuning-scoped degree identity ([`TunedDegree`]) that is
//!   this protocol's floor — the thing raw MIDI famously lacks.
//! * [`facets`] — per-degree configuration carried as op payload: the amplitude
//!   [`Envelope`] (sparse breakpoints + an interpolation rule — a function, never
//!   samples).
//! * [`ops`] / [`lang`] — the [`MusicOp`] alphabet and [`MusicLang`], the canonical
//!   `OpLanguage` instantiation new peers speak: add-wins degrees, causal-maxima
//!   registers, one deterministic fold to [`MusicView`], and the first real
//!   `retain` for compacting leaf stores.
//! * [`fold`] — the fold combinators as plain functions over `FoldCtx`, shared by
//!   `MusicLang::fold` and any dialect that keeps its own wire (walkie's
//!   `WalkieLang` folds its degree/register stages through exactly these).
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
//! Dependency posture: `tutti-core` + serde + thiserror + blake3. No I/O, no UI,
//! no renderer — wasm- and xtensa-clean by construction.

pub mod facets;
pub mod fold;
pub mod lang;
pub mod ops;
pub mod render;
pub mod tuning;

pub use facets::{Envelope, Interp};
pub use lang::{MusicLang, MusicView};
pub use ops::MusicOp;
pub use tuning::{TunedDegree, TunedPeriodicPitch, Tuning, TuningDefinition, TuningId};

/// The author identity [`MusicView::holders`] attributes, re-exported so a
/// view consumer names it through this crate and never takes a `tutti-core`
/// dependency purely to spell it.
pub use tutti_core::AuthorId;
