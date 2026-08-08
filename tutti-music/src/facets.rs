//! Per-degree **facets** — durable configuration carried as op payload.
//!
//! A facet is a *description*, never samples: the log ships the sparse control
//! points plus the rule for filling between them, and the renderer evaluates
//! that function locally at audio rate. Facet registers are independent of a
//! degree's liveness — removing a degree drops its sounding note, but its facet
//! persists, so a re-add resumes under the converged configuration.

use serde::{Deserialize, Serialize};

/// Max breakpoints in one envelope facet — a wire bound, deliberately small
/// enough that any renderer (including a step-expanding one, ≤ 2N−1 points)
/// stays inside common synth engine limits.
pub const MAX_ENV_POINTS: usize = 8;

/// Max linear-amplitude level a breakpoint may carry (7-bit, MIDI-ish).
pub const MAX_ENV_LEVEL: u8 = 127;

/// How a renderer fills between envelope breakpoints. A control point ships
/// *with* its interpolation rule, so every peer renders the same curve.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum Interp {
    /// Straight line between breakpoints.
    #[default]
    Linear,
    /// True-exponential between breakpoints.
    Exp,
    /// Piecewise-constant (sample-and-hold): hold each level flat, then jump.
    Step,
}

/// A continuous amplitude-envelope facet: a sparse breakpoint list plus an
/// interpolation kind. Each `(ms, level)` is a *segment*: reach `level`
/// (0..=[`MAX_ENV_LEVEL`], a linear amplitude) over `ms` milliseconds from the
/// previous point. The last pair is the *release* segment: it fires on note-off;
/// while a note is held the curve runs the earlier points and sustains at the
/// second-to-last level.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Envelope {
    /// `(segment_ms, level_0_127)` breakpoints, in order. Wire bound:
    /// `1..=MAX_ENV_POINTS` points, each level `<= MAX_ENV_LEVEL`.
    pub points: Vec<(u16, u8)>,
    /// How the renderer fills between breakpoints.
    pub interp: Interp,
}
