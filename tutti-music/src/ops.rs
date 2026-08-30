//! The music op alphabet — the wire vocabulary every tutti music peer speaks.
//!
//! Protocol generations are owned by the canonical-history adapter. Existing
//! variants are stable within a generation; a shape change requires a new
//! adapter generation rather than a compatibility shim.
//!
//! Deliberately absent: note events as durable ops. Performance is presence-
//! lease-shaped and never enters the log — the pitch-set is the shared object;
//! held notes are a local projection of it.

use serde::{Deserialize, Serialize};

use crate::facets::{Envelope, MAX_ENV_LEVEL, MAX_ENV_POINTS};
use crate::roundtable::RoundTableConfig;
use crate::tuning::{MAX_SCALE_DEGREES, TunedDegree, TunedPeriodicPitch, TuningDefinition};

/// The music operation. Degrees are a tuning-scoped add-wins set; envelopes are
/// per-degree causal-maxima registers; the tuning is a room-wide register. All
/// four commute — the fold resolves them causally, never by wall-clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MusicOp {
    /// Assert one tuning-scoped degree into the shared pitch-set.
    AddDegree { degree: TunedDegree },
    /// Retract one degree. Cancels only the adds it causally observed; a
    /// concurrent add survives (add-wins).
    RemoveDegree { degree: TunedDegree },
    /// Write the amplitude-envelope facet for one degree (a causal register,
    /// independent of the degree's liveness).
    SetEnvelope { degree: TunedDegree, env: Envelope },
    /// Canonical room-wide tuning definition (register; causal-maxima resolved).
    SetTuning { definition: TuningDefinition },
    /// Room-wide musical parameters for the round-table bass performance.
    /// Running state and turns remain ephemeral session messages.
    SetRoundTable { config: RoundTableConfig },
    /// Assert one absolute tuning-scoped pitch into the shared pitch set.
    AddPitch { pitch: TunedPeriodicPitch },
    /// Retract every causally-observed add of this absolute pitch. Any room
    /// member may do this; a concurrent add survives (observed-remove set).
    RemovePitch { pitch: TunedPeriodicPitch },
}

/// Wire well-formedness for one [`MusicOp`] — bounds only, run once at ingress.
/// Validate the bounded protocol shape independently of any envelope or
/// storage stack. Alternate canonical-history adapters call this at their own
/// admission boundary.
pub fn validate(op: &MusicOp) -> Result<(), String> {
    let validate_degree = |degree: TunedDegree| {
        if usize::from(degree.degree.index()) >= MAX_SCALE_DEGREES {
            Err(format!(
                "degree {} exceeds the supported bound",
                degree.degree.index()
            ))
        } else {
            Ok(())
        }
    };
    match op {
        MusicOp::AddDegree { degree } | MusicOp::RemoveDegree { degree } => {
            validate_degree(*degree)
        }
        MusicOp::SetEnvelope { degree, env } => {
            validate_degree(*degree)?;
            if env.points.is_empty() || env.points.len() > MAX_ENV_POINTS {
                return Err(format!(
                    "envelope must carry 1..={MAX_ENV_POINTS} breakpoints (got {})",
                    env.points.len()
                ));
            }
            if let Some(&(_, level)) = env.points.iter().find(|(_, l)| *l > MAX_ENV_LEVEL) {
                return Err(format!(
                    "envelope level {level} exceeds MAX_ENV_LEVEL={MAX_ENV_LEVEL}"
                ));
            }
            Ok(())
        }
        MusicOp::SetTuning { definition } => definition
            .validate("signed room tuning")
            .map(|_| ())
            .map_err(|error| error.to_string()),
        MusicOp::SetRoundTable { config } => config
            .validate()
            .map(|_| ())
            .map_err(|error| error.to_string()),
        MusicOp::AddPitch { pitch } | MusicOp::RemovePitch { pitch } => {
            validate_degree(pitch.degree())
        }
    }
}

#[cfg(feature = "legacy-source-log")]
pub(crate) fn validate_wire(op: &MusicOp) -> Result<(), String> {
    validate(op)
}
