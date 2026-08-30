//! The room's shared, causally edited pitch set.
//!
//! This is deliberately not partitioned by peer. Every authorized member may
//! add or remove any pitch through [`crate::MusicOp`]. The causal-history
//! adapter supplies observed-remove semantics, so a departed or reidentified
//! peer never owns an unremovable part of the sounding set.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::tuning::{TunedDegree, TunedPeriodicPitch};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SharedPitchSet {
    pub pitch_classes: BTreeSet<TunedDegree>,
    pub pitches: BTreeSet<TunedPeriodicPitch>,
}

impl SharedPitchSet {
    pub fn is_empty(&self) -> bool {
        self.pitch_classes.is_empty() && self.pitches.is_empty()
    }
}
