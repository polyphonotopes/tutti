//! The reconcile-on-reconnect core: outbound MIDI derived from state, with
//! disconnection handled by re-projection instead of gap replay.
//!
//! The bridge privately owns a [`MidiLedger`] as the **endpoint shadow** — what
//! it believes the endpoint currently sounds. Steady state diffs the target
//! (the projection of the convergent view) against the shadow and emits exactly
//! the delta, offs before ons. Reconnection picks an [`Attach`] assumption,
//! then reconciles the assumption against the view **as it is now** — events
//! lost while detached are irrelevant by construction.

use std::collections::BTreeMap;

use tutti_music::tuning::{TunedPeriodicPitch, Tuning};

use crate::ledger::{MidiLedger, MidiMessage, MidiOutputConfig, MidiRouteError};

/// What a (re)attached endpoint is assumed to hold at the moment of attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attach {
    /// The endpoint starts silent — a power-cycled synth, a brand-new peer.
    /// Reconcile emits note-ons only.
    Fresh,
    /// The endpoint kept its state across a brief drop on the same cable.
    /// Reconcile diffs against the last shadow.
    Resumed,
    /// No assumption is safe. Fail to silence first — a panic (balanced
    /// note-offs + Reset All Controllers + All Notes Off per channel) — then
    /// rebuild from the current view. The safe default for MIDI hardware.
    Unknowable,
}

/// One reconcile's output: the messages to send now, in order, plus any sources
/// the output config could not voice (e.g. MPE channels exhausted) — surfaced,
/// never swallowed. An unroutable source keeps its previous shadow state.
#[derive(Debug, Clone, PartialEq)]
pub struct Reconciled<S> {
    pub messages: Vec<MidiMessage>,
    pub unroutable: Vec<(S, MidiRouteError)>,
}

impl<S> Default for Reconciled<S> {
    fn default() -> Self {
        Self {
            messages: Vec::new(),
            unroutable: Vec::new(),
        }
    }
}

/// The reactive MIDI endpoint: single writer of its shadow, read-only
/// introspection out. Constructed **detached** — the first [`Self::on_attach`]
/// is the initial reconcile (connect is a reconcile from assumed silence).
#[derive(Debug, Clone)]
pub struct MidiBridge<S: Ord + Clone> {
    ledger: MidiLedger<S>,
    attached: bool,
    epoch: u64,
}

impl<S: Ord + Clone> MidiBridge<S> {
    pub fn new(tuning: &Tuning, config: MidiOutputConfig) -> Result<Self, MidiRouteError> {
        Ok(Self {
            ledger: MidiLedger::new(tuning, config)?,
            attached: false,
            epoch: 0,
        })
    }

    /// Steady state: reconcile the endpoint to `target` — each source key
    /// mapped to the pitch it should sound (the projection of the convergent
    /// view). Emits exactly the delta: releases first (offs), then per-source
    /// updates and additions. A no-op while detached.
    ///
    /// A `tuning` that differs from the shadow's is a register flip observed
    /// mid-attachment and is handled as the doctrine demands: a controlled
    /// panic + repopulate on the same cable.
    pub fn on_view(
        &mut self,
        target: &BTreeMap<S, TunedPeriodicPitch>,
        tuning: &Tuning,
    ) -> Reconciled<S> {
        if !self.attached {
            return Reconciled::default();
        }
        self.reconcile(target, tuning)
    }

    /// (Re)attach the endpoint: `policy` names what it is assumed to hold, the
    /// reconcile target is the view **as it is now** — never the state at
    /// disconnect time. Bumps the epoch so drivers can drop stale async sends.
    ///
    /// Attaching an already-attached bridge is a re-assertion: it reconciles
    /// against the live shadow (the policy describes a *newly* attached
    /// endpoint) and does not bump the epoch — so a repeated attach with an
    /// unchanged view emits nothing.
    pub fn on_attach(
        &mut self,
        policy: Attach,
        target: &BTreeMap<S, TunedPeriodicPitch>,
        tuning: &Tuning,
    ) -> Reconciled<S> {
        if self.attached {
            return self.reconcile(target, tuning);
        }
        let mut prefix = Vec::new();
        match policy {
            Attach::Fresh => {
                // The endpoint is silent: forget the shadow without emitting —
                // offs for notes it never heard would be noise, not reconcile.
                self.ledger.forget();
                if tuning.id() != self.ledger.tuning_id() {
                    self.ledger.align_silent(tuning);
                }
            }
            Attach::Resumed => {}
            Attach::Unknowable => prefix.extend(self.ledger.panic()),
        }
        self.attached = true;
        self.epoch += 1;
        let mut out = self.reconcile(target, tuning);
        prefix.append(&mut out.messages);
        out.messages = prefix;
        out
    }

    /// Detach: stop emitting. The shadow is retained so a later
    /// [`Attach::Resumed`] can diff against it.
    pub fn on_detach(&mut self) {
        self.attached = false;
    }

    /// Explicit tuning/config change: panic + repopulate from `target` while
    /// attached; while detached the shadow is silenced and re-keyed with no
    /// messages (there is no cable to send them on), so a later `Resumed`
    /// attach degrades to a fresh rebuild.
    pub fn change_tuning(
        &mut self,
        tuning: &Tuning,
        config: MidiOutputConfig,
        target: &BTreeMap<S, TunedPeriodicPitch>,
    ) -> Result<Reconciled<S>, MidiRouteError> {
        let mut prefix = self.ledger.change_tuning(tuning, config)?;
        if !self.attached {
            return Ok(Reconciled::default());
        }
        let mut out = self.reconcile(target, tuning);
        prefix.append(&mut out.messages);
        out.messages = prefix;
        Ok(out)
    }

    /// The attach generation. Bumped once per real (detached → attached)
    /// transition; an async driver stamps sends with it and drops stale ones.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn is_attached(&self) -> bool {
        self.attached
    }

    /// Read-only view of the shadow (what the endpoint is believed to sound).
    pub fn ledger(&self) -> &MidiLedger<S> {
        &self.ledger
    }

    /// The shared diff: release sources that left the target, then set every
    /// target source — the ledger's balanced acquire/release makes each step
    /// atomic and refcounted, and unchanged sources emit nothing.
    fn reconcile(
        &mut self,
        target: &BTreeMap<S, TunedPeriodicPitch>,
        tuning: &Tuning,
    ) -> Reconciled<S> {
        let mut out = Reconciled::default();

        // A tuning register flip mid-attachment: controlled panic, then the
        // rebuild below repopulates under the new tuning (same config).
        if tuning.id() != self.ledger.tuning_id() {
            let config = self.ledger.config();
            let messages = self
                .ledger
                .change_tuning(tuning, config)
                .expect("the ledger's own config re-validates");
            out.messages.extend(messages);
        }

        let departed: Vec<S> = self
            .ledger
            .sources()
            .map(|(source, _)| source.clone())
            .filter(|source| !target.contains_key(source))
            .collect();
        for source in departed {
            match self.ledger.set_source(source.clone(), None, tuning) {
                Ok(messages) => out.messages.extend(messages),
                Err(error) => out.unroutable.push((source, error)),
            }
        }
        for (source, pitch) in target {
            match self.ledger.set_source(source.clone(), Some(*pitch), tuning) {
                Ok(messages) => out.messages.extend(messages),
                Err(error) => out.unroutable.push((source.clone(), error)),
            }
        }
        out
    }
}
