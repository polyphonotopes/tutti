//! The OSC shadow + reconcile core — the same state-first contract as
//! `tutti-midi`, over an idempotent address space: reconcile sends every
//! address whose target value differs from the shadow, clears first.

use std::collections::BTreeMap;

use tutti_music::MusicView;

use crate::address::{cleared, project};
use crate::codec::{OscArg, OscMessage};

/// What a (re)attached peer is assumed to hold at the moment of attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attach {
    /// The peer knows nothing yet — send the full image. The safe default for
    /// OSC, where a full refresh is always legal.
    Fresh,
    /// The peer kept the last image it was sent across a brief outage — send
    /// only what changed since.
    Resumed,
    /// No assumption is safe: sweep clears over everything the shadow ever
    /// asserted that no longer holds, then rewrite the full image.
    Unknowable,
}

/// The reactive OSC endpoint: shadow = address → last args sent. Constructed
/// **detached**; the first [`Self::on_attach`] is the initial projection.
/// Liveness (socket errors, peer timeouts, handshakes) is the driver's problem
/// — the core only exposes these transitions and never guesses.
#[derive(Debug, Clone, Default)]
pub struct OscBridge {
    topic: String,
    shadow: BTreeMap<String, Vec<OscArg>>,
    attached: bool,
    epoch: u64,
}

impl OscBridge {
    pub fn new(topic: &str) -> Self {
        Self {
            topic: topic.to_string(),
            ..Self::default()
        }
    }

    /// Steady state: project `view` and send exactly what differs from the
    /// shadow — clears for departed addresses first, then changed values.
    /// A no-op while detached.
    pub fn on_view(&mut self, view: &MusicView) -> Vec<OscMessage> {
        if !self.attached {
            return Vec::new();
        }
        self.reconcile(view, false)
    }

    /// (Re)attach: `policy` names what the peer is assumed to hold; the target
    /// is the view as it is now. Bumps the epoch on a real (detached →
    /// attached) transition; attaching an already-attached bridge reconciles
    /// against the live shadow and emits nothing new for an unchanged view.
    pub fn on_attach(&mut self, policy: Attach, view: &MusicView) -> Vec<OscMessage> {
        if self.attached {
            return self.reconcile(view, false);
        }
        self.attached = true;
        self.epoch += 1;
        match policy {
            Attach::Fresh => {
                self.shadow.clear();
                self.reconcile(view, false)
            }
            Attach::Resumed => self.reconcile(view, false),
            Attach::Unknowable => self.reconcile(view, true),
        }
    }

    /// Detach: stop emitting. The shadow is retained so a later
    /// [`Attach::Resumed`] can diff against it.
    pub fn on_detach(&mut self) {
        self.attached = false;
    }

    /// The attach generation — bumped once per real (detached → attached)
    /// transition, so a driver can drop stale async sends.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn is_attached(&self) -> bool {
        self.attached
    }

    /// Diff the projection against the shadow. With `full_refresh`, every
    /// target address is rewritten even if the shadow says it is current —
    /// the [`Attach::Unknowable`] sweep.
    fn reconcile(&mut self, view: &MusicView, full_refresh: bool) -> Vec<OscMessage> {
        let target = project(&self.topic, view);
        let mut messages = Vec::new();

        // Clears first — the offs-before-ons of an address space.
        let departed: Vec<String> = self
            .shadow
            .keys()
            .filter(|addr| !target.contains_key(*addr))
            .cloned()
            .collect();
        for addr in departed {
            self.shadow.remove(&addr);
            if let Some(args) = cleared(&addr) {
                messages.push(OscMessage { addr, args });
            }
        }

        for (addr, args) in target {
            if full_refresh || self.shadow.get(&addr) != Some(&args) {
                messages.push(OscMessage {
                    addr: addr.clone(),
                    args: args.clone(),
                });
            }
            self.shadow.insert(addr, args);
        }
        messages
    }
}
