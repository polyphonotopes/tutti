//! **tutti-midi** — the reactive MIDI bridge over the tutti music protocol.
//!
//! MIDI is an event protocol, and event protocols fail at exactly one place:
//! disconnection. A dropped cable loses note-offs (stuck notes) and on
//! reconnect a naive bridge replays a gap that no longer describes reality.
//! tutti is state-first — the pitch-set and its facets ARE the convergent
//! state, events a derivable projection — so this crate's contract is:
//!
//! > Outbound MIDI is DERIVED from state, never queued from events.
//! > Reconnection is re-projection: diff the endpoint's assumed state against
//! > the current view and emit exactly the reconciling messages.
//!
//! Three sans-io pieces, each a pure state machine emitting message values
//! (fake-sink testable; no ports, no sockets, no runtime — port I/O stays in
//! the app's drivers):
//!
//! * [`MidiLedger`] — source-balanced voice ownership + MPE microtonal output;
//!   the ledger doubles as the endpoint shadow.
//! * [`MidiBridge`] — the reconcile-on-reconnect core: [`Attach`] policies,
//!   epoch-stamped attachment, offs-before-ons deltas, no gap replay.
//! * [`MidiInputTracker`] — inbound notes → held/released degree intent the app
//!   folds into ops or presence leases.

mod input;
mod ledger;
mod reconcile;

pub use input::{HeldInputAction, MidiInputTracker, PhysicalMidiKey, midi_note_frequency_hz};
pub use ledger::{
    DEFAULT_VELOCITY, MidiLedger, MidiMessage, MidiOutputConfig, MidiRouteError, MidiVoice,
};
pub use reconcile::{Attach, MidiBridge, Reconciled};
