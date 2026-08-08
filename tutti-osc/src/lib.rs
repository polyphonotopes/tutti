//! **tutti-osc** — the reactive OSC bridge over the tutti music protocol.
//!
//! Same discipline as `tutti-midi`, simpler voice model: OSC values live at
//! idempotent addresses, so reconcile is "send every address whose target
//! differs from the shadow" and a full refresh is always legal. Outbound
//! messages are DERIVED from the convergent view, never queued from events;
//! reconnection is re-projection, so a gap is never replayed.
//!
//! * [`codec`] — hand-rolled OSC 1.0 message encoding/decoding (no bundles
//!   until a consumer needs them).
//! * [`address`] — the versioned projection scheme (`/tutti/1/…`), with value
//!   shapes chosen so departures clear naturally.
//! * [`OscBridge`] — the shadow + reconcile core. Liveness is the driver's
//!   problem (UDP has no connection): the core only exposes attach/detach and
//!   never guesses.

pub mod address;
pub mod codec;
mod reconcile;

pub use codec::{OscArg, OscCodecError, OscMessage};
pub use reconcile::{Attach, OscBridge};
