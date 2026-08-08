//! The versioned OSC projection scheme — `/tutti/1/<topic>/…`, the bridge's
//! wire vocabulary. Versioned like a wire magic: a breaking address change
//! bumps the leading `1`.
//!
//! Value shapes are chosen so departures clear naturally:
//!
//! | address | args | notes |
//! |---|---|---|
//! | `/tutti/1/<topic>/degrees` | one float per live degree (fractional MIDI, sorted) | one idempotent list — self-clearing |
//! | `/tutti/1/<topic>/tuning` | the [`TuningId`](tutti_music::TuningId) as a hex string | |
//! | `/tutti/1/<topic>/degree/<i>/env` | interp code (0 linear, 1 exp, 2 step) then flattened `(ms, level)` ints | facets persist past removal; an empty arg list clears |
//! | `/tutti/1/<topic>/degree/<i>/holders` | author count | `0` is the cleared value |
//!
//! Floats are fractional MIDI from [`tutti_music::render`] — microtonality
//! survives where raw MIDI needs MPE.

use std::collections::BTreeMap;

use tutti_music::MusicView;
use tutti_music::facets::Interp;
use tutti_music::render::fractional_midi;
use tutti_music::tuning::PeriodicPitch;

use crate::codec::OscArg;

/// One `<topic>` segment, made address-safe: OSC-reserved and non-printable
/// characters are replaced with `-`.
pub fn topic_segment(topic: &str) -> String {
    topic
        .chars()
        .map(|c| match c {
            ' ' | '#' | '*' | ',' | '/' | '?' | '[' | ']' | '{' | '}' => '-',
            c if c.is_ascii_graphic() => c,
            _ => '-',
        })
        .collect()
}

fn interp_code(interp: Interp) -> i32 {
    match interp {
        Interp::Linear => 0,
        Interp::Exp => 1,
        Interp::Step => 2,
    }
}

/// Project a converged [`MusicView`] into the full address → value target map —
/// the OSC image of the room's state. A pure function of the view, so equal
/// views project byte-identical messages on every peer.
pub fn project(topic: &str, view: &MusicView) -> BTreeMap<String, Vec<OscArg>> {
    let base = format!("/tutti/1/{}", topic_segment(topic));
    let mut target: BTreeMap<String, Vec<OscArg>> = BTreeMap::new();

    target.insert(
        format!("{base}/tuning"),
        vec![OscArg::Str(view.tuning.id.to_string())],
    );

    // The view's degrees are scoped to its resolved tuning, which was
    // wire-validated at ingress; the `.ok()` is defensive.
    if let Some(tuning) = view.tuning.validate("osc projection").ok() {
        let degrees: Vec<OscArg> = view
            .live
            .iter()
            .map(|degree| {
                let pitch = PeriodicPitch::from_degree(degree.degree, 0);
                OscArg::Float(fractional_midi(&tuning, pitch) as f32)
            })
            .collect();
        target.insert(format!("{base}/degrees"), degrees);
    }

    for (degree, envelope) in &view.envelopes {
        let mut args = vec![OscArg::Int(interp_code(envelope.interp))];
        for &(ms, level) in &envelope.points {
            args.push(OscArg::Int(i32::from(ms)));
            args.push(OscArg::Int(i32::from(level)));
        }
        target.insert(
            format!("{base}/degree/{}/env", degree.degree.index()),
            args,
        );
    }

    for (degree, authors) in &view.holders {
        target.insert(
            format!("{base}/degree/{}/holders", degree.degree.index()),
            vec![OscArg::Int(authors.len() as i32)],
        );
    }

    target
}

/// The value that clears a departed address, when one exists: holders drop to
/// `0`, a facet clears to an empty arg list. Addresses whose values are
/// self-clearing (`degrees`, `tuning`) never depart, so they have none.
pub(crate) fn cleared(addr: &str) -> Option<Vec<OscArg>> {
    if addr.ends_with("/holders") {
        Some(vec![OscArg::Int(0)])
    } else if addr.ends_with("/env") {
        Some(Vec::new())
    } else {
        None
    }
}
