//! The OSC bridge conformance suite: the projection is a pure function of the
//! view, steady state sends only deltas, departures clear, the gap is never
//! replayed, re-attach is idempotent, and Unknowable sweeps a full refresh.

use std::collections::{BTreeMap, BTreeSet};

use tutti_music::tuning::{TunedDegree, Tuning};
use tutti_music::{Envelope, Interp, MusicView};
use tutti_osc::{Attach, OscArg, OscBridge, OscMessage, address};

fn degree(index: u16) -> TunedDegree {
    TunedDegree::new(&Tuning::twelve_tet(), index).unwrap()
}

fn author(byte: u8) -> tutti_music::AuthorId {
    tutti_music::AuthorId([byte; 32])
}

fn pluck() -> Envelope {
    Envelope {
        points: vec![(0, 127), (120, 12), (40, 0)],
        interp: Interp::Exp,
    }
}

/// A view with two live degrees (0 held by two authors, 4 by one) and a facet
/// on degree 0.
fn view_two() -> MusicView {
    let mut view = MusicView::default();
    view.live = BTreeSet::from([degree(0), degree(4)]);
    view.holders = BTreeMap::from([
        (degree(0), BTreeSet::from([author(1), author(2)])),
        (degree(4), BTreeSet::from([author(1)])),
    ]);
    view.envelopes = BTreeMap::from([(degree(0), pluck())]);
    view
}

/// `view_two` with degree 4 retracted (its holders entry gone; facets persist).
fn view_one() -> MusicView {
    let mut view = view_two();
    view.live.remove(&degree(4));
    view.holders.remove(&degree(4));
    view
}

fn addrs(messages: &[OscMessage]) -> Vec<&str> {
    messages.iter().map(|m| m.addr.as_str()).collect()
}

#[test]
fn projection_is_a_pure_total_image_of_the_view() {
    let target = address::project("my room", &view_two());
    // The topic segment is address-safe (the space became '-').
    let expected: Vec<&str> = vec![
        "/tutti/1/my-room/degree/0/env",
        "/tutti/1/my-room/degree/0/holders",
        "/tutti/1/my-room/degree/4/holders",
        "/tutti/1/my-room/degrees",
        "/tutti/1/my-room/tuning",
    ];
    assert_eq!(target.keys().map(String::as_str).collect::<Vec<_>>(), expected);
    assert_eq!(
        target["/tutti/1/my-room/degrees"],
        vec![OscArg::Float(60.0), OscArg::Float(64.0)]
    );
    assert_eq!(target["/tutti/1/my-room/degree/0/holders"], vec![OscArg::Int(2)]);
    // env: interp code then flattened (ms, level) pairs.
    assert_eq!(
        target["/tutti/1/my-room/degree/0/env"],
        vec![
            OscArg::Int(1),
            OscArg::Int(0),
            OscArg::Int(127),
            OscArg::Int(120),
            OscArg::Int(12),
            OscArg::Int(40),
            OscArg::Int(0),
        ]
    );
    // Purity: equal views project equal maps.
    assert_eq!(target, address::project("my room", &view_two()));
    // Every message encodes and round-trips through the codec.
    for (addr, args) in &target {
        let msg = OscMessage { addr: addr.clone(), args: args.clone() };
        assert_eq!(OscMessage::decode(&msg.encode()).unwrap(), msg);
    }
}

#[test]
fn attach_sends_the_full_image_then_steady_state_sends_only_deltas() {
    let mut bridge = OscBridge::new("room");
    // Detached: nothing.
    assert!(bridge.on_view(&view_two()).is_empty());

    let hello = bridge.on_attach(Attach::Fresh, &view_two());
    assert_eq!(hello.len(), 5, "the full image on first attach");
    assert_eq!(bridge.epoch(), 1);

    // Unchanged view: silence.
    assert!(bridge.on_view(&view_two()).is_empty());

    // Degree 4 retracted: its holders clear to 0 and the degrees list shrinks —
    // clears first. The env address persists (facet law) and the tuning is
    // unchanged, so neither is resent.
    let out = bridge.on_view(&view_one());
    assert_eq!(
        addrs(&out),
        vec!["/tutti/1/room/degree/4/holders", "/tutti/1/room/degrees"]
    );
    assert_eq!(out[0].args, vec![OscArg::Int(0)], "holders clear to zero");
    assert_eq!(out[1].args, vec![OscArg::Float(60.0)]);
}

#[test]
fn the_gap_is_never_replayed() {
    let mut bridge = OscBridge::new("room");
    bridge.on_attach(Attach::Fresh, &view_one());

    // Detached churn: grow then shrink back — the peer must never hear of it.
    bridge.on_detach();
    assert!(bridge.on_view(&view_two()).is_empty());
    assert!(bridge.on_view(&view_one()).is_empty());
    let out = bridge.on_attach(Attach::Resumed, &view_one());
    assert!(out.is_empty(), "gap replay: {:?}", addrs(&out));

    // A change that PERSISTED across the gap arrives as one delta.
    bridge.on_detach();
    let out = bridge.on_attach(Attach::Resumed, &view_two());
    assert_eq!(
        addrs(&out),
        vec![
            "/tutti/1/room/degree/4/holders",
            "/tutti/1/room/degrees"
        ]
    );
}

#[test]
fn reattach_with_an_unchanged_view_is_idempotent() {
    let mut bridge = OscBridge::new("room");
    bridge.on_attach(Attach::Fresh, &view_two());
    let epoch = bridge.epoch();
    for policy in [Attach::Fresh, Attach::Resumed, Attach::Unknowable] {
        assert!(bridge.on_attach(policy, &view_two()).is_empty(), "{policy:?}");
        assert_eq!(bridge.epoch(), epoch, "a live-cable attach is not a transition");
    }
    bridge.on_detach();
    assert!(bridge.on_attach(Attach::Resumed, &view_two()).is_empty());
    assert_eq!(bridge.epoch(), epoch + 1);
}

#[test]
fn fresh_forgets_the_shadow_and_unknowable_sweeps_everything() {
    let mut bridge = OscBridge::new("room");
    bridge.on_attach(Attach::Fresh, &view_two());
    bridge.on_detach();

    // Fresh: a power-cycled peer gets the full CURRENT image (no clears — it
    // never heard the old one).
    let mut fresh = bridge.clone();
    let out = fresh.on_attach(Attach::Fresh, &view_one());
    assert_eq!(out.len(), 4, "the full one-degree image");
    assert!(!addrs(&out).contains(&"/tutti/1/room/degree/4/holders"));

    // Unknowable: clears for everything the shadow asserted that no longer
    // holds, PLUS a rewrite of every current address.
    let out = bridge.on_attach(Attach::Unknowable, &view_one());
    assert_eq!(
        addrs(&out),
        vec![
            "/tutti/1/room/degree/4/holders", // cleared (0)
            "/tutti/1/room/degree/0/env",
            "/tutti/1/room/degree/0/holders",
            "/tutti/1/room/degrees",
            "/tutti/1/room/tuning",
        ]
    );
}
