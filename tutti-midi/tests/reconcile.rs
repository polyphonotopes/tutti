//! The bridge conformance suite — the reconnect contract's four properties,
//! proven against a fake sink (a model MIDI endpoint):
//!
//! 1. **No stuck notes, ever**: after any detach/attach interleaving, the
//!    endpoint's sounding set equals the bridge's shadow, and an empty view
//!    silences it.
//! 2. **The gap is never replayed**: events lost while detached are irrelevant
//!    by construction — reconcile reads only (assumed, target).
//! 3. **Idempotent re-attach**: attaching again with an unchanged view emits
//!    nothing.
//! 4. **Tuning change = panic + repopulate**: a register flip mid-attachment is
//!    a controlled detach/attach on the same cable.

use std::collections::{BTreeMap, BTreeSet};

use tutti_midi::{Attach, MidiBridge, MidiMessage, MidiOutputConfig, MidiRouteError};
use tutti_music::tuning::{TunedPeriodicPitch, Tuning};

/// The fake sink: a model MIDI endpoint with real MIDI semantics — a note-off
/// for a silent note is a no-op, CC 123 (All Notes Off) clears its channel.
/// It only hears what the test delivers (nothing while "unplugged").
#[derive(Debug, Default)]
struct FakeEndpoint {
    sounding: BTreeSet<(u8, u8)>,
}

impl FakeEndpoint {
    fn hear(&mut self, messages: &[MidiMessage]) {
        for message in messages {
            match message {
                MidiMessage::NoteOn { channel, note, .. } => {
                    self.sounding.insert((*channel, *note));
                }
                MidiMessage::NoteOff { channel, note, .. } => {
                    self.sounding.remove(&(*channel, *note));
                }
                MidiMessage::ControlChange {
                    channel,
                    controller: 123,
                    ..
                } => {
                    self.sounding.retain(|(c, _)| c != channel);
                }
                _ => {}
            }
        }
    }

    fn power_cycle(&mut self) {
        self.sounding.clear();
    }
}

/// What the bridge believes the endpoint sounds (the shadow's voice set).
fn shadow_voices(bridge: &MidiBridge<u8>) -> BTreeSet<(u8, u8)> {
    bridge
        .ledger()
        .sources()
        .map(|(_, voice)| (voice.channel, voice.note))
        .collect()
}

fn pitch(tuning: &Tuning, degree: u16) -> TunedPeriodicPitch {
    TunedPeriodicPitch::new(tuning, degree, 0).unwrap()
}

fn target(tuning: &Tuning, entries: &[(u8, u16)]) -> BTreeMap<u8, TunedPeriodicPitch> {
    entries
        .iter()
        .map(|&(source, degree)| (source, pitch(tuning, degree)))
        .collect()
}

fn bridge12() -> (MidiBridge<u8>, Tuning) {
    let tuning = Tuning::twelve_tet();
    let bridge = MidiBridge::new(&tuning, MidiOutputConfig::exact_twelve_tet()).unwrap();
    (bridge, tuning)
}

/// SplitMix64 — a deterministic driver for the interleaving property test.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

#[test]
fn connect_is_a_reconcile_from_silence_and_detached_views_emit_nothing() {
    let (mut bridge, tuning) = bridge12();
    let t = target(&tuning, &[(1, 0), (2, 4)]);

    // Constructed detached: a view change emits nothing yet.
    assert!(bridge.on_view(&t, &tuning).messages.is_empty());
    assert!(!bridge.is_attached());
    assert_eq!(bridge.epoch(), 0);

    // The first attach IS the initial reconcile (assumed silence → two ons).
    let mut endpoint = FakeEndpoint::default();
    let out = bridge.on_attach(Attach::Fresh, &t, &tuning);
    endpoint.hear(&out.messages);
    assert_eq!(bridge.epoch(), 1);
    assert!(out.unroutable.is_empty());
    assert_eq!(out.messages.len(), 2, "exactly the two note-ons");
    assert_eq!(endpoint.sounding, shadow_voices(&bridge));
    assert_eq!(endpoint.sounding, BTreeSet::from([(0, 60), (0, 64)]));
}

#[test]
fn steady_state_emits_exactly_the_delta_offs_before_ons() {
    let (mut bridge, tuning) = bridge12();
    let mut endpoint = FakeEndpoint::default();
    endpoint.hear(&bridge.on_attach(Attach::Fresh, &target(&tuning, &[(1, 0), (2, 7)]), &tuning).messages);

    // Source 2 leaves, source 3 arrives: one off (first), one on.
    let out = bridge.on_view(&target(&tuning, &[(1, 0), (3, 4)]), &tuning);
    endpoint.hear(&out.messages);
    assert_eq!(
        out.messages,
        vec![
            MidiMessage::NoteOff { channel: 0, note: 67, velocity: 0 },
            MidiMessage::NoteOn { channel: 0, note: 64, velocity: tutti_midi::DEFAULT_VELOCITY },
        ]
    );
    assert_eq!(endpoint.sounding, shadow_voices(&bridge));

    // An unchanged view emits nothing.
    assert!(bridge.on_view(&target(&tuning, &[(1, 0), (3, 4)]), &tuning).messages.is_empty());
}

#[test]
fn the_gap_is_never_replayed() {
    let (mut bridge, tuning) = bridge12();
    let mut endpoint = FakeEndpoint::default();
    let held = target(&tuning, &[(1, 0)]);
    endpoint.hear(&bridge.on_attach(Attach::Fresh, &held, &tuning).messages);

    // Cable drops; the endpoint keeps its state. A degree is added AND removed
    // while detached — the endpoint must never hear about it.
    bridge.on_detach();
    assert!(bridge.on_view(&target(&tuning, &[(1, 0), (2, 4)]), &tuning).messages.is_empty());
    assert!(bridge.on_view(&held, &tuning).messages.is_empty());

    let out = bridge.on_attach(Attach::Resumed, &held, &tuning);
    assert!(out.messages.is_empty(), "gap replay: {:?}", out.messages);
    assert_eq!(endpoint.sounding, shadow_voices(&bridge));

    // A degree added (and kept) while detached emits exactly one on.
    bridge.on_detach();
    let grown = target(&tuning, &[(1, 0), (2, 4)]);
    let out = bridge.on_attach(Attach::Resumed, &grown, &tuning);
    endpoint.hear(&out.messages);
    assert_eq!(
        out.messages,
        vec![MidiMessage::NoteOn { channel: 0, note: 64, velocity: tutti_midi::DEFAULT_VELOCITY }]
    );
    assert_eq!(endpoint.sounding, shadow_voices(&bridge));
}

#[test]
fn reattach_with_an_unchanged_view_is_idempotent() {
    let (mut bridge, tuning) = bridge12();
    let t = target(&tuning, &[(1, 0), (2, 4)]);
    let first = bridge.on_attach(Attach::Fresh, &t, &tuning);
    assert_eq!(first.messages.len(), 2);
    let epoch = bridge.epoch();

    // A second attach on the live cable: plain diff, empty; epoch unchanged.
    for policy in [Attach::Fresh, Attach::Resumed, Attach::Unknowable] {
        let again = bridge.on_attach(policy, &t, &tuning);
        assert!(again.messages.is_empty(), "{policy:?} re-attach replayed");
        assert_eq!(bridge.epoch(), epoch);
    }

    // A real detach/attach cycle with no view change: Resumed emits nothing,
    // and the epoch advances exactly once.
    bridge.on_detach();
    let again = bridge.on_attach(Attach::Resumed, &t, &tuning);
    assert!(again.messages.is_empty());
    assert_eq!(bridge.epoch(), epoch + 1);
}

#[test]
fn unknowable_fails_to_silence_then_rebuilds() {
    let (bridge, tuning) = bridge12();
    let before = target(&tuning, &[(1, 0)]);
    let after = target(&tuning, &[(1, 4)]);

    // Endpoint A kept its state across the drop; endpoint B power-cycled.
    // Unknowable must leave BOTH matching the shadow.
    for kept_state in [true, false] {
        let mut endpoint = FakeEndpoint::default();
        let mut b = bridge.clone();
        endpoint.hear(&b.on_attach(Attach::Fresh, &before, &tuning).messages);
        b.on_detach();
        if !kept_state {
            endpoint.power_cycle();
        }
        let out = b.on_attach(Attach::Unknowable, &after, &tuning);
        endpoint.hear(&out.messages);
        assert_eq!(
            endpoint.sounding,
            shadow_voices(&b),
            "kept_state={kept_state}: endpoint diverged from shadow"
        );
        assert_eq!(endpoint.sounding, BTreeSet::from([(0, 64)]));
        // The panic prefix really is offs/resets before the rebuild's on.
        assert!(matches!(out.messages.first(), Some(MidiMessage::NoteOff { .. })));
        assert!(matches!(out.messages.last(), Some(MidiMessage::NoteOn { note: 64, .. })));
    }
}

#[test]
fn tuning_change_is_panic_then_repopulate() {
    let quarter =
        Tuning::from_scl_text("quarter", "quarter tones\n2\n50.0\n1200.0\n", None).unwrap();
    let (mut bridge, tuning) = bridge12();
    let mut endpoint = FakeEndpoint::default();
    endpoint.hear(&bridge.on_attach(Attach::Fresh, &target(&tuning, &[(1, 0), (2, 4)]), &tuning).messages);

    // Explicit change: MPE config under the microtonal tuning.
    let new_target = target(&quarter, &[(1, 1)]);
    let out = bridge
        .change_tuning(&quarter, MidiOutputConfig::default(), &new_target)
        .unwrap();
    endpoint.hear(&out.messages);
    assert!(out.unroutable.is_empty());
    // Offs for both old voices came before the new note-on.
    let first_on = out.messages.iter().position(|m| matches!(m, MidiMessage::NoteOn { .. })).unwrap();
    let offs_before = out.messages[..first_on]
        .iter()
        .filter(|m| matches!(m, MidiMessage::NoteOff { .. }))
        .count();
    assert_eq!(offs_before, 2, "both old voices released before the rebuild");
    assert_eq!(endpoint.sounding, shadow_voices(&bridge));

    // The same doctrine fires implicitly when on_view sees a flipped register.
    let (mut bridge, tuning) = bridge12();
    let mut endpoint = FakeEndpoint::default();
    endpoint.hear(&bridge.on_attach(Attach::Fresh, &target(&tuning, &[(1, 0)]), &tuning).messages);
    let out = bridge.on_view(&target(&quarter, &[(1, 0)]), &quarter);
    endpoint.hear(&out.messages);
    assert!(matches!(out.messages.first(), Some(MidiMessage::NoteOff { .. })));
    assert_eq!(endpoint.sounding, shadow_voices(&bridge));
}

#[test]
fn unroutable_sources_are_surfaced_not_swallowed() {
    let quarter =
        Tuning::from_scl_text("quarter", "quarter tones\n2\n50.0\n1200.0\n", None).unwrap();
    let config = MidiOutputConfig::Mpe {
        master_channel: 0,
        member_channels: vec![3],
        pitch_bend_range_semitones: 2.0,
    };
    let mut bridge: MidiBridge<u8> = MidiBridge::new(&quarter, config).unwrap();
    let mut endpoint = FakeEndpoint::default();

    // Two sources, one member channel: the second is unroutable and reported.
    let t = target(&quarter, &[(1, 0), (2, 1)]);
    let out = bridge.on_attach(Attach::Fresh, &t, &quarter);
    endpoint.hear(&out.messages);
    assert_eq!(out.unroutable.len(), 1);
    assert!(matches!(out.unroutable[0], (2, MidiRouteError::MpeChannelsExhausted)));
    assert_eq!(endpoint.sounding, shadow_voices(&bridge), "the shadow stays honest");

    // When the channel frees up, the reported source becomes routable.
    let out = bridge.on_view(&target(&quarter, &[(2, 1)]), &quarter);
    endpoint.hear(&out.messages);
    assert!(out.unroutable.is_empty());
    assert_eq!(endpoint.sounding, shadow_voices(&bridge));
}

/// The interleaving property: hundreds of seeded random steps — view churn,
/// detaches, attaches under every policy (with the endpoint's reality matched
/// to the policy's assumption) — and the endpoint NEVER diverges from the
/// shadow while attached; an empty final view leaves silence.
#[test]
fn no_stuck_notes_across_random_interleavings() {
    let tuning = Tuning::twelve_tet();
    for seed in [3u64, 17, 99, 2024] {
        let mut rng = Rng(seed);
        let mut bridge: MidiBridge<u8> =
            MidiBridge::new(&tuning, MidiOutputConfig::exact_twelve_tet()).unwrap();
        let mut endpoint = FakeEndpoint::default();
        let mut current: BTreeMap<u8, TunedPeriodicPitch> = BTreeMap::new();
        endpoint.hear(&bridge.on_attach(Attach::Fresh, &current, &tuning).messages);

        for step in 0..300 {
            match rng.next() % 10 {
                // View churn: add/move/remove one of 8 sources.
                0..=5 => {
                    let source = (rng.next() % 8) as u8;
                    if rng.next() % 3 == 0 {
                        current.remove(&source);
                    } else {
                        let degree = (rng.next() % 12) as u16;
                        current.insert(source, pitch(&tuning, degree));
                    }
                    let out = bridge.on_view(&current, &tuning);
                    if bridge.is_attached() {
                        endpoint.hear(&out.messages);
                    }
                    assert!(out.unroutable.is_empty(), "seed {seed} step {step}");
                }
                // Cable drops.
                6 => bridge.on_detach(),
                // Reattach under a policy whose assumption matches reality.
                // (On a live cable an attach is a plain re-assertion, so the
                // endpoint's state only changes across a REAL reattach.)
                _ => {
                    let policy = if !bridge.is_attached() {
                        match rng.next() % 3 {
                            0 => {
                                endpoint.power_cycle();
                                Attach::Fresh
                            }
                            1 => Attach::Resumed,
                            _ => {
                                if rng.next() % 2 == 0 {
                                    endpoint.power_cycle();
                                }
                                Attach::Unknowable
                            }
                        }
                    } else {
                        Attach::Resumed
                    };
                    let out = bridge.on_attach(policy, &current, &tuning);
                    endpoint.hear(&out.messages);
                }
            }
            if bridge.is_attached() {
                assert_eq!(
                    endpoint.sounding,
                    shadow_voices(&bridge),
                    "seed {seed} step {step}: endpoint diverged from the shadow"
                );
            }
        }

        // Fail to silence: reattach if needed, then an empty view.
        if !bridge.is_attached() {
            endpoint.hear(&bridge.on_attach(Attach::Resumed, &current, &tuning).messages);
        }
        current.clear();
        endpoint.hear(&bridge.on_view(&current, &tuning).messages);
        assert!(endpoint.sounding.is_empty(), "seed {seed}: stuck notes at teardown");
        assert!(shadow_voices(&bridge).is_empty());
    }
}
