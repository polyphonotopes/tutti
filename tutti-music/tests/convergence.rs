//! The music protocol's conformance gates: add-wins degrees, causal-maxima
//! facet registers, the tuning register's scoping, order-independence, and
//! oracle parity — all over REAL `Store<MusicLang>` peers exchanging signed
//! ops. (Moved in with the protocol from the tutti-amy leaf, re-keyed to the
//! tuning-scoped degree identity.)

use std::collections::BTreeSet;

use tutti_core::{SignedOp, Store, VerifiedOpG, signing_key_from_seed, verify_signed_op_in};
use tutti_music::tuning::{TunedDegree, Tuning, TuningDefinition};
use tutti_music::{Envelope, Interp, MusicLang, MusicOp, MusicView};

const TOPIC: &str = "tutti-music-conformance";

/// A 31-EDO room definition anchored so degree 0 sounds MIDI 60.
fn edo31() -> TuningDefinition {
    let mut scl = String::from("! generated\n31-tone equal temperament\n31\n");
    for step in 1..=31 {
        scl.push_str(&format!("{:.6}\n", f64::from(step) * 1200.0 / 31.0));
    }
    TuningDefinition::new(scl, Some("0\n0\n127\n60\n60\n261.6255653005986\n0\n".to_owned()))
        .expect("the generated 31-EDO definition is valid")
}

fn edo31_tuning() -> Tuning {
    edo31().validate("31-EDO room").unwrap()
}

fn degree31(pc: u16) -> TunedDegree {
    TunedDegree::new(&edo31_tuning(), pc).unwrap()
}

fn degree12(pc: u16) -> TunedDegree {
    TunedDegree::new(&Tuning::twelve_tet(), pc).unwrap()
}

fn verify(signed: &SignedOp) -> VerifiedOpG<MusicLang> {
    verify_signed_op_in::<MusicLang>(signed).expect("a signed music op verifies")
}

fn indices(view: &MusicView) -> BTreeSet<u16> {
    view.live.iter().map(|d| d.degree.index()).collect()
}

fn swell() -> Envelope {
    Envelope {
        points: vec![(0, 8), (350, 127), (60, 0)],
        interp: Interp::Linear,
    }
}

fn pluck() -> Envelope {
    Envelope {
        points: vec![(0, 127), (120, 12), (40, 0)],
        interp: Interp::Exp,
    }
}

/// Two partitioned peers (with the same in-log tuning) diverge, then converge
/// to the identical add-wins union on rejoin.
#[test]
fn partition_then_converge_to_union() {
    let ka = signing_key_from_seed(&[1u8; 32]);
    let kb = signing_key_from_seed(&[2u8; 32]);
    let mut a: Store<MusicLang> = Store::new();
    let mut b: Store<MusicLang> = Store::new();
    let mut ts = 0u64;
    let mut tick = move || {
        ts += 1;
        ts
    };

    let mut a_ops = vec![a.commit(&ka, TOPIC, tick(), MusicOp::SetTuning { definition: edo31() })];
    for pc in [0, 10, 18] {
        a_ops.push(a.commit(&ka, TOPIC, tick(), MusicOp::AddDegree { degree: degree31(pc) }));
    }
    let mut b_ops = vec![b.commit(&kb, TOPIC, tick(), MusicOp::SetTuning { definition: edo31() })];
    for op in [
        MusicOp::AddDegree { degree: degree31(8) },
        MusicOp::AddDegree { degree: degree31(25) },
        MusicOp::AddDegree { degree: degree31(5) },
        MusicOp::RemoveDegree { degree: degree31(5) },
    ] {
        b_ops.push(b.commit(&kb, TOPIC, tick(), op));
    }

    assert_eq!(indices(&a.view()), BTreeSet::from([0, 10, 18]));
    assert_eq!(indices(&b.view()), BTreeSet::from([8, 25]));

    for signed in &b_ops {
        a.ingest_verified(verify(signed));
    }
    for signed in &a_ops {
        b.ingest_verified(verify(signed));
    }

    assert_eq!(a.view(), b.view(), "peers must converge");
    assert_eq!(indices(&a.view()), BTreeSet::from([0, 8, 10, 18, 25]));
    assert!(!a.view().live.contains(&degree31(5)), "the observed remove wins");
    assert_eq!(a.view().tuning, edo31(), "the tuning register converged");
    assert_eq!(a.pending_len(), 0);
    assert_eq!(b.pending_len(), 0);
}

/// The full signed op-set ingested in several shuffled orders lands on the same
/// view every time, and the cheap lazy view equals the kernel oracle.
#[test]
fn convergence_is_order_independent() {
    let ka = signing_key_from_seed(&[1u8; 32]);
    let kb = signing_key_from_seed(&[2u8; 32]);
    let mut producer_a: Store<MusicLang> = Store::new();
    let mut producer_b: Store<MusicLang> = Store::new();
    let mut ops: Vec<SignedOp> = Vec::new();
    let mut ts = 0u64;
    let mut tick = move || {
        ts += 1;
        ts
    };
    ops.push(producer_a.commit(&ka, TOPIC, tick(), MusicOp::SetTuning { definition: edo31() }));
    ops.push(producer_b.commit(&kb, TOPIC, tick(), MusicOp::SetTuning { definition: edo31() }));
    for (key, producer, pcs) in [
        (&ka, &mut producer_a, [0u16, 10, 18].as_slice()),
        (&kb, &mut producer_b, [8u16, 25, 5].as_slice()),
    ] {
        for &pc in pcs {
            ops.push(producer.commit(key, TOPIC, tick(), MusicOp::AddDegree {
                degree: degree31(pc),
            }));
        }
    }
    ops.push(producer_b.commit(&kb, TOPIC, tick(), MusicOp::RemoveDegree { degree: degree31(5) }));

    let mut reference: Option<MusicView> = None;
    for rot in [0usize, 1, 3, 5, 7] {
        let mut store: Store<MusicLang> = Store::new();
        let n = ops.len();
        for i in 0..n {
            store.ingest_verified(verify(&ops[(i + rot) % n]));
        }
        assert_eq!(store.pending_len(), 0, "rot {rot} left ops parked");
        assert_eq!(store.view(), store.view_reference(), "rot {rot}: lazy != oracle");
        assert_eq!(indices(&store.view()), BTreeSet::from([0, 8, 10, 18, 25]));
        match &reference {
            None => reference = Some(store.view()),
            Some(r) => assert_eq!(&store.view(), r, "rot {rot} diverged"),
        }
    }
}

/// Add-wins under genuine CONCURRENCY: a remove kills only the adds it
/// causally observed; a concurrent add survives — and holders attribute the
/// surviving author.
#[test]
fn add_wins_over_concurrent_remove() {
    let ka = signing_key_from_seed(&[10u8; 32]);
    let kb = signing_key_from_seed(&[20u8; 32]);
    let mut a: Store<MusicLang> = Store::new();
    let mut b: Store<MusicLang> = Store::new();
    let d = degree12(7);

    let a_add = a.commit(&ka, TOPIC, 1, MusicOp::AddDegree { degree: d });
    let b_add = b.commit(&kb, TOPIC, 1, MusicOp::AddDegree { degree: d });
    let b_rem = b.commit(&kb, TOPIC, 2, MusicOp::RemoveDegree { degree: d });

    assert!(!b.view().live.contains(&d));

    a.ingest_verified(verify(&b_add));
    a.ingest_verified(verify(&b_rem));
    b.ingest_verified(verify(&a_add));

    assert!(a.view().live.contains(&d), "concurrent add must win");
    assert_eq!(a.view(), b.view(), "peers converge");
    let holders = &a.view().holders[&d];
    assert_eq!(holders.len(), 1, "only A's add survived B's observed remove");
}

/// A degree added then removed WITHIN one causal chain is gone.
#[test]
fn observed_remove_actually_removes() {
    let ka = signing_key_from_seed(&[9u8; 32]);
    let mut a: Store<MusicLang> = Store::new();
    a.commit(&ka, TOPIC, 1, MusicOp::AddDegree { degree: degree12(3) });
    a.commit(&ka, TOPIC, 2, MusicOp::RemoveDegree { degree: degree12(3) });
    assert!(a.view().live.is_empty(), "observed remove clears the degree");
}

/// Concurrent `SetEnvelope`s on the same degree resolve to ONE causal-maxima
/// winner on every peer; disjoint degrees keep each peer's own write.
#[test]
fn envelope_registers_converge_across_peers() {
    let ka = signing_key_from_seed(&[11u8; 32]);
    let kb = signing_key_from_seed(&[22u8; 32]);
    let mut a: Store<MusicLang> = Store::new();
    let mut b: Store<MusicLang> = Store::new();
    let (contested, a_only, b_only) = (degree12(0), degree12(4), degree12(9));

    let a_ops = vec![
        a.commit(&ka, TOPIC, 1, MusicOp::AddDegree { degree: contested }),
        a.commit(&ka, TOPIC, 2, MusicOp::SetEnvelope { degree: contested, env: swell() }),
        a.commit(&ka, TOPIC, 3, MusicOp::SetEnvelope { degree: a_only, env: swell() }),
    ];
    let b_ops = vec![
        b.commit(&kb, TOPIC, 1, MusicOp::AddDegree { degree: contested }),
        b.commit(&kb, TOPIC, 2, MusicOp::SetEnvelope { degree: contested, env: pluck() }),
        b.commit(&kb, TOPIC, 3, MusicOp::SetEnvelope { degree: b_only, env: pluck() }),
    ];

    for signed in &b_ops {
        a.ingest_verified(verify(signed));
    }
    for signed in &a_ops {
        b.ingest_verified(verify(signed));
    }

    assert_eq!(a.view(), b.view(), "peers converge on the same registers");
    let won = &a.view().envelopes[&contested];
    assert!(*won == swell() || *won == pluck(), "winner is one of the writes");
    assert_eq!(a.view().envelopes[&a_only], swell());
    assert_eq!(a.view().envelopes[&b_only], pluck());
    assert_eq!(a.pending_len(), 0);
    assert_eq!(b.pending_len(), 0);
}

/// A later `SetEnvelope` that causally OBSERVES an earlier one supersedes it —
/// last-writer-wins by causal order, never wall-clock.
#[test]
fn envelope_register_lww_by_causal_order() {
    let ka = signing_key_from_seed(&[42u8; 32]);
    let mut a: Store<MusicLang> = Store::new();
    let d = degree12(0);
    a.commit(&ka, TOPIC, 1, MusicOp::SetEnvelope { degree: d, env: swell() });
    a.commit(&ka, TOPIC, 2, MusicOp::SetEnvelope { degree: d, env: pluck() });
    assert_eq!(a.view().envelopes[&d], pluck());
}

/// Removing a degree drops its sounding note but PRESERVES its envelope
/// register — the facet-persistence law.
#[test]
fn removing_a_degree_keeps_its_envelope_facet() {
    let ka = signing_key_from_seed(&[7u8; 32]);
    let mut a: Store<MusicLang> = Store::new();
    let d = degree12(4);
    a.commit(&ka, TOPIC, 1, MusicOp::AddDegree { degree: d });
    a.commit(&ka, TOPIC, 2, MusicOp::SetEnvelope { degree: d, env: pluck() });
    a.commit(&ka, TOPIC, 3, MusicOp::RemoveDegree { degree: d });
    let v = a.view();
    assert!(!v.live.contains(&d), "degree retracted → not sounding");
    assert_eq!(v.envelopes.get(&d), Some(&pluck()), "its register persists");
}

/// The tuning register scopes everything degree-keyed: switching tunings hides
/// other-tuning state; switching back resurrects it — a free property of
/// tuning-scoped keys.
#[test]
fn tuning_switch_scopes_the_view_and_switching_back_resurrects() {
    let ka = signing_key_from_seed(&[5u8; 32]);
    let mut a: Store<MusicLang> = Store::new();
    let d12 = degree12(4);
    a.commit(&ka, TOPIC, 1, MusicOp::AddDegree { degree: d12 });
    a.commit(&ka, TOPIC, 2, MusicOp::SetEnvelope { degree: d12, env: swell() });
    assert!(a.view().live.contains(&d12));

    a.commit(&ka, TOPIC, 3, MusicOp::SetTuning { definition: edo31() });
    let d31 = degree31(20);
    a.commit(&ka, TOPIC, 4, MusicOp::AddDegree { degree: d31 });
    let v = a.view();
    assert_eq!(v.tuning, edo31());
    assert!(!v.live.contains(&d12), "12-TET degree hidden under 31-EDO");
    assert!(v.envelopes.get(&d12).is_none(), "its facet is scoped out too");
    assert!(v.live.contains(&d31));

    a.commit(&ka, TOPIC, 5, MusicOp::SetTuning {
        definition: TuningDefinition::twelve_tet(),
    });
    let v = a.view();
    assert!(v.live.contains(&d12), "switching back resurrects the degree");
    assert_eq!(v.envelopes.get(&d12), Some(&swell()), "and its facet");
    assert!(!v.live.contains(&d31), "the 31-EDO degree is scoped out now");
}

/// With no `SetTuning` in the log the view resolves to built-in 12-TET.
#[test]
fn default_tuning_is_twelve_tet() {
    let store: Store<MusicLang> = Store::new();
    assert_eq!(store.view().tuning, TuningDefinition::twelve_tet());
}

/// Wire bounds are enforced at ingress: an envelope with too many breakpoints
/// never verifies.
#[test]
fn oversized_envelope_is_rejected_at_ingress() {
    let ka = signing_key_from_seed(&[3u8; 32]);
    let too_many = Envelope {
        points: (0..9).map(|i| (10, i as u8)).collect(),
        interp: Interp::Linear,
    };
    let versioned = tutti_core::VersionedOpG::<MusicLang>::current_for_topic(
        MusicOp::SetEnvelope {
            degree: degree12(0),
            env: too_many,
        },
        1,
        TOPIC,
    );
    let (signed, _) = tutti_core::sign_versioned_op(&ka, &tutti_core::LogHead::genesis(), versioned);
    assert!(verify_signed_op_in::<MusicLang>(&signed).is_err());
}
