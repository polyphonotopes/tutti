//! The compaction gate for `MusicLang::retain`: a compacting
//! `WindowedStore<MusicLang>` (bounded window, adversarially-timed `compact()`
//! calls, shuffled arrivals) folds EXACTLY as a full `Store<MusicLang>` over
//! full history, which itself equals the kernel reference oracle — across
//! degree churn (kills, resurrections), superseding envelope generations, and
//! tuning-register flips. If the retention rule dropped anything a future fold
//! could still see, some shuffle here diverges.


use tutti_core::{SignedOp, Store, VerifiedOpG, WindowedStore, signing_key_from_seed, verify_signed_op_in};
use tutti_music::tuning::{TunedDegree, Tuning, TuningDefinition};
use tutti_music::{Envelope, Interp, MusicLang, MusicOp};

const TOPIC: &str = "tutti-music-retain";

fn edo31() -> TuningDefinition {
    let mut scl = String::from("! generated\n31-tone equal temperament\n31\n");
    for step in 1..=31 {
        scl.push_str(&format!("{:.6}\n", f64::from(step) * 1200.0 / 31.0));
    }
    TuningDefinition::new(scl, Some("0\n0\n127\n60\n60\n261.6255653005986\n0\n".to_owned()))
        .expect("valid 31-EDO")
}

fn degree31(pc: u16) -> TunedDegree {
    TunedDegree::new(&edo31().validate("31-EDO").unwrap(), pc).unwrap()
}

fn degree12(pc: u16) -> TunedDegree {
    TunedDegree::new(&Tuning::twelve_tet(), pc).unwrap()
}

fn env(seed: u8) -> Envelope {
    Envelope {
        points: vec![(0, 8 + seed % 100), (200, 127 - seed % 50), (40, 0)],
        interp: if seed % 2 == 0 { Interp::Linear } else { Interp::Exp },
    }
}

fn verify(signed: &SignedOp) -> VerifiedOpG<MusicLang> {
    verify_signed_op_in::<MusicLang>(signed).expect("verifies")
}

/// SplitMix64 — deterministic seeds for the shuffles and compaction points.
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

fn shuffled(ops: &[SignedOp], seed: u64) -> Vec<SignedOp> {
    let mut rng = Rng(seed);
    let mut out: Vec<SignedOp> = ops.to_vec();
    for i in (1..out.len()).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        out.swap(i, j);
    }
    out
}

/// The adversarial history: two authors, cross-author causality (each exchange
/// makes later ops observe the other's), degree add/remove/re-add churn,
/// several superseding envelope generations per degree, and tuning-register
/// flips (31-EDO → 12-TET → 31-EDO) so retention must keep register maxima and
/// out-of-scope keys alike.
fn adversarial_ops() -> Vec<SignedOp> {
    let ka = signing_key_from_seed(&[81u8; 32]);
    let kb = signing_key_from_seed(&[82u8; 32]);
    let mut a: Store<MusicLang> = Store::new();
    let mut b: Store<MusicLang> = Store::new();
    let mut ops: Vec<SignedOp> = Vec::new();
    let mut ts = 0u64;
    let mut tick = move || {
        ts += 1;
        ts
    };

    let exchange = |from: &[SignedOp], into: &mut Store<MusicLang>| {
        for signed in from {
            into.ingest_verified(verify(signed));
        }
    };

    // A establishes the room and a first generation of degrees + facets.
    ops.push(a.commit(&ka, TOPIC, tick(), MusicOp::SetTuning { definition: edo31() }));
    for pc in [0u16, 5, 10, 18] {
        ops.push(a.commit(&ka, TOPIC, tick(), MusicOp::AddDegree { degree: degree31(pc) }));
        ops.push(a.commit(&ka, TOPIC, tick(), MusicOp::SetEnvelope {
            degree: degree31(pc),
            env: env(pc as u8),
        }));
    }
    exchange(&ops, &mut b);

    // B observes all of A: kills one degree, supersedes a facet, adds its own,
    // and flips the room to 12-TET.
    let b_start = ops.len();
    ops.push(b.commit(&kb, TOPIC, tick(), MusicOp::RemoveDegree { degree: degree31(5) }));
    ops.push(b.commit(&kb, TOPIC, tick(), MusicOp::SetEnvelope {
        degree: degree31(0),
        env: env(101),
    }));
    ops.push(b.commit(&kb, TOPIC, tick(), MusicOp::AddDegree { degree: degree31(25) }));
    ops.push(b.commit(&kb, TOPIC, tick(), MusicOp::SetTuning {
        definition: TuningDefinition::twelve_tet(),
    }));
    ops.push(b.commit(&kb, TOPIC, tick(), MusicOp::AddDegree { degree: degree12(4) }));
    exchange(&ops[b_start..], &mut a);

    // A observes all of B: resurrects the killed degree, supersedes facets
    // again, churns a 12-TET degree through add→remove, flips back to 31-EDO.
    let a_start = ops.len();
    ops.push(a.commit(&ka, TOPIC, tick(), MusicOp::AddDegree { degree: degree31(5) }));
    ops.push(a.commit(&ka, TOPIC, tick(), MusicOp::SetEnvelope {
        degree: degree31(0),
        env: env(102),
    }));
    ops.push(a.commit(&ka, TOPIC, tick(), MusicOp::SetEnvelope {
        degree: degree31(10),
        env: env(103),
    }));
    ops.push(a.commit(&ka, TOPIC, tick(), MusicOp::AddDegree { degree: degree12(7) }));
    ops.push(a.commit(&ka, TOPIC, tick(), MusicOp::RemoveDegree { degree: degree12(7) }));
    ops.push(a.commit(&ka, TOPIC, tick(), MusicOp::SetTuning { definition: edo31() }));
    exchange(&ops[a_start..], &mut b);

    // B: a final generation — remove a long-lived degree (its facet persists),
    // one more superseding facet write, one more add.
    let b2_start = ops.len();
    ops.push(b.commit(&kb, TOPIC, tick(), MusicOp::RemoveDegree { degree: degree31(10) }));
    ops.push(b.commit(&kb, TOPIC, tick(), MusicOp::SetEnvelope {
        degree: degree31(18),
        env: env(104),
    }));
    ops.push(b.commit(&kb, TOPIC, tick(), MusicOp::AddDegree { degree: degree31(2) }));
    exchange(&ops[b2_start..], &mut a);

    assert_eq!(a.view(), b.view(), "the producers themselves converge");
    ops
}

fn ingest_full(ops: &[SignedOp]) -> Store<MusicLang> {
    let mut store = Store::new();
    for signed in ops {
        store.ingest_verified(verify(signed));
    }
    store
}

/// The gate: for several arrival shuffles and adversarially-seeded compaction
/// points, a bounded compacting window folds identically to the full store at
/// EVERY step, and the full store equals the kernel oracle at the end.
#[test]
fn compacting_window_folds_identically_to_full_history() {
    let ops = adversarial_ops();
    let reference = ingest_full(&ops).view();

    let mut discarded_somewhere = false;
    for seed in [1u64, 7, 42, 1337] {
        let arrival = shuffled(&ops, seed);
        let mut rng = Rng(seed ^ 0xC0FFEE);
        let mut full: Store<MusicLang> = Store::new();
        let mut windowed: WindowedStore<MusicLang> = WindowedStore::with_window(8);

        for (i, signed) in arrival.iter().enumerate() {
            full.ingest_verified(verify(signed));
            windowed.ingest_verified(verify(signed));
            if rng.next() % 3 == 0 {
                windowed.compact();
            }
            assert_eq!(
                windowed.view(),
                full.view(),
                "seed {seed}: windowed view diverged from full after ingest {i}"
            );
        }
        windowed.compact();
        assert_eq!(windowed.view(), full.view(), "seed {seed}: final views differ");
        assert_eq!(full.view(), full.view_reference(), "seed {seed}: lazy != oracle");
        assert_eq!(full.view(), reference, "seed {seed}: diverged from reference");
        assert_eq!(windowed.pending_len(), 0, "seed {seed}: ops parked");
        discarded_somewhere |= windowed.total_discarded() > 0;
    }
    assert!(
        discarded_somewhere,
        "the suite never exercised a real discard — raise the churn or lower the cap"
    );
}

/// Retention keeps EXACTLY the fold-relevant residue: after compacting a fully
/// quiescent store, superseded envelope generations and killed adds are gone,
/// while surviving adds, remove maxima, facet winners, and the tuning winner
/// remain — and the view is unchanged.
#[test]
fn compaction_discards_superseded_history_but_preserves_the_view() {
    let ops = adversarial_ops();
    let full = ingest_full(&ops);

    let mut windowed: WindowedStore<MusicLang> = WindowedStore::with_window(6);
    for signed in &ops {
        windowed.ingest_verified(verify(signed));
    }
    let compaction = windowed.compact();
    assert_eq!(windowed.view(), full.view());
    assert!(
        windowed.total_discarded() > 0 || compaction.retained < ops.len(),
        "quiescent compaction at cap 6 over {} ops must shed history",
        ops.len()
    );

    // Late arrival AFTER compaction: an op concurrent with discarded history
    // (a fresh author's add of a degree that was removed) still folds right.
    let kc = signing_key_from_seed(&[83u8; 32]);
    let mut c: Store<MusicLang> = Store::new();
    let late = c.commit(&kc, TOPIC, 999, MusicOp::AddDegree { degree: degree31(10) });
    let mut full2 = ingest_full(&ops);
    full2.ingest_verified(verify(&late));
    windowed.ingest_verified(verify(&late));
    assert_eq!(
        windowed.view(),
        full2.view(),
        "a post-compaction late add (concurrent with a discarded remove) diverged"
    );
    assert!(
        windowed.view().live.contains(&degree31(10)),
        "the concurrent add survives the earlier remove (add-wins)"
    );
}
