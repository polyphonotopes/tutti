//! The tutti-amy scenario harness: two REAL `Store<MusicLang>` peers partition,
//! diverge, then exchange signed ops and converge — and the converging fold
//! drives AMY. This proves the leaf thesis: **verifiable eventually-consistent
//! convergence produces audio** (docs/research/tutti-amy-esp32-leaf.md,
//! experiment 1).
//!
//! The music *protocol* (`MusicOp`/`MusicLang`/`MusicView`, the fold, tuning
//! identity, the facet types) lives in `tutti-music`; its convergence suite
//! travels with it. What stays here is the leaf: the concrete 31-EDO room, the
//! partition→rejoin scenarios, the AMY driver, and the no-stuck-notes ledger.
//!
//! Because the room is a non-12 EDO, degrees resolve to FRACTIONAL MIDI notes —
//! the microtonal path AMY takes for free.

use std::collections::{BTreeMap, BTreeSet};

use tutti_core::{SignedOp, Store, VerifiedOpG, signing_key_from_seed, verify_signed_op_in};
use tutti_music::tuning::{TunedDegree, Tuning, TuningDefinition};

pub use tutti_music::{Envelope, Interp, MusicLang, MusicOp, MusicView};

use crate::{Amy, degrees_to_amy_events, rms};

// ===========================================================================
// The room: 31-EDO, anchored so degree 0 sounds middle C.
// ===========================================================================

/// The room's topic — every op is bound to it (contract: topic-scoped authorship).
pub const TOPIC: &str = "tutti-amy-music";

/// The room's tuning: 31 divisions of the octave (display/diagnostics; the
/// authoritative identity is [`room_definition`]'s `TuningId`).
pub const EDO: u16 = 31;

/// AMY oscillator address space bound (well under the desktop default of 250).
pub const MAX_OSCS: u16 = 250;

/// The Scala keyboard mapping anchoring MIDI 60 to C4, so degree 0 = MIDI 60
/// and degree `d` = `60 + 12d/31` — fractional for every non-multiple of 31.
const EDO31_KBM: &str = "0\n0\n127\n60\n60\n261.6255653005986\n0\n";

fn edo31_scl() -> String {
    let mut scl = format!("! generated\n{EDO}-tone equal temperament\n{EDO}\n");
    for step in 1..=EDO {
        scl.push_str(&format!("{:.6}\n", f64::from(step) * 1200.0 / f64::from(EDO)));
    }
    scl
}

/// The canonical room tuning definition — what [`MusicOp::SetTuning`] carries.
pub fn room_definition() -> TuningDefinition {
    TuningDefinition::new(edo31_scl(), Some(EDO31_KBM.to_owned()))
        .expect("the generated 31-EDO definition is valid")
}

/// The validated room tuning.
pub fn room_tuning() -> Tuning {
    room_definition()
        .validate("tutti-amy room")
        .expect("the room definition validates")
}

/// One room degree, by index.
pub fn degree(pc: u16) -> TunedDegree {
    TunedDegree::new(&room_tuning(), pc).expect("degree within 31-EDO")
}

/// The AMY oscillator a room degree is assigned to (mirrors the compiler's
/// pure, stable osc mapping — for assertions about specific oscillators).
pub fn osc_of(pc: u16, max_oscs: u16) -> u16 {
    pc % max_oscs.max(1)
}

/// A view's live set as plain degree indices (for display and assertions).
fn indices(view: &MusicView) -> BTreeSet<u16> {
    view.live.iter().map(|d| d.degree.index()).collect()
}

fn verify(signed: &SignedOp) -> VerifiedOpG<MusicLang> {
    verify_signed_op_in::<MusicLang>(signed).expect("a signed music op verifies")
}

/// Construct a fresh `Store<MusicLang>` — so a bin/test can drive convergence
/// without naming the tutti-core `Store`/`MusicLang` types itself.
pub fn new_store() -> Store<MusicLang> {
    Store::new()
}

/// Verify a signed music op into the ingest-ready `VerifiedOpG<MusicLang>`.
pub fn verify_signed(signed: &SignedOp) -> VerifiedOpG<MusicLang> {
    verify(signed)
}

// ===========================================================================
// The partition → rejoin scenario, driven by TWO real Store<MusicLang> peers.
// ===========================================================================

/// The outcome of running the two-peer partition→rejoin scenario. Pure
/// tutti-core + tutti-music: no AMY, fully testable on its own. Degree sets are
/// reported as plain indices in the 31-EDO room.
pub struct Scenario {
    /// Peer A's view WHILE PARTITIONED (before it saw any of B's ops).
    pub a_partition: BTreeSet<u16>,
    /// Peer B's view WHILE PARTITIONED (before it saw any of A's ops).
    pub b_partition: BTreeSet<u16>,
    /// Peer A's view AFTER rejoin (ingested B's signed ops).
    pub a_converged: BTreeSet<u16>,
    /// Peer B's view AFTER rejoin (ingested A's signed ops).
    pub b_converged: BTreeSet<u16>,
    /// The hand-computed add-wins union oracle — what both peers MUST converge to.
    pub expected_union: BTreeSet<u16>,
    /// The degree B added then retracted; the remove observed the add, so it must
    /// be ABSENT from the union (remove wins ⇒ never sounds after teardown).
    pub removed_degree: u16,
    /// The leaf's REAL fold outputs over the whole partition→rejoin timeline — each
    /// a `store.view()` after a commit or the rejoin. Consecutive diffs drive AMY.
    pub timeline: Vec<BTreeSet<u16>>,
    /// The room tuning used for the audio projection (divisions per octave).
    pub edo: u16,
    /// Ops parked in A / B after rejoin (must be 0 — liveness, nothing stuck).
    pub a_pending: usize,
    pub b_pending: usize,
}

/// Run the two-peer scenario end to end:
///
/// 1. **Partition.** Both peers commit the room's `SetTuning` (the same
///    definition — the register converges either way), then A commits
///    `AddDegree`s for a near-just 31-EDO triad (`{0,10,18}`); B commits its own
///    degrees AND retracts one (`Add 8, Add 25, Add 5, Remove 5`). They do NOT
///    exchange ops — their views diverge. B's `view()` is snapshotted after each
///    degree commit → the real fold timeline the leaf's speaker plays while
///    partitioned.
/// 2. **Rejoin.** Each peer `ingest_verified`s the OTHER's signed ops (the
///    tutti-core convergence path). Both refold to the identical union pitch-set.
///
/// Degree 5 is added then removed inside B's own causal chain, so the remove
/// observes the add and 5 dies; A never touches 5. Under add-wins the union is
/// `{0, 8, 10, 18, 25}` — 5 is gone (remove wins).
pub fn run_scenario() -> Scenario {
    let ka = signing_key_from_seed(&[1u8; 32]);
    let kb = signing_key_from_seed(&[2u8; 32]);
    let mut ts: u64 = 1_700_000_000_000_000; // µs, monotone; NOT used for ordering
    let mut tick = || {
        let t = ts;
        ts += 1;
        t
    };

    let mut a: Store<MusicLang> = Store::new();
    let mut b: Store<MusicLang> = Store::new();
    let definition = room_definition();

    // --- Partition: A sets the tuning, then plays a 31-EDO near-just major
    //     triad (steps 0, 10, 18). ---
    let mut a_ops = vec![a.commit(
        &ka,
        TOPIC,
        tick(),
        MusicOp::SetTuning {
            definition: definition.clone(),
        },
    )];
    for pc in [0, 10, 18] {
        a_ops.push(a.commit(&ka, TOPIC, tick(), MusicOp::AddDegree { degree: degree(pc) }));
    }

    // --- Partition: B, the leaf with a speaker, sets the same tuning, plays 8 &
    //     25 and momentarily 5, then RETRACTS 5. Snapshot B's fold after each
    //     degree commit → the audio timeline.
    let mut timeline: Vec<BTreeSet<u16>> = vec![BTreeSet::new()]; // start silent
    let mut b_ops = vec![b.commit(
        &kb,
        TOPIC,
        tick(),
        MusicOp::SetTuning {
            definition: definition.clone(),
        },
    )];
    for op in [
        MusicOp::AddDegree { degree: degree(8) },
        MusicOp::AddDegree { degree: degree(25) },
        MusicOp::AddDegree { degree: degree(5) },
        MusicOp::RemoveDegree { degree: degree(5) },
    ] {
        b_ops.push(b.commit(&kb, TOPIC, tick(), op));
        timeline.push(indices(&b.view()));
    }

    let a_partition = indices(&a.view());
    let b_partition = indices(&b.view());

    // --- Rejoin: each peer verifies + ingests the other's SIGNED ops in causal
    //     (commit) order. ---
    for signed in &b_ops {
        a.ingest_verified(verify(signed));
    }
    for signed in &a_ops {
        b.ingest_verified(verify(signed));
    }

    // The leaf's post-rejoin fold: the union clicks into place. This last timeline
    // entry is B's converged view — the audio diff from `{8,25}` adds A's degrees.
    timeline.push(indices(&b.view()));

    Scenario {
        a_partition,
        b_partition,
        a_converged: indices(&a.view()),
        b_converged: indices(&b.view()),
        expected_union: BTreeSet::from([0, 8, 10, 18, 25]),
        removed_degree: 5,
        timeline,
        edo: EDO,
        a_pending: a.pending_len(),
        b_pending: b.pending_len(),
    }
}

// ===========================================================================
// The AMY driver + the end-to-end no-stuck-notes ledger.
// ===========================================================================

/// The audio produced by driving AMY along a fold timeline, plus the ledger that
/// proves NO STUCK NOTES: every emitted note-on had a matching note-off.
pub struct AudioReport {
    /// Interleaved-stereo i16 PCM of the whole render (timeline + teardown).
    pub pcm: Vec<i16>,
    /// Mean RMS while each timeline step rang (same length as the driven timeline).
    pub step_rms: Vec<f64>,
    /// Mean RMS during the teardown tail (after release-all). Near-zero ⇒ silence.
    pub teardown_rms: f64,
    /// Every wire event emitted, in order (for inspection / the ledger).
    pub events: Vec<String>,
    /// Total note-on (`l1`) and note-off (`l0`) events.
    pub note_ons: usize,
    pub note_offs: usize,
    /// Oscillators still holding a note-on after teardown — MUST be empty. A
    /// non-empty set is a stuck note.
    pub stuck_oscs: BTreeSet<u16>,
    /// Note-offs that hit an oscillator that was not sounding (should be 0).
    pub unmatched_offs: usize,
}

/// `(osc, is_note_on)` for a wire event: `v8n63.097l1` (on) or `v8l0` (off).
fn parse_event(ev: &str) -> (u16, bool) {
    let rest = ev.strip_prefix('v').expect("event starts with v<osc>");
    let osc_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let osc: u16 = rest[..osc_end].parse().expect("osc index parses");
    (osc, ev.ends_with("l1"))
}

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        0.0
    } else {
        xs.iter().sum::<f64>() / xs.len() as f64
    }
}

/// Drive AMY along `fold_timeline` (a sequence of real `view()` live sets, as
/// degree indices under `tuning`), diffing each consecutive pair through
/// [`degrees_to_amy_events`], then release everything at teardown. Renders
/// `blocks_per_step` blocks per timeline entry and `teardown_blocks` for the
/// release tail, accumulating PCM. Builds the no-stuck-notes ledger straight
/// from the emitted events.
pub fn drive_amy(
    amy: &Amy,
    fold_timeline: &[BTreeSet<u16>],
    tuning: &Tuning,
    blocks_per_step: usize,
    teardown_blocks: usize,
) -> AudioReport {
    let mut pcm: Vec<i16> = Vec::new();
    let mut step_rms: Vec<f64> = Vec::new();
    let mut events: Vec<String> = Vec::new();
    let no_envelopes: BTreeMap<TunedDegree, Envelope> = BTreeMap::new();
    let to_degrees = |pcs: &BTreeSet<u16>| -> BTreeSet<TunedDegree> {
        pcs.iter()
            .map(|&pc| TunedDegree::new(tuning, pc).expect("timeline degree in tuning"))
            .collect()
    };
    let mut prev: BTreeSet<TunedDegree> = BTreeSet::new();

    let render = |n: usize, pcm: &mut Vec<i16>| -> f64 {
        let mut rmss = Vec::with_capacity(n);
        for _ in 0..n {
            let block = amy.render_block();
            rmss.push(rms(&block));
            pcm.extend_from_slice(&block);
        }
        mean(&rmss)
    };

    // Drive each real fold output.
    for degrees in fold_timeline {
        let cur = to_degrees(degrees);
        let evs = degrees_to_amy_events(&prev, &cur, &no_envelopes, tuning, MAX_OSCS);
        for ev in &evs {
            amy.send(ev);
        }
        events.extend(evs);
        step_rms.push(render(blocks_per_step, &mut pcm));
        prev = cur;
    }

    // Teardown: release everything still sounding → silence (the no-stuck-note
    // discipline applied end to end — fail to silence).
    let empty = BTreeSet::new();
    let evs = degrees_to_amy_events(&prev, &empty, &no_envelopes, tuning, MAX_OSCS);
    for ev in &evs {
        amy.send(ev);
    }
    events.extend(evs);
    let teardown_rms = render(teardown_blocks, &mut pcm);

    // The ledger: fold the events into a sounding set. Every note-on adds an osc,
    // every note-off removes one; after teardown the set MUST be empty.
    let mut sounding: BTreeSet<u16> = BTreeSet::new();
    let (mut note_ons, mut note_offs, mut unmatched_offs) = (0usize, 0usize, 0usize);
    for ev in &events {
        let (osc, on) = parse_event(ev);
        if on {
            note_ons += 1;
            sounding.insert(osc);
        } else {
            note_offs += 1;
            if !sounding.remove(&osc) {
                unmatched_offs += 1;
            }
        }
    }

    AudioReport {
        pcm,
        step_rms,
        teardown_rms,
        events,
        note_ons,
        note_offs,
        stuck_oscs: sounding,
        unmatched_offs,
    }
}

// ===========================================================================
// Continuous-envelope facet: demo curves, the two-peer convergence scenario, and
// the render/analysis helpers shared by the bin, the tests, and the wav.
// ===========================================================================

/// A slow SWELL: jump to a whisper, LINEAR-ramp to full over 350 ms, then release.
/// While held, RMS RISES — a pad-like onset. (Last pair is the note-off release.)
pub fn swell() -> Envelope {
    Envelope {
        points: vec![(0, 8), (350, 127), (60, 0)],
        interp: Interp::Linear,
    }
}

/// A fast PLUCK: jump to full, TRUE-EXPONENTIAL-decay to a whisper over 120 ms,
/// then release. While held, RMS FALLS — a plucked/percussive onset.
pub fn pluck() -> Envelope {
    Envelope {
        points: vec![(0, 127), (120, 12), (40, 0)],
        interp: Interp::Exp,
    }
}

/// Outcome of the two-peer **envelope-facet** partition→rejoin scenario. Pure
/// tutti-core + tutti-music; no AMY. Both peers concurrently `SetEnvelope` on
/// the SAME degree (`pc_contested`, different curves) and each on a disjoint
/// degree, then exchange signed ops and converge.
pub struct EnvelopeScenario {
    /// Peer A's converged `MusicView` (live set + envelope registers).
    pub a_converged: MusicView,
    /// Peer B's converged `MusicView`. MUST equal `a_converged`.
    pub b_converged: MusicView,
    /// The degree both peers wrote an envelope on, concurrently (the contested register).
    pub pc_contested: u16,
    /// A degree only A wrote an envelope on.
    pub pc_a_only: u16,
    /// A degree only B wrote an envelope on.
    pub pc_b_only: u16,
    /// A's envelope for the contested degree (a swell).
    pub env_a: Envelope,
    /// B's envelope for the contested degree (a pluck).
    pub env_b: Envelope,
    /// The causal-maxima winner on the contested degree (== `env_a` or `env_b`).
    pub winner: Envelope,
    /// The other one — what the audio must NOT sound like after convergence.
    pub loser: Envelope,
    pub a_pending: usize,
    pub b_pending: usize,
}

/// The degrees used by the envelope scenario / op-set.
const ENV_PC_CONTESTED: u16 = 0;
const ENV_PC_A_ONLY: u16 = 10;
const ENV_PC_B_ONLY: u16 = 18;

fn ka_env() -> tutti_core::SigningKey {
    signing_key_from_seed(&[11u8; 32])
}
fn kb_env() -> tutti_core::SigningKey {
    signing_key_from_seed(&[22u8; 32])
}

/// One peer's envelope-scenario chain: set the room tuning, then add + envelope
/// the contested degree and a disjoint one.
fn envelope_chain(
    store: &mut Store<MusicLang>,
    key: &tutti_core::SigningKey,
    own_pc: u16,
    env: &Envelope,
) -> Vec<SignedOp> {
    let mut ts = 0u64;
    let mut tick = move || {
        ts += 1;
        ts
    };
    vec![
        store.commit(key, TOPIC, tick(), MusicOp::SetTuning { definition: room_definition() }),
        store.commit(key, TOPIC, tick(), MusicOp::AddDegree { degree: degree(ENV_PC_CONTESTED) }),
        store.commit(key, TOPIC, tick(), MusicOp::SetEnvelope {
            degree: degree(ENV_PC_CONTESTED),
            env: env.clone(),
        }),
        store.commit(key, TOPIC, tick(), MusicOp::AddDegree { degree: degree(own_pc) }),
        store.commit(key, TOPIC, tick(), MusicOp::SetEnvelope {
            degree: degree(own_pc),
            env: env.clone(),
        }),
    ]
}

/// Run the two-peer envelope-facet scenario: A and B each build an independent
/// causal chain (so their contested-degree writes are genuinely CONCURRENT), then
/// each `ingest_verified`s the other's signed ops and refolds. Returns both
/// converged views + the resolved winner.
pub fn run_envelope_scenario() -> EnvelopeScenario {
    let (ka, kb) = (ka_env(), kb_env());
    let mut a: Store<MusicLang> = Store::new();
    let mut b: Store<MusicLang> = Store::new();
    let (env_a, env_b) = (swell(), pluck());

    let a_ops = envelope_chain(&mut a, &ka, ENV_PC_A_ONLY, &env_a);
    let b_ops = envelope_chain(&mut b, &kb, ENV_PC_B_ONLY, &env_b);

    // Rejoin: exchange signed ops.
    for signed in &b_ops {
        a.ingest_verified(verify(signed));
    }
    for signed in &a_ops {
        b.ingest_verified(verify(signed));
    }

    let a_converged = a.view();
    let b_converged = b.view();
    let winner = a_converged.envelopes[&degree(ENV_PC_CONTESTED)].clone();
    let loser = if winner == env_a { env_b.clone() } else { env_a.clone() };

    EnvelopeScenario {
        a_converged,
        b_converged,
        pc_contested: ENV_PC_CONTESTED,
        pc_a_only: ENV_PC_A_ONLY,
        pc_b_only: ENV_PC_B_ONLY,
        env_a,
        env_b,
        winner,
        loser,
        a_pending: a.pending_len(),
        b_pending: b.pending_len(),
    }
}

/// The raw signed op-set behind [`run_envelope_scenario`] (A's chain then B's) —
/// two mutually-concurrent chains — for order-independence / determinism tests
/// that ingest it in many arrival orders into fresh stores.
pub fn envelope_op_set() -> Vec<SignedOp> {
    let (ka, kb) = (ka_env(), kb_env());
    let mut a: Store<MusicLang> = Store::new();
    let mut b: Store<MusicLang> = Store::new();
    let mut ops = envelope_chain(&mut a, &ka, ENV_PC_A_ONLY, &swell());
    ops.extend(envelope_chain(&mut b, &kb, ENV_PC_B_ONLY, &pluck()));
    ops
}

/// Play a single held degree `pc` under envelope facet `env` and capture it:
/// project the envelope-carrying note-on via [`degrees_to_amy_events`], render
/// `held_blocks` (returning per-block RMS — the audible trajectory of the curve),
/// then note-off and render `tail_blocks` of release so the oscillator returns to
/// silence before the next call. Returns the full PCM (held + tail) and the
/// held-phase per-block RMS.
pub fn render_held_with_envelope(
    amy: &Amy,
    pc: u16,
    env: &Envelope,
    tuning: &Tuning,
    held_blocks: usize,
    tail_blocks: usize,
) -> (Vec<i16>, Vec<f64>) {
    let d = TunedDegree::new(tuning, pc).expect("degree within the tuning");
    let mut envs = BTreeMap::new();
    envs.insert(d, env.clone());
    let before = BTreeSet::new();
    let after = BTreeSet::from([d]);

    let mut pcm = Vec::new();
    for ev in degrees_to_amy_events(&before, &after, &envs, tuning, MAX_OSCS) {
        amy.send(&ev);
    }
    let mut held_rms = Vec::with_capacity(held_blocks);
    for _ in 0..held_blocks {
        let block = amy.render_block();
        held_rms.push(rms(&block));
        pcm.extend_from_slice(&block);
    }
    for ev in degrees_to_amy_events(&after, &before, &envs, tuning, MAX_OSCS) {
        amy.send(&ev);
    }
    for _ in 0..tail_blocks {
        pcm.extend_from_slice(&amy.render_block());
    }
    (pcm, held_rms)
}

/// The wire events a held-degree note-on emits under `env` — the byte stream the
/// determinism gate compares across peers. (Just the note-on; the note-off is a
/// facet-independent `vNl0`.)
pub fn envelope_note_on_wire(pc: u16, env: &Envelope, tuning: &Tuning) -> Vec<String> {
    let d = TunedDegree::new(tuning, pc).expect("degree within the tuning");
    let mut envs = BTreeMap::new();
    envs.insert(d, env.clone());
    degrees_to_amy_events(&BTreeSet::new(), &BTreeSet::from([d]), &envs, tuning, MAX_OSCS)
}

/// Least-squares slope of a per-block RMS series vs. block index (RMS units per
/// block). Negative ⇒ the amplitude curve is decaying; positive ⇒ swelling. This
/// is the "measure per-block RMS slope" the gate calls for.
pub fn rms_slope(rmss: &[f64]) -> f64 {
    let n = rmss.len();
    if n < 2 {
        return 0.0;
    }
    let mean_x = (n as f64 - 1.0) / 2.0;
    let mean_y = rmss.iter().sum::<f64>() / n as f64;
    let (mut num, mut den) = (0.0, 0.0);
    for (i, &y) in rmss.iter().enumerate() {
        let dx = i as f64 - mean_x;
        num += dx * (y - mean_y);
        den += dx * dx;
    }
    if den == 0.0 { 0.0 } else { num / den }
}
