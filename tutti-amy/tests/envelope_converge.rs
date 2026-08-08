//! THE GATE for the continuous-envelope facet (docs/research/tutti-amy-esp32-leaf.md
//! §4): **convergence of a continuous *function* drives audio.** This is the
//! INTERPOLATION-axis analogue of `partition_rejoin.rs` — where that test proves a
//! converging *pitch-set* sounds, this proves a converging per-degree *envelope
//! register* shapes synthesis, verifiably and identically on every peer.
//!
//! One `#[test]` in its own integration binary because AMY is a global singleton
//! (`Amy::start` panics if one is already live); this binary starts/stops fresh
//! engines in sequence so "equal op-sets ⇒ identical audio" is a real cross-peer
//! claim (each `amy_start` re-inits the clock + oscillators, api.c:529-547).
//!
//! It asserts three things and writes one wav:
//!   1. PURE CONVERGENCE — two peers concurrently `SetEnvelope` on the same degree
//!      (+ disjoint degrees), exchange signed ops, and converge to the identical
//!      `BTreeMap<pc,Envelope>` (causal-maxima winner), order-independently
//!      (`view()==view_reference()`), nothing parked.
//!   2. AUDIO REFLECTS THE CONVERGED CURVE — a fast-decay envelope (A) renders a
//!      falling RMS trajectory, a slow-swell (B) a rising one; A decays faster than
//!      B (per-block RMS slope). After the concurrent edit converges to the winner,
//!      the audio matches the WINNER's shape, not the loser's.
//!   3. DETERMINISM — the same op-set ingested in two arrival orders yields the same
//!      view ⇒ byte-identical AMY wire stream ⇒ byte-identical PCM on both peers.
//!   + writes `envelope-converge.wav`: the loser's curve, then the converged winner's
//!     — an audible change driven purely by a converging facet.

use std::collections::BTreeSet;

use tutti_amy::music::{self, MusicView};
use tutti_amy::{Amy, degrees_to_amy_events, envelope_to_amy, nchans, sample_rate, write_wav};

const HELD_BLOCKS: usize = 70; // ~406 ms — long enough to see a 350 ms swell fully
const TAIL_BLOCKS: usize = 30; // ~174 ms release tail → silence before the next hit

/// Render one held degree under `env` on a FRESH AMY engine (start→render→stop), so
/// two peers' renders are independent and any equality is a real determinism claim.
fn render_fresh(pc: u16, env: &tutti_amy::Envelope) -> (Vec<i16>, Vec<f64>) {
    let amy = Amy::start();
    let out = music::render_held_with_envelope(&amy, pc, env, &music::room_tuning(), HELD_BLOCKS, TAIL_BLOCKS);
    drop(amy);
    out
}

/// Render a whole converged `MusicView` as a held chord (each live degree carrying
/// its converged envelope) + release, on a fresh engine. The determinism oracle.
fn render_view_chord(view: &MusicView) -> Vec<i16> {
    let amy = Amy::start();
    let tuning = music::room_tuning();
    let before = BTreeSet::new();
    let after = view.live.clone();
    let mut pcm = Vec::new();
    for ev in degrees_to_amy_events(&before, &after, &view.envelopes, &tuning, music::MAX_OSCS) {
        amy.send(&ev);
    }
    for _ in 0..HELD_BLOCKS {
        pcm.extend_from_slice(&amy.render_block());
    }
    for ev in degrees_to_amy_events(&after, &before, &view.envelopes, &tuning, music::MAX_OSCS) {
        amy.send(&ev);
    }
    for _ in 0..TAIL_BLOCKS {
        pcm.extend_from_slice(&amy.render_block());
    }
    drop(amy);
    pcm
}

fn window_mean(xs: &[f64], lo: usize, hi: usize) -> f64 {
    let hi = hi.min(xs.len());
    if hi <= lo {
        return 0.0;
    }
    xs[lo..hi].iter().sum::<f64>() / (hi - lo) as f64
}

#[test]
fn envelope_convergence_drives_and_shapes_audio() {
    // ------------------------------------------------------------------
    // Part 1 — PURE CONVERGENCE (two real Store<MusicLang> peers, no AMY).
    // ------------------------------------------------------------------
    let s = music::run_envelope_scenario();

    println!("=== envelope-facet convergence (pc {} contested) ===", s.pc_contested);
    println!("  A.env[{}] concurrent = {:?}", s.pc_contested, s.env_a);
    println!("  B.env[{}] concurrent = {:?}", s.pc_contested, s.env_b);

    assert_eq!(
        s.a_converged, s.b_converged,
        "peers MUST converge on the identical (live-set, envelope-registers)"
    );
    let won = &s.a_converged.envelopes[&music::degree(s.pc_contested)];
    assert!(*won == s.env_a || *won == s.env_b, "winner is one of the two");
    assert_eq!(*won, s.winner);
    assert_ne!(s.winner, s.loser, "winner and loser must differ (a real tie)");
    assert_eq!(s.a_converged.envelopes[&music::degree(s.pc_a_only)], s.env_a, "A's disjoint reg kept");
    assert_eq!(s.a_converged.envelopes[&music::degree(s.pc_b_only)], s.env_b, "B's disjoint reg kept");
    assert_eq!(s.a_pending, 0, "liveness: nothing parked in A");
    assert_eq!(s.b_pending, 0, "liveness: nothing parked in B");

    // Order-independence + kernel oracle: ingest the op-set in several arrival orders
    // into fresh stores; every one lands on the same view AND equals view_reference().
    let ops = music::envelope_op_set();
    let mut reference: Option<MusicView> = None;
    for rot in [0usize, 1, 3, 5, 7] {
        let mut store = music::new_store();
        let n = ops.len();
        for i in 0..n {
            store.ingest_verified(music::verify_signed(&ops[(i + rot) % n]));
        }
        assert_eq!(store.pending_len(), 0, "rot {rot} left ops parked");
        assert_eq!(store.view(), store.view_reference(), "rot {rot}: lazy != oracle");
        match &reference {
            None => reference = Some(store.view()),
            Some(r) => assert_eq!(&store.view(), r, "rot {rot} diverged"),
        }
    }
    let reference = reference.unwrap();
    assert_eq!(reference, s.a_converged, "op-set fold == scenario converged view");
    println!(
        "  PASS convergence: winner={:?}  (order-independent, view==view_reference, pending=0)",
        s.winner
    );

    // ------------------------------------------------------------------
    // Part 2 — AUDIO REFLECTS THE CONVERGED CURVE.
    // ------------------------------------------------------------------
    // Wire the two curves onto EG0 and read what AMY actually parses.
    println!("=== audio: the curves as AMY EG0 wire fragments ===");
    println!("  swell -> {}", envelope_to_amy(&music::swell()));
    println!("  pluck -> {}", envelope_to_amy(&music::pluck()));

    // A = fast-decay pluck, B = slow-swell. (Named A/B per the gate wording.)
    let env_a = music::pluck();
    let env_b = music::swell();
    let (_pcm_a, rms_a) = render_fresh(s.pc_contested, &env_a);
    let (_pcm_b, rms_b) = render_fresh(s.pc_contested, &env_b);

    let (a_early, a_late) = (window_mean(&rms_a, 2, 8), window_mean(&rms_a, HELD_BLOCKS - 8, HELD_BLOCKS));
    let (b_early, b_late) = (window_mean(&rms_b, 2, 8), window_mean(&rms_b, HELD_BLOCKS - 8, HELD_BLOCKS));
    let (slope_a, slope_b) = (music::rms_slope(&rms_a), music::rms_slope(&rms_b));
    println!(
        "  A (fast-decay): early {a_early:.4} -> late {a_late:.4}  slope {slope_a:+.6}/block"
    );
    println!(
        "  B (slow-swell): early {b_early:.4} -> late {b_late:.4}  slope {slope_b:+.6}/block"
    );

    assert!(a_early > 0.01, "A must be audible on note-on (rms {a_early:.4})");
    assert!(b_late > 0.01, "B must be audible once swelled (rms {b_late:.4})");
    // A DECAYS: it ends quieter than it started; B SWELLS: it ends louder.
    assert!(a_late < a_early, "A (fast-decay) must fall: {a_late:.4} < {a_early:.4}");
    assert!(b_late > b_early, "B (slow-swell) must rise: {b_late:.4} > {b_early:.4}");
    assert!(slope_a < 0.0, "A's RMS slope must be negative (decaying): {slope_a:+.6}");
    assert!(slope_b > 0.0, "B's RMS slope must be positive (swelling): {slope_b:+.6}");
    // THE gate line: A decays faster than B.
    assert!(
        slope_a < slope_b,
        "A must decay faster than B: slope_A {slope_a:+.6} < slope_B {slope_b:+.6}"
    );
    println!("  PASS trajectory: A decays (slope {slope_a:+.6}) faster than B swells (slope {slope_b:+.6}).");

    // After the concurrent edit CONVERGED to the winner, the audio matches the
    // WINNER's shape, not the loser's. Render the converged winner and both
    // reference curves; assert winner-audio == render(winner env), != render(loser).
    let (pcm_winner, rms_winner) = render_fresh(s.pc_contested, &s.winner);
    let (pcm_win_ref, _) = render_fresh(s.pc_contested, &s.winner);
    let (pcm_loser_ref, _) = render_fresh(s.pc_contested, &s.loser);
    assert_eq!(
        pcm_winner, pcm_win_ref,
        "rendering the converged winner twice must be byte-identical (determinism)"
    );
    assert_ne!(
        pcm_winner, pcm_loser_ref,
        "the converged audio must NOT match the loser's curve"
    );
    // The winner's wire == the winner-envelope's wire, and != the loser's wire.
    assert_eq!(
        music::envelope_note_on_wire(s.pc_contested, &s.winner, &music::room_tuning()),
        music::envelope_note_on_wire(s.pc_contested, won, &music::room_tuning()),
    );
    assert_ne!(
        music::envelope_note_on_wire(s.pc_contested, &s.winner, &music::room_tuning()),
        music::envelope_note_on_wire(s.pc_contested, &s.loser, &music::room_tuning()),
    );
    let winner_slope = music::rms_slope(&rms_winner);
    let winner_is_swell = s.winner == music::swell();
    if winner_is_swell {
        assert!(winner_slope > 0.0, "winner is the swell → rising trajectory");
    } else {
        assert!(winner_slope < 0.0, "winner is the pluck → falling trajectory");
    }
    println!(
        "  PASS winner-shape: converged audio matches the winner ({}) not the loser; slope {winner_slope:+.6}.",
        if winner_is_swell { "swell" } else { "pluck" }
    );

    // ------------------------------------------------------------------
    // Part 3 — DETERMINISM: equal op-set, two orders ⇒ identical wire ⇒ identical PCM.
    // ------------------------------------------------------------------
    let mut peer1 = music::new_store();
    let mut peer2 = music::new_store();
    let n = ops.len();
    for i in 0..n {
        peer1.ingest_verified(music::verify_signed(&ops[i])); // forward order
        peer2.ingest_verified(music::verify_signed(&ops[n - 1 - i])); // reverse order
    }
    assert_eq!(peer1.view(), peer2.view(), "peers converge to the same view");
    let v1 = peer1.view();
    let v2 = peer2.view();
    // Byte-identical projected wire stream (pure function of the converged view).
    let tuning = music::room_tuning();
    let wire1 = degrees_to_amy_events(&BTreeSet::new(), &v1.live, &v1.envelopes, &tuning, music::MAX_OSCS);
    let wire2 = degrees_to_amy_events(&BTreeSet::new(), &v2.live, &v2.envelopes, &tuning, music::MAX_OSCS);
    assert_eq!(wire1, wire2, "equal views must project a byte-identical wire stream");
    // Byte-identical audio (fresh engines fed the identical view).
    let pcm1 = render_view_chord(&v1);
    let pcm2 = render_view_chord(&v2);
    assert_eq!(pcm1, pcm2, "byte-identical wire ⇒ byte-identical PCM on both peers");
    println!(
        "  PASS determinism: 2 arrival orders → identical view, wire ({} evs), and {} PCM samples.",
        wire1.len(),
        pcm1.len()
    );

    // ------------------------------------------------------------------
    // Part 4 — the wav: the loser's curve, then the converged winner's.
    // ------------------------------------------------------------------
    let amy = Amy::start();
    let mut wav_pcm = Vec::new();
    // Silence lead-in.
    for _ in 0..8 {
        wav_pcm.extend_from_slice(&amy.render_block());
    }
    // The curve BEFORE convergence (the loser), then AFTER (the winner) — audibly different.
    let (loser_pcm, _) = music::render_held_with_envelope(&amy, s.pc_contested, &s.loser, &music::room_tuning(), HELD_BLOCKS, TAIL_BLOCKS);
    wav_pcm.extend_from_slice(&loser_pcm);
    for _ in 0..16 {
        wav_pcm.extend_from_slice(&amy.render_block()); // gap
    }
    let (winner_pcm, _) = music::render_held_with_envelope(&amy, s.pc_contested, &s.winner, &music::room_tuning(), HELD_BLOCKS, TAIL_BLOCKS);
    wav_pcm.extend_from_slice(&winner_pcm);
    drop(amy);

    let wav = concat!(env!("CARGO_MANIFEST_DIR"), "/envelope-converge.wav");
    write_wav(wav, &wav_pcm, sample_rate() as u32, nchans() as u16).expect("wav writes");
    let frames = wav_pcm.len() / nchans();
    println!(
        "  wrote {wav} ({frames} frames, {:.2} s): loser curve then converged winner.",
        frames as f64 / sample_rate() as f64
    );
    println!("ALL ENVELOPE-FACET GATE ASSERTIONS PASSED.");
}
