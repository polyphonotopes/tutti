//! Desktop-AMY tutti leaf — the audible render (experiment 1 of
//! `docs/research/tutti-amy-esp32-leaf.md`).
//!
//! Run: `cargo run` inside tutti-amy/ (AMY is compiled by build.rs).
//!
//!   Checkpoint 1: prove Rust ↔ AMY renders non-silent audio (raw oscillator).
//!   Checkpoint 2: run the REAL two-peer partition→rejoin scenario over
//!                 `Store<MusicLang>` and drive AMY from its converging fold —
//!                 the same path the acceptance test asserts.
//!   Checkpoint 3: dump the partition→rejoin render to partition-rejoin.wav so a
//!                 human can hear the union click into place.

use tutti_amy::music::{self, EDO};
use tutti_amy::{block_frames, envelope_to_amy, nchans, rms, sample_rate, write_wav, Amy};

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        0.0
    } else {
        xs.iter().sum::<f64>() / xs.len() as f64
    }
}

fn main() {
    println!("=== tutti-amy: desktop AMY tutti leaf ===");
    println!(
        "AMY geometry: {} frames/block × {} chans @ {} Hz  (one block = {:.2} ms)",
        block_frames(),
        nchans(),
        sample_rate(),
        block_frames() as f64 * 1000.0 / sample_rate() as f64,
    );

    let amy = Amy::start();
    println!("amy_start() OK. sysclock = {} ms", amy.sysclock());

    // ------------------------------------------------------------------
    // Checkpoint 1 — raw render proof: note-on → non-silent; note-off → decay.
    // ------------------------------------------------------------------
    println!("\n--- Checkpoint 1: Rust ↔ AMY render proof ---");
    let mut baseline = Vec::new();
    for _ in 0..2 {
        baseline.push(rms(&amy.render_block()));
    }
    amy.send("v0n60l1"); // osc 0, middle C, velocity 1
    let mut on = Vec::new();
    for _ in 0..10 {
        let block = amy.render_block();
        on.push(rms(&block));
    }
    amy.send("v0l0"); // note off
    let mut off = Vec::new();
    for _ in 0..10 {
        off.push(rms(&amy.render_block()));
    }
    let (b, o, tail) = (mean(&baseline), mean(&on), mean(&off[off.len() - 3..]));
    let on_peak = on.iter().cloned().fold(0.0_f64, f64::max);
    assert!(on_peak > 0.0, "silent after note-on");
    assert!(o > b + 0.01, "rms did not rise after note-on");
    assert!(tail < o, "rms did not decay after note-off");
    println!(
        "PASS: rms {b:.4} → {o:.4} on note-on (peak {on_peak:.4}), decayed to {tail:.4} on note-off."
    );
    // Let the tail ring out before the scenario so it doesn't smear step 0.
    for _ in 0..12 {
        let _ = amy.render_block();
    }

    // ------------------------------------------------------------------
    // Checkpoint 2 — the REAL partition→rejoin scenario drives AMY.
    // ------------------------------------------------------------------
    println!("\n--- Checkpoint 2: two Store<MusicLang> peers, partition → rejoin ---");
    let s = music::run_scenario();
    println!("  partition:  A.view={:?}   B.view={:?}", s.a_partition, s.b_partition);
    assert_ne!(s.a_partition, s.b_partition, "partition views must differ");
    println!(
        "  rejoin:     A.view={:?}  ==  B.view={:?}",
        s.a_converged, s.b_converged
    );
    assert_eq!(s.a_converged, s.b_converged, "peers must converge");
    assert_eq!(s.a_converged, s.expected_union, "must equal the union");
    println!(
        "  converged to the union {:?} (degree {} removed — the remove wins).",
        s.expected_union, s.removed_degree
    );

    println!("\n  driving AMY from the converging fold (EDO={EDO}):");
    let tuning = music::room_tuning();
    let report = music::drive_amy(&amy, &s.timeline, &tuning, 24, 40);
    for (i, degrees) in s.timeline.iter().enumerate() {
        println!(
            "    step {i}: view={:<20} rms={:.4}",
            format!("{degrees:?}"),
            report.step_rms[i]
        );
    }
    println!("    teardown rms = {:.4}", report.teardown_rms);
    println!("    wire events: {:?}", report.events);

    let union_rms = report.step_rms[s.timeline.len() - 1];
    assert!(union_rms > report.step_rms[2], "union must be louder than the 2-note partition chord");
    assert_eq!(report.note_ons, report.note_offs, "balanced note on/off");
    assert!(report.stuck_oscs.is_empty(), "no stuck notes");
    assert!(report.teardown_rms < union_rms * 0.2, "silent after release");
    println!(
        "  PASS: union ({union_rms:.4}) louder than partition; {} on / {} off balanced; silent tail ({:.4}) — NO STUCK NOTES.",
        report.note_ons, report.note_offs, report.teardown_rms
    );

    // A peek at the microtonal payoff: fractional MIDI notes for a 31-EDO room.
    let fractional: Vec<&String> = report
        .events
        .iter()
        .filter(|e| e.contains('n') && e.contains('.'))
        .collect();
    println!("  microtonal (31-EDO) note-ons carry fractional MIDI notes: {fractional:?}");

    // ------------------------------------------------------------------
    // Checkpoint 3 — write the partition→rejoin WAV.
    // ------------------------------------------------------------------
    let wav = concat!(env!("CARGO_MANIFEST_DIR"), "/partition-rejoin.wav");
    match write_wav(wav, &report.pcm, sample_rate() as u32, nchans() as u16) {
        Ok(()) => println!(
            "\n--- Checkpoint 3: wrote {wav} ({} frames, {:.2} s) ---",
            report.pcm.len() / nchans(),
            (report.pcm.len() / nchans()) as f64 / sample_rate() as f64
        ),
        Err(err) => eprintln!("could not write WAV: {err}"),
    }

    // ------------------------------------------------------------------
    // Checkpoint 4 — a CONTINUOUS FACET converges and shapes synthesis.
    //   Two peers concurrently SetEnvelope on the SAME degree (a slow swell vs a
    //   fast pluck), exchange signed ops, and converge to the causal-maxima winner.
    //   The converged CURVE (not samples — the function) drives AMY's amplitude EG,
    //   and the RMS trajectory reflects it: the swell rises, the pluck falls.
    // ------------------------------------------------------------------
    println!("\n--- Checkpoint 4: a converging envelope FACET shapes AMY synthesis ---");
    let es = music::run_envelope_scenario();
    println!(
        "  peers concurrently SetEnvelope on degree {}:\n    A = {}  (swell)\n    B = {}  (pluck)",
        es.pc_contested,
        envelope_to_amy(&es.env_a),
        envelope_to_amy(&es.env_b),
    );
    assert_eq!(es.a_converged, es.b_converged, "envelope facets must converge");
    assert_eq!(es.a_pending, 0);
    assert_eq!(es.b_pending, 0);
    println!(
        "  converged: envelope[{}] = {} (causal-maxima winner); disjoint regs 10 & 18 both kept.",
        es.pc_contested,
        envelope_to_amy(&es.winner),
    );

    // Render the two curves and show the RMS trajectory each produces.
    const HELD: usize = 70;
    const TAIL: usize = 30;
    let (_, swell_rms) = music::render_held_with_envelope(&amy, es.pc_contested, &music::swell(), &tuning, HELD, TAIL);
    let (_, pluck_rms) = music::render_held_with_envelope(&amy, es.pc_contested, &music::pluck(), &tuning, HELD, TAIL);
    let (swell_slope, pluck_slope) = (music::rms_slope(&swell_rms), music::rms_slope(&pluck_rms));
    let early = |r: &[f64]| mean(&r[2..8]);
    let late = |r: &[f64]| mean(&r[r.len() - 8..]);
    println!(
        "    swell: rms {:.4} -> {:.4}  slope {swell_slope:+.6}/block (rises)",
        early(&swell_rms), late(&swell_rms)
    );
    println!(
        "    pluck: rms {:.4} -> {:.4}  slope {pluck_slope:+.6}/block (falls)",
        early(&pluck_rms), late(&pluck_rms)
    );
    assert!(swell_slope > 0.0 && pluck_slope < 0.0, "swell rises, pluck falls");
    assert!(pluck_slope < swell_slope, "the pluck decays faster than the swell swells");
    println!("  PASS: the converged breakpoints actually shaped the loudness contour.");

    // Write envelope-converge.wav: the loser's curve, then the converged winner's —
    // a facet edit converging, the curve audibly changing.
    let mut env_wav: Vec<i16> = Vec::new();
    for _ in 0..8 {
        env_wav.extend_from_slice(&amy.render_block());
    }
    let (loser_pcm, _) = music::render_held_with_envelope(&amy, es.pc_contested, &es.loser, &tuning, HELD, TAIL);
    env_wav.extend_from_slice(&loser_pcm);
    for _ in 0..16 {
        env_wav.extend_from_slice(&amy.render_block());
    }
    let (winner_pcm, _) = music::render_held_with_envelope(&amy, es.pc_contested, &es.winner, &tuning, HELD, TAIL);
    env_wav.extend_from_slice(&winner_pcm);
    let env_path = concat!(env!("CARGO_MANIFEST_DIR"), "/envelope-converge.wav");
    match write_wav(env_path, &env_wav, sample_rate() as u32, nchans() as u16) {
        Ok(()) => println!(
            "  wrote {env_path} ({} frames, {:.2} s): loser curve, then converged winner.",
            env_wav.len() / nchans(),
            (env_wav.len() / nchans()) as f64 / sample_rate() as f64
        ),
        Err(err) => eprintln!("could not write envelope WAV: {err}"),
    }

    println!("\nfinal sysclock = {} ms. all checkpoints passed.", amy.sysclock());
    drop(amy); // amy_stop()
}
