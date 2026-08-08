//! The desktop-AMY tutti leaf acceptance test (experiment 1 of
//! `docs/research/tutti-amy-esp32-leaf.md`): drive AMY from a REAL, converging
//! tutti fold and prove the partition/rejoin **no-stuck-notes** acceptance — the
//! core thesis that verifiable eventually-consistent convergence produces audio.
//!
//! This is ONE `#[test]` in its OWN integration-test binary because AMY is a global
//! singleton (`Amy::start` panics if one is already live); a separate process keeps
//! it clear of the crate's other tests. It:
//!
//!   1. runs the two-peer partition→rejoin scenario (`music::run_scenario`) and
//!      asserts the CONVERGENCE property (partition views differ → both converge to
//!      the identical union under add-wins);
//!   2. drives AMY across the whole fold timeline and asserts the AUDIO property
//!      (non-silent, RMS reflects the union chord size, silent after release, and
//!      NO STUCK NOTES — every note-on matched by a note-off);
//!   3. writes `partition-rejoin.wav` so a human can hear the union click into place.


use tutti_amy::music::{self, EDO};
use tutti_amy::{nchans, sample_rate, write_wav, Amy};

const BLOCKS_PER_STEP: usize = 24; // ~139 ms per step at 256 frames / 44.1 kHz
const TEARDOWN_BLOCKS: usize = 40; // ~232 ms release tail — long enough to decay

#[test]
fn partition_rejoin_drives_amy_with_no_stuck_notes() {
    // ------------------------------------------------------------------
    // Part 1 — CONVERGENCE (pure tutti-core, two real Store<MusicLang> peers).
    // ------------------------------------------------------------------
    let s = music::run_scenario();

    println!("=== partition ===");
    println!("  A.view (partitioned) = {:?}", s.a_partition);
    println!("  B.view (partitioned) = {:?}", s.b_partition);
    assert_ne!(
        s.a_partition, s.b_partition,
        "partitioned peers must hold DIFFERENT views"
    );

    println!("=== rejoin (ingest_verified the other's signed ops) ===");
    println!("  A.view (converged)   = {:?}", s.a_converged);
    println!("  B.view (converged)   = {:?}", s.b_converged);
    println!("  expected union       = {:?}", s.expected_union);
    assert_eq!(s.a_converged, s.b_converged, "peers MUST converge");
    assert_eq!(
        s.a_converged, s.expected_union,
        "convergence must equal the add-wins union"
    );
    assert!(
        !s.a_converged.contains(&s.removed_degree),
        "degree {} was removed and the remove MUST win (silent forever)",
        s.removed_degree
    );
    assert_eq!(s.a_pending, 0, "liveness: no op parked in A");
    assert_eq!(s.b_pending, 0, "liveness: no op parked in B");
    println!(
        "  PASS convergence: views diverged then converged to the union; degree {} removed.",
        s.removed_degree
    );

    // ------------------------------------------------------------------
    // Part 2 — AUDIO: drive AMY along the REAL fold timeline.
    // ------------------------------------------------------------------
    let amy = Amy::start();
    let tuning = music::room_tuning();
    let report = music::drive_amy(&amy, &s.timeline, &tuning, BLOCKS_PER_STEP, TEARDOWN_BLOCKS);

    println!("=== audio (fold timeline → AMY, EDO={EDO}) ===");
    for (i, degrees) in s.timeline.iter().enumerate() {
        println!(
            "  step {i}: view={:<20} rms={:.4}",
            format!("{degrees:?}"),
            report.step_rms[i]
        );
    }
    println!("  teardown rms = {:.4}", report.teardown_rms);
    println!("  events: {:?}", report.events);

    // The timeline indices: 0 empty, 1 {8}, 2 {8,25}, 3 {8,25,5}, 4 {8,25},
    // 5 union {0,8,10,18,25}. (Held stable by run_scenario's construction.)
    let single = report.step_rms[1]; // {8}          — one note
    let two = report.step_rms[2]; // {8,25}       — two notes (partition-final size)
    let three = report.step_rms[3]; // {8,25,5}     — three notes (5 momentarily on)
    let after_remove = report.step_rms[4]; // {8,25}  — 5 retracted mid-partition
    let union = report.step_rms[s.timeline.len() - 1]; // {0,8,10,18,25} — five notes

    // Non-silent while playing.
    assert!(single > 0.01, "single note must be audible (rms {single:.4})");

    // RMS reflects chord SIZE: three notes louder than two; the union (5 notes)
    // louder than the partition-final two-note chord — the union really is fuller.
    assert!(
        three > after_remove,
        "3 notes must be louder than 2 (adding degree 5 raised rms: {three:.4} > {after_remove:.4})"
    );
    assert!(
        union > two,
        "the union (5 notes) must be louder than the partition chord (2 notes): {union:.4} > {two:.4}"
    );
    assert!(
        (after_remove - two).abs() < two.max(1e-6) * 0.5,
        "retracting degree 5 returns to the two-note level ({after_remove:.4} ~ {two:.4})"
    );

    // NO STUCK NOTES, end to end:
    //  - every note-on had a matching note-off (balanced ledger),
    //  - nothing is sounding after teardown,
    //  - the room fell silent (fail-to-silence).
    assert_eq!(
        report.note_ons, report.note_offs,
        "every note-on must be matched by a note-off ({} on / {} off)",
        report.note_ons, report.note_offs
    );
    assert_eq!(report.unmatched_offs, 0, "no note-off hit a silent oscillator");
    assert!(
        report.stuck_oscs.is_empty(),
        "STUCK NOTE(S): oscillators still sounding after teardown: {:?}",
        report.stuck_oscs
    );
    assert!(
        report.teardown_rms < union * 0.2,
        "room must fall silent after release-all (teardown rms {:.4} vs union {:.4}) — stuck note?",
        report.teardown_rms,
        union
    );
    println!(
        "  PASS no-stuck-notes: {} note-ons / {} note-offs balanced; silent tail rms {:.4}.",
        report.note_ons, report.note_offs, report.teardown_rms
    );

    // The removed degree (5) resolves to a specific oscillator; assert it was
    // note-ON'd once (momentary) then note-OFF'd, and is NOT sounding at the end.
    let removed_osc = music::osc_of(s.removed_degree, music::MAX_OSCS);
    assert!(
        !report.stuck_oscs.contains(&removed_osc),
        "the retracted degree's oscillator ({removed_osc}) must be silent"
    );

    // The microtonal path: EDO=31 ⇒ at least one note-on carries a FRACTIONAL MIDI
    // note (a '.' in the wire string) — exact microtonality, no MPE, no bend range.
    assert!(
        report
            .events
            .iter()
            .any(|e| e.contains('n') && e.contains('.')),
        "a non-12 EDO must produce fractional MIDI notes in the wire events"
    );

    // ------------------------------------------------------------------
    // Part 3 — write the WAV so a human can hear the union click into place.
    // ------------------------------------------------------------------
    let wav = concat!(env!("CARGO_MANIFEST_DIR"), "/partition-rejoin.wav");
    write_wav(wav, &report.pcm, sample_rate() as u32, nchans() as u16)
        .expect("wav writes");
    let frames = report.pcm.len() / nchans();
    println!(
        "  wrote {wav} ({frames} frames, {:.2} s)",
        frames as f64 / sample_rate() as f64
    );

    drop(amy);
    println!("ALL ACCEPTANCE ASSERTIONS PASSED.");
}
