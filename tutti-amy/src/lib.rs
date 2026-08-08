//! tutti-amy — the AMY render leaf of the tutti stack.
//!
//! Two things live here:
//!
//! 1. A thin, safe Rust wrapper over the AMY C synthesizer (`Amy`): start the
//!    engine, feed it compact ASCII wire events, render audio blocks, read the
//!    sysclock.
//!
//! 2. The **compilers** from `tutti_music` render-surface values to AMY wire
//!    strings: [`degrees_to_amy_events`] (state diff → note-on/off, offs before
//!    ons) and [`envelope_to_amy`] (an [`Envelope`] facet → AMY's amplitude-EG
//!    breakpoint fragment). AMY is a render target; the shared object stays the
//!    pitch-set — "reconciliation upstream, events downstream"
//!    (docs/research/tutti-amy-esp32-leaf.md §3.1).
//!
//! The music *protocol* — `MusicOp`/`MusicLang`, tuning identity, the
//! [`Envelope`]/[`Interp`] facet types — lives in `tutti-music`; this crate
//! only compiles its values for one target.
//!
//! AMY is a global singleton (one `amy_global`), so `Amy::start()` hands out a
//! single guard; construct at most one at a time.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicBool, Ordering};

use tutti_music::render::{PitchSetDiff, fractional_midi};
use tutti_music::tuning::{PeriodicPitch, TunedDegree, Tuning};

/// The op-payload facet types, re-exported from the protocol crate so this
/// crate's callers keep their `tutti_amy::Envelope` spellings.
pub use tutti_music::facets::{Envelope, Interp, MAX_ENV_LEVEL, MAX_ENV_POINTS};

/// The two-peer partition→rejoin scenario + AMY driver over `Store<MusicLang>`
/// (docs/research/tutti-amy-esp32-leaf.md, experiment 1).
pub mod music;

mod ffi {
    use super::{c_char, c_int};
    extern "C" {
        // Our config bridge (csrc/amy_shim.c).
        pub fn ws_amy_start_headless();
        pub fn ws_amy_render_block() -> *mut i16;
        pub fn ws_amy_block_frames() -> c_int;
        pub fn ws_amy_nchans() -> c_int;
        pub fn ws_amy_block_samples() -> c_int;
        pub fn ws_amy_sample_rate() -> c_int;

        // AMY's own clean C-ABI surface, bound directly.
        pub fn amy_add_message(message: *const c_char);
        pub fn amy_sysclock() -> u32;
        pub fn amy_stop();
    }
}

/// Ensures only one live `Amy` guard exists (AMY has one global engine).
static AMY_LIVE: AtomicBool = AtomicBool::new(false);

/// A running AMY engine (headless). Dropping it calls `amy_stop()`.
pub struct Amy {
    _priv: (),
}

impl Amy {
    /// Start AMY headless (no audio device, no MIDI). Panics if one is already
    /// live in this process.
    pub fn start() -> Amy {
        if AMY_LIVE.swap(true, Ordering::SeqCst) {
            panic!("AMY is already running (it is a global singleton)");
        }
        // SAFETY: single-threaded startup, guarded by AMY_LIVE.
        unsafe { ffi::ws_amy_start_headless() };
        Amy { _priv: () }
    }

    /// Feed one compact ASCII wire event (e.g. `"v0n60l1"`). Plays immediately
    /// (no `t` prefix → scheduled "now").
    pub fn send(&self, message: &str) {
        let c = CString::new(message).expect("wire message contained a NUL byte");
        // SAFETY: AMY copies out what it needs during parse; pointer valid for the call.
        unsafe { ffi::amy_add_message(c.as_ptr()) };
    }

    /// Render one block: returns a fresh interleaved-stereo i16 buffer of
    /// [`block_samples`] samples (256 frames × 2 chans = 512 by default).
    pub fn render_block(&self) -> Vec<i16> {
        let n = block_samples();
        // SAFETY: ws_amy_render_block returns AMY's output block, valid until the
        // next render call; we copy it out immediately.
        unsafe {
            let p = ffi::ws_amy_render_block();
            assert!(!p.is_null(), "AMY returned a null output block");
            std::slice::from_raw_parts(p, n).to_vec()
        }
    }

    /// AMY's millisecond clock, derived from total samples rendered.
    pub fn sysclock(&self) -> u32 {
        // SAFETY: trivial read.
        unsafe { ffi::amy_sysclock() }
    }
}

impl Drop for Amy {
    fn drop(&mut self) {
        // SAFETY: matched with start(); engine is live.
        unsafe { ffi::amy_stop() };
        AMY_LIVE.store(false, Ordering::SeqCst);
    }
}

/// Frames per render block (AMY_BLOCK_SIZE, 256 on desktop).
pub fn block_frames() -> usize {
    // SAFETY: pure constant getter.
    unsafe { ffi::ws_amy_block_frames() as usize }
}
/// Interleaved channels (AMY_NCHANS, 2).
pub fn nchans() -> usize {
    unsafe { ffi::ws_amy_nchans() as usize }
}
/// Samples per block = frames × channels (512 by default).
pub fn block_samples() -> usize {
    unsafe { ffi::ws_amy_block_samples() as usize }
}
/// Output sample rate in Hz (AMY_SAMPLE_RATE, 44100 on desktop).
pub fn sample_rate() -> usize {
    unsafe { ffi::ws_amy_sample_rate() as usize }
}

/// Root-mean-square level of a block, normalized to [0,1] against full scale.
pub fn rms(block: &[i16]) -> f64 {
    if block.is_empty() {
        return 0.0;
    }
    let sum_sq: f64 = block.iter().map(|&s| (s as f64).powi(2)).sum();
    (sum_sq / block.len() as f64).sqrt() / i16::MAX as f64
}

/// Peak absolute sample of a block.
pub fn peak(block: &[i16]) -> i16 {
    block.iter().map(|&s| s.saturating_abs()).max().unwrap_or(0)
}

/// Write interleaved i16 samples as a 16-bit PCM WAV (no external crate). Shared by
/// the render-proof bin and the partition→rejoin acceptance test.
pub fn write_wav(
    path: &str,
    samples: &[i16],
    sample_rate: u32,
    channels: u16,
) -> std::io::Result<()> {
    use std::io::Write;

    let bits_per_sample: u16 = 16;
    let byte_rate = sample_rate * channels as u32 * (bits_per_sample as u32 / 8);
    let block_align = channels * (bits_per_sample / 8);
    let data_bytes = (samples.len() * 2) as u32;

    let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
    f.write_all(b"RIFF")?;
    f.write_all(&(36 + data_bytes).to_le_bytes())?;
    f.write_all(b"WAVE")?;
    f.write_all(b"fmt ")?;
    f.write_all(&16u32.to_le_bytes())?; // PCM fmt chunk size
    f.write_all(&1u16.to_le_bytes())?; // audio format = PCM
    f.write_all(&channels.to_le_bytes())?;
    f.write_all(&sample_rate.to_le_bytes())?;
    f.write_all(&byte_rate.to_le_bytes())?;
    f.write_all(&block_align.to_le_bytes())?;
    f.write_all(&bits_per_sample.to_le_bytes())?;
    f.write_all(b"data")?;
    f.write_all(&data_bytes.to_le_bytes())?;
    for &s in samples {
        f.write_all(&s.to_le_bytes())?;
    }
    f.flush()
}

// ---------------------------------------------------------------------------
// The tutti → AMY compilers (render surface → wire strings).
// ---------------------------------------------------------------------------

/// The AMY oscillator index a degree is assigned to: a *pure, stable* function
/// of the degree, so a note-off targets exactly the oscillator its note-on lit
/// — the anti-stuck-note discipline by construction. Distinct degrees map to
/// distinct oscillators until the count wraps; a small chord never collides.
fn osc_index(degree: TunedDegree, max_oscs: u16) -> u16 {
    degree.degree.index() % max_oscs.max(1)
}

/// Format a MIDI note for the wire: integers stay integral (`60`), fractional
/// notes get up to 3 decimals (`60.387`), matching AMY's own 3-dp convention.
fn fmt_midi_note(note: f64) -> String {
    if (note.fract()).abs() < 1e-4 {
        format!("{}", note.round() as i64)
    } else {
        let s = format!("{:.3}", note);
        // trim trailing zeros ("60.500" -> "60.5") for tidy wire strings.
        let trimmed = s.trim_end_matches('0').trim_end_matches('.');
        trimmed.to_string()
    }
}

/// Compile a degree-set transition into AMY wire events, each *added* degree's
/// note-on carrying its converged **envelope facet** (when the room holds a
/// register for it) as an AMY `A`/`T` amplitude-EG fragment; a degree with no
/// facet uses AMY's default envelope. Degrees resolve to (possibly fractional)
/// MIDI notes under `tuning` — a non-12 EDO renders exactly, with no MPE
/// channel rotation or bend-range negotiation.
///
/// Note-offs precede note-ons ([`PitchSetDiff`]'s ordering contract), so a
/// voice freed by the transition is reused rather than stomped.
pub fn degrees_to_amy_events(
    before: &BTreeSet<TunedDegree>,
    after: &BTreeSet<TunedDegree>,
    envelopes: &BTreeMap<TunedDegree, Envelope>,
    tuning: &Tuning,
    max_oscs: u16,
) -> Vec<String> {
    let diff = PitchSetDiff::between(before, after);
    let mut events = Vec::new();
    for degree in &diff.retracted {
        events.push(format!("v{}l0", osc_index(*degree, max_oscs)));
    }
    for degree in &diff.added {
        let note = fractional_midi(tuning, PeriodicPitch::from_degree(degree.degree, 0));
        let mut ev = format!("v{}n{}", osc_index(*degree, max_oscs), fmt_midi_note(note));
        if let Some(env) = envelopes.get(degree) {
            ev.push_str(&envelope_to_amy(env));
        }
        ev.push_str("l1");
        events.push(ev);
    }
    events
}

// ---------------------------------------------------------------------------
// The envelope facet → AMY EG0 compiler.
// ---------------------------------------------------------------------------
//
// tutti ships the *function* — a sparse breakpoint list plus the rule to fill
// between the points — and AMY evaluates it at 44.1 kHz locally. AMY's control
// model is already "generators, not streams": each oscillator has two
// breakpoint envelope generators (EG0/EG1), `(time_ms, value)` pairs with a
// per-EG interpolation `eg_type` (amy.h:238-242; docs/api.md `A`/`T`). The
// default oscillator gates its amplitude by EG0 (amy.c:868), so an EG0
// breakpoint string shapes the note's loudness contour directly.

/// AMY's `eg_type` code (docs/api.md `T`) for an interpolation kind. `Step`
/// rides the LINEAR engine (its staircase makes the curve piecewise-constant).
fn eg_type_code(interp: Interp) -> u8 {
    match interp {
        Interp::Linear | Interp::Step => 1, // ENVELOPE_LINEAR
        Interp::Exp => 3,                   // ENVELOPE_TRUE_EXPONENTIAL
    }
}

/// One breakpoint level (0..=127) as AMY's linear-amplitude float (0..1), formatted
/// like AMY's own patch strings: fixed 4-dp then trimmed, so it is compact AND a
/// deterministic pure function of the level (determinism gate).
fn fmt_level(level: u8) -> String {
    let v = (level.min(MAX_ENV_LEVEL) as f32) / (MAX_ENV_LEVEL as f32);
    let s = format!("{:.4}", v);
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// `Interp::Step` expansion: over AMY's LINEAR engine, hold each level flat for its
/// whole segment then jump to the next in `STEP_JUMP_MS`, yielding a
/// piecewise-constant curve — realized *honestly* as a staircase, not by
/// mislabeling the curve family. The last emitted pair stays the release segment.
const STEP_JUMP_MS: u16 = 1;
fn staircase(points: &[(u16, u8)]) -> Vec<(u16, u8)> {
    if points.len() <= 1 {
        return points.to_vec();
    }
    let mut out = Vec::with_capacity(points.len() * 2 - 1);
    out.push(points[0]); // reach level0 over its ms (usually 0 = instant)
    for w in points.windows(2) {
        let (_prev_ms, prev_level) = w[0];
        let (seg_ms, level) = w[1];
        let hold = seg_ms.saturating_sub(STEP_JUMP_MS);
        out.push((hold, prev_level)); // hold flat at the previous level
        out.push((STEP_JUMP_MS, level)); // then jump to the new level
    }
    out
}

/// Project an [`Envelope`] facet into AMY's amplitude-EG wire fragment: the `A`
/// breakpoint-set string (docs/api.md `A` → `eg0_times`/`eg0_values`; comma-
/// separated `time_ms,value` pairs, last pair = release) plus the `T` eg_type
/// code (docs/api.md `T` → `eg_type[0]`). AMY's tokenizer copies the `A` argument
/// over the charset `" 0123456789-,."` and stops at the next letter (parse.c:188),
/// so appending `T…` (and later `l1`) to the same message is unambiguous.
///
/// Example — `Envelope{ points:[(0,127),(120,12),(40,0)], interp: Exp }`
/// projects to `"A0,1,120,0.0945,40,0T3"`: jump to full, true-exp decay to ~0.09
/// over 120 ms, then a 40 ms release to silence on note-off.
pub fn envelope_to_amy(env: &Envelope) -> String {
    let pairs: Vec<(u16, u8)> = match env.interp {
        Interp::Step => staircase(&env.points),
        _ => env.points.clone(),
    };
    let mut s = String::from("A");
    for (i, (ms, level)) in pairs.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&ms.to_string());
        s.push(',');
        s.push_str(&fmt_level(*level));
    }
    s.push('T');
    s.push_str(&eg_type_code(env.interp).to_string());
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn degree(tuning: &Tuning, index: u16) -> TunedDegree {
        TunedDegree::new(tuning, index).unwrap()
    }

    fn set(tuning: &Tuning, indices: &[u16]) -> BTreeSet<TunedDegree> {
        indices.iter().map(|&i| degree(tuning, i)).collect()
    }

    #[test]
    fn envelope_to_amy_linear_and_exp_grammar() {
        // Linear pluck-ish: instant to full, ramp to half over 200 ms, release.
        let lin = Envelope {
            points: vec![(0, 127), (200, 64), (100, 0)],
            interp: Interp::Linear,
        };
        // 127/127=1, 64/127=0.5039..→"0.5039", 0→"0". Last pair is release.
        assert_eq!(envelope_to_amy(&lin), "A0,1,200,0.5039,100,0T1");

        // True-exp decay (the docstring's example), eg_type 3.
        let exp = Envelope {
            points: vec![(0, 127), (120, 12), (40, 0)],
            interp: Interp::Exp,
        };
        assert_eq!(envelope_to_amy(&exp), "A0,1,120,0.0945,40,0T3");
    }

    #[test]
    fn envelope_to_amy_step_is_a_staircase_on_linear() {
        // Step over 3 points expands to hold-then-jump on the LINEAR engine (T1).
        let step = Envelope {
            points: vec![(0, 0), (200, 64), (100, 127)],
            interp: Interp::Step,
        };
        // points[0]=(0,0); window0 -> (200-1, 0),(1, 0.5039); window1 -> (100-1, 0.5039),(1,1)
        assert_eq!(
            envelope_to_amy(&step),
            "A0,0,199,0,1,0.5039,99,0.5039,1,1T1"
        );
    }

    #[test]
    fn envelope_projection_is_a_deterministic_pure_function() {
        // Equal envelopes ⇒ byte-identical strings, every time (determinism gate).
        let e = Envelope {
            points: vec![(0, 8), (350, 127), (60, 0)],
            interp: Interp::Linear,
        };
        assert_eq!(envelope_to_amy(&e), envelope_to_amy(&e.clone()));
    }

    #[test]
    fn degree_note_on_carries_the_facet_or_the_default() {
        let tuning = Tuning::twelve_tet();
        let mut envs: BTreeMap<TunedDegree, Envelope> = BTreeMap::new();
        envs.insert(
            degree(&tuning, 0),
            Envelope {
                points: vec![(0, 127), (120, 12), (40, 0)],
                interp: Interp::Exp,
            },
        );
        let before = BTreeSet::new();
        let after = set(&tuning, &[0, 7]);
        let ev = degrees_to_amy_events(&before, &after, &envs, &tuning, 250);
        // Degree 0 (osc 0) carries its envelope; degree 7 (osc 7) has no facet → default.
        assert!(ev.contains(&"v0n60A0,1,120,0.0945,40,0T3l1".to_string()));
        assert!(ev.contains(&"v7n67l1".to_string()));

        // With NO facets the note-ons are plain (byte-identical minus the fragment).
        let plain = degrees_to_amy_events(&before, &after, &BTreeMap::new(), &tuning, 250);
        assert_eq!(plain, vec!["v0n60l1".to_string(), "v7n67l1".to_string()]);
    }

    #[test]
    fn fractional_midi_note_for_a_non_twelve_edo() {
        // A quarter-tone step above middle C = 60.5, anchored by an explicit KBM.
        let tuning = Tuning::from_scl_text(
            "quarter",
            "quarter tones\n2\n50.0\n1200.0\n",
            Some("0\n0\n127\n60\n60\n261.6255653005986\n0\n"),
        )
        .unwrap();
        let ev = degrees_to_amy_events(
            &BTreeSet::new(),
            &set(&tuning, &[1]),
            &BTreeMap::new(),
            &tuning,
            250,
        );
        assert_eq!(ev, vec!["v1n60.5l1".to_string()]);
    }

    #[test]
    fn empty_to_chord_is_all_note_ons() {
        let tuning = Tuning::twelve_tet();
        let ev = degrees_to_amy_events(
            &BTreeSet::new(),
            &set(&tuning, &[0, 4, 7]),
            &BTreeMap::new(),
            &tuning,
            250,
        );
        // C major triad on distinct oscs 0, 4, 7.
        assert_eq!(ev.len(), 3);
        assert!(ev.contains(&"v0n60l1".to_string()));
        assert!(ev.contains(&"v4n64l1".to_string()));
        assert!(ev.contains(&"v7n67l1".to_string()));
    }

    #[test]
    fn chord_to_empty_is_all_note_offs() {
        let tuning = Tuning::twelve_tet();
        let ev = degrees_to_amy_events(
            &set(&tuning, &[0, 7]),
            &BTreeSet::new(),
            &BTreeMap::new(),
            &tuning,
            250,
        );
        assert_eq!(ev, vec!["v0l0".to_string(), "v7l0".to_string()]);
    }

    #[test]
    fn only_the_delta_is_emitted() {
        // Hold 0 and 7, add 4, drop 7.
        let tuning = Tuning::twelve_tet();
        let ev = degrees_to_amy_events(
            &set(&tuning, &[0, 7]),
            &set(&tuning, &[0, 4]),
            &BTreeMap::new(),
            &tuning,
            250,
        );
        // 0 is held (no event), 7 off, 4 on. Off precedes on.
        assert_eq!(ev, vec!["v7l0".to_string(), "v4n64l1".to_string()]);
    }

    #[test]
    fn note_off_targets_the_same_osc_as_note_on() {
        // Any degree's note-on and note-off address the same oscillator — the
        // no-stuck-note invariant, as a pure property of the osc mapping.
        let tuning = Tuning::twelve_tet();
        for index in 0..12 {
            let one = set(&tuning, &[index]);
            let on = degrees_to_amy_events(&BTreeSet::new(), &one, &BTreeMap::new(), &tuning, 250);
            let off = degrees_to_amy_events(&one, &BTreeSet::new(), &BTreeMap::new(), &tuning, 250);
            let on_osc = on[0].split('n').next().unwrap().to_string();
            let off_osc = off[0].trim_end_matches("l0").to_string();
            assert_eq!(on_osc, off_osc, "on/off osc mismatch for degree {index}");
        }
    }
}
