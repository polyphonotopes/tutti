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
//!    pitch-set — "reconciliation upstream, events downstream."
//!
//! The music values live in `tutti-music`; capability admission,
//! materialization, and repair live in `tutti-music-hhhs`. This crate only
//! compiles the resulting values for one target.
//!
//! AMY is a global singleton (one `amy_global`), so `Amy::start()` hands out a
//! single guard; construct at most one at a time.

use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicBool, Ordering};

pub use tutti_amy_wire::{
    degrees_to_amy_events, envelope_to_amy, AmyVoiceCapacityError, Envelope, Interp, MAX_ENV_LEVEL,
    MAX_ENV_POINTS,
};

/// The two-peer partition→rejoin scenario and AMY driver over HHHS music Replicas.
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

/// Root-mean-square level of a block, normalized to `0..=1` against full scale.
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
