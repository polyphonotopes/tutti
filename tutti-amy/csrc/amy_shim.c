// amy_shim.c — a tiny C bridge over AMY's C API for the Rust desktop leaf.
//
// The only awkward part of AMY's ABI for `extern "C"` binding is that
// `amy_start()` takes an `amy_config_t` *by value* (a large struct with
// bitfields and many function-pointer members). Rather than mirror that layout
// in Rust, we build the config here in C — where `amy.h` is authoritative — and
// expose plain, trivially-bindable functions. Everything else in AMY's API
// (amy_add_message/amy_sysclock/amy_stop/amy_simple_fill_buffer) is already a
// clean C-ABI surface the Rust side binds directly.
//
// This file is compiled by build.rs together with AMY's own sources; it does
// NOT modify anything under the AMY checkout.

#include "amy.h"

// Start AMY headless and deterministic:
//   audio   = NONE   -> no miniaudio device is opened; amy_start never touches
//                       the OS audio backend. Audio comes out of
//                       amy_simple_fill_buffer() regardless.
//   midi    = NONE   -> no MIDI backend.
//   default_synths=0 -> the caller drives raw oscillators / synths itself.
//   multicore/thread=0 -> single-threaded offline render (the flags are only
//                       consulted by i2s.c / amy_midi.c, neither of which is on
//                       the desktop render path, but we set them for clarity).
void ws_amy_start_headless(void) {
    amy_config_t c = amy_default_config();
    c.audio = AMY_AUDIO_IS_NONE;
    c.midi = AMY_MIDI_IS_NONE;
    c.features.default_synths = 0;
    c.platform.multicore = 0;
    c.platform.multithread = 0;
    amy_start(c);
}

// Render exactly one block: execute all due deltas, render every oscillator,
// then mix/effect/output. Returns AMY's interleaved int16 output block
// (AMY_BLOCK_SIZE * AMY_NCHANS samples). This is `amy_simple_fill_buffer`,
// i.e. the `amy_fill_buffer` the task names plus the execute+render steps that
// actually advance synthesis.
int16_t *ws_amy_render_block(void) {
    return amy_simple_fill_buffer();
}

// Compile-time geometry, surfaced so Rust never has to guess.
int ws_amy_block_frames(void) { return AMY_BLOCK_SIZE; }   // frames per block
int ws_amy_nchans(void)       { return AMY_NCHANS; }        // interleaved chans
int ws_amy_block_samples(void){ return AMY_BLOCK_SIZE * AMY_NCHANS; }
int ws_amy_sample_rate(void)  { return AMY_SAMPLE_RATE; }
