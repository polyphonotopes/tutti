// build.rs — compile the AMY C synthesizer into a static lib and link it.
//
// This reproduces AMY's own desktop Makefile recipe (the load-bearing artifact
// for the eventual ESP32 port):
//
//   CC      = gcc
//   CFLAGS  = -O3 -Wall -Wno-strict-aliasing -Wextra -Wno-unused-parameter \
//             -Wpointer-arith -Wno-float-conversion -Wno-missing-declarations \
//             -DAMY_WAVETABLE
//   SOURCES = src/algorithms.c src/amy.c src/envelope.c src/examples.c
//             src/parse.c src/filters.c src/oscillators.c src/pcm.c
//             src/interp_partials.c src/custom.c src/delay.c src/log2_exp2.c
//             src/patches.c src/transfer.c src/sequencer.c
//             src/libminiaudio-audio.c src/instrument.c src/amy_midi.c
//             src/api.c src/midi_mappings.c src/cv_trigger.c
//   LIBS    = -lm -pthread   (+ -ldl on Linux for miniaudio's runtime linking)
//
// The example `main`s (amy-example.c / amy-message.c / amy-piano.c) are NOT part
// of the library — they carry their own `int main` — so we omit them and supply
// our own entry via csrc/amy_shim.c.
//
// Generated headers: AMY's Makefile regenerates src/patches.h (and other LUT
// headers) with a Python step that needs numpy + soundfile. Those headers are
// already committed in the AMY checkout, so we do NOT run that step; we just
// compile against them. build.rs errors clearly if patches.h is missing.

use std::path::PathBuf;

fn main() {
    // AMY checkout. Override with AMY_SRC=/path/to/amy if it moves.
    let amy_root = std::env::var("AMY_SRC").unwrap_or_else(|_| "/laboratory/amy".to_string());
    let amy_src = PathBuf::from(&amy_root).join("src");

    // The generated header AMY's Makefile builds via `python3 -m amy.headers`.
    // It ships pre-generated in the checkout; fail loudly rather than silently
    // if someone points AMY_SRC at a tree where the header-gen never ran.
    let patches_h = amy_src.join("patches.h");
    if !patches_h.exists() {
        panic!(
            "AMY generated header not found: {}\n\
             Run `make src/patches.h` inside {} first (needs the numpy + soundfile\n\
             python deps from requirements.txt), or set AMY_SRC to a prepared checkout.",
            patches_h.display(),
            amy_root
        );
    }

    // The AMY library sources (Makefile SOURCES, minus the example mains).
    let sources = [
        "algorithms.c",
        "amy.c",
        "envelope.c",
        "examples.c",
        "parse.c",
        "filters.c",
        "oscillators.c",
        "pcm.c",
        "interp_partials.c",
        "custom.c",
        "delay.c",
        "log2_exp2.c",
        "patches.c",
        "transfer.c",
        "sequencer.c",
        "libminiaudio-audio.c",
        "instrument.c",
        "amy_midi.c",
        "api.c",
        "midi_mappings.c",
        "cv_trigger.c",
    ];

    let mut build = cc::Build::new();
    build
        .include(&amy_src)
        // Match AMY's desktop CFLAGS.
        .opt_level(3)
        .define("AMY_WAVETABLE", None)
        .flag_if_supported("-Wno-strict-aliasing")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wpointer-arith")
        .flag_if_supported("-Wno-float-conversion")
        .flag_if_supported("-Wno-missing-declarations")
        // AMY's C is warning-noisy by design; don't let it drown the build log.
        .warnings(false);

    for f in sources {
        build.file(amy_src.join(f));
    }
    // Our config bridge (lives in this crate, does not touch the AMY checkout).
    build.file("csrc/amy_shim.c");

    build.compile("amy"); // -> libamy.a, linked automatically.

    // AMY needs libm + pthread; miniaudio uses dlopen() for its audio backends
    // on Linux, so libdl too. (We never open a device, but the symbols must
    // resolve at link time.)
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=pthread");
    #[cfg(target_os = "linux")]
    println!("cargo:rustc-link-lib=dylib=dl");

    // Rebuild triggers.
    println!("cargo:rerun-if-changed=csrc/amy_shim.c");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=AMY_SRC");
    for f in sources {
        println!("cargo:rerun-if-changed={}", amy_src.join(f).display());
    }
}
