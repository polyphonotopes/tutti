# tutti

Tutti contains reusable music state and host adapters. Its HHHS 0.4 protocol
layer is `tutti-music-hhhs`; networking remains an application concern. The
`v0.4.5` uses the immutable HHHS `v0.4.4` tag throughout, including the AMY
leaf. Its HHHS materializer keeps only live causal maxima with `WalkingReach`
instead of constructing an eager transitive closure.

## Crates

- `tutti-music` — music command/value language: degrees, tunings, and envelopes.
- `tutti-music-hhhs` — HHHS 0.4 command codec, receiver-bound capability areas,
  admission policy, production Replica builder, deterministic roots, and
  rebuildable materializer. It owns no endpoint, mesh, carrier, task runtime,
  clock, filesystem, or application-extension state.
- `tutti-core` — the older generic signed-state/fold substrate retained for
  compatibility and fold/compaction conformance; it is not a production 0.4
  authority or sync host.
- `tutti-midi` — MIDI input/output with state rediff on reconnect.
- `tutti-osc` — OSC output.
- `tutti-amy` — AMY C synth leaf driven by the same capability-native music
  Replica and repair records; excluded from the default workspace because it
  requires a C toolchain.

Walkie room v5 imports `tutti-music-hhhs` directly and composes its production
music Replica with a separate application-extension Replica. A bare music peer
can therefore share the same music command/admission/materialization protocol
without learning Walkie's extension lane.

```sh
cargo test -p tutti-music-hhhs
cargo clippy -p tutti-music-hhhs --all-targets -- -D warnings
cargo test --manifest-path tutti-amy/Cargo.toml --all-features
```

Before a release, run the complete manual gate:

```sh
scripts/verify-release.sh
```

It checks formatting, the complete workspace and excluded AMY test suites,
strict Clippy and rustdoc, the WASM compile surface, and a fresh external
Git consumer built from an isolated snapshot. It is intentionally opt-in: no repository workflow runs it
automatically. The AMY checks require a prepared checkout at `/laboratory/amy`
or at `AMY_SRC`.

The generation-5 music wire is deliberately distinct from earlier Walkie/Tutti
formats. Functional interoperability is the contract; old hashes and hosts are
not preserved.

## Executable realtime-session probe

`tutti-music-hhhs/tests/realtime_session_model.rs` grounds the proposed fast
session boundary without making it a public API yet. It proves one durable
capability presentation can authorize an exact compact binding table, a short
authenticated gate frame can update a projection immediately, and ordinary
HHHS admission and repair later confirm or correct that projection. The model
packet layout and MAC are deliberately non-normative; key agreement, AEAD,
expiry/revocation cadence, MIDI 2.0/UMP mappings, and replay-window policy remain
open design work.

```sh
cargo test -p tutti-music-hhhs --test realtime_session_model
```
