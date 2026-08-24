# tutti

Tutti contains reusable music state and host adapters. Its HHHS 0.4 protocol
layer is `tutti-music-hhhs`; networking remains an application concern. The
current release uses the immutable HHHS v0.4.2 tag throughout, including the
AMY leaf.

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

The generation-5 music wire is deliberately distinct from earlier Walkie/Tutti
formats. Functional interoperability is the contract; old hashes and hosts are
not preserved.
