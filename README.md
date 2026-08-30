# tutti

Tutti contains reusable music state and host adapters. The current development
line adds the embedded session, BLE, shared pitch-set, round-table, realtime,
and AMY wire boundaries used by Tutti Leaf and Walkie Songie. Its HHHS 0.4 protocol
layer is `tutti-music-hhhs`; discovery and carriers remain application
concerns. The workspace uses the immutable HHHS `v0.4.4` tag throughout. Its
HHHS materializer keeps only live causal maxima with `WalkingReach` instead of
constructing an eager transitive closure.

## Crates

- `tutti-music` — music command/value language: degrees, tunings, and envelopes.
- `tutti-music-hhhs` — HHHS 0.4 command codec, explicit capability and
  authenticated-channel/open authority profiles, production Replica builders,
  deterministic roots, and rebuildable materializers. Profiles refuse implicit
  downgrade. The crate owns no session, endpoint, mesh, carrier, runtime,
  clock, filesystem, or application-extension state.
- `tutti-session` — transport-independent Ed25519-authenticated ephemeral
  X25519 handshake, directional keyed-BLAKE3 channel authentication, and a
  bounded replay window. Discovery, peer trust policy, retransmission, packet
  sizing, encryption, and HHHS admission are caller-owned boundaries.
- `tutti-ble` — platform-neutral Tutti GATT UUIDs, boot-scoped session binding,
  bounded fragmentation, authenticated control/realtime/HHHS lane framing, and
  an `hhhs-sync::FrameStream` adapter over an application-demultiplexed repair
  lane. It owns no Bluetooth adapter, discovery policy, or platform runtime.
- `tutti-amy-wire` — C-free, collision-safe projection from materialized music
  views to AMY wire messages, shared by desktop and embedded render leaves.
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
automatically. The AMY checks require a clean checkout at `/laboratory/amy`
or at `AMY_SRC`, pinned to the exact revision in `tutti-amy/AMY_REV`.

The generation-5 music wire is deliberately distinct from earlier Walkie/Tutti
formats. Functional interoperability is the contract; old hashes and hosts are
not preserved.

## Realtime sessions

`tutti-session` is the public authenticated-channel boundary. One signed
ephemeral handshake establishes directional session keys; subsequent frames
use a 16-byte keyed tag and no public-key operation. It authenticates but does
not encrypt payloads.

`tutti-music-hhhs/tests/realtime_session_model.rs` remains an executable model
for the optional lower-latency musical gate plane: a bounded binding table,
compact gate frames, and later durable HHHS confirmation/correction. The ESP32
currently sends ordinary open-authority HHHS repair through `tutti-session`;
the compact gate plane can be added without changing either crate's trust
boundary.

```sh
cargo test -p tutti-music-hhhs --test realtime_session_model
cargo test -p tutti-session
```
