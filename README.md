# tutti

A server-less signed-op store for music, plus MIDI / OSC / AMY bridges.
Peers sign ops, gossip them, converge — no server. Extracted from walkie-songie.

## crates

- `tutti-core` — the substrate: signed-op envelope + fold seam, over [hhhs-dag].
- `tutti-music` — the music op-language: degrees, tunings, envelopes. State, not events.
- `tutti-midi` — MIDI in/out. Reconnect re-diffs the current state, so no stuck notes.
- `tutti-osc` — OSC out, same idea.
- `tutti-amy` — drives the AMY C synth. Needs clang; excluded from the default build.

Early. The music wire isn't frozen yet.

[hhhs-dag]: https://gitlab.com/micahscopes/hhhs-rs
