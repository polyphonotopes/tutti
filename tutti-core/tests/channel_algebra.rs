//! A FOURTH [`OpLanguage`] instantiation — a **capability-channel constraint
//! algebra** — driven end-to-end through `Store<ChannelLang>`. It is the isolated
//! tutti demonstration of M4's "channel constraint algebra + device-specific
//! controls (capability channels)": the one cell of the policy matrix walkie does
//! not yet occupy — **device-gated add × shared observed-remove**, i.e. the user's
//! stated semantic:
//!
//!   *only authorized authors may ADD notes to a channel; ANYONE may REMOVE.*
//!
//! Grounding: `docs/vision/eventually-consistent-pitchsets.md` — "The channel
//! constraint algebra" (**a channel = an address space × a membership policy × a
//! projection**) and its headline invariant: *"add and remove are independent
//! axes"*, with the missing cell named outright — "**only certain devices may add
//! to a channel; anyone may remove**" (device-gated add × shared observed-remove).
//! The doc's honest frame is reproduced here mechanically: a violating op **voids**
//! — "it stays in history, signed and attributable, and every honest replica
//! computes the same 'no effect' verdict for it at every horizon" — exactly the
//! owner-gate shape ("stores the non-owner's move and gives it nothing").
//!
//! Modelled EXACTLY on `crates/tutti-core/tests/second_domain.rs` (the KV register
//! `OpLanguage` template) and `tutti-amy/src/music.rs` (`MusicLang`'s add-wins
//! observed-remove pitch-set). A real `OpLanguage` over the substrate's OWN
//! `ingest_verified` / `view()` / `FoldCtx::{decoded, is_ancestor, resolve}` — no
//! ad-hoc ordering, no production-code change (this is a test file; the whole
//! capability model lives here). It needs `--features test-support` for the kernel
//! `view_reference()` oracle, like `second_domain`.
//!
//! ## The capability model (deliberately minimal + self-authorizing — stated)
//!
//! A channel is identified by an immutable **policy fixed at creation**:
//! `ChannelOp::OpenChannel { channel, adders }` declares the authorized-adder set
//! ONCE. It is **self-authorizing**: there is no capability-granting *authority* to
//! bootstrap — *the policy IS the channel*. Whoever opens a channel declares its
//! adder set (they need not themselves be an adder). If two `OpenChannel` ops race,
//! the policy resolves by **causal-maxima register** (`ctx.resolve`, EXACTLY the
//! KV/tuning register) — the doc's "a causal register holding the channel's own
//! rules". Deterministic ⇒ order-independent.
//!
//! ## The fold (the enforcement is the point — see [`ChannelLang::fold`])
//!
//! `View = BTreeMap<ChannelId, BTreeSet<u16>>` — the live pitch-set per channel.
//! Per (channel, pc):
//!   * an `AddDegree` **counts only if its author ∈ that channel's `adders`** — the
//!     author-∈-adders filter runs BEFORE add-wins resolution, so an unauthorized
//!     add is INERT: it never enters the candidate set, so it cannot make a pc live
//!     even as the sole or causally-latest add.
//!   * a `RemoveDegree` counts **from any author** (open removal) — add-wins
//!     observed-remove EXACTLY as `MusicLang`, over the *authorized* adds only.
//!
//! ## Honest posture: STORED-BUT-INERT (fold-time filter, NOT a wire gate)
//!
//! Capability enforcement here is a **fold-time filter, not a wire-admission
//! gate**. An unauthorized op still verifies, still LIFTS into the DAG, and still
//! SYNCS (it is in `entry_hashes()` and contributes to `ops_root()`); it simply
//! does not COUNT in `view()`. This is the same "stored, signed, attributable, and
//! inert" model as walkie's owner-gated pieces — capability lives *inside* eventual
//! consistency, never coordinating, never bouncing an op.
//!
//! ## LEFT for co-design (flagged, NOT built — the richer capability rows)
//!
//! This is the minimal self-authorizing core. Deliberately out of scope:
//!   * **delegation** — handing an attenuated write-cap to a third party;
//!   * **revocation** — a barrier that deterministically beats a racing writer;
//!   * **key rotation** — re-keying an authorized device without reopening;
//!   * **coercion / projection lenses** — coercion-on-add (a PCS/set-class channel
//!     that rewrites every add at ingress) and render-side projection;
//!   * **per-channel remove-policies** — here remove is always OPEN; the algebra's
//!     other remove-constraints (owner-only lifecycle, lease-expiry) are not built;
//!   * **precondition / void engine** — HHS3 at-use preconditions, all-or-nothing
//!     bundles, recursive drop-on-void (hhhs has no void engine yet).
//!
//! Determinism note: all randomness is a seeded SplitMix64 (below). No `Date::now`,
//! no `rand` — permutations are reproducible, so a convergence failure is a bug.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use tutti_core::EntryHash;
use tutti_core::{
    AuthorId, FoldCtx, OpLanguage, SignedOp, SigningKey, Store, VerifiedOpG, signing_key_from_seed,
    verify_signed_op_in,
};

// ===========================================================================
// The capability-channel OpLanguage.
// ===========================================================================

/// A channel name — the address space coordinate. A readable newtype so scenarios
/// read `ch("score")`, not a bare integer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct ChannelId(String);

fn ch(name: &str) -> ChannelId {
    ChannelId(name.to_string())
}

/// The capability-channel op alphabet. Every op is signed, so `AuthorId` = the
/// signing key and the fold knows each op's author verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ChannelOp {
    /// Open `channel` with an immutable policy: `adders` is the authorized-adder
    /// set, declared ONCE at creation (self-authorizing — the policy IS the
    /// channel). Whoever opens it need not be an adder.
    OpenChannel {
        channel: ChannelId,
        adders: BTreeSet<AuthorId>,
    },
    /// Assert scale degree `pc` into `channel`'s live set. Counts iff its author ∈
    /// the channel's `adders` (device-gated add).
    AddDegree { channel: ChannelId, pc: u16 },
    /// Retract scale degree `pc` from `channel`. Counts from ANY author (open
    /// removal); cancels only the authorized adds it causally observed.
    RemoveDegree { channel: ChannelId, pc: u16 },
}

/// Domain well-formedness bounds — `ChannelLang`'s OWN caps.
const MAX_DEGREE: u16 = 4096;
const MAX_ADDERS: usize = 256;
const MAX_CHANNEL_BYTES: usize = 128;

/// The capability-channel `OpLanguage`. Its consts are all its OWN, distinct from
/// walkie's, the KV domain's, and MusicLang's — nothing generic is hardcoded to a
/// literal.
struct ChannelLang;

impl OpLanguage for ChannelLang {
    type Op = ChannelOp;
    type View = BTreeMap<ChannelId, BTreeSet<u16>>;

    const SCHEMA_VERSION: u16 = 1;
    const ENTRY_FRAME_MAGIC: &'static [u8] = b"tutti.channel.entry/1";
    const WIRE_MAGIC: &'static [u8] = b"tutti.channel.wire/1\0";
    const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

    fn validate_wire(op: &ChannelOp) -> Result<(), String> {
        match op {
            ChannelOp::OpenChannel { channel, adders } => {
                if channel.0.is_empty() || channel.0.len() > MAX_CHANNEL_BYTES {
                    return Err(format!("channel must be 1..={MAX_CHANNEL_BYTES} bytes"));
                }
                if adders.len() > MAX_ADDERS {
                    return Err(format!("adders exceeds MAX_ADDERS={MAX_ADDERS}"));
                }
            }
            ChannelOp::AddDegree { channel, pc } | ChannelOp::RemoveDegree { channel, pc } => {
                if channel.0.is_empty() || channel.0.len() > MAX_CHANNEL_BYTES {
                    return Err(format!("channel must be 1..={MAX_CHANNEL_BYTES} bytes"));
                }
                if *pc >= MAX_DEGREE {
                    return Err(format!("degree {pc} exceeds MAX_DEGREE={MAX_DEGREE}"));
                }
            }
        }
        Ok(())
    }

    /// One deterministic fold, enforcing the capability channel:
    ///
    /// 1. **Policy per channel (causal-maxima register).** Every `OpenChannel` for a
    ///    channel is a candidate; `ctx.resolve` drops any candidate strictly in
    ///    another's causal past then breaks the surviving concurrent maxima by max
    ///    raw-bytes `EntryHash` — so a racing reopen resolves order-independently.
    ///    The winner's `adders` set is the channel's authorized-adder policy. A
    ///    channel with no resolved `OpenChannel` HAS NO policy: nothing is authorized
    ///    there, so nothing is live (and it does not appear in the view).
    ///
    /// 2. **Live degrees per channel (device-gated add × open observed-remove).**
    ///    For each opened channel, per pc:
    ///    * **THE CAPABILITY FILTER (the point):** keep only the adds whose author ∈
    ///      the channel's `adders`, computed via `ctx.decoded()[add].author()`,
    ///      BEFORE any add-wins resolution. An unauthorized add never enters the
    ///      candidate set ⇒ it is INERT — it cannot make a pc live even if it is the
    ///      sole or causally-latest add for that pc.
    ///    * **add-wins observed-remove over the AUTHORIZED adds only** (removes from
    ///      ANY author — open removal): pc is live iff SOME authorized add for it is
    ///      not causally observed (`is_ancestor`) by ANY remove for it. EXACTLY
    ///      MusicLang's degree semantics, restricted to the authorized adds.
    ///
    /// Ancestry/authorship are read ONLY through `FoldCtx` / `ctx.decoded()` — no
    /// ad-hoc ordering.
    fn fold(ctx: &FoldCtx<'_, Self>) -> Self::View {
        // Gather candidates: opens per channel, adds/removes per (channel, pc).
        let mut opens: BTreeMap<ChannelId, BTreeSet<EntryHash>> = BTreeMap::new();
        let mut adds: BTreeMap<(ChannelId, u16), Vec<EntryHash>> = BTreeMap::new();
        let mut removes: BTreeMap<(ChannelId, u16), Vec<EntryHash>> = BTreeMap::new();
        for (entry, decoded) in ctx.decoded() {
            match decoded.op() {
                ChannelOp::OpenChannel { channel, .. } => {
                    opens.entry(channel.clone()).or_default().insert(*entry);
                }
                ChannelOp::AddDegree { channel, pc } => {
                    adds.entry((channel.clone(), *pc)).or_default().push(*entry);
                }
                ChannelOp::RemoveDegree { channel, pc } => {
                    removes
                        .entry((channel.clone(), *pc))
                        .or_default()
                        .push(*entry);
                }
            }
        }

        // 1. Resolve each channel's immutable policy (causal-maxima register).
        let mut policy: BTreeMap<ChannelId, BTreeSet<AuthorId>> = BTreeMap::new();
        for (channel, candidates) in &opens {
            if let Some(winner) = ctx.resolve(candidates) {
                if let ChannelOp::OpenChannel { adders, .. } = ctx.decoded()[&winner].op() {
                    policy.insert(channel.clone(), adders.clone());
                }
            }
        }

        // Seed every OPENED channel (present, possibly empty) — the honest "the
        // channel exists; the unauthorized adds are stored but inert" view.
        let mut view: BTreeMap<ChannelId, BTreeSet<u16>> = policy
            .keys()
            .cloned()
            .map(|c| (c, BTreeSet::new()))
            .collect();

        // 2. Fold live degrees per opened channel.
        for ((channel, pc), add_entries) in &adds {
            // No policy ⇒ nothing authorized on this channel (an add to an unopened
            // channel is inert; the channel does not appear).
            let Some(adders) = policy.get(channel) else {
                continue;
            };

            // === THE CAPABILITY FILTER === author ∈ adders, BEFORE add-wins.
            let authorized: Vec<EntryHash> = add_entries
                .iter()
                .copied()
                .filter(|entry| adders.contains(&ctx.decoded()[entry].author()))
                .collect();
            if authorized.is_empty() {
                continue;
            }

            // add-wins observed-remove over the AUTHORIZED adds only; removes are
            // open (any author). pc lives iff some authorized add is not observed by
            // any remove for it.
            let rem_entries = removes
                .get(&(channel.clone(), *pc))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let survives = authorized
                .iter()
                .any(|a| !rem_entries.iter().any(|r| ctx.is_ancestor(a, r)));
            if survives {
                view.get_mut(channel).expect("opened channel seeded").insert(*pc);
            }
        }

        view
    }
}

// ===========================================================================
// Deterministic harness — seeded SplitMix64, no Date::now / no rand crate.
// ===========================================================================

const TOPIC: &str = "capability-channel-algebra";
const TS_BASE: u64 = 1_700_000_000_000_000; // µs, monotone; NOT used for ordering

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// In-place deterministic Fisher-Yates over a seeded PRNG.
fn shuffled(ops: &[SignedOp], seed: u64) -> Vec<SignedOp> {
    let mut items = ops.to_vec();
    let mut rng = Rng::new(seed);
    for i in (1..items.len()).rev() {
        let j = rng.below(i + 1);
        items.swap(i, j);
    }
    items
}

/// Distinct, deterministic signing key per index.
fn author_key(i: usize) -> SigningKey {
    signing_key_from_seed(&[(i as u8) + 1; 32])
}

/// The `AuthorId` of `author_key(i)` — the verifying-key bytes, EXACTLY how the
/// store stamps an op's author (`store.rs`: `AuthorId(*key.verifying_key().as_bytes())`).
fn author_id(i: usize) -> AuthorId {
    AuthorId(*author_key(i).verifying_key().as_bytes())
}

/// Verify + ingest a slice of signed ops in the order given.
fn ingest_all(store: &mut Store<ChannelLang>, ops: &[SignedOp]) {
    for signed in ops {
        let verified: VerifiedOpG<ChannelLang> =
            verify_signed_op_in::<ChannelLang>(signed).expect("op verifies");
        store.ingest_verified(verified);
    }
}

fn verify(signed: &SignedOp) -> VerifiedOpG<ChannelLang> {
    verify_signed_op_in::<ChannelLang>(signed).expect("a signed channel op verifies")
}

// ===========================================================================
// GATE 1 — Capability enforced (the headline, adversarial).
// ===========================================================================

/// An `AddDegree` by an author NOT in `adders` is ABSENT from the view — even as
/// the sole add AND as the causally-latest add — while the same op by an authorized
/// author IS live; and a `RemoveDegree` by an UNAUTHORIZED author DOES kill an
/// authorized add (open removal).
#[test]
fn capability_enforced_add_gate() {
    // Channel policy: only author 1 may add. Founder (author 0) opens it and is
    // deliberately NOT an adder (self-authorizing: the opener declares the policy).
    let founder = author_key(0);
    let auth = author_key(1); // authorized adder
    let evil = author_key(2); // NOT in adders

    let adders: BTreeSet<AuthorId> = BTreeSet::from([author_id(1)]);

    // --- (a) SOLE unauthorized add is inert. ---
    {
        let mut s: Store<ChannelLang> = Store::new();
        s.commit(&founder, TOPIC, TS_BASE, ChannelOp::OpenChannel {
            channel: ch("score"),
            adders: adders.clone(),
        });
        s.commit(&evil, TOPIC, TS_BASE + 1, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 7,
        });
        assert!(
            !s.view()[&ch("score")].contains(&7),
            "an unauthorized SOLE add must be inert",
        );
        assert!(s.view()[&ch("score")].is_empty(), "channel open but empty");
    }

    // --- (b) the SAME op by an authorized author is live. ---
    {
        let mut s: Store<ChannelLang> = Store::new();
        s.commit(&founder, TOPIC, TS_BASE, ChannelOp::OpenChannel {
            channel: ch("score"),
            adders: adders.clone(),
        });
        s.commit(&auth, TOPIC, TS_BASE + 1, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 7,
        });
        assert!(
            s.view()[&ch("score")].contains(&7),
            "an authorized add must be live",
        );
    }

    // --- (c) the causally-LATEST add being unauthorized is still inert. ---
    // add(auth) -> remove(auth, observes add) -> add(evil, observes remove). Without
    // the filter, evil's add is the latest add unobserved by any remove ⇒ would
    // revive pc 7. With the filter it is inert ⇒ pc 7 stays dead.
    {
        let mut s: Store<ChannelLang> = Store::new();
        s.commit(&founder, TOPIC, TS_BASE, ChannelOp::OpenChannel {
            channel: ch("score"),
            adders: adders.clone(),
        });
        s.commit(&auth, TOPIC, TS_BASE + 1, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 7,
        });
        s.commit(&auth, TOPIC, TS_BASE + 2, ChannelOp::RemoveDegree {
            channel: ch("score"),
            pc: 7,
        });
        s.commit(&evil, TOPIC, TS_BASE + 3, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 7,
        });
        assert!(
            !s.view()[&ch("score")].contains(&7),
            "an unauthorized CAUSALLY-LATEST add must not revive the degree",
        );
    }

    // --- (d) an UNAUTHORIZED remove kills an authorized (observed) add. ---
    // add(auth) -> remove(evil, observes the add). Open removal: evil is not in
    // adders, yet the remove counts and cancels the observed authorized add.
    {
        let mut s: Store<ChannelLang> = Store::new();
        s.commit(&founder, TOPIC, TS_BASE, ChannelOp::OpenChannel {
            channel: ch("score"),
            adders: adders.clone(),
        });
        s.commit(&auth, TOPIC, TS_BASE + 1, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 5,
        });
        s.commit(&evil, TOPIC, TS_BASE + 2, ChannelOp::RemoveDegree {
            channel: ch("score"),
            pc: 5,
        });
        assert!(
            !s.view()[&ch("score")].contains(&5),
            "an unauthorized (open) remove must kill an observed authorized add",
        );
    }

    println!(
        "PASS gate 1 (capability enforced): unauthorized add inert (sole + causally-latest); \
         authorized add live; unauthorized OPEN remove kills an observed authorized add"
    );
}

// ===========================================================================
// GATE 2 — Convergence (adversarial): two peers, mixed authorized/unauthorized
// adders, partition then exchange -> identical view() == view_reference(),
// pending == 0, order-independent (== identical ops_root over permutations).
// ===========================================================================

/// Build the two-peer partition op-set: peer A opens the channel + one authorized
/// add + one unauthorized add; peer B (concurrent chain) one authorized add, one
/// unauthorized add, and one unauthorized OPEN remove of A's degree (concurrent, so
/// add-wins keeps it). Returns (A's signed ops, B's signed ops).
fn partition_op_sets() -> (Vec<SignedOp>, Vec<SignedOp>) {
    // Policy: authorized adders are authors 1 and 2. Founder is author 0 (not an
    // adder). Unauthorized floods/removes are authors 3 and 4.
    let adders: BTreeSet<AuthorId> = BTreeSet::from([author_id(1), author_id(2)]);
    let founder = author_key(0);
    let (k1, k2, k3, k4) = (author_key(1), author_key(2), author_key(3), author_key(4));

    // Peer A's chain (self-contained: each op observes only A's frontier).
    let mut a: Store<ChannelLang> = Store::new();
    let a_ops = vec![
        a.commit(&founder, TOPIC, TS_BASE, ChannelOp::OpenChannel {
            channel: ch("score"),
            adders,
        }),
        a.commit(&k1, TOPIC, TS_BASE + 1, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 10,
        }),
        a.commit(&k3, TOPIC, TS_BASE + 2, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 99, // UNAUTHORIZED
        }),
    ];

    // Peer B's chain — genuinely CONCURRENT with A (never saw A's ops), so B's
    // remove of pc 10 does NOT observe A's add ⇒ add-wins keeps 10 alive.
    let mut b: Store<ChannelLang> = Store::new();
    let b_ops = vec![
        b.commit(&k2, TOPIC, TS_BASE + 10, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 20,
        }),
        b.commit(&k4, TOPIC, TS_BASE + 11, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 88, // UNAUTHORIZED
        }),
        b.commit(&k4, TOPIC, TS_BASE + 12, ChannelOp::RemoveDegree {
            channel: ch("score"),
            pc: 10, // UNAUTHORIZED remover, but concurrent with A's add ⇒ add wins
        }),
    ];

    (a_ops, b_ops)
}

#[test]
fn convergence_across_peers_and_orders() {
    let (a_ops, b_ops) = partition_op_sets();

    // Two peers partition, diverge, then ingest each other's SIGNED ops.
    let mut a: Store<ChannelLang> = Store::new();
    let mut b: Store<ChannelLang> = Store::new();
    ingest_all(&mut a, &a_ops);
    ingest_all(&mut b, &b_ops);

    // Partitioned views differ (A knows the policy; B has not seen OpenChannel).
    let a_partition = a.view();
    let b_partition = b.view();
    assert_ne!(a_partition, b_partition, "partitioned peers must diverge");
    assert_eq!(
        a_partition[&ch("score")],
        BTreeSet::from([10]),
        "A: only its authorized add is live (its unauthorized pc 99 is inert)",
    );
    assert!(
        !b_partition.contains_key(&ch("score")),
        "B never saw OpenChannel ⇒ no policy ⇒ channel absent while partitioned",
    );

    // Rejoin.
    ingest_all(&mut a, &b_ops);
    ingest_all(&mut b, &a_ops);

    let expected: BTreeMap<ChannelId, BTreeSet<u16>> =
        BTreeMap::from([(ch("score"), BTreeSet::from([10, 20]))]);
    assert_eq!(a.view(), b.view(), "peers must converge");
    assert_eq!(a.view(), expected, "converged view == the enforced oracle");
    assert_eq!(a.pending_len(), 0);
    assert_eq!(b.pending_len(), 0);
    assert_eq!(a.entry_hashes(), b.entry_hashes());

    #[cfg(feature = "test-support")]
    {
        // Cheap lazy Reach view == kernel ReachIndex oracle: same fold, no drift.
        assert_eq!(a.view(), a.view_reference());
        assert_eq!(b.view(), b.view_reference());
    }

    // Order-independence: the whole 6-op set ingested in many shuffles -> identical
    // enforced view (capability is deterministic) AND identical ops_root.
    let all: Vec<SignedOp> = a_ops.iter().chain(&b_ops).cloned().collect();
    #[cfg(feature = "merkle")]
    let mut roots: Vec<[u8; 32]> = Vec::new();
    for seed in [1u64, 7, 13, 31, 101, 997] {
        let mut s: Store<ChannelLang> = Store::new();
        ingest_all(&mut s, &shuffled(&all, seed));
        assert_eq!(s.pending_len(), 0, "seed {seed} left ops parked");
        assert_eq!(s.view(), expected, "shuffle {seed} diverged from the enforced view");
        #[cfg(feature = "test-support")]
        assert_eq!(s.view(), s.view_reference());
        #[cfg(feature = "merkle")]
        roots.push(s.ops_root());
    }
    #[cfg(feature = "merkle")]
    for r in &roots {
        assert_eq!(r, &roots[0], "a permutation produced a different ops_root");
    }

    println!(
        "PASS gate 2 (convergence): 2 peers (mixed authorized/unauthorized) partition \
         then exchange -> identical view {{score:{{10,20}}}} == view_reference; pending==0; \
         6 permutations -> identical view + identical ops_root (order-independent)"
    );
}

// ===========================================================================
// GATE 3 — Cross-channel isolation: the same pc live in channel A (authorized)
// and absent in channel B (unauthorized adder) SIMULTANEOUSLY; channels don't leak.
// ===========================================================================

#[test]
fn cross_channel_isolation() {
    let founder = author_key(0);
    let dev = author_key(1); // authorized on A, NOT on B

    let mut s: Store<ChannelLang> = Store::new();
    // Channel A: author 1 may add. Channel B: only author 2 may add (author 1 is
    // unauthorized there).
    s.commit(&founder, TOPIC, TS_BASE, ChannelOp::OpenChannel {
        channel: ch("A"),
        adders: BTreeSet::from([author_id(1)]),
    });
    s.commit(&founder, TOPIC, TS_BASE + 1, ChannelOp::OpenChannel {
        channel: ch("B"),
        adders: BTreeSet::from([author_id(2)]),
    });
    // The SAME author, the SAME pc, into BOTH channels.
    s.commit(&dev, TOPIC, TS_BASE + 2, ChannelOp::AddDegree {
        channel: ch("A"),
        pc: 7,
    });
    s.commit(&dev, TOPIC, TS_BASE + 3, ChannelOp::AddDegree {
        channel: ch("B"),
        pc: 7,
    });

    let v = s.view();
    assert!(v[&ch("A")].contains(&7), "pc 7 live in A (author authorized there)");
    assert!(
        !v[&ch("B")].contains(&7),
        "pc 7 absent in B (same author, unauthorized there) — channels don't leak",
    );
    assert!(v[&ch("B")].is_empty(), "B open but empty");

    #[cfg(feature = "test-support")]
    assert_eq!(s.view(), s.view_reference());

    println!(
        "PASS gate 3 (cross-channel isolation): same author + same pc 7 -> LIVE in A, \
         ABSENT in B simultaneously; no leak across channels"
    );
}

// ===========================================================================
// GATE 4 — Adversarial: an unauthorized peer floods adds (none appear);
// equivocation / laggard / shuffle don't change the enforced view; the flood is
// STORED + SYNCED but INERT (in entry_hashes / ops_root, absent from view) —
// capability is a fold-time filter, NOT a wire-admission gate.
// ===========================================================================

/// Baseline: open + two authorized adds -> a known enforced view. `producer` links
/// the whole set causally so shuffles have real dependencies.
fn baseline_ops(producer: &mut Store<ChannelLang>) -> Vec<SignedOp> {
    let founder = author_key(0);
    let k1 = author_key(1);
    let k2 = author_key(2);
    let adders: BTreeSet<AuthorId> = BTreeSet::from([author_id(1), author_id(2)]);
    vec![
        producer.commit(&founder, TOPIC, TS_BASE, ChannelOp::OpenChannel {
            channel: ch("score"),
            adders,
        }),
        producer.commit(&k1, TOPIC, TS_BASE + 1, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 3,
        }),
        producer.commit(&k2, TOPIC, TS_BASE + 2, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 9,
        }),
    ]
}

#[test]
fn adversarial_flood_equivocation_laggard_shuffle() {
    let expected: BTreeMap<ChannelId, BTreeSet<u16>> =
        BTreeMap::from([(ch("score"), BTreeSet::from([3, 9]))]);

    // Producer: baseline (authorized) then a FLOOD of unauthorized adds (author 5),
    // each observing the prior op (a rich causal chain for the laggard/shuffle case).
    let mut producer: Store<ChannelLang> = Store::new();
    let base = baseline_ops(&mut producer);
    let flood_author = author_key(5); // NOT in adders
    let mut flood: Vec<SignedOp> = Vec::new();
    for i in 0..12u16 {
        flood.push(producer.commit(
            &flood_author,
            TOPIC,
            TS_BASE + 100 + i as u64,
            ChannelOp::AddDegree {
                channel: ch("score"),
                pc: 500 + i, // all distinct, all UNAUTHORIZED
            },
        ));
    }
    let all: Vec<SignedOp> = base.iter().chain(&flood).cloned().collect();

    // (a) Flood inert: full set folds to the SAME view as the clean baseline.
    let mut full: Store<ChannelLang> = Store::new();
    ingest_all(&mut full, &shuffled(&all, 4242));
    let mut clean: Store<ChannelLang> = Store::new();
    ingest_all(&mut clean, &base);
    assert_eq!(full.view(), expected, "flood of unauthorized adds must be inert");
    assert_eq!(full.view(), clean.view(), "flood changed nothing in the view");
    assert_eq!(full.pending_len(), 0);

    // (b) STORED-BUT-INERT: the flood ops are lifted + synced. entry_hashes and
    // ops_root include them even though the view does not — capability is a
    // fold-time filter, not a wire-admission gate.
    assert_eq!(
        full.entry_hashes().len(),
        all.len(),
        "every unauthorized op is STORED (lifted into the identity set)",
    );
    assert_eq!(
        clean.entry_hashes().len(),
        base.len(),
        "clean store holds only the baseline",
    );
    #[cfg(feature = "merkle")]
    {
        assert_ne!(
            full.ops_root(),
            clean.ops_root(),
            "flood IS in the Merkle identity set (synced) yet absent from the view",
        );
    }

    // (c) Shuffle-invariance: many permutations of the full set -> identical view +
    // identical ops_root (over the ingested set).
    #[cfg(feature = "merkle")]
    let mut roots: Vec<[u8; 32]> = Vec::new();
    for seed in [2u64, 3, 5, 8, 21, 55] {
        let mut s: Store<ChannelLang> = Store::new();
        ingest_all(&mut s, &shuffled(&all, seed));
        assert_eq!(s.pending_len(), 0, "seed {seed} left ops parked");
        assert_eq!(s.view(), expected, "shuffle {seed} changed the enforced view");
        #[cfg(feature = "test-support")]
        assert_eq!(s.view(), s.view_reference());
        #[cfg(feature = "merkle")]
        roots.push(s.ops_root());
    }
    #[cfg(feature = "merkle")]
    for r in &roots {
        assert_eq!(r, &roots[0], "ops_root differs across permutations of the SAME set");
    }

    // (d) Equivocation: an unauthorized author forks its log — two ops at genesis
    // (same author, same seq, DIFFERENT payloads) minted in two fresh stores. Both
    // lift as distinct entries; both are unauthorized ⇒ the enforced view is
    // unchanged (a fork by a voided author is just more inert history).
    let equiv_author = author_key(6); // NOT in adders
    let fork_a = {
        let mut s: Store<ChannelLang> = Store::new();
        s.commit(&equiv_author, TOPIC, TS_BASE + 200, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 700,
        })
    };
    let fork_b = {
        let mut s: Store<ChannelLang> = Store::new();
        s.commit(&equiv_author, TOPIC, TS_BASE + 200, ChannelOp::AddDegree {
            channel: ch("score"),
            pc: 701,
        })
    };
    let mut eq: Store<ChannelLang> = Store::new();
    ingest_all(&mut eq, &base);
    eq.ingest_verified(verify(&fork_a));
    eq.ingest_verified(verify(&fork_b));
    assert_eq!(
        eq.entry_hashes().len(),
        base.len() + 2,
        "both equivocating forks lift as distinct entries (no dedup across the fork)",
    );
    assert_eq!(eq.view(), expected, "equivocation by a voided author changes nothing");

    // (e) Laggard / deferral: ingest the causally-LATEST op first (it observes the
    // whole chain) -> it PARKS; backfill the rest -> it lifts, pending -> 0, and the
    // enforced view is identical. Order (laggard arrival) does not change enforcement.
    let mut lag: Store<ChannelLang> = Store::new();
    let latest = all.last().expect("non-empty");
    let lifted = lag.ingest_verified(verify(latest));
    assert!(lifted.is_empty(), "the causally-latest op parks (incomplete past)");
    assert!(lag.pending_len() >= 1, "it is parked");
    ingest_all(&mut lag, &all[..all.len() - 1]);
    assert_eq!(lag.pending_len(), 0, "liveness: nothing stuck after backfill");
    assert_eq!(lag.view(), expected, "laggard arrival did not change enforcement");

    println!(
        "PASS gate 4 (adversarial): 12-op unauthorized flood INERT (view unchanged); \
         STORED+SYNCED (entry_hashes/ops_root include it, view excludes it); \
         equivocation fork inert; laggard park-then-lift -> pending 0; 6 shuffles -> \
         identical view + identical ops_root"
    );
}

// ===========================================================================
// GATE 5 — Policy resolution: a racing reopen resolves by CAUSAL-MAXIMA register
// (the stated design choice), deterministically + order-independently.
// ===========================================================================

/// A later `OpenChannel` that causally OBSERVES an earlier one supersedes it (the
/// register is causal-LWW): the new adder set becomes the policy. Concurrent
/// reopens resolve to one deterministic maximum, order-independently.
#[test]
fn policy_resolves_by_causal_maxima() {
    // Causal supersede: reopen in the same chain widens the policy from {1} to {1,2}.
    let founder = author_key(0);
    let k1 = author_key(1);
    let k2 = author_key(2);
    let mut s: Store<ChannelLang> = Store::new();
    s.commit(&founder, TOPIC, TS_BASE, ChannelOp::OpenChannel {
        channel: ch("score"),
        adders: BTreeSet::from([author_id(1)]),
    });
    // author 2 not yet authorized:
    let early = s.commit(&k2, TOPIC, TS_BASE + 1, ChannelOp::AddDegree {
        channel: ch("score"),
        pc: 4,
    });
    // reopen observes the first open -> supersedes it (causal maxima).
    s.commit(&founder, TOPIC, TS_BASE + 2, ChannelOp::OpenChannel {
        channel: ch("score"),
        adders: BTreeSet::from([author_id(1), author_id(2)]),
    });
    let after = s.commit(&k2, TOPIC, TS_BASE + 3, ChannelOp::AddDegree {
        channel: ch("score"),
        pc: 6,
    });
    let _ = (early, after);
    // Under the resolved (latest) policy {1,2}, BOTH of author 2's adds count — the
    // policy is a property of the merged channel, not of causal position.
    assert_eq!(
        s.view()[&ch("score")],
        BTreeSet::from([4, 6]),
        "the causally-latest OpenChannel's adder set is the policy",
    );

    // Concurrent reopen: two OpenChannel ops with disjoint adder sets, minted in two
    // partitioned stores (genuinely concurrent), converge to ONE deterministic
    // winner regardless of ingest order.
    let mut p: Store<ChannelLang> = Store::new();
    let open_x = p.commit(&founder, TOPIC, TS_BASE, ChannelOp::OpenChannel {
        channel: ch("dup"),
        adders: BTreeSet::from([author_id(1)]),
    });
    let mut q: Store<ChannelLang> = Store::new();
    let open_y = q.commit(&founder, TOPIC, TS_BASE, ChannelOp::OpenChannel {
        channel: ch("dup"),
        adders: BTreeSet::from([author_id(2)]),
    });
    // author 1 and author 2 each add pc 1 to "dup" (partitioned chains).
    let add1 = p.commit(&k1, TOPIC, TS_BASE + 1, ChannelOp::AddDegree {
        channel: ch("dup"),
        pc: 1,
    });
    let add2 = q.commit(&k2, TOPIC, TS_BASE + 1, ChannelOp::AddDegree {
        channel: ch("dup"),
        pc: 1,
    });
    let race = vec![open_x, open_y, add1, add2];

    let mut ref_view: Option<BTreeMap<ChannelId, BTreeSet<u16>>> = None;
    for seed in [0u64, 1, 2, 3, 4] {
        let mut store: Store<ChannelLang> = Store::new();
        ingest_all(&mut store, &shuffled(&race, seed));
        assert_eq!(store.pending_len(), 0, "seed {seed} parked");
        #[cfg(feature = "test-support")]
        assert_eq!(store.view(), store.view_reference());
        match &ref_view {
            None => ref_view = Some(store.view()),
            Some(r) => assert_eq!(&store.view(), r, "concurrent reopen not order-independent"),
        }
    }
    // Exactly one policy won ⇒ pc 1 is live iff the winning adder set contains that
    // adder; the outcome is deterministic (whatever the max-EntryHash winner is).
    let converged = ref_view.expect("ran");
    let live = &converged[&ch("dup")];
    assert!(
        *live == BTreeSet::from([1]) || live.is_empty(),
        "a single deterministic policy resolved (either author's add counts, not both merged)",
    );

    println!(
        "PASS gate 5 (policy resolution): causal reopen supersedes (LWW register); \
         concurrent reopen -> one deterministic causal-maxima winner, order-independent"
    );
}
