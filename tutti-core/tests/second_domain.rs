//! A SECOND, deliberately non-musical [`OpLanguage`] instantiation, driven end-to-
//! end through `Store<KvLang>`, plus the substrate conformance suite (design §2.2).
//!
//! The domain is a collaborative **key/value register store** — the cheapest real
//! evidence that the tutti-core seam is genuinely generic (design §6.1: "genuinely
//! reusable vs. walkie-masquerading-as-generic"), not walkie wearing a trait. It
//! reuses EXACTLY the machinery walkie's `with_registers` uses (observed-remove +
//! causal-maxima via `FoldCtx::resolve`) but with zero musical content: no tuning,
//! no pitches, no pieces — `Op = KvOp::{Set,Del}`, `View = BTreeMap<String,String>`.
//!
//! Every associated const is KvLang's OWN value, DISTINCT from walkie's, proving
//! nothing generic is hardcoded to a walkie literal.
//!
//! Determinism note: all randomness is a seeded SplitMix64 (below). No `Date::now`,
//! no `rand` — permutations are reproducible so a convergence failure is a bug, not
//! a flake.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

// Fix #1 (closed): `EntryHash` — the KEY type of `FoldCtx::decoded()` and the
// argument type of `is_ancestor`/`resolve` — is now re-exported by tutti-core, so
// a downstream domain names the fold's candidate key through `tutti_core` WITHOUT
// a direct, rev-pinned `hhhs` dependency. This whole file spells it via
// `tutti_core::EntryHash`; the `entry_hash_nameable_via_tutti_core` test pins it.
use tutti_core::EntryHash;

use tutti_core::{
    LogHead, OpLanguage, OpVerifyError, SignedOp, SignedOpWireError, Store, VerifiedOpG,
    VersionedOpG, sign_versioned_op, signing_key_from_seed, verify_signed_op_in,
};
use tutti_core::{FoldCtx, SigningKey};

// ===========================================================================
// The second OpLanguage: a collaborative key/value register store. Zero music.
// ===========================================================================

/// The KV op alphabet. A `Set` writes a value to a key; a `Del` writes a tombstone.
/// BOTH are register writes to the same per-key slot — last-writer-wins is resolved
/// causally, never by wall-clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum KvOp {
    Set { key: String, val: String },
    Del { key: String },
}

/// Domain well-formedness bounds — KvLang's OWN caps, unrelated to any walkie value.
const MAX_KEY_BYTES: usize = 128;
const MAX_VAL_BYTES: usize = 4096;

/// The second `OpLanguage` instantiation.
struct KvLang;

impl OpLanguage for KvLang {
    type Op = KvOp;
    type View = BTreeMap<String, String>;

    // Every const below is KvLang's own, and every one differs from walkie's
    // (walkie: SCHEMA_VERSION=3, ENTRY_FRAME_MAGIC=b"walkie.hhhs.signed-op/1",
    //  WIRE_MAGIC=b"walkie.signed-op/3\0", MAX_PAYLOAD_BYTES=1 MiB).
    const SCHEMA_VERSION: u16 = 1;
    const ENTRY_FRAME_MAGIC: &'static [u8] = b"tutti.kv.entry/1";
    const WIRE_MAGIC: &'static [u8] = b"tutti.kv.wire/1\0";
    const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

    fn validate_wire(op: &KvOp) -> Result<(), String> {
        let key = match op {
            KvOp::Set { key, .. } | KvOp::Del { key } => key,
        };
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(format!("key must be 1..={MAX_KEY_BYTES} UTF-8 bytes"));
        }
        if let KvOp::Set { val, .. } = op {
            if val.len() > MAX_VAL_BYTES {
                return Err(format!("value exceeds {MAX_VAL_BYTES} UTF-8 bytes"));
            }
        }
        Ok(())
    }

    /// Last-writer-wins per key = observed-remove + causal-maxima, EXACTLY walkie's
    /// register machinery (`with_registers`): every `Set`/`Del` on a key is a
    /// candidate; `ctx.resolve` drops any candidate strictly in another's causal
    /// past (superseded) and breaks the surviving concurrent maxima by max raw-bytes
    /// `EntryHash`. A `Set` winner materializes its value; a `Del` winner leaves the
    /// key absent. Reads ancestry ONLY through the erased `FoldCtx` combinators — no
    /// walkie type, no music, in sight.
    fn fold(ctx: &FoldCtx<'_, Self>) -> Self::View {
        let mut writes: BTreeMap<String, BTreeSet<EntryHash>> = BTreeMap::new();
        for (entry, decoded) in ctx.decoded() {
            let key = match decoded.op() {
                KvOp::Set { key, .. } | KvOp::Del { key } => key,
            };
            writes.entry(key.clone()).or_default().insert(*entry);
        }

        let mut view = BTreeMap::new();
        for (key, candidates) in &writes {
            if let Some(winner) = ctx.resolve(candidates) {
                if let KvOp::Set { val, .. } = ctx.decoded()[&winner].op() {
                    view.insert(key.clone(), val.clone());
                }
                // A `Del` winner supersedes: the key stays absent.
            }
        }
        view
    }
}

/// A THIRD toy `OpLanguage` that stands in for "another tutti domain" (walkie's
/// role) at the FRAME boundary, so the cross-domain-separation tests need no
/// dependency on walkie. Its frame consts are walkie's OWN literals —
/// `WIRE_MAGIC == tutti_core::SIGNED_OP_WIRE_MAGIC` and `MAX_PAYLOAD_BYTES == 1
/// MiB` — so `to_wire_bytes_in::<OtherLang>` is byte-identical to walkie's
/// crate-const `to_wire_bytes`, and a KvLang<->OtherLang frame rejection IS the
/// walkie<->kv rejection. The fold/view are inert; only the frame consts matter.
struct OtherLang;

impl OpLanguage for OtherLang {
    type Op = KvOp;
    type View = ();

    const SCHEMA_VERSION: u16 = 3;
    const ENTRY_FRAME_MAGIC: &'static [u8] = b"walkie.hhhs.signed-op/1";
    // Exactly walkie's wire marker + payload ceiling (WalkieLang's own values).
    const WIRE_MAGIC: &'static [u8] = tutti_core::SIGNED_OP_WIRE_MAGIC;
    const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

    fn validate_wire(_op: &KvOp) -> Result<(), String> {
        Ok(())
    }

    fn fold(_ctx: &FoldCtx<'_, Self>) -> Self::View {}
}

// ===========================================================================
// Deterministic test harness — seeded SplitMix64, no Date::now / no rand crate.
// ===========================================================================

const TOPIC: &str = "kv-domain-conformance";
const TS_BASE: u64 = 1_700_000_000_000_000; // µs

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

fn author_key(i: usize) -> SigningKey {
    signing_key_from_seed(&[(i as u8) + 1; 32])
}

/// Verify + ingest a slice of signed ops in the order given.
fn ingest_all(store: &mut Store<KvLang>, ops: &[SignedOp]) {
    for signed in ops {
        let verified: VerifiedOpG<KvLang> =
            verify_signed_op_in::<KvLang>(signed).expect("op verifies");
        store.ingest_verified(verified);
    }
}

/// Build a rich cross-author verified op-set by committing into ONE producer store,
/// so each op's `observed` frontier really links the other authors' ops (genuine
/// cross-author causality, not independent per-author chains). Returns the signed
/// bytes in causal-commit order plus the producer's own materialized view.
fn build_op_set(seed: u64, authors: usize, count: usize) -> (Vec<SignedOp>, BTreeMap<String, String>) {
    let keys: Vec<SigningKey> = (0..authors).map(author_key).collect();
    let vocab = ["alpha", "beta", "gamma", "delta", "epsilon"];
    let mut store: Store<KvLang> = Store::new();
    let mut rng = Rng::new(seed);
    let mut signed = Vec::with_capacity(count);
    for step in 0..count {
        let key = &keys[rng.below(authors)];
        let slot = vocab[rng.below(vocab.len())].to_string();
        let op = if rng.next_u64() % 4 == 0 {
            KvOp::Del { key: slot }
        } else {
            KvOp::Set {
                key: slot,
                val: format!("v{}", rng.below(1000)),
            }
        };
        signed.push(store.commit(key, TOPIC, TS_BASE + step as u64, op));
    }
    (signed, store.view())
}

// ===========================================================================
// Property 1 — Convergence: same verified op-set, different arrival orders,
// interleaved from >=2 authors -> identical view().
// ===========================================================================

#[test]
fn convergence_across_orders_and_authors() {
    let (ops, expected) = build_op_set(0xC0FFEE, 3, 200);
    assert!(!expected.is_empty(), "producer view must be non-trivial");

    // Two fresh stores ingest the SAME verified op-set in DIFFERENT shuffles.
    let mut a: Store<KvLang> = Store::new();
    let mut b: Store<KvLang> = Store::new();
    ingest_all(&mut a, &shuffled(&ops, 1));
    ingest_all(&mut b, &shuffled(&ops, 999_983));

    // Full causal closure present -> nothing parked, and the views match each other
    // AND the producer (order-independent lift).
    assert_eq!(a.pending_len(), 0);
    assert_eq!(b.pending_len(), 0);
    assert_eq!(a.view(), b.view());
    assert_eq!(a.view(), expected);
    assert_eq!(a.entry_hashes(), b.entry_hashes());

    // The cheap lazy `Reach` view equals the kernel `ReachIndex` reference oracle:
    // the SAME KvLang::fold on both ancestry backends, no drift (test-support).
    #[cfg(feature = "test-support")]
    {
        assert_eq!(a.view(), a.view_reference());
        assert_eq!(b.view(), b.view_reference());
    }

    println!("PASS property 1 (convergence): 200 ops / 3 authors, 2 orders -> identical view");
}

// ===========================================================================
// Property 2 — Determinism / out-of-order: many permutations of one op-set ->
// identical view() AND identical ops_root() (feature merkle).
// ===========================================================================

#[test]
fn determinism_over_permutations() {
    let (ops, expected) = build_op_set(0xD37E12, 4, 160);

    let mut views: Vec<BTreeMap<String, String>> = Vec::new();
    #[cfg(feature = "merkle")]
    let mut roots: Vec<[u8; 32]> = Vec::new();

    for seed in [2, 3, 5, 7, 11, 13, 17, 19] {
        let mut store: Store<KvLang> = Store::new();
        ingest_all(&mut store, &shuffled(&ops, seed));
        assert_eq!(store.pending_len(), 0, "seed {seed} left ops parked");
        views.push(store.view());
        #[cfg(feature = "merkle")]
        roots.push(store.ops_root());
    }

    for view in &views {
        assert_eq!(view, &expected, "a permutation diverged from the producer view");
    }
    #[cfg(feature = "merkle")]
    for root in &roots {
        assert_eq!(root, &roots[0], "a permutation produced a different ops_root");
    }

    println!("PASS property 2 (determinism): 8 permutations -> identical view + identical ops_root");
}

// ===========================================================================
// Property 3 — root <=> set: ops_root() equality iff entry-hash-set equality;
// a different op-set yields a different root (feature merkle).
// ===========================================================================

#[cfg(feature = "merkle")]
#[test]
fn ops_root_iff_entry_set() {
    let (ops, _) = build_op_set(0x5E7, 3, 120);

    // Same set, two orders -> equal entry-hash set AND equal root.
    let mut full_a: Store<KvLang> = Store::new();
    let mut full_b: Store<KvLang> = Store::new();
    ingest_all(&mut full_a, &shuffled(&ops, 41));
    ingest_all(&mut full_b, &shuffled(&ops, 42));
    assert_eq!(full_a.entry_hashes(), full_b.entry_hashes());
    assert_eq!(full_a.ops_root(), full_b.ops_root(), "equal set must give equal root");

    // Drop the causally-latest op (no dependents) -> the rest all lift, so the set
    // differs by exactly one entry, and the root MUST differ.
    let subset: Store<KvLang> = {
        let mut s: Store<KvLang> = Store::new();
        ingest_all(&mut s, &shuffled(&ops[..ops.len() - 1], 43));
        s
    };
    assert_eq!(subset.pending_len(), 0, "dropping the latest op should not park the rest");
    assert_eq!(subset.entry_hashes().len(), full_a.entry_hashes().len() - 1);
    assert_ne!(subset.entry_hashes(), full_a.entry_hashes());
    assert_ne!(subset.ops_root(), full_a.ops_root(), "different set must give different root");

    // sync_root (the weaker digest) tracks the same identity set: same predicate.
    assert_eq!(full_a.sync_root(), full_b.sync_root());
    assert_ne!(subset.sync_root(), full_a.sync_root());

    println!("PASS property 3 (root<=>set): equal set == equal root; -1 op => different root");
}

// ===========================================================================
// Property 4 — Deferral liveness: an op whose `observed` arrives late parks, then
// lifts on backfill (strict deferral + drain). Mirrors walkie's liveness invariant.
// ===========================================================================

#[test]
fn deferral_parks_then_lifts_on_backfill() {
    // Author A commits first; author B then commits observing the producer frontier
    // (which contains A's op), so B's only causal prev is A's op id.
    let ka = author_key(0);
    let kb = author_key(1);
    let mut producer: Store<KvLang> = Store::new();
    let signed_a = producer.commit(&ka, TOPIC, TS_BASE, KvOp::Set {
        key: "alpha".into(),
        val: "1".into(),
    });
    let signed_b = producer.commit(&kb, TOPIC, TS_BASE + 1, KvOp::Set {
        key: "beta".into(),
        val: "2".into(),
    });

    let vb = verify_signed_op_in::<KvLang>(&signed_b).expect("b verifies");
    assert!(!vb.observed().is_empty(), "B must observe A for this to test deferral");

    // Ingest B FIRST: its `observed` references A, which is not lifted -> it PARKS.
    let mut store: Store<KvLang> = Store::new();
    let lifted = store.ingest_verified(vb);
    assert!(lifted.is_empty(), "B must park (its causal past is incomplete)");
    assert_eq!(store.pending_len(), 1);
    assert!(store.entry_hashes().is_empty(), "a parked op is not materialized");
    assert!(store.view().is_empty());

    // Backfill A: A lifts, and the drain immediately unblocks B.
    let va = verify_signed_op_in::<KvLang>(&signed_a).expect("a verifies");
    let lifted = store.ingest_verified(va);
    assert_eq!(lifted.len(), 2, "ingesting A lifts A and drains B");
    assert_eq!(store.pending_len(), 0, "liveness: nothing stuck after backfill");
    assert_eq!(store.entry_hashes().len(), 2);
    assert_eq!(store.view(), producer.view());
    assert_eq!(
        store.view(),
        BTreeMap::from([("alpha".into(), "1".into()), ("beta".into(), "2".into())]),
    );

    println!("PASS property 4 (deferral liveness): parked op lifts on backfill, pending -> 0");
}

// ===========================================================================
// Property 5 — Sign/verify through the generic path: a KvOp signs, frames, and
// verifies; a tampered payload fails; an out-of-bounds op fails validate_wire.
// ===========================================================================

#[test]
fn sign_frame_verify_and_tamper() {
    let ka = author_key(0);
    let mut store: Store<KvLang> = Store::new();
    let signed = store.commit(&ka, TOPIC, TS_BASE, KvOp::Set {
        key: "greeting".into(),
        val: "hello".into(),
    });

    // Framing round-trips losslessly through the length-delimited wire frame.
    let wire = signed.to_wire_bytes().expect("frames");
    let recovered = SignedOp::from_wire_bytes(&wire).expect("unframes");
    assert_eq!(recovered, signed);

    // The generic verifier accepts it and recovers the exact decoded op.
    let verified = verify_signed_op_in::<KvLang>(&recovered).expect("verifies");
    assert_eq!(
        verified.payload(),
        &KvOp::Set { key: "greeting".into(), val: "hello".into() },
    );
    assert_eq!(verified.topic(), Some(TOPIC));

    // Tampering ANY payload byte breaks the body-hash/signature binding -> reject.
    let mut tampered = signed.clone();
    let mid = tampered.payload.len() / 2;
    tampered.payload[mid] ^= 0xFF;
    assert!(
        verify_signed_op_in::<KvLang>(&tampered).is_err(),
        "a tampered payload must fail verification",
    );

    // Domain well-formedness runs at ingress: an empty key is rejected by
    // KvLang::validate_wire (signed via prepare_commit, which does not pre-validate).
    let bad = store.prepare_commit(&ka, TOPIC, TS_BASE + 1, KvOp::Set {
        key: String::new(),
        val: "x".into(),
    });
    assert!(
        matches!(verify_signed_op_in::<KvLang>(&bad), Err(OpVerifyError::InvalidDomain(_))),
        "empty key must fail validate_wire",
    );

    println!("PASS property 5 (sign/verify): frame round-trips; tamper + bad-domain rejected");
}

// ===========================================================================
// Fix #2 — cross-domain FRAME separation: `to_wire_bytes_in`/`from_wire_bytes_in`
// thread `L::WIRE_MAGIC`, so a frame written by one tutti domain is REFUSED by
// another domain's deframe (`WrongDomain`) — two domains no longer accept each
// other's frames. `OtherLang` is walkie's frame consts, so this IS walkie<->kv.
// ===========================================================================

#[test]
fn cross_domain_frames_refuse_each_other() {
    let ka = author_key(0);
    let mut store: Store<KvLang> = Store::new();
    let signed = store.commit(&ka, TOPIC, TS_BASE, KvOp::Set {
        key: "greeting".into(),
        val: "hello".into(),
    });

    // A KvLang-tagged frame round-trips through KvLang's own deframe...
    let kv_framed = signed.to_wire_bytes_in::<KvLang>().expect("kv frames");
    assert_eq!(
        SignedOp::from_wire_bytes_in::<KvLang>(&kv_framed).expect("kv deframes its own frame"),
        signed,
    );
    // ...but the OTHER domain (walkie's magic) REFUSES it distinctly.
    assert_eq!(
        SignedOp::from_wire_bytes_in::<OtherLang>(&kv_framed),
        Err(SignedOpWireError::WrongDomain),
        "a KvLang frame must be refused by another domain's deframe",
    );

    // Vice-versa: an OtherLang(=walkie-magic) frame is refused by KvLang's deframe.
    let other_framed = signed.to_wire_bytes_in::<OtherLang>().expect("other frames");
    assert_eq!(
        SignedOp::from_wire_bytes_in::<KvLang>(&other_framed),
        Err(SignedOpWireError::WrongDomain),
        "a walkie-magic frame must be refused by KvLang's deframe",
    );

    // BYTE-IDENTICAL FOR WALKIE: OtherLang's frame (walkie's consts) equals the
    // crate-const `to_wire_bytes` walkie's transports emit, byte for byte.
    assert_eq!(
        other_framed,
        signed.to_wire_bytes().expect("crate-const frames"),
        "walkie-magic domain frame must equal the crate-const frame",
    );

    println!(
        "PASS fix #2 (frame separation): KvLang<->walkie frames refuse each other (WrongDomain)"
    );
}

// ===========================================================================
// Fix #3 — consistent size ladder: `to_wire_bytes_in::<L>` validates the payload
// against `L::MAX_PAYLOAD_BYTES` (matching `verify_signed_op_in`), not the crate
// 1 MiB. A payload over KvLang's 64 KiB but under walkie's 1 MiB is rejected at
// KV frame time AND at KV verify, yet frames fine under walkie's cap.
// ===========================================================================

#[test]
fn kv_frame_and_verify_share_the_payload_ceiling() {
    let ka = author_key(0);

    // Sign a KvOp whose CBOR payload lands in the (64 KiB, 1 MiB) window. `sign`
    // does NOT run `validate_wire`, so an oversize value can be constructed here.
    let big_val = "x".repeat(200 * 1024);
    let versioned = VersionedOpG::<KvLang>::current_for_topic(
        KvOp::Set { key: "k".into(), val: big_val },
        TS_BASE,
        TOPIC,
    );
    let (signed, _advanced) = sign_versioned_op::<KvLang>(&ka, &LogHead::genesis(), versioned);

    assert!(
        signed.payload.len() > KvLang::MAX_PAYLOAD_BYTES,
        "payload must exceed KvLang's 64 KiB cap",
    );
    assert!(
        signed.payload.len() < 1024 * 1024,
        "payload must be under walkie's 1 MiB cap",
    );

    // KvLang frame time rejects it against KvLang's 64 KiB ceiling (fix #3).
    assert!(
        matches!(
            signed.to_wire_bytes_in::<KvLang>(),
            Err(SignedOpWireError::PayloadTooLarge { max, .. }) if max == KvLang::MAX_PAYLOAD_BYTES
        ),
        "KV frame must reject a >64 KiB payload against L::MAX_PAYLOAD_BYTES",
    );

    // KvLang VERIFY rejects it with the SAME ceiling — framing and verify agree.
    assert!(
        matches!(
            verify_signed_op_in::<KvLang>(&signed),
            Err(OpVerifyError::PayloadTooLarge { max, .. }) if max == KvLang::MAX_PAYLOAD_BYTES
        ),
        "KV verify must reject against the same L::MAX_PAYLOAD_BYTES ceiling",
    );

    // Under walkie's 1 MiB cap the SAME bytes frame fine -> the ladder is per-domain.
    assert!(
        signed.to_wire_bytes_in::<OtherLang>().is_ok(),
        "the same payload must frame fine under walkie's 1 MiB cap",
    );

    println!(
        "PASS fix #3 (size ladder): KvLang frame+verify share the 64 KiB ceiling; walkie accepts"
    );
}

// ===========================================================================
// Fix #1 — `EntryHash` is nameable through `tutti_core`, so a downstream fold
// collects `BTreeSet<EntryHash>` candidates without a direct hhhs rev pin.
// ===========================================================================

#[test]
fn entry_hash_nameable_via_tutti_core() {
    // The candidate key type resolves through `tutti_core` (see top-of-file import,
    // used by KvLang::fold). A store's identity set is exactly this type:
    let hashes: BTreeSet<tutti_core::EntryHash> = Store::<KvLang>::new().entry_hashes();
    assert!(hashes.is_empty());

    // And it is the very same type hhhs defines — a re-export, not a newtype
    // (this fn only type-checks if `tutti_core::EntryHash == hhhs::EntryHash`).
    fn _same_type(h: tutti_core::EntryHash) -> hhhs::EntryHash {
        h
    }
    let _ = _same_type;

    println!("PASS fix #1 (EntryHash re-export): nameable via tutti_core::EntryHash");
}
