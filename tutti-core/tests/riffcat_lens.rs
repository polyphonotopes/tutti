//! A **provable riff-cat lens** — a convergence-preserving projection (coercion)
//! from a tutti **pitch-set** to a **pitch-class-set** and a **transposition-
//! invariant set-class**, driven end-to-end through the REAL tutti-core substrate.
//! This is the isolated tutti demonstration of M4's "riff-cat provable lenses
//! (projections/coercions into PCSs)".
//!
//! ## The two layers
//!
//! 1. **The substrate layer** — a music [`OpLanguage`] (`RiffLang`), a FIFTH
//!    instantiation modelled EXACTLY on `crates/tutti-core/tests/second_domain.rs`
//!    (the KV register template), `crates/tutti-core/tests/channel_algebra.rs`, and
//!    `tutti-amy/src/music.rs` (`MusicLang`'s add-wins observed-remove pitch-set).
//!    `Op = { AddDegree{degree}, RemoveDegree{degree} }`, `View = BTreeSet<u16>` —
//!    the live tutti **pitch-set** (raw scale degrees, possibly multi-octave, i.e.
//!    `>= edo`), folded add-wins over `Store<RiffLang>` through the substrate's OWN
//!    `commit` / `ingest_verified` / `view()` / `view_reference()` /
//!    `FoldCtx::{decoded,is_ancestor}`. No production-code change: the whole
//!    demonstration lives in this test file.
//!
//! 2. **The lens layer** — PURE functions over the folded view:
//!    * [`pitch_set_to_pcs`] — the coercion **PS ↠ PCS**: fold every pitch to its
//!      pitch CLASS (`mod edo`). Many-to-one (octave collapse) ⇒ NOT invertible.
//!    * [`pcs_to_set_class`] — the coercion **PCS ↠ set-class**: the transposition-
//!      AND-inversion-invariant **prime form**, a canonical representative of the
//!      dihedral orbit. Many-to-one (major and minor triads share one class) ⇒ NOT
//!      invertible.
//!
//! The composite `set_class ∘ pcs ∘ view` is the lens whose laws are proven below.
//!
//! ## Provenance of the definitions (honest sourcing)
//!
//! The user's riff-catalog is present at `/laboratory/fe-stuff/riff-catalog`; its
//! **cubical music instance** `cubical/Riffcat/Music.agda` is the cited source for
//! the set-class normal form. That module defines, and machine-checks by `refl`:
//!   * pitch-class sets as characteristic vectors (a bitmask over `Z_edo`);
//!   * **transposition** = the `Z/n` cyclic action (`rotate1` / `transpose`);
//!   * **inversion** = the dihedral mirror `pc ↦ (n − pc) mod n` (`invertI`);
//!   * the **Rahn packing order** (`msbLE`/`rahnLE`/`rahnMin`): read the
//!     characteristic vector as an integer with pitch class `n−1` the MOST
//!     significant bit and prefer the SMALLER integer — "most compact, packed
//!     inward from the right";
//!   * `transNormalForm` = the integer-minimal transposition (the `Tn` normal form);
//!   * `primeForm p = rahnMin (transNormalForm p) (transNormalForm (invert p))` —
//!     the set-class prime form; `p ~SC q ≜ primeForm p ≡ primeForm q`.
//!
//! [`prime_form`] below is a faithful port of that algorithm: [`rahn_le`] is the
//! MSB-first `msbLE ∘ rev` comparison verbatim; [`trans_normal_form`] and
//! [`prime_form`] are `transNormalForm`/`primeForm`. riff-cat FIXES the octave at 12
//! divisions; the ONLY generalization here is edo-parametricity (`Z_edo`, so 31-EDO
//! works), which the min-bitmask rule admits unchanged. The
//! [`grounding_reproduces_riffcat_forte_prime_forms`] test reproduces every one of
//! Music.agda's `refl`-checked values (Forte 3-11 `[0,3,7]`, 3-12 `[0,4,8]`, 4-26
//! `[0,3,5,8]`, and the 3-11A/3-11B `Tn` split) — pinning our port to riff-cat's
//! published convention. Everything else (the add-wins fold, the convergence
//! harness) is standard tutti/CRDT, self-contained; there is NO `riff-catalog`
//! crate dependency.
//!
//! ## Honest scope (what this proves, and what it does not)
//!
//! This proves the *coercion* PS ↠ PCS ↠ set-class **commutes with eventual-
//! consistency convergence** and satisfies the **projection / retraction /
//! transposition-invariance** laws, adversarially, over the real signed-op DAG. The
//! FULLER lens algebra — arbitrary projections, coercion-ON-WRITE ("constraint-lens
//! channels" that rewrite each add at ingress), the Lean-machine-checked laws,
//! riff-cat's cubical set-quotient HIT + computing-transport, and the
//! inversional/multiplicative equivalence lattice — is left for co-design. Here the
//! set-class already folds inversion (dihedral prime form); the `Tn`-only projection
//! is exercised only as the finer relation that refines it.
//!
//! Determinism note: all randomness is a seeded SplitMix64 (below). No `Date::now`,
//! no `rand` — permutations are reproducible, so a convergence failure is a bug.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use tutti_core::EntryHash;
use tutti_core::{
    FoldCtx, OpLanguage, SignedOp, SigningKey, Store, VerifiedOpG, signing_key_from_seed,
    verify_signed_op_in,
};

// ===========================================================================
// The music OpLanguage: an add-wins observed-remove pitch-set (the tutti substrate
// leaf the lens sits atop). Modelled on tutti-amy's MusicLang, minus envelopes.
// ===========================================================================

/// The op alphabet. `AddDegree` asserts a raw scale **degree** (a step in the room's
/// EDO — possibly `>= edo`, i.e. a multi-octave pitch) into the room's live
/// pitch-set; `RemoveDegree` retracts it. Both COMMUTE — the fold resolves them
/// causally, add-wins, never by wall-clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum RiffOp {
    /// Assert scale degree `degree` into the pitch-set.
    AddDegree { degree: u16 },
    /// Retract scale degree `degree`. Only cancels the adds it causally observed.
    RemoveDegree { degree: u16 },
}

/// Domain well-formedness bound — `RiffLang`'s OWN cap. Generous enough for a
/// multi-octave microtonal pitch-set (matches tutti-amy `MusicLang::MAX_DEGREE`).
const MAX_DEGREE: u16 = 4096;

/// The music `OpLanguage`. Its consts are all its OWN, distinct from walkie's, the
/// KV domain's, the channel domain's, and MusicLang's — nothing generic is hardcoded
/// to a literal.
struct RiffLang;

impl OpLanguage for RiffLang {
    type Op = RiffOp;
    /// The live tutti **pitch-set**: raw scale degrees, folded add-wins. This is the
    /// domain of the lens.
    type View = BTreeSet<u16>;

    const SCHEMA_VERSION: u16 = 1;
    const ENTRY_FRAME_MAGIC: &'static [u8] = b"tutti.riffcat.entry/1";
    const WIRE_MAGIC: &'static [u8] = b"tutti.riffcat.wire/1\0";
    const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

    fn validate_wire(op: &RiffOp) -> Result<(), String> {
        match op {
            RiffOp::AddDegree { degree } | RiffOp::RemoveDegree { degree } => {
                if *degree >= MAX_DEGREE {
                    return Err(format!("degree {degree} exceeds MAX_DEGREE={MAX_DEGREE}"));
                }
            }
        }
        Ok(())
    }

    /// Add-wins observed-remove pitch-set — EXACTLY tutti-amy `MusicLang`'s degree
    /// semantics and the `store.rs` smoke fold: a degree is live iff SOME `Add` for
    /// it is not causally observed (`is_ancestor`) by ANY `Remove` for it. A
    /// `Remove` cancels only the adds in its causal past; a concurrent add survives.
    /// Reads ancestry ONLY through the erased `FoldCtx`.
    fn fold(ctx: &FoldCtx<'_, Self>) -> BTreeSet<u16> {
        let mut adds: BTreeMap<u16, Vec<EntryHash>> = BTreeMap::new();
        let mut removes: BTreeMap<u16, Vec<EntryHash>> = BTreeMap::new();
        for (entry, decoded) in ctx.decoded() {
            match decoded.op() {
                RiffOp::AddDegree { degree } => adds.entry(*degree).or_default().push(*entry),
                RiffOp::RemoveDegree { degree } => {
                    removes.entry(*degree).or_default().push(*entry)
                }
            }
        }

        let mut live = BTreeSet::new();
        for (degree, add_ops) in &adds {
            let rem_ops = removes.get(degree).map(Vec::as_slice).unwrap_or(&[]);
            let survives = add_ops
                .iter()
                .any(|a| !rem_ops.iter().any(|r| ctx.is_ancestor(a, r)));
            if survives {
                live.insert(*degree);
            }
        }
        live
    }
}

// ===========================================================================
// THE LENS LAYER — pure functions over the folded pitch-set.
//
// PS ↠ PCS ↠ set-class. Each arrow is a many-to-one coercion (a projection), not
// an isomorphism. `pcs_to_set_class` is a genuine retraction onto prime forms.
// ===========================================================================

/// **PS ↠ PCS.** Fold every raw pitch/degree to its pitch CLASS (`mod edo`). The
/// coercion that collapses octaves: distinct pitch-sets that agree up to octave map
/// to the SAME pitch-class-set, so this is NOT invertible.
fn pitch_set_to_pcs(view: &BTreeSet<u16>, edo: u16) -> BTreeSet<u16> {
    view.iter()
        .map(|&degree| (degree as u32 % edo as u32) as u16)
        .collect()
}

/// A **set-class**: the canonical prime-form pitch-class signature (sorted, always
/// starting at 0). The transposition-and-inversion-invariant address of a pitch-
/// class-set. This is riff-cat's `SetClass = Pcs / ~SC` representative — the value
/// `primeForm` returns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SetClass(Vec<u16>);

/// **PCS ↠ set-class.** The transposition-AND-inversion-invariant **prime form**
/// (riff-cat `cubical/Riffcat/Music.agda :: primeForm`). Many-to-one (all 24
/// transpositions/inversions of a chord share it) ⇒ NOT invertible; idempotent as a
/// retraction (the prime form of a prime form is itself).
fn pcs_to_set_class(pcs: &BTreeSet<u16>, edo: u16) -> SetClass {
    SetClass(prime_form(pcs, edo))
}

/// The whole lens in one shot: `set_class ∘ pcs ∘ view`.
fn set_class_of_pitch_set(view: &BTreeSet<u16>, edo: u16) -> SetClass {
    pcs_to_set_class(&pitch_set_to_pcs(view, edo), edo)
}

// --- The riff-cat prime-form algorithm (a faithful port of Music.agda). ---

/// The `Z/n` transposition action: shift every pitch class up by `k` (`mod edo`).
/// riff-cat `transpose` (iterated `rotate1`).
fn transpose(pcs: &BTreeSet<u16>, k: u16, edo: u16) -> BTreeSet<u16> {
    pcs.iter()
        .map(|&p| ((p as u32 + k as u32) % edo as u32) as u16)
        .collect()
}

/// The dihedral inversion generator `I`: `pc ↦ (edo − pc) mod edo` (0 fixed). riff-
/// cat `invertI` (`rev` differs only by a transposition, so both give one set-class).
fn invert(pcs: &BTreeSet<u16>, edo: u16) -> BTreeSet<u16> {
    pcs.iter()
        .map(|&p| ((edo as u32 - p as u32) % edo as u32) as u16)
        .collect()
}

/// The **Rahn packing order** `a ≤ b`: read each characteristic vector as an integer
/// with pitch class `edo−1` the MOST significant bit, and prefer the SMALLER integer.
/// A faithful, overflow-free port of Music.agda's `rahnLE a b = msbLE (rev a) (rev
/// b)` — compare MSB-first (highest pitch class down): at the first pitch class where
/// membership differs, the set that HAS it is the larger integer. "Most compact,
/// packed inward from the right."
fn rahn_le(a: &BTreeSet<u16>, b: &BTreeSet<u16>, edo: u16) -> bool {
    let mut pc = edo;
    while pc > 0 {
        pc -= 1;
        let (ain, bin) = (a.contains(&pc), b.contains(&pc));
        if ain && !bin {
            return false; // a has the higher bit ⇒ a > b
        }
        if !ain && bin {
            return true; // b has the higher bit ⇒ a < b
        }
    }
    true // identical characteristic vectors ⇒ a ≤ b
}

/// The **transposition normal form** (`Tn`-type): the integer-minimal transposition
/// over the `edo` rotations. riff-cat `transNormalForm`. Always contains pitch class
/// 0 (transposing any representative down by its least element strictly lowers the
/// integer), so its sorted form is canonical.
fn trans_normal_form(pcs: &BTreeSet<u16>, edo: u16) -> BTreeSet<u16> {
    if pcs.is_empty() {
        return BTreeSet::new();
    }
    let mut best: Option<BTreeSet<u16>> = None;
    for k in 0..edo {
        let cand = transpose(pcs, k, edo);
        match &best {
            Some(b) if !rahn_le(&cand, b, edo) => {}
            _ => best = Some(cand),
        }
    }
    best.expect("non-empty pcs has at least one transposition")
}

/// The set-class **prime form**: `rahnMin (transNormalForm p) (transNormalForm
/// (invert p))`, returned as a sorted `Vec<u16>` starting at 0. riff-cat `primeForm`
/// — the canonical representative of the dihedral (T/I) orbit.
fn prime_form(pcs: &BTreeSet<u16>, edo: u16) -> Vec<u16> {
    let tnf = trans_normal_form(pcs, edo);
    let inv_tnf = trans_normal_form(&invert(pcs, edo), edo);
    let chosen = if rahn_le(&tnf, &inv_tnf, edo) { tnf } else { inv_tnf };
    chosen.into_iter().collect()
}

// ===========================================================================
// Deterministic harness — seeded SplitMix64, no Date::now / no rand crate.
// ===========================================================================

const TOPIC: &str = "tutti-riffcat-lens";
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

fn verify(signed: &SignedOp) -> VerifiedOpG<RiffLang> {
    verify_signed_op_in::<RiffLang>(signed).expect("a signed riffcat op verifies")
}

/// Verify + ingest a slice of signed ops in the order given.
fn ingest_all(store: &mut Store<RiffLang>, ops: &[SignedOp]) {
    for signed in ops {
        store.ingest_verified(verify(signed));
    }
}

fn add(degree: u16) -> RiffOp {
    RiffOp::AddDegree { degree }
}
fn rem(degree: u16) -> RiffOp {
    RiffOp::RemoveDegree { degree }
}

fn set<const N: usize>(xs: [u16; N]) -> BTreeSet<u16> {
    xs.into_iter().collect()
}

// ===========================================================================
// GROUNDING — reproduce riff-catalog's cubical/Riffcat/Music.agda refl-checked
// prime forms, pinning our port to the published (Rahn) convention. edo = 12.
// ===========================================================================

/// Every prime form Music.agda checks by `refl`, recomputed here. If any of these
/// drift, the port has diverged from riff-cat's convention.
#[test]
fn grounding_reproduces_riffcat_forte_prime_forms() {
    let edo = 12;

    // The set-class (T/I) prime forms — Music.agda `primeForm ... ≡ ...`.
    // C major {0,4,7}, A minor {0,4,9}, C minor {0,3,7}, G major {2,7,11} all land
    // on Forte 3-11, prime form [0,3,7] (the headline collapse).
    assert_eq!(prime_form(&set([0, 4, 7]), edo), vec![0, 3, 7], "C major → 3-11");
    assert_eq!(prime_form(&set([0, 4, 9]), edo), vec![0, 3, 7], "A minor → 3-11");
    assert_eq!(prime_form(&set([0, 3, 7]), edo), vec![0, 3, 7], "C minor → 3-11");
    assert_eq!(prime_form(&set([2, 7, 11]), edo), vec![0, 3, 7], "G major → 3-11");
    // Non-collapse: the augmented triad is Forte 3-12, prime form [0,4,8].
    assert_eq!(prime_form(&set([0, 4, 8]), edo), vec![0, 4, 8], "aug → 3-12");
    // The PACKING-RULE witness: the minor seventh {0,4,7,9} is Forte 4-26, whose
    // compact prime form is [0,3,5,8] (NOT the lex-least [0,2,5,9]) — the exact case
    // riff-cat's engine `prime_form` fix pinned.
    assert_eq!(
        prime_form(&set([0, 4, 7, 9]), edo),
        vec![0, 3, 5, 8],
        "minor 7th → 4-26 (compact [0,3,5,8], not lex [0,2,5,9])",
    );

    // The A/B distinction at the FINER Tn level: major and minor are DISTINCT
    // transposition classes (3-11B [0,4,7] vs 3-11A [0,3,7]) — the inversion the
    // set-class prime form folds. `~T` refines `~SC`.
    let major_tnf: Vec<u16> = trans_normal_form(&set([0, 4, 7]), edo).into_iter().collect();
    let minor_tnf: Vec<u16> = trans_normal_form(&set([0, 4, 9]), edo).into_iter().collect();
    assert_eq!(major_tnf, vec![0, 4, 7], "major Tn = 3-11B");
    assert_eq!(minor_tnf, vec![0, 3, 7], "minor Tn = 3-11A");
    assert_ne!(major_tnf, minor_tnf, "Tn keeps major/minor apart (A/B)…");
    // …yet the set-class prime form merges them (inversion folded).
    assert_eq!(
        pcs_to_set_class(&set([0, 4, 7]), edo),
        pcs_to_set_class(&set([0, 4, 9]), edo),
        "…but ~SC merges major and minor (Forte 3-11)",
    );

    println!(
        "PASS grounding (riff-cat Music.agda): 3-11 [0,3,7] (maj/min/Gmaj collapse), \
         3-12 [0,4,8] (aug non-collapse), 4-26 [0,3,5,8] (packing-rule witness); \
         Tn A/B split 3-11B [0,4,7] vs 3-11A [0,3,7] folded by ~SC"
    );
}

// ===========================================================================
// GATE 1 — THE LENS COMMUTES WITH CONVERGENCE (the substrate claim).
//
// Two Store<RiffLang> peers partition, diverge, then ingest each other's SIGNED ops
// → not only view()==view(), but pitch_set_to_pcs(view) and pcs_to_set_class(...)
// are IDENTICAL across peers AND order-independent across ingest permutations. The
// lens of a converged state is a deterministic function of the op-SET. view_reference
// is the oracle.
// ===========================================================================

/// Peer A builds a multi-octave C-major pitch-set; peer B adds the remaining chord
/// tones (also across octaves) and momentarily a passing tone it then retracts. The
/// converged pitch-set folds to PCS {0,4,7} ⇒ set-class [0,3,7] (Forte 3-11).
/// Returns (A's ops, B's ops).
fn triad_partition_op_sets() -> (Vec<SignedOp>, Vec<SignedOp>) {
    let (ka, kb) = (author_key(0), author_key(1));

    // A: pitch classes 0 and 4, each doubled an octave up (12, 16) → the fold to PCS
    // is genuinely many-to-one (octave collapse).
    let mut a: Store<RiffLang> = Store::new();
    let a_ops = vec![
        a.commit(&ka, TOPIC, TS_BASE, add(0)),
        a.commit(&ka, TOPIC, TS_BASE + 1, add(4)),
        a.commit(&ka, TOPIC, TS_BASE + 2, add(12)), // pc 0, octave up
        a.commit(&ka, TOPIC, TS_BASE + 3, add(16)), // pc 4, octave up
    ];

    // B (concurrent chain): pc 7 doubled (7, 19), plus a passing tone (degree 3)
    // added then removed WITHIN B's chain (observed remove ⇒ 3 dies).
    let mut b: Store<RiffLang> = Store::new();
    let b_ops = vec![
        b.commit(&kb, TOPIC, TS_BASE + 10, add(7)),
        b.commit(&kb, TOPIC, TS_BASE + 11, add(19)), // pc 7, octave up
        b.commit(&kb, TOPIC, TS_BASE + 12, add(3)),
        b.commit(&kb, TOPIC, TS_BASE + 13, rem(3)), // observed ⇒ 3 absent
    ];

    (a_ops, b_ops)
}

#[test]
fn lens_commutes_with_convergence() {
    let edo = 12;
    let (a_ops, b_ops) = triad_partition_op_sets();

    let mut a: Store<RiffLang> = Store::new();
    let mut b: Store<RiffLang> = Store::new();
    ingest_all(&mut a, &a_ops);
    ingest_all(&mut b, &b_ops);

    // Partitioned: the peers' pitch-sets AND their lensed set-classes differ.
    assert_ne!(a.view(), b.view(), "partitioned peers must diverge (pitch-set)");
    assert_ne!(
        set_class_of_pitch_set(&a.view(), edo),
        set_class_of_pitch_set(&b.view(), edo),
        "…and their lensed set-classes differ while partitioned",
    );

    // Rejoin: exchange signed ops.
    ingest_all(&mut a, &b_ops);
    ingest_all(&mut b, &a_ops);

    // Converged pitch-set (add-wins union, passing tone 3 gone).
    let expected_ps = set([0, 4, 7, 12, 16, 19]);
    assert_eq!(a.view(), b.view(), "peers converge (pitch-set)");
    assert_eq!(a.view(), expected_ps, "converged pitch-set == oracle");
    assert_eq!(a.pending_len(), 0);
    assert_eq!(b.pending_len(), 0);

    // THE LENS COMMUTES: PS ↠ PCS ↠ set-class is identical across the two peers.
    let pcs_a = pitch_set_to_pcs(&a.view(), edo);
    let pcs_b = pitch_set_to_pcs(&b.view(), edo);
    assert_eq!(pcs_a, pcs_b, "PCS identical across converged peers");
    assert_eq!(pcs_a, set([0, 4, 7]), "PCS == {{0,4,7}} (octaves collapsed)");
    let sc_a = pcs_to_set_class(&pcs_a, edo);
    let sc_b = pcs_to_set_class(&pcs_b, edo);
    assert_eq!(sc_a, sc_b, "set-class identical across converged peers");
    assert_eq!(sc_a, SetClass(vec![0, 3, 7]), "set-class == Forte 3-11 [0,3,7]");

    // The lens of view() equals the lens of the kernel oracle view_reference() — the
    // SAME fold on the Θ(N²) kernel index, no drift.
    #[cfg(feature = "test-support")]
    {
        assert_eq!(a.view(), a.view_reference());
        assert_eq!(b.view(), b.view_reference());
        assert_eq!(
            set_class_of_pitch_set(&a.view_reference(), edo),
            sc_a,
            "lens over the kernel oracle matches",
        );
    }

    // ORDER-INDEPENDENCE: the whole 8-op set ingested in many shuffles → identical
    // pitch-set, identical PCS, identical set-class, and (merkle) identical ops_root.
    // The lens is a deterministic function of the op-SET, not of arrival order.
    let all: Vec<SignedOp> = a_ops.iter().chain(&b_ops).cloned().collect();
    #[cfg(feature = "merkle")]
    let mut roots: Vec<[u8; 32]> = Vec::new();
    for seed in [1u64, 7, 13, 31, 101, 997] {
        let mut s: Store<RiffLang> = Store::new();
        ingest_all(&mut s, &shuffled(&all, seed));
        assert_eq!(s.pending_len(), 0, "seed {seed} left ops parked");
        assert_eq!(s.view(), expected_ps, "shuffle {seed} diverged (pitch-set)");
        assert_eq!(pitch_set_to_pcs(&s.view(), edo), set([0, 4, 7]), "shuffle {seed} PCS");
        assert_eq!(
            set_class_of_pitch_set(&s.view(), edo),
            SetClass(vec![0, 3, 7]),
            "shuffle {seed} set-class",
        );
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
        "PASS gate 1 (lens commutes with convergence): 2 peers partition → converge to \
         pitch-set {{0,4,7,12,16,19}}; lens identical across peers (PCS {{0,4,7}}, \
         set-class 3-11 [0,3,7]) == lens∘view_reference; 6 permutations → identical \
         PCS + set-class + ops_root (order-independent)"
    );
}

// ===========================================================================
// GATE 2 — PROJECTION / RETRACTION LAWS.
//
// (a) pcs_to_set_class is IDEMPOTENT as a retraction (prime-form of a prime form =
//     itself). (b) The coercion direction: PS-equal ⇒ PCS-equal ⇒ set-class-equal.
// (c) NOT invertible: distinct pitch-sets share a PCS; distinct PCS share a
//     set-class — a lens/coercion, not an iso.
// ===========================================================================

#[test]
fn projection_retraction_and_noninvertibility() {
    let edo = 12;

    // --- (a) RETRACTION IDEMPOTENCE: r(r(x)) = r(x). ---
    // The set-class of any pcs is a prime form; feeding that prime form back through
    // the lens returns the SAME set-class. Checked over many chords AND at edo 31.
    for chord in [
        vec![0, 4, 7],
        vec![0, 4, 9],
        vec![2, 5, 9, 11],
        vec![0, 1, 2, 3, 4],
        vec![0, 4, 7, 9],
        vec![3, 6, 8],
    ] {
        for &edo in &[12u16, 31] {
            let pcs: BTreeSet<u16> = chord.iter().map(|&p| p % edo).collect();
            let sc = pcs_to_set_class(&pcs, edo);
            // The prime form is itself a valid pcs; re-normalizing is a no-op.
            let sc_again = pcs_to_set_class(&sc.0.iter().copied().collect(), edo);
            assert_eq!(sc, sc_again, "retraction not idempotent for {chord:?} @ edo {edo}");
            // A prime form always starts at 0 (canonical).
            assert_eq!(sc.0.first(), Some(&0), "prime form must start at 0");
        }
    }

    // --- (b) THE COERCION DIRECTION: PS= ⇒ PCS= ⇒ set-class=. ---
    // Two DISTINCT pitch-sets that agree mod-edo have equal PCS, hence equal
    // set-class (functions are deterministic; the arrows compose).
    let ps1 = set([0, 4, 7]);
    let ps2 = set([12, 16, 19]); // same chord an octave up — distinct pitch-set
    assert_ne!(ps1, ps2, "the two pitch-sets are genuinely distinct");
    assert_eq!(
        pitch_set_to_pcs(&ps1, edo),
        pitch_set_to_pcs(&ps2, edo),
        "octave-equal pitch-sets ⇒ equal PCS (PS ↠ PCS coerces)",
    );
    assert_eq!(
        pcs_to_set_class(&pitch_set_to_pcs(&ps1, edo), edo),
        pcs_to_set_class(&pitch_set_to_pcs(&ps2, edo), edo),
        "equal PCS ⇒ equal set-class (PCS ↠ set-class coerces)",
    );

    // --- (c) NON-INVERTIBILITY (both arrows are strictly many-to-one). ---
    // PS ↠ PCS: distinct pitch-sets share a PCS (already shown: ps1 ≠ ps2, same PCS).
    // A third witness folding the same:
    let ps3 = set([0, 4, 7, 12]); // adds a doubled pc 0
    assert_ne!(ps3, ps1);
    assert_eq!(pitch_set_to_pcs(&ps3, edo), pitch_set_to_pcs(&ps1, edo), "PS↠PCS not injective");

    // PCS ↠ set-class: distinct pitch-class-sets share a set-class. C major {0,4,7}
    // and A minor {0,4,9} are DIFFERENT PCS but ONE set-class (Forte 3-11) — the
    // dihedral fold. So the coercion cannot be inverted.
    let pcs_major = set([0, 4, 7]);
    let pcs_minor = set([0, 4, 9]);
    assert_ne!(pcs_major, pcs_minor, "C major and A minor are distinct pitch-class-sets");
    assert_eq!(
        pcs_to_set_class(&pcs_major, edo),
        pcs_to_set_class(&pcs_minor, edo),
        "…yet one set-class (Forte 3-11) ⇒ PCS ↠ set-class not injective",
    );
    // And a genuine NON-collapse guards against a degenerate (constant) lens: the
    // augmented triad is a DIFFERENT set-class, so the retraction is non-trivial.
    assert_ne!(
        pcs_to_set_class(&set([0, 4, 8]), edo),
        pcs_to_set_class(&pcs_major, edo),
        "augmented (3-12) ≠ major (3-11): the lens is not constant",
    );

    println!(
        "PASS gate 2 (projection/retraction): pcs_to_set_class idempotent (prime-form of \
         a prime-form = itself, edo 12 & 31); PS= ⇒ PCS= ⇒ set-class=; NON-invertible \
         both arrows (octave-equal pitch-sets share PCS; C-maj vs A-min share set-class \
         3-11) with aug/maj a checked non-collapse"
    );
}

// ===========================================================================
// GATE 3 — TRANSPOSITION (and INVERSION) INVARIANCE.
//
// Transposing every degree by any k (mod edo) leaves pcs_to_set_class UNCHANGED (the
// riff-cat invariant), at edo 12 AND 31. Inversion invariance too: the prime form
// folds the dihedral I generator, so pcs_to_set_class(invert(pcs)) == the original.
// ===========================================================================

#[test]
fn transposition_and_inversion_invariance() {
    for &edo in &[12u16, 31] {
        // A handful of representative chords at this edo.
        let chords: Vec<BTreeSet<u16>> = [
            vec![0, 4, 7],
            vec![0, 3, 7],
            vec![0, 4, 8],
            vec![0, 4, 7, 9],
            vec![0, 5, 10, 18],
        ]
        .into_iter()
        .map(|c| c.into_iter().filter(|&p| p < edo).collect())
        .collect();

        for pcs in &chords {
            let base = pcs_to_set_class(pcs, edo);

            // TRANSPOSITION invariance: EVERY k in 0..edo leaves the set-class fixed.
            for k in 0..edo {
                let t = transpose(pcs, k, edo);
                assert_eq!(
                    pcs_to_set_class(&t, edo),
                    base,
                    "transposition by {k} changed the set-class @ edo {edo} for {pcs:?}",
                );
            }

            // INVERSION invariance: the dihedral I generator leaves it fixed too.
            let inv = invert(pcs, edo);
            assert_eq!(
                pcs_to_set_class(&inv, edo),
                base,
                "inversion changed the set-class @ edo {edo} for {pcs:?}",
            );

            // And T∘I (invert then transpose) — the full dihedral orbit is one class.
            for k in 0..edo {
                let ti = transpose(&inv, k, edo);
                assert_eq!(pcs_to_set_class(&ti, edo), base, "T∘I orbit not one class");
            }
        }
    }

    // End-to-end through the substrate: two peers whose pitch material differs by a
    // constant transposition converge to DIFFERENT pitch-sets and PCS, but the SAME
    // set-class — the invariant survives the real fold.
    let edo = 12;
    let (ka, kb) = (author_key(3), author_key(4));
    let mut plain: Store<RiffLang> = Store::new();
    let mut shifted: Store<RiffLang> = Store::new();
    for (i, &d) in [0u16, 4, 7].iter().enumerate() {
        plain.commit(&ka, TOPIC, TS_BASE + i as u64, add(d));
        shifted.commit(&kb, TOPIC, TS_BASE + i as u64, add((d + 5) % edo)); // T5
    }
    assert_ne!(plain.view(), shifted.view(), "the transposed pitch-sets differ");
    assert_ne!(
        pitch_set_to_pcs(&plain.view(), edo),
        pitch_set_to_pcs(&shifted.view(), edo),
        "…and their PCS differ",
    );
    assert_eq!(
        set_class_of_pitch_set(&plain.view(), edo),
        set_class_of_pitch_set(&shifted.view(), edo),
        "…yet one set-class (transposition-invariant through the substrate)",
    );

    println!(
        "PASS gate 3 (transposition/inversion invariance): pcs_to_set_class fixed under \
         all edo transpositions, under inversion, and the full T∘I dihedral orbit \
         (edo 12 & 31); end-to-end, a T5-shifted peer keeps the same set-class"
    );
}

// ===========================================================================
// GATE 4 — ADVERSARIAL: laggards / equivocation / shuffled arrival keep the lensed
// view + set-class deterministic; a microtonal EDO (31) still yields a well-defined
// pc-set + set-class (fractional-free at the pc level).
// ===========================================================================

/// Baseline: a producer commits a linked chain folding to PCS {0,4,7}. Returns the
/// ops and the producer's own lensed set-class (the oracle both adversaries target).
fn baseline_triad_ops() -> (Vec<SignedOp>, SetClass) {
    let (ka, kb) = (author_key(0), author_key(1));
    let mut p: Store<RiffLang> = Store::new();
    let ops = vec![
        p.commit(&ka, TOPIC, TS_BASE, add(0)),
        p.commit(&kb, TOPIC, TS_BASE + 1, add(4)),
        p.commit(&ka, TOPIC, TS_BASE + 2, add(7)),
        p.commit(&kb, TOPIC, TS_BASE + 3, add(19)), // pc 7 doubled
    ];
    (ops, set_class_of_pitch_set(&p.view(), 12))
}

#[test]
fn adversarial_laggard_equivocation_shuffle_microtonal() {
    let edo = 12;
    let (base, oracle_sc) = baseline_triad_ops();
    assert_eq!(oracle_sc, SetClass(vec![0, 3, 7]), "baseline lenses to 3-11");

    // --- (a) SHUFFLED ARRIVAL: many permutations → identical lens. ---
    #[cfg(feature = "merkle")]
    let mut roots: Vec<[u8; 32]> = Vec::new();
    for seed in [2u64, 3, 5, 8, 21, 55] {
        let mut s: Store<RiffLang> = Store::new();
        ingest_all(&mut s, &shuffled(&base, seed));
        assert_eq!(s.pending_len(), 0, "seed {seed} parked");
        assert_eq!(set_class_of_pitch_set(&s.view(), edo), oracle_sc, "shuffle {seed} lens");
        #[cfg(feature = "test-support")]
        assert_eq!(s.view(), s.view_reference());
        #[cfg(feature = "merkle")]
        roots.push(s.ops_root());
    }
    #[cfg(feature = "merkle")]
    for r in &roots {
        assert_eq!(r, &roots[0], "ops_root differs across permutations of the same set");
    }

    // --- (b) LAGGARD / deferral: ingest the causally-LATEST op first → it PARKS;
    //     backfill the rest → it lifts, pending → 0, and the lens is unchanged. ---
    let mut lag: Store<RiffLang> = Store::new();
    let latest = base.last().expect("non-empty");
    let lifted = lag.ingest_verified(verify(latest));
    assert!(lifted.is_empty(), "the causally-latest op parks (incomplete past)");
    assert!(lag.pending_len() >= 1, "it is parked");
    ingest_all(&mut lag, &base[..base.len() - 1]);
    assert_eq!(lag.pending_len(), 0, "liveness: nothing stuck after backfill");
    assert_eq!(
        set_class_of_pitch_set(&lag.view(), edo),
        oracle_sc,
        "laggard arrival did not change the lens",
    );

    // --- (c) EQUIVOCATION absorbed by the coercion: an author FORKS its genesis log
    //     (same author + same seq, DIFFERENT payloads) in two fresh stores. Both
    //     forks add OCTAVE-EQUIVALENTS of pc 0 (degrees 12 and 24), so they lift as
    //     TWO distinct entries yet the PCS — hence the set-class — is UNCHANGED: the
    //     PS ↠ PCS coercion collapses the equivocation. Two peers ingest the forks in
    //     opposite orders and agree. ---
    let equiv = author_key(9);
    let fork_a = {
        let mut s: Store<RiffLang> = Store::new();
        s.commit(&equiv, TOPIC, TS_BASE + 100, add(12)) // pc 0
    };
    let fork_b = {
        let mut s: Store<RiffLang> = Store::new();
        s.commit(&equiv, TOPIC, TS_BASE + 100, add(24)) // pc 0, different octave
    };

    let mut peer_x: Store<RiffLang> = Store::new();
    let mut peer_y: Store<RiffLang> = Store::new();
    ingest_all(&mut peer_x, &base);
    ingest_all(&mut peer_y, &base);
    // Opposite fork-arrival orders.
    peer_x.ingest_verified(verify(&fork_a));
    peer_x.ingest_verified(verify(&fork_b));
    peer_y.ingest_verified(verify(&fork_b));
    peer_y.ingest_verified(verify(&fork_a));

    assert_eq!(
        peer_x.entry_hashes().len(),
        base.len() + 2,
        "both equivocating forks lift as distinct entries (no dedup across the fork)",
    );
    assert_eq!(peer_x.view(), peer_y.view(), "peers converge under equivocation (pitch-set)");
    assert_eq!(
        set_class_of_pitch_set(&peer_x.view(), edo),
        set_class_of_pitch_set(&peer_y.view(), edo),
        "…and agree on the lensed set-class",
    );
    assert_eq!(
        set_class_of_pitch_set(&peer_x.view(), edo),
        oracle_sc,
        "the coercion ABSORBS the equivocation: set-class still 3-11 (pc 0 doubled)",
    );

    // --- (d) MICROTONAL EDO (31): a well-defined pc-set + set-class, fractional-free
    //     at the pc level. Two peers partition a 31-EDO near-just triad across octaves
    //     then converge. ---
    let edo31 = 31;
    let (km, kn) = (author_key(5), author_key(6));
    let mut m: Store<RiffLang> = Store::new();
    let mut n: Store<RiffLang> = Store::new();
    // A 31-EDO near-just major triad: steps 0, 10, 18 — with octave doublings 31, 41
    // (= 0, 10 mod 31) so the fold is many-to-one microtonally too.
    let m_ops = vec![
        m.commit(&km, TOPIC, TS_BASE, add(0)),
        m.commit(&km, TOPIC, TS_BASE + 1, add(10)),
        m.commit(&km, TOPIC, TS_BASE + 2, add(31)), // pc 0
    ];
    let n_ops = vec![
        n.commit(&kn, TOPIC, TS_BASE + 10, add(18)),
        n.commit(&kn, TOPIC, TS_BASE + 11, add(41)), // pc 10
    ];
    ingest_all(&mut m, &m_ops);
    ingest_all(&mut n, &n_ops);
    ingest_all(&mut m, &n_ops);
    ingest_all(&mut n, &m_ops);

    assert_eq!(m.view(), n.view(), "31-EDO peers converge (pitch-set)");
    assert_eq!(m.pending_len(), 0);
    assert_eq!(n.pending_len(), 0);
    let pcs31 = pitch_set_to_pcs(&m.view(), edo31);
    assert_eq!(pcs31, set([0, 10, 18]), "31-EDO PCS is integer (fractional-free)");
    // Every pitch class is a well-defined integer in 0..31.
    assert!(pcs31.iter().all(|&p| p < edo31), "pcs live in Z_31");
    let sc31 = pcs_to_set_class(&pcs31, edo31);
    assert_eq!(sc31.0.first(), Some(&0), "31-EDO set-class prime form starts at 0");
    // The 31-EDO set-class is transposition-invariant like the 12-EDO one.
    let shifted31 = transpose(&pcs31, 7, edo31);
    assert_eq!(
        pcs_to_set_class(&shifted31, edo31),
        sc31,
        "31-EDO set-class transposition-invariant",
    );
    assert_eq!(sc31, SetClass(vec![0, 8, 18]), "31-EDO near-just triad set-class [0,8,18]");

    println!(
        "PASS gate 4 (adversarial): 6 shuffles → identical set-class + ops_root; laggard \
         park-then-lift → pending 0, lens unchanged; equivocation fork (2 distinct \
         entries) ABSORBED by PS↠PCS (set-class still 3-11); 31-EDO peers converge to \
         integer PCS {{0,10,18}}, set-class [0,8,18], transposition-invariant"
    );
}
