//! Generic Merkle commitment / proof layer over the entry-hash identity set
//! (feature `merkle`).
//!
//! [`ops_root_of`] is a canonical [`radix_immutable`] Merkle trie keyed by the
//! **entry hash** of every lifted op. Its input is exactly the store's
//! `entry_to_source.keys()` — the *same* identity set
//! [`sync_root_of`](crate::store::sync_root_of) digests — so the two commitments
//! can never skew. Root equality iff entry-set equality, **plus** O(log n)
//! inclusion / non-inclusion proofs ([`prove_op`] + standalone
//! [`radix_immutable::verify`]).
//!
//! This is the domain-agnostic half of the M2 Merkle work: the key *is* the op's
//! cryptographic identity, so no domain view is involved. The `state_root` over a
//! canonical view (`L::View: Canonical`) is NOT here yet — it stays walkie-facing
//! until the canonical-view bound is wired.
//!
//! Both roots are recomputed on demand from the store's existing maps rather than
//! maintained in a persistent trie field. At room scale this is microseconds, and
//! — decisively — recomputing `ops_root` from the same `entry_to_source.keys()`
//! iterator `sync_root_of` consumes makes skew between the two commitments
//! structurally impossible.

use hhhs_dag::EntryHash;
use radix_immutable::{BytesKeyConverter, Proof, Trie};

/// The `ops_root` trie: key = 32-byte entry hash, value = `()` (presence only).
///
/// Presence-only leaves (`ValueToBytes for () == b""`) suffice because the key
/// *is* the op's cryptographic identity; the value carries no extra information.
pub type OpsTrie = Trie<[u8; 32], (), BytesKeyConverter<[u8; 32]>>;

/// Build the `ops_root` trie from an entry-hash identity set.
///
/// Feed it `entry_to_source.keys()` so the committed set is byte-for-byte the set
/// `sync_root_of` digests. Insertion order is irrelevant — the trie shape (and
/// thus the root) is a pure function of the final key set.
pub fn ops_trie<'a>(hashes: impl IntoIterator<Item = &'a EntryHash>) -> OpsTrie {
    let mut trie = OpsTrie::new_bytes_key();
    for hash in hashes {
        trie = trie.insert(*hash.as_bytes(), ());
    }
    trie
}

/// The `ops_root`: a canonical blake3-256 Merkle commitment to the entry-hash set.
pub fn ops_root_of<'a>(hashes: impl IntoIterator<Item = &'a EntryHash>) -> [u8; 32] {
    ops_trie(hashes).merkle_root()
}

/// An inclusion / non-inclusion proof for `entry` against `ops_root_of(hashes)`.
///
/// Verify standalone (no store) with
/// `radix_immutable::verify(&root, entry.as_bytes(), Some(&[]), &proof)` for an
/// inclusion (the `()` value encodes to empty bytes), or
/// `radix_immutable::verify(&root, entry.as_bytes(), None, &proof)` for a
/// non-inclusion.
pub fn prove_op<'a>(hashes: impl IntoIterator<Item = &'a EntryHash>, entry: &EntryHash) -> Proof {
    ops_trie(hashes).prove(entry.as_bytes())
}
