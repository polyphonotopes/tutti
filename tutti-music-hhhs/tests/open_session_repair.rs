//! Multi-peer convergence for the authenticated-channel/open-authority profile.

use std::collections::BTreeSet;

use futures::executor::block_on;
use hhhs::{DagRead, Digest};
use hhhs_replica::{ReplicaRepairHost, ReplicaRepairSnapshot};
use hhhs_store::MemoryStorage;
use hhhs_sync::{EntrySource, RepairHost, entry_set_root};
use tutti_music::{
    MusicOp, RoundTableConfig, RoundTablePitchMode, RoundTableScale, TunedDegree,
    TunedPeriodicPitch, Tuning,
};
use tutti_music_hhhs::{ActorId, MusicReplica, author_open, initialize_open, materialize_open};

fn repair_all(source: &MusicReplica<MemoryStorage>, target: &MusicReplica<MemoryStorage>) {
    let snapshot: ReplicaRepairSnapshot = ReplicaRepairHost::new(source.clone())
        .capture([0x44; 16])
        .unwrap();
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for entry in source.snapshot().history.entries_topo() {
        records.extend(snapshot.bytes_with_closure(&entry.hash(), &mut seen));
    }
    let mut target = ReplicaRepairHost::new(target.clone());
    let report = block_on(target.apply(&records)).unwrap();
    assert!(report.refused.is_empty());
}

fn root(replica: &MusicReplica<MemoryStorage>) -> [u8; 32] {
    let hashes: BTreeSet<_> = replica
        .snapshot()
        .history
        .entries_topo()
        .into_iter()
        .map(|entry| entry.hash())
        .collect();
    entry_set_root(hashes)
}

#[test]
fn open_session_peers_repair_concurrent_music_without_signatures() {
    let namespace = Digest::of(b"tutti open-session two-board repair");
    let first = initialize_open(namespace, MemoryStorage::new()).unwrap();
    let second = initialize_open(namespace, MemoryStorage::new()).unwrap();
    let first_actor = ActorId::from_bytes([1; 32]);
    let second_actor = ActorId::from_bytes([2; 32]);
    let tuning = Tuning::twelve_tet();
    let low = TunedDegree::new(&tuning, 2).unwrap();
    let high = TunedDegree::new(&tuning, 9).unwrap();

    author_open(
        &first,
        namespace,
        first_actor,
        MusicOp::AddDegree { degree: low },
    )
    .unwrap();
    author_open(
        &second,
        namespace,
        second_actor,
        MusicOp::AddDegree { degree: high },
    )
    .unwrap();

    repair_all(&first, &second);
    repair_all(&second, &first);
    let expected = BTreeSet::from([low, high]);
    assert_eq!(
        materialize_open(&first.snapshot().history, namespace).live,
        expected
    );
    assert_eq!(
        materialize_open(&second.snapshot().history, namespace).live,
        expected
    );
    assert_eq!(root(&first), root(&second));

    author_open(
        &first,
        namespace,
        first_actor,
        MusicOp::RemoveDegree { degree: low },
    )
    .unwrap();
    repair_all(&first, &second);
    assert_eq!(
        materialize_open(&second.snapshot().history, namespace).live,
        BTreeSet::from([high])
    );
    assert_eq!(root(&first), root(&second));
}

#[test]
fn any_peer_can_remove_a_shared_pitch_and_concurrent_add_still_wins() {
    let namespace = Digest::of(b"tutti shared pitch cross-peer editing");
    let first = initialize_open(namespace, MemoryStorage::new()).unwrap();
    let second = initialize_open(namespace, MemoryStorage::new()).unwrap();
    let first_actor = ActorId::from_bytes([0x21; 32]);
    let second_actor = ActorId::from_bytes([0x22; 32]);
    let pitch = TunedPeriodicPitch::new(&Tuning::twelve_tet(), 7, 0).unwrap();

    author_open(&first, namespace, first_actor, MusicOp::AddPitch { pitch }).unwrap();
    repair_all(&first, &second);

    // A removal by another actor observes and clears the first actor's add.
    author_open(
        &second,
        namespace,
        second_actor,
        MusicOp::RemovePitch { pitch },
    )
    .unwrap();
    repair_all(&second, &first);
    assert!(
        materialize_open(&first.snapshot().history, namespace)
            .shared_pitches
            .pitches
            .is_empty()
    );

    // A genuinely concurrent add is not observed by this remove, so add-wins.
    author_open(&first, namespace, first_actor, MusicOp::AddPitch { pitch }).unwrap();
    author_open(
        &second,
        namespace,
        second_actor,
        MusicOp::RemovePitch { pitch },
    )
    .unwrap();
    repair_all(&first, &second);
    repair_all(&second, &first);
    assert_eq!(
        materialize_open(&first.snapshot().history, namespace)
            .shared_pitches
            .pitches,
        BTreeSet::from([pitch])
    );

    // Once the second peer has observed that add, it can turn the note off.
    author_open(
        &second,
        namespace,
        second_actor,
        MusicOp::RemovePitch { pitch },
    )
    .unwrap();
    repair_all(&second, &first);
    assert!(
        materialize_open(&first.snapshot().history, namespace)
            .shared_pitches
            .pitches
            .is_empty()
    );
    assert_eq!(root(&first), root(&second));
}

#[test]
fn round_table_settings_converge_as_durable_hhhs_state() {
    let namespace = Digest::of(b"tutti durable round-table settings");
    let first = initialize_open(namespace, MemoryStorage::new()).unwrap();
    let second = initialize_open(namespace, MemoryStorage::new()).unwrap();
    let first_actor = ActorId::from_bytes([0x31; 32]);
    let second_actor = ActorId::from_bytes([0x32; 32]);
    let left = RoundTableConfig {
        pitch_mode: RoundTablePitchMode::Random,
        center_millihz: 72_000,
        scale: RoundTableScale::Dorian,
        ..RoundTableConfig::default()
    };
    let mut right_pattern = RoundTableConfig::default().pattern;
    right_pattern = right_pattern.toggled(60).unwrap();
    let right = RoundTableConfig {
        pitch_mode: RoundTablePitchMode::Ascending,
        pattern: right_pattern,
        center_millihz: 96_000,
        spread_semitones: 9,
        ..RoundTableConfig::default()
    };

    author_open(
        &first,
        namespace,
        first_actor,
        MusicOp::SetRoundTable { config: left },
    )
    .unwrap();
    author_open(
        &second,
        namespace,
        second_actor,
        MusicOp::SetRoundTable { config: right },
    )
    .unwrap();
    repair_all(&first, &second);
    repair_all(&second, &first);

    let first_view = materialize_open(&first.snapshot().history, namespace);
    let second_view = materialize_open(&second.snapshot().history, namespace);
    assert_eq!(first_view.round_table, second_view.round_table);
    let mut left_settings = left;
    left_settings.pattern = RoundTableConfig::default().pattern.cleared();
    let mut right_settings = right;
    right_settings.pattern = RoundTableConfig::default().pattern.cleared();
    assert!([left_settings, right_settings].contains(&first_view.round_table));
    assert!(first_view.round_table.pattern.is_empty());
    assert_eq!(root(&first), root(&second));
}
