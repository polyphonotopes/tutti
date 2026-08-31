//! End-to-end Tutti qualification of the upstream hhhs-session fast path.
//!
//! The session predicts compact authenticated pitch-set edits, then reifies
//! the exact edits through the ordinary Tutti music Replica. Durable
//! materialization and repair remain authoritative. There is deliberately no
//! Tutti-local session manifest, replay window, packet MAC, or recovery state
//! machine in this test.

use std::collections::BTreeSet;

use futures::executor::block_on;
use hhhs::{DagRead, Digest, EntryHash};
use hhhs_cap::{Area, CapabilitySnapshot, Receiver, Right};
use hhhs_proof::{Ed25519Verifier, SigningKey};
use hhhs_replica::{AdmissionRequest, ReplicaRecord, ReplicaRepairHost};
use hhhs_session::{
    AllowedMessageClasses, CausalContext, CausalReadiness, DirectedSessionBinding,
    DurableProjection, DurableProjectionHorizon, EventClass, FoundationProfileId,
    ProjectionGeneration, ReplayDisposition, SeatFoundationClaim, SessionAdmission,
    SessionEffectCode, SessionEffectInstruction, SessionEffectIntent, SessionEffectKind,
    SessionEffectLedger, SessionEvent, SessionEventCode, SessionKeyEpoch, SessionLeaseTime,
    SessionManifest, SessionPolicy, SessionProjectionChange, SessionProjectionHost,
    SessionProjector, SessionReceiverLane, SessionSeat, SessionSenderLane, SimulationTime,
    VerifiedSeatFoundation, XChaCha20Poly1305Key, XChaCha20Poly1305Profile,
    XChaChaCompactPacketCodec, XChaChaCounterNonceSource, authorize_session,
    xchacha20poly1305_profile_id,
};
use hhhs_store::{MemoryStorage, history_root};
use hhhs_sync::{EntrySource, RepairHost, Snapshot};
use tutti_music::{MusicOp, SharedPitchSet, TunedDegree, Tuning};
use tutti_music_hhhs::{
    ActorId, MusicReplica, delegate, encode_command, initialize, materialize, notes_area,
};

const ADD_DEGREE: SessionEventCode = SessionEventCode::new(1);
const REMOVE_DEGREE: SessionEventCode = SessionEventCode::new(2);
const DEGREE: u8 = 6;
const MAX_MESSAGE_BYTES: usize = 2_048;
const EVENT_CAPACITY: usize = 16;

struct MusicProjector;

impl SessionProjector<MusicOp, SharedPitchSet, 2> for MusicProjector {
    type Error = &'static str;

    fn apply(
        &self,
        view: &mut SharedPitchSet,
        _correlation: hhhs_session::SessionCorrelation,
        event: &SessionEvent<MusicOp, 2>,
    ) -> Result<(), Self::Error> {
        match event.payload() {
            MusicOp::AddDegree { degree } => {
                view.pitch_classes.insert(*degree);
            }
            MusicOp::RemoveDegree { degree } => {
                view.pitch_classes.remove(degree);
            }
            _ => return Err("compact note-set session only accepts degree add/remove"),
        }
        Ok(())
    }
}

fn degree(index: u8) -> TunedDegree {
    TunedDegree::new(&Tuning::twelve_tet(), u16::from(index)).unwrap()
}

fn decode_music(code: SessionEventCode, payload: Vec<u8>) -> Result<MusicOp, &'static str> {
    let [index] = payload.as_slice() else {
        return Err("compact degree command must contain exactly one index");
    };
    match code {
        ADD_DEGREE => Ok(MusicOp::AddDegree {
            degree: degree(*index),
        }),
        REMOVE_DEGREE => Ok(MusicOp::RemoveDegree {
            degree: degree(*index),
        }),
        _ => Err("unknown compact music command"),
    }
}

fn receiver(key: &SigningKey) -> Receiver {
    Receiver::new(key.verifying_key().to_bytes().to_vec()).unwrap()
}

fn repair_records(
    source: &MusicReplica<MemoryStorage>,
    latest: EntryHash,
) -> Vec<(EntryHash, Vec<u8>)> {
    ReplicaRepairHost::new(source.clone())
        .capture([0x91; 16])
        .unwrap()
        .bytes_with_closure(&latest, &mut BTreeSet::new())
}

#[test]
fn upstream_session_predicts_reifies_repairs_and_recovers_tutti_effects() {
    let namespace = Digest::of(b"tutti upstream session qualification");
    let owner_key = SigningKey::from_bytes(&[0x31; 32]);
    let member_key = SigningKey::from_bytes(&[0x42; 32]);
    let owner = ActorId::from_signing_key(&owner_key);
    let member = ActorId::from_signing_key(&member_key);
    let owner_receiver = receiver(&owner_key);
    let member_receiver = receiver(&member_key);
    let (source, root) = initialize(namespace, owner, MemoryStorage::new()).unwrap();
    let member_grant = delegate(&source, namespace, root, &owner_key, member)
        .unwrap()
        .entry;
    let base_snapshot = source.snapshot();
    let base = base_snapshot.history.frontier();
    let initial_view = materialize(&base_snapshot.history, &[root]).shared_pitches;

    let foundation_profile = FoundationProfileId::for_domain(b"tutti ed25519 foundation v1");
    let manifest = SessionManifest::builder()
        .epoch(hhhs_session::SessionEpoch::new(11))
        .namespace(namespace)
        .base(base.clone())
        .rules(Digest::of(b"tutti observed-remove shared pitch set v1"))
        .vocabulary(Digest::of(b"tutti compact add/remove degree v1"))
        .area(notes_area(namespace))
        .allowed(AllowedMessageClasses::DURABLE_COMMAND)
        .lease(
            SessionLeaseTime::from_ticks(100),
            SessionLeaseTime::from_ticks(200),
        )
        .max_events_per_seat(8)
        .max_message_bytes(MAX_MESSAGE_BYTES as u32)
        .security_profile(xchacha20poly1305_profile_id())
        .channel_binding(Digest::of(b"tutti bounded carrier binding"))
        .seats([
            SessionSeat::new(owner_receiver.clone(), foundation_profile),
            SessionSeat::new(member_receiver.clone(), foundation_profile),
        ])
        .build()
        .unwrap();
    let policy = SessionPolicy::builder()
        .namespace(namespace)
        .rules(manifest.rules())
        .vocabulary(manifest.vocabulary())
        .area(Area::root(namespace))
        .supported(AllowedMessageClasses::DURABLE_COMMAND)
        .foundation_profiles([foundation_profile])
        .security_profiles([xchacha20poly1305_profile_id()])
        .max_seats(2)
        .max_duration(100)
        .max_events_per_seat(8)
        .max_message_bytes(MAX_MESSAGE_BYTES as u32)
        .build()
        .unwrap();
    let manifest_digest = manifest.digest();
    let foundation = |seat, holder, grant| {
        VerifiedSeatFoundation::assume_verified(
            SeatFoundationClaim::new(
                seat,
                holder,
                foundation_profile,
                vec![grant],
                manifest_digest,
                base.clone(),
            )
            .unwrap(),
        )
    };
    let capabilities = CapabilitySnapshot::capture(&base_snapshot.history, [root]);
    let session = authorize_session(
        &capabilities,
        &policy,
        manifest,
        &[
            foundation(0, owner_receiver, root),
            foundation(1, member_receiver, member_grant),
        ],
    )
    .unwrap();

    let owner_binding =
        DirectedSessionBinding::new(&session, SessionKeyEpoch::new(1), 0, 1).unwrap();
    let member_binding =
        DirectedSessionBinding::new(&session, SessionKeyEpoch::new(1), 1, 0).unwrap();
    let owner_prefix = [0xa1; 16];
    let member_prefix = [0xb2; 16];
    let owner_secret = XChaCha20Poly1305Key::from_bytes([0x51; 32]);
    let member_secret = XChaCha20Poly1305Key::from_bytes([0x62; 32]);
    let mut owner_sender = SessionSenderLane::new(
        owner_binding.clone(),
        XChaCha20Poly1305Profile::new(XChaChaCounterNonceSource::new(owner_prefix)),
        owner_secret.clone(),
    )
    .unwrap();
    let mut owner_receiver_lane = SessionReceiverLane::<_, 2, 8>::new(
        owner_binding.clone(),
        XChaCha20Poly1305Profile::new(XChaChaCounterNonceSource::new(owner_prefix)),
        owner_secret,
    )
    .unwrap();
    let mut member_sender = SessionSenderLane::new(
        member_binding.clone(),
        XChaCha20Poly1305Profile::new(XChaChaCounterNonceSource::new(member_prefix)),
        member_secret.clone(),
    )
    .unwrap();
    let mut member_receiver_lane = SessionReceiverLane::<_, 2, 8>::new(
        member_binding.clone(),
        XChaCha20Poly1305Profile::new(XChaChaCounterNonceSource::new(member_prefix)),
        member_secret,
    )
    .unwrap();

    let add_header = owner_binding
        .header(
            1,
            CausalContext::zero(),
            EventClass::DurableCommand,
            ADD_DEGREE,
            SimulationTime::from_ticks(110),
        )
        .unwrap();
    let remove_header = member_binding
        .header(
            1,
            CausalContext::from_counters([1, 0]),
            EventClass::DurableCommand,
            REMOVE_DEGREE,
            SimulationTime::from_ticks(120),
        )
        .unwrap();
    let add_packet = owner_sender.seal(add_header, &[DEGREE]).unwrap();
    let remove_packet = member_sender.seal(remove_header, &[DEGREE]).unwrap();
    let owner_codec = XChaChaCompactPacketCodec::new(owner_prefix);
    let member_codec = XChaChaCompactPacketCodec::new(member_prefix);
    let add_frame = owner_codec.encode(&owner_binding, &add_packet).unwrap();
    let remove_frame = member_codec
        .encode(&member_binding, &remove_packet)
        .unwrap();
    assert!(add_frame.len() <= 64 && remove_frame.len() <= 64);

    let mut tampered = add_frame.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        owner_receiver_lane
            .receive(&owner_codec.decode(&owner_binding, &tampered).unwrap())
            .is_err()
    );
    let remove_received = member_receiver_lane
        .receive(&member_codec.decode(&member_binding, &remove_frame).unwrap())
        .unwrap();
    assert_eq!(remove_received.disposition(), ReplayDisposition::Fresh);
    let remove_event = remove_received.try_decode(decode_music).unwrap();
    let remove_permitted = session
        .permit_event(
            SessionLeaseTime::from_ticks(120),
            remove_event.clone(),
            remove_frame.len(),
        )
        .unwrap();
    let remove_duplicate = member_receiver_lane
        .receive(&member_codec.decode(&member_binding, &remove_frame).unwrap())
        .unwrap();
    assert_eq!(remove_duplicate.disposition(), ReplayDisposition::Duplicate);
    let remove_duplicate = remove_duplicate.try_decode(decode_music).unwrap();
    let remove_duplicate_permitted = session
        .permit_event(
            SessionLeaseTime::from_ticks(120),
            remove_duplicate,
            remove_frame.len(),
        )
        .unwrap();
    let add_received = owner_receiver_lane
        .receive(&owner_codec.decode(&owner_binding, &add_frame).unwrap())
        .unwrap();
    let add_event = add_received.try_decode(decode_music).unwrap();
    let add_permitted = session
        .permit_event(
            SessionLeaseTime::from_ticks(120),
            add_event.clone(),
            add_frame.len(),
        )
        .unwrap();

    let mut kernel = session.kernel::<MusicOp, EVENT_CAPACITY>().unwrap();
    let initial_cut = kernel.closed_cut(CausalContext::zero()).unwrap();
    assert!(matches!(
        kernel.ingest(remove_permitted).unwrap().readiness(),
        CausalReadiness::Parked { .. }
    ));
    assert_eq!(
        kernel.gap().unwrap().first_missing(),
        add_event.event().dot()
    );
    kernel.ingest(remove_duplicate_permitted).unwrap();
    assert!(kernel.ingest(add_permitted).unwrap().readiness().advanced());
    assert!(kernel.gap().is_none());

    let mut projection =
        SessionProjectionHost::<MusicOp, SharedPitchSet, 2, EVENT_CAPACITY, EVENT_CAPACITY>::new(
            &session,
            initial_cut,
            ProjectionGeneration::new(1),
            SimulationTime::from_ticks(120),
            DurableProjection::new(
                0,
                base.clone(),
                history_root(&base_snapshot.history),
                initial_view.clone(),
            ),
        )
        .unwrap();
    let predicted = projection
        .predict_between(&kernel, initial_cut, kernel.ready_cut(), &MusicProjector)
        .unwrap()
        .unwrap();
    assert!(matches!(
        predicted.change(),
        SessionProjectionChange::Predicted { events: 2, .. }
    ));
    assert!(projection.view().is_empty());
    assert_eq!(projection.pending_len(), 2);

    let add_correlation = kernel.correlation(add_event.event().dot()).unwrap();
    let mut effects =
        SessionEffectLedger::<_, 2, EVENT_CAPACITY>::new(SimulationTime::from_ticks(120)).unwrap();
    let immediate = effects
        .predict(
            add_correlation,
            kernel.event(add_correlation.dot()).unwrap(),
            &[
                SessionEffectIntent::new(
                    SessionEffectCode::for_domain(b"tutti preview tone"),
                    SessionEffectKind::Reversible,
                    "preview tone",
                ),
                SessionEffectIntent::new(
                    SessionEffectCode::for_domain(b"tutti publish revision"),
                    SessionEffectKind::Irreversible,
                    "publish revision",
                ),
            ],
        )
        .unwrap();
    assert_eq!(immediate.len(), 1);

    let add_dot = add_event.event().dot();
    let remove_dot = remove_event.event().dot();
    let mut planner = session.reification_planner::<EVENT_CAPACITY>().unwrap();
    let add_plan = planner.plan(&kernel, add_dot).unwrap();
    let add_command = encode_command(
        namespace,
        owner,
        &[root],
        MusicOp::AddDegree {
            degree: degree(DEGREE),
        },
    )
    .unwrap();
    let add_entry = add_plan.entry(&add_command).unwrap();
    let add_context = source
        .presentation_context(&add_entry, notes_area(namespace), Right::Invoke)
        .unwrap();
    let add_presentation = Ed25519Verifier::present(&owner_key, vec![root], &add_context).unwrap();
    let admitted_add = source
        .admit(AdmissionRequest::presented(
            add_entry.clone(),
            add_presentation,
            notes_area(namespace),
            Right::Invoke,
        ))
        .unwrap();
    let add_session_admission = SessionAdmission::from_replica(
        &add_entry,
        admitted_add.durable_entry_admission(),
        MAX_MESSAGE_BYTES,
    )
    .unwrap();
    let add_admission = planner
        .record_admission(&add_plan, &add_entry, add_session_admission)
        .unwrap();
    assert_eq!(add_admission.entry(), admitted_add.entry);
    let after_add = source.snapshot();
    let add_view = materialize(&after_add.history, &[root]).shared_pitches;
    assert_eq!(add_view.pitch_classes, BTreeSet::from([degree(DEGREE)]));

    let remove_plan = planner.plan(&kernel, remove_dot).unwrap();
    assert!(remove_plan.predecessors().contains(&admitted_add.entry));
    let remove_command = encode_command(
        namespace,
        member,
        &[member_grant],
        MusicOp::RemoveDegree {
            degree: degree(DEGREE),
        },
    )
    .unwrap();
    let remove_entry = remove_plan.entry(&remove_command).unwrap();
    let remove_context = source
        .presentation_context(&remove_entry, notes_area(namespace), Right::Invoke)
        .unwrap();
    let remove_presentation =
        Ed25519Verifier::present(&member_key, vec![member_grant], &remove_context).unwrap();
    let admitted_remove = source
        .admit(AdmissionRequest::presented(
            remove_entry.clone(),
            remove_presentation,
            notes_area(namespace),
            Right::Invoke,
        ))
        .unwrap();
    let remove_session_admission = SessionAdmission::from_replica(
        &remove_entry,
        admitted_remove.durable_entry_admission(),
        MAX_MESSAGE_BYTES,
    )
    .unwrap();
    let remove_admission = planner
        .record_admission(&remove_plan, &remove_entry, remove_session_admission)
        .unwrap();
    assert_eq!(remove_admission.entry(), admitted_remove.entry);
    let after_remove = source.snapshot();
    let remove_view = materialize(&after_remove.history, &[root]).shared_pitches;
    assert!(remove_view.is_empty());

    projection
        .confirm(
            add_admission,
            DurableProjection::new(
                1,
                after_add.history.frontier(),
                history_root(&after_add.history),
                add_view,
            ),
            &MusicProjector,
        )
        .unwrap()
        .unwrap();
    assert!(
        projection.view().is_empty(),
        "pending remove remains applied"
    );
    projection
        .confirm(
            remove_admission,
            DurableProjection::new(
                2,
                after_remove.history.frontier(),
                history_root(&after_remove.history),
                remove_view,
            ),
            &MusicProjector,
        )
        .unwrap()
        .unwrap();
    assert_eq!(projection.pending_len(), 0);
    assert!(projection.view().is_empty());

    let records = repair_records(&source, admitted_remove.entry);
    let (target, target_root) = initialize(namespace, owner, MemoryStorage::new()).unwrap();
    assert_eq!(target_root, root);
    let mut target_host = ReplicaRepairHost::new(target.clone());
    let applied = block_on(target_host.apply(&records)).unwrap();
    assert!(applied.refused.is_empty());
    assert!(applied.admitted.contains(&admitted_add.entry));
    assert!(applied.admitted.contains(&admitted_remove.entry));
    let source_host = ReplicaRepairHost::new(source.clone());
    let source_cut = source_host.capture([0x91; 16]).unwrap();
    let target_cut = target_host.capture([0x91; 16]).unwrap();
    assert_eq!(target_cut.root(), source_cut.root());
    assert_eq!(target_cut.len(), source_cut.len());
    assert!(
        materialize(&target.snapshot().history, &[root])
            .shared_pitches
            .is_empty()
    );

    let admitted_record = |expected| {
        records
            .iter()
            .find_map(|(hash, bytes)| {
                (*hash == expected).then(|| ReplicaRecord::decode(bytes).unwrap())
            })
            .unwrap()
    };
    let repaired_add_record = admitted_record(admitted_add.entry);
    let repaired_remove_record = admitted_record(admitted_remove.entry);
    let repaired_add_admission = SessionAdmission::from_replica(
        repaired_add_record.entry(),
        target
            .durable_entry_admission(admitted_add.entry)
            .expect("repaired add is retained by the target Replica"),
        MAX_MESSAGE_BYTES,
    )
    .unwrap();
    let repaired_remove_admission = SessionAdmission::from_replica(
        repaired_remove_record.entry(),
        target
            .durable_entry_admission(admitted_remove.entry)
            .expect("repaired remove is retained by the target Replica"),
        MAX_MESSAGE_BYTES,
    )
    .unwrap();
    assert_eq!(repaired_add_admission, add_admission);
    let mut repaired_planner = session.reification_planner::<EVENT_CAPACITY>().unwrap();
    repaired_planner
        .record_observed_admission(&kernel, repaired_add_record.entry(), repaired_add_admission)
        .unwrap();
    repaired_planner
        .record_observed_admission(
            &kernel,
            repaired_remove_record.entry(),
            repaired_remove_admission,
        )
        .unwrap();

    let mut repair_projection =
        SessionProjectionHost::<MusicOp, SharedPitchSet, 2, EVENT_CAPACITY, EVENT_CAPACITY>::new(
            &session,
            initial_cut,
            ProjectionGeneration::new(1),
            SimulationTime::from_ticks(120),
            DurableProjection::new(0, base, history_root(&base_snapshot.history), initial_view),
        )
        .unwrap();
    let mut late_kernel = session.kernel::<MusicOp, EVENT_CAPACITY>().unwrap();
    let target_snapshot = target.snapshot();
    let repaired_change = repair_projection
        .resynchronize(
            ProjectionGeneration::new(2),
            &late_kernel,
            SimulationTime::from_ticks(120),
            DurableProjectionHorizon::new(
                DurableProjection::new(
                    2,
                    target_snapshot.history.frontier(),
                    history_root(&target_snapshot.history),
                    materialize(&target_snapshot.history, &[root]).shared_pitches,
                ),
                &target_snapshot.history,
                MAX_MESSAGE_BYTES,
            ),
            &MusicProjector,
        )
        .unwrap();
    assert!(matches!(
        repaired_change.change(),
        SessionProjectionChange::Reset { revision: 2, .. }
    ));
    assert_eq!(repair_projection.confirmed_len(), 2);
    assert_eq!(repair_projection.pending_len(), 0);

    let mut recovery_lookups = 0;
    let recovered = effects
        .resynchronize(|correlation| {
            recovery_lookups += 1;
            repair_projection.confirmed_admission(correlation)
        })
        .unwrap();
    assert_eq!(
        recovery_lookups, 1,
        "one cause decision must be reused for all sibling effects"
    );
    assert!(matches!(
        recovered.iter().next(),
        Some(SessionEffectInstruction::RunIrreversible { attempt, .. })
            if attempt.get() == 1
    ));

    late_kernel
        .ingest(
            session
                .permit_event(
                    SessionLeaseTime::from_ticks(120),
                    remove_event,
                    remove_frame.len(),
                )
                .unwrap(),
        )
        .unwrap();
    late_kernel
        .ingest(
            session
                .permit_event(
                    SessionLeaseTime::from_ticks(120),
                    add_event,
                    add_frame.len(),
                )
                .unwrap(),
        )
        .unwrap();
    assert!(
        repair_projection
            .predict_between(
                &late_kernel,
                initial_cut,
                late_kernel.ready_cut(),
                &MusicProjector,
            )
            .unwrap()
            .is_none(),
        "late realtime copies of repaired admissions must be suppressed"
    );
    assert!(repair_projection.view().is_empty());

    eprintln!(
        "d216 session resources: frames={}/{}, kernel_slots={}B projection_slots={}B planner_slots={}B effect_slots={}B",
        add_frame.len(),
        remove_frame.len(),
        kernel.retained_slot_bytes(),
        projection.retained_slot_bytes(),
        planner.retained_slot_bytes(),
        effects.retained_slot_bytes(),
    );
}
