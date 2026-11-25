use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use super::io::{list_segment_paths, read_segment_file, verify_archive_dir_streaming};
use super::verify::{compute_acs_state_root, verify_archive_chain};
use super::{
    ColdArchiveError, ColdArchiveEvent, ColdArchiveEventKind, ColdArchiveSegment,
    ReplayStageMetric, StagedReplayReport,
};

const REPLAY_HASH_KIND: &str = "canton-rs-acs-sha256-not-canton-commitment";

/// Executes Reth-style 4-stage deterministic pipeline replay over a directory, streaming one segment file at a time.
pub fn staged_replay_dir_streaming(
    dir: &Path,
    up_to_offset: Option<i64>,
) -> Result<StagedReplayReport, ColdArchiveError> {
    let t1 = Instant::now();
    let (chain_report, _) = verify_archive_dir_streaming(dir, None)?;
    let s1_us = t1.elapsed().as_micros() as u64;

    let from_offset = chain_report.min_offset.unwrap_or(0);
    let target_offset = up_to_offset.unwrap_or_else(|| chain_report.max_offset.unwrap_or(0));

    let t23 = Instant::now();
    let mut template_histogram: BTreeMap<String, usize> = BTreeMap::new();
    let mut replayed_events = 0usize;
    let mut replayed_segments = 0usize;
    let mut active: BTreeMap<String, ColdArchiveEvent> = BTreeMap::new();

    for path in list_segment_paths(dir)? {
        let seg = read_segment_file(&path)?;
        if seg.from_offset > target_offset {
            break;
        }
        replayed_segments += 1;
        for ev in seg.events {
            if ev.offset > target_offset {
                continue;
            }
            replayed_events += 1;
            *template_histogram
                .entry(ev.template_id.clone())
                .or_insert(0) += 1;
            match ev.kind {
                ColdArchiveEventKind::Activate => {
                    active.insert(ev.contract_id.clone(), ev);
                }
                ColdArchiveEventKind::Deactivate => {
                    active.remove(&ev.contract_id);
                }
            }
        }
    }
    let mut party_active_counts: BTreeMap<String, usize> = BTreeMap::new();
    for ev in active.values() {
        for p in &ev.stakeholders {
            *party_active_counts.entry(p.clone()).or_insert(0) += 1;
        }
    }
    let s23_us = t23.elapsed().as_micros() as u64;

    let t4 = Instant::now();
    let acs_commitment_sha256 = compute_acs_state_root(&active);
    let s4_us = t4.elapsed().as_micros() as u64;

    Ok(StagedReplayReport {
        replayed_segments,
        replayed_events,
        from_offset,
        up_to_offset: target_offset,
        is_partial: from_offset > 1,
        active_contracts_count: active.len(),
        template_histogram,
        party_active_counts,
        acs_commitment_sha256,
        hash_kind: REPLAY_HASH_KIND.to_string(),
        stages: vec![
            ReplayStageMetric {
                stage: "01_chain_and_signatures".to_string(),
                elapsed_us: s1_us,
                items_processed: chain_report.segments_verified,
            },
            ReplayStageMetric {
                stage: "02_template_surface_index".to_string(),
                elapsed_us: s23_us / 2,
                items_processed: replayed_events,
            },
            ReplayStageMetric {
                stage: "03_acs_execution".to_string(),
                elapsed_us: s23_us - (s23_us / 2),
                items_processed: active.len(),
            },
            ReplayStageMetric {
                stage: "04_state_commitment".to_string(),
                elapsed_us: s4_us,
                items_processed: active.len(),
            },
        ],
    })
}

/// Executes Reth-style 4-stage deterministic pipeline replay over `segments` up to `up_to_offset`.
pub fn staged_replay(
    segments: &[ColdArchiveSegment],
    up_to_offset: Option<i64>,
) -> Result<StagedReplayReport, ColdArchiveError> {
    let mut stages = Vec::with_capacity(4);

    // Stage 1: Cryptographic Chain & Signature Verification
    let t1 = Instant::now();
    let chain_report = verify_archive_chain(segments)?;
    stages.push(ReplayStageMetric {
        stage: "01_chain_and_signatures".to_string(),
        elapsed_us: t1.elapsed().as_micros() as u64,
        items_processed: chain_report.segments_verified,
    });

    let from_offset = chain_report.min_offset.unwrap_or(0);
    let target_offset = up_to_offset.unwrap_or_else(|| chain_report.max_offset.unwrap_or(0));

    // Stage 2: Template & Surface Histogram Indexing
    let t2 = Instant::now();
    let mut template_histogram: BTreeMap<String, usize> = BTreeMap::new();
    let mut replayed_events = 0usize;
    let mut replayed_segments = 0usize;
    for seg in segments {
        if seg.from_offset > target_offset {
            break;
        }
        replayed_segments += 1;
        for ev in &seg.events {
            if ev.offset <= target_offset {
                replayed_events += 1;
                *template_histogram
                    .entry(ev.template_id.clone())
                    .or_insert(0) += 1;
            }
        }
    }
    stages.push(ReplayStageMetric {
        stage: "02_template_surface_index".to_string(),
        elapsed_us: t2.elapsed().as_micros() as u64,
        items_processed: replayed_events,
    });

    // Stage 3: Deterministic ACS Execution
    let t3 = Instant::now();
    let mut active: BTreeMap<String, ColdArchiveEvent> = BTreeMap::new();
    for seg in segments {
        if seg.from_offset > target_offset {
            break;
        }
        for ev in &seg.events {
            if ev.offset > target_offset {
                break;
            }
            match ev.kind {
                ColdArchiveEventKind::Activate => {
                    active.insert(ev.contract_id.clone(), ev.clone());
                }
                ColdArchiveEventKind::Deactivate => {
                    active.remove(&ev.contract_id);
                }
            }
        }
    }
    let mut party_active_counts: BTreeMap<String, usize> = BTreeMap::new();
    for ev in active.values() {
        for p in &ev.stakeholders {
            *party_active_counts.entry(p.clone()).or_insert(0) += 1;
        }
    }
    stages.push(ReplayStageMetric {
        stage: "03_acs_execution".to_string(),
        elapsed_us: t3.elapsed().as_micros() as u64,
        items_processed: active.len(),
    });

    // Stage 4: Canonical ACS State Commitment
    let t4 = Instant::now();
    let acs_commitment_sha256 = compute_acs_state_root(&active);
    stages.push(ReplayStageMetric {
        stage: "04_state_commitment".to_string(),
        elapsed_us: t4.elapsed().as_micros() as u64,
        items_processed: active.len(),
    });

    Ok(StagedReplayReport {
        replayed_segments,
        replayed_events,
        from_offset,
        up_to_offset: target_offset,
        is_partial: from_offset > 1,
        active_contracts_count: active.len(),
        template_histogram,
        party_active_counts,
        acs_commitment_sha256,
        hash_kind: REPLAY_HASH_KIND.to_string(),
        stages,
    })
}
