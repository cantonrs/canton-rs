use std::fs;
use std::path::{Path, PathBuf};

use super::verify::{check_segment_prunable_provenance, verify_single_segment};
use super::{
    ArchiveVerifyReport, ColdArchiveError, ColdArchiveSegment, ColdArchiveSegmentMeta,
    PruneCoverageSpec, StorageOverviewStats,
};

/// Writes `seg` into `<dir>/seg-<from>-<to>.crs-seg.json` (temporary file, fsync, rename, directory fsync) and
/// verifies the file read back.
pub fn write_segment_to_dir(
    dir: &Path,
    seg: &ColdArchiveSegment,
) -> Result<PathBuf, ColdArchiveError> {
    verify_single_segment(seg)?;
    fs::create_dir_all(dir).map_err(|e| ColdArchiveError::Io {
        path: dir.display().to_string(),
        reason: e.to_string(),
    })?;
    let file_name = format!(
        "seg-{:012}-{:012}.crs-seg.json",
        seg.from_offset, seg.to_offset
    );
    let final_path = dir.join(&file_name);
    let tmp_path = dir.join(format!(".{file_name}.tmp"));
    let json =
        serde_json::to_string_pretty(seg).map_err(|e| ColdArchiveError::Json(e.to_string()))?;
    let io = |path: &Path| {
        let path = path.display().to_string();
        move |e: std::io::Error| ColdArchiveError::Io {
            path,
            reason: e.to_string(),
        }
    };
    {
        use std::io::Write;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        // segments hold contract bodies: readable by the archiving user only
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&tmp_path).map_err(io(&tmp_path))?;
        file.write_all(json.as_bytes()).map_err(io(&tmp_path))?;
        file.sync_all().map_err(io(&tmp_path))?;
    }
    fs::rename(&tmp_path, &final_path).map_err(io(&final_path))?;
    // [CANTON-NOTE: WHY] The caller may prune right after this returns; the rename only survives a power loss once
    // the directory entry is on disk too.
    #[cfg(unix)]
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io(dir))?;

    // Read-back verification before returning (essential safety gate prior to DB pruning).
    let read_back_raw = fs::read_to_string(&final_path).map_err(|e| ColdArchiveError::Io {
        path: final_path.display().to_string(),
        reason: e.to_string(),
    })?;
    let decoded: ColdArchiveSegment =
        serde_json::from_str(&read_back_raw).map_err(|e| ColdArchiveError::Json(e.to_string()))?;
    verify_single_segment(&decoded)?;
    Ok(final_path)
}

/// Lists `.crs-seg.json` segment paths in `dir`, sorted by filename (and therefore ascending offset window).
pub fn list_segment_paths(dir: &Path) -> Result<Vec<PathBuf>, ColdArchiveError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(dir).map_err(|e| ColdArchiveError::Io {
        path: dir.display().to_string(),
        reason: e.to_string(),
    })?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| ColdArchiveError::Io {
            path: dir.display().to_string(),
            reason: e.to_string(),
        })?;
        let p = entry.path();
        if p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".crs-seg.json") && !n.starts_with('.'))
        {
            paths.push(p);
        }
    }
    paths.sort();
    Ok(paths)
}

pub(super) fn read_segment_file(path: &Path) -> Result<ColdArchiveSegment, ColdArchiveError> {
    let raw = fs::read_to_string(path).map_err(|e| ColdArchiveError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    serde_json::from_str(&raw).map_err(|e| ColdArchiveError::Json(e.to_string()))
}

/// Streams and verifies every segment in `dir` one file at a time (constant segment memory),
/// optionally checking that every segment is signed by `expected_signer_hex` and returning header summaries.
pub fn verify_archive_dir_streaming(
    dir: &Path,
    expected_signer_hex: Option<&str>,
) -> Result<(ArchiveVerifyReport, Vec<ColdArchiveSegmentMeta>), ColdArchiveError> {
    let paths = list_segment_paths(dir)?;
    if expected_signer_hex.is_some() && paths.is_empty() {
        return Err(ColdArchiveError::SignatureInvalid {
            from: 0,
            to: 0,
            reason: "archive contains no segments to verify expected signer".to_string(),
        });
    }
    let expected = expected_signer_hex.map(str::trim);
    let mut expected_prev: Option<String> = None;
    let mut min_offset: Option<i64> = None;
    let mut prev_to: Option<i64> = None;
    let mut total_events = 0usize;
    let mut signed_segments = 0usize;
    let mut metas = Vec::with_capacity(paths.len());

    for path in paths {
        let seg = read_segment_file(&path)?;
        verify_single_segment(&seg)?;
        if seg.prev_segment_sha256 != expected_prev {
            return Err(ColdArchiveError::BrokenHashChain {
                from: seg.from_offset,
                to: seg.to_offset,
                expected: expected_prev,
                actual: seg.prev_segment_sha256,
            });
        }
        if let Some(pt) = prev_to {
            if seg.from_offset != pt.saturating_add(1) {
                return Err(ColdArchiveError::DisjointOrOverlappingRange {
                    prev_to: pt,
                    next_from: seg.from_offset,
                });
            }
        }
        if let Some(exp) = expected {
            if !seg
                .signer_public_key_hex
                .as_deref()
                .is_some_and(|pk| pk.eq_ignore_ascii_case(exp))
            {
                return Err(ColdArchiveError::SignatureInvalid {
                    from: seg.from_offset,
                    to: seg.to_offset,
                    reason: format!(
                        "not signed by the expected key {exp} (signer {:?})",
                        seg.signer_public_key_hex
                    ),
                });
            }
        }
        if min_offset.is_none() {
            min_offset = Some(seg.from_offset);
        }
        if seg.ed25519_signature_hex.is_some() {
            signed_segments += 1;
        }
        total_events += seg.events.len();
        expected_prev = Some(seg.segment_sha256.clone());
        prev_to = Some(seg.to_offset);
        metas.push(ColdArchiveSegmentMeta::from_segment(&seg, true));
    }

    let report = ArchiveVerifyReport {
        segments_verified: metas.len(),
        signed_segments,
        total_events,
        min_offset,
        max_offset: prev_to,
        head_segment_sha256: expected_prev,
    };
    Ok((report, metas))
}

fn verify_dir_chain_for_prune(
    dir: &Path,
    spec: &PruneCoverageSpec<'_>,
    require_complete_coverage: bool,
) -> Result<(), ColdArchiveError> {
    let refuse = |reason: String| Err(ColdArchiveError::NotPrunable { reason });
    let paths = list_segment_paths(dir)?;
    let start = spec.expected_start.max(1);
    let mut expected_prev: Option<String> = None;
    let mut min_offset: Option<i64> = None;
    let mut prev_to: Option<i64> = None;

    for path in paths {
        let seg = read_segment_file(&path)?;
        verify_single_segment(&seg)?;
        if seg.prev_segment_sha256 != expected_prev {
            return Err(ColdArchiveError::BrokenHashChain {
                from: seg.from_offset,
                to: seg.to_offset,
                expected: expected_prev,
                actual: seg.prev_segment_sha256,
            });
        }
        if let Some(pt) = prev_to {
            if seg.from_offset != pt.saturating_add(1) {
                return Err(ColdArchiveError::DisjointOrOverlappingRange {
                    prev_to: pt,
                    next_from: seg.from_offset,
                });
            }
        }
        if seg.to_offset >= start && seg.from_offset <= spec.prune_up_to {
            check_segment_prunable_provenance(&seg, spec)?;
        }
        if min_offset.is_none() {
            min_offset = Some(seg.from_offset);
        }
        expected_prev = Some(seg.segment_sha256.clone());
        prev_to = Some(seg.to_offset);
    }

    if !require_complete_coverage {
        if let Some(min) = min_offset {
            if min > start {
                return refuse(format!(
                    "existing archive starts at {min}, leaving {start}..={min_prev} unarchived",
                    min_prev = min.saturating_sub(1)
                ));
            }
        }
        return Ok(());
    }

    match (min_offset, prev_to) {
        (Some(min), Some(max)) if min <= start && max >= spec.prune_up_to => Ok(()),
        (min, max) => refuse(format!(
            "the archive covers {min:?}..={max:?}, not {start}..={}",
            spec.prune_up_to
        )),
    }
}

/// Pre-flight check before exporting a new segment for `--prune-after-archive`: rejects any existing segments
/// overlapping `[spec.expected_start..=spec.prune_up_to]` that fail provenance/signer/payload checks.
pub fn ensure_existing_segments_prunable_provenance(
    dir: &Path,
    spec: &PruneCoverageSpec<'_>,
) -> Result<(), ColdArchiveError> {
    verify_dir_chain_for_prune(dir, spec, false)
}

/// Streams segments in `dir` one by one to check prunable coverage `[spec.expected_start..=spec.prune_up_to]`,
/// PostgreSQL provenance, DB identity, expected signer, and non-redacted contract bodies.
pub fn ensure_prunable_coverage_dir_streaming(
    dir: &Path,
    spec: &PruneCoverageSpec<'_>,
) -> Result<(), ColdArchiveError> {
    verify_dir_chain_for_prune(dir, spec, true)
}

/// Loads all `.crs-seg.json` segments from `dir` ordered by `from_offset`.
pub fn load_segments_from_dir(dir: &Path) -> Result<Vec<ColdArchiveSegment>, ColdArchiveError> {
    let paths = list_segment_paths(dir)?;
    let mut segments = Vec::with_capacity(paths.len());
    for p in paths {
        segments.push(read_segment_file(&p)?);
    }
    segments.sort_by_key(|s| s.from_offset);
    Ok(segments)
}

/// Populates cold-archive metrics on [`StorageOverviewStats`] from `<dir>` one segment at a time (works offline without PostgreSQL).
pub fn populate_cold_stats_from_dir(dir: &Path, stats: &mut StorageOverviewStats) {
    match verify_archive_dir_streaming(dir, None) {
        Ok((rep, _)) => {
            stats.cold_segments_count = rep.segments_verified;
            stats.cold_events_count = rep.total_events;
            stats.cold_max_offset = rep.max_offset;
            stats.cold_chain_valid = true;
        }
        Err(_) => {
            stats.cold_chain_valid = false;
            if let Ok(paths) = list_segment_paths(dir) {
                stats.cold_segments_count = paths.len();
                let mut total_events = 0usize;
                let mut max_off = None;
                for p in paths {
                    if let Ok(seg) = read_segment_file(&p) {
                        total_events += seg.events.len();
                        max_off = Some(seg.to_offset);
                    }
                }
                stats.cold_events_count = total_events;
                stats.cold_max_offset = max_off;
            }
        }
    }
}
