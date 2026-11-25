//! ZIP archive extraction, security limit enforcement, and DAR package resolution.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};
use std::path::Path;
use zip::ZipArchive;

use crate::decode::{decode_dalf_with, load_dalf_with, resolve_metadata, resolve_modules};
use crate::error::{DarError, ManifestError};
use crate::manifest::Manifest;
use crate::proto::daml_lf_2::Package;

/// Maximum allowable uncompressed bytes for any single entry (256 MiB).
pub const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum allowable cumulative uncompressed bytes for the entire archive (2 GiB).
pub const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Manifest relative path inside JAR/DAR archive.
pub const MANIFEST_PATH: &str = "META-INF/MANIFEST.MF";

/// Information about an individual DALF package inside the DAR archive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DalfInfo {
    /// Relative path/name of the DALF entry in the archive.
    pub name: String,

    /// Lowercase 64-character SHA-256 Package ID.
    pub package_id: String,

    /// True if this is the primary entry-point contract package.
    pub is_main: bool,

    /// Package metadata name. Empty when the DALF has no metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,

    /// Package metadata version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,

    /// Module names defined by this DALF.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<String>,
}

/// Fully parsed DAR archive metadata and packages.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DarArchive {
    /// Relative path of the primary contract DALF.
    pub main_dalf_name: String,

    /// Lowercase 64-character SHA-256 Package ID of the main package.
    pub main_package_id: String,

    /// Daml-LF version (e.g. "2.1").
    pub lf_version: String,

    /// Resolved package name from interned metadata.
    pub package_name: Option<String>,

    /// Resolved package version from interned metadata.
    pub package_version: Option<String>,

    /// Package name declared in manifest header.
    pub manifest_name: Option<String>,

    /// Package version declared in manifest header.
    pub manifest_version: Option<String>,

    /// All DALF packages (main package and dependencies).
    pub dalfs: Vec<DalfInfo>,

    /// Module names defined in the main package.
    pub modules: Vec<String>,

    /// Decoded module surfaces for all templates in the main package.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub module_surfaces: Vec<crate::surface::ModuleSurface>,
}

/// Validates entry path against traversal attacks (AT-A02).
pub fn validate_entry_path(name: &str) -> Result<(), DarError> {
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(DarError::PathTraversal(name.to_string()));
    }

    if name.len() >= 2 && name.as_bytes()[1] == b':' && name.as_bytes()[0].is_ascii_alphabetic() {
        return Err(DarError::PathTraversal(name.to_string()));
    }

    for part in name.split(['/', '\\']) {
        if part == ".." {
            return Err(DarError::PathTraversal(name.to_string()));
        }
    }

    Ok(())
}

/// Reads an entry's decompressed bytes with strict per-entry and cumulative budget limits (AT-A01).
pub fn read_entry_bounded<R: Read>(
    entry_name: &str,
    mut reader: R,
    total_decompressed: &mut u64,
) -> Result<Vec<u8>, DarError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];

    loop {
        let bytes_to_read = chunk
            .len()
            .min((MAX_ENTRY_BYTES - buf.len() as u64 + 1) as usize);
        if bytes_to_read == 0 {
            return Err(DarError::EntryTooLarge {
                entry: entry_name.to_string(),
                size: buf.len() as u64 + 1,
                limit: MAX_ENTRY_BYTES,
            });
        }

        let n = reader.read(&mut chunk[..bytes_to_read])?;
        if n == 0 {
            break;
        }

        if (buf.len() as u64) + (n as u64) > MAX_ENTRY_BYTES {
            return Err(DarError::EntryTooLarge {
                entry: entry_name.to_string(),
                size: (buf.len() as u64) + (n as u64),
                limit: MAX_ENTRY_BYTES,
            });
        }

        if *total_decompressed + (n as u64) > MAX_TOTAL_BYTES {
            return Err(DarError::ArchiveTooLarge {
                total: *total_decompressed + (n as u64),
                limit: MAX_TOTAL_BYTES,
            });
        }

        buf.extend_from_slice(&chunk[..n]);
        *total_decompressed += n as u64;
    }

    Ok(buf)
}

fn identity_from_dalf(
    name: &str,
    bytes: &[u8],
    is_main: bool,
    allow_dev: bool,
) -> Result<(DalfInfo, Package, String), DarError> {
    let loaded = load_dalf_with(bytes, allow_dev)?;
    // AT-A08: the whole package must have valid interned references, as the JVM requires.
    crate::interned::validate_interned_references(&loaded.package)?;
    let (package_name, package_version) = resolve_metadata(&loaded.package)?;
    let modules = resolve_modules(&loaded.package)?;
    let info = DalfInfo {
        name: name.to_string(),
        package_id: loaded.package_id,
        is_main,
        package_name,
        package_version,
        modules,
    };
    Ok((info, loaded.package, loaded.lf_version))
}

/// Parsed archive plus the LF package of every DALF, keyed by package id.
pub struct LoadedDar {
    pub archive: DarArchive,
    pub packages: HashMap<String, Package>,
    /// Daml-LF language version string (e.g. `"2.1"`, `"2.3"`, `"2.dev"`) per package id.
    pub package_versions: HashMap<String, String>,
    /// The manifest `Dalfs` list as written, kept so the upload check can see an empty header.
    pub manifest_dalfs: Vec<String>,
}

/// Upload-level checks the JVM applies on top of a loadable archive (S-GUARD-004). `known` is the set of package
/// ids that satisfy dependencies without being in the DAR (empty in the measured JVM behavior, see
/// [`missing_dependencies`]).
///
/// [CANTON-NOTE: ORACLE] Parsing stays lenient about an empty `Dalfs` header because hand-built test DARs omit it;
/// the JVM upload endpoint rejects it (`INVALID_ZIP_ENTRY`), so an upload path must call this.
pub fn check_dar_for_upload(dar: &LoadedDar, known: &HashSet<String>) -> Result<(), DarError> {
    if dar.manifest_dalfs.is_empty() {
        return Err(DarError::EmptyDalfsList);
    }
    let missing = missing_dependencies(dar, known);
    if let Some(first) = missing.first() {
        return Err(DarError::MissingDependency(first.clone()));
    }
    // [CANTON-NOTE: ORACLE] Run full Canton-equivalent LF validation (Collision, Recursion, DependencyVersion,
    // Typing, Serializability) using per-package LF versions (U-11, AT-L01).
    crate::typecheck::check_packages_with_versions(&dar.packages, &dar.package_versions)
        .map_err(|e| DarError::Validation(e.to_string()))?;
    Ok(())
}

/// Package ids a decoded package refers to, other than itself, read from its interned string table.
///
/// [CANTON-NOTE: LIMITATION] Daml-LF 2.1 stores every imported package id as an interned string (a
/// `SelfOrImportedPackageId.imported_package_id_interned_str`). This scans the string table for 64-character
/// lowercase hex strings instead of walking every type and expression. A text literal of exactly that shape would
/// count as a dependency, which makes the check stricter, never more lenient. Walking the AST removes the false
/// positive; it is not done because no corpus package has such a literal.
pub fn referenced_package_ids(package_id: &str, package: &Package) -> HashSet<String> {
    // [CANTON-NOTE: ORACLE] The package this one UPGRADES (`metadata.upgraded_package_id`) is a string of the table but not a
    // dependency: the node accepted `tests/oracle/upgrade/upg-2.0.0.dar` without `upg-1.0.0` inside it (S-LF-014). Counting it
    // made the server refuse a valid upgrade DAR.
    let upgraded = package
        .metadata
        .as_ref()
        .and_then(|m| m.upgraded_package_id.as_ref())
        .and_then(|u| usize::try_from(u.upgraded_package_id_interned_str).ok())
        .and_then(|i| package.interned_strings.get(i));
    package
        .interned_strings
        .iter()
        .filter(|s| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .filter(|s| s.as_str() != package_id)
        .filter(|s| Some(*s) != upgraded)
        .cloned()
        .collect()
}

/// Package ids that the DAR's packages refer to but neither the DAR itself nor `known` provides (AT-A07).
///
/// [CANTON-NOTE: ORACLE] The JVM answers `DAR_DEPENDENCIES_NOT_VALID` when a package depends on one that is
/// neither in the archive nor already on the participant; `known` stands for the participant's package store.
pub fn missing_dependencies(dar: &LoadedDar, known: &HashSet<String>) -> Vec<String> {
    let mut missing: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (id, package) in &dar.packages {
        for dep in referenced_package_ids(id, package) {
            if !dar.packages.contains_key(&dep) && !known.contains(&dep) {
                missing.insert(dep);
            }
        }
    }
    missing.into_iter().collect()
}

/// Opens and parses a DAR archive from a seekable stream.
pub fn parse_dar_reader<R: Read + Seek>(reader: R) -> Result<DarArchive, DarError> {
    Ok(parse_loaded_dar(reader)?.archive)
}

/// Opens a DAR and keeps each decoded LF package for evaluation.
pub fn parse_loaded_dar<R: Read + Seek>(reader: R) -> Result<LoadedDar, DarError> {
    parse_loaded_dar_with(reader, false)
}

/// Like `parse_loaded_dar`, but also permits Daml-LF `2.dev`.
pub fn parse_loaded_dar_allow_dev<R: Read + Seek>(reader: R) -> Result<LoadedDar, DarError> {
    parse_loaded_dar_with(reader, true)
}

fn parse_loaded_dar_with<R: Read + Seek>(
    reader: R,
    allow_dev: bool,
) -> Result<LoadedDar, DarError> {
    let mut zip = ZipArchive::new(reader)?;
    let mut total_decompressed: u64 = 0;

    // Pass 1: Path traversal validation across all entry names, declared size ceilings, and locate entries
    let mut manifest_idx: Option<usize> = None;
    let mut dalf_indices: HashMap<String, usize> = HashMap::new();
    let mut total_declared_size: u64 = 0;

    for i in 0..zip.len() {
        let entry = zip.by_index_raw(i)?;
        let name = entry.name().to_string();

        validate_entry_path(&name)?;

        let entry_size = entry.size();
        if entry_size > MAX_ENTRY_BYTES {
            return Err(DarError::EntryTooLarge {
                entry: name,
                size: entry_size,
                limit: MAX_ENTRY_BYTES,
            });
        }

        total_declared_size = total_declared_size.saturating_add(entry_size);
        if total_declared_size > MAX_TOTAL_BYTES {
            return Err(DarError::ArchiveTooLarge {
                total: total_declared_size,
                limit: MAX_TOTAL_BYTES,
            });
        }

        if name == MANIFEST_PATH {
            manifest_idx = Some(i);
        } else if name.ends_with(".dalf") {
            dalf_indices.insert(name, i);
        }
    }

    // Pass 2: Extract and parse manifest
    let manifest_idx = manifest_idx.ok_or(DarError::Manifest(ManifestError::MissingManifest))?;
    let manifest_bytes = {
        let entry = zip.by_index(manifest_idx)?;
        read_entry_bounded(MANIFEST_PATH, entry, &mut total_decompressed)?
    };
    let manifest = Manifest::parse(&manifest_bytes)?;

    // Pass 3: Locate main DALF entry
    let main_dalf_name = manifest.main_dalf.clone();
    let main_dalf_idx = dalf_indices
        .get(&main_dalf_name)
        .copied()
        .ok_or_else(|| DarError::MainDalfNotFound(main_dalf_name.clone()))?;

    // Pass 4: Extract and decode main DALF package
    let main_dalf_bytes = {
        let entry = zip.by_index(main_dalf_idx)?;
        read_entry_bounded(&main_dalf_name, entry, &mut total_decompressed)?
    };

    let decoded_main = decode_dalf_with(&main_dalf_bytes, allow_dev)?;
    let mut packages = HashMap::new();
    let mut package_versions = HashMap::new();

    // Pass 5: Resolve dependency DALFs
    let mut dalfs = Vec::new();
    let mut processed = HashSet::new();

    let (main_info, main_package, main_lf_ver) =
        identity_from_dalf(&main_dalf_name, &main_dalf_bytes, true, allow_dev)?;
    package_versions.insert(main_info.package_id.clone(), main_lf_ver);
    packages.insert(main_info.package_id.clone(), main_package);
    dalfs.push(main_info);
    processed.insert(main_dalf_name.clone());

    // Extract dependencies declared in manifest
    for dep_name in &manifest.dalfs {
        if processed.contains(dep_name) {
            continue;
        }

        // [CANTON-NOTE: ORACLE] A listed but absent entry is an error, not a skip: the JVM rejects it
        // (INVALID_ZIP_ENTRY), so accepting it would let a DAR load that Canton refuses.
        let dep_idx = *dalf_indices
            .get(dep_name)
            .ok_or_else(|| DarError::ManifestDalfNotFound(dep_name.clone()))?;
        let dep_bytes = {
            let entry = zip.by_index(dep_idx)?;
            read_entry_bounded(dep_name, entry, &mut total_decompressed)?
        };

        let (info, package, lf_ver) = identity_from_dalf(dep_name, &dep_bytes, false, allow_dev)?;
        package_versions.insert(info.package_id.clone(), lf_ver);
        packages.insert(info.package_id.clone(), package);
        dalfs.push(info);
        processed.insert(dep_name.clone());
    }

    // Also include any other unreferenced .dalf packages in the archive
    let mut sorted_dalfs: Vec<_> = dalf_indices.keys().cloned().collect();
    sorted_dalfs.sort();

    for dalf_name in sorted_dalfs {
        if processed.contains(&dalf_name) {
            continue;
        }

        let idx = dalf_indices[&dalf_name];
        let dep_bytes = {
            let entry = zip.by_index(idx)?;
            read_entry_bounded(&dalf_name, entry, &mut total_decompressed)?
        };

        let (info, package, lf_ver) = identity_from_dalf(&dalf_name, &dep_bytes, false, allow_dev)?;
        package_versions.insert(info.package_id.clone(), lf_ver);
        packages.insert(info.package_id.clone(), package);
        dalfs.push(info);
        processed.insert(dalf_name);
    }

    if dalfs.is_empty() {
        return Err(DarError::EmptyArchive);
    }

    Ok(LoadedDar {
        archive: DarArchive {
            main_dalf_name,
            main_package_id: decoded_main.package_id,
            lf_version: decoded_main.lf_version,
            package_name: decoded_main.package_name,
            package_version: decoded_main.package_version,
            manifest_name: manifest.name,
            manifest_version: manifest.version,
            dalfs,
            modules: decoded_main.modules,
            module_surfaces: decoded_main.module_surfaces,
        },
        packages,
        package_versions,
        manifest_dalfs: manifest.dalfs,
    })
}

/// Parses a DAR archive and its LF packages from an open file path.
pub fn load_dar_file<P: AsRef<Path>>(path: P) -> Result<LoadedDar, DarError> {
    let file = std::fs::File::open(path)?;
    parse_loaded_dar(file)
}

/// Like `load_dar_file`, but also permits Daml-LF `2.dev`.
pub fn load_dar_file_allow_dev<P: AsRef<Path>>(path: P) -> Result<LoadedDar, DarError> {
    let file = std::fs::File::open(path)?;
    parse_loaded_dar_allow_dev(file)
}

/// Parses a DAR archive from an open file path.
pub fn parse_dar_file<P: AsRef<Path>>(path: P) -> Result<DarArchive, DarError> {
    let file = std::fs::File::open(path)?;
    parse_dar_reader(file)
}

/// Parses a DAR archive from in-memory byte slice.
pub fn parse_dar_bytes(bytes: &[u8]) -> Result<DarArchive, DarError> {
    let cursor = std::io::Cursor::new(bytes);
    parse_dar_reader(cursor)
}

/// The package payloads of every `.dalf` entry of a DAR: `(package id, payload bytes)`, in entry order. The payload is the
/// `ArchivePayload` message inside the DALF's `Archive` envelope, i.e. the bytes whose SHA-256 is the package id (what a
/// ledger serves for a package).
pub fn dalf_payloads(dar: &[u8]) -> Result<Vec<(String, Vec<u8>)>, DarError> {
    Ok(dalf_entries(dar)?
        .into_iter()
        .map(|(id, _, payload)| (id, payload))
        .collect())
}

/// Every `.dalf` entry of a DAR: `(package id, the entry's bytes (the `Archive` message), the payload inside it)`, in entry order. A participant's
/// database keeps the entry's bytes as the package (`par_daml_packages.data`) and the payload's length as its size (`package_size`).
#[allow(
    clippy::type_complexity,
    reason = "protocol or ledger hook signature uses an inline composite type"
)]
pub fn dalf_entries(dar: &[u8]) -> Result<Vec<(String, Vec<u8>, Vec<u8>)>, DarError> {
    let mut zip = ZipArchive::new(std::io::Cursor::new(dar))?;
    let mut total_decompressed: u64 = 0;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let name = zip.by_index_raw(i)?.name().to_string();
        validate_entry_path(&name)?;
        if !name.ends_with(".dalf") {
            continue;
        }
        let entry = zip.by_index(i)?;
        let bytes = read_entry_bounded(&name, entry, &mut total_decompressed)?;
        let (archive, package_id) = crate::decode::decode_dalf_envelope(&bytes)?;
        out.push((package_id, bytes, archive.payload));
    }
    Ok(out)
}
