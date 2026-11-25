//! # `lf-archive`
//!
//! Pure-Rust parser and validator for Daml 3.x / Canton 3.x DAR archives and Daml-LF2 packages.
//!
//! Features:
//! - Safe ZIP extraction with per-entry (256 MiB) and total budget (2 GiB) decompression ceilings (AT-A01).
//! - Path traversal defenses rejecting `..`, absolute paths, and volume drive prefixes (AT-A02).
//! - RFC 822 line continuation unfolding for `META-INF/MANIFEST.MF`.
//! - Cryptographic Package ID SHA-256 calculation and tamper verification (AT-A04).
//! - Fail-closed Daml-LF2 major and minor version gating (AT-A06).
//! - Zero-dependency prost protobuf decoding with interned string and dotted-name table resolution (AT-A08).

pub mod archive;
pub mod crypto;
pub mod decode;
pub mod error;
mod expr_features;
pub mod features;
pub mod interned;
pub mod manifest;
pub mod package_graph;
pub mod proto;
pub mod surface;
pub mod typecheck;
pub mod upgrade;
pub mod value;

pub use archive::{
    check_dar_for_upload, dalf_entries, dalf_payloads, load_dar_file, load_dar_file_allow_dev,
    missing_dependencies, parse_dar_bytes, parse_dar_file, parse_dar_reader, parse_loaded_dar,
    parse_loaded_dar_allow_dev, referenced_package_ids, DalfInfo, DarArchive, LoadedDar,
    MAX_ENTRY_BYTES, MAX_TOTAL_BYTES,
};
pub use crypto::{compute_sha256, verify_package_id};
pub use decode::{
    decode_dalf, decode_dalf_allow_dev, decode_dalf_envelope, load_dalf, load_dalf_allow_dev,
    load_dalf_payload, resolve_interned_dotted_name, resolve_interned_string, resolve_metadata,
    resolve_modules, resolve_single_module_name, DecodedDalf, LoadedDalf, SUPPORTED_LF2_MINORS,
};
pub use error::{DarError, DecodeError, ManifestError};
pub use manifest::Manifest;
pub use package_graph::{GraphError, PackageDependencyGraph};
pub use surface::{
    BytePresence, ChoiceDef, ChoiceParam, FieldDef, ModuleSurface, SurfaceType, TemplateSurface,
};
pub use upgrade::{
    typecheck_upgrades, validate_upgrade, PackageMeta, PackageRef, PackageSignature, PackageVersion,
    RecordOrigin, UpgradeCheckError, UpgradeError,
};
pub use value::{ProtoValue, Value, ValueError, MAX_VALUE_RECURSION_DEPTH};
