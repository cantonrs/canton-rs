//! Strongly-typed error definitions for DAR and DALF decoding.

use thiserror::Error;

/// Errors arising during JAR manifest (`META-INF/MANIFEST.MF`) decoding.
#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest not found: missing META-INF/MANIFEST.MF")]
    MissingManifest,

    #[error("manifest is not valid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),

    #[error("manifest missing required 'Main-Dalf' header")]
    MissingMainDalf,

    #[error("malformed manifest header line: {0}")]
    MalformedHeader(String),
}

/// Errors arising during Daml-LF protobuf decoding and AST verification.
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("protobuf decode error: {0}")]
    Protobuf(#[from] prost::DecodeError),

    #[error("unsupported hash function enum: {0}")]
    UnsupportedHashFunction(i32),

    #[error("package ID mismatch: declared '{declared}', computed '{computed}'")]
    PackageIdMismatch { declared: String, computed: String },

    /// The package nests deeper than Canton parses (`EXTENDED_PROTOBUF_RECURSION_LIMIT`).
    #[error("{0}")]
    NestingTooDeep(String),

    #[error("missing archive payload")]
    MissingPayload,

    #[error("unsupported Daml-LF major version: {0} (only Daml-LF 2 is supported)")]
    UnsupportedMajorVersion(String),

    #[error("unsupported Daml-LF 2 minor version: '{0}' (supported: 2.1, 2.2, 2.3, 2.4)")]
    UnsupportedMinorVersion(String),

    /// The package uses a feature its LF version does not have (`DecodeV2.notSupportedError`).
    #[error("{0}")]
    UnsupportedFeature(String),

    #[error(
        "interned table index out of bounds: index {index} >= table size {table_size} in {context}"
    )]
    InternedIndexOutOfBounds {
        index: i32,
        table_size: usize,
        context: &'static str,
    },

    /// The JVM refuses a bare type constructor or builtin outside the interning table, and a table entry that is
    /// itself only a reference ("Immediate Interned type in interning table"), as `DAR_PARSE_ERROR` (S-LF-009).
    #[error("invalid type form in {0}")]
    InvalidTypeForm(&'static str),

    /// The JVM answers `DAR_PARSE_ERROR` ("Unexpected PackageError Exception") for a module name that appears twice.
    #[error("duplicate module name index {0}")]
    DuplicateModule(i32),

    #[error("missing package metadata")]
    MissingMetadata,

    #[error("record definition for template '{template}' not found in module data types")]
    TemplateRecordNotFound { template: String },

    #[error("invalid record definition for template '{template}': {reason}")]
    InvalidTemplateRecord { template: String, reason: String },

    #[error("parameter record '{type_name}' for choice '{choice}' not found in module data types")]
    ChoiceRecordNotFound { choice: String, type_name: String },

    #[error("template '{0}' must have at least one signatory resolved")]
    MissingSignatory(String),

    #[error("could not resolve controller for choice '{0}'")]
    UnresolvedChoiceController(String),

    #[error("invalid or unsupported type construct: {0}")]
    InvalidType(String),

    #[error("type or expression recursion limit exceeded in {context}")]
    RecursionLimitExceeded { context: &'static str },
}

/// Top-level error type for DAR archive extraction and parsing.
#[derive(Debug, Error)]
pub enum DarError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ZIP decompression error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),

    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),

    #[error("decompression bomb defense: entry '{entry}' size {size} bytes exceeds ceiling {limit} bytes")]
    EntryTooLarge {
        entry: String,
        size: u64,
        limit: u64,
    },

    #[error("decompression bomb defense: total archive size {total} bytes exceeds ceiling {limit} bytes")]
    ArchiveTooLarge { total: u64, limit: u64 },

    #[error("path traversal defense: entry name '{0}' contains illegal path components")]
    PathTraversal(String),

    #[error("main dalf '{0}' specified in manifest not found in archive")]
    MainDalfNotFound(String),

    #[error("empty archive: no valid DALF entries found")]
    EmptyArchive,

    /// [CANTON-NOTE: ORACLE] The JVM upload endpoint answers `INVALID_ZIP_ENTRY` when the manifest `Dalfs` header
    /// lists a file the archive does not contain (S-GUARD-004, AT-A03).
    #[error("manifest Dalfs lists '{0}', which is not an entry of the archive")]
    ManifestDalfNotFound(String),

    /// The JVM answers `DAR_DEPENDENCIES_NOT_VALID` (S-GUARD-004, AT-A07).
    #[error("package dependency {0} is neither in the DAR nor known")]
    MissingDependency(String),

    /// The JVM answers `DAR_VALIDATION_ERROR` (`ETypeMismatch`, `EFieldTypeMismatch` ...): a package does not type-check
    /// (S-LF-009; checked by `typecheck.rs`, U-11, S-LF-016).
    #[error("package validation failed: {0}")]
    Validation(String),

    /// The JVM answers `INVALID_ZIP_ENTRY` for an empty or missing `Dalfs` header (S-GUARD-004, AT-A03).
    #[error("manifest Dalfs header is empty or missing")]
    EmptyDalfsList,
}

impl DarError {
    /// The error code the Canton 3.7.2 upload endpoint answers for this failure (S-LF-014; measured on the 56 cases of
    /// `tests/oracle/dar-input`).
    ///
    /// [CANTON-NOTE: LIMITATION] Four cases the node accepts are refused here as `INVALID_DAR` on purpose (path traversal in
    /// an entry name, an entry above the size ceiling): the loader's defenses are stricter than the node's.
    pub fn node_code(&self) -> &'static str {
        match self {
            DarError::MissingDependency(_) => "DAR_DEPENDENCIES_NOT_VALID",
            DarError::Validation(_) => "DAR_VALIDATION_ERROR",
            DarError::MainDalfNotFound(_)
            | DarError::ManifestDalfNotFound(_)
            | DarError::EmptyDalfsList => "INVALID_ZIP_ENTRY",
            DarError::Decode(
                DecodeError::UnsupportedMajorVersion(_) | DecodeError::UnsupportedMinorVersion(_),
            ) => "ALLOWED_LANGUAGE_VERSIONS",
            DarError::Decode(_) => "DAR_PARSE_ERROR",
            _ => "INVALID_DAR",
        }
    }
}
