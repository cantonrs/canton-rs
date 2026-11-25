//! JAR Manifest (`META-INF/MANIFEST.MF`) RFC 822 unfolding and parsing.

use crate::error::ManifestError;
use std::collections::BTreeMap;

/// Parsed representation of a DAR archive manifest (`META-INF/MANIFEST.MF`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Relative path to the primary contract DALF inside the archive.
    pub main_dalf: String,

    /// List of relative paths to dependency DALFs bundled in the archive.
    pub dalfs: Vec<String>,

    /// Optional format identifier (typically "daml-lf").
    pub format: Option<String>,

    /// Optional package name declared in manifest.
    pub name: Option<String>,

    /// Optional SDK version that produced the DAR.
    pub sdk_version: Option<String>,

    /// Optional package version declared in manifest.
    pub version: Option<String>,

    /// Raw header attributes extracted from the manifest.
    pub raw_attributes: BTreeMap<String, String>,
}

impl Manifest {
    /// Parses raw manifest bytes into a `Manifest` structure.
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        let text = std::str::from_utf8(bytes)?;
        Self::parse_str(text)
    }

    /// Parses manifest UTF-8 text into a `Manifest` structure.
    pub fn parse_str(text: &str) -> Result<Self, ManifestError> {
        let unfolded_lines = unfold_rfc822_lines(text);
        let mut attributes = BTreeMap::new();

        for line in unfolded_lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some((key, val)) = trimmed.split_once(':') {
                let k = key.trim().to_string();
                let v = val.trim().to_string();
                attributes.insert(k, v);
            }
        }

        // Helper to find header case-insensitively
        let get_attr = |name: &str| -> Option<String> {
            for (k, v) in &attributes {
                if k.eq_ignore_ascii_case(name) {
                    return Some(v.clone());
                }
            }
            None
        };

        let main_dalf = get_attr("Main-Dalf").ok_or(ManifestError::MissingMainDalf)?;
        let format = get_attr("Format");
        let name = get_attr("Name");
        let sdk_version = get_attr("Sdk-Version");
        let version = get_attr("Version");

        let mut dalfs = Vec::new();
        if let Some(dalfs_str) = get_attr("Dalfs") {
            for item in dalfs_str.split(|c: char| c == ',' || c.is_whitespace()) {
                let trimmed = item.trim();
                if !trimmed.is_empty() {
                    dalfs.push(trimmed.to_string());
                }
            }
        }

        Ok(Manifest {
            main_dalf,
            dalfs,
            format,
            name,
            sdk_version,
            version,
            raw_attributes: attributes,
        })
    }
}

/// Unfolds RFC 822 space/tab continuation lines.
/// Lines starting with ' ' or '\t' have that leading whitespace stripped
/// and are appended directly to the preceding line.
pub fn unfold_rfc822_lines(input: &str) -> Vec<String> {
    let mut logical_lines: Vec<String> = Vec::new();

    for raw_line in input.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if let Some(continuation) = line.strip_prefix(' ').or_else(|| line.strip_prefix('\t')) {
            if let Some(last) = logical_lines.last_mut() {
                last.push_str(continuation);
            } else {
                logical_lines.push(continuation.to_string());
            }
        } else {
            logical_lines.push(line.to_string());
        }
    }

    logical_lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unfold_rfc822_lines() {
        let input = "Main-Dalf: very-long-contract-name-that-is-split-across\r\n -multiple-lines.dalf\r\nName: test\r\n";
        let unfolded = unfold_rfc822_lines(input);
        assert_eq!(unfolded.len(), 2);
        assert_eq!(
            unfolded[0],
            "Main-Dalf: very-long-contract-name-that-is-split-across-multiple-lines.dalf"
        );
        assert_eq!(unfolded[1], "Name: test");
    }

    #[test]
    fn test_parse_valid_manifest() {
        let input = "Manifest-Version: 1.0\r\nMain-Dalf: contract.dalf\r\nDalfs: dep1.dalf, dep2.dalf\r\nFormat: daml-lf\r\nName: sample\r\nVersion: 1.0.0\r\n";
        let manifest = Manifest::parse_str(input).unwrap();
        assert_eq!(manifest.main_dalf, "contract.dalf");
        assert_eq!(manifest.dalfs, vec!["dep1.dalf", "dep2.dalf"]);
        assert_eq!(manifest.name.as_deref(), Some("sample"));
        assert_eq!(manifest.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn test_parse_manifest_missing_main_dalf() {
        let input = "Manifest-Version: 1.0\r\nName: sample\r\n";
        let res = Manifest::parse_str(input);
        assert!(matches!(res, Err(ManifestError::MissingMainDalf)));
    }
}
