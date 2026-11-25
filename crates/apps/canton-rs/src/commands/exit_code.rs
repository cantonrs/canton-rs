//! Structured CLI process exit codes matching `S-DX` Axiom A4 (`0 / 1 / 2 / 3`).
//!
//! [CANTON-NOTE: INVARIANT] Commands return `Result<(), String>` so domain helpers stay testable in
//! unit tests without calling `std::process::exit`. When a subcommand needs a specific non-1 exit
//! code (`2` for preflight/rejected input, `3` for verification mismatch), it encodes the code via
//! this module and [`crate::main`] exits cleanly with that code.

/// Success (warnings allowed).
pub const EXIT_OK: i32 = 0;
/// Unexpected or internal error.
pub const EXIT_INTERNAL: i32 = 1;
/// Preflight failure (`daemon doctor` / `daemon up`) or rejected user input.
pub const EXIT_PREFLIGHT: i32 = 2;
/// Verification mismatch (corrupt snapshot, oracle diff, or digest mismatch).
#[allow(dead_code, reason = "shared A4 exit code used by upcoming S-DX slices")]
pub const EXIT_MISMATCH: i32 = 3;

const SILENT_PREFIX: &str = "\x1bCANTON_EXIT_SILENT:";
const MSG_PREFIX: &str = "\x1bCANTON_EXIT:";

/// Returns an error marker telling `main` to exit with `code` without printing an extra error line.
pub fn silent_exit(code: i32) -> String {
    format!("{SILENT_PREFIX}{code}")
}

/// Returns an error marker telling `main` to print `msg` to stderr and exit with `code`.
#[allow(dead_code, reason = "shared A4 exit helper for S-DX slices")]
pub fn exit_with_message(code: i32, msg: impl std::fmt::Display) -> String {
    format!("{MSG_PREFIX}{code}:{msg}")
}

/// Decodes a `Result<(), String>` error into `(exit_code, optional_stderr_message)`.
pub fn decode_exit(err: &str) -> (i32, Option<&str>) {
    if let Some(code_str) = err.strip_prefix(SILENT_PREFIX) {
        let code = code_str.trim().parse::<i32>().unwrap_or(EXIT_INTERNAL);
        return (code, None);
    }
    if let Some(rest) = err.strip_prefix(MSG_PREFIX) {
        if let Some((code_str, msg)) = rest.split_once(':') {
            let code = code_str.trim().parse::<i32>().unwrap_or(EXIT_INTERNAL);
            return (code, Some(msg));
        }
    }
    (EXIT_INTERNAL, Some(err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_silent_messaged_and_plain_errors() {
        assert_eq!(decode_exit(&silent_exit(EXIT_PREFLIGHT)), (2, None));
        assert_eq!(
            decode_exit(&exit_with_message(EXIT_MISMATCH, "digest mismatch")),
            (3, Some("digest mismatch"))
        );
        assert_eq!(decode_exit("boom"), (1, Some("boom")));
    }
}
