//! S-LF-002: `lf-eval --batch` evaluates many cases against one loaded DAR and reports each case as
//! `id<TAB>OK<TAB>value` or `id<TAB>ERR<TAB>message`; a failing case must not stop the batch.
use std::{fs, path::PathBuf, process::Command};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root")
        .to_path_buf()
}

#[test]
fn batch_reports_values_and_errors_per_case_and_keeps_going() {
    let dar = root().join("tests/oracle/lf-corpus/lf-corpus.dar");
    assert!(dar.exists(), "missing {}", dar.display());
    let cases = std::env::temp_dir().join(format!("lf-eval-batch-{}.tsv", std::process::id()));
    fs::write(
        &cases,
        "a\taddInt\ti:2\ti:40\n\
         b\tdivInt\ti:1\ti:0\n\
         c\tappendText\tt:ab\tt:c\n\
         d\taddInt\ti:9223372036854775807\ti:1\n\
         \n\
         e\teqInt\ti:3\ti:3\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_lf-eval"))
        .args(["--batch", dar.to_str().unwrap(), "Main"])
        .arg(&cases)
        .output()
        .expect("run lf-eval");
    let _ = fs::remove_file(&cases);
    assert!(out.status.success(), "batch itself must succeed");
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<Vec<&str>> = text.lines().map(|l| l.split('\t').collect()).collect();
    assert_eq!(
        lines.len(),
        5,
        "one line per case, blank line skipped: {text}"
    );
    assert_eq!(&lines[0][..3], ["a", "OK", "42"]);
    assert_eq!(lines[1][..2], ["b", "ERR"]);
    assert_eq!(&lines[2][..3], ["c", "OK", "\"abc\""]);
    assert_eq!(
        lines[3][..2],
        ["d", "ERR"],
        "Int64 overflow is an error, not a wrap"
    );
    assert_eq!(&lines[4][..3], ["e", "OK", "true"]);
}

#[test]
fn batch_without_enough_arguments_is_a_usage_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_lf-eval"))
        .args(["--batch", "only-a-dar"])
        .output()
        .expect("run lf-eval");
    assert_eq!(out.status.code(), Some(2));
}
