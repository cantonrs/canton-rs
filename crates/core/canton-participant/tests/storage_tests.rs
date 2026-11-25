use canton_participant::{compute_flyway_checksum, db_lock_id, flyway_file_checksum};

#[test]
fn test_flyway_checksum_line_ending_normalization_and_determinism_at_d04() {
    let sql_lf = "CREATE TABLE test_table (\n  id INT PRIMARY KEY,\n  name TEXT NOT NULL\n);";
    let sql_crlf =
        "CREATE TABLE test_table (\r\n  id INT PRIMARY KEY,\r\n  name TEXT NOT NULL\r\n);";
    let sql_bom =
        "\u{FEFF}CREATE TABLE test_table (\n  id INT PRIMARY KEY,\n  name TEXT NOT NULL\n);";

    let c1 = compute_flyway_checksum(sql_lf);
    let c2 = compute_flyway_checksum(sql_crlf);
    let c3 = compute_flyway_checksum(sql_bom);

    assert_eq!(
        c1, c2,
        "LF and CRLF must produce identical Flyway CRC32 checksum"
    );
    assert_eq!(
        c1, c3,
        "UTF-8 BOM must be stripped before Flyway CRC32 checksum"
    );

    let modified_sql =
        "CREATE TABLE test_table (\n  id BIGINT PRIMARY KEY,\n  name TEXT NOT NULL\n);";
    assert_ne!(c1, compute_flyway_checksum(modified_sql));
}

/// The advisory lock ids the official 3.7.2 participant allocated (`tests/oracle/db-startup/lock-ids.tsv`, its DEBUG log
/// "Allocated new lock ID ... for scope ... and counter ..."): every recorded (database, counter) gives the recorded id.
#[test]
fn the_db_lock_ids_are_the_ones_the_official_participant_allocated() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/oracle/db-startup/lock-ids.tsv");
    let text = std::fs::read_to_string(path).expect("the recording");
    let mut rows = 0;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        let (scope, counter, id): (&str, u32, i32) =
            (f[0], f[1].parse().unwrap(), f[2].parse().unwrap());
        assert_eq!(db_lock_id(scope, counter), id, "{scope} counter {counter}");
        rows += 1;
    }
    assert!(rows >= 5, "the recording has the node's locks: {rows}");
}

/// AT-D03: the checksum of migration files whose bytes vary (line endings, byte order marks, no final newline, empty lines, trailing spaces,
/// a placeholder, non-ASCII text, bytes that are not UTF-8) is what the official node recorded for them
/// (`tests/oracle/db-startup/checksums.tsv`, `scripts/oracle-flyway-checksum.sh`), and the refusal of the file that is not UTF-8 is its.
#[test]
fn flyway_checksums_of_varied_files_are_the_ones_the_official_node_recorded() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let oracle = base.join("tests/oracle/db-startup");
    let text = std::fs::read_to_string(oracle.join("checksums.tsv")).expect("the recording");
    let mut checked = 0;
    for line in text.lines().skip(1) {
        let (file, recorded) = line.split_once('\t').unwrap();
        // the node's own repeatable migration is vendored under migrations/; the others are fixtures
        let path = if file.starts_with("R___default") {
            base.join("crates/core/canton-participant/migrations/postgres/table_settings")
                .join(file)
        } else {
            oracle.join("checksum-fixtures").join(file)
        };
        let bytes = std::fs::read(&path).unwrap_or_else(|e| {
            panic!("missing checksum fixture {}: {e}", path.display());
        });
        let name = file.rsplit('/').next().unwrap();
        match (
            flyway_file_checksum(
                name,
                &bytes,
                &canton_participant::storage::FLYWAY_PLACEHOLDERS,
            ),
            recorded.strip_prefix("refused: "),
        ) {
            (Ok(sum), None) => assert_eq!(sum.to_string(), recorded, "{file}"),
            (Err(why), Some(theirs)) => assert_eq!(why, theirs, "{file}"),
            (ours, _) => panic!("{file}: ours {ours:?}, the node's {recorded}"),
        }
        checked += 1;
    }
    assert!(checked >= 12, "the fixtures were checked: {checked}");
}

/// AT-D06, the rule of `DbVersionCheck` (read from the source; the versions an image exists for are measured by
/// `scripts/verify-pg-versions.sh`): the expected majors pass silently, a higher one passes with a note, a lower one or a string that does
/// not parse is refused with the standard config and only noted without.
#[test]
fn the_postgres_version_rule_is_canton_s() {
    use canton_participant::storage::check_postgres_version as check;
    for ok in [
        "14.25 (Debian 14.25-1.pgdg13+1)",
        "16.15",
        "18.7 (Debian 18.7-1.pgdg13+2)",
    ] {
        assert_eq!(check(ok, true), Ok(None), "{ok}");
        assert_eq!(check(ok, false), Ok(None), "{ok}");
    }
    let higher = "Expected Postgres version 14, 15, 16, 17, or 18 but got higher version 19.1";
    assert_eq!(check("19.1", true), Ok(Some(higher.to_string())));
    assert_eq!(check("19.1", false), Ok(Some(higher.to_string())));
    let lower = "Expected Postgres version 14, 15, 16, 17, or 18 but got lower version 13.23 (Debian 13.23-1.pgdg13+1)";
    assert_eq!(
        check("13.23 (Debian 13.23-1.pgdg13+1)", true),
        Err(lower.to_string())
    );
    assert_eq!(
        check("13.23 (Debian 13.23-1.pgdg13+1)", false),
        Ok(Some(lower.to_string()))
    );
    assert!(check("devel", true)
        .unwrap_err()
        .starts_with("Exception in parsing Postgres version string devel"));
    assert!(check("devel", false).unwrap().is_some());
}

#[cfg(feature = "postgres")]
#[test]
fn embedded_official_migrations_match_recorded_flyway_history_and_checksums() {
    use canton_participant::migrate::{embedded_official, PLACEHOLDERS};
    let migrations = embedded_official().expect("embedded official migrations");
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let recorded =
        std::fs::read_to_string(base.join("tests/oracle/provenance/postgres-flyway-history.tsv"))
            .expect("recorded flyway history");
    let expected_rows: Vec<Vec<&str>> = recorded
        .lines()
        .skip(1)
        .filter(|l| l.starts_with("participant_db\t"))
        .map(|l| l.split('\t').collect())
        .collect();
    assert_eq!(migrations.len(), expected_rows.len());
    for (m, w) in migrations.iter().zip(&expected_rows) {
        let ver = if m.version.is_empty() {
            "-"
        } else {
            &m.version
        };
        assert_eq!(ver, w[2], "version mismatch for {}", m.script);
        assert_eq!(m.description, w[3], "description mismatch for {}", m.script);
        assert_eq!(m.script, w[5], "script mismatch");
        match (&m.sql, w[6]) {
            (Some(sql), want_sum) => {
                let sum = flyway_file_checksum(&m.script, sql.as_bytes(), &PLACEHOLDERS)
                    .expect("valid SQL checksum");
                assert_eq!(sum.to_string(), want_sum, "checksum for {}", m.script);
            }
            (None, "-") => {}
            (other, want) => panic!(
                "unexpected sql/checksum pair for {}: {other:?} vs {want}",
                m.script
            ),
        }
    }
}
