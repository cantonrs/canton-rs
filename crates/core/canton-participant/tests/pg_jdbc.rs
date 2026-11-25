//! G9 (AT-D08): the connection target a Canton storage `config` block means, against what the official participant did with the same
//! blocks (`tests/oracle/db-startup/jdbc.tsv`, `scripts/oracle-db-jdbc.sh`): the database and schema its history went to, the application
//! name of its sessions, and the config it could not run on.
#![allow(
    clippy::type_complexity,
    reason = "protocol or ledger hook signature uses an inline composite type"
)] // [CANTON-NOTE: STYLE] one tuple type, named once
#![cfg(feature = "postgres")]

use canton_participant::pgconn::PgTarget;

/// The `key = value` pairs of one config line of the recording (strings quoted, `properties = { ... }` nested), as (top level, properties).
fn parse(config: &str) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let (mut top, mut props) = (Vec::new(), Vec::new());
    let (outer, inner) = match config.split_once("properties = {") {
        Some((o, rest)) => (
            o.to_string(),
            rest.trim_end().trim_end_matches('}').to_string(),
        ),
        None => (config.to_string(), String::new()),
    };
    let pairs = |text: &str, into: &mut Vec<(String, String)>| {
        for part in text.split(',') {
            if let Some((k, v)) = part.split_once('=') {
                into.push((k.trim().to_string(), v.trim().trim_matches('"').to_string()));
            }
        }
    };
    // a URL has `=` and `&` in it but no `,`: splitting at commas keeps it whole
    pairs(&outer, &mut top);
    pairs(&inner, &mut props);
    (top, props)
}

#[test]
fn a_storage_config_means_the_target_the_official_node_used() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/oracle/db-startup/jdbc.tsv");
    let text = std::fs::read_to_string(path).expect("the recording");
    let mut checked = 0;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        let (name, state, history_in, sessions, config) = (f[0], f[1], f[2], f[3], f[4]);
        let (top, props) = parse(&config.replace("@PG@", "pg"));
        let get = |k: &str| {
            top.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        let properties: Vec<(&str, &str)> = props
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let target =
            PgTarget::from_canton_config(get("url"), get("user"), get("password"), &properties);
        if state.starts_with("down") {
            let why = target.expect_err(name);
            assert!(why.contains("disagree"), "{name}: {why}");
        } else {
            let t = target.unwrap_or_else(|e| panic!("{name}: {e}"));
            let (db, schema) = history_in.split_once('/').unwrap();
            assert_eq!(
                (t.database.as_str(), t.schema.as_deref()),
                (db, Some(schema)),
                "{name}"
            );
            // the node's sessions carry the configured name (the data source also opens one with the driver's default name)
            let app = t.application_name.clone().expect("an application name");
            assert!(
                sessions.split(',').any(|s| s == format!("{db}/{app}")),
                "{name}: {app} in {sessions}"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 4);
}

/// The target's schema and application name are the session's (`CANTON_RS_PG_URL`, run by `scripts/verify-pg-migrate.sh`).
#[cfg(feature = "pg-tests")]
#[test]
fn a_connection_has_the_schema_and_the_name_its_config_says() {
    let url = std::env::var("CANTON_RS_PG_URL").expect("CANTON_RS_PG_URL");
    let rest = url.strip_prefix("postgres://").unwrap();
    let (cred, hostdb) = rest.split_once('@').unwrap();
    let (user, password) = cred.split_once(':').unwrap();
    let jdbc =
        format!("jdbc:postgresql://{hostdb}?currentSchema=pg_catalog&ApplicationName=canton%2Drs");
    let target =
        PgTarget::from_canton_config(Some(&jdbc), Some(user), Some(password), &[]).unwrap();
    let mut client = canton_participant::pgconn::connect(&target).expect("a connection");
    let (schema, name): (String, String) = {
        let r = client
            .query_one(
                "SELECT current_schema()::text, current_setting('application_name')",
                &[],
            )
            .unwrap();
        (r.get(0), r.get(1))
    };
    assert_eq!(
        (schema.as_str(), name.as_str()),
        ("pg_catalog", "canton-rs")
    );
}

#[cfg(feature = "pg-tests")]
#[test]
fn connection_init_sql_runs_on_connect_and_rejects_bad_sql() {
    let url = std::env::var("CANTON_RS_PG_URL").expect("CANTON_RS_PG_URL");
    let target = PgTarget::from_url_or_jdbc(
        &url,
        None,
        None,
        Some("SET TIME ZONE 'UTC'; SET application_name = 'init_hook_ok'"),
    )
    .expect("parse url");
    assert_eq!(
        target.connection_init_sql.as_deref(),
        Some("SET TIME ZONE 'UTC'; SET application_name = 'init_hook_ok'")
    );
    let mut client = canton_participant::pgconn::connect(&target).expect("connect with init sql");
    let row = client
        .query_one(
            "SELECT current_setting('TimeZone'), current_setting('application_name')",
            &[],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "UTC");
    assert_eq!(row.get::<_, String>(1), "init_hook_ok");

    // Bad SQL must fail cleanly with Canton's init error prefix
    let bad =
        PgTarget::from_url_or_jdbc(&url, None, None, Some("SET non_existent_canton_guc TO 1"))
            .unwrap();
    let Err(err) = canton_participant::pgconn::connect(&bad) else {
        panic!("expected bad connectionInitSql to fail");
    };
    assert!(
        err.starts_with("Failed to initialize new connection:"),
        "{err}"
    );
}
