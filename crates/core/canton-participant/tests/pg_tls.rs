//! G9 (AT-D09): one connection of the Rust side to a PostgreSQL server that speaks TLS, as `scripts/oracle-db-tls.sh` describes it
//! (`CANTON_RS_TLS_HOST`, `_PORT`, `_MODE`, `_CA`); prints `TLS connected` or `TLS refused: <why>` for the script, which compares it with
//! what the official node did with the same setting.
#![cfg(feature = "pg-tests")]

use canton_participant::pgconn::{connect, PgTarget, SslMode};

#[test]
fn one_tls_connection_as_the_script_describes_it() {
    let (Ok(host), Ok(port), Ok(mode)) = (
        std::env::var("CANTON_RS_TLS_HOST"),
        std::env::var("CANTON_RS_TLS_PORT"),
        std::env::var("CANTON_RS_TLS_MODE"),
    ) else {
        eprintln!("not run: scripts/oracle-db-tls.sh describes the connection");
        return;
    };
    let ca = std::env::var("CANTON_RS_TLS_CA").unwrap_or_default();
    let target = PgTarget {
        host,
        // the server is the container's published port; the name is only what its certificate is checked against
        hostaddr: Some("127.0.0.1".parse().unwrap()),
        port: port.parse().unwrap(),
        database: "postgres".into(),
        user: "canton".into(),
        password: "canton".into(),
        sslmode: SslMode::parse(&mode).expect("an sslmode"),
        root_cert: (!ca.is_empty()).then(|| std::fs::read(&ca).expect("the CA file")),
        schema: None,
        application_name: None,
        connection_init_sql: None,
    };
    match connect(&target) {
        Ok(mut client) => {
            let ssl: bool = client
                .query_one(
                    "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
                    &[],
                )
                .unwrap()
                .get(0);
            println!("TLS connected ssl={ssl}");
        }
        Err(why) => println!(
            "TLS refused: {}",
            why.replace('\n', " ").chars().take(160).collect::<String>()
        ),
    }
}
