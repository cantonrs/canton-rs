//! G9 (AT-R08): the Rust writer and an official participant on one database. Run by `scripts/oracle-db-writer.sh`, which starts the official
//! node on the database `CANTON_RS_WRITER_DB` and says what to expect (`CANTON_RS_WRITER_EXPECT`): `held` while the node runs, `free` after it
//! stopped. Prints `WRITER <outcome>` for the script's record.
#![cfg(feature = "pg-tests")]

use canton_participant::migrate::WriterLock;
use postgres::{Client, NoTls};

#[test]
fn the_rust_writer_takes_a_database_only_when_no_official_node_writes_it() {
    let (Ok(url), Ok(db), Ok(expect)) = (
        std::env::var("CANTON_RS_PG_URL"),
        std::env::var("CANTON_RS_WRITER_DB"),
        std::env::var("CANTON_RS_WRITER_EXPECT"),
    ) else {
        eprintln!("not run: scripts/oracle-db-writer.sh sets the database and what to expect");
        return;
    };
    let (head, _) = url.rsplit_once('/').unwrap();
    let client = Client::connect(&format!("{head}/{db}"), NoTls).expect("connection");
    match (WriterLock::take(client, &db), expect.as_str()) {
        (Err(why), "held") => println!(
            "WRITER refused: {}",
            why.split(" by the session").next().unwrap()
        ),
        (Ok(lock), "free") => println!("WRITER took the lock {}", lock.id()),
        (outcome, expected) => panic!(
            "expected the lock to be {expected}, got {}",
            outcome
                .map(|l| format!("taken {}", l.id()))
                .unwrap_or_else(|e| e)
        ),
    }
}
