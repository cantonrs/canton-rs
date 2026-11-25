//! G9 (AT-D09, the failover half): a Rust writer whose database connection breaks treats its lock as lost, as the official participant does
//! (`tests/oracle/db-failover/outcome.tsv`), and takes it again only when nobody else wrote the database meanwhile.
//! Needs `CANTON_RS_PG_URL` (a superuser URL; `scripts/verify-pg-migrate.sh` sets it).
#![cfg(feature = "pg-tests")]

use canton_participant::migrate::{LockState, WriterLock};
use postgres::{Client, NoTls};

fn scratch(url: &str, name: &str) -> (Client, String) {
    let mut admin = Client::connect(url, NoTls).expect("admin connection");
    // one statement per call: `DROP`/`CREATE DATABASE` cannot run in the transaction block a batch makes
    admin
        .batch_execute(&format!("DROP DATABASE IF EXISTS {name}"))
        .unwrap();
    admin
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .unwrap();
    let (head, _) = url.rsplit_once('/').unwrap();
    (admin, format!("{head}/{name}"))
}

fn connect(url: &str) -> Client {
    Client::connect(url, NoTls).expect("connection")
}

/// Ends the sessions of the database from outside, as a failover does to the node's connections.
fn kill_sessions(admin: &mut Client, db: &str) {
    admin
        .execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
            &[&db],
        )
        .unwrap();
}

#[test]
fn a_lost_connection_loses_the_lock_and_it_is_rebuilt_only_when_nobody_else_took_it() {
    let Ok(url) = std::env::var("CANTON_RS_PG_URL") else {
        eprintln!("not run: CANTON_RS_PG_URL is not set");
        return;
    };
    let db = format!("wl_{}", std::process::id());
    let (mut admin, db_url) = scratch(&url, &db);
    let mut lock = WriterLock::take(connect(&db_url), &db).expect("the free database is taken");
    assert_eq!(lock.check(), LockState::Held);

    // the connection breaks: the check cannot be answered, and an unanswered check is a lost lock
    kill_sessions(&mut admin, &db);
    assert_eq!(lock.check(), LockState::Lost);

    // another writer takes the database while the lock is lost: the rebuild must refuse, and the lock stays lost
    let other = WriterLock::take(connect(&db_url), &db).expect("the lock is free after the loss");
    let refused = lock.rebuild(connect(&db_url), &db).unwrap_err();
    assert!(refused.contains("has a writer already"), "{refused}");
    assert_eq!(lock.check(), LockState::Lost);
    drop(other);

    // nobody holds it any more: the rebuild works and the lock is held again
    lock.rebuild(connect(&db_url), &db).expect("rebuilt");
    assert_eq!(lock.check(), LockState::Held);
    drop(lock);
    admin.batch_execute(&format!("DROP DATABASE {db}")).unwrap();
}
