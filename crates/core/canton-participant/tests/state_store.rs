//! S-LOCAL-006: both stores keep lines the same way. The directory store always runs; the database store runs when `CANTON_RS_STATE_PG_URL`
//! names a database (scripts/verify-state-pg.sh starts one).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use canton_participant::state_store::{FileStore, StateStore};

fn behaves_like_a_store(store: &dyn StateStore) {
    assert_eq!(
        store.read("journal").unwrap(),
        None,
        "nothing was ever written"
    );
    store.append("journal", "first").unwrap();
    store.append("journal", "second").unwrap();
    assert_eq!(
        store.read("journal").unwrap().as_deref(),
        Some("first\nsecond\n")
    );
    // replaced at once
    store.write("journal", "only\n").unwrap();
    assert_eq!(store.read("journal").unwrap().as_deref(), Some("only\n"));
    store.append("journal", "then").unwrap();
    assert_eq!(
        store.read("journal").unwrap().as_deref(),
        Some("only\nthen\n")
    );
    // keys are apart
    assert_eq!(store.read("other").unwrap(), None);
    // created once, never overwritten
    assert!(store.create_new("identity", "keys\n").unwrap());
    assert!(!store.create_new("identity", "other keys\n").unwrap());
    assert_eq!(store.read("identity").unwrap().as_deref(), Some("keys\n"));
}

#[test]
fn the_directory_store_keeps_lines() {
    let dir = std::env::temp_dir().join(format!("state-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = FileStore::new(&dir).unwrap();
    behaves_like_a_store(store.as_ref());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "postgres")]
#[test]
fn the_database_store_keeps_lines_and_lets_one_node_of_a_name_run() {
    use canton_participant::state_store::PgStore;
    let Ok(url) = std::env::var("CANTON_RS_STATE_PG_URL") else {
        eprintln!("not run: CANTON_RS_STATE_PG_URL names no database");
        return;
    };
    let name = format!("test-{}", std::process::id());
    let store = PgStore::connect(&url, &name).unwrap();
    behaves_like_a_store(store.as_ref());
    // a second process of the same name is refused while the first lives, and a node of another name is not
    let refused = PgStore::connect(&url, &name).err().expect("refused");
    assert!(
        refused.contains("one node of a name runs at a time"),
        "{refused}"
    );
    PgStore::connect(&url, &format!("{name}-other")).unwrap();
    // the state is the database's: a store opened after the first one is dropped reads it
    drop(store);
    let again = PgStore::connect(&url, &name).unwrap();
    assert_eq!(
        again.read("journal").unwrap().as_deref(),
        Some("only\nthen\n")
    );
}

/// Cuts the database sessions of the connections named `application` (what a database failover does to a node's connection).
#[cfg(feature = "postgres")]
fn cut_sessions(url: &str, application: &str) {
    let mut admin = postgres::Client::connect(url, postgres::NoTls).unwrap();
    admin
        .execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = $1",
            &[&application],
        )
        .unwrap();
}

/// A connection that is cut is made again, and the name's lock with it: the next call goes through and nothing was lost (S-STORE-016).
#[cfg(feature = "postgres")]
#[test]
fn a_database_store_whose_connection_was_cut_connects_again() {
    use canton_participant::state_store::PgStore;
    let Ok(url) = std::env::var("CANTON_RS_STATE_PG_URL") else {
        eprintln!("not run: CANTON_RS_STATE_PG_URL names no database");
        return;
    };
    let application = format!("cut-{}", std::process::id());
    let name = format!("cut-{}", std::process::id());
    let store = PgStore::connect(&format!("{url}?application_name={application}"), &name).unwrap();
    store.append("k", "one").unwrap();
    cut_sessions(&url, &application);
    store.append("k", "two").expect("connects again and writes");
    assert_eq!(store.read("k").unwrap().as_deref(), Some("one\ntwo\n"));
    // the lock was taken again with the new connection: another process of the name is still refused
    let refused = PgStore::connect(&url, &name).err().expect("refused");
    assert!(
        refused.contains("one node of a name runs at a time"),
        "{refused}"
    );
}

/// The name was taken by another process while the connection was down: the state is lost for good, and every later call says so rather than
/// writing lines beside the other node's.
#[cfg(feature = "postgres")]
#[test]
fn a_database_store_that_lost_its_name_to_another_process_stops_writing() {
    use canton_participant::state_store::PgStore;
    let Ok(url) = std::env::var("CANTON_RS_STATE_PG_URL") else {
        eprintln!("not run: CANTON_RS_STATE_PG_URL names no database");
        return;
    };
    let application = format!("lost-{}", std::process::id());
    let name = format!("lost-{}", std::process::id());
    let store = PgStore::connect(&format!("{url}?application_name={application}"), &name).unwrap();
    store.append("k", "mine").unwrap();
    cut_sessions(&url, &application);
    // the lock went with the session: another process takes the name before the first one connects again
    // [CANTON-NOTE: TEST] `pg_terminate_backend` only signals the backend: the advisory lock is let go when the backend has exited, a moment
    // later, so the other process may be refused for that moment and takes the name on a retry
    let other = (0..50)
        .find_map(|_| {
            PgStore::connect(&url, &name)
                .map_err(|_| std::thread::sleep(std::time::Duration::from_millis(100)))
                .ok()
        })
        .expect("the other process takes the name once the cut session is gone");
    let why = store
        .append("k", "late")
        .expect_err("the name is not ours any more");
    assert!(why.contains("taken by another process"), "{why}");
    assert!(store.append("k", "later").is_err(), "and it stays lost");
    assert_eq!(
        other.read("k").unwrap().as_deref(),
        Some("mine\n"),
        "nothing was written beside the other node's"
    );
}
