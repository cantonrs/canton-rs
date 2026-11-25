//! G9 (AT-D11): the database an official participant wrote, read by `canton_participant::takeover`, gives what the official node answered
//! through its Ledger API before it stopped: each party's active contracts (ids, templates, the offsets of their creates, in order) and the
//! ledger end. Run by `scripts/oracle-db-takeover.sh` (`CANTON_RS_TAKEOVER_URL`, `CANTON_RS_TAKEOVER_ANSWERS`); prints `TAKEOVER` lines.
#![cfg(feature = "pg-tests")]

use canton_participant::migrate::WriterLock;
use canton_participant::takeover::{
    active_contracts, build_v12_create_for_dar, ledger_end, ActiveContract, TakeoverArchive,
    TakeoverRejected, TakeoverTx, TakeoverWriter,
};
use postgres::{Client, NoTls};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn the_rust_side_reads_what_the_official_participant_answered_from_its_database() {
    let (Ok(url), Ok(answers)) = (
        std::env::var("CANTON_RS_TAKEOVER_URL"),
        std::env::var("CANTON_RS_TAKEOVER_ANSWERS"),
    ) else {
        eprintln!("not run: scripts/oracle-db-takeover.sh gives the database and the official node's answers");
        return;
    };
    let text = std::fs::read_to_string(&answers).expect("the official node's answers");
    let mut acs: BTreeMap<String, Vec<ActiveContract>> = BTreeMap::new();
    let (mut end, mut participant) = (None, None);
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f[0] {
            "acs" => acs
                .entry(f[1].to_string())
                .or_default()
                .push(ActiveContract {
                    contract_id: f[2].to_string(),
                    template_id: f[3].to_string(),
                    offset: f[4].parse().unwrap(),
                }),
            "end" => end = Some(f[1].parse::<i64>().unwrap()),
            "participant" => participant = Some(f[1].trim_start_matches("PAR::").to_string()),
            _ => {}
        }
    }
    let mut client = Client::connect(&url, NoTls).expect("the database");
    let ours = ledger_end(&mut client).unwrap().expect("a ledger end");
    assert_eq!(Some(ours.offset), end, "the ledger end");
    assert_eq!(
        Some(ours.participant_id.clone()),
        participant,
        "the participant"
    );
    println!(
        "TAKEOVER ledger end {} (sequential id {})",
        ours.offset, ours.sequential_id
    );
    assert!(acs.len() >= 2, "the node answered for two parties");
    for (party, theirs) in &acs {
        let read = active_contracts(&mut client, party, &ours).unwrap();
        assert_eq!(&read, theirs, "the active contracts of {party}");
        println!(
            "TAKEOVER {} active contracts of {} equal the node's",
            read.len(),
            party.split("::").next().unwrap()
        );
    }
    // the node stopped: the database is free for a writer, and it is the Rust side that takes it
    let db = url.rsplit('/').next().unwrap();
    let lock = WriterLock::take(Client::connect(&url, NoTls).unwrap(), db)
        .expect("nobody writes the database any more");
    println!("TAKEOVER took the writer lock {}", lock.id());
}

#[test]
fn rust_writes_to_the_official_database() {
    let Ok(url) = std::env::var("CANTON_RS_TAKEOVER_WRITE_URL") else {
        eprintln!("not run: CANTON_RS_TAKEOVER_WRITE_URL is not set");
        return;
    };
    let answers = std::env::var("CANTON_RS_TAKEOVER_ANSWERS")
        .expect("CANTON_RS_TAKEOVER_ANSWERS must be set with CANTON_RS_TAKEOVER_WRITE_URL");
    let dar_path = std::env::var("CANTON_RS_TAKEOVER_DAR")
        .expect("CANTON_RS_TAKEOVER_DAR must be set with CANTON_RS_TAKEOVER_WRITE_URL");
    let out_path = std::env::var("CANTON_RS_TAKEOVER_WRITE_OUT")
        .expect("CANTON_RS_TAKEOVER_WRITE_OUT must be set with CANTON_RS_TAKEOVER_WRITE_URL");

    let text = std::fs::read_to_string(&answers).expect("initial JVM answers");
    let mut parties: Vec<String> = Vec::new();
    let mut initial_acs: BTreeMap<String, Vec<ActiveContract>> = BTreeMap::new();
    let mut initial_end = None;
    let mut participant = None;
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f[0] {
            "acs" => {
                let p = f[1].to_string();
                if !parties.contains(&p) {
                    parties.push(p.clone());
                }
                initial_acs.entry(p).or_default().push(ActiveContract {
                    contract_id: f[2].to_string(),
                    template_id: f[3].to_string(),
                    offset: f[4].parse().unwrap(),
                });
            }
            "end" => initial_end = Some(f[1].parse::<i64>().unwrap()),
            "participant" => participant = Some(f[1].to_string()),
            _ => {}
        }
    }
    let alice = parties
        .iter()
        .find(|p| p.starts_with("alice::"))
        .cloned()
        .expect("alice party in answers");
    let bob = parties
        .iter()
        .find(|p| p.starts_with("bob::"))
        .cloned()
        .expect("bob party in answers");
    let chf_cid = initial_acs
        .get(&alice)
        .and_then(|v| v.get(1))
        .expect("alice second active contract (CHF)")
        .contract_id
        .clone();
    let prev_end = initial_end.expect("initial end");

    let db = url.rsplit('/').next().unwrap().split('?').next().unwrap();
    let data_client = Client::connect(&url, NoTls).expect("data postgres connection");
    let lock_client = Client::connect(&url, NoTls).expect("lock postgres connection");
    let lock = WriterLock::take(lock_client, db).expect("writer lock for write takeover");
    let mut writer = TakeoverWriter::from_parts(data_client, lock);

    let before = ledger_end(writer.client_mut())
        .unwrap()
        .expect("ledger end before write");
    assert_eq!(before.offset, prev_end);

    // 1) Archive CHF (alice's second active contract)
    let r_arch = writer
        .append_transaction(&TakeoverTx {
            user_id: "CantonConsole".to_string(),
            command_id: "canton-rs-takeover-archive-chf".to_string(),
            submission_id: Some("sub-arch-1".to_string()),
            workflow_id: None,
            submitters: vec![alice.clone()],
            synchronizer_id: None,
            record_time_micros: None,
            creates: Vec::new(),
            archives: vec![TakeoverArchive::archive(&chf_cid, vec![alice.clone()], 0)],
        })
        .expect("archive CHF transaction");
    assert_eq!(r_arch.offset, prev_end + 1);

    // 2) Create V12 AssetHolding JPY 500.0 (bank=alice, owner=alice, auditor=bob)
    let salt = [0x42u8; 32];
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    let payload_json = serde_json::json!({
        "bank": alice,
        "owner": alice,
        "auditor": bob,
        "assetSymbol": "JPY",
        "amount": "500.0"
    });
    let jpy = build_v12_create_for_dar(
        &PathBuf::from(&dar_path),
        "AssetHolding",
        "AssetHolding",
        &payload_json,
        std::slice::from_ref(&alice),
        std::slice::from_ref(&bob),
        created_at,
        &salt,
        0,
    )
    .expect("build V12 JPY contract");
    let jpy_cid = jpy.contract_id.clone();

    let r_create = writer
        .append_transaction(&TakeoverTx {
            user_id: "CantonConsole".to_string(),
            command_id: "canton-rs-takeover-create-jpy".to_string(),
            submission_id: Some("sub-create-2".to_string()),
            workflow_id: Some("takeover-wf".to_string()),
            submitters: vec![alice.clone()],
            synchronizer_id: None,
            record_time_micros: None,
            creates: vec![jpy],
            archives: Vec::new(),
        })
        .expect("create JPY transaction");
    assert_eq!(r_create.offset, prev_end + 2);

    // 3) Rejected command completion
    let r_rej = writer
        .append_rejected_completion(&TakeoverRejected {
            user_id: "CantonConsole".to_string(),
            command_id: "canton-rs-takeover-rejected-cmd".to_string(),
            submission_id: Some("sub-rej-3".to_string()),
            submitters: vec![alice.clone()],
            synchronizer_id: None,
            record_time_micros: None,
            status_code: 9,
            status_message: "FAILED_PRECONDITION: post-takeover synthetic rejection".to_string(),
        })
        .expect("append rejected completion");
    assert_eq!(r_rej.offset, prev_end + 3);

    let after = ledger_end(writer.client_mut())
        .unwrap()
        .expect("ledger end after writes");
    assert_eq!(after.offset, r_rej.offset);
    assert_eq!(
        after.sequential_id,
        r_create.sequential_id_last.expect("create seq")
    );

    let mut out_lines = Vec::new();
    for p in &[&alice, &bob] {
        let acs = active_contracts(writer.client_mut(), p, &after).unwrap();
        assert!(
            !acs.iter().any(|c| c.contract_id == chf_cid),
            "CHF must no longer be active for {p}"
        );
        assert!(
            acs.iter()
                .any(|c| c.contract_id == jpy_cid && c.offset == r_create.offset),
            "JPY must be active for {p} at create offset {}",
            r_create.offset
        );
        for c in acs {
            out_lines.push(format!(
                "acs\t{p}\t{}\t{}\t{}",
                c.contract_id, c.template_id, c.offset
            ));
        }
    }
    out_lines.push(format!("end\t{}", after.offset));
    out_lines.push(format!(
        "participant\t{}",
        participant.unwrap_or_else(|| format!("PAR::{}", after.participant_id))
    ));
    std::fs::write(&out_path, out_lines.join("\n") + "\n").expect("write expected_after_write");
    println!(
        "WRITE_TAKEOVER prev_end={prev_end} new_end={} archived={chf_cid} created={jpy_cid}",
        after.offset
    );
    drop(writer);
}

#[test]
fn load_prune_safety_inputs_and_archive_on_official_canton_pg_db() {
    use canton_participant::cold_archive::{export_pg_range_to_segment, verify_single_segment};
    use canton_participant::official_prune::{
        check_prune_safety, highest_safe_prune_offset, load_prune_safety_inputs, PruneRefusal,
    };

    let url = std::env::var("CANTON_RS_TAKEOVER_URL")
        .expect("CANTON_RS_TAKEOVER_URL must point at the official Canton PG DB");
    let answers = std::env::var("CANTON_RS_TAKEOVER_ANSWERS")
        .expect("CANTON_RS_TAKEOVER_ANSWERS must be set with CANTON_RS_TAKEOVER_URL");
    let text = std::fs::read_to_string(&answers).expect("official node answers");
    let expected_end = text
        .lines()
        .find_map(|l| {
            let mut cols = l.split('\t');
            (cols.next() == Some("end")).then(|| cols.next().unwrap().parse::<i64>().unwrap())
        })
        .expect("end in answers");

    let mut client = Client::connect(&url, NoTls).expect("connect to official Canton PG DB");
    let inputs =
        load_prune_safety_inputs(&mut client).expect("load_prune_safety_inputs on official DB");
    assert_eq!(inputs.ledger_end, expected_end);
    assert!(
        inputs.max_dedup_micros.is_some(),
        "official Canton PG DB must populate par_settings.max_deduplication_duration: {inputs:?}"
    );
    assert!(
        inputs.first_offset_in_dedup_window.is_some(),
        "recent official Canton events must fall within dedup window: {inputs:?}"
    );
    assert_eq!(inputs.migrating_synchronizer, None);
    assert_eq!(inputs.missing_record_time_synchronizer, None);

    // Recent official events must keep ledger_end - 1 unsafe to prune (or safe bound strictly below).
    let verdict_near_end = check_prune_safety(inputs.ledger_end - 1, &inputs);
    assert!(
        matches!(verdict_near_end, Err(PruneRefusal::Unsafe { .. })),
        "pruning up to {} right after official writes must be unsafe: {verdict_near_end:?} ({inputs:?})",
        inputs.ledger_end - 1
    );
    let safe_max = highest_safe_prune_offset(&inputs);

    // Also verify read-only Cold Archive export & integrity verification on real official Canton PG rows.
    let seg = export_pg_range_to_segment(&mut client, 1, inputs.ledger_end, None, false, None)
        .expect("export official Canton PG events");
    verify_single_segment(&seg).expect("verify official Canton PG cold segment");
    assert!(
        !seg.events.is_empty(),
        "official Canton PG DB export must contain events"
    );
    println!(
        "OFFICIAL_PG_PRUNE ledger_end={} dedup_first_unsafe={:?} safe_max={:?} cold_events={}",
        inputs.ledger_end,
        inputs.first_offset_in_dedup_window,
        safe_max,
        seg.events.len()
    );
}
