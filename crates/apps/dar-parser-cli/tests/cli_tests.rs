//! Integration tests for `dar-parser` CLI binary.

#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::path::PathBuf;
use std::process::Command;

fn get_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap() // crates/apps
        .parent()
        .unwrap() // crates
        .parent()
        .unwrap() // root
        .to_path_buf()
}

fn get_dar_parser_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dar-parser"))
}

fn get_fixtures_dir() -> PathBuf {
    let mut path = get_workspace_root();
    path.push("tests");
    path.push("e2e");
    path.push("fixtures");
    path
}

#[test]
fn test_cli_help() {
    let output = Command::new(get_dar_parser_bin())
        .arg("--help")
        .output()
        .expect("failed to execute dar-parser");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dar-parser"));
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("--json"));
    assert!(stdout.contains("--summary"));
    assert!(stdout.contains("--verbose"));
}

#[test]
fn test_cli_version() {
    let output = Command::new(get_dar_parser_bin())
        .arg("--version")
        .output()
        .expect("failed to execute dar-parser");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dar-parser 1.0.0"));
}

#[test]
fn test_cli_missing_arg() {
    let output = Command::new(get_dar_parser_bin())
        .output()
        .expect("failed to execute dar-parser");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage:") || stderr.contains("required") || stderr.contains("DAR_PATH")
    );
}

#[test]
fn test_cli_nonexistent_file() {
    let output = Command::new(get_dar_parser_bin())
        .arg("/nonexistent/file/path/here.dar")
        .output()
        .expect("failed to execute dar-parser");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error:"));
}

#[test]
fn test_cli_human_output_valid_minimal() {
    let dar_path = get_fixtures_dir().join("valid_minimal.dar");
    // [CANTON-NOTE: INVARIANT] A missing input is a failure, never a silent pass (AT-V01).
    assert!(
        dar_path.exists(),
        "required test input is missing: {}",
        dar_path.display()
    );

    let output = Command::new(get_dar_parser_bin())
        .arg(&dar_path)
        .output()
        .expect("failed to execute dar-parser");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Daml Archive (DAR) Inspection Report"));
    assert!(stdout.contains("Main Package ID:"));
    assert!(stdout.contains("Daml-LF Version: 2.1"));
    assert!(stdout.contains("sample-contract"));
    assert!(stdout.contains("0.1.0"));
    assert!(stdout.contains("AssetHolding"));
}

#[test]
fn test_cli_json_output_valid_minimal() {
    let dar_path = get_fixtures_dir().join("valid_minimal.dar");
    // [CANTON-NOTE: INVARIANT] A missing input is a failure, never a silent pass (AT-V01).
    assert!(
        dar_path.exists(),
        "required test input is missing: {}",
        dar_path.display()
    );

    let output = Command::new(get_dar_parser_bin())
        .arg("--json")
        .arg(&dar_path)
        .output()
        .expect("failed to execute dar-parser");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");

    assert_eq!(v["main_package"]["name"], "sample-contract");
    assert_eq!(v["main_package"]["version"], "0.1.0");
    assert_eq!(v["main_package"]["lf_version"], "2.1");
    assert!(v["main_package_id"].is_string());
    assert_eq!(v["main_package_id"].as_str().unwrap().len(), 64);
}

#[test]
fn test_cli_summary_output() {
    let dar_path = get_fixtures_dir().join("valid_minimal.dar");
    // [CANTON-NOTE: INVARIANT] A missing input is a failure, never a silent pass (AT-V01).
    assert!(
        dar_path.exists(),
        "required test input is missing: {}",
        dar_path.display()
    );

    let output = Command::new(get_dar_parser_bin())
        .arg("--summary")
        .arg(&dar_path)
        .output()
        .expect("failed to execute dar-parser");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("Package: sample-contract-0.1.0"));
    assert!(stdout.contains("LF: 2.1"));
    assert!(stdout.contains("AssetHolding"));
}

#[test]
fn test_cli_verbose_output() {
    let dar_path = get_fixtures_dir().join("valid_minimal.dar");
    // [CANTON-NOTE: INVARIANT] A missing input is a failure, never a silent pass (AT-V01).
    assert!(
        dar_path.exists(),
        "required test input is missing: {}",
        dar_path.display()
    );

    let output = Command::new(get_dar_parser_bin())
        .arg("--verbose")
        .arg(&dar_path)
        .output()
        .expect("failed to execute dar-parser");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[VERBOSE]"));
    assert!(stdout.contains("Primary Contract Package"));
    assert!(stdout.contains("Compiled Modules"));
    assert!(stdout.contains("DALF Package Inventory"));
}

#[test]
fn test_cli_corrupted_tampered_payload() {
    let dar_path = get_fixtures_dir().join("corrupt_tampered_payload.dar");
    // [CANTON-NOTE: INVARIANT] A missing input is a failure, never a silent pass (AT-V01).
    assert!(
        dar_path.exists(),
        "required test input is missing: {}",
        dar_path.display()
    );

    let output = Command::new(get_dar_parser_bin())
        .arg(&dar_path)
        .output()
        .expect("failed to execute dar-parser");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("mismatch"));
}

#[test]
fn test_cli_json_output_is_the_same_bytes_every_run() {
    let dar_path = get_workspace_root().join("contracts/target/sample-contract.dar");
    assert!(dar_path.exists(), "missing {}", dar_path.display());
    let run = || {
        let out = Command::new(get_dar_parser_bin())
            .arg("--json")
            .arg(&dar_path)
            .output()
            .expect("failed to execute dar-parser");
        assert!(out.status.success());
        out.stdout
    };
    let first = run();
    for _ in 0..4 {
        assert!(
            run() == first,
            "`--json` printed the packages in another order"
        );
    }
}

#[test]
fn test_cli_production_dar() {
    let dar_path = get_workspace_root().join("contracts/target/sample-contract.dar");
    // [CANTON-NOTE: INVARIANT] A missing input is a failure, never a silent pass (AT-V01).
    assert!(
        dar_path.exists(),
        "required test input is missing: {}",
        dar_path.display()
    );

    let output = Command::new(get_dar_parser_bin())
        .arg("--json")
        .arg(&dar_path)
        .output()
        .expect("failed to execute dar-parser");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");

    assert_eq!(
        v["main_package_id"],
        "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"
    );
    assert_eq!(v["main_package"]["name"], "sample-contract");
    assert_eq!(v["main_package"]["version"], "0.1.0");
    assert_eq!(v["main_package"]["lf_version"], "2.1");

    // Verify module_surfaces in JSON (both root and main_package)
    let surfaces = v["module_surfaces"]
        .as_array()
        .expect("module_surfaces must be an array");
    assert_eq!(surfaces.len(), 1);
    assert_eq!(
        v["main_package"]["module_surfaces"].as_array().unwrap(),
        surfaces
    );

    let mod0 = &surfaces[0];
    assert_eq!(mod0["name"], "AssetHolding");
    let templates = mod0["templates"].as_array().unwrap();
    assert_eq!(templates.len(), 1);

    let tmpl = &templates[0];
    assert_eq!(tmpl["name"], "AssetHolding");
    assert_eq!(tmpl["param_name"], "this");

    let fields = tmpl["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 5);
    assert_eq!(fields[0]["name"], "bank");
    assert_eq!(fields[0]["type_str"], "Party");
    assert_eq!(fields[1]["name"], "owner");
    assert_eq!(fields[1]["type_str"], "Party");
    assert_eq!(fields[2]["name"], "auditor");
    assert_eq!(fields[2]["type_str"], "Party");
    assert_eq!(fields[3]["name"], "assetSymbol");
    assert_eq!(fields[3]["type_str"], "Text");
    assert_eq!(fields[4]["name"], "amount");
    assert_eq!(fields[4]["type_str"], "Decimal");

    assert_eq!(tmpl["signatories"], serde_json::json!(["bank", "owner"]));
    assert_eq!(tmpl["observers"], serde_json::json!(["auditor"]));
    assert_eq!(tmpl["ensure"]["present"], true);
    assert!(tmpl["ensure"]["bytes_len"].as_u64().unwrap() > 0);

    let choices = tmpl["choices"].as_array().unwrap();
    assert_eq!(choices.len(), 4);

    let transfer = choices.iter().find(|c| c["name"] == "Transfer").unwrap();
    assert_eq!(transfer["consuming"], true);
    assert_eq!(transfer["controllers"], serde_json::json!(["owner"]));
    assert_eq!(transfer["params"][0]["name"], "newOwner");
    assert_eq!(transfer["params"][0]["type_str"], "Party");
    assert_eq!(transfer["return_type_str"], "ContractId AssetHolding");
    assert_eq!(transfer["do_body"]["present"], true);

    let split = choices
        .iter()
        .find(|c| c["name"] == "SplitTransfer")
        .unwrap();
    assert_eq!(split["consuming"], true);
    assert_eq!(split["controllers"], serde_json::json!(["owner"]));
    assert_eq!(split["params"][0]["name"], "transferAmount");
    assert_eq!(split["params"][0]["type_str"], "Decimal");
    assert_eq!(split["params"][1]["name"], "recipient");
    assert_eq!(split["params"][1]["type_str"], "Party");
    assert_eq!(
        split["return_type_str"],
        "(ContractId AssetHolding, ContractId AssetHolding)"
    );
    assert_eq!(split["do_body"]["present"], true);

    let settle = choices.iter().find(|c| c["name"] == "Settle").unwrap();
    assert_eq!(settle["consuming"], true);
    assert_eq!(settle["controllers"], serde_json::json!(["bank"]));
    assert_eq!(settle["params"].as_array().unwrap().len(), 0);
    assert_eq!(settle["return_type_str"], "()");
    assert_eq!(settle["do_body"]["present"], true);

    let archive = choices.iter().find(|c| c["name"] == "Archive").unwrap();
    assert_eq!(archive["consuming"], true);
    assert_eq!(archive["controllers"], serde_json::json!(["bank", "owner"]));
    assert_eq!(archive["params"].as_array().unwrap().len(), 0);
    assert_eq!(archive["return_type_str"], "()");
    assert_eq!(archive["do_body"]["present"], true);
}

#[test]
fn test_cli_production_dar_human_surface() {
    let dar_path = get_workspace_root().join("contracts/target/sample-contract.dar");
    // [CANTON-NOTE: INVARIANT] A missing input is a failure, never a silent pass (AT-V01).
    assert!(
        dar_path.exists(),
        "required test input is missing: {}",
        dar_path.display()
    );

    let output = Command::new(get_dar_parser_bin())
        .arg(&dar_path)
        .output()
        .expect("failed to execute dar-parser");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"));
    assert!(stdout.contains("template AssetHolding"));
    assert!(stdout.contains("bank : Party"));
    assert!(stdout.contains("owner : Party"));
    assert!(stdout.contains("auditor : Party"));
    assert!(stdout.contains("assetSymbol : Text"));
    assert!(stdout.contains("amount : Decimal"));
    assert!(stdout.contains("Signatories: bank, owner"));
    assert!(stdout.contains("Observers: auditor"));
    assert!(stdout.contains("Ensure Precondition: present"));
    assert!(stdout.contains("choice Transfer (consuming)"));
    assert!(stdout.contains("newOwner : Party"));
    assert!(stdout.contains("choice SplitTransfer (consuming)"));
    assert!(stdout.contains("transferAmount : Decimal, recipient : Party"));
    assert!(stdout.contains("choice Settle (consuming)"));
    assert!(stdout.contains("Controller: bank"));
    assert!(stdout.contains("choice Archive (consuming)"));
    assert!(stdout.contains("Do Body: present"));
}

#[test]
fn test_cli_production_dar_verbose_surface() {
    let dar_path = get_workspace_root().join("contracts/target/sample-contract.dar");
    // [CANTON-NOTE: INVARIANT] A missing input is a failure, never a silent pass (AT-V01).
    assert!(
        dar_path.exists(),
        "required test input is missing: {}",
        dar_path.display()
    );

    let output = Command::new(get_dar_parser_bin())
        .arg("--verbose")
        .arg(&dar_path)
        .output()
        .expect("failed to execute dar-parser");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("[VERBOSE]"));
    assert!(stdout.contains("template AssetHolding"));
    assert!(stdout.contains("Signatories: bank, owner"));
    assert!(stdout.contains("Observers: auditor"));
    assert!(stdout.contains("choice SplitTransfer (consuming)"));
}
