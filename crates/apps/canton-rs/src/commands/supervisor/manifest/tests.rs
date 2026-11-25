use super::*;

#[test]
fn expands_env_vars_and_masks_postgres_secret_in_config_summary() {
    let dotenv =
        parse_dotenv_str("PARTICIPANT1_PG_URL=postgres://canton:topsecretpw@127.0.0.1:6432/p1\n");
    let yaml = r#"
name: ${STACK_NAME:-dev-stack}
synchronizer: dev-sync
state_dir: ./state
metrics_port: 9464
services:
  participant1:
    role: participant
    ports: ["7575:json-api"]
    storage:
      type: postgres
      url: ${PARTICIPANT1_PG_URL}
    depends_on: [sequencer1]
  sequencer1:
    role: sequencer
    ports: ["5018:public"]
"#;
    let parsed =
        parse_yaml_manifest_str(yaml, Path::new("."), &dotenv, None).expect("parse Mode A yaml");
    let ParsedYamlManifest::ModeA(spec) = parsed else {
        panic!("expected ModeA");
    };
    assert_eq!(spec.name, "dev-stack");
    // sequencer1 must be topologically sorted before participant1 despite YAML order.
    assert_eq!(spec.services[0].name, "sequencer1");
    assert_eq!(spec.services[1].name, "participant1");

    let summary = format_masked_config_summary(&spec);
    assert!(!summary.contains("topsecretpw"));
    assert!(summary.contains("****"));
}

#[test]
fn auth_cert_reaches_the_participant_argv_and_is_refused_elsewhere() {
    let dotenv = BTreeMap::new();
    let yaml = r#"
services:
  seq1:
    role: sequencer
    ports: ["5018:public"]
  p1:
    role: participant
    ports: ["7575:json-api"]
    auth_cert: /certs/jwt.crt
    token_file: /certs/admin.jwt
    depends_on: [seq1]
  q1:
    role: pqs
    ledger_of: p1
    storage: { type: postgres, url: "postgres://u@127.0.0.1:1/pqs" }
    depends_on: [p1]
"#;
    let ParsedYamlManifest::ModeA(spec) =
        parse_yaml_manifest_str(yaml, Path::new("."), &dotenv, None).expect("parse")
    else {
        panic!("expected ModeA");
    };
    let p1 = spec.services.iter().find(|s| s.name == "p1").expect("p1");
    assert_eq!(
        p1.token,
        Some(super::super::TokenSource::File(PathBuf::from(
            "/certs/admin.jwt"
        )))
    );
    let pqs = spec.services.iter().find(|s| s.name == "q1").expect("q1");
    let at = pqs
        .argv
        .iter()
        .position(|a| a == "--token-file")
        .expect("pqs inherits the participant token file");
    assert_eq!(pqs.argv[at + 1], "/certs/admin.jwt");
    let at = p1
        .argv
        .iter()
        .position(|a| a == "--auth-cert")
        .expect("participant argv carries --auth-cert");
    assert_eq!(p1.argv[at + 1], "/certs/jwt.crt");

    let on_sequencer = r#"
services:
  seq1:
    role: sequencer
    ports: ["5018:public"]
    auth_cert: /certs/jwt.crt
"#;
    let err = parse_yaml_manifest_str(on_sequencer, Path::new("."), &dotenv, None)
        .expect_err("auth_cert on a sequencer cannot be honoured");
    assert!(err.contains("auth_cert"), "{err}");
}

/// A BFT sequencer serves gRPC admin on `admin` and its status HTTP on `metrics`; one port cannot be both, and its genesis
/// identity is made in its file store, so other storage would run with different keys.
#[test]
fn bft_sequencer_needs_separate_admin_and_metrics_and_file_storage() {
    let dotenv = BTreeMap::new();
    let shared = r#"
services:
  s1:
    role: sequencer
    bft_group: g
    ports: ["5018:public", "5019:admin"]
"#;
    let err = parse_yaml_manifest_str(shared, Path::new("."), &dotenv, None)
        .expect_err("admin doubling as metrics is refused");
    assert!(err.contains("metrics"), "{err}");

    let pg = r#"
services:
  s1:
    role: sequencer
    bft_group: g
    ports: ["5018:public", "5019:admin", "5021:metrics"]
    storage: { type: postgres, url: "postgres://u@127.0.0.1:1/x" }
"#;
    let err = parse_yaml_manifest_str(pg, Path::new("."), &dotenv, None)
        .expect_err("BFT with postgres storage is refused");
    assert!(err.contains("storage"), "{err}");

    let ok = r#"
services:
  s1:
    role: sequencer
    bft_group: g
    ports: ["5018:public", "5019:admin", "5021:metrics"]
"#;
    parse_yaml_manifest_str(ok, Path::new("."), &dotenv, None).expect("separate ports parse");
}

#[test]
fn rejects_port_collisions_and_cyclic_dependencies() {
    let dotenv = BTreeMap::new();
    let colliding = r#"
services:
  seq1:
    role: sequencer
    ports: ["5018:public"]
  p1:
    role: participant
    ports: ["5018:json-api"]
"#;
    let err = parse_yaml_manifest_str(colliding, Path::new("."), &dotenv, None)
        .expect_err("port collision should fail");
    assert!(err.contains("port collision on 5018"));

    let cyclic = r#"
services:
  a:
    role: sequencer
    depends_on: [b]
  b:
    role: mediator
    depends_on: [a]
"#;
    let err = parse_yaml_manifest_str(cyclic, Path::new("."), &dotenv, None)
        .expect_err("cycle should fail");
    assert!(err.contains("cyclic dependency"));
}

#[test]
fn generated_init_templates_parse_cleanly() {
    let dotenv = BTreeMap::new();
    for tmpl in [
        InitTemplate::Default,
        InitTemplate::Localnet,
        InitTemplate::EnterpriseDvp,
        InitTemplate::BftCluster,
        InitTemplate::MultiDomain,
        InitTemplate::OrgProduction,
    ] {
        let yaml = render_init_yaml(tmpl, None, None);
        let parsed = parse_yaml_manifest_str(&yaml, Path::new("."), &dotenv, None)
            .unwrap_or_else(|e| panic!("template {tmpl:?} failed to parse: {e}"));
        let ParsedYamlManifest::ModeA(spec) = parsed else {
            panic!("expected ModeA for {tmpl:?}");
        };
        match tmpl {
            InitTemplate::EnterpriseDvp => {
                assert_eq!(spec.cells.len(), 5);
                assert_eq!(spec.scenarios.len(), 1);
                let p_bank_a = spec
                    .services
                    .iter()
                    .find(|s| s.name == "p-bank-a")
                    .expect("p-bank-a");
                assert!(p_bank_a
                    .state_dir
                    .display()
                    .to_string()
                    .contains("cells/bank-a/p-bank-a"));
            }
            InitTemplate::BftCluster => {
                let bft_seqs: Vec<_> = spec
                    .services
                    .iter()
                    .filter(|s| s.role == NodeRole::Sequencer)
                    .collect();
                assert_eq!(bft_seqs.len(), 4);
                assert_eq!(bft_seqs[0].argv[1], "run-bft");
                assert_eq!(bft_seqs[0].bft_peer_count, Some(4));
            }
            InitTemplate::MultiDomain => {
                let bridge = spec
                    .services
                    .iter()
                    .find(|s| s.name == "p-dealer-bridge")
                    .expect("p-dealer-bridge");
                assert!(bridge.argv.iter().any(|a| a == "--also-sequencer"));
                assert!(bridge
                    .argv
                    .iter()
                    .any(|a| a == "usd-sync=http://127.0.0.1:5318"));
            }
            InitTemplate::OrgProduction => {
                let treasury = spec
                    .services
                    .iter()
                    .find(|s| s.name == "p-treasury")
                    .expect("p-treasury");
                assert!(treasury.argv.contains(&"http://127.0.0.1:5018".to_string()));
            }
            InitTemplate::Default | InitTemplate::Localnet => {}
        }
    }
    let mode_b = render_init_yaml(
        InitTemplate::Default,
        Some(Path::new("canton.conf")),
        Some(Path::new("bootstrap.sc")),
    );
    let parsed_b = parse_yaml_manifest_str(&mode_b, Path::new("."), &dotenv, None)
        .expect("generated Mode B init template must parse cleanly");
    assert!(matches!(parsed_b, ParsedYamlManifest::ModeB(_)));
}

#[test]
fn strict_cell_isolation_rejects_cross_cell_shared_postgres_and_filters_profiles() {
    let dotenv = BTreeMap::new();
    // Negative control: Bank A and Sec B both declare `isolation: strict` yet point at the
    // exact same PostgreSQL `(url, state_name)`. Must fail preflight before spawning!
    let cross_contaminated = r#"
name: contaminated-lab
cells:
  bank-a:
    isolation: strict
  sec-b:
    isolation: strict
services:
  seq1:
    role: sequencer
    ports: ["5018:public"]
  p-bank-a:
    role: participant
    group: bank-a
    ports: ["7575:json-api"]
    storage:
      type: postgres
      url: postgres://canton:secret@127.0.0.1:5432/shared_db
      name: shared_ledger_slot
    depends_on: [seq1]
  p-sec-b:
    role: participant
    group: sec-b
    ports: ["7585:json-api"]
    storage:
      type: postgres
      url: postgres://canton:secret@127.0.0.1:5432/shared_db
      name: shared_ledger_slot
    depends_on: [seq1]
"#;
    let err = parse_yaml_manifest_str(cross_contaminated, Path::new("."), &dotenv, None)
        .expect_err("cross-cell shared Postgres state must be rejected");
    assert!(err.contains("strict cell isolation violation"));
    assert!(
        !err.contains("secret@"),
        "error message must mask DB password: {err}"
    );

    // Positive control + profile/group transitive dependency filter:
    let dvp_yaml = render_init_yaml(InitTemplate::EnterpriseDvp, None, None);
    let ParsedYamlManifest::ModeA(mut spec) =
        parse_yaml_manifest_str(&dvp_yaml, Path::new("."), &dotenv, None).expect("parse dvp")
    else {
        panic!("expected ModeA");
    };
    super::super::topology::filter_spec_services(&mut spec, &[], &["bank-a".to_string()])
        .expect("filter bank-a group");
    let kept_names: Vec<&str> = spec.services.iter().map(|s| s.name.as_str()).collect();
    // Transitive dependencies `seq-core` and `med-core` must be kept automatically, while `p-sec-b` is excluded!
    assert_eq!(kept_names, vec!["seq-core", "med-core", "p-bank-a"]);
}

#[test]
fn xray_flag_is_off_by_default_and_opt_in_via_manifest() {
    let dotenv = BTreeMap::new();
    let default_yaml = "services:\n  p1:\n    role: participant\n    ports: [\"7575:json-api\"]\n";
    let ParsedYamlManifest::ModeA(spec_default) =
        parse_yaml_manifest_str(default_yaml, Path::new("."), &dotenv, None)
            .expect("parse default yaml")
    else {
        panic!("expected ModeA");
    };
    let p1 = &spec_default.services[0];
    assert!(!spec_default.xray);
    assert!(
        !p1.argv.iter().any(|a| a == "--xray"),
        "--xray must be opt-in and omitted by default: {:?}",
        p1.argv
    );
    assert!(
        p1.xray_url.is_none(),
        "xray_url must be None by default: {:?}",
        p1.xray_url
    );

    let enabled_yaml = "\
xray: true
services:
  p1:
    role: participant
    ports: [\"7575:json-api\"]
  p2:
    role: participant
    ports: [\"7576:json-api\"]
    xray: false
";
    let ParsedYamlManifest::ModeA(spec_enabled) =
        parse_yaml_manifest_str(enabled_yaml, Path::new("."), &dotenv, None)
            .expect("parse xray enabled yaml")
    else {
        panic!("expected ModeA");
    };
    assert!(spec_enabled.xray);
    let p1_on = spec_enabled
        .services
        .iter()
        .find(|s| s.name == "p1")
        .expect("p1");
    assert!(
        p1_on.argv.iter().any(|a| a == "--xray"),
        "top-level xray: true must pass --xray to p1: {:?}",
        p1_on.argv
    );
    assert_eq!(
        p1_on.xray_url.as_deref(),
        Some("http://127.0.0.1:7575/_xray")
    );
    let p2_off = spec_enabled
        .services
        .iter()
        .find(|s| s.name == "p2")
        .expect("p2");
    assert!(
        !p2_off.argv.iter().any(|a| a == "--xray"),
        "per-service xray: false must override top-level xray: true: {:?}",
        p2_off.argv
    );
    assert!(p2_off.xray_url.is_none());

    let svc_only_yaml = "\
services:
  p1:
    role: participant
    ports: [\"7575:json-api\"]
    xray: true
";
    let ParsedYamlManifest::ModeA(spec_svc) =
        parse_yaml_manifest_str(svc_only_yaml, Path::new("."), &dotenv, None)
            .expect("parse per-service xray yaml")
    else {
        panic!("expected ModeA");
    };
    assert!(spec_svc.services[0].argv.iter().any(|a| a == "--xray"));
    assert_eq!(
        spec_svc.services[0].xray_url.as_deref(),
        Some("http://127.0.0.1:7575/_xray")
    );
}

#[test]
fn pqs_token_env_defers_lookup_until_spawn_time() {
    let dotenv = BTreeMap::new();
    let var_name = "CANTON_RS_UNSET_TEST_VAR_XYZ";
    let yaml = format!(
        "\
services:
  p1:
    role: participant
    ports: [\"7575:json-api\"]
    token_env: {var_name}
  q1:
    role: pqs
    ledger_of: p1
    storage: {{ type: postgres, url: \"postgres://u@127.0.0.1:1/pqs\" }}
    depends_on: [p1]
"
    );
    let ParsedYamlManifest::ModeA(spec) =
        parse_yaml_manifest_str(&yaml, Path::new("."), &dotenv, None)
            .expect("unset token_env must not fail manifest parsing")
    else {
        panic!("expected ModeA");
    };
    let q1 = spec.services.iter().find(|s| s.name == "q1").expect("q1");
    assert_eq!(
        q1.token,
        Some(super::super::TokenSource::Env(var_name.to_string())),
        "pqs slot must retain inherited TokenSource::Env for spawn-time lookup"
    );
    assert!(
        !q1.env.contains_key("CANTON_RS_PQS_TOKEN"),
        "parsed spec must not freeze or embed CANTON_RS_PQS_TOKEN at parse time"
    );
}
