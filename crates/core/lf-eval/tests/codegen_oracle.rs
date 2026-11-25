//! G10 (AT-K05): the Rust generator against the official generators on the codegen fixture
//! (`scripts/oracle-codegen.sh` records what `codegen-js` and `codegen-java` 3.7.2 emitted, `tests/oracle/codegen/official/`).
//!
//! - The set of types is `codegen-js`'s: every type it emitted has a Rust item and the other way round.
//! - `codegen-java` emits only what a template reaches: all of that has a Rust item too.
//! - A type that is in no official output (`Odd`: it holds an `AnyTemplate`) is not dropped silently here: it is in `skipped` with a reason.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_eval::codegen::generate_rust;
use lf_eval::World;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/codegen")
}

fn lines(name: &str) -> BTreeSet<String> {
    std::fs::read_to_string(root().join("official").join(name))
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

fn generated() -> lf_eval::codegen::Generated {
    let world = World::open(&root().join("codegen-fixture.dar")).unwrap();
    generate_rust(&world).unwrap()
}

#[test]
fn the_types_are_the_ones_codegen_js_emitted() {
    let ours: BTreeSet<String> = generated().items.into_iter().collect();
    let official = lines("js.types");
    assert!(official.len() >= 15, "the recording is empty");
    assert_eq!(
        ours,
        official,
        "only in ours: {:?}; only in the official: {:?}",
        ours.difference(&official).collect::<Vec<_>>(),
        official.difference(&ours).collect::<Vec<_>>()
    );
}

#[test]
fn everything_codegen_java_emitted_is_there_too() {
    let ours = generated().items;
    for java in lines("java.types") {
        let (module, name) = java.split_once('/').unwrap();
        let module = format!("{}{}", module[..1].to_uppercase(), &module[1..]);
        assert!(
            ours.contains(&format!("{module}:{name}")),
            "{java} is emitted by codegen-java and not here"
        );
    }
}

#[test]
fn no_type_of_the_package_is_dropped_without_a_word() {
    let g = generated();
    // the names the fixture's Daml source declares
    let mut declared = BTreeSet::new();
    for file in std::fs::read_dir(root().join("daml")).unwrap() {
        let path = file.unwrap().path();
        let module = path.file_stem().unwrap().to_string_lossy().to_string();
        for line in std::fs::read_to_string(&path).unwrap().lines() {
            for keyword in ["data ", "template ", "interface ", "exception "] {
                if let Some(rest) = line.strip_prefix(keyword) {
                    declared.insert(format!(
                        "{module}:{}",
                        rest.split_whitespace().next().unwrap()
                    ));
                }
            }
        }
    }
    assert!(declared.len() >= 15);
    let said: BTreeSet<String> = g
        .skipped
        .iter()
        .map(|s| format!("{}:{}", s.module, s.name))
        .collect();
    for name in &declared {
        assert!(
            g.items.contains(name) || said.contains(name),
            "{name} is neither generated nor reported as skipped"
        );
    }
    // the one the official generators leave out without a word is reported here, with its reason
    let odd = g
        .skipped
        .iter()
        .find(|s| s.name == "Odd")
        .expect("Odd is reported");
    assert!(odd.reason.contains("AnyTemplate"), "{}", odd.reason);
    assert!(!g.items.contains(&"Types:Odd".to_string()));
}
